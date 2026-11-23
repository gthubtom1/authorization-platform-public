from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from functools import wraps

from django.conf import settings
from django.core.paginator import Paginator
from django.contrib.auth import login, logout, update_session_auth_hash
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.csrf import csrf_failure

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.core.csv_utils import csv_safe_row

from .decorators import _admin_access_request_id
from .forms import LoginForm, PasswordChangeForm, PasswordResetForm, RegistrationForm
from .models import (
    DownstreamAdminOperation,
    DownstreamProfile,
    DownstreamStatus,
    InvitationCode,
    InvitationStatus,
)
from .rate_limit import allow as allow_rate, reset as reset_rate, login_rate_identity, login_allowed, registration_allowed
from .services import (
    AccountOperationError,
    archive_downstream,
    archive_invitations,
    change_own_password,
    create_downstream_direct,
    decrypt_invitation_code,
    delete_archived_downstream,
    delete_invitations,
    get_downstream_profile,
    invitation_code_hash,
    is_active_downstream,
    is_platform_admin,
    issue_invitation_batch,
    list_visible_profiles,
    normalize_invitation_code,
    record_successful_login,
    register_downstream,
    reveal_invitation,
    reset_downstream_password,
    revoke_invitation,
    set_downstream_status,
)


MAX_JSON_BODY = 32 * 1024
MAX_JSON_DEPTH = 64


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied[:128].encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _no_store(response: JsonResponse) -> JsonResponse:
    response["Cache-Control"] = "no-store"
    return response


def _success(payload: dict, *, status: int = 200) -> JsonResponse:
    return _no_store(JsonResponse(payload, status=status))


def _error(
    request: HttpRequest,
    code: str,
    message: str,
    *,
    status: int,
    retryable: bool = False,
    fields: dict[str, list[str]] | None = None,
) -> JsonResponse:
    error = {
        "code": code,
        "message": message,
        "request_id": _request_id(request),
        "retryable": retryable,
    }
    if fields:
        error["fields"] = fields
    return _success({"error": error}, status=status)


def _read_json(request: HttpRequest) -> tuple[dict | None, JsonResponse | None]:
    if len(request.body) > MAX_JSON_BODY:
        return None, _error(request, "INVALID_REQUEST", "请求内容过大。", status=400)
    if not request.body:
        return {}, None
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None, _error(request, "INVALID_REQUEST", "请求格式无效。", status=400)
    if not isinstance(payload, dict):
        return None, _error(request, "INVALID_REQUEST", "请求格式无效。", status=400)
    # JSON permits escaped lone surrogates; UTF-8, the database and identity
    # digests do not. Reject them before any hashing, validation or side effect.
    pending = [(payload, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            return None, _error(request, "INVALID_REQUEST", "请求嵌套过深。", status=400)
        if isinstance(value, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                return None, _error(request, "INVALID_REQUEST", "请求包含无效字符。", status=400)
        elif isinstance(value, dict):
            pending.extend((key, depth + 1) for key in value)
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return payload, None


def _api_methods(*allowed_methods: str):
    allowed = {method.upper() for method in allowed_methods}

    def decorator(view):
        @wraps(view)
        def wrapped(request: HttpRequest, *args, **kwargs):
            if request.method not in allowed:
                response = _error(request, "METHOD_NOT_ALLOWED", "请求方法不受支持。", status=405)
                response["Allow"] = ", ".join(sorted(allowed))
                return response
            return view(request, *args, **kwargs)

        return wrapped

    return decorator


def api_csrf_failure(request: HttpRequest, reason: str = "") -> JsonResponse:
    if request.path.startswith("/api/v1/"):
        return _error(request, "CSRF_FAILED", "请求凭证已失效，请刷新页面后重试。", status=403)
    return csrf_failure(request, reason)


def _username_digest(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return hashlib.sha256(value.strip().casefold()[:150].encode("utf-8")).hexdigest()


def _role_for_request(request: HttpRequest) -> tuple[str, object | None]:
    user = request.user
    if not user.is_authenticated:
        return "anonymous", None
    if is_platform_admin(user):
        return "platform_admin", user
    profile = get_downstream_profile(user)
    expected_version = request.session.get("downstream_session_version")
    if not is_active_downstream(user) or not profile or str(expected_version) != str(profile.session_version):
        logout(request)
        return "anonymous", None
    return "downstream", profile


def _logout_before_account_switch(request: HttpRequest) -> None:
    if not request.user.is_authenticated:
        return
    actor = request.user
    profile = get_downstream_profile(actor)
    record_event(
        actor=actor,
        action="auth.logout",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        object_type="DownstreamProfile" if profile else "",
        object_public_id=profile.public_id if profile else "",
        metadata={"reason": "account_switch"},
    )
    logout(request)


def _user_payload(role: str, identity) -> dict | None:
    if role == "platform_admin":
        return {"username": identity.username, "role": role}
    if role == "downstream":
        return {
            "username": identity.user.username,
            "role": role,
            "public_id": str(identity.public_id),
            "status": identity.status,
        }
    return None


def _admin_required(view):
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        role, identity = _role_for_request(request)
        if role == "anonymous":
            return _error(request, "UNAUTHORIZED", "请先登录管理端。", status=401)
        if role != "platform_admin":
            record_event(
                actor=request.user,
                action="admin.access",
                outcome=AuditOutcome.FAILURE,
                request_id=_admin_access_request_id(request),
                ip_address=_ip_address(request),
                reason_code="FORBIDDEN",
                metadata={"path": request.path[:128]},
            )
            return _error(request, "FORBIDDEN", "当前账号没有访问权限。", status=403)
        return view(request, identity, *args, **kwargs)

    return wrapped


def _authenticated_required(view):
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        role, identity = _role_for_request(request)
        if role == "anonymous":
            record_event(
                action="auth.password_change",
                outcome=AuditOutcome.FAILURE,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                reason_code="UNAUTHORIZED",
                metadata={"path": request.path[:128]},
            )
            return _error(request, "UNAUTHORIZED", "请先登录后再修改密码。", status=401)
        return view(request, role, identity, *args, **kwargs)

    return wrapped


def _password_error_status(code: str) -> int:
    if code == "IDEMPOTENCY_CONFLICT":
        return 409
    if code == "DOWNSTREAM_NOT_FOUND":
        return 404
    if code == "DOWNSTREAM_UNAVAILABLE":
        return 409
    return 400


def _password_rate_limited(request: HttpRequest, *, scope: str, identity: str, limit: int, action: str, metadata: dict) -> JsonResponse | None:
    if allow_rate(scope, identity, limit=limit):
        return None
    record_event(
        actor=request.user if request.user.is_authenticated else None,
        action=action,
        outcome=AuditOutcome.FAILURE,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        reason_code="RATE_LIMITED",
        metadata={**metadata, "rate_scope": scope},
    )
    response = _error(request, "RATE_LIMITED", "密码操作过于频繁，请稍后再试。", status=429, retryable=True)
    response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
    return response


def _profile_payload(profile: DownstreamProfile) -> dict:
    from authorization_platform.credits.models import QuotaAccount
    from authorization_platform.licensing.models import LicenseCard, LicenseCardStatus

    balance = (
        QuotaAccount.objects.filter(downstream_public_id=profile.public_id)
        .values_list("available_balance", flat=True)
        .first()
    )
    cards = LicenseCard.objects.filter(current_downstream_public_id=profile.public_id)
    return {
        "public_id": str(profile.public_id),
        "username": profile.user.username,
        "status": profile.status,
        "registration_source": profile.registration_source,
        "registered_at": profile.registered_at.isoformat(),
        "last_successful_login_at": profile.last_successful_login_at.isoformat() if profile.last_successful_login_at else None,
        "available_balance": int(balance or 0),
        "active_authorization_count": cards.filter(status=LicenseCardStatus.ACTIVATED).count(),
        "unused_card_count": cards.filter(status=LicenseCardStatus.UNUSED).count(),
    }


def _downstream_admin_request_hash(*, action: str, public_id, payload: dict) -> str:
    canonical = json.dumps(
        {
            "action": action,
            "public_id": str(public_id) if public_id is not None else None,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    key = settings.ACCOUNT_OPERATION_HASH_KEY.encode("utf-8")
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _downstream_admin_operation_status(code: str) -> int:
    if code == "IDEMPOTENCY_CONFLICT":
        return 409
    if code == "ADMIN_ACTION_RETRYABLE":
        return 409
    if code in {"NOT_FOUND", "DOWNSTREAM_NOT_FOUND"}:
        return 404
    if code in {"ALREADY_CLOSED", "ARCHIVE_REQUIRED", "BALANCE_NOT_CLEARED"}:
        return 409
    return 400


def _downstream_admin_operation_audit_action(action: str) -> str:
    return {
        "create": "downstream.create_direct",
        "status": "downstream.status",
        "archive": "downstream.archive",
        "delete": "downstream.delete",
    }.get(action, "downstream.admin")


def _record_downstream_admin_failure(request: HttpRequest, *, action: str, public_id, code: str, payload: dict) -> None:
    metadata = {"action": action}
    if public_id is not None:
        metadata["target_profile_public_id"] = str(public_id)
    if "username" in payload and isinstance(payload["username"], str):
        metadata["username_digest"] = _username_digest(payload["username"])
    if "reason" in payload and isinstance(payload["reason"], str):
        metadata["reason_length"] = len(payload["reason"].strip())
    record_event(
        actor=request.user,
        action=_downstream_admin_operation_audit_action(action),
        outcome=AuditOutcome.FAILURE,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        reason_code=code,
        object_type="DownstreamProfile" if public_id is not None else "",
        object_public_id=public_id or "",
        metadata=metadata,
    )


def _run_downstream_admin_operation(
    request: HttpRequest,
    *,
    action: str,
    public_id,
    payload: dict,
    execute,
    response_status: int = 200,
) -> JsonResponse:
    key = request.headers.get("Idempotency-Key", "").strip()
    if not key or len(key) > 128:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    request_hash = _downstream_admin_request_hash(action=action, public_id=public_id, payload=payload)
    actor = request.user
    target_profile_public_id = public_id

    try:
        with transaction.atomic():
            target_username = payload.get("username") if action == "create" else ""
            if not target_username and public_id is not None:
                target_username = (
                    DownstreamProfile.objects.filter(public_id=public_id)
                    .values_list("user__username", flat=True)
                    .first()
                    or ""
                )
            target_username_digest = _username_digest(target_username)
            operation = (
                DownstreamAdminOperation.objects.select_for_update()
                .filter(actor=actor, idempotency_key=key)
                .first()
            )
            if operation is not None:
                if operation.action != action or operation.target_profile_public_id != target_profile_public_id or operation.request_hash != request_hash:
                    raise AccountOperationError(
                        "IDEMPOTENCY_CONFLICT",
                        "同一个幂等键不能对应不同的下游管理动作或请求内容。",
                    )
                if not operation.response_payload:
                    raise AccountOperationError(
                        "ADMIN_ACTION_RETRYABLE",
                        "下游管理动作正在处理中，请稍后重试。",
                    )
                return _success(operation.response_payload, status=operation.response_status)

            try:
                with transaction.atomic():
                    operation = DownstreamAdminOperation.objects.create(
                        actor=actor,
                        actor_username_digest=_username_digest(actor.username),
                        action=action,
                        target_profile_public_id=target_profile_public_id,
                        target_username_digest=target_username_digest,
                        idempotency_key=key,
                        request_hash=request_hash,
                        response_payload={},
                        response_status=response_status,
                    )
            except IntegrityError:
                operation = (
                    DownstreamAdminOperation.objects.select_for_update()
                    .filter(actor=actor, idempotency_key=key)
                    .first()
                )
                if operation is None:
                    raise AccountOperationError(
                        "ADMIN_ACTION_RETRYABLE",
                        "下游管理动作正在处理中，请稍后重试。",
                    )
                if operation.action != action or operation.target_profile_public_id != target_profile_public_id or operation.request_hash != request_hash:
                    raise AccountOperationError(
                        "IDEMPOTENCY_CONFLICT",
                        "同一个幂等键不能对应不同的下游管理动作或请求内容。",
                    )
                if not operation.response_payload:
                    raise AccountOperationError(
                        "ADMIN_ACTION_RETRYABLE",
                        "下游管理动作正在处理中，请稍后重试。",
                    )
                return _success(operation.response_payload, status=operation.response_status)

            response_payload = execute()
            operation.response_payload = response_payload
            operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return _success(response_payload, status=response_status)
    except DownstreamProfile.DoesNotExist:
        _record_downstream_admin_failure(request, action=action, public_id=public_id, code="NOT_FOUND", payload=payload)
        return _error(request, "NOT_FOUND", "下游账号不存在。", status=404)
    except AccountOperationError as exc:
        _record_downstream_admin_failure(request, action=action, public_id=public_id, code=exc.code, payload=payload)
        return _error(request, exc.code, exc.message, status=_downstream_admin_operation_status(exc.code), retryable=exc.code == "ADMIN_ACTION_RETRYABLE")


def _invitation_code_suffix(invitation: InvitationCode, *, code: str | None = None) -> str:
    try:
        plaintext = code if code is not None else decrypt_invitation_code(invitation.code_ciphertext)
        suffix = normalize_invitation_code(plaintext)[-4:]
        return suffix or "????"
    except (AccountOperationError, TypeError, ValueError):
        return "????"


def _invitation_payload(invitation: InvitationCode, *, code: str | None = None) -> dict:
    suffix = _invitation_code_suffix(invitation, code=code)
    payload = {
        "public_id": str(invitation.public_id),
        "status": invitation.effective_status,
        "created_at": invitation.created_at.isoformat(),
        "expires_at": invitation.expires_at.isoformat() if invitation.expires_at else None,
        "consumed_at": invitation.consumed_at.isoformat() if invitation.consumed_at else None,
        "consumed_username": invitation.consumed_username or None,
        "masked_code": f"••••-••••-{suffix}",
        "code_suffix": suffix,
    }
    if code is not None:
        payload["code"] = code
    return payload


@_api_methods("GET")
@ensure_csrf_cookie
def api_session(request: HttpRequest) -> JsonResponse:
    role, identity = _role_for_request(request)
    return _success(
        {
            "authenticated": role != "anonymous",
            "role": role,
            "user": _user_payload(role, identity),
        }
    )


@_api_methods("POST")
def api_login(request: HttpRequest) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    entrypoint = payload.get("entrypoint")
    if entrypoint not in {"admin", "downstream"}:
        return _error(request, "INVALID_REQUEST", "登录入口无效。", status=400)

    username = payload.get("username", "")
    password = payload.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return _error(request, "INVALID_REQUEST", "请填写用户名和密码。", status=400)

    request_id = _request_id(request)
    ip_address = _ip_address(request)
    rate_identity = login_rate_identity(entrypoint, ip_address, username)
    rate_allowed = login_allowed(entrypoint, ip_address, username)
    if not rate_allowed:
        record_event(
            action="auth.login",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="RATE_LIMITED",
            metadata={"username_digest": _username_digest(username), "entrypoint": entrypoint},
        )
        rate_limited = _error(request, "RATE_LIMITED", "尝试过于频繁，请稍后再试。", status=429, retryable=True)
        rate_limited["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return rate_limited

    form = LoginForm(request=request, data={"username": username, "password": password}, expected_role=entrypoint)
    if not form.is_valid():
        suspended = any("账号已暂停" in str(item) for item in form.non_field_errors())
        if suspended:
            record_event(
                action="auth.login",
                outcome=AuditOutcome.FAILURE,
                request_id=request_id,
                ip_address=ip_address,
                reason_code="ACCOUNT_SUSPENDED",
                metadata={"username_digest": _username_digest(username), "entrypoint": entrypoint},
            )
            return _error(request, "ACCOUNT_SUSPENDED", "账号已暂停。", status=403)
        record_event(
            action="auth.login",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="AUTHENTICATION_FAILED",
            metadata={"username_digest": _username_digest(username), "entrypoint": entrypoint},
        )
        return _error(request, "AUTHENTICATION_FAILED", "用户名或密码不正确。", status=401)

    user = form.get_user()
    if request.user.is_authenticated:
        _logout_before_account_switch(request)
    login(request, user)
    profile = get_downstream_profile(user)
    if profile:
        request.session["downstream_session_version"] = profile.session_version
    reset_rate("login", rate_identity)
    record_successful_login(user, request_id=request_id, ip_address=ip_address)
    role = "platform_admin" if is_platform_admin(user) else "downstream"
    return _success(
        {
            "authenticated": True,
            "role": role,
            "user": _user_payload(role, profile if role == "downstream" else user),
            "redirect": "manage.html" if role == "platform_admin" else "downstream.html",
            "request_id": request_id,
        }
    )


@_api_methods("POST")
def api_logout(request: HttpRequest) -> JsonResponse:
    role, identity = _role_for_request(request)
    actor = request.user if request.user.is_authenticated else None
    record_event(
        actor=actor,
        action="auth.logout",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        object_type="DownstreamProfile" if role == "downstream" else "",
        object_public_id=identity.public_id if role == "downstream" else "",
    )
    logout(request)
    redirect = "manage-login.html" if role == "platform_admin" else "downstream-login.html"
    return _success(
        {
            "authenticated": False,
            "role": "anonymous",
            "redirect": redirect,
        }
    )


@_authenticated_required
@_api_methods("POST")
def api_password_change(request: HttpRequest, role: str, identity) -> JsonResponse:
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    target_profile = identity if role == "downstream" else None
    rate_identity = f"{request.user.pk}:{ip_address or 'unknown'}"
    rate_response = _password_rate_limited(
        request,
        scope="password-change",
        identity=rate_identity,
        limit=settings.AUTH_PASSWORD_CHANGE_RATE_LIMIT,
        action="auth.password_change",
        metadata={"target_username_digest": _username_digest(request.user.username)},
    )
    if rate_response:
        return rate_response

    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    form = PasswordChangeForm(data=payload)
    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not idempotency_key or len(idempotency_key) > 128:
        record_event(
            actor=request.user,
            action="auth.password_change",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile" if target_profile else "",
            object_public_id=target_profile.public_id if target_profile else "",
            reason_code="IDEMPOTENCY_REQUIRED",
            metadata={"target_username_digest": _username_digest(request.user.username)},
        )
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    if not form.is_valid():
        record_event(
            actor=request.user,
            action="auth.password_change",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile" if target_profile else "",
            object_public_id=target_profile.public_id if target_profile else "",
            reason_code="FORM_INVALID",
            metadata={"target_username_digest": _username_digest(request.user.username)},
        )
        fields = {name: [str(error) for error in errors] for name, errors in form.errors.items()}
        return _error(request, "PASSWORD_CHANGE_INVALID", "密码修改信息无效，请检查后重试。", status=400, fields=fields or None)

    try:
        result = change_own_password(
            actor=request.user,
            current_password=form.cleaned_data["current_password"],
            new_password=form.cleaned_data["new_password"],
            new_password_confirm=form.cleaned_data["new_password_confirm"],
            idempotency_key=idempotency_key,
            request_id=request_id,
            ip_address=ip_address,
        )
    except AccountOperationError as exc:
        return _error(request, exc.code, exc.message, status=_password_error_status(exc.code))

    update_session_auth_hash(request, result.target_user)
    if result.target_profile:
        request.session["downstream_session_version"] = result.target_profile.session_version
    response_payload = dict(result.operation.response_payload)
    response_payload.update({"request_id": request_id, "replayed": result.replayed})
    return _success(response_payload)


@_admin_required
@_api_methods("POST")
def api_downstream_password_reset(request: HttpRequest, _identity, public_id) -> JsonResponse:
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    rate_identity = f"{request.user.pk}:{public_id}:{ip_address or 'unknown'}"
    rate_response = _password_rate_limited(
        request,
        scope="password-reset",
        identity=rate_identity,
        limit=settings.AUTH_PASSWORD_RESET_RATE_LIMIT,
        action="auth.password_reset",
        metadata={"target_profile_public_id": str(public_id)},
    )
    if rate_response:
        return rate_response

    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    form = PasswordResetForm(data=payload)
    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not idempotency_key or len(idempotency_key) > 128:
        record_event(
            actor=request.user,
            action="auth.password_reset",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile",
            object_public_id=public_id,
            reason_code="IDEMPOTENCY_REQUIRED",
            metadata={"target_profile_public_id": str(public_id)},
        )
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    if not form.is_valid():
        record_event(
            actor=request.user,
            action="auth.password_reset",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile",
            object_public_id=public_id,
            reason_code="FORM_INVALID",
            metadata={"target_profile_public_id": str(public_id)},
        )
        fields = {name: [str(error) for error in errors] for name, errors in form.errors.items()}
        return _error(request, "PASSWORD_RESET_INVALID", "密码重置信息无效，请检查后重试。", status=400, fields=fields or None)

    try:
        result = reset_downstream_password(
            actor=request.user,
            public_id=public_id,
            new_password=form.cleaned_data["new_password"],
            new_password_confirm=form.cleaned_data["new_password_confirm"],
            reason=form.cleaned_data["reason"],
            idempotency_key=idempotency_key,
            request_id=request_id,
            ip_address=ip_address,
        )
    except DownstreamProfile.DoesNotExist:
        return _error(request, "DOWNSTREAM_NOT_FOUND", "下游账号不存在。", status=404)
    except AccountOperationError as exc:
        return _error(request, exc.code, exc.message, status=_password_error_status(exc.code))

    response_payload = dict(result.operation.response_payload)
    response_payload.update({"request_id": request_id, "replayed": result.replayed})
    return _success(response_payload)


@_api_methods("POST")
def api_register(request: HttpRequest) -> JsonResponse:
    current_role, _ = _role_for_request(request)
    if current_role != "anonymous":
        return _error(request, "FORBIDDEN", "当前会话不能注册新下游。", status=403)
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error

    submitted_code = payload.get("invitation_code", "")
    username = payload.get("username", "")
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    rate_allowed = registration_allowed(ip_address, invitation_code_hash(submitted_code if isinstance(submitted_code, str) else ""))
    if not rate_allowed:
        record_event(
            action="downstream.register",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="RATE_LIMITED",
            metadata={"username_digest": _username_digest(username), "invitation_digest": invitation_code_hash(submitted_code if isinstance(submitted_code, str) else '')},
        )
        register_limited = _error(request, "RATE_LIMITED", "尝试过于频繁，请稍后再试。", status=429, retryable=True)
        register_limited["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return register_limited

    form = RegistrationForm(data=payload)
    if not form.is_valid():
        record_event(
            action="downstream.register",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="FORM_INVALID",
            metadata={"username_digest": _username_digest(username), "invitation_digest": invitation_code_hash(submitted_code if isinstance(submitted_code, str) else '')},
        )
        fields = {name: [str(error) for error in errors] for name, errors in form.errors.items() if name != "invitation_code"}
        return _error(request, "REGISTRATION_FAILED", "注册信息无效或邀请码不可用，请检查后重试。", status=400, fields=fields or None)

    result = register_downstream(
        invitation_code=form.cleaned_data["invitation_code"],
        username=form.cleaned_data["username"],
        password=form.cleaned_data["password"],
        request_id=request_id,
        ip_address=ip_address,
    )
    if not result.success:
        return _error(request, "REGISTRATION_FAILED", "注册信息无效或邀请码不可用，请检查后重试。", status=400)
    return _success(
        {
            "authenticated": False,
            "role": "anonymous",
            "redirect": "downstream-login.html",
            "request_id": request_id,
        },
        status=201,
    )


@_admin_required
@_api_methods("GET", "POST")
def api_downstream_collection(request: HttpRequest, _identity) -> JsonResponse:
    if request.method == "GET":
        try:
            page_number = max(1, int(request.GET.get("page", "1")))
            page_size = min(100, max(1, int(request.GET.get("page_size", "20"))))
        except (TypeError, ValueError):
            page_number, page_size = 1, 20
        queryset = list_visible_profiles(request.user).order_by("registered_at", "public_id")
        raw_status = request.GET.get("status", "").strip().casefold()
        if raw_status:
            allowed = {choice.value for choice in DownstreamStatus}
            if raw_status not in allowed:
                return _error(request, "INVALID_STATUS", "下游状态筛选不正确。", status=400)
            queryset = queryset.filter(status=raw_status)
        paginator = Paginator(queryset, page_size)
        page = paginator.get_page(page_number)
        return _success(
            {
                "items": [_profile_payload(profile) for profile in page.object_list],
                "pagination": {
                    "page": page.number,
                    "page_size": paginator.per_page,
                    "total": paginator.count,
                    "total_pages": paginator.num_pages,
                    "has_previous": page.has_previous(),
                    "has_next": page.has_next(),
                },
            }
        )

    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return _error(request, "INVALID_REQUEST", "用户名和密码不能为空。", status=400)
    return _run_downstream_admin_operation(
        request,
        action="create",
        public_id=None,
        payload={"username": username, "password": password},
        execute=lambda: {
            "profile": _profile_payload(
                create_downstream_direct(
                    actor=request.user,
                    username=username,
                    password=password,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            )
        },
        response_status=201,
    )


@_admin_required
@_api_methods("POST")
def api_downstream_status(request: HttpRequest, _identity, public_id) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    status_value = payload.get("status")
    reason = payload.get("reason")
    if not isinstance(status_value, str) or not isinstance(reason, str):
        return _error(request, "INVALID_REQUEST", "状态和操作原因不能为空。", status=400)
    return _run_downstream_admin_operation(
        request,
        action="status",
        public_id=public_id,
        payload={"status": status_value, "reason": reason},
        execute=lambda: {
            "profile": _profile_payload(
                set_downstream_status(
                    actor=request.user,
                    public_id=public_id,
                    status=status_value,
                    reason=reason,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            )
        },
    )


@_admin_required
@_api_methods("POST")
def api_downstream_archive(request: HttpRequest, _identity, public_id) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    reason = payload.get("reason")
    if not isinstance(reason, str):
        return _error(request, "INVALID_REQUEST", "操作原因不能为空。", status=400)
    return _run_downstream_admin_operation(
        request,
        action="archive",
        public_id=public_id,
        payload={"reason": reason},
        execute=lambda: {
            "profile": _profile_payload(
                archive_downstream(
                    actor=request.user,
                    public_id=public_id,
                    reason=reason,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            )
        },
    )


@_admin_required
@_api_methods("POST")
def api_downstream_delete(request: HttpRequest, _identity, public_id) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    if payload.get("confirmation") is not True:
        return _error(request, "CONFIRMATION_REQUIRED", "请确认删除已归档下游。", status=400)
    reason = payload.get("reason")
    if not isinstance(reason, str):
        return _error(request, "INVALID_REQUEST", "操作原因不能为空。", status=400)
    return _run_downstream_admin_operation(
        request,
        action="delete",
        public_id=public_id,
        payload={"confirmation": True, "reason": reason},
        execute=lambda: {
            "deleted": True,
            "tombstone_public_id": str(
                delete_archived_downstream(
                    actor=request.user,
                    public_id=public_id,
                    reason=reason,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                ).public_id
            ),
        },
    )


def _invitation_queryset(request: HttpRequest):
    scope = request.GET.get("scope", "current").strip().lower()
    if scope not in {"current", "archived", "all"}:
        return None, _error(request, "INVALID_SCOPE", "邀请码分类不正确。", status=400)
    rows = InvitationCode.objects.select_related("consumed_profile__user").exclude(
        status=InvitationStatus.DELETED_TOMBSTONE
    )
    if scope == "current":
        rows = rows.exclude(status=InvitationStatus.ARCHIVED)
    elif scope == "archived":
        rows = rows.filter(status=InvitationStatus.ARCHIVED)
    status_filter = request.GET.get("status", "").strip().lower()
    allowed_statuses = {choice.value for choice in InvitationStatus if choice != InvitationStatus.DELETED_TOMBSTONE}
    if status_filter:
        if status_filter not in allowed_statuses:
            return None, _error(request, "INVALID_STATUS", "邀请码状态筛选不正确。", status=400)
        if status_filter == InvitationStatus.EXPIRED:
            rows = rows.filter(
                Q(status=InvitationStatus.EXPIRED)
                | Q(status=InvitationStatus.ISSUED, expires_at__isnull=False, expires_at__lte=timezone.now())
            )
        else:
            rows = rows.filter(status=status_filter)
    query = request.GET.get("q", "").strip()
    if len(query) > 128:
        return None, _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
    if query:
        normalized = "".join(query.split()).upper() if isinstance(query, str) else ""
        hashed = (
            rows.filter(code_hash=invitation_code_hash(normalized)).first()
            if len(normalized) >= 16
            else None
        )
        if hashed is not None:
            rows = rows.filter(pk=hashed.pk)
        else:
            rows = rows.filter(
                Q(consumed_username__icontains=query)
                | Q(consumed_profile__user__username__icontains=query)
            )
    return rows.order_by("-created_at", "-public_id"), None


@_admin_required
@_api_methods("GET", "POST")
def api_invitation_collection(request: HttpRequest, _identity) -> JsonResponse:
    if request.method == "GET":
        rows, error = _invitation_queryset(request)
        if error is not None:
            return error
        scope = request.GET.get("scope", "current").strip().lower()
        try:
            page_number = max(1, int(request.GET.get("page", "1")))
        except (TypeError, ValueError):
            page_number = 1
        paginator = Paginator(rows, 5)
        page_obj = paginator.get_page(page_number)
        return _success({
            "items": [_invitation_payload(row) for row in page_obj.object_list],
            "scope": scope,
            "pagination": {
                "page": page_obj.number,
                "page_size": paginator.per_page,
                "total": paginator.count,
                "total_pages": paginator.num_pages,
                "has_previous": page_obj.has_previous(),
                "has_next": page_obj.has_next(),
            },
        })

    rate_identity = f"{_ip_address(request) or 'unknown'}:{request.user.pk}"
    if not allow_rate("invitation-issue-api", rate_identity, limit=settings.INVITATION_ISSUE_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="invitation.issue",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "invitation-issue-api"},
        )
        response = _error(request, "RATE_LIMITED", "生成邀请码过于频繁，请稍后再试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return response
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    quantity = payload.get("quantity")
    if isinstance(quantity, bool) or not isinstance(quantity, int):
        return _error(request, "INVALID_QUANTITY", "生成数量必须是整数。", status=400)
    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not idempotency_key or len(idempotency_key) > 128:
        return _error(request, "INVALID_REQUEST", "缺少有效的重复提交标识。", status=400)
    request_id = _request_id(request)
    try:
        batch, issued = issue_invitation_batch(
            actor=request.user,
            quantity=quantity,
            idempotency_key=idempotency_key,
            request_id=request_id,
            ip_address=_ip_address(request),
        )
        result = {
            "items": [_invitation_payload(InvitationCode.objects.get(public_id=item.public_id), code=item.code) for item in issued],
            "request_id": request_id,
        }
        return _success(result, status=201)
    except AccountOperationError as exc:
        if exc.code == "INVITATION_NOT_FOUND":
            status = 404
        elif exc.code == "IDEMPOTENCY_CONFLICT":
            status = 409
        else:
            status = 400
        return _error(request, exc.code, exc.message, status=status)


@_admin_required
@_api_methods("POST")
def api_invitation_search(request: HttpRequest, _identity) -> JsonResponse:
    rate_identity = f"{_ip_address(request) or 'unknown'}:{request.user.pk}"
    if not allow_rate("invitation-search-api", rate_identity, limit=settings.INVITATION_SEARCH_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="invitation.search",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "invitation-search-api"},
        )
        response = _error(request, "RATE_LIMITED", "搜索邀请码过于频繁，请稍后再试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return response

    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    code = payload.get("code")
    normalized = "".join(code.split()).upper() if isinstance(code, str) else ""
    if not normalized or len(normalized) > 128:
        return _error(request, "INVITATION_NOT_FOUND", "邀请码不存在。", status=404)
    invitation = InvitationCode.objects.select_related("consumed_profile__user").exclude(
        status=InvitationStatus.DELETED_TOMBSTONE
    ).filter(
        code_hash=invitation_code_hash(normalized)
    ).first()
    if invitation is None:
        return _error(request, "INVITATION_NOT_FOUND", "邀请码不存在。", status=404)
    return _success({"item": _invitation_payload(invitation)})


@_admin_required
@_api_methods("POST")
def api_invitation_reveal(request: HttpRequest, _identity, public_id) -> JsonResponse:
    rate_identity = f"{_ip_address(request) or 'unknown'}:{request.user.pk}"
    if not allow_rate("invitation-reveal-api", rate_identity, limit=settings.INVITATION_REVEAL_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="invitation.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "invitation-reveal-api"},
        )
        response = _error(request, "RATE_LIMITED", "查看邀请码过于频繁，请稍后再试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return response

    try:
        invitation, plaintext = reveal_invitation(
            actor=request.user,
            invitation_public_id=public_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except AccountOperationError as exc:
        status = 404 if exc.code == "INVITATION_NOT_FOUND" else 400
        return _error(request, exc.code, exc.message, status=status)

    # The complete code is returned only in this protected response. It is not
    # included in the list item, URL, audit metadata, or a success audit event.
    return _success({"item": _invitation_payload(invitation), "code": plaintext})


@_admin_required
@_api_methods("POST")
def api_invitation_revoke(request: HttpRequest, _identity, public_id) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        invitation = revoke_invitation(
            actor=request.user,
            public_id=public_id,
            reason=str(payload.get("reason") or ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except InvitationCode.DoesNotExist:
        return _error(request, "INVITATION_NOT_FOUND", "邀请码不存在。", status=404)
    except AccountOperationError as exc:
        status = 404 if exc.code == "INVITATION_NOT_FOUND" else 409 if exc.code in {"INVITATION_UNAVAILABLE", "INVITATION_EXPIRED"} else 400
        return _error(request, exc.code, exc.message, status=status)
    return _success({"item": _invitation_payload(invitation)})


def _invitation_lifecycle(request: HttpRequest, *, action: str) -> JsonResponse:
    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not idempotency_key or len(idempotency_key) > 128:
        return _error(request, "INVALID_REQUEST", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        if action == "archive":
            result = archive_invitations(
                actor=request.user,
                code_ids=payload.get("code_ids", []),
                reason=payload.get("reason", ""),
                idempotency_key=idempotency_key,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        else:
            result = delete_invitations(
                actor=request.user,
                code_ids=payload.get("code_ids", []),
                reason=payload.get("reason", ""),
                idempotency_key=idempotency_key,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
    except AccountOperationError as exc:
        status = 409 if exc.code in {"IDEMPOTENCY_CONFLICT", "LIFECYCLE_RETRYABLE", "INVITATION_NOT_ARCHIVABLE", "INVITATION_NOT_YET_ARCHIVABLE", "INVITATION_ALREADY_ARCHIVED", "INVITATION_NOT_DELETABLE"} else 400
        return _error(request, exc.code, exc.message, status=status, retryable=exc.code == "LIFECYCLE_RETRYABLE")
    return _success(result)


@_admin_required
@_api_methods("POST")
def api_invitation_archive(request: HttpRequest, _identity) -> JsonResponse:
    return _invitation_lifecycle(request, action="archive")


@_admin_required
@_api_methods("POST")
def api_invitation_delete(request: HttpRequest, _identity) -> JsonResponse:
    return _invitation_lifecycle(request, action="delete")


@_api_methods("GET")
@_admin_required
def api_invitation_export(request: HttpRequest, _identity) -> HttpResponse:
    import csv as csv_module
    import io

    rows, error = _invitation_queryset(request)
    if error is not None:
        return error
    total = rows.count()
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(csv_safe_row(["公开ID", "状态", "创建时间", "使用时间", "注册账号"]))
    for code in rows[:1000]:
        writer.writerow(
            csv_safe_row([
                str(code.public_id),
                code.effective_status_display,
                code.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                code.consumed_at.strftime("%Y-%m-%d %H:%M:%S") if code.consumed_at else "",
                code.consumed_username or "",
            ])
        )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="invitations.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    if total > 1000:
        response["X-Export-Truncated"] = "1"
        response["X-Export-Total"] = str(total)
    return response
