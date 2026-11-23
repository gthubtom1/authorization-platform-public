from __future__ import annotations

import hashlib
import secrets
import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.core.exceptions import PermissionDenied
from django.core.cache import cache
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from authorization_platform.core.legacy_html import close_legacy_html

from .decorators import active_downstream_required, platform_admin_required
from .forms import AdminDownstreamForm, ArchiveForm, DeleteArchivedForm, InvitationBatchForm, LoginForm, RegistrationForm
from .models import DownstreamProfile, DownstreamStatus, InvitationBatch, InvitationCode, InvitationStatus
from .services import (
    AccountOperationError,
    IssuedInvitation,
    archive_downstream,
    create_downstream_direct,
    decrypt_invitation_code,
    delete_archived_downstream,
    get_downstream_profile,
    is_active_downstream,
    digest_secret,
    invitation_code_hash,
    issue_invitation_batch,
    is_platform_admin,
    list_visible_profiles,
    record_successful_login,
    register_downstream,
    reveal_invitation,
    revoke_invitation,
    visible_profile_for,
)
from .rate_limit import allow as allow_rate, reset as reset_rate, login_rate_identity, login_allowed, registration_allowed


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied[:128].encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _username_digest(value: str) -> str:
    return digest_secret(value.strip().casefold()[:150]) if isinstance(value, str) else ""


def _issue_submission_cache_key(token: str) -> str:
    return "authorization-invitation-issue:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _ensure_issue_submission_token(request: HttpRequest) -> str:
    token = request.session.get("invitation_issue_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["invitation_issue_token"] = token
    return token


def _landing_for(user) -> str:
    if is_platform_admin(user):
        return "accounts:manage_dashboard"
    if is_active_downstream(user):
        return "accounts:downstream_dashboard"
    raise PermissionDenied


def _safe_next_path(request: HttpRequest, expected_role: str) -> str:
    candidate = (request.POST.get("next") or request.GET.get("next") or "").strip()
    prefix = "/manage/" if expected_role == "admin" else "/downstream/"
    if not candidate.startswith(prefix) or candidate.startswith("//"):
        return ""
    if not url_has_allowed_host_and_scheme(
        candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return ""
    return candidate


@require_GET
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect(_landing_for(request.user))
    return render(request, "accounts/login.html")


def _role_login_view(request: HttpRequest, *, expected_role: str, template_name: str) -> HttpResponse:
    form = LoginForm(request=request, data=request.POST or None, expected_role=expected_role)
    next_path = _safe_next_path(request, expected_role)
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    rate_identity = login_rate_identity(expected_role, ip_address, request.POST.get("username", ""))
    rate_allowed = request.method != "POST" or login_allowed(expected_role, ip_address, request.POST.get("username", ""))
    if not rate_allowed:
        form.add_error(None, "尝试过于频繁，请稍后再试。")
    if request.method == "POST" and rate_allowed and form.is_valid():
        user = form.get_user()
        if request.user.is_authenticated:
            prior_profile = get_downstream_profile(request.user)
            record_event(
                actor=request.user,
                action="auth.logout",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="DownstreamProfile" if prior_profile else "",
                object_public_id=prior_profile.public_id if prior_profile else "",
                metadata={"reason": "account_switch"},
            )
            logout(request)
        login(request, user)
        reset_rate("login", rate_identity)
        record_successful_login(user, request_id=request_id, ip_address=ip_address)
        if is_active_downstream(user):
            profile = get_downstream_profile(user)
            request.session["downstream_session_version"] = profile.session_version
        return redirect(next_path or _landing_for(user))
    if request.method == "POST":
        record_event(
            action="auth.login",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="RATE_LIMITED" if not rate_allowed else "AUTHENTICATION_FAILED",
            metadata={
                "username_digest": _username_digest(request.POST.get("username", "")),
                "entrypoint": expected_role,
            },
        )
    return render(request, template_name, {"form": form, "next_path": next_path})


@require_http_methods(["GET", "POST"])
def manage_login_view(request: HttpRequest) -> HttpResponse:
    return _role_login_view(request, expected_role="admin", template_name="accounts/manage_login.html")


@require_http_methods(["GET", "POST"])
def downstream_login_view(request: HttpRequest) -> HttpResponse:
    return _role_login_view(request, expected_role="downstream", template_name="accounts/downstream_login.html")


@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    actor = request.user if request.user.is_authenticated else None
    profile = get_downstream_profile(actor) if actor else None
    was_admin = bool(actor and is_platform_admin(actor))
    was_downstream = bool(profile)
    record_event(
        actor=actor,
        action="auth.logout",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        object_type="DownstreamProfile" if profile else "",
        object_public_id=profile.public_id if profile else "",
    )
    logout(request)
    if was_admin:
        return redirect("accounts:manage_login")
    if was_downstream:
        return redirect("accounts:downstream_login")
    return redirect("accounts:login")


@require_GET
def legacy_register_redirect(request: HttpRequest) -> HttpResponse:
    return redirect("accounts:downstream_register")


@require_http_methods(["GET", "POST"])
def register_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        if is_active_downstream(request.user):
            return redirect("accounts:downstream_dashboard")
        raise PermissionDenied
    form = RegistrationForm(request.POST or None)
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    submitted_code = request.POST.get("invitation_code", "")
    rate_allowed = request.method != "POST" or registration_allowed(ip_address, invitation_code_hash(submitted_code))
    service_recorded_failure = False
    if not rate_allowed:
        form.add_error(None, "尝试过于频繁，请稍后再试。")
    if request.method == "POST" and rate_allowed and form.is_valid():
        result = register_downstream(
            invitation_code=form.cleaned_data["invitation_code"],
            username=form.cleaned_data["username"],
            password=form.cleaned_data["password"],
            request_id=request_id,
            ip_address=ip_address,
        )
        service_recorded_failure = True
        if result.success and result.user and result.profile:
            messages.success(request, "账号已创建，请使用刚才的用户名登录。")
            return redirect("accounts:downstream_login")
        form.add_error(None, "注册信息无效或邀请码不可用，请检查后重试。")
    if request.method == "POST" and not service_recorded_failure:
        record_event(
            action="downstream.register",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="RATE_LIMITED" if not rate_allowed else "FORM_INVALID",
            metadata={
                "username_digest": _username_digest(request.POST.get("username", "")),
                "invitation_digest": invitation_code_hash(submitted_code[:128]),
            },
        )
    return render(request, "accounts/register.html", {"form": form})


@platform_admin_required
def manage_dashboard(request: HttpRequest) -> HttpResponse:
    from authorization_platform.catalog.models import Software

    return render(
        request,
        "accounts/manage_dashboard.html",
        {
            "downstream_count": DownstreamProfile.objects.filter(status=DownstreamStatus.ACTIVE).count(),
            "software_count": Software.objects.exclude(status="archived").count(),
            "invitation_count": InvitationCode.objects.filter(status=InvitationStatus.ISSUED).count(),
        },
    )


@never_cache
@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def invitation_view(request: HttpRequest) -> HttpResponse:
    form = InvitationBatchForm(request.POST or None)
    issued = None
    batch = None
    if request.method == "POST" and form.is_valid():
        submission_token = request.POST.get("submission_token", "")
        expected_token = request.session.get("invitation_issue_token", "")
        if not submission_token:
            form.add_error(None, "生成请求已失效，请刷新页面后重试。")
        elif submission_token != expected_token:
            message = "这个生成请求已经处理，请刷新页面查看结果。" if cache.get(_issue_submission_cache_key(submission_token)) else "生成请求已失效，请刷新页面后重试。"
            form.add_error(None, message)
        elif not cache.add(
            _issue_submission_cache_key(submission_token),
            True,
            timeout=settings.INVITATION_ISSUE_TOKEN_TTL_SECONDS,
        ):
            form.add_error(None, "这个生成请求已经处理，请刷新页面查看结果。")
        else:
            try:
                batch, issued = issue_invitation_batch(
                    actor=request.user,
                    quantity=form.cleaned_data["quantity"],
                    idempotency_key=submission_token,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            except AccountOperationError as exc:
                cache.delete(_issue_submission_cache_key(submission_token))
                form.add_error(None, exc.message)
            else:
                request.session["new_invitation_batch"] = str(batch.public_id)
                request.session["invitation_issue_token"] = secrets.token_urlsafe(32)
                return redirect("accounts:invitations")
    elif request.method == "GET":
        new_batch_id = request.session.pop("new_invitation_batch", None)
        if new_batch_id:
            batch = InvitationBatch.objects.filter(public_id=new_batch_id, created_by=request.user).first()
            if batch:
                try:
                    issued = [
                        IssuedInvitation(
                            public_id=invitation.public_id,
                            code=decrypt_invitation_code(invitation.code_ciphertext),
                            expires_at=invitation.expires_at,
                        )
                        for invitation in batch.codes.all()
                    ]
                except AccountOperationError as exc:
                    messages.error(request, exc.message)
    recent_codes = InvitationCode.objects.select_related("batch").order_by("-created_at")[:50]
    return render(
        request,
        "accounts/invitations.html",
        {
            "form": form,
            "issued": issued,
            "batch": batch,
            "recent_codes": recent_codes,
            "issue_token": _ensure_issue_submission_token(request),
        },
    )


@never_cache
@require_POST
@platform_admin_required
@close_legacy_html
def reveal_invitation_view(request: HttpRequest, public_id) -> HttpResponse:
    try:
        invitation, plaintext = reveal_invitation(
            actor=request.user,
            invitation_public_id=public_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except AccountOperationError as exc:
        messages.error(request, exc.message)
        return redirect("accounts:invitations")
    return render(request, "accounts/invitation_reveal.html", {"invitation": invitation, "plaintext": plaintext})


@require_POST
@platform_admin_required
@close_legacy_html
def revoke_invitation_view(request: HttpRequest, public_id) -> HttpResponse:
    try:
        revoke_invitation(
            actor=request.user,
            public_id=public_id,
            reason=request.POST.get("reason", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except (AccountOperationError, InvitationCode.DoesNotExist) as exc:
        messages.error(request, getattr(exc, "message", "无法作废该邀请码。"))
    else:
        messages.success(request, "邀请码已作废，不能再用于注册。")
    return redirect("accounts:invitations")


@platform_admin_required
def downstream_list(request: HttpRequest) -> HttpResponse:
    return render(request, "accounts/downstream_list.html", {"profiles": list_visible_profiles(request.user)})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def create_downstream_view(request: HttpRequest) -> HttpResponse:
    form = AdminDownstreamForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            profile = create_downstream_direct(
                actor=request.user,
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except AccountOperationError:
            form.add_error(None, "无法创建下游账号，请检查填写内容。")
        else:
            messages.success(request, f"下游账号 {profile.user.username} 已创建。")
            return redirect("accounts:downstream_detail", public_id=profile.public_id)
    return render(request, "accounts/downstream_form.html", {"form": form})


@platform_admin_required
def downstream_detail(request: HttpRequest, public_id) -> HttpResponse:
    try:
        profile = visible_profile_for(request.user, public_id)
    except DownstreamProfile.DoesNotExist as exc:
        raise Http404 from exc
    return render(request, "accounts/downstream_detail.html", {"profile": profile, "archive_form": ArchiveForm()})


@require_POST
@platform_admin_required
@close_legacy_html
def archive_downstream_view(request: HttpRequest, public_id) -> HttpResponse:
    form = ArchiveForm(request.POST)
    if form.is_valid():
        try:
            archive_downstream(actor=request.user, public_id=public_id, reason=form.cleaned_data["reason"], request_id=_request_id(request), ip_address=_ip_address(request))
        except (AccountOperationError, DownstreamProfile.DoesNotExist) as exc:
            messages.error(request, getattr(exc, "message", "无法归档该下游账号。"))
        else:
            messages.success(request, "下游账号已归档，现有会话将在下一次受保护请求时失效。")
    else:
        messages.error(request, "请填写归档原因。")
    return redirect("accounts:downstream_detail", public_id=public_id)


@require_POST
@platform_admin_required
@close_legacy_html
def delete_downstream_view(request: HttpRequest, public_id) -> HttpResponse:
    form = DeleteArchivedForm(request.POST)
    if not form.is_valid():
        messages.error(request, "请勾选确认并填写至少 2 个字的删除原因。")
        return redirect("accounts:downstream_detail", public_id=public_id)
    try:
        tombstone = delete_archived_downstream(
            actor=request.user,
            public_id=public_id,
            reason=form.cleaned_data["reason"],
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except (AccountOperationError, DownstreamProfile.DoesNotExist) as exc:
        messages.error(request, getattr(exc, "message", "无法删除该下游账号。"))
        return redirect("accounts:downstream_detail", public_id=public_id)
    messages.success(request, f"下游账号已删除，已保留脱敏墓碑 {tombstone.public_id}。")
    return redirect("accounts:downstream_list")


@active_downstream_required
def downstream_dashboard(request: HttpRequest) -> HttpResponse:
    profile = get_downstream_profile(request.user)
    from authorization_platform.credits.services import get_quota_account

    return render(request, "accounts/downstream_dashboard.html", {"profile": profile, "quota_account": get_quota_account(profile)})


@active_downstream_required
def downstream_profile_detail(request: HttpRequest, public_id) -> HttpResponse:
    try:
        profile = visible_profile_for(request.user, public_id)
    except DownstreamProfile.DoesNotExist as exc:
        raise Http404 from exc
    return render(request, "accounts/downstream_profile.html", {"profile": profile})
