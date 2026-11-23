from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from datetime import timedelta
from functools import wraps

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import CharField, F, Max, OuterRef, Q, Subquery
from django.db.models.functions import Cast
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile
from authorization_platform.accounts.api_views import (
    _admin_required,
    _api_methods,
    _error,
    _read_json,
    _role_for_request,
    _success,
)
from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.core.time import format_beijing_wall_clock
from authorization_platform.accounts.services import get_downstream_profile
from authorization_platform.core.csv_utils import csv_safe_row
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.credits.services import get_quota_account
from authorization_platform.credits.models import QuotaAccount

from .device_codes import compact_device_code
from .admin import (
    MAX_RENEWAL_BATCH,
    MAX_RENEWAL_TOTAL_SECONDS,
    authorization_card_is_frozen,
    block_device,
    block_physical_device,
    unblock_physical_device,
    extend_authorization,
    list_risk_signals_for_admin,
    redact_request_id,
    renewal_seconds,
    reset_device_binding,
    revoke_authorization,
    unblock_device,
)
from .models import (
    AuthorizationAdminOperation,
    AuthorizationDeviceOperation,
    AuthorizationState,
    Device,
    DeviceBinding,
    DeviceBindingState,
    LicenseCard,
    LicenseCardStatus,
    LicenseInstance,
    LicenseReclaimOperation,
)
from .authorization import (
    AUTHORIZATION_ALGORITHM,
    AUTHORIZATION_CANONICALIZATION,
    AuthorizationOperationError,
    authorization_signing_public_key,
    current_verify_interval_seconds,
    is_time_rollback_blocked,
)
from .services import (
    LicenseOperationError,
    archive_license_cards,
    decrypt_license_card,
    delete_license_cards,
    generate_license_batch,
    license_card_hash,
    normalize_license_card_code,
    preview_license_batch,
    reclaim_license_card,
    reveal_license_card,
)


MAX_JSON_BODY = 32 * 1024
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
LICENSE_EXPORT_LIMIT = 1000
AUTHORIZATION_EXPORT_LIMIT = 1000
MAX_RECLAIM_COUNT = 1000
RECLAIM_FILTER_KEYS = {
    "status",
    "software_id",
    "software_name",
    "plan_snapshot_id",
    "plan_name",
    "downstream_public_id",
    "device_state",
    "expiry_state",
    "scope",
}


@_admin_required
@_api_methods("GET")
def api_authorization_signing_key(request: HttpRequest, _identity) -> JsonResponse:
    """Return the current public verification key to an authenticated administrator."""

    request_id = _request_id(request)
    try:
        payload = {
            "key_id": settings.AUTHORIZATION_SIGNING_KEY_ID,
            "public_key": authorization_signing_public_key(),
            "algorithm": AUTHORIZATION_ALGORITHM,
            "encoding": "base64url-no-padding",
            "canonicalization": AUTHORIZATION_CANONICALIZATION,
        }
    except AuthorizationOperationError as exc:
        record_event(
            actor=request.user,
            action="authorization.signing_key.export",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=_ip_address(request),
            reason_code=exc.code,
        )
        return _error(request, exc.code, exc.message, status=exc.http_status, retryable=exc.retryable)

    record_event(
        actor=request.user,
        action="authorization.signing_key.export",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        ip_address=_ip_address(request),
        object_type="AuthorizationSigningKey",
        object_public_id=payload["key_id"],
        metadata={"algorithm": payload["algorithm"], "encoding": payload["encoding"]},
    )
    return _success(payload)


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied.encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _idempotency_key(request: HttpRequest) -> str | None:
    value = request.headers.get("Idempotency-Key", "").strip()
    if not value or len(value) > 128:
        return None
    return value


def _downstream_required(view):
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        role, identity = _role_for_request(request)
        if role == "anonymous":
            return _error(request, "UNAUTHORIZED", "请先登录下游端。", status=401)
        if role != "downstream":
            return _error(request, "FORBIDDEN", "当前账号没有访问下游授权卡密的权限。", status=403)
        return view(request, identity, *args, **kwargs)

    return wrapped


def _license_error_status(error: LicenseOperationError) -> int:
    if error.code in {"LICENSE_CARD_NOT_FOUND", "PLAN_NOT_FOUND", "BATCH_NOT_FOUND"}:
        return 404
    if error.code in {"FORBIDDEN", "DOWNSTREAM_NOT_ACTIVE"}:
        return 403
    if error.code in {
        "IDEMPOTENCY_CONFLICT",
        "LIFECYCLE_RETRYABLE",
        "INSUFFICIENT_QUOTA",
        "PREVIEW_MISMATCH",
        "PREVIEW_EXPIRED",
        "PREVIEW_REQUIRED",
        "PLAN_SNAPSHOT_STALE",
        "CARD_NOT_RECLAIMABLE",
        "RECLAIM_INCONSISTENT",
        "RECLAIM_RETRYABLE",
        "RECLAIM_TOO_MANY",
        "NO_RECLAIMABLE_CARDS",
        "SOFTWARE_NOT_OPEN",
        "PLAN_NOT_OPEN",
        "SOFTWARE_NOT_AVAILABLE",
        "PLAN_NOT_AVAILABLE",
        "PLAN_NOT_EFFECTIVE",
        "TOTAL_COST_LIMIT",
        "CARD_NOT_ARCHIVABLE",
        "CARD_NOT_YET_ARCHIVABLE",
        "CARD_ALREADY_ARCHIVED",
        "CARD_NOT_DELETABLE",
        "CARD_HAS_AUTHORIZATION_HISTORY",
    }:
        return 409
    return 400


def _service_error(request: HttpRequest, error: LicenseOperationError) -> JsonResponse:
    return _error(request, error.code, error.message, status=_license_error_status(error), retryable=error.code == "LIFECYCLE_RETRYABLE")


def _license_rate_limit_response(
    request: HttpRequest,
    *,
    scope: str,
    identity: str,
    limit: int,
    action: str,
    message: str,
) -> JsonResponse | None:
    if allow_rate(scope, identity, limit=limit):
        return None
    record_event(
        actor=request.user,
        action=action,
        outcome=AuditOutcome.FAILURE,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        reason_code="RATE_LIMITED",
        metadata={"rate_scope": scope},
    )
    response = _error(request, "RATE_LIMITED", message, status=429, retryable=True)
    response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
    return response


def _integer(payload: dict, key: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise LicenseOperationError("INVALID_REQUEST", f"{key}必须是整数。")
    if minimum is not None and value < minimum:
        raise LicenseOperationError("INVALID_REQUEST", f"{key}不符合范围要求。")
    if maximum is not None and value > maximum:
        raise LicenseOperationError("INVALID_REQUEST", f"{key}不符合范围要求。")
    return value


def _required_string(payload: dict, key: str, *, max_length: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise LicenseOperationError("INVALID_REQUEST", f"{key}格式不正确。")
    return value.strip()


def _read_api_json(request: HttpRequest) -> tuple[dict | None, JsonResponse | None]:
    if len(request.body) > MAX_JSON_BODY:
        return None, _error(request, "INVALID_REQUEST", "请求内容过大。", status=400)
    return _read_json(request)


def _preview_payload(preview) -> dict:
    return {
        "software_id": preview.software_id,
        "plan_id": preview.plan_id,
        "plan_name": preview.plan_name,
        "snapshot_id": str(preview.snapshot_id),
        "snapshot_version": preview.snapshot_version,
        "duration_seconds": preview.duration_seconds,
        "test_only": preview.test_only,
        "quota_cost_per_card": preview.quota_cost_per_card,
        "quantity": preview.quantity,
        "total_quota_cost": preview.total_quota_cost,
        "available_balance": preview.available_balance,
        "balance_after": preview.balance_after,
        "sufficient_balance": preview.sufficient_balance,
        "preview_token": preview.preview_token,
        "expires_in": int(settings.LICENSE_CARD_PREVIEW_TTL_SECONDS),
    }


def _duration_label(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400} 天"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} 小时"
    if seconds % 60 == 0:
        return f"{seconds // 60} 分钟"
    return f"{seconds} 秒"


def _card_code_suffix(card: LicenseCard) -> str:
    try:
        return decrypt_license_card(card.card_ciphertext, key_version=card.encryption_key_version)[-4:]
    except LicenseOperationError:
        return "????"


def _card_payload(card: LicenseCard, *, code: str | None = None, include_downstream: bool = False) -> dict:
    snapshot = card.plan_snapshot
    suffix = (normalize_license_card_code(code)[-4:] if code else _card_code_suffix(card)) or "????"
    try:
        instance = card.authorization_instance
    except LicenseInstance.DoesNotExist:
        instance = None
    latest_binding = _latest_binding(instance) if instance is not None else None
    device = latest_binding.device if latest_binding is not None else None
    device_uuid = _admin_identifier(device.public_id) if device is not None else None
    device_code = _client_device_code(device)
    if latest_binding is None:
        device_state = "未绑定"
        device_label = "尚未绑定"
        device_ip = "尚未产生"
    else:
        device_state = {
            DeviceBindingState.ACTIVE: "已绑定",
            DeviceBindingState.BLOCKED: "已阻断",
            DeviceBindingState.UNBOUND: "已解绑",
            DeviceBindingState.EXPIRED: "已过期",
        }.get(latest_binding.state, latest_binding.get_state_display())
        # Keep the legacy combined field stable while exposing the plain code
        # separately for compact tables and support lookup.
        device_label = f"{device_code or '尚未绑定'} · {device_state}"
        device_ip = _admin_ip(device.last_ip) or "尚未产生"
    if card.expires_at:
        activation_rule = f"{card.expires_at.isoformat()} 到期"
    else:
        activation_rule = f"激活后 {_duration_label(snapshot.duration_seconds)}"
    payload = {
        "public_id": str(card.public_id),
        "authorization_id": str(instance.authorization_id) if instance is not None else None,
        "status": card.status,
        "status_label": card.get_status_display(),
        "software_id": card.software_id,
        "software_name": card.software.name,
        "profile_id": card.profile.profile_id,
        "plan_snapshot_id": str(card.plan_snapshot_id),
        "plan_name": snapshot.name,
        "duration_seconds": snapshot.duration_seconds,
        "duration_label": _duration_label(snapshot.duration_seconds),
        "quota_cost": card.quota_cost,
        "issued_at": card.issued_at.isoformat(),
        "activated_at": card.activated_at.isoformat() if card.activated_at else None,
        "expires_at": card.expires_at.isoformat() if card.expires_at else None,
        "reclaimed_at": card.reclaimed_at.isoformat() if card.reclaimed_at else None,
        "revoked_at": card.revoked_at.isoformat() if card.revoked_at else None,
        "status_reason": card.status_reason or None,
        "masked_code": f"••••-••••-{suffix}",
        "code_suffix": suffix,
        "code_available": bool(card.card_ciphertext),
        "device": device_label,
        "device_code": device_code,
        "installation_id": device.installation_id if device is not None else None,
        "device_uuid": device_uuid,
        # Keep device_id as the internal UUID for existing action references.
        "device_id": device_uuid,
        "device_label": device_label,
        "device_state": device_state,
        "ip": device_ip,
        "activation_rule": activation_rule,
    }
    if include_downstream:
        payload["original_downstream_public_id"] = str(card.original_downstream_public_id)
        payload["current_downstream_public_id"] = str(card.current_downstream_public_id)
        payload["downstream_username"] = (
            card.current_downstream.user.username
            if card.current_downstream_id and card.current_downstream
            else f"已删除下游 · {str(card.current_downstream_public_id)[-8:]}"
        )
    if code is not None:
        payload["code"] = code
    return payload


def _page_number(request: HttpRequest) -> int:
    try:
        return max(1, int(request.GET.get("page", "1")))
    except (TypeError, ValueError):
        return 1


def _page_size(request: HttpRequest) -> int:
    try:
        return min(max(1, int(request.GET.get("page_size", str(DEFAULT_PAGE_SIZE)))), MAX_PAGE_SIZE)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_SIZE


def _filtered_cards(request: HttpRequest, *, admin: bool, profile=None):
    cards = LicenseCard.objects.select_related(
        "software",
        "profile",
        "plan_snapshot",
        "current_downstream__user",
    ).order_by("-issued_at", "-public_id")
    # 已删除（墓碑化）的卡从库存列表消失，不做状态的反复展示。
    cards = cards.exclude(status=LicenseCardStatus.DELETED_TOMBSTONE)
    raw_scope = request.GET.get("scope", "current").strip().casefold()
    if admin:
        if raw_scope not in {"current", "archived", "all"}:
            raise LicenseOperationError("INVALID_QUERY", "授权卡密分类不正确。")
        if raw_scope == "current":
            cards = cards.exclude(status=LicenseCardStatus.ARCHIVED)
        elif raw_scope == "archived":
            cards = cards.filter(status=LicenseCardStatus.ARCHIVED)
    elif raw_scope not in {"", "current"}:
        raise LicenseOperationError("INVALID_QUERY", "下游不能查看归档授权卡密。")
    if not admin:
        cards = cards.filter(current_downstream_public_id=profile.public_id)
        cards = cards.exclude(status=LicenseCardStatus.ARCHIVED)
    raw_status = request.GET.get("status", "").strip()
    if raw_status:
        allowed = {choice.value for choice in LicenseCardStatus if choice != LicenseCardStatus.DISABLED}
        if raw_status not in allowed:
            raise LicenseOperationError("INVALID_STATUS", "授权卡密状态筛选不正确。")
        if not admin and raw_status == LicenseCardStatus.ARCHIVED:
            raise LicenseOperationError("INVALID_STATUS", "下游不能查看归档授权卡密。")
        now = timezone.now()
        if raw_status == LicenseCardStatus.EXPIRED:
            cards = cards.filter(
                Q(status=LicenseCardStatus.EXPIRED)
                | Q(status=LicenseCardStatus.ACTIVATED, expires_at__lte=now)
            )
        elif raw_status == LicenseCardStatus.ACTIVATED:
            cards = cards.filter(status=LicenseCardStatus.ACTIVATED).filter(
                Q(expires_at__isnull=True) | Q(expires_at__gt=now)
            )
        else:
            cards = cards.filter(status=raw_status)
    software_id = request.GET.get("software_id", "").strip().casefold()
    if software_id:
        cards = cards.filter(software_id=software_id)
    downstream_id = request.GET.get("downstream_public_id", "").strip()
    if downstream_id:
        try:
            downstream_uuid = uuid.UUID(downstream_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise LicenseOperationError("INVALID_REQUEST", "下游标识不正确。") from exc
        cards = cards.filter(current_downstream_public_id=downstream_uuid)
    software_name = request.GET.get("software_name", "").strip()
    if len(software_name) > 128:
        raise LicenseOperationError("INVALID_QUERY", "软件筛选内容不能超过 128 个字符。")
    if software_name:
        cards = cards.filter(software__name__iexact=software_name)
    plan_snapshot_id = request.GET.get("plan_snapshot_id", "").strip()
    if plan_snapshot_id:
        try:
            cards = cards.filter(plan_snapshot_id=uuid.UUID(plan_snapshot_id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise LicenseOperationError("INVALID_QUERY", "套餐快照标识不正确。") from exc
    plan_name = request.GET.get("plan_name", "").strip()
    if len(plan_name) > 128:
        raise LicenseOperationError("INVALID_QUERY", "套餐筛选内容不能超过 128 个字符。")
    if plan_name:
        cards = cards.filter(plan_snapshot__name__iexact=plan_name)
    device_state = request.GET.get("device_state", "").strip().casefold()
    if device_state in {"bound", "已绑定"}:
        cards = cards.filter(authorization_instance__device_bindings__state="active").distinct()
    elif device_state in {"unbound", "未绑定"}:
        cards = cards.exclude(authorization_instance__device_bindings__state="active").distinct()
    elif device_state:
        raise LicenseOperationError("INVALID_QUERY", "设备状态筛选不正确。")
    expiry_state = request.GET.get("expiry_state", "").strip().casefold()
    if expiry_state in {"not_started", "未开始"}:
        cards = cards.filter(status=LicenseCardStatus.UNUSED)
    elif expiry_state in {"started", "已开始"}:
        cards = cards.filter(status__in={LicenseCardStatus.ACTIVATED, LicenseCardStatus.EXPIRED})
    elif expiry_state in {"expired", "已过期"}:
        now = timezone.now()
        cards = cards.filter(
            Q(status=LicenseCardStatus.EXPIRED)
            | Q(status=LicenseCardStatus.ACTIVATED, expires_at__lte=now)
        )
    elif expiry_state:
        raise LicenseOperationError("INVALID_QUERY", "期限状态筛选不正确。")
    query = request.GET.get("q", "").strip()
    if len(query) > 128:
        raise LicenseOperationError("INVALID_QUERY", "搜索内容不能超过 128 个字符。")
    if query:
        hashed = _license_card_for_pasted_code(query, admin=admin, profile=profile)
        if hashed is not None:
            cards = cards.filter(pk=hashed.pk)
        else:
            tokens = _table_search_tokens(query)
            if not tokens:
                cards = cards.none()
            else:
                cards = cards.annotate(
                    _public_id_text=Cast("public_id", CharField()),
                    _device_id_text=Cast("authorization_instance__device_bindings__device__public_id", CharField()),
                )
                for token in tokens:
                    cards = cards.filter(
                        Q(software__name__icontains=token)
                        | Q(software__software_id__icontains=token)
                        | Q(plan_snapshot__name__icontains=token)
                        | Q(current_downstream__user__username__icontains=token)
                        | Q(_public_id_text__icontains=token)
                        | Q(_device_id_text__icontains=token)
                        | Q(authorization_instance__device_bindings__device__installation_id__icontains=token)
                        | Q(authorization_instance__device_bindings__device__device_code__icontains=token)
                    )
                cards = cards.distinct()
    return cards


def _normalize_reclaim_filters(payload: dict, *, admin: bool) -> dict:
    raw_filters = payload.get("filters", {})
    if raw_filters is None:
        raw_filters = {}
    if not isinstance(raw_filters, dict):
        raise LicenseOperationError("INVALID_REQUEST", "filters 必须是对象。")
    unknown = set(raw_filters) - RECLAIM_FILTER_KEYS
    if unknown:
        raise LicenseOperationError("INVALID_REQUEST", "回收筛选包含不支持的字段。")

    filters: dict[str, str] = {"status": LicenseCardStatus.UNUSED}
    for key, raw_value in raw_filters.items():
        if raw_value in (None, ""):
            continue
        if not isinstance(raw_value, str) or len(raw_value.strip()) > 128:
            raise LicenseOperationError("INVALID_REQUEST", f"{key}筛选格式不正确。")
        value = raw_value.strip()
        if not value:
            continue
        filters[key] = value

    requested_status = filters.get("status", LicenseCardStatus.UNUSED)
    if requested_status not in {LicenseCardStatus.UNUSED, "未激活"}:
        raise LicenseOperationError("INVALID_REQUEST", "回收筛选只能使用未激活状态。")
    filters["status"] = LicenseCardStatus.UNUSED

    if filters.get("software_id"):
        filters["software_id"] = filters["software_id"].casefold()
    if filters.get("plan_snapshot_id"):
        try:
            filters["plan_snapshot_id"] = str(uuid.UUID(filters["plan_snapshot_id"]))
        except (ValueError, AttributeError, TypeError) as exc:
            raise LicenseOperationError("INVALID_REQUEST", "套餐快照标识不正确。") from exc

    if filters.get("device_state") not in {None, "未绑定", "已绑定", "unbound", "bound"}:
        raise LicenseOperationError("INVALID_REQUEST", "设备筛选不正确。")
    if filters.get("expiry_state") not in {None, "未开始", "not_started"}:
        raise LicenseOperationError("INVALID_REQUEST", "期限筛选不正确。")

    if not admin:
        # The downstream session is the only source of ownership. A client-sent
        # downstream identifier is never part of its filtered-operation hash.
        filters.pop("downstream_public_id", None)
    elif filters.get("downstream_public_id"):
        try:
            filters["downstream_public_id"] = str(uuid.UUID(filters["downstream_public_id"]))
        except (ValueError, AttributeError, TypeError) as exc:
            raise LicenseOperationError("INVALID_REQUEST", "下游标识不正确。") from exc

    raw_scope = filters.pop("scope", "")
    if not isinstance(raw_scope, str):
        raw_scope = ""
    raw_scope = raw_scope.strip().casefold()
    if admin:
        if not raw_scope:
            raw_scope = "current"
        if raw_scope not in {"current", "archived", "all"}:
            raise LicenseOperationError("INVALID_QUERY", "授权卡密分类不正确。")
        filters["scope"] = raw_scope
    elif raw_scope and raw_scope != "current":
        raise LicenseOperationError("INVALID_QUERY", "下游不能查看归档授权卡密。")
    return filters


def _reclaim_candidate_queryset(*, filters: dict, admin: bool, profile=None):
    cards = LicenseCard.objects.filter(status=LicenseCardStatus.UNUSED)
    if not admin:
        cards = cards.filter(current_downstream_public_id=profile.public_id)
    if admin and filters.get("scope") == "archived":
        return cards.none()
    if filters.get("software_id"):
        cards = cards.filter(software_id=filters["software_id"])
    if filters.get("software_name"):
        cards = cards.filter(software__name__iexact=filters["software_name"])
    if filters.get("plan_snapshot_id"):
        cards = cards.filter(plan_snapshot_id=filters["plan_snapshot_id"])
    if filters.get("plan_name"):
        cards = cards.filter(plan_snapshot__name__iexact=filters["plan_name"])
    if admin and filters.get("downstream_public_id"):
        cards = cards.filter(current_downstream_public_id=filters["downstream_public_id"])

    # An unused card has no authorization instance or active binding yet. The
    # explicit negative branches still make unsupported UI states fail closed.
    if filters.get("device_state") in {"已绑定", "bound"}:
        return cards.none()
    if filters.get("expiry_state") not in {None, "未开始", "not_started"}:
        return cards.none()
    return cards.order_by("public_id")


def _lock_reclaim_resources(card_ids: list[uuid.UUID], *, admin: bool, profile=None) -> None:
    """Acquire the shared reclaim resources in one deterministic order.

    The order must match the per-card service path in
    ``credits.services.reclaim_license_card`` (LicenseCard → DownstreamProfile
    → QuotaAccount).  Locking profiles/accounts before the cards here used to
    be the exact reverse, so a batch reclaim and a single-card reclaim running
    at the same time could deadlock on the same two rows.

    Every id is sorted so that two batches touching the same rows always take
    them in the same sequence.
    """

    references = LicenseCard.objects.filter(public_id__in=card_ids)
    if not admin:
        references = references.filter(current_downstream_public_id=profile.public_id)
    ordered_ids = sorted(str(value) for value in references.values_list("public_id", flat=True))
    list(
        LicenseCard.objects.select_for_update()
        .filter(public_id__in=ordered_ids)
        .order_by("public_id")
    )
    owner_ids = sorted(
        {str(value) for value in references.values_list("original_downstream_public_id", flat=True)}
    )
    if owner_ids:
        list(
            DownstreamProfile.objects.select_for_update()
            .filter(public_id__in=owner_ids)
            .order_by("public_id")
        )
        list(
            QuotaAccount.objects.select_for_update()
            .filter(downstream_public_id__in=owner_ids)
            .order_by("downstream_public_id")
        )


def _cards_page_payload(request: HttpRequest, cards, *, include_downstream: bool) -> dict:
    paginator = Paginator(cards, _page_size(request))
    page = paginator.get_page(_page_number(request))
    return {
        "items": [_card_payload(card, include_downstream=include_downstream) for card in page.object_list],
        "pagination": {
            "page": page.number,
            "page_size": paginator.per_page,
            "total": paginator.count,
            "total_pages": paginator.num_pages,
            "has_previous": page.has_previous(),
            "has_next": page.has_next(),
        },
    }


def _lookup_card_for_scope(*, card_public_id, actor, admin: bool):
    queryset = LicenseCard.objects.select_related(
        "software",
        "profile",
        "plan_snapshot",
        "current_downstream__user",
    )
    if not admin:
        profile = get_downstream_profile(actor)
        if not profile:
            raise LicenseOperationError("LICENSE_CARD_NOT_FOUND", "授权卡密不存在或不属于当前操作范围。")
        queryset = queryset.filter(current_downstream_public_id=profile.public_id)
    try:
        return queryset.get(public_id=card_public_id)
    except (LicenseCard.DoesNotExist, ValueError, TypeError) as exc:
        raise LicenseOperationError("LICENSE_CARD_NOT_FOUND", "授权卡密不存在或不属于当前操作范围。") from exc


def _search_card(request: HttpRequest, *, admin: bool, profile=None) -> JsonResponse:
    rate_limited = _license_rate_limit_response(
        request,
        scope="license-card-search-api",
        identity=f"{request.user.pk}:{_ip_address(request) or 'unknown'}:{'admin' if admin else profile.public_id}",
        limit=settings.LICENSE_CARD_SEARCH_RATE_LIMIT,
        action="license_card.search",
        message="授权卡密搜索过于频繁，请稍后再试。",
    )
    if rate_limited:
        return rate_limited
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    try:
        code = _required_string(payload or {}, "code", max_length=256)
        normalized = normalize_license_card_code(code)
        if len(normalized) < 8:
            raise LicenseOperationError("INVALID_REQUEST", "请填写完整授权卡密。")
        queryset = LicenseCard.objects.select_related(
            "software",
            "profile",
            "plan_snapshot",
            "current_downstream__user",
        ).exclude(status=LicenseCardStatus.DELETED_TOMBSTONE)
        if not admin:
            queryset = queryset.filter(current_downstream_public_id=profile.public_id).exclude(
                status=LicenseCardStatus.ARCHIVED
            )
        card = queryset.get(card_hash=license_card_hash(normalized))
    except LicenseCard.DoesNotExist:
        return _error(request, "LICENSE_CARD_NOT_FOUND", "授权卡密不存在或不属于当前操作范围。", status=404)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    return _success({"item": _card_payload(card, include_downstream=admin)})


def _reveal(request: HttpRequest, *, public_id, admin: bool, profile=None) -> JsonResponse:
    actor = request.user
    identity = f"{_ip_address(request) or 'unknown'}:{'admin' if admin else profile.public_id}"
    if not allow_rate("license-card-reveal-api", identity, limit=settings.LICENSE_CARD_REVEAL_RATE_LIMIT):
        record_event(
            actor=actor,
            action="license_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "license-card-reveal-api"},
        )
        response = _error(request, "RATE_LIMITED", "查看授权卡密过于频繁，请稍后再试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return response
    try:
        card, plaintext = reveal_license_card(
            actor=actor,
            card_public_id=public_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except PermissionDenied:
        return _error(request, "FORBIDDEN", "当前账号没有访问这张授权卡密的权限。", status=403)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    response = _success({"item": _card_payload(card, include_downstream=admin), "code": plaintext})
    response["Cache-Control"] = "no-store"
    return response


def _parse_card_ids(payload: dict) -> list[uuid.UUID]:
    raw_ids = payload.get("card_ids")
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > MAX_RECLAIM_COUNT:
        raise LicenseOperationError("INVALID_REQUEST", f"card_ids 必须是 1 至 {MAX_RECLAIM_COUNT} 个卡密 ID。")
    parsed: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for value in raw_ids:
        try:
            public_id = uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError) as exc:
            raise LicenseOperationError("INVALID_REQUEST", "卡密 ID 格式不正确。") from exc
        if public_id in seen:
            raise LicenseOperationError("INVALID_REQUEST", "card_ids 不能重复。")
        seen.add(public_id)
        parsed.append(public_id)
    return parsed


def _reclaim(request: HttpRequest, *, admin: bool, profile=None) -> JsonResponse:
    rate_limited = _license_rate_limit_response(
        request,
        scope="license-card-reclaim-api",
        identity=f"{request.user.pk}:{_ip_address(request) or 'unknown'}:{'admin' if admin else profile.public_id}",
        limit=settings.LICENSE_CARD_RECLAIM_RATE_LIMIT,
        action="license_card.reclaim",
        message="授权卡密回收过于频繁，请稍后再试。",
    )
    if rate_limited:
        return rate_limited
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        card_ids = _parse_card_ids(payload)
        reason = _required_string(payload, "reason", max_length=255)
        if len(reason) < 4:
            raise LicenseOperationError("INVALID_REASON", "回收原因至少需要 4 个字符。")
        request_hash = hashlib.sha256(
            json.dumps(
                {
                    "card_ids": sorted(str(value) for value in card_ids),
                    "reason": reason,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        actor = request.user
        with transaction.atomic():
            operation = LicenseReclaimOperation.objects.select_for_update().filter(
                actor=actor,
                idempotency_key=key,
            ).first()
            if operation is not None:
                if operation.request_hash != request_hash or operation.scope != ("admin" if admin else "downstream"):
                    raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的回收内容。")
                return _success(operation.response_payload)
            try:
                # Keep the unique-key race inside a savepoint. Catching an
                # IntegrityError directly in the outer atomic block leaves a
                # PostgreSQL transaction rollback-only and can turn a normal
                # idempotent replay into a 500.
                with transaction.atomic():
                    operation = LicenseReclaimOperation.objects.create(
                        actor=actor,
                        scope="admin" if admin else "downstream",
                        idempotency_key=key,
                        request_hash=request_hash,
                        response_payload={},
                    )
            except IntegrityError:
                try:
                    operation = LicenseReclaimOperation.objects.select_for_update().get(
                        actor=actor,
                        idempotency_key=key,
                    )
                except LicenseReclaimOperation.DoesNotExist as exc:
                    raise LicenseOperationError("RECLAIM_RETRYABLE", "回收请求正在处理中，请稍后重试。") from exc
                if operation.request_hash != request_hash or operation.scope != ("admin" if admin else "downstream"):
                    raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的回收内容。")
                return _success(operation.response_payload)

            card_ids = sorted(card_ids, key=str)
            _lock_reclaim_resources(card_ids, admin=admin, profile=profile)
            results = []
            refunded_quota = 0
            for card_id in card_ids:
                result = reclaim_license_card(
                    actor=actor,
                    card_public_id=card_id,
                    idempotency_key=f"license-card-reclaim:{card_id}",
                    reason=reason,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
                card = LicenseCard.objects.select_related(
                    "software",
                    "profile",
                    "plan_snapshot",
                    "current_downstream__user",
                ).get(public_id=card_id)
                results.append(_card_payload(card, include_downstream=admin))
                if result.entry is not None and not result.repeated:
                    refunded_quota += result.entry.amount
            response_payload = {
                "items": results,
                "reclaimed_count": len(results),
                "refunded_quota": refunded_quota,
                "repeated": all(item["reclaimed_at"] is not None and item["status"] == LicenseCardStatus.RECLAIMED for item in results)
                and refunded_quota == 0,
                "request_id": _request_id(request),
            }
            operation.response_payload = response_payload
            operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return _success(response_payload)
    except PermissionDenied:
        return _error(request, "FORBIDDEN", "当前账号没有访问这些授权卡密的权限。", status=403)
    except LicenseOperationError as exc:
        return _service_error(request, exc)


def _reclaim_preview(request: HttpRequest, *, admin: bool, profile=None) -> JsonResponse:
    rate_limited = _license_rate_limit_response(
        request,
        scope="license-card-reclaim-preview-api",
        identity=f"{request.user.pk}:{_ip_address(request) or 'unknown'}:{'admin' if admin else profile.public_id}",
        limit=settings.LICENSE_CARD_RECLAIM_RATE_LIMIT,
        action="license_card.reclaim_preview",
        message="授权卡密回收预览过于频繁，请稍后再试。",
    )
    if rate_limited:
        return rate_limited
    payload = {key: request.GET.get(key, "") for key in RECLAIM_FILTER_KEYS if key in request.GET}
    try:
        filters = _normalize_reclaim_filters({"filters": payload}, admin=admin)
        candidates = _reclaim_candidate_queryset(filters=filters, admin=admin, profile=profile)
        count = candidates.count()
        if count > MAX_RECLAIM_COUNT:
            raise LicenseOperationError("RECLAIM_TOO_MANY", f"当前筛选超过 {MAX_RECLAIM_COUNT} 张，请缩小范围。")
        refunded_quota = sum(candidates.values_list("quota_cost", flat=True))
        card_ids = [str(value) for value in candidates.values_list("public_id", flat=True)]
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    return _success(
        {
            "selection": "filtered",
            "filters": filters,
            "card_ids": card_ids,
            "reclaimable_count": count,
            "refundable_quota": refunded_quota,
        }
    )


@_api_methods("POST")
@_downstream_required
def api_downstream_license_preview(request: HttpRequest, profile) -> JsonResponse:
    rate_limited = _license_rate_limit_response(
        request,
        scope="license-card-preview-api",
        identity=f"{request.user.pk}:{_ip_address(request) or 'unknown'}:{profile.public_id}",
        limit=settings.LICENSE_CARD_PREVIEW_RATE_LIMIT,
        action="license_batch.preview",
        message="授权卡密成本预览过于频繁，请稍后再试。",
    )
    if rate_limited:
        return rate_limited
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        software_id = _required_string(payload, "software_id", max_length=64)
        plan_id = _integer(payload, "plan_id", minimum=1)
        quantity = _integer(payload, "quantity", minimum=1, maximum=settings.LICENSE_CARD_MAX_BATCH_SIZE)
        preview = preview_license_batch(
            actor=request.user,
            software_id=software_id,
            plan_id=plan_id,
            quantity=quantity,
        )
    except PermissionDenied:
        return _error(request, "FORBIDDEN", "当前账号没有生成授权卡密的权限。", status=403)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    return _success(_preview_payload(preview))


@_api_methods("POST")
@_downstream_required
def api_downstream_license_issue(request: HttpRequest, profile) -> JsonResponse:
    rate_limited = _license_rate_limit_response(
        request,
        scope="license-card-issue-api",
        identity=f"{request.user.pk}:{_ip_address(request) or 'unknown'}:{profile.public_id}",
        limit=settings.LICENSE_CARD_ISSUE_RATE_LIMIT,
        action="license_batch.issue",
        message="授权卡密发卡过于频繁，请稍后再试。",
    )
    if rate_limited:
        return rate_limited
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        software_id = _required_string(payload, "software_id", max_length=64)
        plan_snapshot_id = _required_string(payload, "plan_snapshot_id", max_length=64)
        quantity = _integer(payload, "quantity", minimum=1, maximum=settings.LICENSE_CARD_MAX_BATCH_SIZE)
        preview_token = _required_string(payload, "preview_token", max_length=4096)
        result = generate_license_batch(
            actor=request.user,
            software_id=software_id,
            plan_snapshot_id=plan_snapshot_id,
            quantity=quantity,
            idempotency_key=key,
            preview_token=preview_token,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        cards = LicenseCard.objects.select_related("software", "profile", "plan_snapshot", "current_downstream__user").filter(
            public_id__in=[item.public_id for item in result.cards]
        )
        card_by_id = {card.public_id: card for card in cards}
        code_by_id = {item.public_id: item.code for item in result.cards}
        items = [
            _card_payload(card_by_id[item.public_id], code=code_by_id[item.public_id])
            for item in result.cards
        ]
        balance = get_quota_account(profile).available_balance
    except PermissionDenied:
        return _error(request, "FORBIDDEN", "当前账号没有生成授权卡密的权限。", status=403)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    return _success(
        {
            "items": items,
            "quantity": len(items),
            "total_quota_cost": sum(item["quota_cost"] for item in items),
            "balance_after": balance,
            "repeated": result.repeated,
            "request_id": _request_id(request),
        },
        status=201,
    )


@_api_methods("GET")
@_downstream_required
def api_downstream_license_cards(request: HttpRequest, profile) -> JsonResponse:
    try:
        payload = _cards_page_payload(request, _filtered_cards(request, admin=False, profile=profile), include_downstream=False)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    payload["account"] = {"available_balance": get_quota_account(profile).available_balance}
    return _success(payload)


@_api_methods("GET")
@_downstream_required
def api_downstream_devices(request: HttpRequest, profile) -> JsonResponse:
    try:
        return _success(_downstream_authorization_page(request, profile))
    except AuthorizationOperationError as exc:
        return _authorization_admin_error(request, exc)


@_api_methods("POST")
@_downstream_required
def api_downstream_device_reset(request: HttpRequest, profile, authorization_id, device_id) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    reason, reason_error = _admin_action_reason(request)
    if reason_error:
        return reason_error
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    try:
        resolved_device_id = _resolve_downstream_device_id(
            device_id,
            authorization_id=authorization_id,
            downstream_public_id=profile.public_id,
        )
    except AuthorizationOperationError as error:
        if error.code == "DEVICE_ACTION_REF_INVALID":
            record_event(
                actor=request.user,
                action="device.reset",
                outcome=AuditOutcome.FAILURE,
                request_id=request_id,
                ip_address=ip_address,
                reason_code=error.code,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
                metadata={
                    "device_action_ref": redact_request_id(device_id),
                    "downstream_public_id": str(profile.public_id),
                    "before_state": "unknown",
                    "after_state": "unchanged",
                },
            )
        return _authorization_admin_error(request, error)
    request_hash = _downstream_device_request_hash(
        authorization_id=authorization_id,
        device_id=resolved_device_id,
        downstream_public_id=profile.public_id,
        reason=reason,
    )
    try:
        with transaction.atomic():
            operation = AuthorizationDeviceOperation.objects.select_for_update().filter(
                actor=request.user,
                idempotency_key=key,
            ).first()
            if operation is not None:
                if not _stored_downstream_device_operation_matches(
                    operation,
                    authorization_id=authorization_id,
                    device_id=resolved_device_id,
                    downstream_public_id=profile.public_id,
                    request_hash=request_hash,
                ):
                    raise AuthorizationOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的设备重置请求。", http_status=409)
                if not operation.response_payload:
                    raise AuthorizationOperationError("DEVICE_ACTION_RETRYABLE", "设备重置正在处理中，请稍后重试。", retryable=True, http_status=409)
                return _success(operation.response_payload)
            try:
                with transaction.atomic():
                    operation = AuthorizationDeviceOperation.objects.create(
                        actor=request.user,
                        downstream_public_id=profile.public_id,
                        action="reset",
                        authorization_id=authorization_id,
                        device_id=resolved_device_id,
                        idempotency_key=key,
                        request_hash=request_hash,
                        response_payload={},
                    )
            except IntegrityError:
                operation = AuthorizationDeviceOperation.objects.select_for_update().get(
                    actor=request.user,
                    idempotency_key=key,
                )
                if not _stored_downstream_device_operation_matches(
                    operation,
                    authorization_id=authorization_id,
                    device_id=resolved_device_id,
                    downstream_public_id=profile.public_id,
                    request_hash=request_hash,
                ):
                    raise AuthorizationOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的设备重置请求。", http_status=409)
                if not operation.response_payload:
                    raise AuthorizationOperationError("DEVICE_ACTION_RETRYABLE", "设备重置正在处理中，请稍后重试。", retryable=True, http_status=409)
                return _success(operation.response_payload)

            result = reset_device_binding(
                actor=request.user,
                authorization_id=authorization_id,
                device_id=resolved_device_id,
                reason=reason,
                request_id=request_id,
                ip_address=ip_address,
                scope_downstream_public_id=profile.public_id,
            )
            response_payload = _downstream_reset_payload(
                authorization_id=authorization_id,
                device_id=resolved_device_id,
                repeated=result.repeated,
            )
            operation.response_payload = response_payload
            operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return _success(response_payload)
    except AuthorizationOperationError as error:
        if error.code == "FORBIDDEN":
            record_event(
                actor=request.user,
                action="device.reset",
                outcome=AuditOutcome.FAILURE,
                request_id=request_id,
                ip_address=ip_address,
                reason_code=error.code,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
                metadata={
                    "device_id": redact_request_id(resolved_device_id),
                    "downstream_public_id": str(profile.public_id),
                    "before_state": "unknown",
                    "after_state": "unchanged",
                },
            )
        return _authorization_admin_error(request, error)
    except Device.DoesNotExist:
        return _authorization_admin_error(request, AuthorizationOperationError("DEVICE_NOT_FOUND", "设备不存在。", http_status=404))


@_api_methods("POST")
@_downstream_required
def api_downstream_license_card_search(request: HttpRequest, profile) -> JsonResponse:
    return _search_card(request, admin=False, profile=profile)


@_api_methods("POST")
@_downstream_required
def api_downstream_license_reveal(request: HttpRequest, profile, public_id) -> JsonResponse:
    return _reveal(request, public_id=public_id, admin=False, profile=profile)


@_api_methods("POST")
@_downstream_required
def api_downstream_license_reclaim(request: HttpRequest, profile) -> JsonResponse:
    return _reclaim(request, admin=False, profile=profile)


@_api_methods("GET")
@_downstream_required
def api_downstream_license_reclaim_preview(request: HttpRequest, profile) -> JsonResponse:
    return _reclaim_preview(request, admin=False, profile=profile)


@_api_methods("GET")
@_admin_required
def api_manage_license_cards(request: HttpRequest, identity) -> JsonResponse:
    try:
        payload = _cards_page_payload(request, _filtered_cards(request, admin=True), include_downstream=True)
        payload["scope"] = request.GET.get("scope", "current").strip().casefold() or "current"
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    return _success(payload)


@_api_methods("POST")
@_admin_required
def api_manage_license_card_search(request: HttpRequest, identity) -> JsonResponse:
    return _search_card(request, admin=True)


@_api_methods("POST")
@_admin_required
def api_manage_license_reveal(request: HttpRequest, identity, public_id) -> JsonResponse:
    return _reveal(request, public_id=public_id, admin=True)


@_api_methods("POST")
@_admin_required
def api_manage_license_reclaim(request: HttpRequest, identity) -> JsonResponse:
    return _reclaim(request, admin=True)


@_api_methods("GET")
@_admin_required
def api_manage_license_reclaim_preview(request: HttpRequest, identity) -> JsonResponse:
    return _reclaim_preview(request, admin=True)


def _lifecycle(request: HttpRequest, *, action: str) -> JsonResponse:
    rate_limited = _license_rate_limit_response(
        request,
        scope="license-card-lifecycle-api",
        identity=f"{request.user.pk}:{_ip_address(request) or 'unknown'}",
        limit=settings.LICENSE_CARD_LIFECYCLE_RATE_LIMIT,
        action=f"license_card.{action}",
        message="授权卡密归档或删除过于频繁，请稍后再试。",
    )
    if rate_limited:
        return rate_limited
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        card_ids = _parse_card_ids(payload)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    reason = str(payload.get("reason") or "").strip()
    request_id = request.headers.get("X-Request-ID")
    ip_address = _ip_address(request)
    try:
        if action == "archive":
            result = archive_license_cards(
                actor=request.user,
                card_ids=card_ids,
                reason=reason,
                idempotency_key=key,
                request_id=request_id,
                ip_address=ip_address,
            )
        else:
            result = delete_license_cards(
                actor=request.user,
                card_ids=card_ids,
                reason=reason,
                idempotency_key=key,
                request_id=request_id,
                ip_address=ip_address,
            )
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    return _success(result)


@_api_methods("POST")
@_admin_required
def api_manage_license_archive(request: HttpRequest, identity) -> JsonResponse:
    return _lifecycle(request, action="archive")


@_api_methods("POST")
@_admin_required
def api_manage_license_delete(request: HttpRequest, identity) -> JsonResponse:
    return _lifecycle(request, action="delete")


def _admin_identifier(value) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _client_device_code(device: Device | None) -> str | None:
    """Return the compact support code without changing authorization identity."""
    if device is None:
        return None
    stored = getattr(device, "device_code", None)
    if stored:
        return stored
    return compact_device_code(getattr(device, "installation_id", None)) or _admin_identifier(device.public_id)


def _table_search_tokens(query: str) -> list[str]:
    cleaned = (
        str(query or "")
        .replace("•", " ")
        .replace("*", " ")
        .replace("…", " ")
        .replace("...", " ")
    )
    return [part.strip() for part in re.split(r"[\s\-_/|]+", cleaned) if len(part.strip()) >= 2]


def _license_card_for_pasted_code(query: str, *, admin: bool, profile=None):
    normalized = normalize_license_card_code(query)
    if len(normalized) < 16:
        return None
    cards = LicenseCard.objects.exclude(status=LicenseCardStatus.DELETED_TOMBSTONE)
    if not admin:
        if profile is None:
            return None
        cards = cards.filter(current_downstream_public_id=profile.public_id).exclude(
            status=LicenseCardStatus.ARCHIVED
        )
    return cards.filter(card_hash=license_card_hash(normalized)).first()


def _admin_ip(value: str | None) -> str | None:
    if not value:
        return None
    return str(value)


_ADMIN_DEVICE_ACTION_PURPOSE = "admin-device-action.v2"
_DOWNSTREAM_DEVICE_ACTION_PURPOSE = "downstream-device-action.v2"


def _device_action_fernet(purpose: str) -> Fernet:
    material = hashlib.sha256(
        f"{settings.LICENSE_CARD_ENCRYPTION_KEY}|device-action|{purpose}".encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(material))


def _seal_device_action_ref(payload: dict, *, purpose: str) -> str:
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _device_action_fernet(purpose).encrypt(blob).decode("ascii")


def _open_device_action_ref(value, *, purpose: str, invalid_message: str) -> dict:
    try:
        raw = _device_action_fernet(purpose).decrypt(
            str(value).encode("ascii"),
            ttl=settings.AUTHORIZATION_ADMIN_ACTION_REF_TTL_SECONDS,
        )
        payload = json.loads(raw.decode("utf-8"))
    except (InvalidToken, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as extra:
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", invalid_message, http_status=400) from extra
    if not isinstance(payload, dict):
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", invalid_message, http_status=400)
    return payload


def _admin_device_action_ref(*, authorization_id, device_id) -> str:
    return _seal_device_action_ref(
        {
            "authorization_id": str(authorization_id),
            "device_id": str(device_id),
        },
        purpose=_ADMIN_DEVICE_ACTION_PURPOSE,
    )


def _resolve_admin_device_id(value, *, authorization_id=None, allow_raw=True):
    if allow_raw:
        try:
            return uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            pass
    payload = _open_device_action_ref(
        value,
        purpose=_ADMIN_DEVICE_ACTION_PURPOSE,
        invalid_message="设备操作引用已失效，请刷新设备与授权列表。",
    )
    if not payload.get("device_id"):
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", "设备操作引用不正确，请刷新设备与授权列表。", http_status=400)
    if authorization_id is not None and str(payload.get("authorization_id")) != str(authorization_id):
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", "设备操作引用与当前授权不匹配。", http_status=400)
    try:
        return uuid.UUID(str(payload["device_id"]))
    except (ValueError, AttributeError, TypeError) as extra:
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", "设备操作引用不正确，请刷新设备与授权列表。", http_status=400) from extra


def _downstream_device_action_ref(*, authorization_id, device_id, downstream_public_id) -> str:
    return _seal_device_action_ref(
        {
            "authorization_id": str(authorization_id),
            "device_id": str(device_id),
            "downstream_public_id": str(downstream_public_id),
        },
        purpose=_DOWNSTREAM_DEVICE_ACTION_PURPOSE,
    )


def _resolve_downstream_device_id(value, *, authorization_id, downstream_public_id):
    payload = _open_device_action_ref(
        value,
        purpose=_DOWNSTREAM_DEVICE_ACTION_PURPOSE,
        invalid_message="设备操作引用已失效，请刷新设备列表。",
    )
    if not payload.get("device_id"):
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", "设备操作引用不正确，请刷新设备列表。", http_status=400)
    if str(payload.get("authorization_id")) != str(authorization_id) or str(payload.get("downstream_public_id")) != str(downstream_public_id):
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", "设备操作引用与当前下游授权不匹配。", http_status=400)
    try:
        return uuid.UUID(str(payload["device_id"]))
    except (ValueError, AttributeError, TypeError) as extra:
        raise AuthorizationOperationError("DEVICE_ACTION_REF_INVALID", "设备操作引用不正确，请刷新设备列表。", http_status=400) from extra


def _admin_username(value: str | None) -> str | None:
    if not value:
        return None
    return str(value)


def _latest_binding(instance: LicenseInstance):
    bindings = DeviceBinding.objects.select_related("device").filter(authorization=instance)
    return (
        bindings.filter(state=DeviceBindingState.ACTIVE).in_history_order().first()
        or bindings.in_history_order().first()
    )


def _downstream_reset_payload(*, authorization_id, device_id, repeated: bool) -> dict:
    binding = (
        DeviceBinding.objects.filter(
            authorization_id=authorization_id,
            device__public_id=device_id,
        )
        .in_history_order()
        .first()
    )
    if binding is None:
        raise AuthorizationOperationError(
            "DEVICE_BINDING_NOT_FOUND",
            "该授权没有这台设备的历史绑定。",
            http_status=404,
        )
    return {
        "repeated": repeated,
        "authorization_id": str(authorization_id),
        "device": {
            "device_id": _admin_identifier(device_id),
            "binding_state": binding.state,
            "binding_state_label": binding.get_state_display(),
        },
    }


def _admin_binding_payload(binding: DeviceBinding) -> dict:
    device = binding.device
    device_uuid = _admin_identifier(device.public_id)
    device_code = _client_device_code(device)
    return {
        # device_id remains the internal UUID used to resolve actions.
        "device_id": device_uuid,
        "device_uuid": device_uuid,
        "installation_id": device.installation_id,
        "device_code": device_code,
        "device_action_ref": _admin_device_action_ref(
            authorization_id=binding.authorization_id,
            device_id=device.public_id,
        ),
        "device_label": device_code,
        "binding_state": binding.state,
        "binding_state_label": binding.get_state_display(),
        "risk_state": device.risk_state,
        "risk_state_label": device.get_risk_state_display(),
        "ip": _admin_ip(device.last_ip),
        "bound_at": binding.bound_at.isoformat() if binding.bound_at else None,
        "unbound_at": binding.unbound_at.isoformat() if binding.unbound_at else None,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "binding_order_known": binding.binding_order > 0,
    }


def _admin_authorization_devices(instance: LicenseInstance, selected_bindings=None, history_by_pair=None) -> list[dict]:
    """Return one current diagnostic row per physical device plus its history."""

    if history_by_pair is None:
        bindings = list(
            DeviceBinding.objects.select_related("device")
            .filter(authorization=instance)
            .in_history_order("device_id")
        )
        scoped_history = {(str(instance.authorization_id), str(binding.device_id)): [] for binding in bindings}
        for binding in bindings:
            scoped_history[(str(instance.authorization_id), str(binding.device_id))].append(binding)
    else:
        scoped_history = {
            key: value
            for key, value in history_by_pair.items()
            if key[0] == str(instance.authorization_id)
        }

    by_device = {
        device_id: history
        for (_authorization_id, device_id), history in scoped_history.items()
    }
    if selected_bindings is None:
        selected = [history[0] for history in by_device.values()]
    else:
        selected = list(selected_bindings)

    devices = []
    for latest in selected:
        history = by_device.get(str(latest.device_id), [latest])
        payload = _admin_binding_payload(latest)
        payload["binding_history"] = [_admin_binding_payload(item) for item in history]
        devices.append(payload)
    return sorted(
        devices,
        key=lambda item: (
            item["binding_state"] != "active",
            item["bound_at"] or "",
            item["device_id"],
        ),
    )


def _latest_device_binding_queryset():
    latest_binding_id = (
        DeviceBinding.objects.filter(
            authorization_id=OuterRef("authorization_id"),
            device_id=OuterRef("device_id"),
        )
        .in_history_order()
        .values("binding_id")[:1]
    )
    return DeviceBinding.objects.annotate(
        latest_binding_id=Subquery(latest_binding_id),
    ).filter(binding_id=F("latest_binding_id"))


def _admin_authorization_device_rows(*, search: str, filters: dict, now=None) -> tuple[list[DeviceBinding], int]:
    now = now or timezone.now()
    bindings = _latest_device_binding_queryset().select_related(
        "device",
        "authorization__software",
        "authorization__profile",
        "authorization__plan_snapshot",
        "authorization__license_card",
        "authorization__license_card__current_downstream__user",
        "authorization__policy_version",
    )
    if filters.get("status"):
        status = filters["status"]
        if status == AuthorizationState.EXPIRED:
            bindings = bindings.filter(
                Q(authorization__state=AuthorizationState.EXPIRED)
                | Q(
                    authorization__state__in={AuthorizationState.ACTIVE, AuthorizationState.GRACE},
                    authorization__expires_at__lte=now,
                )
            )
        elif status in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
            bindings = bindings.filter(authorization__state=status).filter(
                Q(authorization__expires_at__isnull=True) | Q(authorization__expires_at__gt=now)
            )
        else:
            bindings = bindings.filter(authorization__state=status)
    if filters.get("software_id"):
        bindings = bindings.filter(authorization__software_id=filters["software_id"])
    if filters.get("downstream_public_id"):
        bindings = bindings.filter(authorization__current_downstream_public_id=filters["downstream_public_id"])
    if filters.get("device_state") == "bound":
        bindings = bindings.filter(state=DeviceBindingState.ACTIVE)
    elif filters.get("device_state") == "blocked":
        bindings = bindings.filter(state=DeviceBindingState.BLOCKED)
    elif filters.get("device_state") == "unbound":
        bindings = bindings.filter(state=DeviceBindingState.UNBOUND)
    if filters.get("risk_state"):
        bindings = bindings.filter(device__risk_state=filters["risk_state"])
    expiry = filters.get("expiry_state")
    if expiry:
        if expiry == "expired":
            bindings = bindings.filter(authorization__expires_at__lte=now)
        elif expiry == "soon":
            bindings = bindings.filter(authorization__expires_at__gt=now, authorization__expires_at__lte=now + timedelta(days=7))
        elif expiry == "long":
            bindings = bindings.filter(authorization__expires_at__gt=now + timedelta(days=30))

    normalized_query = str(search or "").strip()
    if normalized_query:
        pasted_card = _license_card_for_pasted_code(normalized_query, admin=True)
        if pasted_card is not None:
            bindings = bindings.filter(authorization__license_card=pasted_card)
        else:
            tokens = _table_search_tokens(normalized_query)
            if not tokens:
                bindings = bindings.none()
            else:
                identifier_filter = Q()
                first = True
                for token in tokens:
                    token_filter = (
                        Q(authorization_id_text__icontains=token)
                        | Q(card_id_text__icontains=token)
                        | Q(downstream_id_text__icontains=token)
                        | Q(device_id_text__icontains=token)
                        | Q(device_installation_id__icontains=token)
                        | Q(device_code_text__icontains=token)
                        | Q(authorization__software__software_id__icontains=token)
                        | Q(authorization__software__name__icontains=token)
                        | Q(authorization__profile__profile_id__icontains=token)
                        | Q(authorization__plan_snapshot__name__icontains=token)
                        | Q(authorization__license_card__current_downstream__user__username__icontains=token)
                        | Q(device__last_ip__icontains=token)
                    )
                    identifier_filter = token_filter if first else identifier_filter & token_filter
                    first = False
                bindings = bindings.annotate(
                    authorization_id_text=Cast("authorization__authorization_id", CharField()),
                    card_id_text=Cast("authorization__license_card__public_id", CharField()),
                    downstream_id_text=Cast("authorization__current_downstream_public_id", CharField()),
                    device_id_text=Cast("device__public_id", CharField()),
                    device_installation_id=F("device__installation_id"),
                    device_code_text=F("device__device_code"),
                ).filter(identifier_filter)
    bindings = bindings.in_history_order(
        "-authorization__updated_at",
        "authorization_id",
        "device_id",
    )
    return bindings, bindings.count()


def _group_admin_device_rows(rows: list[DeviceBinding]) -> list[dict]:
    grouped: dict[str, tuple[LicenseInstance, list[DeviceBinding]]] = {}
    for binding in rows:
        key = str(binding.authorization_id)
        if key not in grouped:
            grouped[key] = (binding.authorization, [])
        grouped[key][1].append(binding)
    history_by_pair: dict[tuple[str, str], list[DeviceBinding]] = {}
    if grouped:
        history_rows = (
            DeviceBinding.objects.select_related("device")
            .filter(authorization_id__in=grouped.keys())
            .in_history_order("authorization_id", "device_id")
        )
        for binding in history_rows:
            history_by_pair.setdefault((str(binding.authorization_id), str(binding.device_id)), []).append(binding)
    items = []
    for instance, selected_bindings in grouped.values():
        devices = _admin_authorization_devices(instance, selected_bindings, history_by_pair)
        items.append(
            _admin_authorization_payload(
                instance,
                devices=devices,
                latest_binding=selected_bindings[0] if selected_bindings else None,
            )
        )
    return items


def _admin_authorization_payload(instance: LicenseInstance, devices=None, latest_binding=None) -> dict:
    card = instance.license_card
    device_items = devices if devices is not None else _admin_authorization_devices(instance)
    binding = latest_binding or _latest_binding(instance)
    device = binding.device if binding is not None else None
    downstream = card.current_downstream
    username = downstream.user.username if downstream is not None else None
    first_device = device_items[0] if device_items else None
    payload = {
        "authorization_id": str(instance.authorization_id),
        "masked_code": f"••••-••••-{_card_code_suffix(card)}",
        "software_name": instance.software.name,
        "software_id": instance.software.software_id,
        "profile_id": instance.profile.profile_id,
        "plan_name": instance.plan_snapshot.name,
        "status": instance.state,
        "status_label": instance.get_state_display(),
        "card_status": card.status,
        "card_status_label": card.get_status_display(),
        "audit_reference": f"aud-{str(instance.authorization_id)[:3]}…{str(instance.authorization_id)[-3:]}",
        "expires_at": instance.expires_at.isoformat(),
        "activated_at": instance.activated_at.isoformat(),
        "last_verified_at": instance.last_verified_at.isoformat() if instance.last_verified_at else None,
        "authorization_revision": instance.authorization_revision,
        "downstream_username": _admin_username(username),
        "downstream_public_id": str(card.current_downstream_public_id) if card.current_downstream_public_id else None,
        "devices": device_items,
        "device_id": first_device["device_id"] if first_device else (_admin_identifier(device.public_id) if device is not None else None),
        "device_action_ref": first_device["device_action_ref"] if first_device else (_admin_device_action_ref(
            authorization_id=instance.authorization_id,
            device_id=device.public_id,
        ) if device is not None else None),
        "device_code": first_device["device_code"] if first_device else (_client_device_code(device) if device is not None else None),
        "installation_id": first_device["installation_id"] if first_device else (device.installation_id if device is not None else None),
        "device_uuid": first_device["device_uuid"] if first_device else (_admin_identifier(device.public_id) if device is not None else None),
        "device_label": first_device["device_label"] if first_device else (_client_device_code(device) if device is not None else None),
        "device_binding_state": first_device["binding_state"] if first_device else (binding.state if binding is not None else "unbound"),
        "device_binding_state_label": first_device["binding_state_label"] if first_device else (binding.get_state_display() if binding is not None else "未绑定"),
        "device_risk_state": first_device["risk_state"] if first_device else (device.risk_state if device is not None else None),
        "device_risk_state_label": first_device["risk_state_label"] if first_device else (device.get_risk_state_display() if device is not None else "未产生"),
        "device_ip": first_device["ip"] if first_device else (_admin_ip(device.last_ip) if device is not None else None),
        "device_bound_at": first_device["bound_at"] if first_device else (binding.bound_at.isoformat() if binding is not None else None),
        "device_last_seen_at": first_device["last_seen_at"] if first_device else (device.last_seen_at.isoformat() if device is not None else None),
        "card_frozen": authorization_card_is_frozen(instance),
        "time_rollback_blocked": is_time_rollback_blocked(instance),
        "verify_interval_seconds": current_verify_interval_seconds(
            instance.profile,
            fallback=int(getattr(getattr(instance, "policy_version", None), "verify_interval_seconds", 0) or 0),
        ),
    }
    nominal_expires = instance.activated_at + timedelta(seconds=int(instance.plan_snapshot.duration_seconds))
    added_seconds = max(0, int((instance.expires_at - nominal_expires).total_seconds()))
    payload["is_renewed"] = added_seconds > 0
    payload["renewal_added_seconds"] = added_seconds
    if added_seconds >= 86400:
        days = added_seconds // 86400
        payload["renewal_tag"] = f"已补时 +{days}天"
    elif added_seconds >= 3600:
        hours = added_seconds // 3600
        payload["renewal_tag"] = f"已补时 +{hours}小时"
    else:
        payload["renewal_tag"] = ""
    return payload


def _downstream_authorization_page(request: HttpRequest, profile) -> dict:
    page = _page_number(request)
    page_size = min(_page_size(request), 100)
    search = request.GET.get("q", "").strip()
    if len(search) > 128:
        raise AuthorizationOperationError("INVALID_QUERY", "搜索内容不能超过 128 个字符。", http_status=400)
    queryset = _latest_device_binding_queryset().select_related(
        "device",
        "authorization__software",
        "authorization__profile",
        "authorization__plan_snapshot",
        "authorization__license_card",
    ).filter(authorization__current_downstream_public_id=profile.public_id)
    if search:
        pasted_card = _license_card_for_pasted_code(search, admin=False, profile=profile)
        if pasted_card is not None:
            queryset = queryset.filter(authorization__license_card=pasted_card)
        else:
            tokens = _table_search_tokens(search)
            if not tokens:
                queryset = queryset.none()
            else:
                identifier_filter = Q()
                first = True
                for token in tokens:
                    token_filter = (
                        Q(authorization_id_text__icontains=token)
                        | Q(card_id_text__icontains=token)
                        | Q(device_id_text__icontains=token)
                        | Q(device_installation_id__icontains=token)
                        | Q(device_code_text__icontains=token)
                        | Q(authorization__software__software_id__icontains=token)
                        | Q(authorization__software__name__icontains=token)
                        | Q(authorization__plan_snapshot__name__icontains=token)
                    )
                    identifier_filter = token_filter if first else identifier_filter & token_filter
                    first = False
                queryset = queryset.annotate(
                    authorization_id_text=Cast("authorization__authorization_id", CharField()),
                    card_id_text=Cast("authorization__license_card__public_id", CharField()),
                    device_id_text=Cast("device__public_id", CharField()),
                    device_installation_id=F("device__installation_id"),
                    device_code_text=F("device__device_code"),
                ).filter(identifier_filter)
    queryset = queryset.in_history_order(
        "-authorization__updated_at",
        "authorization_id",
        "device_id",
    )
    paginator = Paginator(queryset, page_size)
    page_obj = paginator.get_page(page)
    items = []
    for binding in page_obj.object_list:
        instance = binding.authorization
        device = binding.device
        reset_allowed = (
            binding.state == "active"
            and device.risk_state != "blocked"
            and instance.state in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}
            and not authorization_card_is_frozen(instance)
        )
        items.append(
            {
                "authorization_id": str(instance.authorization_id),
                "masked_code": f"••••-••••-{_card_code_suffix(instance.license_card)}",
                "software_name": instance.software.name,
                "plan_name": instance.plan_snapshot.name,
                # device_id stays the UUID for reset/block/unblock resolution;
                # device_code is the value shown to support and end users.
                "device_id": _admin_identifier(device.public_id),
                "device_uuid": _admin_identifier(device.public_id),
                "installation_id": device.installation_id,
                "device_code": _client_device_code(device),
                "device_label": _client_device_code(device),
                "device_ip": _admin_ip(device.last_ip),
                "device_action_ref": _downstream_device_action_ref(
                    authorization_id=instance.authorization_id,
                    device_id=device.public_id,
                    downstream_public_id=profile.public_id,
                ),
                "binding_state": binding.state,
                "binding_state_label": binding.get_state_display(),
                "risk_state": device.risk_state,
                "risk_state_label": device.get_risk_state_display(),
                "last_verified_at": instance.last_verified_at.isoformat() if instance.last_verified_at else None,
                "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
                "bound_at": binding.bound_at.isoformat() if binding.bound_at else None,
                "expires_at": instance.expires_at.isoformat(),
                "status": instance.state,
                "status_label": instance.get_state_display(),
                "reset_allowed": reset_allowed,
            }
        )
    return {
        "items": items,
        "pagination": {
            "page": page_obj.number,
            "page_size": paginator.per_page,
            "total": paginator.count,
            "total_pages": paginator.num_pages,
            "has_previous": page_obj.has_previous(),
            "has_next": page_obj.has_next(),
            "query": search,
        },
    }


def _downstream_device_request_hash(*, authorization_id, device_id, downstream_public_id, reason: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "action": "device.reset",
                "authorization_id": str(authorization_id),
                "device_id": str(device_id),
                "downstream_public_id": str(downstream_public_id),
                "reason": reason,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _stored_downstream_device_operation_matches(
    operation: AuthorizationDeviceOperation,
    *,
    authorization_id,
    device_id,
    downstream_public_id,
    request_hash: str,
) -> bool:
    return (
        operation.action == "reset"
        and operation.authorization_id == authorization_id
        and operation.device_id == device_id
        and operation.downstream_public_id == downstream_public_id
        and operation.request_hash == request_hash
    )


def _admin_risk_signal_payload(signal) -> dict:
    return {
        "signal_id": str(signal.public_id),
        "occurred_at": signal.occurred_at.isoformat(),
        "action": signal.action,
        "reason_code": signal.reason_code,
        "object_type": signal.object_type or None,
        "object_id": _admin_identifier(signal.object_public_id),
        "request_id": redact_request_id(signal.request_id),
    }


def _authorization_admin_error(request: HttpRequest, error: AuthorizationOperationError) -> JsonResponse:
    return _error(
        request,
        error.code,
        error.message,
        status=error.http_status,
        retryable=error.retryable,
    )


def _admin_action_audit_name(action: str) -> str:
    return {
        "revoke": "authorization.revoke",
        "reset": "device.reset",
        "block": "device.block",
        "unblock": "device.unblock",
    }.get(action, "authorization.admin")


def _admin_action_reason(request: HttpRequest) -> tuple[str | None, JsonResponse | None]:
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return None, parse_error
    raw_reason = (payload or {}).get("reason")
    if not isinstance(raw_reason, str):
        return None, _error(request, "INVALID_REASON", "请填写至少 2 个字的原因。", status=400)
    reason = raw_reason.strip()
    if len(reason) < 2 or len(reason) > 255:
        return None, _error(request, "INVALID_REASON", "请填写 2 至 255 个字的原因。", status=400)
    return reason, None


def _admin_action_request_hash(*, action: str, authorization_id, device_id, reason: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "action": action,
                "authorization_id": str(authorization_id) if authorization_id is not None else None,
                "device_id": str(device_id) if device_id is not None else None,
                "reason": reason,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _stored_admin_operation_matches(
    operation: AuthorizationAdminOperation,
    *,
    action: str,
    authorization_id,
    device_id,
    request_hash: str,
) -> bool:
    return (
        operation.action == action
        and operation.authorization_id == authorization_id
        and operation.device_id == device_id
        and operation.request_hash == request_hash
    )


def _authorization_admin_filters(request: HttpRequest) -> tuple[dict, JsonResponse | None]:
    fields = {
        "status": request.GET.get("status", "").strip(),
        "software_id": request.GET.get("software_id", "").strip().casefold(),
        "downstream_public_id": request.GET.get("downstream_public_id", "").strip(),
        "device_state": request.GET.get("device_state", "").strip(),
        "risk_state": request.GET.get("risk_state", "").strip(),
        "expiry_state": request.GET.get("expiry_state", "").strip(),
    }
    if len(fields["software_id"]) > 64 or len(fields["downstream_public_id"]) > 64:
        return {}, _error(request, "INVALID_QUERY", "设备筛选内容过长。", status=400)
    if fields["downstream_public_id"]:
        try:
            fields["downstream_public_id"] = str(uuid.UUID(fields["downstream_public_id"]))
        except (ValueError, TypeError):
            return {}, _error(request, "INVALID_QUERY", "下游筛选标识不正确。", status=400)
    allowed = {
        "status": {"", "active", "grace", "expired", "revoked", "blocked"},
        "device_state": {"", "bound", "blocked", "unbound"},
        "risk_state": {"", "normal", "blocked"},
        "expiry_state": {"", "soon", "expired", "long"},
    }
    for key, values in allowed.items():
        if fields[key] not in values:
            return {}, _error(request, "INVALID_QUERY", "设备筛选条件不正确。", status=400)
    return {key: value for key, value in fields.items() if value}, None


def _admin_device_payload(device_id) -> dict:
    """One row per physical device with all of its authorizations attached."""
    try:
        device = Device.objects.get(pk=device_id)
    except Device.DoesNotExist as exc:
        raise AuthorizationOperationError("DEVICE_NOT_FOUND", "设备不存在。", http_status=404) from exc
    pair_bindings = list(
        _latest_device_binding_queryset().select_related(
            "device",
            "authorization__software",
            "authorization__profile",
            "authorization__plan_snapshot",
            "authorization__license_card",
            "authorization__license_card__current_downstream__user",
            "authorization__policy_version",
        )
        .filter(device=device)
        .in_history_order()
    )
    authorizations = _group_admin_device_rows(pair_bindings)
    return {
        "device_id": str(device.public_id),
        "device_uuid": _admin_identifier(device.public_id),
        "installation_id": device.installation_id,
        "device_code": _client_device_code(device),
        "risk_state": device.risk_state,
        "last_ip": _admin_ip(device.last_ip),
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "authorization_count": len(authorizations),
        "authorizations": authorizations,
    }


@_api_methods("GET")
@_admin_required
def api_manage_authorizations(request: HttpRequest, identity) -> JsonResponse:
    page = _page_number(request)
    page_size = min(_page_size(request), 100)
    search = request.GET.get("q", "").strip()
    if len(search) > 128:
        return _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
    filters, filter_error = _authorization_admin_filters(request)
    if filter_error:
        return filter_error
    try:
        device_bindings, _binding_total = _admin_authorization_device_rows(search=search, filters=filters)
        # Paginate by distinct authorization (not binding): one authorization renders
        # one row, so its devices must never split across pages and total must count
        # authorizations to match the rows shown.
        auth_order = (
            device_bindings.order_by()
            .values("authorization_id")
            .annotate(last_updated=Max("authorization__updated_at"))
            .order_by("-last_updated", "authorization_id")
        )
        auth_ids = [row["authorization_id"] for row in auth_order]
        paginator = Paginator(auth_ids, page_size)
        page_obj = paginator.get_page(page)
        page_ids = list(page_obj.object_list)
        page_bindings = (
            list(
                device_bindings.filter(authorization_id__in=page_ids).in_history_order(
                    "-authorization__updated_at",
                    "authorization_id",
                    "device_id",
                )
            )
            if page_ids
            else []
        )
        items = _group_admin_device_rows(page_bindings)
        position = {str(authorization_id): index for index, authorization_id in enumerate(page_ids)}
        items.sort(key=lambda entry: position.get(str(entry["authorization_id"]), 0))
    except AuthorizationOperationError as exc:
        return _error(request, exc.code, exc.message, status=exc.http_status)
    signals = list(list_risk_signals_for_admin(actor=identity, limit=50))
    return _success(
        {
            "items": items,
            "risk_signals": [_admin_risk_signal_payload(signal) for signal in signals],
            "pagination": {
                "page": page_obj.number,
                "page_size": paginator.per_page,
                "total": paginator.count,
                "total_pages": paginator.num_pages,
                "has_previous": page_obj.has_previous(),
                "has_next": page_obj.has_next(),
                "query": search,
                "filters": filters,
            },
        }
    )


def _run_admin_authorization_action(request: HttpRequest, *, action: str, authorization_id=None, device_id=None) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    reason, reason_error = _admin_action_reason(request)
    if reason_error:
        return reason_error
    request_hash = _admin_action_request_hash(
        action=action,
        authorization_id=authorization_id,
        device_id=device_id,
        reason=reason,
    )
    request_id = _request_id(request)
    ip_address = _ip_address(request)
    try:
        actor = request.user
        with transaction.atomic():
            operation = AuthorizationAdminOperation.objects.select_for_update().filter(
                actor=actor,
                idempotency_key=key,
            ).first()
            if operation is not None:
                if not _stored_admin_operation_matches(
                    operation,
                    action=action,
                    authorization_id=authorization_id,
                    device_id=device_id,
                    request_hash=request_hash,
                ):
                    raise AuthorizationOperationError(
                        "IDEMPOTENCY_CONFLICT",
                        "同一个幂等键不能对应不同的管理动作或目标。",
                        http_status=409,
                    )
                if not operation.response_payload:
                    raise AuthorizationOperationError(
                        "ADMIN_ACTION_RETRYABLE",
                        "管理动作正在处理中，请稍后重试。",
                        retryable=True,
                        http_status=409,
                    )
                return _success(operation.response_payload)

            try:
                # Keep the unique-key race inside a savepoint.  The outer
                # transaction must remain usable when another worker wins.
                with transaction.atomic():
                    operation = AuthorizationAdminOperation.objects.create(
                        actor=actor,
                        action=action,
                        authorization_id=authorization_id,
                        device_id=device_id,
                        idempotency_key=key,
                        request_hash=request_hash,
                        response_payload={},
                    )
            except IntegrityError:
                try:
                    operation = AuthorizationAdminOperation.objects.select_for_update().get(
                        actor=actor,
                        idempotency_key=key,
                    )
                except AuthorizationAdminOperation.DoesNotExist as exc:
                    raise AuthorizationOperationError(
                        "ADMIN_ACTION_RETRYABLE",
                        "管理动作正在处理中，请稍后重试。",
                        retryable=True,
                        http_status=409,
                    ) from exc
                if not _stored_admin_operation_matches(
                    operation,
                    action=action,
                    authorization_id=authorization_id,
                    device_id=device_id,
                    request_hash=request_hash,
                ):
                    raise AuthorizationOperationError(
                        "IDEMPOTENCY_CONFLICT",
                        "同一个幂等键不能对应不同的管理动作或目标。",
                        http_status=409,
                    )
                if not operation.response_payload:
                    raise AuthorizationOperationError(
                        "ADMIN_ACTION_RETRYABLE",
                        "管理动作正在处理中，请稍后重试。",
                        retryable=True,
                        http_status=409,
                    )
                return _success(operation.response_payload)

            if action == "revoke":
                result = revoke_authorization(
                    actor=actor,
                    authorization_id=authorization_id,
                    reason=reason,
                    request_id=request_id,
                    ip_address=ip_address,
                )
                instance = (
                    LicenseInstance.objects.select_related("software", "profile", "plan_snapshot", "policy_version", "license_card", "license_card__current_downstream__user")
                    .get(authorization_id=result.authorization_id)
                )
                response_payload = {"repeated": result.repeated, "item": _admin_authorization_payload(instance)}
            elif action == "reset":
                result = reset_device_binding(
                    actor=actor,
                    authorization_id=authorization_id,
                    device_id=device_id,
                    reason=reason,
                    request_id=request_id,
                    ip_address=ip_address,
                )
                device = Device.objects.get(public_id=result.device_id)
                response_payload = {
                    "repeated": result.repeated,
                    "device": {
                        "device_id": _admin_identifier(device.public_id),
                        "device_uuid": _admin_identifier(device.public_id),
                        "installation_id": device.installation_id,
                        "device_code": _client_device_code(device),
                        "device_label": _client_device_code(device),
                        "risk_state": device.risk_state,
                        "risk_state_label": device.get_risk_state_display(),
                    },
                }
            elif action == "block":
                result = block_device(
                    actor=actor,
                    authorization_id=authorization_id,
                    device_id=device_id,
                    reason=reason,
                    request_id=request_id,
                    ip_address=ip_address,
                )
                instance = (
                    LicenseInstance.objects.select_related(
                        "software",
                        "profile",
                        "plan_snapshot",
                        "policy_version",
                        "license_card",
                        "license_card__current_downstream__user",
                    ).get(authorization_id=result.authorization_id)
                )
                device = Device.objects.get(public_id=result.device_id)
                response_payload = {
                    "repeated": result.repeated,
                    "item": _admin_authorization_payload(instance),
                    "device": {
                        "device_id": _admin_identifier(device.public_id),
                        "device_uuid": _admin_identifier(device.public_id),
                        "installation_id": device.installation_id,
                        "device_code": _client_device_code(device),
                        "device_label": _client_device_code(device),
                        "risk_state": device.risk_state,
                        "risk_state_label": device.get_risk_state_display(),
                    },
                }
            elif action == "unblock":
                result = unblock_device(
                    actor=actor,
                    authorization_id=authorization_id,
                    device_id=device_id,
                    reason=reason,
                    request_id=request_id,
                    ip_address=ip_address,
                )
                instance = (
                    LicenseInstance.objects.select_related(
                        "software",
                        "profile",
                        "plan_snapshot",
                        "policy_version",
                        "license_card",
                        "license_card__current_downstream__user",
                    ).get(authorization_id=result.authorization_id)
                )
                device = Device.objects.get(public_id=result.device_id)
                response_payload = {
                    "repeated": result.repeated,
                    "item": _admin_authorization_payload(instance),
                    "device": {
                        "device_id": _admin_identifier(device.public_id),
                        "device_uuid": _admin_identifier(device.public_id),
                        "installation_id": device.installation_id,
                        "device_code": _client_device_code(device),
                        "device_label": _client_device_code(device),
                        "risk_state": device.risk_state,
                        "risk_state_label": device.get_risk_state_display(),
                    },
                }
            else:
                raise AuthorizationOperationError("INVALID_REQUEST", "管理动作不受支持。", http_status=400)

            operation.response_payload = response_payload
            operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return _success(response_payload)
    except (AuthorizationOperationError, Device.DoesNotExist) as error:
        if isinstance(error, Device.DoesNotExist):
            error = AuthorizationOperationError("DEVICE_NOT_FOUND", "设备不存在。", http_status=404)
        if error.code != "FORBIDDEN":
            try:
                record_event(
                    actor=request.user,
                    action=_admin_action_audit_name(action),
                    outcome=AuditOutcome.FAILURE,
                    request_id=request_id,
                    ip_address=ip_address,
                    reason_code=error.code,
                    object_type="LicenseInstance" if authorization_id is not None else "Device",
                    object_public_id=authorization_id if authorization_id is not None else device_id,
                    metadata={
                        "action": action,
                        "authorization_id": str(authorization_id) if authorization_id is not None else None,
                        "device_id": str(device_id) if device_id is not None else None,
                        "before_state": "unknown",
                        "after_state": "unchanged",
                    },
                )
            except Exception:
                pass
        return _authorization_admin_error(request, error)


@_api_methods("POST")
@_admin_required
def api_manage_authorization_revoke(request: HttpRequest, identity, authorization_id) -> JsonResponse:
    return _run_admin_authorization_action(request, action="revoke", authorization_id=authorization_id)


@_api_methods("POST")
@_admin_required
def api_manage_authorization_device_reset(request: HttpRequest, identity, authorization_id, device_id) -> JsonResponse:
    try:
        resolved_device_id = _resolve_admin_device_id(device_id, authorization_id=authorization_id, allow_raw=False)
    except AuthorizationOperationError as error:
        _record_admin_device_ref_failure(request, action="reset", authorization_id=authorization_id, error=error)
        return _authorization_admin_error(request, error)
    return _run_admin_authorization_action(request, action="reset", authorization_id=authorization_id, device_id=resolved_device_id)


@_api_methods("POST")
@_admin_required
def api_manage_authorization_device_block(request: HttpRequest, identity, authorization_id, device_id) -> JsonResponse:
    try:
        resolved_device_id = _resolve_admin_device_id(device_id, authorization_id=authorization_id, allow_raw=False)
    except AuthorizationOperationError as error:
        _record_admin_device_ref_failure(request, action="block", authorization_id=authorization_id, error=error)
        return _authorization_admin_error(request, error)
    return _run_admin_authorization_action(
        request,
        action="block",
        authorization_id=authorization_id,
        device_id=resolved_device_id,
    )


@_api_methods("POST")
@_admin_required
def api_manage_authorization_device_unblock(request: HttpRequest, identity, authorization_id, device_id) -> JsonResponse:
    try:
        resolved_device_id = _resolve_admin_device_id(device_id, authorization_id=authorization_id, allow_raw=False)
    except AuthorizationOperationError as error:
        _record_admin_device_ref_failure(request, action="unblock", authorization_id=authorization_id, error=error)
        return _authorization_admin_error(request, error)
    return _run_admin_authorization_action(
        request,
        action="unblock",
        authorization_id=authorization_id,
        device_id=resolved_device_id,
    )


def _record_admin_device_ref_failure(request: HttpRequest, *, action: str, authorization_id, error: AuthorizationOperationError) -> None:
    try:
        record_event(
            actor=request.user,
            action="device.reset",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code=error.code,
            object_type="LicenseInstance",
            object_public_id=authorization_id,
            metadata={
                "action": action,
                "authorization_id": str(authorization_id),
            },
        )
    except Exception:
        pass

def _license_export_csv(request: HttpRequest, *, admin: bool, profile=None) -> HttpResponse:
    import csv as csv_module
    import io

    try:
        cards = _filtered_cards(request, admin=admin, profile=profile)
    except LicenseOperationError as exc:
        return _service_error(request, exc)
    if not admin:
        cards = cards.filter(current_downstream_public_id=profile.public_id)
    cards = cards.select_related("software", "profile", "plan_snapshot", "current_downstream__user")
    total = cards.count()
    truncated = total > LICENSE_EXPORT_LIMIT
    exported = list(cards[:LICENSE_EXPORT_LIMIT])
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(csv_safe_row(["公开ID", "尾号", "状态", "软件", "Profile", "套餐", "当前下游", "额度成本", "发行时间", "激活时间", "到期时间"]))
    for card in exported:
        writer.writerow(
            csv_safe_row([
                str(card.public_id),
                _card_code_suffix(card) or "????",
                card.get_status_display(),
                card.software.name if card.software else "",
                card.profile.profile_id if card.profile else "",
                card.plan_snapshot.name if card.plan_snapshot else "",
                card.current_downstream.user.username if card.current_downstream and card.current_downstream.user else "",
                card.quota_cost,
                format_beijing_wall_clock(card.issued_at),
                format_beijing_wall_clock(card.activated_at),
                format_beijing_wall_clock(card.expires_at),
            ])
        )
    record_event(
        actor=request.user if request.user.is_authenticated else None,
        action="license_card.export",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        metadata={"exported": len(exported), "total": total, "truncated": truncated, "admin": admin},
    )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="license-cards.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    if truncated:
        response["X-Export-Truncated"] = "1"
        response["X-Export-Total"] = str(total)
    return response


@_api_methods("GET")
@_admin_required
def api_manage_license_export(request: HttpRequest, identity) -> HttpResponse:
    return _license_export_csv(request, admin=True)


@_api_methods("GET")
@_downstream_required
def api_downstream_license_export(request: HttpRequest, profile) -> HttpResponse:
    return _license_export_csv(request, admin=False, profile=profile)

@_api_methods("GET")
@_admin_required
def api_manage_authorizations_export(request: HttpRequest, identity) -> HttpResponse:
    import csv as csv_module
    import io

    search = request.GET.get("q", "").strip()
    if len(search) > 128:
        return _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
    filters, filter_error = _authorization_admin_filters(request)
    if filter_error:
        return filter_error
    try:
        device_bindings, total = _admin_authorization_device_rows(search=search, filters=filters)
        truncated = total > AUTHORIZATION_EXPORT_LIMIT
        bindings = list(device_bindings[:AUTHORIZATION_EXPORT_LIMIT])
    except AuthorizationOperationError as exc:
        return _error(request, exc.code, exc.message, status=exc.http_status)
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(csv_safe_row(["授权ID", "卡密尾号", "软件", "当前下游", "设备", "绑定状态", "风险", "状态", "激活时间", "到期时间", "最后验证"]))
    for binding in bindings:
        instance = binding.authorization
        device = _admin_binding_payload(binding)
        writer.writerow(
            csv_safe_row([
                str(instance.authorization_id),
                _card_code_suffix(instance.license_card),
                getattr(instance.software, "name", "") if getattr(instance, "software", None) else "",
                _admin_username(instance.license_card.current_downstream.user.username) if instance.license_card.current_downstream and instance.license_card.current_downstream.user else "已删除下游",
                device["device_label"] or "—",
                device["binding_state_label"],
                device["risk_state_label"],
                instance.get_state_display(),
                format_beijing_wall_clock(instance.activated_at),
                format_beijing_wall_clock(instance.expires_at),
                format_beijing_wall_clock(instance.last_verified_at),
            ])
        )
    record_event(
        actor=request.user if request.user.is_authenticated else None,
        action="authorization.export",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        metadata={"exported": len(bindings), "total": total, "truncated": truncated, "query": search, "filters": filters},
    )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="authorizations.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    if truncated:
        response["X-Export-Truncated"] = "1"
        response["X-Export-Total"] = str(total)
    return response


# ---------------------------------------------------------------------------
# 批量续期（ADR-0016）
# ---------------------------------------------------------------------------


def _renewal_candidate_queryset(*, search: str, filters: dict, now):
    """Intersect the unpaginated list projection with renewal eligibility.

    All search/device/risk predicates apply to the same latest device row.
    Projecting IDs first avoids joining separate historical binding aliases.
    """
    rows, _total = _admin_authorization_device_rows(search=search, filters=filters, now=now)
    return (
        LicenseInstance.objects.select_related(
            "software", "profile", "plan_snapshot", "license_card",
            "license_card__current_downstream__user",
        ).filter(
            authorization_id__in=rows.order_by().values("authorization_id"),
            state__in=(AuthorizationState.ACTIVE, AuthorizationState.GRACE),
            expires_at__gt=now,
            license_card__status=LicenseCardStatus.ACTIVATED,
        ).order_by("expires_at", "authorization_id")
    )


def _renewal_item_payload(instance: LicenseInstance, added_seconds: int) -> dict:
    card = instance.license_card
    return {
        "authorization_id": str(instance.authorization_id),
        "masked_code": f"••••-••••-{_card_code_suffix(card)}",
        "software_name": instance.software.name,
        "software_id": instance.software.software_id,
        "plan_name": instance.plan_snapshot.name,
        "downstream_username": _admin_username(
            card.current_downstream.user.username if card.current_downstream_id else None
        ),
        "status": instance.state,
        "status_label": instance.get_state_display(),
        "expires_at": instance.expires_at.isoformat(),
        "new_expires_at": (instance.expires_at + timedelta(seconds=added_seconds)).isoformat(),
    }


def _parse_batch_authorization_ids(
    payload: dict,
    action_label: str = "处理",
    error_code_prefix: str = "BATCH",
) -> tuple[list, tuple[str, str] | None]:
    raw = payload.get("authorization_ids")
    if raw is None or (isinstance(raw, list) and not raw):
        return [], ("INVALID_REQUEST", f"请先选择要{action_label}的授权。")
    if not isinstance(raw, list):
        return [], ("INVALID_REQUEST", f"授权标识必须是数组，请重新勾选要{action_label}的授权。")
    seen: list = []
    for position, value in enumerate(raw, start=1):
        try:
            parsed = uuid.UUID(str(value))
        except (ValueError, TypeError, AttributeError):
            return [], ("INVALID_REQUEST", f"第 {position} 条授权标识不正确，请关闭重选。")
        if parsed not in seen:
            seen.append(parsed)
    if len(seen) > MAX_RENEWAL_BATCH:
        return [], (f"{error_code_prefix}_TOO_MANY", f"一次最多{action_label} {MAX_RENEWAL_BATCH} 条，请缩小范围。")
    return seen, None


def _parse_renewal_ids(payload: dict) -> tuple[list, tuple[str, str] | None]:
    return _parse_batch_authorization_ids(payload, action_label="续期", error_code_prefix="RENEWAL")


@_api_methods("GET")
@_admin_required
def api_manage_authorization_renew_preview(request: HttpRequest, identity) -> JsonResponse:
    """Freeze the current filter into an explicit list of renewable authorizations."""

    filters, filter_error = _authorization_admin_filters(request)
    if filter_error:
        return filter_error
    search = request.GET.get("q", "").strip()
    if len(search) > 128:
        return _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
    try:
        added_seconds = renewal_seconds(request.GET.get("unit", ""), request.GET.get("amount", ""))
    except AuthorizationOperationError as exc:
        return _error(request, exc.code, exc.message, status=exc.http_status)
    try:
        amount = int(request.GET.get("amount"))
    except (TypeError, ValueError):
        amount = 0
    now = timezone.now()
    candidates = _renewal_candidate_queryset(search=search, filters=filters, now=now)
    total = candidates.count()
    if total > MAX_RENEWAL_BATCH:
        return _error(
            request,
            "RENEWAL_TOO_MANY",
            f"当前筛选有 {total} 条，一次最多续期 {MAX_RENEWAL_BATCH} 条，请缩小范围。",
            status=400,
        )
    renewable = [
        instance
        for instance in candidates[:MAX_RENEWAL_BATCH]
        if instance.expires_at + timedelta(seconds=added_seconds)
        <= instance.activated_at + timedelta(seconds=MAX_RENEWAL_TOTAL_SECONDS)
    ]
    items = [_renewal_item_payload(instance, added_seconds) for instance in renewable]
    return _success(
        {
            "authorization_ids": [item["authorization_id"] for item in items],
            "items": items,
            "renewable_count": len(items),
            "added_seconds": added_seconds,
            "unit": str(request.GET.get("unit") or "").strip().casefold(),
            "amount": amount,
            "filters": filters,
            "query": search,
            "request_id": _request_id(request),
        }
    )


def _freeze_admin_batch_targets(action, authorization_ids):
    """Freeze every physical target before the first state-changing item."""
    if action in {"renew", "bulk_revoke"}:
        return [{"authorization_ids": [str(value)]} for value in authorization_ids]
    state = DeviceBindingState.ACTIVE if action == "bulk_block" else DeviceBindingState.BLOCKED
    pairs = list(DeviceBinding.objects.filter(
        authorization_id__in=authorization_ids, state=state,
    ).in_history_order("authorization_id").values_list("authorization_id", "device_id"))
    devices_by_auth = {}
    for authorization_id, device_id in pairs:
        devices_by_auth.setdefault(str(authorization_id), {})[str(device_id)] = None
    existing_ids = set(str(value) for value in LicenseInstance.objects.filter(
        authorization_id__in=authorization_ids,
    ).values_list("authorization_id", flat=True))
    targets = []
    by_device = {}
    for value in authorization_ids:
        auth_id = str(value)
        device_ids = devices_by_auth.get(auth_id, {})
        if not device_ids:
            code = "AUTHORIZATION_NOT_FOUND" if auth_id not in existing_ids else (
                "DEVICE_NOT_BOUND" if action == "bulk_block" else "DEVICE_NOT_BLOCKED"
            )
            targets.append({"authorization_ids": [auth_id], "error": {
                "code": code, "message": "授权不存在或没有符合条件的设备绑定，已跳过。",
            }})
        for device_id in device_ids:
            if device_id not in by_device:
                target = {"device_id": device_id, "authorization_ids": []}
                by_device[device_id] = target
                targets.append(target)
            by_device[device_id]["authorization_ids"].append(auth_id)
    return targets


def _admin_batch_failure(*, actor, action, target, error, request_id, ip_address):
    audit_action = {"renew": "authorization.extend", "bulk_revoke": "authorization.revoke",
                    "bulk_block": "device.block", "bulk_unblock": "device.unblock"}[action]
    failures = []
    for auth_id in target["authorization_ids"]:
        entry = {"authorization_id": auth_id, "code": error.code, "message": error.message}
        if target.get("device_id"):
            entry["device_id"] = target["device_id"]
        failures.append(entry)
        record_event(
            actor=actor, action=audit_action, outcome=AuditOutcome.FAILURE,
            request_id=request_id, ip_address=ip_address, reason_code=error.code,
            object_type="LicenseInstance", object_public_id=auth_id,
            metadata={"batch": True, **entry},
        )
    return {"items": [], "failures": failures}


def _execute_admin_batch_target(*, actor, action, target, reason, request_id, ip_address, added_seconds):
    common = dict(actor=actor, reason=reason, request_id=request_id, ip_address=ip_address)
    auth_id = target["authorization_ids"][0]
    if target.get("error"):
        raise AuthorizationOperationError(**target["error"])
    if action == "renew":
        result = extend_authorization(authorization_id=auth_id, added_seconds=added_seconds, **common)
        instance = LicenseInstance.objects.select_related(
            "software", "profile", "plan_snapshot", "license_card", "license_card__current_downstream__user",
        ).get(pk=auth_id)
        item = _renewal_item_payload(instance, 0)
        item["new_expires_at"] = result.new_expires_at.isoformat()
        items = [item]
    elif action == "bulk_revoke":
        result = revoke_authorization(authorization_id=auth_id, **common)
        items = [{"authorization_id": auth_id, "status": "already_revoked" if result.repeated else "revoked"}]
    else:
        service = block_physical_device if action == "bulk_block" else unblock_physical_device
        result = service(device_id=target["device_id"], **common)
        status = "blocked" if action == "bulk_block" else ("already_unblocked" if result.repeated else "unblocked")
        items = [{"authorization_id": value, "device_id": target["device_id"], "status": status}
                 for value in target["authorization_ids"]]
    return {"items": items, "failures": []}


def _run_resumable_admin_batch(request, *, actor, key, action, request_hash, authorization_ids,
                               reason, request_id, ip_address, added_seconds=0, unit=None):
    # The parent row is a short-lived per-item mutex, never a batch-long
    # transaction. Its JSON records the frozen mapping and each committed fact.
    with transaction.atomic():
        operation, _created = AuthorizationAdminOperation.objects.select_for_update().get_or_create(
            actor=actor, idempotency_key=key,
            defaults=dict(action=action, request_hash=request_hash, response_payload={}),
        )
        if operation.action != action or operation.request_hash != request_hash:
            return _error(request, "IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的批量内容。", status=409)
        if _created:
            operation.response_payload = {"_batch": {
                "targets": _freeze_admin_batch_targets(action, authorization_ids),
                "results": {}, "request_id": request_id,
            }}
            operation.save(update_fields=("response_payload",), _allow_mutation=True)
        elif not operation.response_payload:
            # Legacy empty reservations have no per-item facts to safely infer.
            code = "RENEWAL_RETRYABLE" if action == "renew" else "ADMIN_ACTION_RETRYABLE"
            return _error(request, code, "旧请求缺少逐项进度，需核对原操作结果。", status=409, retryable=True)
        if "_batch" not in operation.response_payload:
            return _success({**operation.response_payload, "repeated": True})
        targets = operation.response_payload["_batch"]["targets"]

    for index, target in enumerate(targets):
        with transaction.atomic():
            operation = AuthorizationAdminOperation.objects.select_for_update().get(pk=operation.pk)
            progress = operation.response_payload.get("_batch")
            if progress is None:
                return _success({**operation.response_payload, "repeated": True})
            if str(index) in progress["results"]:
                continue
            try:
                # Roll back the item even if an exception occurs after the
                # nested business service has returned but before recording it.
                with transaction.atomic():
                    result = _execute_admin_batch_target(
                        actor=actor, action=action, target=target, reason=reason,
                        request_id=progress["request_id"], ip_address=ip_address, added_seconds=added_seconds,
                    )
            except AuthorizationOperationError as exc:
                result = _admin_batch_failure(
                    actor=actor, action=action, target=target, error=exc,
                    request_id=progress["request_id"], ip_address=ip_address,
                )
            progress["results"][str(index)] = result
            operation.save(update_fields=("response_payload",), _allow_mutation=True)

    with transaction.atomic():
        operation = AuthorizationAdminOperation.objects.select_for_update().get(pk=operation.pk)
        progress = operation.response_payload.get("_batch")
        if progress is None:
            return _success({**operation.response_payload, "repeated": True})
        results = [progress["results"][str(index)] for index in range(len(targets))]
        items = [entry for result in results for entry in result["items"]]
        failures = [entry for result in results for entry in result["failures"]]
        response = dict(items=items, failures=failures, failed_count=len(failures),
                        repeated=False, request_id=progress["request_id"])
        if action == "renew":
            response.update(renewed_count=len(items), added_seconds=added_seconds, unit=unit)
        elif action == "bulk_revoke":
            response["revoked_count"] = sum(item["status"] == "revoked" for item in items)
        elif action == "bulk_block":
            response["blocked_count"] = len(items)
        else:
            response["unblocked_count"] = sum(item["status"] == "unblocked" for item in items)
        operation.response_payload = response
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
    return _success(response)


@_api_methods("POST")
@_admin_required
def api_manage_authorization_renew(request: HttpRequest, identity) -> JsonResponse:
    """Extend every explicitly submitted authorization by the same amount."""

    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    authorization_ids, id_error = _parse_renewal_ids(payload)
    if id_error is not None:
        return _error(request, id_error[0], id_error[1], status=400)
    reason = str(payload.get("reason") or "").strip()
    if len(reason) < 2 or len(reason) > 255:
        return _error(request, "INVALID_REASON", "请填写 2 至 255 个字的续期原因。", status=400)
    unit = str(payload.get("unit") or "").strip().casefold()
    try:
        added_seconds = renewal_seconds(unit, payload.get("amount"))
    except AuthorizationOperationError as exc:
        return _error(request, exc.code, exc.message, status=exc.http_status)

    request_id = _request_id(request)
    ip_address = _ip_address(request)
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "action": "renew",
                "authorization_ids": sorted(str(value) for value in authorization_ids),
                "added_seconds": added_seconds,
                "reason": reason,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    actor = request.user

    return _run_resumable_admin_batch(
        request, actor=actor, key=key, action="renew", request_hash=request_hash,
        authorization_ids=authorization_ids, reason=reason,
        request_id=request_id, ip_address=ip_address, added_seconds=added_seconds, unit=unit,
    )


@_api_methods("POST")
@_admin_required
def api_manage_authorization_bulk_revoke(request: HttpRequest, identity) -> JsonResponse:
    """Revoke multiple authorizations in one batch operation."""
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    authorization_ids, id_error = _parse_batch_authorization_ids(payload, action_label="撤销", error_code_prefix="REVOKE")
    if id_error is not None:
        return _error(request, id_error[0], id_error[1], status=400)
    reason = str(payload.get("reason") or "").strip()
    if len(reason) < 2 or len(reason) > 255:
        return _error(request, "INVALID_REASON", "请填写 2 至 255 个字的撤销原因。", status=400)

    request_id = _request_id(request)
    ip_address = _ip_address(request)
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "action": "bulk_revoke",
                "authorization_ids": sorted(str(value) for value in authorization_ids),
                "reason": reason,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    actor = request.user

    return _run_resumable_admin_batch(
        request, actor=actor, key=key, action="bulk_revoke", request_hash=request_hash,
        authorization_ids=authorization_ids, reason=reason,
        request_id=request_id, ip_address=ip_address,
    )


@_api_methods("POST")
@_admin_required
def api_manage_authorization_bulk_block(request: HttpRequest, identity) -> JsonResponse:
    """Block active devices associated with multiple authorizations in one batch."""
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    authorization_ids, id_error = _parse_batch_authorization_ids(payload, action_label="封禁设备", error_code_prefix="BLOCK")
    if id_error is not None:
        return _error(request, id_error[0], id_error[1], status=400)
    reason = str(payload.get("reason") or "").strip()
    if len(reason) < 2 or len(reason) > 255:
        return _error(request, "INVALID_REASON", "请填写 2 至 255 个字的封禁原因。", status=400)

    request_id = _request_id(request)
    ip_address = _ip_address(request)
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "action": "bulk_block",
                "authorization_ids": sorted(str(value) for value in authorization_ids),
                "reason": reason,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    actor = request.user

    return _run_resumable_admin_batch(
        request, actor=actor, key=key, action="bulk_block", request_hash=request_hash,
        authorization_ids=authorization_ids, reason=reason,
        request_id=request_id, ip_address=ip_address,
    )


@_api_methods("POST")
@_admin_required
def api_manage_authorization_bulk_unblock(request: HttpRequest, identity) -> JsonResponse:
    """Unblock physical devices associated with multiple authorizations in one batch."""
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_api_json(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    authorization_ids, id_error = _parse_batch_authorization_ids(payload, action_label="解封设备", error_code_prefix="UNBLOCK")
    if id_error is not None:
        return _error(request, id_error[0], id_error[1], status=400)
    reason = str(payload.get("reason") or "").strip()
    if len(reason) < 2 or len(reason) > 255:
        return _error(request, "INVALID_REASON", "请填写 2 至 255 个字的解封原因。", status=400)

    request_id = _request_id(request)
    ip_address = _ip_address(request)
    request_hash = hashlib.sha256(
        json.dumps(
            {
                "action": "bulk_unblock",
                "authorization_ids": sorted(str(value) for value in authorization_ids),
                "reason": reason,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    actor = request.user

    return _run_resumable_admin_batch(
        request, actor=actor, key=key, action="bulk_unblock", request_hash=request_hash,
        authorization_ids=authorization_ids, reason=reason,
        request_id=request_id, ip_address=ip_address,
    )
