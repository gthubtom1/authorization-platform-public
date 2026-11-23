"""Product-neutral administrator actions for authorization risk control.

These actions are deliberately separate from the public client API.  They
change server-side facts, keep historical rows and write an auditable record.
Freezing a card occupies its current seats without unbinding them.  Client
applications can only observe the result through the existing authorization.v1
response.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps

from django.db import connection, transaction
from django.db.models import CharField, Q
from django.db.models.functions import Cast
from django.utils import timezone

from authorization_platform.accounts.services import is_platform_admin
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.core.time import as_utc

from .models import (
    Device,
    DeviceBinding,
    DeviceBindingState,
    DeviceRiskState,
    LicenseCard,
    LicenseCardStatus,
    LicenseInstance,
    AuthorizationState,
)
from .authorization import (
    TIME_ROLLBACK_BINDING_REASON,
    AuthorizationOperationError,
    is_time_rollback_blocked,
)


@dataclass(frozen=True)
class AuthorizationAdminActionResult:
    """The durable object changed by an administrator action."""

    authorization_id: object | None = None
    device_id: object | None = None
    repeated: bool = False


# High-signal authorization failures that deserve administrator review.  These
# are deliberately separate from hard enforcement: proof/identity failures
# alone must not silently block a customer, while replay and rollback controls
# already fail closed in the authorization service.
RISK_REVIEW_REASON_CODES = (
    "DEVICE_PROOF_INVALID",
    "DEVICE_PROOF_REQUIRED",
    "DEVICE_KEY_REUSED",
    "DEVICE_KEY_MISMATCH",
    "PROFILE_MISMATCH",
    "REPLAY_DETECTED",
    "TIME_ROLLBACK_DETECTED",
)


def authorization_card_is_frozen(instance: LicenseInstance) -> bool:
    """True when this card is frozen: instance blocked, seats still occupied."""

    return instance.state == AuthorizationState.BLOCKED and DeviceBinding.objects.filter(
        authorization=instance,
        state=DeviceBindingState.ACTIVE,
    ).exists()


# How many times a physical-device action retries when a concurrent activation
# adds a binding for an instance the transaction had not locked yet.
_PHYSICAL_DEVICE_LOCK_RETRIES = 5


def _device_pk_or_404(device_id):
    """Resolve a device PK without taking a lock, mapping bad input to 404.

    ``filter(...).first()`` never raises DoesNotExist, and a malformed UUID
    raises ValidationError rather than ValueError, so both cases are handled
    explicitly instead of leaking a 500.
    """

    from django.core.exceptions import ValidationError

    try:
        found = Device.objects.filter(pk=device_id).only("pk").first()
    except (ValidationError, ValueError, TypeError):
        found = None
    if found is None:
        raise AuthorizationOperationError("DEVICE_NOT_FOUND", "设备不存在。", http_status=404)
    return found


def redact_request_id(value: str | None) -> str:
    """Return a stable non-sensitive correlation value for administrator UI."""

    if not value:
        return "unknown"
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def _require_platform_admin(
    actor,
    *,
    action: str = "authorization.admin",
    request_id: str | None = None,
    ip_address: str | None = None,
) -> None:
    if not is_platform_admin(actor):
        try:
            record_event(
                actor=actor,
                action=action,
                outcome=AuditOutcome.FAILURE,
                request_id=redact_request_id(request_id),
                ip_address=ip_address,
                reason_code="FORBIDDEN",
                metadata={"admin_action_denied": True},
            )
        except Exception:
            pass
        raise AuthorizationOperationError("FORBIDDEN", "只有平台管理员可以执行该操作。", http_status=403)


def _reason(value: str) -> str:
    if not isinstance(value, str):
        raise AuthorizationOperationError("INVALID_REASON", "请填写至少 2 个字的原因。", http_status=400)
    value = value.strip()
    if len(value) < 2 or len(value) > 255:
        raise AuthorizationOperationError("INVALID_REASON", "请填写 2 至 255 个字的原因。", http_status=400)
    return value


def _record_admin_failure(
    *,
    actor,
    action: str,
    reason_code: str,
    request_id: str | None,
    ip_address: str | None,
    object_type: str,
    object_public_id,
    metadata: dict | None = None,
) -> None:
    """Record a failed administrator action without hiding the real error."""

    try:
        record_event(
            actor=actor,
            action=action,
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=reason_code,
            object_type=object_type,
            object_public_id=object_public_id,
            metadata={"before_state": "unknown", "after_state": "unchanged", **(metadata or {})},
        )
    except Exception:
        # Auditing must never turn a deterministic business error into a 500.
        pass


def _audit_admin_failures(action: str, *, object_type: str, target_key: str):
    """Persist service-layer failures after the business transaction rolls back."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            try:
                return view(*args, **kwargs)
            except AuthorizationOperationError as error:
                if error.code != "FORBIDDEN" and not connection.in_atomic_block:
                    target = kwargs.get(target_key)
                    _record_admin_failure(
                        actor=kwargs.get("actor"),
                        action=action,
                        reason_code=error.code,
                        request_id=kwargs.get("request_id"),
                        ip_address=kwargs.get("ip_address"),
                        object_type=object_type,
                        object_public_id=target,
                        metadata={
                            "action": action,
                            target_key: str(target) if target is not None else None,
                        },
                    )
                raise

        return wrapped

    return decorator


def _now(value: datetime | None) -> datetime:
    current = as_utc(value or timezone.now())
    return current.replace(microsecond=0)


def list_authorizations_for_admin(
    *,
    actor,
    limit: int = 100,
    offset: int = 0,
    query: str = "",
    filters: dict | None = None,
):
    _require_platform_admin(actor, action="authorization.admin_list")
    limit = max(1, min(int(limit), 201))
    offset = max(0, int(offset))
    queryset = (
        LicenseInstance.objects.select_related("software", "profile", "license_card")
        .prefetch_related("device_bindings__device")
    )
    if filters:
        if filters.get("status"):
            queryset = queryset.filter(state=filters["status"])
        if filters.get("software_id"):
            queryset = queryset.filter(software_id=filters["software_id"])
        if filters.get("downstream_public_id"):
            queryset = queryset.filter(current_downstream_public_id=filters["downstream_public_id"])
        if filters.get("device_state") == "bound":
            queryset = queryset.filter(device_bindings__state="active")
        elif filters.get("device_state") == "blocked":
            queryset = queryset.filter(device_bindings__device__risk_state="blocked")
        elif filters.get("device_state") == "unbound":
            queryset = queryset.exclude(device_bindings__state="active")
        if filters.get("risk_state") in {"normal", "blocked"}:
            queryset = queryset.filter(device_bindings__device__risk_state=filters["risk_state"])
        expiry = filters.get("expiry_state")
        if expiry:
            now = timezone.now()
            if expiry == "expired":
                queryset = queryset.filter(expires_at__lte=now)
            elif expiry == "soon":
                queryset = queryset.filter(expires_at__gt=now, expires_at__lte=now + timedelta(days=7))
            elif expiry == "long":
                queryset = queryset.filter(expires_at__gt=now + timedelta(days=30))

    normalized_query = str(query or "").strip()
    if normalized_query:
        if len(normalized_query) > 128:
            raise AuthorizationOperationError("INVALID_QUERY", "搜索内容不能超过 128 个字符。", http_status=400)
        identifier_query = normalized_query.replace("-", "")
        identifier_filter = (
            Q(authorization_id_text__icontains=normalized_query)
            | Q(card_id_text__icontains=normalized_query)
            | Q(downstream_id_text__icontains=normalized_query)
            | Q(device_id_text__icontains=normalized_query)
            | Q(device_bindings__device__installation_id__icontains=normalized_query)
            | Q(device_bindings__device__device_code__icontains=normalized_query)
        )
        if identifier_query != normalized_query:
            identifier_filter |= (
                Q(authorization_id_text__icontains=identifier_query)
                | Q(card_id_text__icontains=identifier_query)
                | Q(downstream_id_text__icontains=identifier_query)
                | Q(device_id_text__icontains=identifier_query)
                | Q(device_bindings__device__installation_id__icontains=identifier_query)
                | Q(device_bindings__device__device_code__icontains=identifier_query)
            )
        queryset = queryset.annotate(
            authorization_id_text=Cast("authorization_id", CharField()),
            card_id_text=Cast("license_card__public_id", CharField()),
            downstream_id_text=Cast("current_downstream_public_id", CharField()),
            device_id_text=Cast("device_bindings__device__public_id", CharField()),
        ).filter(
            identifier_filter
            | Q(software__software_id__icontains=normalized_query)
            | Q(software__name__icontains=normalized_query)
            | Q(profile__profile_id__icontains=normalized_query)
            | Q(plan_snapshot__name__icontains=normalized_query)
            | Q(license_card__current_downstream__user__username__icontains=normalized_query)
            | Q(device_bindings__device__last_ip__icontains=normalized_query)
        ).distinct()
    return queryset.order_by("-updated_at", "authorization_id")[offset : offset + limit]


def list_devices_for_admin(*, actor, limit: int = 100):
    _require_platform_admin(actor, action="device.admin_list")
    return Device.objects.select_related("software", "profile").prefetch_related("authorization_bindings").order_by("-last_seen_at", "public_id")[:limit]


def list_risk_signals_for_admin(*, actor, limit: int = 50):
    """Return recent high-signal failures for human review only.

    A signal is not an automatic ban.  The authorization service owns the
    fail-closed decisions for replay, rollback and device risk; this list only
    gives an administrator a bounded, product-neutral review queue.
    """

    _require_platform_admin(actor, action="authorization.risk_list")
    limit = max(1, min(int(limit), 200))
    return (
        AuditEvent.objects.filter(
            outcome=AuditOutcome.FAILURE,
            reason_code__in=RISK_REVIEW_REASON_CODES,
        )
        .order_by("-occurred_at", "-public_id")[:limit]
    )


@_audit_admin_failures("authorization.revoke", object_type="LicenseInstance", target_key="authorization_id")
def revoke_authorization(
    *,
    actor,
    authorization_id,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuthorizationAdminActionResult:
    """Revoke one authorization and invalidate its card and active bindings."""

    _require_platform_admin(actor, action="authorization.revoke", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    current_time = _now(now)
    with transaction.atomic():
        try:
            reference = LicenseInstance.objects.only("license_card_id").get(authorization_id=authorization_id)
        except LicenseInstance.DoesNotExist as exc:
            _record_admin_failure(
                actor=actor,
                action="authorization.revoke",
                reason_code="AUTHORIZATION_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
            )
            raise AuthorizationOperationError("AUTHORIZATION_NOT_FOUND", "授权实例不存在。", http_status=404) from exc

        # Keep the global write order aligned with activation and device risk
        # actions: card -> authorization instance -> device -> binding.
        card = LicenseCard.objects.select_for_update().get(pk=reference.license_card_id)
        instance = LicenseInstance.objects.select_for_update().get(authorization_id=authorization_id)

        if card.status in {LicenseCardStatus.ARCHIVED, LicenseCardStatus.DELETED_TOMBSTONE}:
            frozen_code = "CARD_ARCHIVED" if card.status == LicenseCardStatus.ARCHIVED else "CARD_DELETED"
            _record_admin_failure(
                actor=actor,
                action="authorization.revoke",
                reason_code=frozen_code,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
            )
            raise AuthorizationOperationError(frozen_code, "授权卡密已归档或已删除，按不存在处理，不能撤销。", http_status=409)

        if instance.state == AuthorizationState.REVOKED:
            record_event(
                actor=actor,
                action="authorization.revoke",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "repeated": True,
                    "reason": reason,
                    "effective_at": current_time.isoformat(),
                    "before_state": AuthorizationState.REVOKED,
                    "after_state": AuthorizationState.REVOKED,
                    "before_revision": instance.authorization_revision,
                    "after_revision": instance.authorization_revision,
                    "card_status_before": card.status,
                    "card_status_after": card.status,
                    "binding_active_before": 0,
                    "binding_active_after": 0,
                },
            )
            return AuthorizationAdminActionResult(authorization_id=instance.authorization_id, repeated=True)

        before_state = instance.state
        before_revision = instance.authorization_revision
        before_card_status = card.status
        instance.state = AuthorizationState.REVOKED
        instance.authorization_revision += 1
        instance.revoked_at = current_time
        instance.last_server_time = max(filter(None, (instance.last_server_time, current_time)), default=current_time)
        instance.state_reason = reason
        instance.save(
            update_fields=("state", "authorization_revision", "revoked_at", "last_server_time", "state_reason", "updated_at"),
            _allow_mutation=True,
        )

        if card.status != LicenseCardStatus.RECLAIMED:
            card.status = LicenseCardStatus.REVOKED
            card.revoked_at = current_time
            card.status_reason = reason
            card.save(update_fields=("status", "revoked_at", "status_reason"), _allow_mutation=True)

        bindings = list(
            DeviceBinding.objects.select_for_update()
            .filter(authorization=instance, state=DeviceBindingState.ACTIVE)
            .in_history_order().reverse()
        )
        for binding in bindings:
            binding.state = DeviceBindingState.BLOCKED
            binding.unbound_at = current_time
            binding.reason = reason
            binding.save(update_fields=("state", "unbound_at", "reason"), _allow_mutation=True)

        record_event(
            actor=actor,
            action="authorization.revoke",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseInstance",
            object_public_id=instance.authorization_id,
            metadata={
                "reason": reason,
                "reason_length": len(reason),
                "binding_count": len(bindings),
                "effective_at": current_time.isoformat(),
                "repeated": False,
                "before_state": before_state,
                "after_state": instance.state,
                "before_revision": before_revision,
                "after_revision": instance.authorization_revision,
                "card_status_before": before_card_status,
                "card_status_after": card.status,
                "binding_active_before": len(bindings),
                "binding_active_after": 0,
            },
        )
        return AuthorizationAdminActionResult(authorization_id=instance.authorization_id)


def _lock_authorization_device(*, authorization_id, device_id, action: str, actor, request_id, ip_address):
    try:
        reference = LicenseInstance.objects.only("license_card_id", "software_id", "profile_id").get(
            authorization_id=authorization_id
        )
    except LicenseInstance.DoesNotExist as exc:
        _record_admin_failure(
            actor=actor,
            action=action,
            reason_code="AUTHORIZATION_NOT_FOUND",
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseInstance",
            object_public_id=authorization_id,
            metadata={"device_id": str(device_id) if device_id is not None else None},
        )
        raise AuthorizationOperationError("AUTHORIZATION_NOT_FOUND", "授权实例不存在。", http_status=404) from exc

    card = LicenseCard.objects.select_for_update().get(pk=reference.license_card_id)
    instance = LicenseInstance.objects.select_for_update().get(authorization_id=authorization_id)
    device = None
    if device_id is not None:
        try:
            device = Device.objects.select_for_update().get(
                public_id=device_id,
                software_id=instance.software_id,
                profile_id=instance.profile_id,
            )
        except Device.DoesNotExist as exc:
            _record_admin_failure(
                actor=actor,
                action=action,
                reason_code="DEVICE_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="Device",
                object_public_id=device_id,
                metadata={"authorization_id": str(authorization_id)},
            )
            raise AuthorizationOperationError("DEVICE_NOT_FOUND", "设备不存在或不属于该授权。", http_status=404) from exc
        binding = (
            DeviceBinding.objects.select_for_update()
            .filter(authorization=instance, device=device)
            .in_history_order()
            .first()
        )
        if binding is None:
            _record_admin_failure(
                actor=actor,
                action=action,
                reason_code="DEVICE_BINDING_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
                metadata={"device_id": str(device_id)},
            )
            raise AuthorizationOperationError("DEVICE_BINDING_NOT_FOUND", "该授权没有这台设备的历史绑定。", http_status=404)
    return card, instance, device


@_audit_admin_failures("device.block", object_type="LicenseInstance", target_key="authorization_id")
def block_device(
    *,
    actor,
    authorization_id,
    device_id=None,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuthorizationAdminActionResult:
    """Freeze this card: no new activation, current seats stay occupied."""

    _require_platform_admin(actor, action="device.block", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    current_time = _now(now)
    with transaction.atomic():
        _card, instance, device = _lock_authorization_device(
            authorization_id=authorization_id,
            device_id=device_id,
            action="device.block",
            actor=actor,
            request_id=request_id,
            ip_address=ip_address,
        )
        active_count = DeviceBinding.objects.filter(
            authorization=instance,
            state=DeviceBindingState.ACTIVE,
        ).count()
        if authorization_card_is_frozen(instance):
            record_event(
                actor=actor,
                action="device.block",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "repeated": True,
                    "reason": reason,
                    "effective_at": current_time.isoformat(),
                    "card_frozen": True,
                    "before_state": instance.state,
                    "after_state": instance.state,
                    "binding_active_before": active_count,
                    "binding_active_after": active_count,
                    "device_id": str(device.public_id) if device is not None else None,
                    "device_risk_state": device.risk_state if device is not None else None,
                },
            )
            return AuthorizationAdminActionResult(
                authorization_id=instance.authorization_id,
                device_id=device.public_id if device is not None else None,
                repeated=True,
            )
        if instance.state == AuthorizationState.BLOCKED:
            raise AuthorizationOperationError(
                "AUTHORIZATION_BLOCKED",
                "当前授权已因安全原因阻断，不能按冻卡处理。",
                http_status=409,
            )
        if instance.state not in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
            raise AuthorizationOperationError("AUTHORIZATION_NOT_ACTIVE", "当前授权不能冻结。", http_status=409)
        if active_count < 1:
            raise AuthorizationOperationError("CARD_NOT_BOUND", "没有占用中的设备，不能冻卡占座。", http_status=409)

        before_state = instance.state
        before_revision = instance.authorization_revision
        instance.state = AuthorizationState.BLOCKED
        instance.state_reason = reason
        instance.authorization_revision += 1
        instance.save(
            update_fields=("state", "state_reason", "authorization_revision", "updated_at"),
            _allow_mutation=True,
        )
        record_event(
            actor=actor,
            action="device.block",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseInstance",
            object_public_id=instance.authorization_id,
            metadata={
                "reason": reason,
                "reason_length": len(reason),
                "effective_at": current_time.isoformat(),
                "repeated": False,
                "card_frozen": True,
                "before_state": before_state,
                "after_state": instance.state,
                "before_revision": before_revision,
                "after_revision": instance.authorization_revision,
                "binding_active_before": active_count,
                "binding_active_after": active_count,
                "device_id": str(device.public_id) if device is not None else None,
                "device_risk_state": device.risk_state if device is not None else None,
            },
        )
        return AuthorizationAdminActionResult(
            authorization_id=instance.authorization_id,
            device_id=device.public_id if device is not None else None,
        )


@_audit_admin_failures("device.unblock", object_type="LicenseInstance", target_key="authorization_id")
def unblock_device(
    *,
    actor,
    authorization_id,
    device_id=None,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuthorizationAdminActionResult:
    """Clear this card's freeze mark. Existing ACTIVE bindings stay occupying."""

    _require_platform_admin(actor, action="device.unblock", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    current_time = _now(now)
    with transaction.atomic():
        _card, instance, device = _lock_authorization_device(
            authorization_id=authorization_id,
            device_id=device_id,
            action="device.unblock",
            actor=actor,
            request_id=request_id,
            ip_address=ip_address,
        )
        active_count = DeviceBinding.objects.filter(
            authorization=instance,
            state=DeviceBindingState.ACTIVE,
        ).count()
        if not authorization_card_is_frozen(instance):
            if instance.state in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
                record_event(
                    actor=actor,
                    action="device.unblock",
                    outcome=AuditOutcome.SUCCESS,
                    request_id=request_id,
                    ip_address=ip_address,
                    object_type="LicenseInstance",
                    object_public_id=instance.authorization_id,
                    metadata={
                        "repeated": True,
                        "reason": reason,
                        "effective_at": current_time.isoformat(),
                        "card_frozen": False,
                        "before_state": instance.state,
                        "after_state": instance.state,
                        "binding_active_before": active_count,
                        "binding_active_after": active_count,
                        "device_id": str(device.public_id) if device is not None else None,
                        "device_risk_state": device.risk_state if device is not None else None,
                    },
                )
                return AuthorizationAdminActionResult(
                    authorization_id=instance.authorization_id,
                    device_id=device.public_id if device is not None else None,
                    repeated=True,
                )
            if not is_time_rollback_blocked(instance):
                raise AuthorizationOperationError(
                    "AUTHORIZATION_BLOCKED",
                    "当前授权不是冻卡状态，不能解冻。",
                    http_status=409,
                )

        rollback_recovery = is_time_rollback_blocked(instance)
        before_state = instance.state
        before_revision = instance.authorization_revision
        before_active_count = DeviceBinding.objects.filter(
            authorization=instance,
            state=DeviceBindingState.ACTIVE,
        ).count()
        restored_bindings = 0
        skipped_risky_bindings = 0
        if rollback_recovery:
            remaining_seats = max(0, instance.policy_version.max_devices - before_active_count)
            # Clock rollback had blocked every seat; put back exactly the seats
            # it took so the customer does not have to re-activate.  Bindings
            # blocked by an administrator or by the risk engine stay blocked,
            # and so does any seat whose physical device is still blacklisted —
            # resurrecting it would leave an ACTIVE seat that can never verify.
            for binding in DeviceBinding.objects.select_for_update().filter(
                authorization=instance,
                state=DeviceBindingState.BLOCKED,
                reason=TIME_ROLLBACK_BINDING_REASON,
            ).in_history_order():
                if restored_bindings >= remaining_seats:
                    break
                binding_device = Device.objects.filter(pk=binding.device_id).only("risk_state").first()
                if binding_device is not None and binding_device.risk_state == DeviceRiskState.BLOCKED:
                    skipped_risky_bindings += 1
                    continue
                binding.state = DeviceBindingState.ACTIVE
                binding.reason = ""
                binding.unbound_at = None
                binding.save(
                    update_fields=("state", "reason", "unbound_at"),
                    _allow_mutation=True,
                )
                restored_bindings += 1
            active_count = DeviceBinding.objects.filter(
                authorization=instance,
                state=DeviceBindingState.ACTIVE,
            ).count()
        instance.state = AuthorizationState.ACTIVE
        instance.state_reason = reason
        instance.authorization_revision += 1
        instance.save(
            update_fields=("state", "state_reason", "authorization_revision", "updated_at"),
            _allow_mutation=True,
        )
        record_event(
            actor=actor,
            action="device.unblock",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseInstance",
            object_public_id=instance.authorization_id,
            metadata={
                "reason": reason,
                "reason_length": len(reason),
                "effective_at": current_time.isoformat(),
                "repeated": False,
                "card_frozen": False,
                "rollback_recovery": rollback_recovery,
                "bindings_restored": restored_bindings,
                "bindings_skipped_risky": skipped_risky_bindings,
                "before_state": before_state,
                "after_state": instance.state,
                "before_revision": before_revision,
                "after_revision": instance.authorization_revision,
                "binding_active_before": before_active_count,
                "binding_active_after": active_count,
                "device_id": str(device.public_id) if device is not None else None,
                "device_risk_state": device.risk_state if device is not None else None,
            },
        )
        return AuthorizationAdminActionResult(
            authorization_id=instance.authorization_id,
            device_id=device.public_id if device is not None else None,
        )


@_audit_admin_failures("device.reset", object_type="DeviceBinding", target_key="authorization_id")
def reset_device_binding(
    *,
    actor,
    authorization_id,
    device_id,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    scope_downstream_public_id=None,
) -> AuthorizationAdminActionResult:
    """Unbind one authorization's current binding for one device.

    The authorization and device are both part of the target so a shared
    device cannot accidentally unbind another customer's authorization.
    Historical bindings remain immutable facts, authorization expiry and card
    revenue fields are untouched, and repeated resets do not increment the
    revision again.
    """

    if scope_downstream_public_id is None:
        _require_platform_admin(actor, action="device.reset", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    current_time = _now(now)
    with transaction.atomic():
        try:
            reference = LicenseInstance.objects.only(
                "license_card_id",
                "current_downstream_public_id",
            ).get(authorization_id=authorization_id)
        except LicenseInstance.DoesNotExist as exc:
            _record_admin_failure(
                actor=actor,
                action="device.reset",
                reason_code="AUTHORIZATION_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
                metadata={"device_id": str(device_id)},
            )
            raise AuthorizationOperationError("AUTHORIZATION_NOT_FOUND", "授权实例不存在。", http_status=404) from exc

        if (
            scope_downstream_public_id is not None
            and str(reference.current_downstream_public_id) != str(scope_downstream_public_id)
        ):
            raise AuthorizationOperationError("FORBIDDEN", "当前下游没有这份授权的设备处置权限。", http_status=403)

        # Keep the same card -> authorization -> device -> binding lock order
        # used by activation and the other administrator risk actions.
        card = LicenseCard.objects.select_for_update().get(pk=reference.license_card_id)
        instance = LicenseInstance.objects.select_for_update().get(authorization_id=authorization_id)
        try:
            device = Device.objects.select_for_update().get(
                public_id=device_id,
                software_id=instance.software_id,
                profile_id=instance.profile_id,
            )
        except Device.DoesNotExist as exc:
            _record_admin_failure(
                actor=actor,
                action="device.reset",
                reason_code="DEVICE_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="Device",
                object_public_id=device_id,
                metadata={"authorization_id": str(authorization_id)},
            )
            raise AuthorizationOperationError("DEVICE_NOT_FOUND", "设备不存在或不属于该授权。", http_status=404) from exc

        binding = (
            DeviceBinding.objects.select_for_update()
            .filter(authorization=instance, device=device)
            .in_history_order()
            .first()
        )
        if binding is None:
            _record_admin_failure(
                actor=actor,
                action="device.reset",
                reason_code="DEVICE_BINDING_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
                metadata={"device_id": str(device_id)},
            )
            raise AuthorizationOperationError("DEVICE_BINDING_NOT_FOUND", "该授权没有这台设备的历史绑定。", http_status=404)

        if authorization_card_is_frozen(instance):
            raise AuthorizationOperationError("CARD_FROZEN", "已冻结的卡不能重置腾座。", http_status=409)

        binding_active_before = DeviceBinding.objects.filter(
            authorization=instance,
            state=DeviceBindingState.ACTIVE,
        ).count()
        if binding.state != DeviceBindingState.ACTIVE:
            record_event(
                actor=actor,
                action="device.reset",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="DeviceBinding",
                object_public_id=binding.binding_id,
                metadata={
                    "repeated": True,
                    "authorization_id": str(instance.authorization_id),
                    "device_id": str(device.public_id),
                    "before_state": binding.state,
                    "after_state": binding.state,
                    "before_revision": instance.authorization_revision,
                    "after_revision": instance.authorization_revision,
                    "card_status_before": card.status,
                    "card_status_after": card.status,
                    "binding_active_before": binding_active_before,
                    "binding_active_after": binding_active_before,
                    "reason": reason,
                    "effective_at": current_time.isoformat(),
                },
            )
            return AuthorizationAdminActionResult(
                authorization_id=instance.authorization_id,
                device_id=device.public_id,
                repeated=True,
            )

        before_revision = instance.authorization_revision
        before_card_status = card.status
        instance.authorization_revision += 1
        instance.save(update_fields=("authorization_revision", "updated_at"), _allow_mutation=True)
        binding.state = DeviceBindingState.UNBOUND
        binding.unbound_at = current_time
        binding.reason = reason
        binding.save(update_fields=("state", "unbound_at", "reason"), _allow_mutation=True)
        binding_active_after = DeviceBinding.objects.filter(
            authorization=instance,
            state=DeviceBindingState.ACTIVE,
        ).count()

        record_event(
            actor=actor,
            action="device.reset",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DeviceBinding",
            object_public_id=binding.binding_id,
            metadata={
                "repeated": False,
                "authorization_id": str(instance.authorization_id),
                "device_id": str(device.public_id),
                "before_state": DeviceBindingState.ACTIVE,
                "after_state": DeviceBindingState.UNBOUND,
                "before_revision": before_revision,
                "after_revision": instance.authorization_revision,
                "reason": reason,
                "reason_length": len(reason),
                "effective_at": current_time.isoformat(),
                "expiry_preserved": True,
                "card_status_before": before_card_status,
                "card_status_after": card.status,
                "binding_active_before": binding_active_before,
                "binding_active_after": binding_active_after,
            },
        )
        return AuthorizationAdminActionResult(
            authorization_id=instance.authorization_id,
            device_id=device.public_id,
        )


# ---------------------------------------------------------------------------
# 卡密续期（ADR-0016）
# ---------------------------------------------------------------------------

# 单次续期上限：366 天。运营赠送时间不允许一次推后一年以上。
MAX_RENEWAL_SECONDS = 366 * 86400
# 累计上限：续期后的到期时间不能超过这张卡激活起 10 年。
# 这是防手滑（连着点很多次），不是运营限制。
MAX_RENEWAL_TOTAL_SECONDS = 10 * 366 * 86400
MAX_RENEWAL_BATCH = 500
RENEWAL_UNIT_SECONDS = {"hour": 3600, "day": 86400, "小时": 3600, "天": 86400}


@dataclass(frozen=True)
class AuthorizationRenewalResult:
    """One authorization whose server-side expiry was pushed later."""

    authorization_id: object
    previous_expires_at: datetime
    new_expires_at: datetime
    added_seconds: int
    repeated: bool = False


def renewal_seconds(unit: str, amount) -> int:
    """Translate an operator-friendly hour/day amount into seconds."""

    normalized = str(unit or "").strip().casefold()
    if normalized not in RENEWAL_UNIT_SECONDS:
        raise AuthorizationOperationError("INVALID_RENEWAL_UNIT", "续期单位只能是小时或天。", http_status=400)
    try:
        quantity = int(amount)
    except (TypeError, ValueError) as exc:
        raise AuthorizationOperationError("INVALID_RENEWAL_AMOUNT", "续期数量必须是正整数。", http_status=400) from exc
    if quantity < 1:
        raise AuthorizationOperationError("INVALID_RENEWAL_AMOUNT", "续期数量至少为 1。", http_status=400)
    seconds = quantity * RENEWAL_UNIT_SECONDS[normalized]
    if seconds > MAX_RENEWAL_SECONDS:
        raise AuthorizationOperationError(
            "RENEWAL_TOO_LONG",
            f"单次续期不能超过 {MAX_RENEWAL_SECONDS // 86400} 天。",
            http_status=400,
        )
    return seconds


_RENEWAL_BLOCKER_MESSAGES = {
    "AUTHORIZATION_REVOKED": "该授权已撤销，不能续期。",
    "AUTHORIZATION_BLOCKED": "该授权已阻断，不能续期。",
    "AUTHORIZATION_EXPIRED": "该授权已过期，不能续期；请发新卡。",
    "AUTHORIZATION_NOT_ACTIVE": "只有已激活且未过期的授权可以续期。",
    "CARD_NOT_ACTIVATED": "该卡密不是已激活状态，不能续期。",
}


def renewal_blocker(card, instance, now: datetime) -> str | None:
    """Return a stable reason code when this authorization must not be renewed."""

    if instance.state == AuthorizationState.REVOKED:
        return "AUTHORIZATION_REVOKED"
    if instance.state == AuthorizationState.BLOCKED:
        return "AUTHORIZATION_BLOCKED"
    if instance.state == AuthorizationState.EXPIRED or now >= instance.expires_at:
        return "AUTHORIZATION_EXPIRED"
    if instance.state not in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
        return "AUTHORIZATION_NOT_ACTIVE"
    if card.status != LicenseCardStatus.ACTIVATED:
        return "CARD_NOT_ACTIVATED"
    return None


def extend_authorization(
    *,
    actor,
    authorization_id,
    added_seconds: int,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuthorizationRenewalResult:
    """Push one active authorization's server-side expiry later.

    Only the expiry facts move.  The plan snapshot, its duration, device rules,
    downstream ownership, quota cost and the quota ledger stay untouched: a
    renewal is granted operating time, not a sale.  The authorization revision
    is bumped so the next verify cannot answer `not_modified` with the old
    expiry.
    """

    _require_platform_admin(actor, action="authorization.extend", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    try:
        seconds = int(added_seconds)
    except (TypeError, ValueError) as exc:
        raise AuthorizationOperationError("INVALID_RENEWAL_AMOUNT", "续期时长不正确。", http_status=400) from exc
    if seconds < 1 or seconds > MAX_RENEWAL_SECONDS:
        raise AuthorizationOperationError(
            "INVALID_RENEWAL_AMOUNT",
            f"单次续期时长必须在 1 秒到 {MAX_RENEWAL_SECONDS // 86400} 天之间。",
            http_status=400,
        )
    current_time = _now(now)

    with transaction.atomic():
        try:
            reference = LicenseInstance.objects.only("license_card_id").get(authorization_id=authorization_id)
        except LicenseInstance.DoesNotExist as exc:
            _record_admin_failure(
                actor=actor,
                action="authorization.extend",
                reason_code="AUTHORIZATION_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=authorization_id,
            )
            raise AuthorizationOperationError("AUTHORIZATION_NOT_FOUND", "授权实例不存在。", http_status=404) from exc

        # Keep the global write order aligned with activation, revoke and device
        # actions: card -> authorization instance.
        card = LicenseCard.objects.select_for_update().get(pk=reference.license_card_id)
        instance = LicenseInstance.objects.select_for_update().get(authorization_id=authorization_id)

        blocker = renewal_blocker(card, instance, current_time)
        if blocker is not None:
            _record_admin_failure(
                actor=actor,
                action="authorization.extend",
                reason_code=blocker,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "authorization_id": str(instance.authorization_id),
                    "before_expires_at": instance.expires_at.isoformat(),
                    "requested_seconds": seconds,
                    "instance_state": instance.state,
                    "card_status": card.status,
                },
            )
            raise AuthorizationOperationError(blocker, _RENEWAL_BLOCKER_MESSAGES[blocker], http_status=409)

        previous_expires_at = instance.expires_at
        new_expires_at = previous_expires_at + timedelta(seconds=seconds)
        renewal_ceiling = instance.activated_at + timedelta(seconds=MAX_RENEWAL_TOTAL_SECONDS)
        if new_expires_at > renewal_ceiling:
            _record_admin_failure(
                actor=actor,
                action="authorization.extend",
                reason_code="RENEWAL_LIMIT_EXCEEDED",
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "authorization_id": str(instance.authorization_id),
                    "before_expires_at": previous_expires_at.isoformat(),
                    "requested_seconds": seconds,
                    "renewal_ceiling": renewal_ceiling.isoformat(),
                },
            )
            raise AuthorizationOperationError(
                "RENEWAL_LIMIT_EXCEEDED",
                "续期后到期时间会超过这张卡激活起 10 年的上限，已拒绝。",
                http_status=409,
            )
        before_revision = instance.authorization_revision
        instance.expires_at = new_expires_at
        instance.authorization_revision += 1
        instance.save(
            update_fields=("expires_at", "authorization_revision", "updated_at"),
            _allow_mutation=True,
        )
        if card.expires_at != new_expires_at:
            card.expires_at = new_expires_at
            card.save(update_fields=("expires_at",), _allow_mutation=True)

        record_event(
            actor=actor,
            action="authorization.extend",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseInstance",
            object_public_id=instance.authorization_id,
            metadata={
                "repeated": False,
                "authorization_id": str(instance.authorization_id),
                "software_id": instance.software_id,
                "profile_id": instance.profile_id,
                "card_public_id": str(card.public_id),
                "added_seconds": seconds,
                "before_expires_at": previous_expires_at.isoformat(),
                "after_expires_at": new_expires_at.isoformat(),
                "before_revision": before_revision,
                "after_revision": instance.authorization_revision,
                "reason": reason,
                "reason_length": len(reason),
                "quota_cost_unchanged": True,
                "effective_at": current_time.isoformat(),
            },
        )
        return AuthorizationRenewalResult(
            authorization_id=instance.authorization_id,
            previous_expires_at=previous_expires_at,
            new_expires_at=new_expires_at,
            added_seconds=seconds,
        )


@_audit_admin_failures("device.block_physical", object_type="Device", target_key="device_id")
def block_physical_device(
    *,
    actor,
    device_id,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuthorizationAdminActionResult:
    """Block a physical hardware device entirely across the platform."""

    _require_platform_admin(actor, action="device.block", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    current_time = _now(now)
    with transaction.atomic():
        # Runtime activation locks LicenseCard → LicenseInstance → Device →
        # DeviceKey → DeviceBinding.  This path used to take Device first and
        # then the instances, which is the reverse order and can deadlock
        # against a concurrent activation.  Resolve the target instances first,
        # lock them in a stable order, then lock the device.
        #
        # A concurrent activation can still insert a new binding for this device
        # between the instance snapshot and the device lock.  If that happened,
        # the newly seen instance would have no lock and its binding would be
        # blocked while the instance stayed active — leaving a seat that is dead
        # but not recoverable by unblock.  Re-check after locking the bindings
        # and retry the whole operation a bounded number of times.
        device_row = _device_pk_or_404(device_id)

        for attempt in range(_PHYSICAL_DEVICE_LOCK_RETRIES):
            target_instance_ids = sorted(
                {
                    str(value)
                    for value in DeviceBinding.objects.filter(
                        device_id=device_id, state=DeviceBindingState.ACTIVE
                    ).values_list("authorization_id", flat=True)
                }
            )
            locked_instances = {}
            for authorization_id in target_instance_ids:
                instance = (
                    LicenseInstance.objects.select_for_update()
                    .filter(pk=authorization_id)
                    .first()
                )
                if instance is not None:
                    locked_instances[str(instance.pk)] = instance

            device = Device.objects.select_for_update().get(pk=device_id)

            before_state = device.risk_state
            device.risk_state = DeviceRiskState.BLOCKED
            device.save(update_fields=("risk_state",), _allow_mutation=True)

            active_bindings = list(
                DeviceBinding.objects.select_for_update()
                .filter(device=device, state=DeviceBindingState.ACTIVE)
                .order_by("binding_id")
            )
            missing = sorted(
                {
                    str(binding.authorization_id)
                    for binding in active_bindings
                    if str(binding.authorization_id) not in locked_instances
                }
            )
            if missing and attempt + 1 < _PHYSICAL_DEVICE_LOCK_RETRIES:
                # A binding appeared for an instance we did not lock. Roll back
                # and try again with the wider set.
                transaction.set_rollback(True)
                continue

            for binding in active_bindings:
                binding.state = DeviceBindingState.BLOCKED
                binding.unbound_at = current_time
                binding.reason = f"硬件设备已被封禁: {reason}"
                binding.save(update_fields=("state", "unbound_at", "reason"), _allow_mutation=True)

                instance = locked_instances.get(str(binding.authorization_id))
                if instance:
                    instance.authorization_revision += 1
                    instance.last_server_time = max(filter(None, (instance.last_server_time, current_time)), default=current_time)
                    has_other_active = DeviceBinding.objects.filter(authorization=instance, state=DeviceBindingState.ACTIVE).exclude(pk=binding.pk).exists()
                    if not has_other_active and instance.state in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
                        instance.state = AuthorizationState.BLOCKED
                        instance.state_reason = f"硬件设备已被封禁: {reason}"
                        instance.save(update_fields=("state", "state_reason", "authorization_revision", "last_server_time", "updated_at"), _allow_mutation=True)
                    else:
                        instance.save(update_fields=("authorization_revision", "last_server_time", "updated_at"), _allow_mutation=True)
            break

        record_event(
            actor=actor,
            action="device.block_physical",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Device",
            object_public_id=device.public_id,
            metadata={
                "reason": reason,
                "before_state": before_state,
                "after_state": device.risk_state,
                "binding_blocked_count": len(active_bindings),
                "effective_at": current_time.isoformat(),
            },
        )
        return AuthorizationAdminActionResult(device_id=device.public_id)


@_audit_admin_failures("device.unblock_physical", object_type="Device", target_key="device_id")
def unblock_physical_device(
    *,
    actor,
    device_id,
    reason: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> AuthorizationAdminActionResult:
    """Unblock a physical hardware device without resurrecting dead seats."""

    _require_platform_admin(actor, action="device.unblock", request_id=request_id, ip_address=ip_address)
    reason = _reason(reason)
    current_time = _now(now)
    with transaction.atomic():
        # Same lock order as block_physical_device: resolve and lock the
        # target instances in a stable order first, then lock the device, and
        # retry if a concurrent writer widened the binding set in between.
        device_row = _device_pk_or_404(device_id)

        for attempt in range(_PHYSICAL_DEVICE_LOCK_RETRIES):
            target_instance_ids = sorted(
                {
                    str(value)
                    for value in DeviceBinding.objects.filter(
                        device_id=device_id, state=DeviceBindingState.BLOCKED
                    ).values_list("authorization_id", flat=True)
                }
            )
            locked_instances = {}
            for authorization_id in target_instance_ids:
                instance = (
                    LicenseInstance.objects.select_for_update()
                    .filter(pk=authorization_id)
                    .first()
                )
                if instance is not None:
                    locked_instances[str(instance.pk)] = instance

            device = Device.objects.select_for_update().get(pk=device_id)

            before_state = device.risk_state
            dead_bindings = list(
                DeviceBinding.objects.select_for_update()
                .filter(device=device, state=DeviceBindingState.BLOCKED)
                .order_by("binding_id")
            )
            missing = sorted(
                {
                    str(binding.authorization_id)
                    for binding in dead_bindings
                    if str(binding.authorization_id) not in locked_instances
                }
            )
            if missing and attempt + 1 < _PHYSICAL_DEVICE_LOCK_RETRIES:
                transaction.set_rollback(True)
                continue
            break

        if before_state == DeviceRiskState.NORMAL and not dead_bindings:
            record_event(
                actor=actor,
                action="device.unblock_physical",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="Device",
                object_public_id=device.public_id,
                metadata={
                    "repeated": True,
                    "reason": reason,
                    "before_state": before_state,
                    "after_state": before_state,
                    "effective_at": current_time.isoformat(),
                },
            )
            return AuthorizationAdminActionResult(device_id=device.public_id, repeated=True)

        touched_instances = set()
        device.risk_state = DeviceRiskState.NORMAL
        device.save(update_fields=("risk_state",), _allow_mutation=True)

        for binding in dead_bindings:
            instance = locked_instances.get(str(binding.authorization_id))
            if instance and instance.pk not in touched_instances:
                touched_instances.add(instance.pk)
                instance.authorization_revision += 1
                instance.last_server_time = max(filter(None, (instance.last_server_time, current_time)), default=current_time)
                instance.save(update_fields=("authorization_revision", "last_server_time", "updated_at"), _allow_mutation=True)

        record_event(
            actor=actor,
            action="device.unblock_physical",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Device",
            object_public_id=device.public_id,
            metadata={
                "repeated": False,
                "reason": reason,
                "before_state": before_state,
                "after_state": device.risk_state,
                "dead_binding_count": len(dead_bindings),
                "touched_instance_count": len(touched_instances),
                "effective_at": current_time.isoformat(),
            },
        )
        return AuthorizationAdminActionResult(device_id=device.public_id)

