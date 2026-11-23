from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .models import (
    DownstreamProfile,
    DownstreamStatus,
    DownstreamTombstone,
    InvitationBatch,
    InvitationCode,
    InvitationCodeTombstone,
    InvitationLifecycleOperation,
    InvitationStatus,
    PasswordOperation,
    PasswordOperationAction,
    RegistrationSource,
)
from .roles import DOWNSTREAM_GROUP, is_platform_admin_user


INVITATION_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
INVITATION_PREFIX = "INV-"


class AccountOperationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class IssuedInvitation:
    public_id: object
    code: str
    expires_at: datetime | None


@dataclass(frozen=True)
class RegistrationResult:
    success: bool
    user: object | None = None
    profile: DownstreamProfile | None = None


@dataclass(frozen=True)
class PasswordOperationResult:
    operation: PasswordOperation
    target_user: object | None = None
    target_profile: DownstreamProfile | None = None
    replayed: bool = False


def is_platform_admin(user) -> bool:
    return is_platform_admin_user(user)


def get_downstream_profile(user) -> DownstreamProfile | None:
    if not user or not user.is_authenticated:
        return None
    try:
        return user.downstream_profile
    except DownstreamProfile.DoesNotExist:
        return None


def is_active_downstream(user) -> bool:
    profile = get_downstream_profile(user)
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and profile
        and profile.status == DownstreamStatus.ACTIVE
        and user.groups.filter(name=DOWNSTREAM_GROUP).exists()
    )


def require_platform_admin(user) -> None:
    if not is_platform_admin(user):
        raise PermissionDenied


def normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise AccountOperationError("REGISTRATION_FAILED", "注册信息无效。")
    normalized = username.strip().casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,149}", normalized):
        raise AccountOperationError("REGISTRATION_FAILED", "注册信息无效。")
    return normalized


def normalize_invitation_code(code: str) -> str:
    if not isinstance(code, str):
        return ""
    return "".join(code.split()).upper()


def digest_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def invitation_code_hash(code: str) -> str:
    return digest_secret(normalize_invitation_code(code))


def _fernet() -> Fernet:
    key = settings.INVITATION_ENCRYPTION_KEY
    return Fernet(key.encode("ascii") if isinstance(key, str) else key)


def encrypt_invitation_code(code: str) -> str:
    return _fernet().encrypt(code.encode("utf-8")).decode("ascii")


def decrypt_invitation_code(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise AccountOperationError("CREDENTIAL_UNAVAILABLE", "凭证暂时无法再次交付，请联系管理员。") from exc


def reveal_invitation(*, actor, invitation_public_id, request_id: str | None = None, ip_address: str | None = None) -> tuple[InvitationCode, str]:
    """Return one invitation's plaintext only after the admin scope check.

    The encrypted value is the durable source for repeat delivery. Successful
    display/copy/download is intentionally not an audit event; failed access
    and decryption attempts are recorded by the caller/service boundary.
    """

    require_platform_admin(actor)
    try:
        invitation = InvitationCode.objects.select_related("batch", "consumed_profile__user").get(
            public_id=invitation_public_id
        )
        if invitation.status == InvitationStatus.DELETED_TOMBSTONE:
            raise InvitationCode.DoesNotExist
    except (InvitationCode.DoesNotExist, ValueError, TypeError) as exc:
        error = AccountOperationError("INVITATION_NOT_FOUND", "邀请码不存在。")
        record_event(
            actor=actor,
            action="invitation.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=error.code,
        )
        raise error from exc

    try:
        plaintext = decrypt_invitation_code(invitation.code_ciphertext)
    except AccountOperationError as exc:
        record_event(
            actor=actor,
            action="invitation.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="InvitationCode",
            object_public_id=invitation.public_id,
            reason_code=exc.code,
            metadata={"status": invitation.status},
        )
        raise
    return invitation, plaintext


def _ensure_group(name: str) -> Group:
    group, _ = Group.objects.get_or_create(name=name)
    return group


def _validate_password(password: str, user=None) -> None:
    try:
        validate_password(password, user=user)
    except ValidationError as exc:
        raise AccountOperationError("REGISTRATION_FAILED", "密码不符合安全要求。") from exc


def _normalize_idempotency_key(value: str | None) -> str:
    if not isinstance(value, str):
        raise AccountOperationError("IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。")
    normalized = value.strip()
    if not normalized or len(normalized) > 128:
        raise AccountOperationError("IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。")
    return normalized


def _password_request_hash(
    *,
    action: str,
    target_profile_public_id: object | None,
    current_password: str = "",
    new_password: str,
    new_password_confirm: str,
    reason: str = "",
) -> str:
    """Hash password-operation inputs without storing a crackable bare digest."""

    canonical = json.dumps(
        {
            "action": action,
            "target_profile_public_id": str(target_profile_public_id or ""),
            "current_password": current_password,
            "new_password": new_password,
            "new_password_confirm": new_password_confirm,
            "reason": reason,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    key = getattr(settings, "PASSWORD_OPERATION_HASH_KEY", settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _validate_password_pair(*, new_password: str, new_password_confirm: str, user) -> None:
    if not isinstance(new_password, str) or not isinstance(new_password_confirm, str):
        raise AccountOperationError("PASSWORD_INVALID", "新密码不符合安全要求。")
    if new_password != new_password_confirm:
        raise AccountOperationError("PASSWORD_MISMATCH", "两次输入的新密码不一致。")
    try:
        validate_password(new_password, user=user)
    except ValidationError as exc:
        raise AccountOperationError("PASSWORD_INVALID", "密码不符合安全要求。") from exc


def _password_action_name(action: str) -> str:
    return "auth.password_change" if action == PasswordOperationAction.CHANGE else "auth.password_reset"


def _password_target_metadata(
    *,
    username: str,
    idempotency_key: str | None = None,
    reason_length: int | None = None,
    reason_digest: str | None = None,
) -> dict:
    metadata = {"target_username_digest": digest_secret(username)}
    if idempotency_key is not None:
        metadata["idempotency_key_digest"] = digest_secret(idempotency_key)
    if reason_length is not None:
        metadata["reason_length"] = reason_length
    if reason_digest is not None:
        metadata["reason_digest"] = reason_digest
    return metadata


def _record_password_failure(
    *,
    actor,
    action: str,
    reason_code: str,
    request_id: str | None,
    ip_address: str | None,
    username: str = "",
    target_profile_public_id: object | None = None,
    idempotency_key: str | None = None,
    reason_length: int | None = None,
    reason: str | None = None,
) -> None:
    record_event(
        actor=actor,
        action=_password_action_name(action),
        outcome=AuditOutcome.FAILURE,
        request_id=request_id,
        ip_address=ip_address,
        object_type="DownstreamProfile" if target_profile_public_id else "",
        object_public_id=target_profile_public_id or "",
        reason_code=reason_code,
        metadata=_password_target_metadata(
            username=username,
            idempotency_key=idempotency_key,
            reason_length=reason_length,
            reason_digest=digest_secret(reason) if reason is not None else None,
        ),
    )


def _operation_replay_or_conflict(
    *,
    operation: PasswordOperation | None,
    action: str,
    request_hash: str,
    actor,
    request_id: str | None,
    ip_address: str | None,
    username: str,
    target_profile_public_id: object | None,
    idempotency_key: str,
    reason_length: int | None = None,
    reason: str | None = None,
) -> PasswordOperationResult | None:
    if operation is None:
        return None
    if operation.action != action or not hmac.compare_digest(operation.request_hash, request_hash):
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code="IDEMPOTENCY_CONFLICT",
            request_id=request_id,
            ip_address=ip_address,
            username=username,
            target_profile_public_id=target_profile_public_id,
            idempotency_key=idempotency_key,
            reason_length=reason_length,
            reason=reason,
        )
        raise AccountOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的密码操作。")
    return PasswordOperationResult(operation=operation, replayed=True)


def _password_operation_response(*, action: str, user, profile: DownstreamProfile | None) -> dict:
    if action == PasswordOperationAction.CHANGE:
        return {
            "changed": True,
            "username": user.username,
            "role": "downstream" if profile else "platform_admin",
        }
    return {
        "reset": True,
        "profile": {
            "public_id": str(profile.public_id),
            "username": profile.user.username,
            "status": profile.status,
        },
    }


def _password_operation_success(
    *,
    actor,
    target_user,
    target_profile: DownstreamProfile | None,
    action: str,
    idempotency_key: str,
    request_hash: str,
    response_payload: dict,
    request_id: str | None,
    ip_address: str | None,
    reason_length: int | None = None,
    reason: str | None = None,
) -> PasswordOperation:
    operation = PasswordOperation.objects.create(
        actor=actor,
        target_user=target_user,
        target_profile_public_id=target_profile.public_id if target_profile else None,
        target_username_digest=digest_secret(target_user.username),
        action=action,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        response_payload=response_payload,
    )
    metadata = _password_target_metadata(
        username=target_user.username,
        idempotency_key=idempotency_key,
        reason_length=reason_length,
        reason_digest=digest_secret(reason) if reason is not None else None,
    )
    metadata["operation_id"] = str(operation.public_id)
    record_event(
        actor=actor,
        action=_password_action_name(action),
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        ip_address=ip_address,
        object_type="DownstreamProfile" if target_profile else "",
        object_public_id=target_profile.public_id if target_profile else "",
        metadata=metadata,
    )
    return operation


def change_own_password(
    *,
    actor,
    current_password: str,
    new_password: str,
    new_password_confirm: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> PasswordOperationResult:
    """Change the authenticated account password and preserve only its session."""

    if not actor or not actor.is_authenticated or not (is_platform_admin(actor) or is_active_downstream(actor)):
        raise PermissionDenied
    key = _normalize_idempotency_key(idempotency_key)
    profile = get_downstream_profile(actor) if is_active_downstream(actor) else None
    action = PasswordOperationAction.CHANGE
    target_profile_public_id = profile.public_id if profile else None
    request_hash = _password_request_hash(
        action=action,
        target_profile_public_id=target_profile_public_id,
        current_password=current_password,
        new_password=new_password,
        new_password_confirm=new_password_confirm,
    )

    existing = PasswordOperation.objects.filter(actor=actor, idempotency_key=key).first()
    replay = _operation_replay_or_conflict(
        operation=existing,
        action=action,
        request_hash=request_hash,
        actor=actor,
        request_id=request_id,
        ip_address=ip_address,
        username=actor.username,
        target_profile_public_id=target_profile_public_id,
        idempotency_key=key,
    )
    if replay:
        replay_profile = get_downstream_profile(actor) if is_active_downstream(actor) else None
        return PasswordOperationResult(
            operation=replay.operation,
            target_user=actor,
            target_profile=replay_profile,
            replayed=True,
        )

    if not isinstance(current_password, str) or not actor.check_password(current_password):
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code="CURRENT_PASSWORD_INVALID",
            request_id=request_id,
            ip_address=ip_address,
            username=actor.username,
            target_profile_public_id=target_profile_public_id,
            idempotency_key=key,
        )
        raise AccountOperationError("CURRENT_PASSWORD_INVALID", "当前密码不正确。")
    if current_password == new_password:
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code="PASSWORD_REUSE",
            request_id=request_id,
            ip_address=ip_address,
            username=actor.username,
            target_profile_public_id=target_profile_public_id,
            idempotency_key=key,
        )
        raise AccountOperationError("PASSWORD_REUSE", "新密码不能与当前密码相同。")
    try:
        _validate_password_pair(new_password=new_password, new_password_confirm=new_password_confirm, user=actor)
    except AccountOperationError as exc:
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code=exc.code,
            request_id=request_id,
            ip_address=ip_address,
            username=actor.username,
            target_profile_public_id=target_profile_public_id,
            idempotency_key=key,
        )
        raise

    with transaction.atomic():
        locked_actor = get_user_model().objects.select_for_update().get(pk=actor.pk)
        existing = PasswordOperation.objects.select_for_update().filter(actor=locked_actor, idempotency_key=key).first()
        replay = _operation_replay_or_conflict(
            operation=existing,
            action=action,
            request_hash=request_hash,
            actor=locked_actor,
            request_id=request_id,
            ip_address=ip_address,
            username=locked_actor.username,
            target_profile_public_id=target_profile_public_id,
            idempotency_key=key,
        )
        if replay:
            replay_profile = get_downstream_profile(locked_actor) if is_active_downstream(locked_actor) else None
            return PasswordOperationResult(
                operation=replay.operation,
                target_user=locked_actor,
                target_profile=replay_profile,
                replayed=True,
            )

        if not locked_actor.check_password(current_password):
            _record_password_failure(
                actor=locked_actor,
                action=action,
                reason_code="CURRENT_PASSWORD_INVALID",
                request_id=request_id,
                ip_address=ip_address,
                username=locked_actor.username,
                target_profile_public_id=target_profile_public_id,
                idempotency_key=key,
            )
            raise AccountOperationError("CURRENT_PASSWORD_INVALID", "当前密码不正确。")
        locked_profile = None
        if profile is not None:
            locked_profile = DownstreamProfile.objects.select_for_update().get(user=locked_actor)
            if (
                not locked_actor.is_active
                or locked_profile.status != DownstreamStatus.ACTIVE
                or not locked_actor.groups.filter(name=DOWNSTREAM_GROUP).exists()
            ):
                _record_password_failure(
                    actor=locked_actor,
                    action=action,
                    reason_code="ACCOUNT_UNAVAILABLE",
                    request_id=request_id,
                    ip_address=ip_address,
                    username=locked_actor.username,
                    target_profile_public_id=locked_profile.public_id,
                    idempotency_key=key,
                )
                raise AccountOperationError("ACCOUNT_UNAVAILABLE", "当前账号不可用。")
            locked_profile.session_version += 1
        locked_actor.set_password(new_password)
        locked_actor.save(update_fields=("password",))
        if locked_profile:
            locked_profile.save(update_fields=("session_version", "updated_at"))
        response_payload = _password_operation_response(action=action, user=locked_actor, profile=locked_profile)
        operation = _password_operation_success(
            actor=locked_actor,
            target_user=locked_actor,
            target_profile=locked_profile,
            action=action,
            idempotency_key=key,
            request_hash=request_hash,
            response_payload=response_payload,
            request_id=request_id,
            ip_address=ip_address,
        )
        return PasswordOperationResult(
            operation=operation,
            target_user=locked_actor,
            target_profile=locked_profile,
            replayed=False,
        )


def reset_downstream_password(
    *,
    actor,
    public_id,
    new_password: str,
    new_password_confirm: str,
    reason: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> PasswordOperationResult:
    """Reset one active downstream account, invalidating every old session."""

    require_platform_admin(actor)
    key = _normalize_idempotency_key(idempotency_key)
    reason = reason.strip() if isinstance(reason, str) else ""
    if len(reason) < 2 or len(reason) > 255:
        _record_password_failure(
            actor=actor,
            action=PasswordOperationAction.RESET,
            reason_code="INVALID_REASON",
            request_id=request_id,
            ip_address=ip_address,
            username="",
            idempotency_key=key,
            reason_length=len(reason),
            reason=reason,
        )
        raise AccountOperationError("INVALID_REASON", "请填写至少 2 个字的重置原因。")

    action = PasswordOperationAction.RESET
    target_profile_public_id = public_id
    request_hash = _password_request_hash(
        action=action,
        target_profile_public_id=target_profile_public_id,
        new_password=new_password,
        new_password_confirm=new_password_confirm,
        reason=reason,
    )
    existing = PasswordOperation.objects.filter(actor=actor, idempotency_key=key).first()
    replay = _operation_replay_or_conflict(
        operation=existing,
        action=action,
        request_hash=request_hash,
        actor=actor,
        request_id=request_id,
        ip_address=ip_address,
        username="",
        target_profile_public_id=target_profile_public_id,
        idempotency_key=key,
        reason_length=len(reason),
        reason=reason,
    )
    if replay:
        profile = DownstreamProfile.objects.select_related("user").filter(public_id=public_id).first()
        return PasswordOperationResult(operation=replay.operation, target_user=profile.user if profile else None, target_profile=profile, replayed=True)

    try:
        preview_profile = DownstreamProfile.objects.select_related("user").get(public_id=public_id)
    except DownstreamProfile.DoesNotExist as exc:
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code="DOWNSTREAM_NOT_FOUND",
            request_id=request_id,
            ip_address=ip_address,
            idempotency_key=key,
            reason_length=len(reason),
            reason=reason,
        )
        raise AccountOperationError("DOWNSTREAM_NOT_FOUND", "下游账号不存在。") from exc
    if preview_profile.status == DownstreamStatus.CLOSED or not preview_profile.user.is_active:
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code="DOWNSTREAM_UNAVAILABLE",
            request_id=request_id,
            ip_address=ip_address,
            username=preview_profile.user.username,
            target_profile_public_id=preview_profile.public_id,
            idempotency_key=key,
            reason_length=len(reason),
            reason=reason,
        )
        raise AccountOperationError("DOWNSTREAM_UNAVAILABLE", "下游账号不存在或已归档。")
    try:
        _validate_password_pair(new_password=new_password, new_password_confirm=new_password_confirm, user=preview_profile.user)
    except AccountOperationError as exc:
        _record_password_failure(
            actor=actor,
            action=action,
            reason_code=exc.code,
            request_id=request_id,
            ip_address=ip_address,
            username=preview_profile.user.username,
            target_profile_public_id=preview_profile.public_id,
            idempotency_key=key,
            reason_length=len(reason),
            reason=reason,
        )
        raise

    with transaction.atomic():
        locked_actor = get_user_model().objects.select_for_update().get(pk=actor.pk)
        existing = PasswordOperation.objects.select_for_update().filter(actor=locked_actor, idempotency_key=key).first()
        replay = _operation_replay_or_conflict(
            operation=existing,
            action=action,
            request_hash=request_hash,
            actor=locked_actor,
            request_id=request_id,
            ip_address=ip_address,
            username="",
            target_profile_public_id=target_profile_public_id,
            idempotency_key=key,
            reason_length=len(reason),
            reason=reason,
        )
        if replay:
            profile = DownstreamProfile.objects.select_related("user").filter(public_id=public_id).first()
            return PasswordOperationResult(operation=replay.operation, target_user=profile.user if profile else None, target_profile=profile, replayed=True)

        try:
            profile = DownstreamProfile.objects.select_for_update().select_related("user").get(public_id=public_id)
        except DownstreamProfile.DoesNotExist:
            _record_password_failure(
                actor=locked_actor,
                action=action,
                reason_code="DOWNSTREAM_NOT_FOUND",
                request_id=request_id,
                ip_address=ip_address,
                idempotency_key=key,
                reason_length=len(reason),
                reason=reason,
            )
            raise AccountOperationError("DOWNSTREAM_NOT_FOUND", "下游账号不存在。")
        if profile.status == DownstreamStatus.CLOSED or not profile.user.is_active:
            _record_password_failure(
                actor=locked_actor,
                action=action,
                reason_code="DOWNSTREAM_UNAVAILABLE",
                request_id=request_id,
                ip_address=ip_address,
                username=profile.user.username,
                target_profile_public_id=profile.public_id,
                idempotency_key=key,
                reason_length=len(reason),
                reason=reason,
            )
            raise AccountOperationError("DOWNSTREAM_UNAVAILABLE", "下游账号不存在或已归档。")
        _validate_password_pair(new_password=new_password, new_password_confirm=new_password_confirm, user=profile.user)
        profile.user.set_password(new_password)
        profile.user.save(update_fields=("password",))
        profile.session_version += 1
        profile.save(update_fields=("session_version", "updated_at"))
        response_payload = _password_operation_response(action=action, user=profile.user, profile=profile)
        operation = _password_operation_success(
            actor=locked_actor,
            target_user=profile.user,
            target_profile=profile,
            action=action,
            idempotency_key=key,
            request_hash=request_hash,
            response_payload=response_payload,
            request_id=request_id,
            ip_address=ip_address,
            reason_length=len(reason),
            reason=reason,
        )
        return PasswordOperationResult(
            operation=operation,
            target_user=profile.user,
            target_profile=profile,
            replayed=False,
        )


def _new_invitation_code() -> str:
    return INVITATION_PREFIX + "".join(secrets.choice(INVITATION_ALPHABET) for _ in range(24))


def _invitation_issue_request_hash(quantity: int) -> str:
    return hashlib.sha256(f"invitation.issue:{quantity}".encode("utf-8")).hexdigest()


def _issued_invitations_for_batch(batch: InvitationBatch) -> list[IssuedInvitation]:
    issued: list[IssuedInvitation] = []
    for invitation in batch.codes.order_by("id"):
        if invitation.status == InvitationStatus.DELETED_TOMBSTONE:
            continue
        issued.append(
            IssuedInvitation(
                public_id=invitation.public_id,
                code=decrypt_invitation_code(invitation.code_ciphertext),
                expires_at=invitation.expires_at,
            )
        )
    if not issued:
        raise AccountOperationError("INVITATION_NOT_FOUND", "邀请码不存在。")
    return issued


def issue_invitation_batch(*, actor, quantity: int, idempotency_key: str | None = None, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> tuple[InvitationBatch, list[IssuedInvitation]]:
    require_platform_admin(actor)
    if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 1 or quantity > settings.INVITATION_MAX_BATCH_SIZE:
        raise AccountOperationError("INVALID_QUANTITY", f"数量必须在 1 到 {settings.INVITATION_MAX_BATCH_SIZE} 之间。")
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if not idempotency_key or len(idempotency_key) > 128:
            raise AccountOperationError("IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。")
    request_hash = _invitation_issue_request_hash(quantity)
    created_at = now or timezone.now()
    expires_at = None

    with transaction.atomic():
        if idempotency_key is not None:
            existing_batch = (
                InvitationBatch.objects.select_for_update()
                .filter(created_by=actor, idempotency_key=idempotency_key)
                .first()
            )
            if existing_batch:
                if existing_batch.request_hash != request_hash:
                    raise AccountOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发行数量。")
                return existing_batch, _issued_invitations_for_batch(existing_batch)

        try:
            with transaction.atomic():
                batch = InvitationBatch.objects.create(
                    created_by=actor,
                    quantity=quantity,
                    created_at=created_at,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash if idempotency_key is not None else None,
                )
        except IntegrityError:
            if idempotency_key is None:
                raise
            existing_batch = (
                InvitationBatch.objects.select_for_update()
                .filter(created_by=actor, idempotency_key=idempotency_key)
                .first()
            )
            if existing_batch is None:
                raise
            if existing_batch.request_hash != request_hash:
                raise AccountOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发行数量。")
            return existing_batch, _issued_invitations_for_batch(existing_batch)

        result: list[IssuedInvitation] = []
        for _ in range(quantity):
            while True:
                code = _new_invitation_code()
                code_hash = invitation_code_hash(code)
                if not InvitationCode.objects.filter(code_hash=code_hash).exists():
                    break
            invitation = InvitationCode.objects.create(
                batch=batch,
                code_hash=code_hash,
                code_ciphertext=encrypt_invitation_code(code),
                status=InvitationStatus.ISSUED,
                created_at=created_at,
                expires_at=expires_at,
                max_attempts=None,
            )
            result.append(IssuedInvitation(public_id=invitation.public_id, code=code, expires_at=expires_at))
        record_event(
            actor=actor,
            action="invitation.issue",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="InvitationBatch",
            object_public_id=batch.public_id,
            metadata={"quantity": quantity},
        )
    return batch, result


def revoke_invitation(*, actor, public_id, reason: str, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> InvitationCode:
    require_platform_admin(actor)
    reason = reason.strip()
    if len(reason) < 2 or len(reason) > 255:
        raise AccountOperationError("INVALID_REASON", "请填写至少 2 个字的作废原因。")
    current_time = now or timezone.now()
    operation_error: tuple[str, str] | None = None

    with transaction.atomic():
        invitation = InvitationCode.objects.select_for_update().get(public_id=public_id)
        if invitation.status != InvitationStatus.ISSUED:
            record_event(
                actor=actor,
                action="invitation.revoke",
                outcome=AuditOutcome.FAILURE,
                request_id=request_id,
                ip_address=ip_address,
                object_type="InvitationCode",
                object_public_id=invitation.public_id,
                reason_code="INVITATION_UNAVAILABLE",
                metadata={"status": invitation.status},
            )
            operation_error = ("INVITATION_UNAVAILABLE", "该邀请码当前不可作废。")
        elif invitation.expires_at is not None and current_time >= invitation.expires_at:
            invitation.status = InvitationStatus.EXPIRED
            invitation.save(update_fields=("status",), _allow_mutation=True)
            record_event(
                actor=actor,
                action="invitation.revoke",
                outcome=AuditOutcome.FAILURE,
                request_id=request_id,
                ip_address=ip_address,
                object_type="InvitationCode",
                object_public_id=invitation.public_id,
                reason_code="INVITATION_EXPIRED",
                metadata={"status": invitation.status},
            )
            operation_error = ("INVITATION_EXPIRED", "该邀请码已过期，不能作废。")
        else:
            invitation.status = InvitationStatus.REVOKED
            invitation.revoked_at = current_time
            invitation.revoke_reason = reason
            invitation.save(update_fields=("status", "revoked_at", "revoke_reason"), _allow_mutation=True)
            record_event(
                actor=actor,
                action="invitation.revoke",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="InvitationCode",
                object_public_id=invitation.public_id,
                metadata={"reason_length": len(reason)},
            )

    if operation_error:
        raise AccountOperationError(*operation_error)
    return invitation


def _registration_failure(*, username: str, request_id: str | None, ip_address: str | None, reason_code: str = "REGISTRATION_FAILED") -> RegistrationResult:
    record_event(
        action="downstream.register",
        outcome=AuditOutcome.FAILURE,
        request_id=request_id,
        ip_address=ip_address,
        reason_code=reason_code,
        metadata={"username_digest": digest_secret(username.strip().casefold()) if isinstance(username, str) else ""},
    )
    return RegistrationResult(success=False)


def register_downstream(*, invitation_code: str, username: str, password: str, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> RegistrationResult:
    """Register and consume one invitation atomically; all failures are generic."""

    user_model = get_user_model()
    try:
        normalized_username = normalize_username(username)
        _validate_password(password, user=user_model(username=normalized_username))
    except AccountOperationError:
        return _registration_failure(username=username, request_id=request_id, ip_address=ip_address)

    current_time = now or timezone.now()
    code_hash = invitation_code_hash(invitation_code)
    if not code_hash or len(normalize_invitation_code(invitation_code)) > 128:
        return _registration_failure(username=normalized_username, request_id=request_id, ip_address=ip_address)

    user_model = get_user_model()
    with transaction.atomic():
        invitation = InvitationCode.objects.select_for_update().filter(code_hash=code_hash).first()
        if invitation is not None:
            invitation = InvitationCode.objects.select_related("consumed_profile__user").get(pk=invitation.pk)
        if invitation is None:
            return _registration_failure(username=normalized_username, request_id=request_id, ip_address=ip_address)
        if invitation.status != InvitationStatus.ISSUED:
            if invitation.status == InvitationStatus.CONSUMED:
                consumed_name = (invitation.consumed_username or "").casefold()
                if consumed_name == normalized_username:
                    user = user_model.objects.filter(username__iexact=normalized_username).first()
                    profile = invitation.consumed_profile or (get_downstream_profile(user) if user else None)
                    if user is not None and profile is not None and user.check_password(password):
                        return RegistrationResult(success=True, user=user, profile=profile)
            return _registration_failure(username=normalized_username, request_id=request_id, ip_address=ip_address, reason_code="INVITATION_UNAVAILABLE")
        if invitation.expires_at is not None and current_time >= invitation.expires_at:
            invitation.status = InvitationStatus.EXPIRED
            invitation.save(update_fields=("status",), _allow_mutation=True)
            return _registration_failure(username=normalized_username, request_id=request_id, ip_address=ip_address, reason_code="INVITATION_EXPIRED")
        if user_model.objects.filter(username__iexact=normalized_username).exists():
            return _registration_failure(username=normalized_username, request_id=request_id, ip_address=ip_address, reason_code="REGISTRATION_FAILED")

        try:
            with transaction.atomic():
                user = user_model.objects.create_user(username=normalized_username, password=password, is_active=True)
                profile = DownstreamProfile.objects.create(
                    user=user,
                    status=DownstreamStatus.ACTIVE,
                    registration_source=RegistrationSource.INVITATION,
                    registered_at=current_time,
                )
                user.groups.add(_ensure_group(DOWNSTREAM_GROUP))
        except IntegrityError:
            return _registration_failure(username=normalized_username, request_id=request_id, ip_address=ip_address, reason_code="REGISTRATION_FAILED")

        invitation.status = InvitationStatus.CONSUMED
        invitation.consumed_at = current_time
        invitation.consumed_profile = profile
        invitation.consumed_username = normalized_username
        invitation.consumed_username_digest = digest_secret(normalized_username)
        invitation.save(update_fields=("status", "consumed_at", "consumed_profile", "consumed_username", "consumed_username_digest"), _allow_mutation=True)
        record_event(
            actor=user,
            action="downstream.register",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile",
            object_public_id=profile.public_id,
            reason_code="INVITATION_CONSUMED",
            metadata={"username_digest": digest_secret(normalized_username)},
        )
    return RegistrationResult(success=True, user=user, profile=profile)


def create_downstream_direct(*, actor, username: str, password: str, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> DownstreamProfile:
    require_platform_admin(actor)
    user_model = get_user_model()
    try:
        normalized_username = normalize_username(username)
        _validate_password(password, user=None)
    except AccountOperationError as exc:
        record_event(
            actor=actor,
            action="downstream.create_direct",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="ACCOUNT_CREATION_FAILED",
        )
        raise AccountOperationError("ACCOUNT_CREATION_FAILED", "无法创建下游账号，请检查填写内容。") from exc
    current_time = now or timezone.now()
    user_model = get_user_model()
    if user_model.objects.filter(username__iexact=normalized_username).exists():
        record_event(
            actor=actor,
            action="downstream.create_direct",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="ACCOUNT_CREATION_FAILED",
        )
        raise AccountOperationError("ACCOUNT_CREATION_FAILED", "无法创建下游账号，请检查填写内容。")
    try:
        with transaction.atomic():
            try:
                user = user_model.objects.create_user(username=normalized_username, password=password, is_active=True)
                profile = DownstreamProfile.objects.create(
                    user=user,
                    status=DownstreamStatus.ACTIVE,
                    registration_source=RegistrationSource.DIRECT,
                    created_by=actor,
                    registered_at=current_time,
                )
                user.groups.add(_ensure_group(DOWNSTREAM_GROUP))
            except IntegrityError as exc:
                raise AccountOperationError("ACCOUNT_CREATION_FAILED", "无法创建下游账号，请检查填写内容。") from exc
            record_event(
                actor=actor,
                action="downstream.create_direct",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="DownstreamProfile",
                object_public_id=profile.public_id,
                metadata={"username_digest": digest_secret(normalized_username)},
            )
    except AccountOperationError:
        record_event(
            actor=actor,
            action="downstream.create_direct",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code="ACCOUNT_CREATION_FAILED",
        )
        raise
    return profile


def set_downstream_status(*, actor, public_id, status: str, reason: str, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> DownstreamProfile:
    require_platform_admin(actor)
    reason = reason.strip()
    if len(reason) < 2 or len(reason) > 255:
        raise AccountOperationError("INVALID_REASON", "请填写至少 2 个字的状态变更原因。")
    if status not in {DownstreamStatus.ACTIVE, DownstreamStatus.SUSPENDED}:
        raise AccountOperationError("INVALID_STATUS", "下游状态无效。")
    with transaction.atomic():
        profile = DownstreamProfile.objects.select_for_update().select_related("user").get(public_id=public_id)
        if profile.status == DownstreamStatus.CLOSED:
            raise AccountOperationError("ALREADY_CLOSED", "已归档下游不能恢复。")
        profile.status = status
        profile.user.is_active = True
        profile.user.save(update_fields=("is_active",))
        profile.save(update_fields=("status", "updated_at"))
        record_event(
            actor=actor,
            action="downstream.resume" if status == DownstreamStatus.ACTIVE else "downstream.suspend",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile",
            object_public_id=profile.public_id,
            metadata={"reason_length": len(reason), "status": status},
        )
    return profile


def record_successful_login(user, *, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> None:
    profile = get_downstream_profile(user)
    if profile and profile.status == DownstreamStatus.ACTIVE:
        profile.last_successful_login_at = now or timezone.now()
        profile.save(update_fields=("last_successful_login_at", "updated_at"))
    record_event(
        actor=user,
        action="auth.login",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        ip_address=ip_address,
        object_type="DownstreamProfile" if profile else "",
        object_public_id=profile.public_id if profile else "",
    )


def visible_profile_for(actor, public_id) -> DownstreamProfile:
    if is_platform_admin(actor):
        return DownstreamProfile.objects.select_related("user").get(public_id=public_id)
    profile = get_downstream_profile(actor)
    if not is_active_downstream(actor) or not profile or profile.public_id != public_id:
        raise DownstreamProfile.DoesNotExist
    return DownstreamProfile.objects.select_related("user").get(public_id=public_id, user=actor)


def list_visible_profiles(actor) -> Iterable[DownstreamProfile]:
    if is_platform_admin(actor):
        return DownstreamProfile.objects.select_related("user", "created_by").all()
    profile = get_downstream_profile(actor)
    if not is_active_downstream(actor) or not profile:
        return DownstreamProfile.objects.none()
    return DownstreamProfile.objects.select_related("user").filter(public_id=profile.public_id, user=actor)


def _require_cleared_downstream_balance(profile: DownstreamProfile) -> None:
    from authorization_platform.credits.models import QuotaAccount

    account = (
        QuotaAccount.objects.select_for_update()
        .filter(downstream_public_id=profile.public_id)
        .first()
    )
    if account is not None and int(account.available_balance or 0) > 0:
        raise AccountOperationError("BALANCE_NOT_CLEARED", "请先把可用额度扣光，未清完不能归档或删除。")


def archive_downstream(*, actor, public_id, reason: str, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> DownstreamProfile:
    require_platform_admin(actor)
    reason = reason.strip()
    if not reason or len(reason) > 255:
        raise AccountOperationError("INVALID_REASON", "请填写归档原因。")
    current_time = now or timezone.now()
    with transaction.atomic():
        profile = DownstreamProfile.objects.select_for_update().select_related("user").get(public_id=public_id)
        if profile.status == DownstreamStatus.CLOSED:
            raise AccountOperationError("ALREADY_CLOSED", "该下游已经归档。")
        _require_cleared_downstream_balance(profile)
        profile.status = DownstreamStatus.CLOSED
        profile.closed_at = current_time
        profile.closed_by = actor
        profile.closed_reason = reason
        profile.session_version += 1
        profile.save(update_fields=("status", "closed_at", "closed_by", "closed_reason", "session_version", "updated_at"))
        profile.user.is_active = False
        profile.user.save(update_fields=("is_active",))
        record_event(
            actor=actor,
            action="downstream.archive",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamProfile",
            object_public_id=profile.public_id,
            metadata={"reason_length": len(reason)},
        )
    return profile


def delete_archived_downstream(*, actor, public_id, reason: str, now: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> DownstreamTombstone:
    require_platform_admin(actor)
    reason = reason.strip()
    if len(reason) < 2 or len(reason) > 255:
        raise AccountOperationError("INVALID_REASON", "请填写至少 2 个字的删除原因。")
    current_time = now or timezone.now()
    with transaction.atomic():
        profile = DownstreamProfile.objects.select_for_update().select_related("user").get(public_id=public_id)
        if profile.status != DownstreamStatus.CLOSED:
            raise AccountOperationError("ARCHIVE_REQUIRED", "必须先归档下游账号，才能删除。")
        _require_cleared_downstream_balance(profile)
        tombstone = DownstreamTombstone.objects.create(
            public_id=profile.public_id,
            username_digest=digest_secret(profile.user.username),
            deleted_at=current_time,
            deleted_by=actor,
            delete_reason=reason[:255],
        )
        user = profile.user
        profile.delete()
        user.delete()
        record_event(
            actor=actor,
            action="downstream.delete",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamTombstone",
            object_public_id=tombstone.public_id,
            metadata={"reason_length": len(reason)},
        )
    return tombstone


TERMINAL_INVITATION_STATUSES = {
    InvitationStatus.CONSUMED,
    InvitationStatus.REVOKED,
    InvitationStatus.EXPIRED,
}


def _invitation_terminal_at(code: InvitationCode, *, now=None):
    current_time = now or timezone.now()
    if code.status == InvitationStatus.ISSUED and code.expires_at is not None and current_time >= code.expires_at:
        return code.expires_at
    if code.status == InvitationStatus.CONSUMED:
        return code.consumed_at
    if code.status == InvitationStatus.REVOKED:
        return code.revoked_at
    if code.status == InvitationStatus.EXPIRED:
        return code.expires_at
    return None


def _invitation_lifecycle_request_hash(*, code_ids: list, reason: str) -> str:
    joined = ",".join(sorted(str(public_id) for public_id in code_ids))
    return hashlib.sha256(f"{joined}\n{reason}".encode("utf-8")).hexdigest()


def _normalize_invitation_code_ids(values) -> list:
    import uuid as uuid_module

    if not isinstance(values, (list, tuple)) or not values:
        raise AccountOperationError("INVALID_REQUEST", "请至少选择一个邀请码。")
    normalized: list = []
    for raw in values:
        try:
            normalized.append(uuid_module.UUID(str(raw)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise AccountOperationError("INVALID_REQUEST", "邀请码标识格式不正确。") from exc
    if len(normalized) != len(set(normalized)):
        raise AccountOperationError("INVALID_REQUEST", "邀请码标识重复，请检查选择。")
    return sorted(normalized)


def _validate_invitation_archivable(code: InvitationCode, *, now) -> None:
    terminal_at = _invitation_terminal_at(code, now=now)
    if code.status == InvitationStatus.ISSUED and terminal_at is None:
        raise AccountOperationError(
            "INVITATION_NOT_ARCHIVABLE",
            "有效未使用邀请码需先撤销后才能归档。",
        )
    if code.status == InvitationStatus.ARCHIVED:
        raise AccountOperationError(
            "INVITATION_ALREADY_ARCHIVED",
            "这个邀请码已经归档，不能重复归档。",
        )
    if terminal_at is None:
        raise AccountOperationError(
            "INVITATION_NOT_ARCHIVABLE",
            "这个邀请码还没有进入可归档状态。",
        )
    return


def _claim_invitation_lifecycle_operation(*, actor, action: str, idempotency_key: str, request_hash: str):
    existing = InvitationLifecycleOperation.objects.select_for_update().filter(
        actor=actor,
        idempotency_key=idempotency_key,
    ).first()
    if existing is not None:
        if existing.action != action or existing.request_hash != request_hash:
            raise AccountOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的生命周期内容。")
        if not existing.response_payload:
            raise AccountOperationError("LIFECYCLE_RETRYABLE", "生命周期操作正在处理中，请稍后重试。")
        return None, {**existing.response_payload, "repeated": True}
    try:
        with transaction.atomic():
            operation = InvitationLifecycleOperation.objects.create(
                actor=actor,
                action=action,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_payload={},
            )
    except IntegrityError:
        existing = InvitationLifecycleOperation.objects.select_for_update().get(
            actor=actor,
            idempotency_key=idempotency_key,
        )
        if existing.action != action or existing.request_hash != request_hash:
            raise AccountOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的生命周期内容。")
        if not existing.response_payload:
            raise AccountOperationError("LIFECYCLE_RETRYABLE", "生命周期操作正在处理中，请稍后重试。")
        return None, {**existing.response_payload, "repeated": True}
    return operation, None


def archive_invitations(
    *,
    actor,
    code_ids,
    reason: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
    now=None,
) -> dict:
    if not is_platform_admin(actor):
        raise AccountOperationError("FORBIDDEN", "只有平台管理员可以归档邀请码。")
    if not isinstance(reason, str) or len(reason.strip()) < 4 or len(reason.strip()) > 255:
        raise AccountOperationError("INVALID_REASON", "归档原因必须是 4 至 255 个字符。")
    normalized = _normalize_invitation_code_ids(code_ids)
    archive_reason = reason.strip()
    current_time = now or timezone.now()
    request_key = _normalize_idempotency_key(idempotency_key)
    request_hash = _invitation_lifecycle_request_hash(code_ids=normalized, reason=archive_reason)

    with transaction.atomic():
        operation, replay = _claim_invitation_lifecycle_operation(
            actor=actor,
            action="archive",
            idempotency_key=request_key,
            request_hash=request_hash,
        )
        if replay is not None:
            return replay
        codes = list(
            InvitationCode.objects.select_for_update().filter(public_id__in=normalized)
        )
        if len(codes) != len(normalized):
            raise AccountOperationError("INVITATION_NOT_FOUND", "部分邀请码不存在。")
        for code in codes:
            _validate_invitation_archivable(code, now=current_time)
        archived: list[dict] = []
        for code in codes:
            from_status = code.status
            code.status = InvitationStatus.ARCHIVED
            code.archived_at = current_time
            code.status_reason = archive_reason
            code.save(update_fields=("status", "archived_at", "status_reason"), _allow_mutation=True)
            record_event(
                actor=actor,
                action="invitation.archive",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="InvitationCode",
                object_public_id=code.public_id,
                metadata={
                    "from_status": from_status,
                    "to_status": InvitationStatus.ARCHIVED,
                    "code_digest": code.code_hash,
                    "reason": archive_reason,
                },
            )
            archived.append({"public_id": str(code.public_id)})
        response_payload = {"archived_count": len(archived), "archived": archived, "reason": archive_reason}
        operation.response_payload = response_payload
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return response_payload


def delete_invitations(
    *,
    actor,
    code_ids,
    reason: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
    now=None,
) -> dict:
    if not is_platform_admin(actor):
        raise AccountOperationError("FORBIDDEN", "只有平台管理员可以删除邀请码。")
    if not isinstance(reason, str) or len(reason.strip()) < 4 or len(reason.strip()) > 255:
        raise AccountOperationError("INVALID_REASON", "删除原因必须是 4 至 255 个字符。")
    normalized = _normalize_invitation_code_ids(code_ids)
    delete_reason = reason.strip()
    current_time = now or timezone.now()
    request_key = _normalize_idempotency_key(idempotency_key)
    request_hash = _invitation_lifecycle_request_hash(code_ids=normalized, reason=delete_reason)

    with transaction.atomic():
        operation, replay = _claim_invitation_lifecycle_operation(
            actor=actor,
            action="delete",
            idempotency_key=request_key,
            request_hash=request_hash,
        )
        if replay is not None:
            return replay
        codes = list(
            InvitationCode.objects.select_for_update().filter(public_id__in=normalized)
        )
        if len(codes) != len(normalized):
            raise AccountOperationError("INVITATION_NOT_FOUND", "部分邀请码不存在。")
        deleted: list[dict] = []
        for code in codes:
            if code.status != InvitationStatus.ARCHIVED:
                raise AccountOperationError(
                    "INVITATION_NOT_DELETABLE",
                    "只有已归档的邀请码才能删除。",
                )
            InvitationCodeTombstone.objects.create(
                code_public_id=code.public_id,
                code_hash=code.code_hash,
                terminal_status=code.status,
                consumed_username_digest=code.consumed_username_digest,
                archived_at=code.archived_at or current_time,
                deleted_at=current_time,
                actor_id=actor.pk,
                reason=delete_reason,
            )
            record_event(
                actor=actor,
                action="invitation.delete",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="InvitationCodeTombstone",
                object_public_id=code.public_id,
                metadata={
                    "from_status": code.status,
                    "to_status": InvitationStatus.DELETED_TOMBSTONE,
                    "reason": delete_reason,
                },
            )
            deleted_public_id = str(code.public_id)
            code.status = InvitationStatus.DELETED_TOMBSTONE
            code.status_reason = delete_reason
            code.save(update_fields=("status", "status_reason"), _allow_mutation=True)
            deleted.append({"public_id": deleted_public_id})
        response_payload = {"deleted_count": len(deleted), "deleted": deleted, "reason": delete_reason}
        operation.response_payload = response_payload
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return response_payload
