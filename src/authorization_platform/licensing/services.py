from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.db import IntegrityError, transaction
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus
from authorization_platform.accounts.services import get_downstream_profile, is_active_downstream, is_platform_admin
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.configuration import ConfigurationOperationError, new_config_version, normalize_configuration
from authorization_platform.catalog.models import (
    DownstreamSoftware,
    DownstreamSoftwareStatus,
    Plan,
    PlanSnapshot,
    PlanStatus,
    ProfileStatus,
    SoftwareStatus,
    SoftwareProfile,
)
from authorization_platform.credits.models import QuotaLedgerEntry, QuotaLedgerOperation
from authorization_platform.credits.services import (
    QuotaOperationError,
    debit_quota,
    get_quota_account,
    rebuild_quota_balance,
    _refund_license_card_quota,
)

from .models import (
    LicenseCard,
    LicenseCardBatch,
    LicenseCardLifecycleOperation,
    LicenseCardStatus,
    LicenseCardTombstone,
    LicenseInstance,
)


LICENSE_CARD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
LICENSE_CARD_PREFIX = "LC-"
MAX_CARD_COLLISION_RETRIES = 12


class LicenseOperationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def set_authorization_configuration_override(*, actor, authorization_id, values: dict | None = None, clear: bool = False, request_id: str | None = None, ip_address: str | None = None) -> LicenseInstance:
    """Set or clear a typed per-authorization configuration override."""

    if not is_platform_admin(actor):
        raise LicenseOperationError("FORBIDDEN", "只有管理员可以配置客户授权覆盖。")
    try:
        normalized = {} if clear else normalize_configuration(values or {})
    except ConfigurationOperationError as exc:
        raise LicenseOperationError(exc.code, exc.message) from exc
    with transaction.atomic():
        try:
            instance = LicenseInstance.objects.select_for_update().get(
                authorization_id=authorization_id,
            )
        except LicenseInstance.DoesNotExist as exc:
            raise LicenseOperationError("AUTHORIZATION_NOT_FOUND", "授权实例不存在。") from exc
        profile = SoftwareProfile.objects.select_for_update().get(pk=instance.profile_id)
        base_config_version = profile.config_version
        if clear:
            access = DownstreamSoftware.objects.select_for_update().filter(
                downstream__public_id=instance.current_downstream_public_id,
                software_id=instance.software_id,
            ).first()
            if access and access.configuration_enabled:
                base_config_version = access.config_version
        instance.configuration_override = normalized
        instance.config_version = base_config_version if clear else new_config_version()
        instance.save(update_fields=("configuration_override", "config_version", "updated_at"), _allow_mutation=True)
        record_event(
            actor=actor,
            action="authorization.configuration_override.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseInstance",
            object_public_id=instance.authorization_id,
            metadata={"enabled": not clear, "config_version": instance.config_version},
        )
    return instance


@dataclass(frozen=True)
class IssuedLicenseCard:
    public_id: object
    software_id: str
    profile_id: str
    plan_snapshot_id: object
    quota_cost: int
    code: str


@dataclass(frozen=True)
class LicenseBatchResult:
    batch: LicenseCardBatch
    cards: list[IssuedLicenseCard]
    repeated: bool = False


@dataclass(frozen=True)
class LicenseReclaimResult:
    card: LicenseCard
    entry: QuotaLedgerEntry | None
    repeated: bool = False


@dataclass(frozen=True)
class LicenseBatchPreview:
    software_id: str
    plan_id: int
    plan_name: str
    snapshot_id: object
    snapshot_version: int
    duration_seconds: int
    test_only: bool
    quota_cost_per_card: int
    quantity: int
    total_quota_cost: int
    available_balance: int
    balance_after: int | None
    sufficient_balance: bool
    preview_token: str


def normalize_license_card_code(value: str) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(value.split()).upper()


def license_card_hash(value: str) -> str:
    key = getattr(settings, "LICENSE_CARD_HASH_KEY", settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, normalize_license_card_code(value).encode("utf-8"), hashlib.sha256).hexdigest()


def _fernet_for_key(key) -> Fernet:
    return Fernet(key.encode("ascii") if isinstance(key, str) else key)


def _fernet_candidates(key_version: str | None = None) -> list[Fernet]:
    current_key = settings.LICENSE_CARD_ENCRYPTION_KEY
    current_version = settings.LICENSE_CARD_ENCRYPTION_KEY_VERSION
    legacy_key = getattr(settings, "LICENSE_CARD_LEGACY_ENCRYPTION_KEY", "")
    candidates: list[Fernet] = []
    if not key_version or key_version == current_version:
        candidates.append(_fernet_for_key(current_key))
    if legacy_key and (not key_version or key_version != current_version or key_version == "v1"):
        if legacy_key != current_key:
            candidates.append(_fernet_for_key(legacy_key))
    return candidates


def _fernet() -> Fernet:
    candidates = _fernet_candidates()
    if not candidates:
        raise LicenseOperationError("CREDENTIAL_UNAVAILABLE", "授权卡密加密密钥未配置。")
    return candidates[0]


def encrypt_license_card(code: str) -> str:
    return _fernet().encrypt(code.encode("utf-8")).decode("ascii")


def decrypt_license_card(ciphertext: str, *, key_version: str | None = None) -> str:
    last_error: Exception | None = None
    for fernet in _fernet_candidates(key_version):
        try:
            return fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
            last_error = exc
    raise LicenseOperationError("CREDENTIAL_UNAVAILABLE", "授权卡密暂时无法再次交付，请联系管理员。") from last_error


def _new_license_card_code() -> str:
    return LICENSE_CARD_PREFIX + "".join(secrets.choice(LICENSE_CARD_ALPHABET) for _ in range(24))


def _positive_int(value, *, label: str, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise LicenseOperationError("INVALID_QUANTITY", f"{label}必须是正整数。")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise LicenseOperationError("INVALID_QUANTITY", f"{label}必须是正整数。") from exc
    if number < 1 or (maximum is not None and number > maximum):
        suffix = f"，不能超过 {maximum}" if maximum is not None else ""
        raise LicenseOperationError("INVALID_QUANTITY", f"{label}必须是正整数{suffix}。")
    return number


def _idempotency_key(value: str | None) -> str:
    if not isinstance(value, str):
        raise LicenseOperationError("IDEMPOTENCY_REQUIRED", "缺少幂等键，请重新预览后确认。")
    normalized = value.strip()
    if not normalized or len(normalized) > 128:
        raise LicenseOperationError("IDEMPOTENCY_REQUIRED", "幂等键格式不正确，请重新预览后确认。")
    return normalized


def _active_profile(actor) -> DownstreamProfile:
    profile = get_downstream_profile(actor)
    if not profile:
        raise PermissionDenied
    if not is_active_downstream(actor) or profile.status != DownstreamStatus.ACTIVE:
        raise LicenseOperationError("DOWNSTREAM_NOT_ACTIVE", "当前下游账号不可生成授权卡密。")
    return profile


def _request_hash(*, software_id: str, snapshot_id, quantity: int) -> str:
    payload = f"license_batch:{software_id}:{snapshot_id}:{quantity}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _preview_signer() -> TimestampSigner:
    return TimestampSigner(salt="authorization-platform.license-preview.v1")


def _create_preview_token(*, profile: DownstreamProfile, software_id: str, snapshot: PlanSnapshot, quantity: int, total_cost: int) -> str:
    payload = {
        "downstream_id": str(profile.public_id),
        "software_id": software_id,
        "snapshot_id": str(snapshot.snapshot_id),
        "quantity": quantity,
        "unit_cost": snapshot.quota_cost,
        "total_cost": total_cost,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return _preview_signer().sign(raw)


def _read_preview_token(*, token: str, profile: DownstreamProfile, software_id: str, snapshot_id, quantity: int) -> dict:
    if not isinstance(token, str) or not token.strip():
        raise LicenseOperationError("PREVIEW_REQUIRED", "请先完成成本预览，再确认生成。")
    try:
        payload = json.loads(_preview_signer().unsign(token, max_age=settings.LICENSE_CARD_PREVIEW_TTL_SECONDS))
    except (BadSignature, SignatureExpired, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LicenseOperationError("PREVIEW_EXPIRED", "成本预览已失效，请重新预览。") from exc
    if not isinstance(payload, dict):
        raise LicenseOperationError("PREVIEW_EXPIRED", "成本预览已失效，请重新预览。")
    expected = {
        "downstream_id": str(profile.public_id),
        "software_id": software_id,
        "snapshot_id": str(snapshot_id),
        "quantity": quantity,
    }
    if any(str(payload.get(key)) != str(value) for key, value in expected.items()):
        raise LicenseOperationError("PREVIEW_MISMATCH", "确认内容已脱离成本预览，请重新预览。")
    try:
        payload["unit_cost"] = int(payload["unit_cost"])
        payload["total_cost"] = int(payload["total_cost"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LicenseOperationError("PREVIEW_EXPIRED", "成本预览已失效，请重新预览。") from exc
    return payload


def _total_cost(*, unit_cost: int, quantity: int) -> int:
    total = unit_cost * quantity
    if total > settings.LICENSE_CARD_MAX_TOTAL_COST:
        raise LicenseOperationError(
            "TOTAL_COST_LIMIT",
            f"本批次总额度成本不能超过 {settings.LICENSE_CARD_MAX_TOTAL_COST}。",
        )
    return total


def _get_access(*, profile: DownstreamProfile, plan: Plan) -> DownstreamSoftware:
    software = plan.software
    access = DownstreamSoftware.objects.select_for_update().filter(
        downstream=profile,
        software=software,
        status=DownstreamSoftwareStatus.ACTIVE,
    ).first()
    if not access:
        raise LicenseOperationError("SOFTWARE_NOT_OPEN", "当前下游没有经营这个软件。")
    if not access.all_plans_allowed and not access.allowed_plans.filter(pk=plan.pk).exists():
        raise LicenseOperationError("PLAN_NOT_OPEN", "当前下游没有开放这个套餐。")
    if software.status not in {SoftwareStatus.TESTING, SoftwareStatus.ACTIVE}:
        raise LicenseOperationError("SOFTWARE_NOT_AVAILABLE", "软件当前没有开放授权卡密生成。")
    if software.status == SoftwareStatus.TESTING and not plan.test_only:
        raise LicenseOperationError("PLAN_NOT_AVAILABLE", "测试中的软件只能生成测试套餐授权卡密。")
    if plan.status != PlanStatus.ACTIVE or plan.profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
        raise LicenseOperationError("PLAN_NOT_AVAILABLE", "套餐当前不可生成授权卡密。")
    if plan.effective_at > timezone.now():
        raise LicenseOperationError("PLAN_NOT_EFFECTIVE", "套餐尚未到生效时间。")
    if plan.profile.software_id != software.software_id:
        raise LicenseOperationError("PLAN_NOT_AVAILABLE", "套餐与软件 Profile 不匹配。")
    return access


def _resolve_latest_snapshot(*, profile: DownstreamProfile, software_id: str, plan_id) -> PlanSnapshot:
    try:
        plan = (
            Plan.objects.select_for_update()
            .select_related("software", "profile")
            .get(pk=plan_id, software_id=software_id)
        )
    except (Plan.DoesNotExist, ValueError, TypeError) as exc:
        raise LicenseOperationError("PLAN_NOT_AVAILABLE", "套餐当前不可生成授权卡密。") from exc
    try:
        _get_access(profile=profile, plan=plan)
    except LicenseOperationError as exc:
        raise LicenseOperationError("PLAN_NOT_AVAILABLE", "套餐当前不可生成授权卡密。") from exc
    snapshot = plan.snapshots.select_related("software", "profile", "policy_version").order_by("-snapshot_version").first()
    if not snapshot:
        raise LicenseOperationError("PLAN_SNAPSHOT_NOT_FOUND", "套餐还没有可用的不可变快照。")
    return snapshot


def _resolve_snapshot_for_generation(*, profile: DownstreamProfile, software_id: str, snapshot_id) -> PlanSnapshot:
    try:
        requested = PlanSnapshot.objects.select_related("software", "profile", "plan").get(pk=snapshot_id)
        plan = Plan.objects.select_for_update().select_related("software", "profile").get(pk=requested.plan_id)
    except (PlanSnapshot.DoesNotExist, Plan.DoesNotExist, ValueError, TypeError) as exc:
        raise LicenseOperationError("PLAN_SNAPSHOT_NOT_FOUND", "套餐快照不存在或已不可用。") from exc
    if str(plan.software_id) != software_id or requested.software_id != plan.software_id or requested.profile_id != plan.profile_id:
        raise LicenseOperationError("PLAN_NOT_AVAILABLE", "所选套餐快照与软件 Profile 不匹配。")
    latest_id = plan.snapshots.order_by("-snapshot_version").values_list("snapshot_id", flat=True).first()
    if latest_id != requested.snapshot_id:
        raise LicenseOperationError("PLAN_SNAPSHOT_STALE", "套餐已更新，请返回重新预览最新成本。")
    _get_access(profile=profile, plan=plan)
    return PlanSnapshot.objects.select_related("software", "profile", "plan", "policy_version").get(pk=requested.pk)


def preview_license_batch(*, actor, software_id: str, plan_id, quantity: int) -> LicenseBatchPreview:
    profile = _active_profile(actor)
    if not isinstance(software_id, str) or not software_id.strip():
        raise LicenseOperationError("INVALID_REQUEST", "请选择软件。")
    software_id = software_id.strip().casefold()
    quantity = _positive_int(quantity, label="生成数量", maximum=settings.LICENSE_CARD_MAX_BATCH_SIZE)
    with transaction.atomic():
        snapshot = _resolve_latest_snapshot(profile=profile, software_id=software_id, plan_id=plan_id)
        account = get_quota_account(profile)
        if rebuild_quota_balance(account) != account.available_balance:
            raise LicenseOperationError("BALANCE_INCONSISTENT", "额度账本与余额汇总不一致，已阻止本次预览。")
        total = _total_cost(unit_cost=snapshot.quota_cost, quantity=quantity)
        return LicenseBatchPreview(
            software_id=software_id,
            plan_id=snapshot.plan_id,
            plan_name=snapshot.name,
            snapshot_id=snapshot.snapshot_id,
            snapshot_version=snapshot.snapshot_version,
            duration_seconds=snapshot.duration_seconds,
            test_only=snapshot.test_only,
            quota_cost_per_card=snapshot.quota_cost,
            quantity=quantity,
            total_quota_cost=total,
            available_balance=account.available_balance,
            balance_after=account.available_balance - total if account.available_balance >= total else None,
            sufficient_balance=account.available_balance >= total,
            preview_token=_create_preview_token(
                profile=profile,
                software_id=software_id,
                snapshot=snapshot,
                quantity=quantity,
                total_cost=total,
            ),
        )


def _existing_batch(*, profile: DownstreamProfile, key: str) -> LicenseCardBatch | None:
    return (
        LicenseCardBatch.objects.select_for_update()
        .select_related("software", "profile", "plan_snapshot")
        .filter(current_downstream_public_id=profile.public_id, idempotency_key=key)
        .first()
    )


def _result_for_batch(batch: LicenseCardBatch, *, repeated: bool) -> LicenseBatchResult:
    cards: list[IssuedLicenseCard] = []
    for card in batch.cards.select_related("profile").order_by("issued_at", "public_id"):
        if card.status == LicenseCardStatus.DELETED_TOMBSTONE:
            continue
        cards.append(
            IssuedLicenseCard(
                public_id=card.public_id,
                software_id=card.software_id,
                profile_id=card.profile.profile_id,
                plan_snapshot_id=card.plan_snapshot_id,
                quota_cost=card.quota_cost,
                code=decrypt_license_card(card.card_ciphertext, key_version=card.encryption_key_version),
            )
        )
    if not cards:
        raise LicenseOperationError("LICENSE_CARD_NOT_FOUND", "授权卡密不存在。")
    return LicenseBatchResult(batch=batch, cards=cards, repeated=repeated)


def _create_card(*, batch: LicenseCardBatch, code: str, issued_at: datetime) -> LicenseCard:
    return LicenseCard.objects.create(
        batch=batch,
        software=batch.software,
        profile=batch.profile,
        plan_snapshot=batch.plan_snapshot,
        original_downstream=batch.original_downstream,
        current_downstream=batch.current_downstream,
        original_downstream_public_id=batch.original_downstream_public_id,
        current_downstream_public_id=batch.current_downstream_public_id,
        quota_cost=batch.quota_cost_per_card,
        card_hash=license_card_hash(code),
        card_ciphertext=encrypt_license_card(code),
        encryption_key_version=settings.LICENSE_CARD_ENCRYPTION_KEY_VERSION,
        status=LicenseCardStatus.UNUSED,
        issued_by=batch.created_by,
        issued_at=issued_at,
    )


def _issue_cards(*, batch: LicenseCardBatch, issued_at: datetime) -> list[IssuedLicenseCard]:
    issued: list[IssuedLicenseCard] = []
    for _ in range(batch.quantity):
        card = None
        code = ""
        for _attempt in range(MAX_CARD_COLLISION_RETRIES):
            code = _new_license_card_code()
            if LicenseCard.objects.filter(card_hash=license_card_hash(code)).exists():
                continue
            try:
                with transaction.atomic():
                    card = _create_card(batch=batch, code=code, issued_at=issued_at)
            except IntegrityError:
                continue
            break
        if card is None:
            raise LicenseOperationError("CARD_GENERATION_FAILED", "授权卡密生成失败，事务已回滚，请稍后重试。")
        issued.append(
            IssuedLicenseCard(
                public_id=card.public_id,
                software_id=card.software_id,
                profile_id=card.profile.profile_id,
                plan_snapshot_id=card.plan_snapshot_id,
                quota_cost=card.quota_cost,
                code=code,
            )
        )
    return sorted(issued, key=lambda item: str(item.public_id))


def generate_license_batch(
    *,
    actor,
    software_id: str,
    plan_snapshot_id,
    quantity: int,
    idempotency_key: str | None,
    preview_token: str | None = None,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> LicenseBatchResult:
    profile = _active_profile(actor)
    if not isinstance(software_id, str) or not software_id.strip():
        raise LicenseOperationError("INVALID_REQUEST", "缺少软件身份。")
    software_id = software_id.strip().casefold()
    quantity = _positive_int(quantity, label="生成数量", maximum=settings.LICENSE_CARD_MAX_BATCH_SIZE)
    key = _idempotency_key(idempotency_key)
    issued_at = now or timezone.now()
    preview_payload = _read_preview_token(
        token=preview_token,
        profile=profile,
        software_id=software_id,
        snapshot_id=plan_snapshot_id,
        quantity=quantity,
    ) if preview_token is not None else None
    request_hash = _request_hash(software_id=software_id, snapshot_id=plan_snapshot_id, quantity=quantity)

    try:
        with transaction.atomic():
            try:
                profile = DownstreamProfile.objects.select_for_update().select_related("user").get(pk=profile.pk)
            except DownstreamProfile.DoesNotExist as exc:
                raise LicenseOperationError("DOWNSTREAM_NOT_ACTIVE", "当前下游账号不可生成授权卡密。") from exc
            if profile.status != DownstreamStatus.ACTIVE or not profile.user.is_active:
                raise LicenseOperationError("DOWNSTREAM_NOT_ACTIVE", "当前下游账号不可生成授权卡密。")
            existing = _existing_batch(profile=profile, key=key)
            if existing:
                if existing.request_hash != request_hash:
                    raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发卡内容。")
                return _result_for_batch(existing, repeated=True)

            snapshot = _resolve_snapshot_for_generation(
                profile=profile,
                software_id=software_id,
                snapshot_id=plan_snapshot_id,
            )
            total_cost = _total_cost(unit_cost=snapshot.quota_cost, quantity=quantity)
            if preview_payload and (
                preview_payload["unit_cost"] != snapshot.quota_cost
                or preview_payload["total_cost"] != total_cost
            ):
                raise LicenseOperationError("PREVIEW_MISMATCH", "套餐成本已变化，请重新预览。")
            request_hash = _request_hash(software_id=software_id, snapshot_id=snapshot.snapshot_id, quantity=quantity)

            existing = _existing_batch(profile=profile, key=key)
            if existing:
                if existing.request_hash != request_hash:
                    raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发卡内容。")
                return _result_for_batch(existing, repeated=True)

            try:
                with transaction.atomic():
                    batch = LicenseCardBatch.objects.create(
                        software=snapshot.software,
                        profile=snapshot.profile,
                        plan_snapshot=snapshot,
                        original_downstream=profile,
                        current_downstream=profile,
                        original_downstream_public_id=profile.public_id,
                        current_downstream_public_id=profile.public_id,
                        quantity=quantity,
                        quota_cost_per_card=snapshot.quota_cost,
                        total_quota_cost=total_cost,
                        source="downstream",
                        idempotency_key=key,
                        request_hash=request_hash,
                        created_by=actor,
                        created_at=issued_at,
                    )
            except IntegrityError:
                existing = _existing_batch(profile=profile, key=key)
                if not existing:
                    raise
                if existing.request_hash != request_hash:
                    raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发卡内容。")
                return _result_for_batch(existing, repeated=True)

            debit_entry = None
            if batch.total_quota_cost:
                try:
                    debit_entry = debit_quota(
                        actor=actor,
                        downstream=profile,
                        amount=batch.total_quota_cost,
                        reason=f"生成授权卡密：{snapshot.name} × {quantity}",
                        idempotency_key=f"license-batch:{batch.batch_id}",
                        source_type="LicenseCardBatch",
                        source_public_id=str(batch.batch_id),
                        operation_type=QuotaLedgerOperation.LICENSE_CARD_ISSUE,
                        now=issued_at,
                        request_id=request_id,
                        ip_address=ip_address,
                    )
                except QuotaOperationError as exc:
                    raise LicenseOperationError(exc.code, exc.message) from exc

            issued = _issue_cards(batch=batch, issued_at=issued_at)
            record_event(
                actor=actor,
                action="license_batch.issue",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseCardBatch",
                object_public_id=batch.batch_id,
                metadata={
                    "software_id": snapshot.software_id,
                    "profile_id": snapshot.profile.profile_id,
                    "plan_snapshot_id": str(snapshot.snapshot_id),
                    "quantity": quantity,
                    "quota_cost": batch.total_quota_cost,
                    "quota_ledger_entry_id": str(debit_entry.public_id) if debit_entry else "",
                },
            )
            from authorization_platform.backup_control.services import schedule_change_backup

            schedule_change_backup(actor=actor)
            return LicenseBatchResult(batch=batch, cards=issued)
    except LicenseOperationError as exc:
        record_event(
            actor=actor,
            action="license_batch.issue",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=exc.code,
            object_type="DownstreamProfile",
            object_public_id=profile.public_id,
            metadata={"software_id": software_id, "quantity": quantity},
        )
        raise


def issued_cards_for_batch(*, actor, batch_public_id) -> list[IssuedLicenseCard]:
    profile = _active_profile(actor)
    try:
        batch = LicenseCardBatch.objects.select_related("software", "profile", "plan_snapshot").prefetch_related("cards__profile").get(
            batch_id=batch_public_id,
            current_downstream_public_id=profile.public_id,
        )
    except (LicenseCardBatch.DoesNotExist, ValueError, TypeError) as exc:
        raise LicenseOperationError("BATCH_NOT_FOUND", "授权卡密批次不存在。") from exc
    return _result_for_batch(batch, repeated=False).cards


def list_license_batches(*, actor, limit: int = 50):
    profile = _active_profile(actor)
    limit = _positive_int(limit, label="列表数量", maximum=200)
    return (
        LicenseCardBatch.objects.filter(current_downstream_public_id=profile.public_id)
        .select_related("software", "profile", "plan_snapshot__plan")
        .prefetch_related("cards")
        .order_by("-created_at")[:limit]
    )


def export_license_batch(*, actor, batch_public_id, request_id: str | None = None, ip_address: str | None = None):
    profile = _active_profile(actor)
    try:
        batch = (
            LicenseCardBatch.objects.filter(
                batch_id=batch_public_id,
                current_downstream_public_id=profile.public_id,
            )
            .select_related("software", "profile", "plan_snapshot")
            .prefetch_related("cards__profile")
            .get()
        )
    except (LicenseCardBatch.DoesNotExist, ValueError, TypeError) as exc:
        error = LicenseOperationError("BATCH_NOT_FOUND", "授权卡密批次不存在。")
        record_event(
            actor=actor,
            action="license_batch.export",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=error.code,
        )
        raise error from exc
    cards = list(batch.cards.all())
    record_event(
        actor=actor,
        action="license_batch.export",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        ip_address=ip_address,
        object_type="LicenseCardBatch",
        object_public_id=batch.batch_id,
        metadata={
            "card_count": len(cards),
            "fields": ["card_id", "software_id", "profile_id", "plan_snapshot_id", "quota_cost", "status", "issued_at"],
            "includes_plaintext": False,
        },
    )
    return batch, cards


def reveal_license_card(*, actor, card_public_id, request_id: str | None = None, ip_address: str | None = None) -> tuple[LicenseCard, str]:
    admin = is_platform_admin(actor)
    profile = None if admin else _active_profile(actor)
    lookup = LicenseCard.objects.select_related("batch", "software", "profile", "plan_snapshot")
    if profile is not None:
        lookup = lookup.filter(current_downstream_public_id=profile.public_id)
    try:
        card = lookup.get(public_id=card_public_id)
        if card.status == LicenseCardStatus.DELETED_TOMBSTONE:
            raise LicenseCard.DoesNotExist
        if not admin and card.status == LicenseCardStatus.ARCHIVED:
            raise LicenseCard.DoesNotExist
        plaintext = decrypt_license_card(card.card_ciphertext, key_version=card.encryption_key_version)
    except (LicenseCard.DoesNotExist, ValueError, TypeError) as exc:
        error = LicenseOperationError("LICENSE_CARD_NOT_FOUND", "授权卡密不存在。")
        record_event(
            actor=actor,
            action="license_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=error.code,
        )
        raise error from exc
    except LicenseOperationError as exc:
        record_event(
            actor=actor,
            action="license_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="LicenseCard",
            object_public_id=card_public_id,
            reason_code=exc.code,
        )
        raise
    # Product freeze ADR-0010: successful display/copy/download of a complete
    # code is intentionally not a "who viewed it" audit event. Generation,
    # reclaim and activation remain audited separately.
    return card, plaintext


def reclaim_license_card(
    *,
    actor,
    card_public_id,
    idempotency_key: str | None,
    reason: str = "回收未激活授权卡密",
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> LicenseReclaimResult:
    """Reclaim one unused card and refund its original downstream cost once."""

    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 255:
        raise LicenseOperationError("INVALID_REASON", "回收原因必须是 1 至 255 个字符。")
    reclaim_reason = reason.strip()
    admin = is_platform_admin(actor)
    profile = None if admin else _active_profile(actor)
    lookup = LicenseCard.objects.select_related("batch", "software", "profile", "plan_snapshot")
    if profile is not None:
        lookup = lookup.filter(current_downstream_public_id=profile.public_id)
    try:
        card_reference = lookup.get(public_id=card_public_id)
    except (LicenseCard.DoesNotExist, ValueError, TypeError) as exc:
        error = LicenseOperationError("LICENSE_CARD_NOT_FOUND", "授权卡密不存在或不属于当前操作范围。")
        record_event(
            actor=actor,
            action="license_card.reclaim",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=error.code,
        )
        raise error from exc

    request_key = _idempotency_key(idempotency_key)
    current_time = now or timezone.now()
    reclaim_key = f"license-card-reclaim:{card_reference.public_id}"
    try:
        with transaction.atomic():
            locked_lookup = LicenseCard.objects.select_for_update().select_related(
                "batch", "software", "profile", "plan_snapshot"
            )
            if profile is not None:
                locked_lookup = locked_lookup.filter(current_downstream_public_id=profile.public_id)
            card = locked_lookup.get(public_id=card_reference.public_id)

            existing_entry = QuotaLedgerEntry.objects.filter(
                downstream_public_id=card.original_downstream_public_id,
                idempotency_key=reclaim_key,
                operation_type=QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
            ).first()
            if card.status == LicenseCardStatus.RECLAIMED:
                if card.quota_cost and existing_entry is None:
                    raise LicenseOperationError("RECLAIM_INCONSISTENT", "授权卡密回收记录不完整，已阻止重复操作。")
                record_event(
                    actor=actor,
                    action="license_card.reclaim",
                    outcome=AuditOutcome.SUCCESS,
                    request_id=request_id,
                    ip_address=ip_address,
                    object_type="LicenseCard",
                    object_public_id=card.public_id,
                    metadata={
                        "repeated": True,
                        "to_status": LicenseCardStatus.RECLAIMED,
                        "quota_cost": card.quota_cost,
                        "quota_ledger_entry_id": str(existing_entry.public_id) if existing_entry else "",
                        "balance_before": existing_entry.balance_before if existing_entry else None,
                        "balance_after": existing_entry.balance_after if existing_entry else None,
                    },
                )
                return LicenseReclaimResult(card=card, entry=existing_entry, repeated=True)
            if card.status != LicenseCardStatus.UNUSED:
                raise LicenseOperationError("CARD_NOT_RECLAIMABLE", "只有未激活授权卡密可以回收。")

            entry = None
            try:
                entry = _refund_license_card_quota(
                    actor=actor,
                    license_card_public_id=card.public_id,
                    idempotency_key=reclaim_key,
                    reason=reclaim_reason,
                    now=current_time,
                )
            except QuotaOperationError as exc:
                raise LicenseOperationError(exc.code, exc.message) from exc

            card.status = LicenseCardStatus.RECLAIMED
            card.reclaimed_at = current_time
            card.status_reason = reclaim_reason
            record_event(
                actor=actor,
                action="license_card.reclaim",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseCard",
                object_public_id=card.public_id,
                metadata={
                    "from_status": LicenseCardStatus.UNUSED,
                    "to_status": LicenseCardStatus.RECLAIMED,
                    "original_downstream_public_id": str(card.original_downstream_public_id),
                    "quota_cost": card.quota_cost,
                    "quota_ledger_entry_id": str(entry.public_id) if entry else "",
                    "balance_before": entry.balance_before if entry else None,
                    "balance_after": entry.balance_after if entry else None,
                    "reason": card.status_reason,
                    "request_key_digest": hashlib.sha256(request_key.encode("utf-8")).hexdigest(),
                },
            )
            return LicenseReclaimResult(card=card, entry=entry)
    except LicenseOperationError as exc:
        record_event(
            actor=actor,
            action="license_card.reclaim",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=exc.code,
            object_type="LicenseCard",
            object_public_id=card_reference.public_id,
            metadata={"status": card_reference.status},
        )
        raise


def _card_terminal_at(card, *, now=None) -> datetime | None:
    """Return when the card entered its terminal state, or None."""
    current_time = now or timezone.now()
    if card.status == LicenseCardStatus.ACTIVATED and card.expires_at is not None and current_time >= card.expires_at:
        return card.expires_at
    if card.status == LicenseCardStatus.EXPIRED:
        return card.expires_at
    if card.status == LicenseCardStatus.REVOKED:
        return card.revoked_at
    if card.status == LicenseCardStatus.RECLAIMED:
        return card.reclaimed_at
    if card.status == LicenseCardStatus.DISABLED:
        return card.archived_at or card.revoked_at
    return None


def _lifecycle_request_hash(*, card_ids: list[uuid.UUID], reason: str) -> str:
    joined = ",".join(str(public_id) for public_id in sorted(set(card_ids)))
    return hashlib.sha256(f"{joined}\n{reason}".encode("utf-8")).hexdigest()


def _normalize_card_ids(values) -> list[uuid.UUID]:
    if not isinstance(values, (list, tuple)) or not values:
        raise LicenseOperationError("INVALID_REQUEST", "请至少选择一张授权卡密。")
    normalized: list[uuid.UUID] = []
    for raw in values:
        try:
            normalized.append(uuid.UUID(str(raw)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise LicenseOperationError("INVALID_REQUEST", "授权卡密标识格式不正确。") from exc
    if len(normalized) != len(set(normalized)):
        raise LicenseOperationError("INVALID_REQUEST", "授权卡密标识重复，请检查选择。")
    return sorted(normalized)


def _require_platform_admin(actor) -> None:
    if not is_platform_admin(actor):
        raise LicenseOperationError("FORBIDDEN", "只有平台管理员可以执行授权卡密归档或删除。")


def _claim_license_card_lifecycle_operation(*, actor, action: str, idempotency_key: str, request_hash: str):
    existing = LicenseCardLifecycleOperation.objects.select_for_update().filter(
        actor=actor,
        idempotency_key=idempotency_key,
    ).first()
    if existing is not None:
        if existing.action != action or existing.request_hash != request_hash:
            raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的生命周期内容。")
        if not existing.response_payload:
            raise LicenseOperationError("LIFECYCLE_RETRYABLE", "生命周期操作正在处理中，请稍后重试。")
        return None, {**existing.response_payload, "repeated": True}
    try:
        with transaction.atomic():
            operation = LicenseCardLifecycleOperation.objects.create(
                actor=actor,
                action=action,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_payload={},
            )
    except IntegrityError:
        existing = LicenseCardLifecycleOperation.objects.select_for_update().get(
            actor=actor,
            idempotency_key=idempotency_key,
        )
        if existing.action != action or existing.request_hash != request_hash:
            raise LicenseOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的生命周期内容。")
        if not existing.response_payload:
            raise LicenseOperationError("LIFECYCLE_RETRYABLE", "生命周期操作正在处理中，请稍后重试。")
        return None, {**existing.response_payload, "repeated": True}
    return operation, None


def archive_license_cards(
    *,
    actor,
    card_ids,
    reason: str,
    idempotency_key: str | None,
    request_id: str | None = None,
    ip_address: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Archive terminal license cards immediately.

    Archiving stops the card from being activated, verified or reclaimed, but
    keeps the record and all history searchable. Audit and quota ledger are
    never touched. Only platform administrators may archive.
    """
    if not isinstance(reason, str) or len(reason.strip()) < 4 or len(reason.strip()) > 255:
        raise LicenseOperationError("INVALID_REASON", "归档原因必须是 4 至 255 个字符。")
    _require_platform_admin(actor)
    normalized = _normalize_card_ids(card_ids)
    archive_reason = reason.strip()
    current_time = now or timezone.now()
    request_key = _idempotency_key(idempotency_key)
    request_hash = _lifecycle_request_hash(card_ids=normalized, reason=archive_reason)

    with transaction.atomic():
        operation, replay = _claim_license_card_lifecycle_operation(
            actor=actor,
            action="archive",
            idempotency_key=request_key,
            request_hash=request_hash,
        )
        if replay is not None:
            return replay

        locked = LicenseCard.objects.select_for_update().select_related(
            "software", "profile", "plan_snapshot"
        ).filter(public_id__in=normalized)
        cards = list(locked)
        if len(cards) != len(normalized):
            raise LicenseOperationError(
                "LICENSE_CARD_NOT_FOUND",
                "部分授权卡密不存在或不在当前操作范围。",
            )
        for card in cards:
            _validate_archivable(card, now=current_time)
        archived: list[dict] = []
        for card in cards:
            from_status = card.status
            card.status = LicenseCardStatus.ARCHIVED
            card.archived_at = current_time
            card.archived_from_status = from_status
            card.status_reason = archive_reason
            card.save(_allow_mutation=True)
            record_event(
                actor=actor,
                action="license_card.archive",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseCard",
                object_public_id=card.public_id,
                metadata={
                    "from_status": from_status,
                    "to_status": LicenseCardStatus.ARCHIVED,
                    "archived_at": current_time.isoformat(),
                    "software_id": card.software.software_id if card.software else "",
                    "profile_id": card.profile.profile_id if card.profile else "",
                    "quota_cost": card.quota_cost,
                    "reason": archive_reason,
                    "request_key_digest": hashlib.sha256(request_key.encode("utf-8")).hexdigest(),
                },
            )
            archived.append(
                {
                    "public_id": str(card.public_id),
                    "from_status": from_status,
                    "to_status": LicenseCardStatus.ARCHIVED,
                }
            )
        response_payload = {
            "archived_count": len(archived),
            "archived": archived,
            "reason": archive_reason,
        }
        operation.response_payload = response_payload
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return response_payload


def _validate_archivable(card, *, now: datetime) -> None:
    terminal_at = _card_terminal_at(card, now=now)
    if card.status == LicenseCardStatus.ACTIVATED and terminal_at is None:
        raise LicenseOperationError(
            "CARD_NOT_ARCHIVABLE",
            "有效授权需先到期或撤销后才能归档。",
        )
    if card.status == LicenseCardStatus.UNUSED:
        raise LicenseOperationError(
            "CARD_NOT_ARCHIVABLE",
            "未激活卡需先回收后才能归档。",
        )
    if card.status == LicenseCardStatus.DISABLED:
        raise LicenseOperationError(
            "CARD_NOT_ARCHIVABLE",
            "已禁用卡暂不支持归档。",
        )
    if card.status == LicenseCardStatus.ARCHIVED:
        raise LicenseOperationError(
            "CARD_ALREADY_ARCHIVED",
            "这张授权卡密已经归档，不能重复归档。",
        )
    if terminal_at is None:
        raise LicenseOperationError(
            "CARD_NOT_ARCHIVABLE",
            "这张授权卡密还没有进入可归档状态。",
        )
    return


def delete_license_cards(
    *,
    actor,
    card_ids,
    reason: str,
    idempotency_key: str | None,
    request_id: str | None = None,
    ip_address: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Tombstone already-archived cards, keeping history auditable.

    The card row is moved to `deleted_tombstone` so it disappears from stock
    while the authorization instance, device history, audit trail and quota
    ledger remain fully explainable. A minimal redacted tombstone is written
    before the status change. Only platform administrators may delete; audit
    and quota ledger are never touched.
    """
    if not isinstance(reason, str) or len(reason.strip()) < 4 or len(reason.strip()) > 255:
        raise LicenseOperationError("INVALID_REASON", "删除原因必须是 4 至 255 个字符。")
    _require_platform_admin(actor)
    normalized = _normalize_card_ids(card_ids)
    delete_reason = reason.strip()
    current_time = now or timezone.now()
    request_key = _idempotency_key(idempotency_key)
    request_hash = _lifecycle_request_hash(card_ids=normalized, reason=delete_reason)

    with transaction.atomic():
        operation, replay = _claim_license_card_lifecycle_operation(
            actor=actor,
            action="delete",
            idempotency_key=request_key,
            request_hash=request_hash,
        )
        if replay is not None:
            return replay

        locked = LicenseCard.objects.select_for_update().select_related(
            "software", "profile", "plan_snapshot"
        ).filter(public_id__in=normalized)
        cards = list(locked)
        if len(cards) != len(normalized):
            raise LicenseOperationError(
                "LICENSE_CARD_NOT_FOUND",
                "部分授权卡密不存在或不在当前操作范围。",
            )
        deleted: list[dict] = []
        for card in cards:
            if card.status != LicenseCardStatus.ARCHIVED:
                raise LicenseOperationError(
                    "CARD_NOT_DELETABLE",
                    "只有已归档的授权卡密才能删除。",
                )
            LicenseCardTombstone.objects.create(
                card_public_id=card.public_id,
                card_hash=card.card_hash,
                software_id=card.software.software_id if card.software else "",
                profile_id=card.profile.profile_id if card.profile else "",
                plan_snapshot_id=card.plan_snapshot_id,
                original_downstream_public_id=card.original_downstream_public_id,
                current_downstream_public_id=card.current_downstream_public_id,
                quota_cost=card.quota_cost,
                terminal_status=card.archived_from_status or card.status,
                archived_at=card.archived_at or current_time,
                deleted_at=current_time,
                actor_id=actor.pk,
                reason=delete_reason,
            )
            record_event(
                actor=actor,
                action="license_card.delete",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="LicenseCardTombstone",
                object_public_id=card.public_id,
                metadata={
                    "from_status": card.status,
                    "to_status": LicenseCardStatus.DELETED_TOMBSTONE,
                    "deleted_at": current_time.isoformat(),
                    "archived_at": (card.archived_at or current_time).isoformat(),
                    "software_id": card.software.software_id if card.software else "",
                    "profile_id": card.profile.profile_id if card.profile else "",
                    "quota_cost": card.quota_cost,
                    "retained_authorization_history": hasattr(card, "authorization_instance"),
                    "reason": delete_reason,
                    "request_key_digest": hashlib.sha256(request_key.encode("utf-8")).hexdigest(),
                },
            )
            deleted_public_id = str(card.public_id)
            card.status = LicenseCardStatus.DELETED_TOMBSTONE
            card.status_reason = delete_reason
            card.save(_allow_mutation=True)
            deleted.append({"public_id": deleted_public_id})
        response_payload = {
            "deleted_count": len(deleted),
            "deleted": deleted,
            "reason": delete_reason,
        }
        operation.response_payload = response_payload
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return response_payload


@dataclass(frozen=True)
class PlanCardInvalidationResult:
    unused_invalidated: int = 0
    activated_revoked: int = 0
    already_invalid: int = 0
    quota_refunded: int = 0


_PLAN_DELETE_TERMINAL_STATUSES = {
    LicenseCardStatus.RECLAIMED,
    LicenseCardStatus.REVOKED,
    LicenseCardStatus.EXPIRED,
    LicenseCardStatus.DISABLED,
    LicenseCardStatus.ARCHIVED,
    LicenseCardStatus.DELETED_TOMBSTONE,
}


def _revoke_card_for_plan_delete(
    *,
    actor,
    card: LicenseCard,
    reason: str,
    now: datetime,
    request_id: str | None,
    ip_address: str | None,
) -> int:
    from authorization_platform.licensing.admin import revoke_authorization

    instance = LicenseInstance.objects.filter(license_card_id=card.pk).first()
    if instance is not None:
        result = revoke_authorization(
            actor=actor,
            authorization_id=instance.authorization_id,
            reason=reason,
            now=now,
            request_id=request_id,
            ip_address=ip_address,
        )
        locked = LicenseCard.objects.select_for_update().get(pk=card.pk)
        if locked.status == LicenseCardStatus.ACTIVATED:
            locked.status = LicenseCardStatus.REVOKED
            locked.revoked_at = now
            locked.status_reason = reason
            locked.save(update_fields=("status", "revoked_at", "status_reason"), _allow_mutation=True)
            return 1
        return 0 if result.repeated else 1

    locked = LicenseCard.objects.select_for_update().get(pk=card.pk)
    if locked.status in _PLAN_DELETE_TERMINAL_STATUSES:
        return 0
    locked.status = LicenseCardStatus.REVOKED
    locked.revoked_at = now
    locked.status_reason = reason
    locked.save(update_fields=("status", "revoked_at", "status_reason"), _allow_mutation=True)
    record_event(
        actor=actor,
        action="license_card.revoke",
        outcome=AuditOutcome.SUCCESS,
        request_id=request_id,
        ip_address=ip_address,
        object_type="LicenseCard",
        object_public_id=locked.public_id,
        metadata={
            "from_status": LicenseCardStatus.ACTIVATED,
            "to_status": LicenseCardStatus.REVOKED,
            "reason": reason,
            "source": "plan.delete",
        },
    )
    return 1


def invalidate_cards_for_plan_delete(
    *,
    actor,
    plan_id: int,
    reason: str,
    request_id: str | None = None,
    ip_address: str | None = None,
    now: datetime | None = None,
) -> PlanCardInvalidationResult:
    """Make every remaining card of a plan unusable. Unused cards are reclaimed."""

    current_time = now or timezone.now()
    unused_invalidated = 0
    activated_revoked = 0
    already_invalid = 0
    quota_refunded = 0
    public_ids = list(
        LicenseCard.objects.filter(plan_snapshot__plan_id=plan_id).order_by("public_id").values_list("public_id", flat=True)
    )
    for public_id in public_ids:
        card = LicenseCard.objects.get(pk=public_id)
        if card.status == LicenseCardStatus.UNUSED:
            try:
                result = reclaim_license_card(
                    actor=actor,
                    card_public_id=public_id,
                    idempotency_key=f"plan-delete-reclaim:{public_id}",
                    reason=reason,
                    now=current_time,
                    request_id=request_id,
                    ip_address=ip_address,
                )
            except LicenseOperationError as exc:
                if exc.code != "CARD_NOT_RECLAIMABLE":
                    raise
                card.refresh_from_db()
                activated_revoked += _revoke_card_for_plan_delete(
                    actor=actor,
                    card=card,
                    reason=reason,
                    now=current_time,
                    request_id=request_id,
                    ip_address=ip_address,
                )
                continue
            unused_invalidated += 1
            if result.entry is not None and not result.repeated:
                quota_refunded += card.quota_cost
        elif card.status == LicenseCardStatus.ACTIVATED:
            activated_revoked += _revoke_card_for_plan_delete(
                actor=actor,
                card=card,
                reason=reason,
                now=current_time,
                request_id=request_id,
                ip_address=ip_address,
            )
        else:
            already_invalid += 1
    return PlanCardInvalidationResult(
        unused_invalidated=unused_invalidated,
        activated_revoked=activated_revoked,
        already_invalid=already_invalid,
        quota_refunded=quota_refunded,
    )
