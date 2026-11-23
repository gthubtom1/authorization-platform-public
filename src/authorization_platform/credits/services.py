from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from django.apps import apps
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, transaction
from django.db.models import Case, F, IntegerField, Sum, Value, When
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus
from authorization_platform.accounts.services import get_downstream_profile, is_active_downstream, is_platform_admin, require_platform_admin
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .models import (
    QuotaAccount,
    QuotaCard,
    QuotaCardBatch,
    QuotaCardLifecycleOperation,
    QuotaCardStatus,
    QuotaCardTombstone,
    QuotaLedgerDirection,
    QuotaLedgerEntry,
    QuotaLedgerOperation,
    QuotaPlatformSettings,
    QuotaPurchaseUrlOperation,
)


QUOTA_CARD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
QUOTA_CARD_PREFIX = "QC-"


class QuotaOperationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class IssuedQuotaCard:
    public_id: object
    amount: int
    code: str


@dataclass(frozen=True)
class QuotaRedemptionResult:
    card: QuotaCard
    entry: QuotaLedgerEntry
    repeated: bool = False


@dataclass(frozen=True)
class QuotaPurchaseUrlResult:
    purchase_url: str


@dataclass(frozen=True)
class QuotaCardKeyMigrationResult:
    from_version: str
    to_version: str
    scanned: int
    migrated: int
    dry_run: bool


def quota_ip_digest(value: str | None) -> str:
    if not value:
        return ""
    key = getattr(settings, "QUOTA_REDEEM_IP_HASH_KEY", settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_quota_purchase_url(value: str) -> str:
    if not isinstance(value, str):
        raise QuotaOperationError("INVALID_PURCHASE_URL", "购买链接格式不正确。")
    value = value.strip()
    if len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise QuotaOperationError("INVALID_PURCHASE_URL", "购买链接格式不正确。")
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise QuotaOperationError("INVALID_PURCHASE_URL", "购买链接只能使用不带账号密码的 HTTP 或 HTTPS 地址。")
    return value


def get_quota_platform_settings() -> QuotaPlatformSettings:
    settings_row, _ = QuotaPlatformSettings.objects.get_or_create(key="default")
    return settings_row


def update_quota_purchase_url(
    *,
    actor,
    purchase_url: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaPurchaseUrlResult:
    require_platform_admin(actor)
    purchase_url = normalize_quota_purchase_url(purchase_url)
    idempotency_key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(f"quota_purchase_url:{purchase_url}".encode("utf-8")).hexdigest()
    with transaction.atomic():
        settings_row, _ = QuotaPlatformSettings.objects.get_or_create(key="default")
        settings_row = QuotaPlatformSettings.objects.select_for_update().get(pk=settings_row.pk)
        operation = (
            QuotaPurchaseUrlOperation.objects.select_for_update()
            .filter(actor=actor, idempotency_key=idempotency_key)
            .first()
        )
        if operation:
            if operation.request_hash != request_hash:
                raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的购买链接。")
            return QuotaPurchaseUrlResult(purchase_url=operation.purchase_url)

        try:
            with transaction.atomic():
                operation = QuotaPurchaseUrlOperation.objects.create(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    purchase_url=purchase_url,
                )
        except IntegrityError:
            operation = (
                QuotaPurchaseUrlOperation.objects.select_for_update()
                .filter(actor=actor, idempotency_key=idempotency_key)
                .first()
            )
            if operation is None:
                raise
            if operation.request_hash != request_hash:
                raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的购买链接。")
            return QuotaPurchaseUrlResult(purchase_url=operation.purchase_url)

        settings_row.purchase_url = purchase_url
        # Keep the legacy fields readable for older internal callers; the
        # operation table above is the durable idempotency source of truth.
        settings_row.last_idempotency_key = idempotency_key
        settings_row.last_request_hash = request_hash
        settings_row.save(update_fields=("purchase_url", "last_idempotency_key", "last_request_hash", "updated_at"))
        record_event(
            actor=actor,
            action="quota.settings.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="QuotaPlatformSettings",
            object_public_id=settings_row.key,
            metadata={"purchase_url_configured": bool(purchase_url)},
        )
    return QuotaPurchaseUrlResult(purchase_url=purchase_url)


def normalize_quota_card_code(value: str) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(value.split()).upper()


def quota_card_hash(value: str) -> str:
    key = getattr(settings, "QUOTA_CARD_HASH_KEY", settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, normalize_quota_card_code(value).encode("utf-8"), hashlib.sha256).hexdigest()


def _fernet_for_key(key) -> Fernet:
    try:
        return Fernet(key.encode("ascii") if isinstance(key, str) else key)
    except (TypeError, ValueError) as exc:
        raise QuotaOperationError("CREDENTIAL_UNAVAILABLE", "额度卡加密密钥未配置或格式无效。") from exc


def _quota_card_key_for_version(key_version: str) -> str:
    if key_version == settings.QUOTA_CARD_ENCRYPTION_KEY_VERSION:
        return settings.QUOTA_CARD_ENCRYPTION_KEY
    if key_version == settings.QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION:
        legacy_key = settings.QUOTA_CARD_LEGACY_ENCRYPTION_KEY
        if legacy_key:
            return legacy_key
        raise QuotaOperationError("CREDENTIAL_UNAVAILABLE", "额度卡历史加密密钥未配置。")
    raise QuotaOperationError("CREDENTIAL_UNAVAILABLE", "额度卡加密密钥版本未配置。")


def _fernet_for_quota_card_version(key_version: str | None = None) -> Fernet:
    version = key_version or settings.QUOTA_CARD_ENCRYPTION_KEY_VERSION
    return _fernet_for_key(_quota_card_key_for_version(version))


def _fernet() -> Fernet:
    return _fernet_for_quota_card_version(settings.QUOTA_CARD_ENCRYPTION_KEY_VERSION)


def encrypt_quota_card(code: str) -> str:
    return _fernet().encrypt(code.encode("utf-8")).decode("ascii")


def decrypt_quota_card(ciphertext: str, *, key_version: str | None = None) -> str:
    try:
        return _fernet_for_quota_card_version(key_version).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise QuotaOperationError("CREDENTIAL_UNAVAILABLE", "额度卡暂时无法再次交付，请联系管理员。") from exc


def decrypt_quota_card_with_version(ciphertext: str, *, key_version: str) -> str:
    return decrypt_quota_card(ciphertext, key_version=key_version)


def migrate_quota_card_encryption_keys(
    *,
    from_version: str | None = None,
    to_version: str | None = None,
    dry_run: bool = True,
    batch_size: int = 500,
) -> QuotaCardKeyMigrationResult:
    """Validate or rewrap legacy quota-card ciphertext in one safe pass.

    The plaintext is held only in memory.  Hashes, statuses, ownership and
    lifecycle fields do not change.  A failed decrypt or hash check aborts an
    applying transaction instead of partially rotating the table.
    """

    source_version = from_version or settings.QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION
    target_version = to_version or settings.QUOTA_CARD_ENCRYPTION_KEY_VERSION
    if source_version == target_version:
        raise QuotaOperationError("KEY_ROTATION_INVALID", "历史密钥版本和当前密钥版本必须不同。")
    if target_version != settings.QUOTA_CARD_ENCRYPTION_KEY_VERSION:
        raise QuotaOperationError("KEY_ROTATION_INVALID", "迁移目标必须是当前额度卡密钥版本。")
    if batch_size < 1:
        raise QuotaOperationError("KEY_ROTATION_INVALID", "迁移批大小必须是正整数。")
    # Resolve both keys before scanning so a missing target/legacy key fails
    # before any database row is touched.
    target_fernet = _fernet_for_quota_card_version(target_version)
    _fernet_for_quota_card_version(source_version)
    queryset = QuotaCard.objects.filter(encryption_key_version=source_version).order_by("issued_at", "public_id")
    scanned = 0
    migrated = 0

    if dry_run:
        iterator = queryset.iterator(chunk_size=batch_size)
        for card in iterator:
            plaintext = decrypt_quota_card_with_version(card.card_ciphertext, key_version=source_version)
            if quota_card_hash(plaintext) != card.card_hash:
                raise QuotaOperationError("CREDENTIAL_CORRUPT", "额度卡密文与查询哈希不匹配。")
            scanned += 1
        return QuotaCardKeyMigrationResult(source_version, target_version, scanned, 0, True)

    with transaction.atomic():
        iterator = queryset.select_for_update().iterator(chunk_size=batch_size)
        for card in iterator:
            plaintext = decrypt_quota_card_with_version(card.card_ciphertext, key_version=source_version)
            if quota_card_hash(plaintext) != card.card_hash:
                raise QuotaOperationError("CREDENTIAL_CORRUPT", "额度卡密文与查询哈希不匹配。")
            card.card_ciphertext = target_fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
            card.encryption_key_version = target_version
            card.save(update_fields=("card_ciphertext", "encryption_key_version"), _allow_mutation=True)
            scanned += 1
            migrated += 1
    return QuotaCardKeyMigrationResult(source_version, target_version, scanned, migrated, False)


def reveal_quota_card(*, actor, card_public_id, request_id: str | None = None, ip_address: str | None = None) -> tuple[QuotaCard, str]:
    """Return one quota card's plaintext through the administrator scope."""

    require_platform_admin(actor)
    try:
        card = QuotaCard.objects.select_related("batch", "issued_by", "redeemed_by__user").get(
            public_id=card_public_id
        )
        if card.status == QuotaCardStatus.DELETED_TOMBSTONE:
            raise QuotaCard.DoesNotExist
    except (QuotaCard.DoesNotExist, ValueError, TypeError) as exc:
        error = QuotaOperationError("QUOTA_CARD_NOT_FOUND", "额度兑换码不存在。")
        record_event(
            actor=actor,
            action="quota_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=error.code,
        )
        raise error from exc

    try:
        plaintext = decrypt_quota_card(card.card_ciphertext, key_version=card.encryption_key_version)
    except QuotaOperationError as exc:
        record_event(
            actor=actor,
            action="quota_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            object_type="QuotaCard",
            object_public_id=card.public_id,
            reason_code=exc.code,
            metadata={"status": card.status},
        )
        raise
    return card, plaintext


def _new_quota_card_code() -> str:
    return QUOTA_CARD_PREFIX + "".join(secrets.choice(QUOTA_CARD_ALPHABET) for _ in range(24))


def _positive_int(value, *, label: str, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise QuotaOperationError("INVALID_AMOUNT", f"{label}必须是正整数。")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise QuotaOperationError("INVALID_AMOUNT", f"{label}必须是正整数。") from exc
    if number < 1 or (maximum is not None and number > maximum):
        suffix = f"，不能超过 {maximum}" if maximum is not None else ""
        raise QuotaOperationError("INVALID_AMOUNT", f"{label}必须是正整数{suffix}。")
    return number


def _idempotency_key(value: str | None) -> str:
    if not isinstance(value, str):
        raise QuotaOperationError("IDEMPOTENCY_REQUIRED", "缺少幂等键，请刷新页面后重试。")
    normalized = value.strip()
    if not normalized or len(normalized) > 128:
        raise QuotaOperationError("IDEMPOTENCY_REQUIRED", "幂等键格式不正确，请刷新页面后重试。")
    return normalized


def _reason(value: str) -> str:
    if not isinstance(value, str):
        raise QuotaOperationError("INVALID_REASON", "请填写操作原因。")
    normalized = value.strip()
    if len(normalized) < 2 or len(normalized) > 255:
        raise QuotaOperationError("INVALID_REASON", "请填写 2 到 255 个字的操作原因。")
    return normalized


def _active_profile(profile: DownstreamProfile | None) -> DownstreamProfile:
    if not profile or profile.status != DownstreamStatus.ACTIVE or not profile.user.is_active:
        raise QuotaOperationError("DOWNSTREAM_NOT_ACTIVE", "当前下游账号不可进行额度操作。")
    return profile


def _locked_active_profile(profile: DownstreamProfile) -> DownstreamProfile:
    locked_profile = (
        DownstreamProfile.objects.select_for_update()
        .select_related("user")
        .filter(public_id=profile.public_id)
        .first()
    )
    return _active_profile(locked_profile)


def _ensure_account(profile: DownstreamProfile, *, lock: bool = False) -> QuotaAccount:
    try:
        account, _ = QuotaAccount.objects.get_or_create(
            downstream_public_id=profile.public_id,
            defaults={"downstream": profile},
        )
    except IntegrityError:
        account = QuotaAccount.objects.get(downstream_public_id=profile.public_id)
    if account.downstream_id != profile.public_id:
        account.downstream = profile
        account.save(update_fields=("downstream", "updated_at"), _allow_mutation=True)
    if lock:
        return QuotaAccount.objects.select_for_update().get(pk=account.pk)
    return account


def get_quota_account(profile: DownstreamProfile) -> QuotaAccount:
    return _ensure_account(_active_profile(profile))


def _rebuild_balance(account: QuotaAccount) -> int:
    totals = QuotaLedgerEntry.objects.filter(account=account).aggregate(
        credits=Sum(
            Case(
                When(direction=QuotaLedgerDirection.CREDIT, then=F("amount")),
                default=Value(0),
                output_field=IntegerField(),
            )
        ),
        debits=Sum(
            Case(
                When(direction=QuotaLedgerDirection.DEBIT, then=F("amount")),
                default=Value(0),
                output_field=IntegerField(),
            )
        ),
    )
    return int((totals["credits"] or 0) - (totals["debits"] or 0))


def rebuild_quota_balance(account: QuotaAccount) -> int:
    """Return the ledger-derived balance without changing the cached account field."""

    return _rebuild_balance(account)


def _locked_account(profile: DownstreamProfile) -> QuotaAccount:
    account = _ensure_account(profile, lock=True)
    rebuilt = _rebuild_balance(account)
    if rebuilt != account.available_balance:
        raise QuotaOperationError("BALANCE_INCONSISTENT", "额度账本与余额汇总不一致，已阻止本次操作。")
    return account


def _locked_account_by_public_id(downstream_public_id) -> QuotaAccount:
    account = (
        QuotaAccount.objects.select_for_update()
        .filter(downstream_public_id=downstream_public_id)
        .first()
    )
    if account is None:
        raise QuotaOperationError("QUOTA_ACCOUNT_NOT_FOUND", "额度账户不存在，已阻止本次操作。")
    rebuilt = _rebuild_balance(account)
    if rebuilt != account.available_balance:
        raise QuotaOperationError("BALANCE_INCONSISTENT", "额度账本与余额汇总不一致，已阻止本次操作。")
    return account


def _append_entry(
    *,
    account: QuotaAccount,
    direction: str,
    amount: int,
    operation_type: str,
    source_type: str,
    source_public_id: str,
    idempotency_key: str,
    request_hash: str,
    actor,
    reason: str,
    occurred_at: datetime,
) -> QuotaLedgerEntry:
    before = account.available_balance
    after = before + amount if direction == QuotaLedgerDirection.CREDIT else before - amount
    if after < 0:
        raise QuotaOperationError("INSUFFICIENT_QUOTA", f"额度不足 {amount}，当前可用额度为 {before}。")
    entry = QuotaLedgerEntry.objects.create(
        account=account,
        downstream_public_id=account.downstream_public_id,
        direction=direction,
        amount=amount,
        operation_type=operation_type,
        source_type=source_type,
        source_public_id=source_public_id,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        actor=actor,
        reason=reason,
        balance_before=before,
        balance_after=after,
        occurred_at=occurred_at,
    )
    account.available_balance = after
    account.save(update_fields=("available_balance", "updated_at"), _allow_mutation=True)
    from authorization_platform.backup_control.services import schedule_change_backup

    schedule_change_backup(actor=actor)
    return entry


def _existing_entry(account: QuotaAccount, *, key: str, request_hash: str) -> QuotaLedgerEntry | None:
    entry = QuotaLedgerEntry.objects.filter(account=account, idempotency_key=key).first()
    if entry and entry.request_hash != request_hash:
        raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的操作内容。")
    return entry


def issue_quota_card_batch(
    *,
    actor,
    amount: int,
    quantity: int,
    target_downstream: DownstreamProfile | None = None,
    idempotency_key: str | None = None,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> tuple[QuotaCardBatch, list[IssuedQuotaCard]]:
    require_platform_admin(actor)
    amount = _positive_int(amount, label="面额", maximum=settings.QUOTA_CARD_MAX_AMOUNT)
    quantity = _positive_int(quantity, label="生成数量", maximum=settings.QUOTA_CARD_MAX_BATCH_SIZE)
    if target_downstream is not None:
        raise QuotaOperationError("TARGET_DOWNSTREAM_FORBIDDEN", "额度兑换码发行时不能绑定下游。")
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(f"issue:{amount}:{quantity}".encode("utf-8")).hexdigest()
    created_at = now or timezone.now()

    with transaction.atomic():
        existing_batch = QuotaCardBatch.objects.filter(created_by=actor, idempotency_key=key).first()
        if existing_batch:
            if existing_batch.request_hash != request_hash:
                raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发行内容。")
            return existing_batch, issued_cards_for_batch(actor=actor, batch_public_id=existing_batch.public_id)
        try:
            with transaction.atomic():
                batch = QuotaCardBatch.objects.create(
                    amount=amount,
                    quantity=quantity,
                    idempotency_key=key,
                    request_hash=request_hash,
                    created_by=actor,
                    created_at=created_at,
                )
        except IntegrityError:
            existing_batch = QuotaCardBatch.objects.filter(created_by=actor, idempotency_key=key).first()
            if existing_batch is None:
                raise
            if existing_batch.request_hash != request_hash:
                raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的发行内容。")
            return existing_batch, issued_cards_for_batch(actor=actor, batch_public_id=existing_batch.public_id)
        issued: list[IssuedQuotaCard] = []
        for _ in range(quantity):
            while True:
                code = _new_quota_card_code()
                card_hash = quota_card_hash(code)
                if not QuotaCard.objects.filter(card_hash=card_hash).exists():
                    break
            card = QuotaCard.objects.create(
                batch=batch,
                amount=amount,
                card_hash=card_hash,
                card_ciphertext=encrypt_quota_card(code),
                encryption_key_version=settings.QUOTA_CARD_ENCRYPTION_KEY_VERSION,
                issued_by=actor,
                issued_at=created_at,
            )
            issued.append(IssuedQuotaCard(public_id=card.public_id, amount=card.amount, code=code))
        # The replay path reconstructs cards from the database, so make the
        # first response use the same deterministic order as a replay.
        issued.sort(key=lambda item: str(item.public_id))
        record_event(
            actor=actor,
            action="quota_card.issue",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="QuotaCardBatch",
            object_public_id=batch.public_id,
            metadata={
                "amount": amount,
                "quantity": quantity,
            },
        )
    from authorization_platform.backup_control.services import schedule_change_backup

    schedule_change_backup(actor=actor)
    return batch, issued


def issued_cards_for_batch(*, actor, batch_public_id) -> list[IssuedQuotaCard]:
    require_platform_admin(actor)
    cards = QuotaCard.objects.filter(batch_id=batch_public_id).order_by("issued_at", "public_id")
    issued: list[IssuedQuotaCard] = []
    for card in cards:
        if card.status == QuotaCardStatus.DELETED_TOMBSTONE:
            continue
        issued.append(
            IssuedQuotaCard(
                public_id=card.public_id,
                amount=card.amount,
                code=decrypt_quota_card(card.card_ciphertext, key_version=card.encryption_key_version),
            )
        )
    if not issued:
        raise QuotaOperationError("QUOTA_CARD_NOT_FOUND", "额度兑换码不存在。")
    return issued


def redeem_quota_card(
    *,
    actor,
    card_code: str,
    idempotency_key: str | None = None,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaRedemptionResult:
    profile = get_downstream_profile(actor)
    if not profile:
        raise PermissionDenied
    if not is_active_downstream(actor):
        raise QuotaOperationError("DOWNSTREAM_NOT_ACTIVE", "当前下游账号不可进行额度操作。")
    normalized_code = normalize_quota_card_code(card_code)
    if not normalized_code or len(normalized_code) > 128:
        raise QuotaOperationError("QUOTA_CARD_UNAVAILABLE", "额度卡无效或已不可兑换。")
    card_hash = quota_card_hash(normalized_code)
    key = _idempotency_key(idempotency_key or f"card:{card_hash}")
    request_hash = hashlib.sha256(f"card_redeem:{card_hash}".encode("utf-8")).hexdigest()
    current_time = now or timezone.now()

    try:
        with transaction.atomic():
            profile = _locked_active_profile(profile)
            card = QuotaCard.objects.select_for_update().filter(card_hash=card_hash).first()
            if card is None:
                raise QuotaOperationError("QUOTA_CARD_UNAVAILABLE", "额度卡无效或已不可兑换。")
            account = _locked_account(profile)
            existing = _existing_entry(account, key=key, request_hash=request_hash)
            if existing:
                return QuotaRedemptionResult(card=card, entry=existing, repeated=True)
            if card.status != QuotaCardStatus.ISSUED:
                raise QuotaOperationError("QUOTA_CARD_UNAVAILABLE", "额度卡无效或已不可兑换。")
            entry = _append_entry(
                account=account,
                direction=QuotaLedgerDirection.CREDIT,
                amount=card.amount,
                operation_type=QuotaLedgerOperation.CARD_REDEEM,
                source_type="QuotaCard",
                source_public_id=str(card.public_id),
                idempotency_key=key,
                request_hash=request_hash,
                actor=actor,
                reason="兑换额度卡",
                occurred_at=current_time,
            )
            card.status = QuotaCardStatus.REDEEMED
            card.redeemed_by = profile
            card.redeemed_by_public_id = profile.public_id
            card.redeemed_at = current_time
            card.redeemed_ip_digest = quota_ip_digest(ip_address)
            card.save(
                update_fields=(
                    "status",
                    "redeemed_by",
                    "redeemed_by_public_id",
                    "redeemed_at",
                    "redeemed_ip_digest",
                ),
                _allow_mutation=True,
            )
            record_event(
                actor=actor,
                action="quota_card.redeem",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="QuotaCard",
                object_public_id=card.public_id,
                metadata={
                    "amount": card.amount,
                    "card_digest": card_hash,
                    "balance_before": entry.balance_before,
                    "balance_after": entry.balance_after,
                    "ledger_entry_id": str(entry.public_id),
                },
            )
            return QuotaRedemptionResult(card=card, entry=entry)
    except QuotaOperationError as exc:
        record_event(
            actor=actor,
            action="quota_card.redeem",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=exc.code,
            metadata={"card_digest": card_hash},
        )
        raise


def revoke_quota_card(
    *,
    actor,
    card_public_id,
    reason: str,
    idempotency_key: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaCard:
    require_platform_admin(actor)
    reason = _reason(reason)
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(f"revoke:{card_public_id}:{reason}".encode("utf-8")).hexdigest()
    current_time = now or timezone.now()

    with transaction.atomic():
        previous = QuotaCard.objects.select_for_update().filter(revoke_idempotency_key=key).first()
        if previous:
            if previous.revoke_request_hash != request_hash:
                raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的作废内容。")
            return previous
        card = QuotaCard.objects.select_for_update().filter(public_id=card_public_id).first()
        if card is None:
            raise QuotaOperationError("QUOTA_CARD_NOT_FOUND", "额度兑换码不存在。")
        if card.status != QuotaCardStatus.ISSUED:
            raise QuotaOperationError("QUOTA_CARD_UNAVAILABLE", "只有未兑换额度兑换码可以作废。")
        card.status = QuotaCardStatus.REVOKED
        card.revoked_at = current_time
        card.revoke_reason = reason
        card.revoke_idempotency_key = key
        card.revoke_request_hash = request_hash
        card.save(
            update_fields=(
                "status",
                "revoked_at",
                "revoke_reason",
                "revoke_idempotency_key",
                "revoke_request_hash",
            ),
            _allow_mutation=True,
        )
        record_event(
            actor=actor,
            action="quota_card.revoke",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="QuotaCard",
            object_public_id=card.public_id,
            metadata={"amount": card.amount, "card_digest": card.card_hash, "reason": reason},
        )
        return card


def credit_quota(
    *,
    actor,
    downstream: DownstreamProfile,
    amount: int,
    reason: str,
    idempotency_key: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaLedgerEntry:
    require_platform_admin(actor)
    amount = _positive_int(amount, label="充值额度", maximum=settings.QUOTA_CARD_MAX_AMOUNT)
    reason = _reason(reason)
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(f"manual_credit:{downstream.public_id}:{amount}:{reason}".encode("utf-8")).hexdigest()
    current_time = now or timezone.now()

    try:
        with transaction.atomic():
            downstream = _locked_active_profile(downstream)
            account = _locked_account(downstream)
            existing = _existing_entry(account, key=key, request_hash=request_hash)
            if existing:
                return existing
            entry = _append_entry(
                account=account,
                direction=QuotaLedgerDirection.CREDIT,
                amount=amount,
                operation_type=QuotaLedgerOperation.MANUAL_CREDIT,
                source_type="Admin",
                source_public_id=str(downstream.public_id),
                idempotency_key=key,
                request_hash=request_hash,
                actor=actor,
                reason=reason,
                occurred_at=current_time,
            )
            record_event(
                actor=actor,
                action="quota.manual_credit",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="QuotaAccount",
                object_public_id=account.public_id,
                metadata={"amount": amount, "downstream_public_id": str(downstream.public_id), "balance_after": entry.balance_after},
            )
            return entry
    except QuotaOperationError as exc:
        record_event(
            actor=actor,
            action="quota.manual_credit",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=exc.code,
            object_type="DownstreamProfile",
            object_public_id=downstream.public_id,
            metadata={"amount": amount},
        )
        raise


def _refund_license_card_quota(
    *,
    actor,
    license_card_public_id,
    idempotency_key: str,
    reason: str = "回收未激活授权卡密",
    now: datetime | None = None,
) -> QuotaLedgerEntry | None:
    """Atomically reclaim a real unused license card and refund its cost.

    This is intentionally a private cross-domain seam. It resolves the card
    from the database instead of accepting caller-supplied amount, owner, or
    source fields, and it completes the card transition itself so a direct
    internal misuse cannot mint a refund while leaving the card unused.
    """

    reason = _reason(reason)
    key = _idempotency_key(idempotency_key)
    current_time = now or timezone.now()
    LicenseCard = apps.get_model("licensing", "LicenseCard")

    with transaction.atomic():
        card = LicenseCard.objects.select_for_update().filter(public_id=license_card_public_id).first()
        if card is None:
            raise QuotaOperationError("LICENSE_CARD_NOT_FOUND", "授权卡密不存在或不属于当前操作范围。")
        if card.status != "unused":
            raise QuotaOperationError("CARD_NOT_RECLAIMABLE", "只有未激活授权卡密可以回收。")
        if card.current_downstream_public_id != card.original_downstream_public_id:
            raise QuotaOperationError("CARD_OWNERSHIP_MISMATCH", "当前版本不支持已转移归属的授权卡密回收。")

        downstream_public_id = card.original_downstream_public_id
        target_profile = (
            DownstreamProfile.objects.select_related("user")
            .select_for_update()
            .filter(public_id=downstream_public_id)
            .first()
        )
        if not is_platform_admin(actor):
            actor_profile = get_downstream_profile(actor)
            if (
                not target_profile
                or not actor_profile
                or actor_profile.public_id != target_profile.public_id
                or not is_active_downstream(actor)
            ):
                raise PermissionDenied

        try:
            amount = int(card.quota_cost)
        except (TypeError, ValueError) as exc:
            raise QuotaOperationError("INVALID_AMOUNT", "返还额度必须是非负整数。") from exc
        if amount < 0 or amount > settings.QUOTA_CARD_MAX_AMOUNT:
            raise QuotaOperationError("INVALID_AMOUNT", "返还额度超出允许范围。")
        source_public_id = str(card.public_id)
        request_hash = hashlib.sha256(
            f"license_card_reclaim:{downstream_public_id}:{amount}:{source_public_id}:{reason}".encode("utf-8")
        ).hexdigest()
        entry = None
        if amount:
            account = _locked_account_by_public_id(downstream_public_id)
            existing = _existing_entry(account, key=key, request_hash=request_hash)
            if existing:
                raise QuotaOperationError("RECLAIM_INCONSISTENT", "授权卡密回收记录已存在，但卡密仍未完成状态转换。")
            entry = _append_entry(
                account=account,
                direction=QuotaLedgerDirection.CREDIT,
                amount=amount,
                operation_type=QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
                source_type="LicenseCard",
                source_public_id=source_public_id,
                idempotency_key=key,
                request_hash=request_hash,
                actor=actor,
                reason=reason,
                occurred_at=current_time,
            )
        card.status = "reclaimed"
        card.reclaimed_at = current_time
        card.status_reason = reason
        card.save(update_fields=("status", "reclaimed_at", "status_reason"), _allow_mutation=True)
        return entry


def debit_quota(
    *,
    actor,
    downstream: DownstreamProfile,
    amount: int,
    reason: str,
    idempotency_key: str,
    source_type: str = "LicenseBatch",
    source_public_id: str = "",
    operation_type: str = QuotaLedgerOperation.LICENSE_CARD_ISSUE,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaLedgerEntry:
    profile = _active_profile(downstream)
    actor_profile = get_downstream_profile(actor)
    if not is_platform_admin(actor) and (not actor_profile or actor_profile.public_id != profile.public_id):
        raise PermissionDenied
    if operation_type not in {QuotaLedgerOperation.LICENSE_CARD_ISSUE, QuotaLedgerOperation.ADMIN_ADJUSTMENT}:
        raise QuotaOperationError("INVALID_OPERATION", "额度扣除动作不受支持。")
    if operation_type == QuotaLedgerOperation.ADMIN_ADJUSTMENT and not is_platform_admin(actor):
        raise PermissionDenied
    amount = _positive_int(amount, label="扣除额度", maximum=settings.QUOTA_CARD_MAX_AMOUNT)
    reason = _reason(reason)
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(
        f"debit:{profile.public_id}:{amount}:{reason}:{source_type}:{source_public_id}:{operation_type}".encode("utf-8")
    ).hexdigest()
    current_time = now or timezone.now()

    try:
        with transaction.atomic():
            profile = _locked_active_profile(profile)
            account = _locked_account(profile)
            existing = _existing_entry(account, key=key, request_hash=request_hash)
            if existing:
                return existing
            entry = _append_entry(
                account=account,
                direction=QuotaLedgerDirection.DEBIT,
                amount=amount,
                operation_type=operation_type,
                source_type=source_type,
                source_public_id=source_public_id,
                idempotency_key=key,
                request_hash=request_hash,
                actor=actor,
                reason=reason,
                occurred_at=current_time,
            )
            record_event(
                actor=actor,
                action="quota.admin_recovery" if operation_type == QuotaLedgerOperation.ADMIN_ADJUSTMENT else "quota.debit",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="QuotaAccount",
                object_public_id=account.public_id,
                metadata={
                    "amount": amount,
                    "operation_type": operation_type,
                    "source_type": source_type,
                    "source_public_id": source_public_id,
                    "balance_before": entry.balance_before,
                    "reason": reason,
                    "ledger_entry_id": str(entry.public_id),
                    "balance_after": entry.balance_after,
                },
            )
            return entry
    except QuotaOperationError as exc:
        record_event(
            actor=actor,
            action="quota.admin_recovery" if operation_type == QuotaLedgerOperation.ADMIN_ADJUSTMENT else "quota.debit",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=exc.code,
            object_type="DownstreamProfile",
            object_public_id=profile.public_id,
            metadata={
                "amount": amount,
                "operation_type": operation_type,
                "source_type": source_type,
                "source_public_id": source_public_id,
            },
        )
        raise


def recover_downstream_credits(
    *,
    actor,
    downstream: DownstreamProfile,
    amount: int,
    reason: str,
    idempotency_key: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaLedgerEntry:
    """Remove quota from a downstream account through a fixed admin action."""

    require_platform_admin(actor)
    return debit_quota(
        actor=actor,
        downstream=downstream,
        amount=amount,
        reason=reason,
        idempotency_key=idempotency_key,
        source_type="AdminQuotaRecovery",
        source_public_id=str(downstream.public_id),
        operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
        now=now,
        request_id=request_id,
        ip_address=ip_address,
    )


def recover_deleted_downstream_credits(
    *,
    actor,
    downstream_public_id,
    amount: int,
    reason: str,
    idempotency_key: str,
    now: datetime | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> QuotaLedgerEntry:
    """Debit leftover balance from a tombstone quota account; never use the live adjust window."""

    require_platform_admin(actor)
    amount = _positive_int(amount, label="扣回额度", maximum=settings.QUOTA_CARD_MAX_AMOUNT)
    reason = _reason(reason)
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(
        f"recover-deleted:{downstream_public_id}:{amount}:{reason}".encode("utf-8")
    ).hexdigest()
    current_time = now or timezone.now()
    try:
        with transaction.atomic():
            account = _locked_account_by_public_id(downstream_public_id)
            if account.downstream_id is not None:
                raise QuotaOperationError("DOWNSTREAM_STILL_PRESENT", "下游档案还在，请用「调整下游额度」扣回。")
            existing = _existing_entry(account, key=key, request_hash=request_hash)
            if existing:
                return existing
            entry = _append_entry(
                account=account,
                direction=QuotaLedgerDirection.DEBIT,
                amount=amount,
                operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
                source_type="DeletedDownstreamRecovery",
                source_public_id=str(downstream_public_id),
                idempotency_key=key,
                request_hash=request_hash,
                actor=actor,
                reason=reason,
                occurred_at=current_time,
            )
            record_event(
                actor=actor,
                action="quota.deleted_recovery",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="QuotaAccount",
                object_public_id=account.public_id,
                metadata={
                    "amount": amount,
                    "downstream_public_id": str(downstream_public_id),
                    "balance_after": entry.balance_after,
                    "ledger_entry_id": str(entry.public_id),
                },
            )
            return entry
    except QuotaOperationError as exc:
        record_event(
            actor=actor,
            action="quota.deleted_recovery",
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            ip_address=ip_address,
            reason_code=exc.code,
            object_type="QuotaAccount",
            metadata={"amount": amount, "downstream_public_id": str(downstream_public_id)},
        )
        raise


def list_quota_accounts(*, actor):
    require_platform_admin(actor)
    return QuotaAccount.objects.select_related("downstream__user").order_by("downstream_public_id")


def list_quota_entries(*, profile: DownstreamProfile, limit: int = 50):
    _active_profile(profile)
    account = get_quota_account(profile)
    return QuotaLedgerEntry.objects.filter(account=account).select_related("actor").order_by("-occurred_at", "-public_id")[:limit]


def _quota_card_terminal_at(card: QuotaCard):
    if card.status == QuotaCardStatus.REDEEMED:
        return card.redeemed_at
    if card.status == QuotaCardStatus.REVOKED:
        return card.revoked_at
    return None


def _quota_lifecycle_request_hash(*, card_ids: list, reason: str) -> str:
    joined = ",".join(sorted(str(public_id) for public_id in card_ids))
    return hashlib.sha256(f"{joined}\n{reason}".encode("utf-8")).hexdigest()


def _normalize_quota_card_ids(values) -> list:
    import uuid as uuid_module

    if not isinstance(values, (list, tuple)) or not values:
        raise QuotaOperationError("INVALID_REQUEST", "请至少选择一张额度兑换码。")
    normalized: list = []
    for raw in values:
        try:
            normalized.append(uuid_module.UUID(str(raw)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise QuotaOperationError("INVALID_REQUEST", "额度兑换码标识格式不正确。") from exc
    if len(normalized) != len(set(normalized)):
        raise QuotaOperationError("INVALID_REQUEST", "额度兑换码标识重复，请检查选择。")
    return sorted(normalized)


def _validate_quota_archivable(card: QuotaCard, *, now: datetime) -> None:
    if card.status == QuotaCardStatus.ISSUED:
        raise QuotaOperationError(
            "QUOTA_CARD_NOT_ARCHIVABLE",
            "未兑换额度兑换码需先作废后才能归档。",
        )
    if card.status == QuotaCardStatus.ARCHIVED:
        raise QuotaOperationError(
            "QUOTA_CARD_ALREADY_ARCHIVED",
            "这张额度兑换码已经归档，不能重复归档。",
        )
    terminal_at = _quota_card_terminal_at(card)
    if terminal_at is None:
        raise QuotaOperationError(
            "QUOTA_CARD_NOT_ARCHIVABLE",
            "这张额度兑换码还没有进入可归档状态。",
        )
    return


def _claim_quota_card_lifecycle_operation(*, actor, action: str, idempotency_key: str, request_hash: str):
    existing = QuotaCardLifecycleOperation.objects.select_for_update().filter(
        actor=actor,
        idempotency_key=idempotency_key,
    ).first()
    if existing is not None:
        if existing.action != action or existing.request_hash != request_hash:
            raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的生命周期内容。")
        if not existing.response_payload:
            raise QuotaOperationError("LIFECYCLE_RETRYABLE", "生命周期操作正在处理中，请稍后重试。")
        return None, {**existing.response_payload, "repeated": True}
    try:
        with transaction.atomic():
            operation = QuotaCardLifecycleOperation.objects.create(
                actor=actor,
                action=action,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_payload={},
            )
    except IntegrityError:
        existing = QuotaCardLifecycleOperation.objects.select_for_update().get(
            actor=actor,
            idempotency_key=idempotency_key,
        )
        if existing.action != action or existing.request_hash != request_hash:
            raise QuotaOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同的生命周期内容。")
        if not existing.response_payload:
            raise QuotaOperationError("LIFECYCLE_RETRYABLE", "生命周期操作正在处理中，请稍后重试。")
        return None, {**existing.response_payload, "repeated": True}
    return operation, None


def archive_quota_cards(
    *,
    actor,
    card_ids,
    reason: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
    now: datetime | None = None,
) -> dict:
    require_platform_admin(actor)
    if not isinstance(reason, str) or len(reason.strip()) < 4 or len(reason.strip()) > 255:
        raise QuotaOperationError("INVALID_REASON", "归档原因必须是 4 至 255 个字符。")
    normalized = _normalize_quota_card_ids(card_ids)
    archive_reason = reason.strip()
    current_time = now or timezone.now()
    request_key = _idempotency_key(idempotency_key)
    request_hash = _quota_lifecycle_request_hash(card_ids=normalized, reason=archive_reason)

    with transaction.atomic():
        operation, replay = _claim_quota_card_lifecycle_operation(
            actor=actor,
            action="archive",
            idempotency_key=request_key,
            request_hash=request_hash,
        )
        if replay is not None:
            return replay
        cards = list(
            QuotaCard.objects.select_for_update().filter(public_id__in=normalized)
        )
        if len(cards) != len(normalized):
            raise QuotaOperationError("QUOTA_CARD_NOT_FOUND", "部分额度兑换码不存在。")
        for card in cards:
            _validate_quota_archivable(card, now=current_time)
        archived: list[dict] = []
        for card in cards:
            from_status = card.status
            card.status = QuotaCardStatus.ARCHIVED
            card.archived_at = current_time
            card.status_reason = archive_reason
            card.save(update_fields=("status", "archived_at", "status_reason"), _allow_mutation=True)
            record_event(
                actor=actor,
                action="quota_card.archive",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="QuotaCard",
                object_public_id=card.public_id,
                metadata={
                    "from_status": from_status,
                    "to_status": QuotaCardStatus.ARCHIVED,
                    "amount": card.amount,
                    "card_digest": card.card_hash,
                    "reason": archive_reason,
                },
            )
            archived.append({"public_id": str(card.public_id)})
        response_payload = {"archived_count": len(archived), "archived": archived, "reason": archive_reason}
        operation.response_payload = response_payload
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return response_payload


def delete_quota_cards(
    *,
    actor,
    card_ids,
    reason: str,
    idempotency_key: str,
    request_id: str | None = None,
    ip_address: str | None = None,
    now: datetime | None = None,
) -> dict:
    require_platform_admin(actor)
    if not isinstance(reason, str) or len(reason.strip()) < 4 or len(reason.strip()) > 255:
        raise QuotaOperationError("INVALID_REASON", "删除原因必须是 4 至 255 个字符。")
    normalized = _normalize_quota_card_ids(card_ids)
    delete_reason = reason.strip()
    current_time = now or timezone.now()
    request_key = _idempotency_key(idempotency_key)
    request_hash = _quota_lifecycle_request_hash(card_ids=normalized, reason=delete_reason)

    with transaction.atomic():
        operation, replay = _claim_quota_card_lifecycle_operation(
            actor=actor,
            action="delete",
            idempotency_key=request_key,
            request_hash=request_hash,
        )
        if replay is not None:
            return replay
        cards = list(
            QuotaCard.objects.select_for_update().filter(public_id__in=normalized)
        )
        if len(cards) != len(normalized):
            raise QuotaOperationError("QUOTA_CARD_NOT_FOUND", "部分额度兑换码不存在。")
        deleted: list[dict] = []
        for card in cards:
            if card.status != QuotaCardStatus.ARCHIVED:
                raise QuotaOperationError(
                    "QUOTA_CARD_NOT_DELETABLE",
                    "只有已归档的额度兑换码才能删除。",
                )
            QuotaCardTombstone.objects.create(
                card_public_id=card.public_id,
                card_hash=card.card_hash,
                amount=card.amount,
                target_downstream_public_id=card.target_downstream_public_id,
                redeemed_by_public_id=card.redeemed_by_public_id,
                terminal_status=card.status,
                archived_at=card.archived_at or current_time,
                deleted_at=current_time,
                actor_id=actor.pk,
                reason=delete_reason,
            )
            record_event(
                actor=actor,
                action="quota_card.delete",
                outcome=AuditOutcome.SUCCESS,
                request_id=request_id,
                ip_address=ip_address,
                object_type="QuotaCardTombstone",
                object_public_id=card.public_id,
                metadata={
                    "from_status": card.status,
                    "to_status": QuotaCardStatus.DELETED_TOMBSTONE,
                    "amount": card.amount,
                    "reason": delete_reason,
                },
            )
            deleted_public_id = str(card.public_id)
            card.status = QuotaCardStatus.DELETED_TOMBSTONE
            card.status_reason = delete_reason
            card.save(update_fields=("status", "status_reason"), _allow_mutation=True)
            deleted.append({"public_id": deleted_public_id})
        response_payload = {"deleted_count": len(deleted), "deleted": deleted, "reason": delete_reason}
        operation.response_payload = response_payload
        operation.save(update_fields=("response_payload",), _allow_mutation=True)
        return response_payload
