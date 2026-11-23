from __future__ import annotations

import uuid

from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone


class QuotaCardStatus(models.TextChoices):
    ISSUED = "issued", "未兑换"
    REDEEMED = "redeemed", "已兑换"
    REVOKED = "revoked", "已作废"
    ARCHIVED = "archived", "已归档"
    DELETED_TOMBSTONE = "deleted_tombstone", "已删除"


class QuotaLedgerDirection(models.TextChoices):
    CREDIT = "credit", "增加"
    DEBIT = "debit", "扣除"


class QuotaLedgerOperation(models.TextChoices):
    MANUAL_CREDIT = "manual_credit", "人工充值"
    CARD_REDEEM = "card_redeem", "额度卡兑换"
    LICENSE_CARD_ISSUE = "license_card_issue", "生成授权卡密"
    LICENSE_CARD_RECLAIM = "license_card_reclaim", "回收授权卡密"
    ADMIN_ADJUSTMENT = "admin_adjustment", "管理员调整"


class ImmutableQuotaLedgerQuerySet(models.QuerySet):
    def bulk_create(self, objs, batch_size=None, ignore_conflicts=False, update_conflicts=False, update_fields=None, unique_fields=None):
        if update_conflicts:
            raise ValueError("额度流水不可修改；请通过新的业务动作产生反向流水。")
        return super().bulk_create(objs, batch_size=batch_size, ignore_conflicts=ignore_conflicts, update_conflicts=False, update_fields=update_fields, unique_fields=unique_fields)

    def update(self, **kwargs):
        raise ValueError("额度流水不可修改；请通过新的业务动作产生反向流水。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("额度流水不可修改；请通过新的业务动作产生反向流水。")

    def delete(self):
        raise ValueError("额度流水不可删除。")


class ImmutableQuotaPurchaseUrlOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("额度购买链接幂等记录不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("额度购买链接幂等记录不可修改。")

    def delete(self):
        raise ValueError("额度购买链接幂等记录不可删除。")


class ImmutableQuotaCardBatchQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("额度卡生成分组不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("额度卡生成分组不可修改。")

    def delete(self):
        raise ValueError("额度卡生成分组不可删除。")


class QuotaCardBatch(models.Model):
    objects = ImmutableQuotaCardBatchQuerySet.as_manager()
    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    amount = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    quantity = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    target_downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_quota_card_batches",
    )
    target_downstream_public_id = models.UUIDField(null=True, blank=True, db_index=True)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="issued_quota_card_batches",
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("created_by", "idempotency_key"),
                name="credits_batch_creator_idempotency_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"额度卡批次 {self.public_id} ({self.quantity} × {self.amount})"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("额度卡生成分组不可修改；请通过新的业务动作产生状态变化。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("额度卡生成分组不可删除。")


class QuotaPlatformSettings(models.Model):
    """Singleton settings used by the platform-wide quota purchase entrypoint."""

    key = models.CharField(max_length=32, primary_key=True, default="default", editable=False)
    purchase_url = models.URLField(max_length=2048, blank=True)
    last_idempotency_key = models.CharField(max_length=128, blank=True)
    last_request_hash = models.CharField(max_length=64, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"额度平台设置 {self.key}"


class QuotaPurchaseUrlOperation(models.Model):
    """Immutable idempotency record for one administrator URL update."""

    objects = ImmutableQuotaPurchaseUrlOperationQuerySet.as_manager()

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="quota_purchase_url_operations",
    )
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    purchase_url = models.URLField(max_length=2048, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="credits_purchase_url_actor_idempotency_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"额度购买链接操作 {self.actor_id} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("额度购买链接幂等记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("额度购买链接幂等记录不可删除。")


class ImmutableQuotaCardQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("额度卡生命周期不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("额度卡生命周期不可直接修改。")

    def delete(self):
        raise ValueError("额度卡不可删除；请通过明确的业务动作改变状态。")


class QuotaCard(models.Model):
    objects = ImmutableQuotaCardQuerySet.as_manager()
    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    batch = models.ForeignKey(QuotaCardBatch, on_delete=models.PROTECT, related_name="cards")
    amount = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    card_hash = models.CharField(max_length=64, unique=True)
    card_ciphertext = models.TextField()
    encryption_key_version = models.CharField(max_length=32, default="v2")
    target_downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="targeted_quota_cards",
    )
    target_downstream_public_id = models.UUIDField(null=True, blank=True, db_index=True)
    status = models.CharField(max_length=24, choices=QuotaCardStatus.choices, default=QuotaCardStatus.ISSUED, db_index=True)
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_quota_cards",
    )
    issued_at = models.DateTimeField(default=timezone.now)
    redeemed_by = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="redeemed_quota_cards",
    )
    redeemed_by_public_id = models.UUIDField(null=True, blank=True, db_index=True)
    redeemed_at = models.DateTimeField(null=True, blank=True)
    redeemed_ip_digest = models.CharField(max_length=64, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=255, blank=True)
    revoke_idempotency_key = models.CharField(max_length=128, null=True, blank=True, unique=True)
    revoke_request_hash = models.CharField(max_length=64, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    status_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-issued_at",)
        indexes = [models.Index(fields=("status", "issued_at"))]
        constraints = [
            models.CheckConstraint(condition=models.Q(amount__gt=0), name="credits_card_amount_positive"),
        ]

    def __str__(self) -> str:
        return f"额度卡 {self.public_id} / {self.status}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("额度卡生命周期只能通过业务服务改变。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("额度卡不可物理删除；请先走归档或作废服务。")


class QuotaAccount(models.Model):
    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    downstream = models.OneToOneField(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="quota_account",
    )
    downstream_public_id = models.UUIDField(unique=True, db_index=True)
    available_balance = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("downstream_public_id",)
        constraints = [
            models.CheckConstraint(condition=models.Q(available_balance__gte=0), name="credits_account_balance_nonnegative"),
        ]

    def __str__(self) -> str:
        owner = self.downstream.user.username if self.downstream_id and self.downstream else self.downstream_public_id
        return f"额度账户 {owner} / {self.available_balance}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("额度余额只能通过不可变流水服务改变。")
        return super().save(*args, **kwargs)


class QuotaLedgerEntry(models.Model):
    objects = ImmutableQuotaLedgerQuerySet.as_manager()

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(QuotaAccount, on_delete=models.PROTECT, related_name="entries")
    downstream_public_id = models.UUIDField(db_index=True)
    direction = models.CharField(max_length=8, choices=QuotaLedgerDirection.choices)
    amount = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    operation_type = models.CharField(max_length=32, choices=QuotaLedgerOperation.choices)
    source_type = models.CharField(max_length=64)
    source_public_id = models.CharField(max_length=128, blank=True)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="quota_ledger_entries",
    )
    reason = models.CharField(max_length=255, blank=True)
    balance_before = models.PositiveIntegerField()
    balance_after = models.PositiveIntegerField()
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-occurred_at", "-public_id")
        constraints = [
            models.UniqueConstraint(fields=("account", "idempotency_key"), name="credits_entry_account_idempotency_unique"),
            models.CheckConstraint(condition=models.Q(amount__gt=0), name="credits_entry_amount_positive"),
            models.CheckConstraint(condition=models.Q(balance_before__gte=0), name="credits_entry_before_nonnegative"),
            models.CheckConstraint(condition=models.Q(balance_after__gte=0), name="credits_entry_after_nonnegative"),
        ]
        indexes = [
            models.Index(fields=("downstream_public_id", "occurred_at")),
            models.Index(fields=("operation_type", "occurred_at")),
        ]

    def __str__(self) -> str:
        sign = "+" if self.direction == QuotaLedgerDirection.CREDIT else "-"
        return f"{sign}{self.amount} / {self.operation_type} / {self.occurred_at.isoformat()}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("额度流水不可修改；请通过新的业务动作产生反向流水。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("额度流水不可删除。")


class QuotaCardTombstone(models.Model):
    """Minimal auditable tombstone kept after a quota card is deleted.

    The plaintext card code is never stored; the hash and redacted metadata
    keep redeemed quota ledger entries explainable.
    """

    tombstone_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    card_public_id = models.UUIDField(unique=True)
    card_hash = models.CharField(max_length=64)
    amount = models.PositiveIntegerField(default=0)
    target_downstream_public_id = models.UUIDField(null=True, blank=True)
    redeemed_by_public_id = models.UUIDField(null=True, blank=True)
    terminal_status = models.CharField(max_length=24)
    archived_at = models.DateTimeField()
    deleted_at = models.DateTimeField(default=timezone.now)
    actor_id = models.PositiveBigIntegerField()
    reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-deleted_at",)
        indexes = [models.Index(fields=("deleted_at",))]

    def __str__(self) -> str:
        return f"额度兑换码墓碑 {self.card_public_id} / {self.deleted_at}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("额度兑换码墓碑不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("额度兑换码墓碑不可删除。")


class ImmutableQuotaCardLifecycleOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("额度兑换码生命周期幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("额度兑换码生命周期幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("额度兑换码生命周期幂等记录不可删除。")


class QuotaCardLifecycleOperation(models.Model):
    """Durable idempotency record for one quota-card archive/delete request."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="quota_card_lifecycle_operations",
    )
    action = models.CharField(max_length=16)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableQuotaCardLifecycleOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="credits_quota_card_lifecycle_actor_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"额度兑换码生命周期 {self.actor_id} / {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("额度兑换码生命周期幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("额度兑换码生命周期幂等记录不可删除。")
