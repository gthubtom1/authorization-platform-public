from __future__ import annotations

import uuid

from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone

from .device_codes import compact_device_code


class LicenseCardStatus(models.TextChoices):
    UNUSED = "unused", "未激活"
    ACTIVATED = "activated", "已激活"
    EXPIRED = "expired", "已过期"
    RECLAIMED = "reclaimed", "已回收"
    REVOKED = "revoked", "已撤销"
    DISABLED = "disabled", "已禁用"
    ARCHIVED = "archived", "已归档"
    DELETED_TOMBSTONE = "deleted_tombstone", "已删除"


class ImmutableLicenseCardQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权卡密生命周期不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权卡密生命周期不可直接修改。")

    def delete(self):
        raise ValueError("授权卡密不可删除。")


class ImmutableLicenseCardBatchQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权卡密批次不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权卡密批次不可修改。")

    def delete(self):
        raise ValueError("授权卡密批次不可删除。")


class LicenseCardBatch(models.Model):
    objects = ImmutableLicenseCardBatchQuerySet.as_manager()
    batch_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    software = models.ForeignKey("catalog.Software", on_delete=models.PROTECT, related_name="license_card_batches")
    profile = models.ForeignKey("catalog.SoftwareProfile", on_delete=models.PROTECT, related_name="license_card_batches")
    plan_snapshot = models.ForeignKey("catalog.PlanSnapshot", on_delete=models.PROTECT, related_name="license_card_batches")
    original_downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="original_license_card_batches",
    )
    current_downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="current_license_card_batches",
    )
    original_downstream_public_id = models.UUIDField(db_index=True)
    current_downstream_public_id = models.UUIDField(db_index=True)
    quantity = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    quota_cost_per_card = models.PositiveIntegerField(default=0)
    total_quota_cost = models.PositiveIntegerField(default=0)
    source = models.CharField(max_length=32, default="downstream")
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_license_card_batches",
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("current_downstream_public_id", "idempotency_key"),
                name="licensing_batch_owner_idempotency_unique",
            ),
            models.CheckConstraint(condition=models.Q(quantity__gt=0), name="licensing_batch_quantity_positive"),
            models.CheckConstraint(condition=models.Q(quota_cost_per_card__gte=0), name="licensing_batch_unit_cost_nonnegative"),
            models.CheckConstraint(condition=models.Q(total_quota_cost__gte=0), name="licensing_batch_total_cost_nonnegative"),
        ]

    def __str__(self) -> str:
        return f"授权卡密批次 {self.batch_id} ({self.quantity} 张)"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权卡密批次不可修改；请通过明确的业务动作改变卡密状态。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权卡密批次不可删除。")


class LicenseCard(models.Model):
    objects = ImmutableLicenseCardQuerySet.as_manager()

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    batch = models.ForeignKey(LicenseCardBatch, on_delete=models.PROTECT, related_name="cards")
    software = models.ForeignKey("catalog.Software", on_delete=models.PROTECT, related_name="license_cards")
    profile = models.ForeignKey("catalog.SoftwareProfile", on_delete=models.PROTECT, related_name="license_cards")
    plan_snapshot = models.ForeignKey("catalog.PlanSnapshot", on_delete=models.PROTECT, related_name="license_cards")
    original_downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="original_license_cards",
    )
    current_downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="current_license_cards",
    )
    original_downstream_public_id = models.UUIDField(db_index=True)
    current_downstream_public_id = models.UUIDField(db_index=True)
    quota_cost = models.PositiveIntegerField(default=0)
    card_hash = models.CharField(max_length=64, unique=True)
    card_ciphertext = models.TextField()
    encryption_key_version = models.CharField(max_length=32, default="v1")
    status = models.CharField(max_length=24, choices=LicenseCardStatus.choices, default=LicenseCardStatus.UNUSED, db_index=True)
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_license_cards",
    )
    issued_at = models.DateTimeField(default=timezone.now)
    activated_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    reclaimed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_from_status = models.CharField(max_length=24, blank=True)
    status_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-issued_at", "public_id")
        indexes = [
            models.Index(fields=("current_downstream_public_id", "issued_at")),
            models.Index(fields=("software", "status", "issued_at")),
        ]
        constraints = [
            models.CheckConstraint(condition=models.Q(quota_cost__gte=0), name="licensing_card_cost_nonnegative"),
        ]

    def __str__(self) -> str:
        return f"授权卡密 {self.public_id} / {self.status}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权卡密生命周期不可直接修改；请通过明确的业务动作改变状态。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if not kwargs.pop("_allow_lifecycle_delete", False):
            raise ValueError("授权卡密不可删除；请通过明确的业务动作改变状态。")
        return super().delete(*args, **kwargs)


class ImmutableLicenseReclaimOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权卡密回收幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权卡密回收幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("授权卡密回收幂等记录不可删除。")


class LicenseReclaimOperation(models.Model):
    """Durable idempotency record for one API-level reclaim request.

    The response only contains redacted card metadata and quota totals. It
    never stores or replays a plaintext license card code.
    """

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="license_reclaim_operations",
    )
    scope = models.CharField(max_length=32)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableLicenseReclaimOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="licensing_reclaim_actor_idempotency_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"授权卡回收操作 {self.actor_id} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权卡回收幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权卡回收幂等记录不可删除。")


class ImmutableAuthorizationAdminOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权管理员处置幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权管理员处置幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("授权管理员处置幂等记录不可删除。")


class AuthorizationAdminOperation(models.Model):
    """Immutable idempotency fact for one administrator risk action."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="authorization_admin_operations",
    )
    action = models.CharField(max_length=32)
    authorization_id = models.UUIDField(null=True, blank=True, db_index=True)
    device_id = models.UUIDField(null=True, blank=True, db_index=True)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableAuthorizationAdminOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="licensing_admin_action_actor_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"授权管理员处置 {self.actor_id} / {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权管理员处置幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权管理员处置幂等记录不可删除。")


class ImmutableAuthorizationDeviceOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权设备操作幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权设备操作幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("授权设备操作幂等记录不可删除。")


class AuthorizationDeviceOperation(models.Model):
    """Immutable idempotency fact for a downstream-owned device action."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="authorization_device_operations",
    )
    downstream_public_id = models.UUIDField(db_index=True)
    action = models.CharField(max_length=32)
    authorization_id = models.UUIDField(db_index=True)
    device_id = models.UUIDField(db_index=True)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableAuthorizationDeviceOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="licensing_device_operation_actor_key_unique",
            ),
        ]
        indexes = [
            models.Index(fields=("downstream_public_id", "created_at")),
            models.Index(fields=("authorization_id", "device_id")),
        ]

    def __str__(self) -> str:
        return f"授权设备操作 {self.actor_id} / {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权设备操作幂等记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权设备操作幂等记录不可删除。")


class AuthorizationState(models.TextChoices):
    ACTIVE = "active", "有效"
    GRACE = "grace", "宽限"
    EXPIRED = "expired", "已过期"
    REVOKED = "revoked", "已撤销"
    BLOCKED = "blocked", "已阻断"


class DeviceRiskState(models.TextChoices):
    NORMAL = "normal", "正常"
    BLOCKED = "blocked", "已阻断"


class DeviceBindingState(models.TextChoices):
    ACTIVE = "active", "有效"
    UNBOUND = "unbound", "已解绑"
    BLOCKED = "blocked", "已阻断"
    EXPIRED = "expired", "已过期"


class ImmutableAuthorizationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权运行时记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权运行时记录不可直接修改。")

    def delete(self):
        raise ValueError("授权运行时记录不可删除。")


class LicenseInstance(models.Model):
    """One server-side authorization fact created by the first valid activation."""

    objects = ImmutableAuthorizationQuerySet.as_manager()

    authorization_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    license_card = models.OneToOneField(
        LicenseCard,
        on_delete=models.PROTECT,
        related_name="authorization_instance",
    )
    software = models.ForeignKey("catalog.Software", on_delete=models.PROTECT, related_name="license_instances")
    profile = models.ForeignKey("catalog.SoftwareProfile", on_delete=models.PROTECT, related_name="license_instances")
    plan_snapshot = models.ForeignKey("catalog.PlanSnapshot", on_delete=models.PROTECT, related_name="license_instances")
    policy_version = models.ForeignKey("catalog.PolicyVersion", on_delete=models.PROTECT, related_name="license_instances")
    current_downstream_public_id = models.UUIDField(db_index=True)
    client_id = models.CharField(max_length=128)
    contract_version = models.CharField(max_length=64, default="authorization.v1")
    target = models.CharField(max_length=32)
    arch = models.CharField(max_length=32)
    channel = models.CharField(max_length=32)
    client_version = models.CharField(max_length=64)
    state = models.CharField(max_length=16, choices=AuthorizationState.choices, default=AuthorizationState.ACTIVE, db_index=True)
    authorization_revision = models.PositiveBigIntegerField(default=1)
    config_version = models.CharField(max_length=64, default="cfg-1")
    configuration_override = models.JSONField(default=dict, blank=True)
    issued_at = models.DateTimeField(default=timezone.now)
    activated_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    last_verified_at = models.DateTimeField(null=True, blank=True)
    last_server_time = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    state_reason = models.CharField(max_length=255, blank=True)
    device_switch_count = models.PositiveIntegerField(default=0)
    device_switch_day = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "authorization_id")
        constraints = [
            models.CheckConstraint(condition=models.Q(authorization_revision__gt=0), name="licensing_authorization_revision_positive"),
            models.CheckConstraint(condition=models.Q(expires_at__gt=models.F("activated_at")), name="licensing_authorization_expiry_after_activation"),
        ]
        indexes = [
            models.Index(fields=("software", "profile", "state")),
            models.Index(fields=("current_downstream_public_id", "state")),
        ]

    def __str__(self) -> str:
        return f"授权实例 {self.authorization_id} / {self.state}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权实例不可直接修改；请通过授权服务改变状态。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权实例不可删除；历史授权事实必须保留。")


class Device(models.Model):
    objects = ImmutableAuthorizationQuerySet.as_manager()

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    software = models.ForeignKey("catalog.Software", on_delete=models.PROTECT, related_name="devices")
    profile = models.ForeignKey("catalog.SoftwareProfile", on_delete=models.PROTECT, related_name="devices")
    installation_hash = models.CharField(max_length=64)
    # Preserve the client-facing identifier for support lookup.  The hash above
    # remains the authorization identity and must not be replaced by this value.
    installation_id = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    # Denormalized support-facing alias.  The authorization identity remains
    # installation_hash and the protocol still carries installation_id.
    device_code = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    risk_state = models.CharField(max_length=16, choices=DeviceRiskState.choices, default=DeviceRiskState.NORMAL, db_index=True)

    class Meta:
        ordering = ("-last_seen_at", "public_id")
        constraints = [
            models.UniqueConstraint(fields=("software", "profile", "installation_hash"), name="licensing_device_scope_unique"),
        ]

    def __str__(self) -> str:
        return f"设备 {self.public_id} / {self.software_id}/{self.profile_id}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("设备记录不可直接修改；请通过授权服务改变状态。")
        if self.installation_id:
            expected_code = compact_device_code(self.installation_id)
            if self.device_code != expected_code:
                self.device_code = expected_code
                update_fields = kwargs.get("update_fields")
                if update_fields is not None and "device_code" not in update_fields:
                    kwargs["update_fields"] = tuple(update_fields) + ("device_code",)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("设备历史不可删除。")


class DeviceKey(models.Model):
    objects = ImmutableAuthorizationQuerySet.as_manager()

    key_id = models.CharField(primary_key=True, max_length=128)
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name="keys")
    algorithm = models.CharField(max_length=32, default="ed25519")
    public_key = models.TextField()
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("device", "public_key"), name="licensing_device_key_unique"),
        ]

    def __str__(self) -> str:
        return f"设备密钥 {self.key_id}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("设备密钥不可直接修改；请通过授权服务改变状态。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("设备密钥历史不可删除。")


class DeviceBindingQuerySet(ImmutableAuthorizationQuerySet):
    def in_history_order(self, *prefix):
        # Zero denotes pre-sequence history. Time can order different instants;
        # within a legacy tie, ACTIVE is a current fact, not a UUID chronology.
        # The remaining state/UUID tie-breaks are conservative display choices.
        return self.order_by(
            *prefix, "-binding_order", "-bound_at",
            models.Case(
                models.When(state=DeviceBindingState.ACTIVE, then=0),
                models.When(state=DeviceBindingState.BLOCKED, then=1),
                models.When(state=DeviceBindingState.EXPIRED, then=2),
                default=3, output_field=models.IntegerField(),
            ),
            "-binding_id",
        )

    def latest_candidates(self):
        """All indistinguishable last events; UUID never determines billing."""
        latest = self.in_history_order().first()
        if latest is None:
            return self.none()
        candidates = self.filter(binding_order=latest.binding_order)
        if latest.binding_order == 0:
            candidates = candidates.filter(bound_at=latest.bound_at)
        return candidates.in_history_order()


class DeviceBinding(models.Model):
    objects = DeviceBindingQuerySet.as_manager()

    binding_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Only events observed after migration receive a sequence. Never backfill
    # random UUID order into legacy same-second histories.
    binding_order = models.PositiveBigIntegerField(default=0, editable=False)
    authorization = models.ForeignKey(LicenseInstance, on_delete=models.PROTECT, related_name="device_bindings")
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name="authorization_bindings")
    device_key = models.ForeignKey(DeviceKey, on_delete=models.PROTECT, related_name="authorization_bindings")
    state = models.CharField(max_length=16, choices=DeviceBindingState.choices, default=DeviceBindingState.ACTIVE, db_index=True)
    switch_count = models.PositiveIntegerField(default=0)
    bound_at = models.DateTimeField(default=timezone.now)
    unbound_at = models.DateTimeField(null=True, blank=True)
    last_server_time = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-binding_order", "-bound_at", "binding_id")
        constraints = [
            models.UniqueConstraint(
                fields=("authorization", "device"),
                condition=models.Q(state=DeviceBindingState.ACTIVE),
                name="licensing_active_authorization_device_unique",
            ),
            models.UniqueConstraint(
                fields=("authorization", "binding_order"),
                condition=models.Q(binding_order__gt=0),
                name="licensing_binding_order_unique",
            ),
        ]
        indexes = [
            models.Index(fields=("authorization", "state")),
            models.Index(fields=("device", "state")),
        ]

    def __str__(self) -> str:
        return f"设备绑定 {self.binding_id} / {self.state}"

    def save(self, *args, **kwargs):
        advance_order = kwargs.pop("_advance_order", False)
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("设备绑定不可直接修改；请通过授权服务改变状态。")
        if self._state.adding or advance_order:
            # Re-entering the already-held instance lock in public services
            # preserves card -> instance -> device -> key -> binding lock order.
            # Direct legitimate creates also serialize on the same parent.
            from django.db import router, transaction

            using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
            with transaction.atomic(using=using):
                LicenseInstance.objects.using(using).select_for_update().get(pk=self.authorization_id)
                maximum = type(self).objects.using(using).filter(authorization_id=self.authorization_id).aggregate(
                    value=models.Max("binding_order"),
                )["value"] or 0
                self.binding_order = maximum + 1
                if kwargs.get("update_fields") is not None:
                    kwargs["update_fields"] = (*kwargs["update_fields"], "binding_order")
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("设备绑定历史不可删除。")


class AuthorizationNonce(models.Model):
    """One-time proof nonce; the raw value is never persisted."""

    objects = ImmutableAuthorizationQuerySet.as_manager()

    nonce_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    software = models.ForeignKey("catalog.Software", on_delete=models.PROTECT, related_name="authorization_nonces")
    profile = models.ForeignKey("catalog.SoftwareProfile", on_delete=models.PROTECT, related_name="authorization_nonces")
    device = models.ForeignKey(Device, on_delete=models.PROTECT, null=True, blank=True, related_name="authorization_nonces")
    nonce_hash = models.CharField(max_length=64)
    action = models.CharField(max_length=16)
    request_id = models.CharField(max_length=128)
    consumed_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("software", "profile", "nonce_hash"), name="licensing_authorization_nonce_unique"),
        ]
        indexes = [models.Index(fields=("profile", "consumed_at"))]

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权随机值不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权随机值不可删除。")


class AuthorizationRequestRecord(models.Model):
    objects = ImmutableAuthorizationQuerySet.as_manager()

    request_id = models.CharField(primary_key=True, max_length=128)
    action = models.CharField(max_length=16)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_status = models.PositiveSmallIntegerField(default=200)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at", "request_id")
        constraints = [
            models.UniqueConstraint(
                fields=("action", "idempotency_key"),
                name="licensing_authorization_action_idempotency_unique",
            ),
        ]
        indexes = [models.Index(fields=("action", "created_at"))]

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权请求记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权请求记录不可删除。")

    @classmethod
    def purge_older_than(cls, *, cutoff, batch_size: int = 1000, max_batches: int = 20) -> int:
        """保留期清理：这张表唯一被授权的物理删除出口。

        普通 ``delete()`` 与 ``.filter().delete()`` 继续被守卫拦住——这张表是幂等
        台账，一次误删的批量删除会重新打开"重放旧 allow 信封"这条路。这里是唯一
        的例外，而且它有三重限制：只删 cutoff 之前、每批有上限、单次运行的批数有
        上限；每批都重新带上 ``created_at < cutoff``，所以运行期间被改动的行不会
        被顺手带走。

        走原生 SQL 是刻意的：它绕开 queryset 的删除守卫，守卫因此仍然是"默认关闭、
        只此一条通路打开"，而不是被整体删掉。
        """

        from django.db import connection

        batch_size = max(1, int(batch_size))
        removed = 0
        for _ in range(max(1, int(max_batches))):
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM licensing_authorizationrequestrecord "
                    "WHERE request_id IN ("
                    "  SELECT request_id FROM licensing_authorizationrequestrecord"
                    "   WHERE created_at < %s ORDER BY created_at LIMIT %s"
                    ")",
                    [cutoff, batch_size],
                )
                deleted = cursor.rowcount or 0
            removed += deleted
            if deleted < batch_size:
                break
        return removed


class LaunchTicket(models.Model):
    """一次性启动票据：短期、单设备绑定、可核销。

    启动器每次启动凭它拉起覆盖层，覆盖层只钉平台公钥。票据过期或被核销后
    即失效；重放旧票据会被拒绝。行本身保留作审计，不物理删除。
    """

    ticket_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    instance = models.ForeignKey(
        LicenseInstance, on_delete=models.PROTECT, related_name="launch_tickets"
    )
    device = models.ForeignKey(
        Device, on_delete=models.PROTECT, related_name="launch_tickets"
    )
    software_id = models.CharField(max_length=64)
    audience = models.CharField(max_length=128)
    issued_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    request_id = models.CharField(max_length=128)

    class Meta:
        ordering = ("-issued_at", "ticket_id")
        indexes = [
            models.Index(fields=("instance", "expires_at")),
            models.Index(fields=("device", "expires_at")),
        ]


class LicenseCardTombstone(models.Model):
    """Minimal auditable tombstone kept after a license card is deleted.

    The plaintext card code is never stored here; only the hash and redacted
    metadata survive so historical quota/audit entries remain explainable.
    """

    tombstone_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    card_public_id = models.UUIDField(unique=True)
    card_hash = models.CharField(max_length=64)
    software_id = models.CharField(max_length=64)
    profile_id = models.CharField(max_length=64)
    plan_snapshot_id = models.UUIDField()
    original_downstream_public_id = models.UUIDField()
    current_downstream_public_id = models.UUIDField()
    quota_cost = models.PositiveIntegerField(default=0)
    terminal_status = models.CharField(max_length=16)
    archived_at = models.DateTimeField()
    deleted_at = models.DateTimeField(default=timezone.now)
    actor_id = models.PositiveBigIntegerField()
    reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-deleted_at",)
        indexes = [
            models.Index(fields=("deleted_at",)),
            models.Index(fields=("original_downstream_public_id",)),
        ]

    def __str__(self) -> str:
        return f"授权卡密墓碑 {self.card_public_id} / {self.deleted_at}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权卡密墓碑不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权卡密墓碑不可删除。")


class ImmutableLicenseCardLifecycleOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("授权卡密生命周期幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("授权卡密生命周期幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("授权卡密生命周期幂等记录不可删除。")


class LicenseCardLifecycleOperation(models.Model):
    """Durable idempotency record for one archive/delete API request.

    Only redacted metadata is kept; the plaintext card code never appears.
    """

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="license_card_lifecycle_operations",
    )
    action = models.CharField(max_length=16)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableLicenseCardLifecycleOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="licensing_card_lifecycle_actor_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"授权卡密生命周期 {self.actor_id} / {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("授权卡密生命周期幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("授权卡密生命周期幂等记录不可删除。")
