from __future__ import annotations

import uuid

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class SoftwareStatus(models.TextChoices):
    DRAFT = "draft", "草稿"
    TESTING = "testing", "测试中"
    ACTIVE = "active", "正常"
    ARCHIVED = "archived", "已归档"


class ProfileStatus(models.TextChoices):
    DRAFT = "draft", "草稿"
    TESTING = "testing", "测试中"
    ACTIVE = "active", "正常"
    ARCHIVED = "archived", "已归档"


class PolicyStatus(models.TextChoices):
    DRAFT = "draft", "草稿"
    ACTIVE = "active", "生效"
    ARCHIVED = "archived", "已归档"


# 正式、测试、本地新建默认 60 秒。已售卡下次 verify 读当前 ACTIVE 策略间隔。
DEFAULT_VERIFY_INTERVAL_SECONDS = 60


class CapabilityValueType(models.TextChoices):
    BOOLEAN = "boolean", "布尔"
    INTEGER = "integer", "整数"
    STRING = "string", "文本"


class CapabilityStatus(models.TextChoices):
    ACTIVE = "active", "正常"
    ARCHIVED = "archived", "已归档"


class PlanStatus(models.TextChoices):
    DRAFT = "draft", "草稿"
    ACTIVE = "active", "可用"
    ARCHIVED = "archived", "已归档"
    DELETED = "deleted", "已删除"


class DownstreamSoftwareStatus(models.TextChoices):
    ACTIVE = "active", "已开放"
    CLOSED = "closed", "已关闭"


class Software(models.Model):
    software_id = models.SlugField(primary_key=True, max_length=64)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=SoftwareStatus.choices, default=SoftwareStatus.DRAFT, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "software_id")

    def __str__(self) -> str:
        return f"{self.name} ({self.software_id})"


class SoftwareProfile(models.Model):
    software = models.ForeignKey(Software, on_delete=models.PROTECT, related_name="profiles")
    profile_id = models.SlugField(max_length=64)
    client_id = models.CharField(max_length=128)
    contract_version = models.CharField(max_length=64, default="authorization.v1")
    target = models.CharField(max_length=32, default="windows")
    arch = models.CharField(max_length=32, default="x64")
    channel = models.CharField(max_length=32, default="stable")
    adapter_key = models.CharField(max_length=64, default="generic-online-v1")
    adapter_version = models.CharField(max_length=32, default="1")
    minimum_client_version = models.CharField(max_length=64, blank=True)
    config_version = models.CharField(max_length=64, default="cfg-1")
    support_purchase_url = models.URLField(max_length=2048, blank=True)
    support_qq = models.CharField(max_length=64, blank=True)
    support_wechat = models.CharField(max_length=64, blank=True)
    announcement_enabled = models.BooleanField(default=False)
    announcement_title = models.CharField(max_length=120, blank=True)
    announcement_body = models.TextField(max_length=2000, blank=True)
    status = models.CharField(max_length=16, choices=ProfileStatus.choices, default=ProfileStatus.DRAFT, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("software_id", "profile_id")
        constraints = [
            models.UniqueConstraint(fields=("software", "profile_id"), name="catalog_profile_per_software_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.software_id}/{self.profile_id}"


class ImmutablePolicyVersionQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("策略版本不可直接修改；请创建新的策略版本。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("策略版本不可直接修改；请创建新的策略版本。")

    def delete(self):
        raise ValueError("策略版本不可删除。")


class PolicyVersion(models.Model):
    objects = ImmutablePolicyVersionQuerySet.as_manager()
    profile = models.ForeignKey(SoftwareProfile, on_delete=models.PROTECT, related_name="policy_versions")
    version = models.SlugField(max_length=64)
    status = models.CharField(max_length=16, choices=PolicyStatus.choices, default=PolicyStatus.DRAFT, db_index=True)
    max_devices = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    allow_device_switch = models.BooleanField(default=False)
    device_switch_limit = models.PositiveIntegerField(default=0)
    device_proof_required = models.BooleanField(default=True)
    verify_interval_seconds = models.PositiveIntegerField(default=DEFAULT_VERIFY_INTERVAL_SECONDS)
    offline_grace_seconds = models.PositiveIntegerField(default=0)
    launch_ticket_enabled = models.BooleanField(default=True)
    launch_ticket_ttl_seconds = models.PositiveIntegerField(
        default=180, validators=[MinValueValidator(30), MaxValueValidator(3600)]
    )
    effective_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_policy_versions",
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-effective_at", "-created_at")
        constraints = [
            models.UniqueConstraint(fields=("profile", "version"), name="catalog_policy_version_per_profile_unique"),
            models.CheckConstraint(condition=models.Q(max_devices__gt=0), name="catalog_policy_max_devices_positive"),
        ]

    def __str__(self) -> str:
        return f"{self.profile} / {self.version}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("策略版本不可修改；请创建新的策略版本。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("策略版本不可删除。")


class ImmutablePolicyRevisionOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("策略修订幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("策略修订幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("策略修订幂等记录不可删除。")


class PolicyRevisionOperation(models.Model):
    """Durable idempotency fact for a versioned authorization policy change."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="catalog_policy_revision_operations",
    )
    profile = models.ForeignKey(
        SoftwareProfile,
        on_delete=models.PROTECT,
        related_name="policy_revision_operations",
    )
    policy = models.ForeignKey(
        PolicyVersion,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="revision_operations",
    )
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_status = models.PositiveSmallIntegerField(default=200)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutablePolicyRevisionOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "profile", "idempotency_key"),
                name="catalog_policy_revision_actor_profile_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("profile", "created_at"))]

    def __str__(self) -> str:
        return f"策略修订操作 {self.actor_id} / {self.profile_id} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("策略修订幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("策略修订幂等记录不可删除。")


class CapabilityDefinition(models.Model):
    profile = models.ForeignKey(SoftwareProfile, on_delete=models.PROTECT, related_name="capabilities")
    capability_key = models.CharField(max_length=128)
    value_type = models.CharField(max_length=16, choices=CapabilityValueType.choices)
    default_value = models.JSONField(null=True, blank=True, default=None)
    minimum_value = models.IntegerField(null=True, blank=True)
    maximum_value = models.IntegerField(null=True, blank=True)
    is_public = models.BooleanField(default=True)
    status = models.CharField(max_length=16, choices=CapabilityStatus.choices, default=CapabilityStatus.ACTIVE, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("profile_id", "capability_key")
        constraints = [
            models.UniqueConstraint(fields=("profile", "capability_key"), name="catalog_capability_per_profile_unique"),
            models.CheckConstraint(
                condition=(
                    models.Q(minimum_value__isnull=True)
                    | models.Q(maximum_value__isnull=True)
                    | models.Q(minimum_value__lte=models.F("maximum_value"))
                ),
                name="catalog_capability_range_ordered",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.profile} / {self.capability_key}"


class Plan(models.Model):
    software = models.ForeignKey(Software, on_delete=models.PROTECT, related_name="plans")
    profile = models.ForeignKey(SoftwareProfile, on_delete=models.PROTECT, related_name="plans")
    name = models.CharField(max_length=120)
    duration_seconds = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    quota_cost = models.PositiveIntegerField(default=0)
    test_only = models.BooleanField(default=False)
    status = models.CharField(max_length=16, choices=PlanStatus.choices, default=PlanStatus.DRAFT, db_index=True)
    effective_at = models.DateTimeField(default=timezone.now)
    capability_values = models.JSONField(default=dict)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_catalog_plans",
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("software_id", "name", "id")
        constraints = [
            models.CheckConstraint(condition=models.Q(duration_seconds__gt=0), name="catalog_plan_duration_positive"),
        ]

    @property
    def latest_snapshot(self) -> "PlanSnapshot | None":
        return self.snapshots.order_by("-snapshot_version").first()

    def __str__(self) -> str:
        return f"{self.software_id} / {self.name}"


class ImmutablePlanSnapshotQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("套餐快照不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("套餐快照不可修改。")

    def delete(self):
        raise ValueError("套餐快照不可删除。")


class PlanSnapshot(models.Model):
    objects = ImmutablePlanSnapshotQuerySet.as_manager()
    snapshot_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="snapshots")
    software = models.ForeignKey(Software, on_delete=models.PROTECT, related_name="plan_snapshots")
    profile = models.ForeignKey(SoftwareProfile, on_delete=models.PROTECT, related_name="plan_snapshots")
    policy_version = models.ForeignKey(PolicyVersion, on_delete=models.PROTECT, related_name="plan_snapshots")
    snapshot_version = models.PositiveIntegerField(default=1)
    name = models.CharField(max_length=120)
    duration_seconds = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    quota_cost = models.PositiveIntegerField(default=0)
    test_only = models.BooleanField(default=False)
    capability_values = models.JSONField(default=dict)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_plan_snapshots",
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("plan_id", "-snapshot_version")
        constraints = [
            models.UniqueConstraint(fields=("plan", "snapshot_version"), name="catalog_plan_snapshot_version_unique"),
            models.CheckConstraint(condition=models.Q(duration_seconds__gt=0), name="catalog_snapshot_duration_positive"),
        ]

    def __str__(self) -> str:
        return f"{self.name} / 快照 {self.snapshot_version}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("套餐快照不可修改；请通过套餐修订产生新快照。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("套餐快照不可删除。")


class ImmutableConfigurationOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("配置操作记录不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("配置操作记录不可修改。")

    def delete(self):
        raise ValueError("配置操作记录不可删除。")


class ConfigurationOperation(models.Model):
    """Committed configuration result, including the original version and response."""

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="catalog_configuration_operations")
    target = models.CharField(max_length=256)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableConfigurationOperationQuerySet.as_manager()

    class Meta:
        constraints = [models.UniqueConstraint(fields=("actor", "idempotency_key"), name="catalog_config_actor_key_unique")]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("配置操作记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("配置操作记录不可删除。")


class ImmutablePlanCreateOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("套餐新增幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("套餐新增幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("套餐新增幂等记录不可删除。")


class PlanCreateOperation(models.Model):
    """Durable creation fact, scoped by namespace to software or plan requests.

    Software creation/status requests have no plan; stable identities and responses are
    retained in response_payload. The historical model/table name stays stable.
    """

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="catalog_plan_create_operations",
    )
    namespace = models.CharField(max_length=128)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="create_operations",
    )
    response_status = models.PositiveSmallIntegerField(default=201)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutablePlanCreateOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "namespace", "idempotency_key"),
                name="catalog_plan_create_actor_scope_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"套餐新增操作 {self.actor_id} / {self.namespace} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("套餐新增幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("套餐新增幂等记录不可删除。")


class ImmutablePlanLifecycleOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("套餐生命周期幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("套餐生命周期幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("套餐生命周期幂等记录不可删除。")


class PlanLifecycleOperation(models.Model):
    """Durable idempotency fact for a plan archive/restore/delete transition."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="catalog_plan_lifecycle_operations",
    )
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        related_name="lifecycle_operations",
    )
    action = models.CharField(max_length=32, default="status")
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_status = models.PositiveSmallIntegerField(default=200)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutablePlanLifecycleOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "action", "idempotency_key"),
                name="catalog_plan_lifecycle_actor_action_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"套餐生命周期操作 {self.actor_id} / {self.plan_id} / {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("套餐生命周期幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("套餐生命周期幂等记录不可删除。")


class ImmutablePlanRevisionOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("套餐修订幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("套餐修订幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("套餐修订幂等记录不可删除。")


class PlanRevisionOperation(models.Model):
    """Durable idempotency fact for a plan revision request."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="catalog_plan_revision_operations",
    )
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        related_name="revision_operations",
    )
    action = models.CharField(max_length=32, default="revise")
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_status = models.PositiveSmallIntegerField(default=200)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutablePlanRevisionOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "action", "idempotency_key"),
                name="catalog_plan_revision_actor_action_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"套餐修订操作 {self.actor_id} / {self.plan_id} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("套餐修订幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("套餐修订幂等记录不可删除。")


class ImmutableDownstreamSoftwareOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("下游经营范围幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("下游经营范围幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("下游经营范围幂等记录不可删除。")


class DownstreamSoftwareOperation(models.Model):
    """Durable idempotency fact for a downstream software-scope write."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="catalog_downstream_software_operations",
    )
    downstream_public_id = models.UUIDField()
    software_id = models.CharField(max_length=64)
    action = models.CharField(max_length=32, default="set")
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_status = models.PositiveSmallIntegerField(default=200)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableDownstreamSoftwareOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "action", "idempotency_key"),
                name="catalog_downstream_scope_actor_action_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("downstream_public_id", "software_id"))]

    def __str__(self) -> str:
        return f"下游经营范围操作 {self.actor_id} / {self.downstream_public_id} / {self.software_id} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("下游经营范围幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("下游经营范围幂等记录不可删除。")


class DownstreamSoftware(models.Model):
    downstream = models.ForeignKey(
        "accounts.DownstreamProfile",
        on_delete=models.CASCADE,
        related_name="software_accesses",
    )
    software = models.ForeignKey(Software, on_delete=models.PROTECT, related_name="downstream_accesses")
    status = models.CharField(max_length=16, choices=DownstreamSoftwareStatus.choices, default=DownstreamSoftwareStatus.ACTIVE, db_index=True)
    all_plans_allowed = models.BooleanField(default=True)
    allowed_plans = models.ManyToManyField(Plan, blank=True, related_name="downstream_accesses")
    configuration_enabled = models.BooleanField(default=False)
    config_version = models.CharField(max_length=64, default="cfg-1")
    support_purchase_url = models.URLField(max_length=2048, blank=True)
    support_qq = models.CharField(max_length=64, blank=True)
    support_wechat = models.CharField(max_length=64, blank=True)
    announcement_enabled = models.BooleanField(default=False)
    announcement_title = models.CharField(max_length=120, blank=True)
    announcement_body = models.TextField(max_length=2000, blank=True)
    opened_at = models.DateTimeField(default=timezone.now)
    closed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("software_id", "downstream_id")
        constraints = [
            models.UniqueConstraint(fields=("downstream", "software"), name="catalog_downstream_software_unique"),
        ]

    def __str__(self) -> str:
        return f"{self.downstream_id} → {self.software_id}"
