from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class DownstreamStatus(models.TextChoices):
    ACTIVE = "active", "正常"
    SUSPENDED = "suspended", "暂停"
    CLOSED = "closed", "已归档"


class RegistrationSource(models.TextChoices):
    DIRECT = "direct", "管理员直建"
    INVITATION = "invitation", "邀请码注册"


class InvitationStatus(models.TextChoices):
    ISSUED = "issued", "未使用"
    CONSUMED = "consumed", "已使用"
    REVOKED = "revoked", "已撤销"
    EXPIRED = "expired", "已过期"
    ARCHIVED = "archived", "已归档"
    DELETED_TOMBSTONE = "deleted_tombstone", "已删除"


class DownstreamProfile(models.Model):
    """Business identity for a channel account; User remains the auth identity."""

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="downstream_profile",
    )
    status = models.CharField(max_length=16, choices=DownstreamStatus.choices, default=DownstreamStatus.ACTIVE, db_index=True)
    registration_source = models.CharField(max_length=16, choices=RegistrationSource.choices)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_downstream_profiles",
    )
    registered_at = models.DateTimeField(default=timezone.now)
    last_successful_login_at = models.DateTimeField(null=True, blank=True)
    session_version = models.PositiveIntegerField(default=1)
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="closed_downstream_profiles",
    )
    closed_reason = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-registered_at",)
        indexes = [models.Index(fields=("status", "registered_at"))]

    def __str__(self) -> str:
        return f"下游 {self.user.username} ({self.public_id})"


class DownstreamTombstone(models.Model):
    """Minimal trace retained after an archived downstream is physically deleted."""

    public_id = models.UUIDField(primary_key=True)
    username_digest = models.CharField(max_length=64)
    deleted_at = models.DateTimeField(default=timezone.now)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deleted_downstream_tombstones",
    )
    delete_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-deleted_at",)

    def __str__(self) -> str:
        return f"已删除下游 {self.public_id}"


class DownstreamAdminOperationAction(models.TextChoices):
    CREATE = "create", "管理员创建下游"
    STATUS = "status", "管理员变更下游状态"
    ARCHIVE = "archive", "管理员归档下游"
    DELETE = "delete", "管理员删除下游"


class ImmutableDownstreamAdminOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("下游管理员操作记录不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("下游管理员操作记录不可修改。")

    def delete(self):
        raise ValueError("下游管理员操作记录不可删除。")


class DownstreamAdminOperation(models.Model):
    """Durable idempotency fact for an administrator downstream write.

    The request hash is an HMAC created by the API boundary.  It may cover an
    initial password, but the password itself is never persisted.  A pending
    row is completed inside the same transaction as the business mutation;
    ``response_status`` makes a replay return the original HTTP status too.
    """

    objects = ImmutableDownstreamAdminOperationQuerySet.as_manager()

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="downstream_admin_operations",
    )
    actor_username_digest = models.CharField(max_length=64, blank=True)
    action = models.CharField(max_length=16, choices=DownstreamAdminOperationAction.choices)
    target_profile_public_id = models.UUIDField(null=True, blank=True, db_index=True)
    target_username_digest = models.CharField(max_length=64, blank=True)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    response_status = models.PositiveSmallIntegerField(default=200)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ("-created_at", "-public_id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="downstream_admin_operation_actor_key_unique",
            ),
        ]
        indexes = [
            models.Index(
                fields=("action", "created_at"),
                name="accounts_dow_action_5d4a3a_idx",
            )
        ]

    def __str__(self) -> str:
        return f"下游管理员操作 {self.public_id} / {self.action}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("下游管理员操作记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("下游管理员操作记录不可删除。")


class PasswordOperationAction(models.TextChoices):
    CHANGE = "change", "自助修改密码"
    RESET = "reset", "管理员重置密码"


class ImmutablePasswordOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("密码操作记录不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("密码操作记录不可修改。")

    def delete(self):
        raise ValueError("密码操作记录不可删除。")


class PasswordOperation(models.Model):
    """Durable, non-secret record for a password mutation request.

    The passwords themselves never enter this table.  The request hash is an
    HMAC generated by the service layer and exists only to detect reuse of an
    idempotency key with a different request.  The target digest and
    ``target_profile_public_id`` keep the audit trail useful after a
    downstream is archived or deleted.
    """

    objects = ImmutablePasswordOperationQuerySet.as_manager()

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="password_operations_acted",
    )
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="password_operations_targeted",
    )
    target_profile_public_id = models.UUIDField(null=True, blank=True, db_index=True)
    target_username_digest = models.CharField(max_length=64, blank=True)
    action = models.CharField(max_length=16, choices=PasswordOperationAction.choices)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ("-created_at", "-public_id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="password_operation_actor_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("action", "created_at"))]

    def __str__(self) -> str:
        return f"密码操作 {self.public_id} / {self.action}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("密码操作记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("密码操作记录不可删除。")


class InvitationBatch(models.Model):
    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="invitation_batches")
    quantity = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    # API/legacy-page retries use a durable operation identity.  Historical
    # batches keep this nullable so the migration does not invent keys for old
    # records.
    idempotency_key = models.CharField(max_length=128, null=True, blank=True)
    request_hash = models.CharField(max_length=64, null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("created_by", "idempotency_key"),
                name="invitation_batch_actor_key_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"邀请码批次 {self.public_id} ({self.quantity})"


class ImmutableInvitationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("邀请码生命周期不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("邀请码生命周期不可直接修改。")

    def delete(self):
        raise ValueError("邀请码不可删除；请通过明确的业务动作改变状态。")


class InvitationCode(models.Model):
    objects = ImmutableInvitationQuerySet.as_manager()

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    batch = models.ForeignKey(InvitationBatch, on_delete=models.PROTECT, related_name="codes")
    code_hash = models.CharField(max_length=64, unique=True)
    code_ciphertext = models.TextField()
    status = models.CharField(max_length=24, choices=InvitationStatus.choices, default=InvitationStatus.ISSUED, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    # New invitations have no business expiry or per-code attempt budget.
    # Nullable fields preserve the historical TTL rows during migration.
    expires_at = models.DateTimeField(null=True, blank=True)
    max_attempts = models.PositiveIntegerField(null=True, blank=True)
    attempt_count = models.PositiveIntegerField(default=0)
    consumed_at = models.DateTimeField(null=True, blank=True)
    consumed_profile = models.ForeignKey(
        DownstreamProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="consumed_invitations",
    )
    # Keep the final registered username available after the profile is archived/deleted.
    # This is an admin-only display value, not a password, token, or invitation code.
    consumed_username = models.CharField(max_length=150, blank=True)
    consumed_username_digest = models.CharField(max_length=64, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=255, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    status_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("status", "expires_at"))]

    @property
    def effective_status(self) -> str:
        if self.status == InvitationStatus.ISSUED and self.expires_at is not None and timezone.now() >= self.expires_at:
            return InvitationStatus.EXPIRED
        return self.status

    @property
    def effective_status_display(self) -> str:
        return dict(InvitationStatus.choices).get(self.effective_status, self.effective_status)

    def __str__(self) -> str:
        return f"邀请码 {self.public_id} / {self.status}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("邀请码生命周期不可直接修改；请通过明确的业务动作改变状态。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("邀请码不可删除；请通过明确的业务动作改变状态。")


class InvitationCodeTombstone(models.Model):
    """Minimal auditable tombstone kept after an invitation code is deleted."""

    tombstone_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code_public_id = models.UUIDField(unique=True)
    code_hash = models.CharField(max_length=64)
    terminal_status = models.CharField(max_length=24)
    consumed_username_digest = models.CharField(max_length=64, blank=True)
    archived_at = models.DateTimeField()
    deleted_at = models.DateTimeField(default=timezone.now)
    actor_id = models.PositiveBigIntegerField()
    reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-deleted_at",)
        indexes = [models.Index(fields=("deleted_at",))]

    def __str__(self) -> str:
        return f"邀请码墓碑 {self.code_public_id} / {self.deleted_at}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("邀请码墓碑不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("邀请码墓碑不可删除。")


class ImmutableInvitationLifecycleOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("邀请码生命周期幂等记录不可直接修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("邀请码生命周期幂等记录不可直接修改。")

    def delete(self):
        raise ValueError("邀请码生命周期幂等记录不可删除。")


class InvitationLifecycleOperation(models.Model):
    """Durable idempotency record for one invitation archive/delete request."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="invitation_lifecycle_operations",
    )
    action = models.CharField(max_length=16)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableInvitationLifecycleOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="accounts_invitation_lifecycle_actor_key_unique",
            ),
        ]
        indexes = [models.Index(fields=("actor", "created_at"))]

    def __str__(self) -> str:
        return f"邀请码生命周期 {self.actor_id} / {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("邀请码生命周期幂等记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("邀请码生命周期幂等记录不可删除。")
