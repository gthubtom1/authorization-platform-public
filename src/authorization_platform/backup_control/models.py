from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class BackupPolicy(models.Model):
    """Singleton policy edited by administrators and consumed by the runner."""

    key = models.CharField(max_length=32, primary_key=True, default="default", editable=False)
    enabled = models.BooleanField(default=False)
    schedule_enabled = models.BooleanField(default=False)
    database_enabled = models.BooleanField(default=True)
    github_enabled = models.BooleanField(default=False)
    github_repository = models.CharField(max_length=200, blank=True, default="")
    github_token_ciphertext = models.TextField(blank=True, default="")
    cleanup_enabled = models.BooleanField(default=True)
    retention_full = models.PositiveIntegerField(default=7)
    retention_diff = models.PositiveIntegerField(default=14)
    retention_archive = models.PositiveIntegerField(default=14)
    github_retention_count = models.PositiveIntegerField(default=3)
    schedule_full_hour = models.PositiveSmallIntegerField(default=2)
    schedule_full_minute = models.PositiveSmallIntegerField(default=15)
    diff_interval_hours = models.PositiveSmallIntegerField(default=6)
    updated_at = models.DateTimeField(default=timezone.now)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name = "备份策略"

    def save(self, *args, **kwargs):
        self.key = "default"
        self.updated_at = timezone.now()
        return super().save(*args, **kwargs)


class BackupRunRequest(models.Model):
    class BackupType(models.TextChoices):
        FULL = "full", "全量"
        DIFF = "diff", "增量"

    class Status(models.TextChoices):
        PENDING = "pending", "排队中"
        ACCEPTED = "accepted", "已接收"
        RUNNING = "running", "执行中"
        SUCCEEDED = "succeeded", "成功"
        FAILED = "failed", "失败"

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    backup_type = models.CharField(max_length=8, choices=BackupType.choices, default=BackupType.FULL)
    scheduled_for = models.DateTimeField(null=True, blank=True, db_index=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True)
    # Only the host process that claimed a RUNNING row may complete it.
    attempt_token = models.CharField(max_length=64, blank=True, default="")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    message = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at", "public_id")
        indexes = [models.Index(fields=("status", "created_at"))]


class ImmutableBackupControlOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("备份操作记录不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("备份操作记录不可修改。")

    def delete(self):
        raise ValueError("备份操作记录不可删除。")


class BackupControlOperation(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="backup_control_operations",
    )
    action = models.CharField(max_length=32)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    objects = ImmutableBackupControlOperationQuerySet.as_manager()

    class Meta:
        ordering = ("-created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("actor", "action", "idempotency_key"),
                name="backup_control_actor_action_key_unique",
            )
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("备份操作记录不可直接修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("备份操作记录不可删除。")


class BackupRestoreStaging(models.Model):
    """Short-lived encrypted upload waiting for empty-site time confirmation."""

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="backup_restore_stagings",
    )
    original_name = models.CharField(max_length=180)
    sha256 = models.CharField(max_length=64)
    backup_time_utc = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        ordering = ("-created_at", "public_id")
