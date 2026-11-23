from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class ReleaseStatus(models.TextChoices):
    DRAFT = "draft", "草稿"
    PUBLISHED = "published", "已发布"
    WITHDRAWN = "withdrawn", "已撤回"
    DISCARDED = "discarded", "已丢弃"
    ARCHIVED = "archived", "已归档"


class ReleaseSignatureStatus(models.TextChoices):
    DECLARED = "declared", "已声明"
    VERIFIED = "verified", "已验证"


class ReleaseOperationAction(models.TextChoices):
    UPLOAD = "upload", "上传"
    PUBLISH = "publish", "发布"
    PUBLISH_LINK = "publish_link", "发布网盘地址"
    WITHDRAW = "withdraw", "撤回"
    DISCARD = "discard", "丢弃"
    DELETE_PACKAGE = "delete_package", "删除安装包"
    UPDATE_LINK = "update_link", "修改网盘地址"
    ARCHIVE = "archive", "归档"
    UPDATE_VERSION = "update_version", "修改版本号"


class ImmutableReleaseOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("版本操作记录不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("版本操作记录不可修改。")

    def delete(self):
        raise ValueError("版本操作记录不可删除。")


class Release(models.Model):
    release_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    software = models.ForeignKey("catalog.Software", on_delete=models.PROTECT, related_name="releases")
    profile = models.ForeignKey("catalog.SoftwareProfile", on_delete=models.PROTECT, related_name="releases")
    version = models.CharField(max_length=64)
    target = models.CharField(max_length=32)
    arch = models.CharField(max_length=32)
    channel = models.CharField(max_length=32)
    minimum_client_version = models.CharField(max_length=64, blank=True)
    notes = models.TextField(max_length=2000, blank=True)
    manifest = models.JSONField(default=dict)
    package_name = models.CharField(max_length=255, blank=True)
    package_path = models.CharField(max_length=512, blank=True)
    package_size = models.PositiveBigIntegerField(default=0)
    package_sha256 = models.CharField(max_length=64, blank=True)
    # Default customer path: open this HTTPS URL in a browser. Not authenticated.
    # ZIP upload/package_path remains for optional same-host downloads later.
    external_download_url = models.CharField(max_length=2048, blank=True, default="")
    signature_algorithm = models.CharField(max_length=32)
    signature_key_id = models.CharField(max_length=128)
    signature_status = models.CharField(max_length=16, choices=ReleaseSignatureStatus.choices, default=ReleaseSignatureStatus.DECLARED)
    status = models.CharField(max_length=16, choices=ReleaseStatus.choices, default=ReleaseStatus.DRAFT, db_index=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_releases")
    created_at = models.DateTimeField(default=timezone.now)
    published_at = models.DateTimeField(null=True, blank=True, db_index=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    withdrawal_reason = models.CharField(max_length=255, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_from_status = models.CharField(max_length=16, blank=True)
    archive_reason = models.CharField(max_length=255, blank=True)
    package_deleted_at = models.DateTimeField(null=True, blank=True)
    previous_release = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True, related_name="superseded_releases")

    class Meta:
        ordering = ("-created_at", "-release_id")
        constraints = [
            models.UniqueConstraint(
                fields=("software", "profile", "version", "target", "arch", "channel"),
                condition=~models.Q(status="discarded"),
                name="releases_identity_version_unique",
            ),
            models.CheckConstraint(condition=models.Q(package_size__gte=0), name="releases_package_size_nonnegative"),
        ]
        indexes = [
            models.Index(fields=("software", "profile", "channel", "status", "published_at")),
            models.Index(fields=("status", "withdrawn_at")),
        ]

    def __str__(self) -> str:
        return f"{self.software_id}/{self.profile_id} {self.version} {self.channel}"


class ReleaseOperation(models.Model):
    objects = ImmutableReleaseOperationQuerySet.as_manager()

    operation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="release_operations")
    release = models.ForeignKey(Release, on_delete=models.PROTECT, null=True, blank=True, related_name="operations")
    action = models.CharField(max_length=16, choices=ReleaseOperationAction.choices)
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at", "-operation_id")
        constraints = [
            models.UniqueConstraint(fields=("actor", "action", "idempotency_key"), name="releases_actor_action_idempotency_unique"),
        ]
        indexes = [models.Index(fields=("release", "action", "created_at"))]

    def __str__(self) -> str:
        return f"版本操作 {self.action} / {self.idempotency_key}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("版本操作记录不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("版本操作记录不可删除。")
