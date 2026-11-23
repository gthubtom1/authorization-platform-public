from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class StorageCleanupState(models.Model):
    key = models.CharField(max_length=32, primary_key=True)
    updated_at = models.DateTimeField(default=timezone.now)


class ImmutableStorageCleanupOperationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("存储清理操作不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("存储清理操作不可修改。")

    def delete(self):
        raise ValueError("存储清理操作不可删除。")


class StorageCleanupOperation(models.Model):
    objects = ImmutableStorageCleanupOperationQuerySet.as_manager()

    operation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="storage_cleanup_operations")
    idempotency_key = models.CharField(max_length=128)
    request_hash = models.CharField(max_length=64)
    response = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ("-created_at", "-operation_id")
        constraints = [
            models.UniqueConstraint(fields=("actor", "idempotency_key"), name="storage_cleanup_actor_idempotency_unique"),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("存储清理操作不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("存储清理操作不可删除。")
