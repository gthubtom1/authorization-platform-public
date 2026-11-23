from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class AuditOutcome(models.TextChoices):
    SUCCESS = "success", "成功"
    FAILURE = "failure", "失败"


class ImmutableAuditQuerySet(models.QuerySet):
    def bulk_create(self, objs, batch_size=None, ignore_conflicts=False, update_conflicts=False, update_fields=None, unique_fields=None):
        if update_conflicts:
            raise ValueError("审计事件不可修改。")
        return super().bulk_create(objs, batch_size=batch_size, ignore_conflicts=ignore_conflicts, update_conflicts=False, update_fields=update_fields, unique_fields=unique_fields)

    def update(self, **kwargs):
        raise ValueError("审计事件不可修改。")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValueError("审计事件不可修改。")

    def delete(self):
        raise ValueError("审计事件不可删除。")


class AuditEvent(models.Model):
    objects = ImmutableAuditQuerySet.as_manager()

    public_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_events")
    actor_role = models.CharField(max_length=32, default="anonymous")
    action = models.CharField(max_length=64)
    outcome = models.CharField(max_length=16, choices=AuditOutcome.choices)
    object_type = models.CharField(max_length=64, blank=True)
    object_public_id = models.CharField(max_length=512, blank=True)
    request_id = models.CharField(max_length=128, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    reason_code = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ("-occurred_at", "-public_id")
        indexes = [models.Index(fields=("action", "occurred_at")), models.Index(fields=("object_type", "object_public_id"))]

    def __str__(self) -> str:
        return f"{self.action} / {self.outcome} / {self.occurred_at.isoformat()}"

    def save(self, *args, **kwargs):
        if not self._state.adding and not kwargs.pop("_allow_mutation", False):
            raise ValueError("审计事件不可修改。")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("审计事件不可删除。")
