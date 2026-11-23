from __future__ import annotations

from django.apps import AppConfig


class StorageCleanupConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authorization_platform.storage_cleanup"
    verbose_name = "存储清理"
