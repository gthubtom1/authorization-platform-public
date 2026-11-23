from __future__ import annotations

from django.apps import AppConfig


class CatalogConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authorization_platform.catalog"
    verbose_name = "软件目录"
