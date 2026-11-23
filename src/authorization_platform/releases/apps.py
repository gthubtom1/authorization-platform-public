from __future__ import annotations

from django.apps import AppConfig


class ReleasesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authorization_platform.releases"
    verbose_name = "版本发布"
