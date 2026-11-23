from __future__ import annotations

from django.apps import AppConfig


class CreditsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authorization_platform.credits"
    verbose_name = "额度中心"
