from __future__ import annotations

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authorization_platform.accounts"
    verbose_name = "账号与下游"
