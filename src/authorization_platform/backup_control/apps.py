from django.apps import AppConfig


class BackupControlConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authorization_platform.backup_control"
    verbose_name = "备份控制"
