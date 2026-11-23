import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("backup_control", "0002_backup_schedule_netdisk_telegram"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="backuppolicy",
            name="github_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="github_repository",
            field=models.CharField(blank=True, default="", max_length=200),
        ),
        migrations.AddField(
            model_name="backuppolicy",
            name="github_token_ciphertext",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.CreateModel(
            name="BackupRestoreStaging",
            fields=[
                ("public_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("original_name", models.CharField(max_length=180)),
                ("sha256", models.CharField(max_length=64)),
                ("backup_time_utc", models.DateTimeField()),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("expires_at", models.DateTimeField(db_index=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="backup_restore_stagings",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at", "public_id"),
            },
        ),
    ]
