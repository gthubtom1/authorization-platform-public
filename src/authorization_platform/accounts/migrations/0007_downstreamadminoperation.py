import uuid

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0006_passwordoperation"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="DownstreamAdminOperation",
            fields=[
                (
                    "public_id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("create", "管理员创建下游"),
                            ("status", "管理员变更下游状态"),
                            ("archive", "管理员归档下游"),
                            ("delete", "管理员删除下游"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "target_profile_public_id",
                    models.UUIDField(blank=True, db_index=True, null=True),
                ),
                ("target_username_digest", models.CharField(blank=True, max_length=64)),
                ("idempotency_key", models.CharField(max_length=128)),
                ("request_hash", models.CharField(max_length=64)),
                ("response_payload", models.JSONField(default=dict)),
                ("response_status", models.PositiveSmallIntegerField(default=200)),
                (
                    "created_at",
                    models.DateTimeField(default=django.utils.timezone.now, db_index=True),
                ),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="downstream_admin_operations",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at", "-public_id"),
            },
        ),
        migrations.AddConstraint(
            model_name="downstreamadminoperation",
            constraint=models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="downstream_admin_operation_actor_key_unique",
            ),
        ),
        migrations.AddIndex(
            model_name="downstreamadminoperation",
            index=models.Index(fields=["action", "created_at"], name="accounts_dow_action_5d4a3a_idx"),
        ),
    ]
