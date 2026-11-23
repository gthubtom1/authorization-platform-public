from __future__ import annotations

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0005_invitationbatch_idempotency"),
    ]

    operations = [
        migrations.CreateModel(
            name="PasswordOperation",
            fields=[
                (
                    "public_id",
                    models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
                ),
                ("target_profile_public_id", models.UUIDField(blank=True, db_index=True, null=True)),
                ("target_username_digest", models.CharField(blank=True, max_length=64)),
                (
                    "action",
                    models.CharField(
                        choices=[("change", "自助修改密码"), ("reset", "管理员重置密码")],
                        max_length=16,
                    ),
                ),
                ("idempotency_key", models.CharField(max_length=128)),
                ("request_hash", models.CharField(max_length=64)),
                ("response_payload", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="password_operations_acted",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "target_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="password_operations_targeted",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at", "-public_id"),
            },
        ),
        migrations.AddIndex(
            model_name="passwordoperation",
            index=models.Index(fields=["action", "created_at"], name="accounts_pa_action_22fb3b_idx"),
        ),
        migrations.AddConstraint(
            model_name="passwordoperation",
            constraint=models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="password_operation_actor_key_unique",
            ),
        ),
    ]
