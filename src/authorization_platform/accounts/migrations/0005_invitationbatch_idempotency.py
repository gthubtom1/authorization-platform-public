from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0004_invitation_consumed_username"),
    ]

    operations = [
        migrations.AddField(
            model_name="invitationbatch",
            name="idempotency_key",
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name="invitationbatch",
            name="request_hash",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddConstraint(
            model_name="invitationbatch",
            constraint=models.UniqueConstraint(
                fields=("created_by", "idempotency_key"),
                name="invitation_batch_actor_key_unique",
            ),
        ),
    ]
