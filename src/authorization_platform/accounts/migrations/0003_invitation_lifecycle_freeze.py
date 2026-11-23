from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0002_invitationcode_public_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="invitationcode",
            name="expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="invitationcode",
            name="max_attempts",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.RemoveConstraint(
            model_name="invitationcode",
            name="invitation_max_attempts_positive",
        ),
    ]
