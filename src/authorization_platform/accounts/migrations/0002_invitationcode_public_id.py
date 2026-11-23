from __future__ import annotations

import uuid

from django.db import migrations, models
from django.db.models import Count


def populate_public_ids(apps, schema_editor) -> None:
    invitation_model = apps.get_model("accounts", "InvitationCode")
    database_alias = schema_editor.connection.alias
    for invitation in invitation_model.objects.using(database_alias).filter(public_id__isnull=True).iterator():
        invitation.public_id = uuid.uuid4()
        invitation.save(using=database_alias, update_fields=("public_id",))


def assert_public_ids_complete(apps, schema_editor) -> None:
    invitation_model = apps.get_model("accounts", "InvitationCode")
    database_alias = schema_editor.connection.alias
    queryset = invitation_model.objects.using(database_alias)
    if queryset.filter(public_id__isnull=True).exists():
        raise RuntimeError("InvitationCode.public_id 回填不完整，停止收紧唯一约束。")
    if queryset.values("public_id").annotate(row_count=Count("pk")).filter(row_count__gt=1).exists():
        raise RuntimeError("InvitationCode.public_id 存在重复值，停止收紧唯一约束。")


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="invitationcode",
            name="public_id",
            field=models.UUIDField(blank=True, db_index=True, editable=False, null=True),
        ),
        migrations.RunPython(populate_public_ids, migrations.RunPython.noop),
        migrations.RunPython(assert_public_ids_complete, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="invitationcode",
            name="public_id",
            field=models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
