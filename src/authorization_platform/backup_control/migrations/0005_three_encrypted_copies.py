from django.db import migrations, models


def set_three_encrypted_copies(apps, schema_editor):
    BackupPolicy = apps.get_model("backup_control", "BackupPolicy")
    BackupPolicy.objects.filter(key="default").update(github_retention_count=3)


class Migration(migrations.Migration):

    dependencies = [
        ("backup_control", "0004_schedule_enabled"),
    ]

    operations = [
        migrations.AlterField(
            model_name="backuppolicy",
            name="github_retention_count",
            field=models.PositiveIntegerField(default=3),
        ),
        migrations.RunPython(set_three_encrypted_copies, migrations.RunPython.noop),
    ]
