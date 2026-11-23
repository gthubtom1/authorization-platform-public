from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("backup_control", "0006_master_switch_defaults_off"),
    ]

    operations = [
        migrations.AddField(
            model_name="backuprunrequest",
            name="scheduled_for",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
    ]
