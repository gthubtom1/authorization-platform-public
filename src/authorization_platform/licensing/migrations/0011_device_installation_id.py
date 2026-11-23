from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("licensing", "0010_licenseinstance_device_switch_day"),
    ]

    operations = [
        migrations.AddField(
            model_name="device",
            name="installation_id",
            field=models.CharField(blank=True, db_index=True, max_length=128, null=True),
        ),
    ]
