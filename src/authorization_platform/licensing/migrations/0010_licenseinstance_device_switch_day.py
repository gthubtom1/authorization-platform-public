from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("licensing", "0009_downstream_device_operation"),
    ]

    operations = [
        migrations.AddField(
            model_name="licenseinstance",
            name="device_switch_day",
            field=models.DateField(blank=True, null=True),
        ),
    ]
