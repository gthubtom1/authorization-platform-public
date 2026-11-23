from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("catalog", "0009_backfill_default_daily_device_switch"),
    ]

    operations = [
        migrations.AlterField(
            model_name="policyversion",
            name="verify_interval_seconds",
            field=models.PositiveIntegerField(default=60),
        ),
    ]
