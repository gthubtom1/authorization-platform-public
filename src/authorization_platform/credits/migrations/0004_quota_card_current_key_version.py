from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("credits", "0003_quota_purchase_url_operations"),
    ]

    operations = [
        migrations.AlterField(
            model_name="quotacard",
            name="encryption_key_version",
            field=models.CharField(default="v2", max_length=32),
        ),
    ]
