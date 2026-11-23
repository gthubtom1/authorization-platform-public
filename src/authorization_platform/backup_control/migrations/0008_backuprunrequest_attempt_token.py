from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("backup_control", "0007_backuprunrequest_scheduled_for"),
    ]

    operations = [
        migrations.AddField(
            model_name="backuprunrequest",
            name="attempt_token",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
    ]
