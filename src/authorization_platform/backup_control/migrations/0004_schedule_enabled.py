from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("backup_control", "0003_github_repo_restore_staging"),
    ]

    operations = [
        migrations.AddField(
            model_name="backuppolicy",
            name="schedule_enabled",
            field=models.BooleanField(default=False),
        ),
    ]
