from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("backup_control", "0005_three_encrypted_copies"),
    ]

    operations = [
        migrations.AlterField(
            model_name="backuppolicy",
            name="enabled",
            field=models.BooleanField(default=False),
        ),
    ]
