from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0007_downstreamadminoperation"),
    ]

    operations = [
        migrations.AddField(
            model_name="downstreamadminoperation",
            name="actor_username_digest",
            field=models.CharField(blank=True, max_length=64),
        ),
    ]
