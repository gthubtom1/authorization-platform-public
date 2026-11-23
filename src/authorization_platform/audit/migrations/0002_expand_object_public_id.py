from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]
    operations = [
        migrations.AlterField(
            model_name="auditevent", name="object_public_id",
            field=models.CharField(max_length=512, blank=True),
        ),
    ]
