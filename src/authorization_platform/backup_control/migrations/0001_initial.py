from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="BackupPolicy",
            fields=[
                ("key", models.CharField(default="default", editable=False, max_length=32, primary_key=True, serialize=False)),
                ("enabled", models.BooleanField(default=True)),
                ("database_enabled", models.BooleanField(default=True)),
                ("github_enabled", models.BooleanField(default=True)),
                ("cleanup_enabled", models.BooleanField(default=True)),
                ("retention_full", models.PositiveIntegerField(default=7)),
                ("retention_diff", models.PositiveIntegerField(default=14)),
                ("retention_archive", models.PositiveIntegerField(default=14)),
                ("github_retention_count", models.PositiveIntegerField(default=7)),
                ("updated_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={"verbose_name": "备份策略"},
        ),
    ]
