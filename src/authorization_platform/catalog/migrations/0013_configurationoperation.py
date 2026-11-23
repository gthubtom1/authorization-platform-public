from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("catalog", "0012_policyversion_launch_ticket_enabled_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="ConfigurationOperation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("target", models.CharField(max_length=256)),
                ("idempotency_key", models.CharField(max_length=128)),
                ("request_hash", models.CharField(max_length=64)),
                ("response_payload", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="catalog_configuration_operations", to=settings.AUTH_USER_MODEL)),
            ],
            options={"constraints": [models.UniqueConstraint(fields=("actor", "idempotency_key"), name="catalog_config_actor_key_unique")]},
        ),
    ]
