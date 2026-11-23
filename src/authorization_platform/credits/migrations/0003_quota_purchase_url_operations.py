from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("credits", "0002_generic_quota_cards_and_settings"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="QuotaPurchaseUrlOperation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("idempotency_key", models.CharField(max_length=128)),
                ("request_hash", models.CharField(max_length=64)),
                ("purchase_url", models.URLField(blank=True, max_length=2048)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "actor",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="quota_purchase_url_operations",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at", "id"),
            },
        ),
        migrations.AddConstraint(
            model_name="quotapurchaseurloperation",
            constraint=models.UniqueConstraint(
                fields=("actor", "idempotency_key"),
                name="credits_purchase_url_actor_idempotency_unique",
            ),
        ),
        migrations.AddIndex(
            model_name="quotapurchaseurloperation",
            index=models.Index(fields=["actor", "created_at"], name="credits_quo_actor_i_a11d40_idx"),
        ),
    ]
