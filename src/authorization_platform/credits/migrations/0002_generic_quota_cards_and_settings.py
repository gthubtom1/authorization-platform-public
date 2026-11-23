from django.db import migrations, models


def clear_legacy_quota_targets(apps, schema_editor):
    QuotaCardBatch = apps.get_model("credits", "QuotaCardBatch")
    QuotaCard = apps.get_model("credits", "QuotaCard")
    QuotaCardBatch.objects.all().update(target_downstream=None, target_downstream_public_id=None)
    QuotaCard.objects.all().update(target_downstream=None, target_downstream_public_id=None)


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0004_invitation_consumed_username"),
        ("credits", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="QuotaPlatformSettings",
            fields=[
                (
                    "key",
                    models.CharField(
                        default="default",
                        editable=False,
                        max_length=32,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("purchase_url", models.URLField(blank=True, max_length=2048)),
                ("last_idempotency_key", models.CharField(blank=True, max_length=128)),
                ("last_request_hash", models.CharField(blank=True, max_length=64)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name="quotacard",
            name="redeemed_ip_digest",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="quotacard",
            name="revoke_idempotency_key",
            field=models.CharField(blank=True, max_length=128, null=True, unique=True),
        ),
        migrations.AddField(
            model_name="quotacard",
            name="revoke_request_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.RunPython(clear_legacy_quota_targets, migrations.RunPython.noop),
    ]
