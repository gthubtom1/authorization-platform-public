from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("licensing", "0012_launchticket")]

    operations = [
        # Legacy timestamps may tie and random UUIDs cannot recover chronology.
        # Preserve every original timestamp/key/state and explicitly leave zero.
        migrations.AddField(
            model_name="devicebinding", name="binding_order",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AlterModelOptions(
            name="devicebinding",
            options={"ordering": ("-binding_order", "-bound_at", "binding_id")},
        ),
        migrations.AddConstraint(
            model_name="devicebinding",
            constraint=models.UniqueConstraint(
                fields=("authorization", "binding_order"),
                condition=models.Q(binding_order__gt=0),
                name="licensing_binding_order_unique",
            ),
        ),
    ]
