from django.db import migrations, models


def _compact_device_code(installation_id):
    import hashlib
    import re

    value = str(installation_id or "").strip()
    if not value:
        return None
    if re.fullmatch(r"^GS-(?:[A-F0-9]{4}-){3,4}[A-F0-9]{4}$", value, re.IGNORECASE):
        return value.upper()
    if re.fullmatch(r"^[0-9A-Fa-f]{64}$", value):
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest().upper()[:20]
        return "GS-" + "-".join(digest[index : index + 4] for index in range(0, 20, 4))
    return value


def backfill_device_codes(apps, schema_editor):
    Device = apps.get_model("licensing", "Device")
    for device in Device.objects.exclude(installation_id__isnull=True).exclude(installation_id="").iterator():
        device.device_code = _compact_device_code(device.installation_id)
        device.save(update_fields=["device_code"])


def clear_device_codes(apps, schema_editor):
    Device = apps.get_model("licensing", "Device")
    for device in Device.objects.exclude(device_code__isnull=True).iterator():
        device.device_code = None
        device.save(update_fields=["device_code"])


class Migration(migrations.Migration):

    dependencies = [
        ("licensing", "0013_devicebinding_binding_order"),
    ]

    operations = [
        migrations.AddField(
            model_name="device",
            name="device_code",
            field=models.CharField(blank=True, db_index=True, max_length=128, null=True),
        ),
        migrations.RunPython(backfill_device_codes, clear_device_codes),
    ]
