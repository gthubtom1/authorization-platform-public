import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('licensing', '0008_licensecard_archived_from_status'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthorizationDeviceOperation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('downstream_public_id', models.UUIDField(db_index=True)),
                ('action', models.CharField(max_length=32)),
                ('authorization_id', models.UUIDField(db_index=True)),
                ('device_id', models.UUIDField(db_index=True)),
                ('idempotency_key', models.CharField(max_length=128)),
                ('request_hash', models.CharField(max_length=64)),
                ('response_payload', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='authorization_device_operations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created_at', 'id'),
                'indexes': [models.Index(fields=['downstream_public_id', 'created_at'], name='licensing_a_downstr_9e8573_idx'), models.Index(fields=['authorization_id', 'device_id'], name='licensing_a_authori_d9ef04_idx')],
                'constraints': [models.UniqueConstraint(fields=('actor', 'idempotency_key'), name='licensing_device_operation_actor_key_unique')],
            },
        ),
    ]
