import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='StorageCleanupState',
            fields=[
                ('key', models.CharField(max_length=32, primary_key=True, serialize=False)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='StorageCleanupOperation',
            fields=[
                ('operation_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('idempotency_key', models.CharField(max_length=128)),
                ('request_hash', models.CharField(max_length=64)),
                ('response', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='storage_cleanup_operations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created_at', '-operation_id'),
                'constraints': [models.UniqueConstraint(fields=('actor', 'idempotency_key'), name='storage_cleanup_actor_idempotency_unique')],
            },
        ),
    ]
