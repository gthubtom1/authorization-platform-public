import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('catalog', '0007_downstreamsoftwareoperation_planrevisionoperation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PolicyRevisionOperation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('idempotency_key', models.CharField(max_length=128)),
                ('request_hash', models.CharField(max_length=64)),
                ('response_status', models.PositiveSmallIntegerField(default=200)),
                ('response_payload', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='catalog_policy_revision_operations', to=settings.AUTH_USER_MODEL)),
                ('policy', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='revision_operations', to='catalog.policyversion')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='policy_revision_operations', to='catalog.softwareprofile')),
            ],
            options={
                'ordering': ('-created_at', 'id'),
                'indexes': [models.Index(fields=['profile', 'created_at'], name='catalog_pol_profile_1c1d95_idx')],
                'constraints': [models.UniqueConstraint(fields=('actor', 'profile', 'idempotency_key'), name='catalog_policy_revision_actor_profile_key_unique')],
            },
        ),
    ]
