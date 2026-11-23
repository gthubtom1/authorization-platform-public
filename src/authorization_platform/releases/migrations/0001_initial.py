import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('catalog', '0004_downstreamsoftware_config_version'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Release',
            fields=[
                ('release_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('version', models.CharField(max_length=64)),
                ('target', models.CharField(max_length=32)),
                ('arch', models.CharField(max_length=32)),
                ('channel', models.CharField(max_length=32)),
                ('minimum_client_version', models.CharField(blank=True, max_length=64)),
                ('notes', models.TextField(blank=True, max_length=2000)),
                ('manifest', models.JSONField(default=dict)),
                ('package_name', models.CharField(max_length=255)),
                ('package_path', models.CharField(blank=True, max_length=512)),
                ('package_size', models.PositiveBigIntegerField(default=0)),
                ('package_sha256', models.CharField(max_length=64)),
                ('signature_algorithm', models.CharField(max_length=32)),
                ('signature_key_id', models.CharField(max_length=128)),
                ('signature_status', models.CharField(choices=[('declared', '已声明'), ('verified', '已验证')], default='declared', max_length=16)),
                ('status', models.CharField(choices=[('draft', '草稿'), ('published', '已发布'), ('withdrawn', '已撤回')], db_index=True, default='draft', max_length=16)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('published_at', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('withdrawn_at', models.DateTimeField(blank=True, null=True)),
                ('withdrawal_reason', models.CharField(blank=True, max_length=255)),
                ('package_deleted_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_releases', to=settings.AUTH_USER_MODEL)),
                ('previous_release', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='superseded_releases', to='releases.release')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='releases', to='catalog.softwareprofile')),
                ('software', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='releases', to='catalog.software')),
            ],
            options={
                'ordering': ('-created_at', '-release_id'),
            },
        ),
        migrations.CreateModel(
            name='ReleaseOperation',
            fields=[
                ('operation_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action', models.CharField(choices=[('upload', '上传'), ('publish', '发布'), ('withdraw', '撤回')], max_length=16)),
                ('idempotency_key', models.CharField(max_length=128)),
                ('request_hash', models.CharField(max_length=64)),
                ('response', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='release_operations', to=settings.AUTH_USER_MODEL)),
                ('release', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='operations', to='releases.release')),
            ],
            options={
                'ordering': ('-created_at', '-operation_id'),
            },
        ),
        migrations.AddIndex(
            model_name='release',
            index=models.Index(fields=['software', 'profile', 'channel', 'status', 'published_at'], name='releases_re_softwar_2f5af7_idx'),
        ),
        migrations.AddIndex(
            model_name='release',
            index=models.Index(fields=['status', 'withdrawn_at'], name='releases_re_status_5af857_idx'),
        ),
        migrations.AddConstraint(
            model_name='release',
            constraint=models.UniqueConstraint(fields=('software', 'profile', 'version', 'target', 'arch', 'channel'), name='releases_identity_version_unique'),
        ),
        migrations.AddConstraint(
            model_name='release',
            constraint=models.CheckConstraint(condition=models.Q(('package_size__gte', 0)), name='releases_package_size_nonnegative'),
        ),
        migrations.AddIndex(
            model_name='releaseoperation',
            index=models.Index(fields=['release', 'action', 'created_at'], name='releases_re_release_10969e_idx'),
        ),
        migrations.AddConstraint(
            model_name='releaseoperation',
            constraint=models.UniqueConstraint(fields=('actor', 'action', 'idempotency_key'), name='releases_actor_action_idempotency_unique'),
        ),
    ]
