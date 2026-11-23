"""Final suite regressions; isolated data only, no configured VPS or credentials."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import OperationalError
from django.test import TestCase, TransactionTestCase, SimpleTestCase, override_settings
from django.urls import resolve, reverse

from authorization_platform.audit.models import AuditEvent
from authorization_platform.backup_control.models import BackupPolicy, BackupControlOperation
from authorization_platform.catalog.services import create_software, create_profile
from authorization_platform.credits.models import QuotaLedgerEntry
from authorization_platform.credits.services import credit_quota
from authorization_platform.accounts.services import create_downstream_direct

ROOT = Path(settings.BASE_DIR)


class PublicUpdateCloseoutTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser('suite-update', password='Fixture-password-123')
        create_software(actor=self.admin, software_id='suite.tool', name='Suite', status='active')
        create_profile(actor=self.admin, software_id='suite.tool', profile_id='stable.v2', client_id='suite-client', target='windows', arch='x64', channel='stable', status='active')
        self.query = dict(client_id='suite-client', target='windows', arch='x64', channel='stable', version='1.0.0')
        self.url = '/api/v1/public/software/suite.tool/profiles/stable.v2/releases/'

    def test_dotted_public_identity_reaches_registry_and_download_handler(self):
        response = self.client.get(self.url, self.query)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['profile_id'], 'stable.v2')
        self.assertEqual(resolve(self.url + str(uuid.uuid4()) + '/download/').view_name, 'releases:public_download')

    def test_bad_and_unbounded_current_version_are_structured_400(self):
        for version in (None, '', ' ', 'garbage', '1.2', '1.2.3-beta', '9'*5000+'.0.0'):
            with self.subTest(version=str(version)[:20]):
                query = dict(self.query)
                if version is None: query.pop('version')
                else: query['version'] = version
                response = self.client.get(self.url, query)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['error']['code'], 'INVALID_VERSION')


class ImmutableCloseoutTests(TestCase):
    def test_conflict_bulk_create_cannot_rewrite_audit_or_ledger(self):
        admin = get_user_model().objects.create_superuser('suite-immutable', password='Fixture-password-123')
        downstream = create_downstream_direct(actor=admin, username='suite-downstream', password='Fixture-password-123')
        credit_quota(actor=admin, downstream=downstream, amount=10, reason='fixture', idempotency_key='suite-credit')
        event = AuditEvent.objects.first()
        ledger = QuotaLedgerEntry.objects.first()
        for model, instance, field, value in ((AuditEvent,event,'action','rewritten'), (QuotaLedgerEntry,ledger,'amount',999)):
            with self.subTest(model=model.__name__):
                original = getattr(instance,field)
                setattr(instance,field,value)
                with self.assertRaises(ValueError):
                    model.objects.bulk_create([instance], update_conflicts=True, update_fields=[field], unique_fields=[instance._meta.pk.name])
                instance.refresh_from_db()
                self.assertEqual(getattr(instance,field),original)


class BackupDeleteCloseoutTests(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.admin = get_user_model().objects.create_superuser('suite-backup', password='Fixture-password-123')
        self.client.force_login(self.admin)
        BackupPolicy.objects.create(key='default', github_retention_count=1)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.override = override_settings(BACKUP_DOWNLOAD_DIR=self.root)
        self.override.enable(); self.addCleanup(self.override.disable)
        (self.root/'first.enc').write_bytes(b'original-first')
        (self.root/'reserve.enc').write_bytes(b'reserve')

    def post(self, name='first.enc', key='suite-delete'):
        return self.client.post(reverse('backup_control:api_delete_download',args=[name]), json.dumps({'confirmed':True}), content_type='application/json', HTTP_IDEMPOTENCY_KEY=key)

    def test_audit_or_operation_database_failure_keeps_recoverable_original(self):
        for failing in ('record_event','store_operation'):
            with self.subTest(failing=failing):
                with patch('authorization_platform.backup_control.views.'+failing,side_effect=OperationalError('injected failure')):
                    response = self.post()
                self.assertEqual(response.status_code,503)
                self.assertEqual((self.root/'first.enc').read_bytes(),b'original-first')
                self.assertEqual(BackupControlOperation.objects.filter(action='download.delete').count(),0)
                self.assertEqual(AuditEvent.objects.filter(action='backup.download.delete',outcome='success').count(),0)
        result = self.post()
        self.assertEqual(result.status_code,200)
        self.assertEqual(self.post().json(),result.json())
        self.assertFalse((self.root/'first.enc').exists())
        self.assertEqual(AuditEvent.objects.filter(action='backup.download.delete',outcome='success').count(),1)

    def test_unknown_missing_file_remains_404(self):
        self.assertEqual(self.post('missing.enc').status_code,404)
        self.assertFalse(BackupControlOperation.objects.exists())

    def _interrupted_delete(self, *, committed=False, before_rename=False):
        from authorization_platform.backup_control import download_deletion as deletion, services, views
        request_hash=views._request_hash({'name':'first.enc','confirmed':True})
        # Suppress only process-exit cleanup to preserve the real on-disk state
        # that a killed process leaves; the next request uses real recovery.
        with patch.object(deletion,'recover_pending',return_value=None):
            with deletion.recoverable_delete(actor=self.admin,key='suite-delete',request_hash=request_hash):
                if before_rename:
                    with patch.object(Path,'rename',side_effect=SystemExit('power loss')), self.assertRaises(SystemExit):
                        services.delete_encrypted_download(name='first.enc',confirmed=True)
                    return None
                result=services.delete_encrypted_download(name='first.enc',confirmed=True)
                if committed:
                    from authorization_platform.audit.services import record_event
                    record_event(actor=self.admin,action='backup.download.delete',outcome='success',object_type='BackupArtifact',object_public_id='first.enc')
                    services.store_operation(actor=self.admin,action='download.delete',key='suite-delete',request_hash=request_hash,response=result)
                return result

    def test_restart_recovers_journal_before_rename(self):
        self._interrupted_delete(before_rename=True)
        self.assertTrue(list(self.root.glob('.delete-*.json')))
        self.assertEqual(self.post().status_code,200)
        self.assertFalse(list(self.root.glob('.delete-*.json')))

    def test_restart_restores_uncommitted_quarantine_then_completes_original_key(self):
        self._interrupted_delete()
        self.assertFalse((self.root/'first.enc').exists())
        self.assertTrue(list(self.root.glob('.delete-*.payload')))
        self.assertEqual(self.post().status_code,200)
        self.assertFalse(list(self.root.glob('.delete-*.*')))
        self.assertEqual(AuditEvent.objects.filter(action='backup.download.delete',outcome='success').count(),1)

    def test_restart_cleans_committed_quarantine_without_deleting_new_same_named_file(self):
        original=self._interrupted_delete(committed=True)
        (self.root/'first.enc').write_bytes(b'a later backup with the same name')
        response=self.post()
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json(),original)
        self.assertEqual((self.root/'first.enc').read_bytes(),b'a later backup with the same name')
        self.assertFalse(list(self.root.glob('.delete-*.*')))
        self.assertEqual(AuditEvent.objects.filter(action='backup.download.delete',outcome='success').count(),1)

    def test_uppercase_backup_extension_deletes_and_replays_normally(self):
        (self.root/'UPPER.ENC').write_bytes(b'uppercase backup')
        result=self.post('UPPER.ENC')
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()['deleted'],'UPPER.ENC')
        self.assertEqual(self.post('UPPER.ENC').json(),result.json())
        self.assertFalse(list(self.root.glob('.delete-*.*')))

    def test_restart_after_restore_link_before_quarantine_unlink_can_continue(self):
        self._interrupted_delete()
        payload=next(self.root.glob('.delete-*.payload'))
        os.link(payload,self.root/'first.enc')
        self.assertTrue(os.path.samefile(payload,self.root/'first.enc'))
        self.assertEqual(self.post().status_code,200)
        self.assertFalse(list(self.root.glob('.delete-*.*')))
        self.assertEqual(AuditEvent.objects.filter(action='backup.download.delete',outcome='success').count(),1)

    def test_uncommitted_new_same_named_identical_bytes_is_not_a_restore_link(self):
        self._interrupted_delete()
        payload=next(self.root.glob('.delete-*.payload'))
        (self.root/'first.enc').write_bytes(b'original-first')
        self.assertFalse(os.path.samefile(payload,self.root/'first.enc'))
        self.assertEqual(self.post().status_code,503)
        self.assertEqual(payload.read_bytes(),b'original-first')
        self.assertEqual((self.root/'first.enc').read_bytes(),b'original-first')


class InstallerTargetCloseoutTests(SimpleTestCase):
    def test_missing_domain_refuses_before_host_actions(self):
        bash = shutil.which('bash')
        self.assertIsNotNone(bash, 'Bash must be on PATH')
        source = (ROOT/'deploy/install-site.sh').read_text(encoding='utf-8')
        prefix = source.split('validate_install_config() {',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory); (tree/'deploy/backup').mkdir(parents=True); (tree/'manage.py').touch()
            # id is the sole root precheck; the rest must reject before installation.
            code = 'id(){ echo 0; }; unset AUTH_DOMAIN; INSTALL_ROOT="$PWD"; '+prefix
            result = subprocess.run([bash,'-c',code],cwd=tree,text=True,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('AUTH_DOMAIN',result.stderr)
