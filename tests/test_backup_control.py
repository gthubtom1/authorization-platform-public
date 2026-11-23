from __future__ import annotations

import inspect
import json
import subprocess
import tempfile
import uuid
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.models import DownstreamTombstone
from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.backup_control.models import BackupPolicy, BackupRunRequest
from authorization_platform.catalog.models import ProfileStatus
from authorization_platform.credits.models import (
    QuotaAccount,
    QuotaLedgerDirection,
    QuotaLedgerEntry,
    QuotaLedgerOperation,
)
from authorization_platform.licensing.models import Device
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from authorization_platform.backup_control.services import (
    OPENSSL_MAGIC,
    BackupControlError,
    _apply_postgres_restore,
    _openssl_key_iv,
    decide_backup_run,
    download_path,
    enqueue_change_backup,
    get_policy,
    list_downloads,
    openssl_decrypt_aes256_cbc,
    openssl_encrypt_aes256_cbc,
    request_backup_run,
    runner_export,
    schedule_due_backups,
    site_restore_status,
    update_policy,
    upload_encrypted_backup,
    write_github_token_file,
    finish_backup_run,
    mark_schedule_stamp,
)


User = get_user_model()


class BackupDownloadTests(SimpleTestCase):
    def test_lists_only_encrypted_regular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "new.dump.enc").write_bytes(b"encrypted")
            (root / "notes.txt").write_text("no", encoding="utf-8")
            with override_settings(BACKUP_DOWNLOAD_DIR=root):
                rows = list_downloads()
            self.assertEqual([row["name"] for row in rows], ["new.dump.enc"])
            self.assertEqual(rows[0]["size"], 9)

    def test_rejects_path_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.enc").write_bytes(b"x")
            with override_settings(BACKUP_DOWNLOAD_DIR=root):
                with self.assertRaises(ValueError):
                    download_path("../safe.enc")
                self.assertEqual(download_path("safe.enc").name, "safe.enc")


class BackupControlApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(username="backup-admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="backup-downstream",
            password="Downstream-password-123",
        )
        self.url = reverse("backup_control:api_dashboard")
        self.run_url = reverse("backup_control:api_backup_run")

    def _admin_client(self) -> Client:
        client = Client()
        client.force_login(self.admin)
        return client

    def _headers(self, key: str) -> dict[str, str]:
        return {"HTTP_IDEMPOTENCY_KEY": key, "HTTP_X_REQUEST_ID": f"backup-{key}"}

    def test_anonymous_and_downstream_cannot_read_backup_center(self):
        self.assertEqual(self.client.get(self.url).status_code, 401)
        downstream = Client()
        login = downstream.post(
            reverse("accounts:downstream_login"),
            {"username": "backup-downstream", "password": "Downstream-password-123"},
        )
        self.assertEqual(login.status_code, 302)
        forbidden = downstream.get(self.url)
        self.assertEqual(forbidden.status_code, 403)

    def test_admin_can_save_schedule_and_secrets_are_not_returned(self):
        client = self._admin_client()
        saved = client.post(
            self.url,
            data=json.dumps(
                {
                    "enabled": True,
                    "schedule_enabled": True,
                    "github_enabled": True,
                    "github_repository": "owner/backup-repo",
                    "github_token": "ghp_test-token-value",
                    "full_time": "03:45",
                    "diff_interval_hours": 4,
                }
            ),
            content_type="application/json",
            **self._headers("backup-save-1"),
        )
        self.assertEqual(saved.status_code, 200, saved.content)
        payload = saved.json()
        policy = payload["policy"]
        self.assertEqual(policy["schedule"]["full_time"], "03:45")
        self.assertEqual(policy["schedule"]["timezone"], "Asia/Shanghai")
        self.assertEqual(policy["schedule"]["diff_interval_hours"], 4)
        self.assertTrue(policy["github_token_configured"])
        self.assertEqual(policy["github_repository"], "owner/backup-repo")
        self.assertNotIn("telegram_enabled", policy)
        self.assertNotIn("telegram_chat_id", policy)
        self.assertNotIn("telegram_token_configured", policy)
        self.assertNotIn("netdisk_preset", policy)
        self.assertNotIn("s3_enabled", policy)
        self.assertNotIn("webdav_enabled", policy)
        self.assertNotIn("webdav_password_configured", policy)
        self.assertNotIn("s3_secret_configured", policy)
        self.assertTrue(policy["enabled"])
        self.assertTrue(policy["schedule_enabled"])
        blob = json.dumps(payload)
        self.assertNotIn("webdav-secret-value", blob)
        self.assertNotIn("secret-token-value", blob)
        self.assertNotIn("ghp_test-token-value", blob)
        stored = BackupPolicy.objects.get(key="default")
        self.assertFalse(hasattr(stored, "webdav_password_ciphertext"))
        self.assertFalse(hasattr(stored, "s3_secret_ciphertext"))
        self.assertFalse(hasattr(stored, "telegram_enabled"))
        self.assertFalse(hasattr(stored, "telegram_chat_id"))
        self.assertFalse(hasattr(stored, "telegram_token_ciphertext"))

    def test_github_enabled_requires_repository_and_token(self):
        client = self._admin_client()
        response = client.post(
            self.url,
            data=json.dumps({"github_enabled": True}),
            content_type="application/json",
            **self._headers("backup-github-required-1"),
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_POLICY")

    def test_omitting_secret_keeps_previous_secret(self):
        client = self._admin_client()
        first = client.post(
            self.url,
            data=json.dumps(
                {
                    "github_enabled": True,
                    "github_repository": "owner/backup-repo",
                    "github_token": "ghp_first-secret",
                }
            ),
            content_type="application/json",
            **self._headers("backup-github-secret-1"),
        )
        self.assertEqual(first.status_code, 200, first.content)
        second = client.post(
            self.url,
            data=json.dumps(
                {
                    "github_enabled": True,
                    "github_repository": "owner/backup-repo",
                    "full_time": "01:10",
                }
            ),
            content_type="application/json",
            **self._headers("backup-github-secret-2"),
        )
        self.assertEqual(second.status_code, 200, second.content)
        self.assertTrue(second.json()["policy"]["github_token_configured"])
        self.assertEqual(second.json()["policy"]["schedule"]["full_time"], "01:10")

    def test_removed_netdisk_fields_are_rejected(self):
        client = self._admin_client()
        for payload in (
            {
                "netdisk_preset": "webdav_custom",
                "webdav_endpoint": "http://files.internal/dav",
                "webdav_username": "owner",
                "webdav_password": "secret",
            },
            {
                "netdisk_preset": "s3_r2",
                "s3_endpoint": "https://<accountid>.r2.cloudflarestorage.com",
                "s3_bucket": "backups",
                "s3_access_key_id": "AKIAEXAMPLE",
                "s3_secret": "secret-value",
            },
        ):
            with self.subTest(preset=payload["netdisk_preset"]):
                response = client.post(
                    self.url,
                    data=json.dumps(payload),
                    content_type="application/json",
                    **self._headers(f"backup-netdisk-rejected-{payload['netdisk_preset']}"),
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "INVALID_POLICY")

    def test_omitting_retention_keeps_previous_download_floor(self):
        client = self._admin_client()
        BackupPolicy.objects.update_or_create(key="default", defaults={"github_retention_count": 7})
        response = client.post(
            self.url,
            data=json.dumps({"enabled": True, "schedule_enabled": True, "full_time": "03:45", "diff_interval_hours": 4}),
            content_type="application/json",
            **self._headers("backup-retention-omitted-1"),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["policy"]["github_retention_count"], 7)
        self.assertEqual(BackupPolicy.objects.get(key="default").github_retention_count, 7)

    def test_same_idempotency_key_replays_and_conflict_is_rejected(self):
        client = self._admin_client()
        first = client.post(
            self.url,
            data=json.dumps({"full_time": "04:00"}),
            content_type="application/json",
            **self._headers("backup-idem-1"),
        )
        self.assertEqual(first.status_code, 200)
        replay = client.post(
            self.url,
            data=json.dumps({"full_time": "04:00"}),
            content_type="application/json",
            **self._headers("backup-idem-1"),
        )
        self.assertEqual(replay.status_code, 200)
        conflict = client.post(
            self.url,
            data=json.dumps({"full_time": "05:00"}),
            content_type="application/json",
            **self._headers("backup-idem-1"),
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(BackupPolicy.objects.get(key="default").schedule_full_hour, 4)

    def test_manual_run_is_queued_without_executing_host_backup(self):
        update_policy(actor=self.admin, values={"enabled": True})
        client = self._admin_client()
        response = client.post(
            self.run_url,
            data=json.dumps({"backup_type": "full"}),
            content_type="application/json",
            **self._headers("backup-run-1"),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(BackupRunRequest.objects.count(), 1)
        run = BackupRunRequest.objects.get()
        self.assertEqual(run.status, BackupRunRequest.Status.PENDING)
        self.assertEqual(run.backup_type, BackupRunRequest.BackupType.FULL)
        self.assertTrue(AuditEvent.objects.filter(action="backup.run.request", outcome="success").exists())
        repeated = client.post(
            self.run_url,
            data=json.dumps({"backup_type": "full"}),
            content_type="application/json",
            **self._headers("backup-run-1"),
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(BackupRunRequest.objects.count(), 1)
        blocked = client.post(
            self.run_url,
            data=json.dumps({"backup_type": "diff"}),
            content_type="application/json",
            **self._headers("backup-run-2"),
        )
        self.assertEqual(blocked.status_code, 409)

    def test_manual_run_requires_master_switch(self):
        client = self._admin_client()
        update_policy(actor=self.admin, values={"enabled": False})
        response = client.post(
            self.run_url,
            data=json.dumps({"backup_type": "full"}),
            content_type="application/json",
            **self._headers("backup-run-off-1"),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "BACKUP_DISABLED")
        self.assertEqual(BackupRunRequest.objects.count(), 0)

    def test_api_download_only_serves_encrypted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ok.dump.enc").write_bytes(b"ciphertext")
            (root / "notes.txt").write_text("no", encoding="utf-8")
            with override_settings(BACKUP_DOWNLOAD_DIR=root):
                client = self._admin_client()
                listing = client.get(self.url)
                self.assertEqual(listing.status_code, 200)
                names = [item["name"] for item in listing.json()["downloads"]]
                self.assertEqual(names, ["ok.dump.enc"])
                download = client.get(reverse("backup_control:api_download", args=["ok.dump.enc"]))
                self.assertEqual(download.status_code, 200)
                self.assertEqual(b"".join(download.streaming_content), b"ciphertext")
                missing = client.get(reverse("backup_control:api_download", args=["notes.txt"]))
                self.assertEqual(missing.status_code, 400)

    def test_api_delete_download_keeps_retention_floor_and_audits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(8):
                (root / f"keep-{index}.dump.enc").write_bytes(b"ciphertext-" + bytes([index]))
            BackupPolicy.objects.update_or_create(key="default", defaults={"github_retention_count": 7})
            with override_settings(BACKUP_DOWNLOAD_DIR=root):
                client = self._admin_client()
                delete_url = reverse("backup_control:api_delete_download", args=["keep-0.dump.enc"])
                first = client.post(
                    delete_url,
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                    **self._headers("backup-delete-1"),
                )
                self.assertEqual(first.status_code, 200)
                self.assertEqual(first.json()["remaining_count"], 7)
                self.assertFalse((root / "keep-0.dump.enc").exists())
                replay = client.post(
                    delete_url,
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                    **self._headers("backup-delete-1"),
                )
                self.assertEqual(replay.status_code, 200)
                self.assertEqual(replay.json()["remaining_count"], 7)
                blocked = client.post(
                    reverse("backup_control:api_delete_download", args=["keep-1.dump.enc"]),
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                    **self._headers("backup-delete-2"),
                )
                self.assertEqual(blocked.status_code, 409)
                self.assertEqual(blocked.json()["error"]["code"], "BACKUP_RETENTION_FLOOR")
                self.assertTrue((root / "keep-1.dump.enc").exists())
                unconfirmed = client.post(
                    reverse("backup_control:api_delete_download", args=["keep-1.dump.enc"]),
                    data=json.dumps({}),
                    content_type="application/json",
                    **self._headers("backup-delete-3"),
                )
                self.assertEqual(unconfirmed.status_code, 400)
                missing_key = client.post(
                    reverse("backup_control:api_delete_download", args=["keep-1.dump.enc"]),
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                )
                self.assertEqual(missing_key.status_code, 400)
                notes = client.post(
                    reverse("backup_control:api_delete_download", args=["notes.txt"]),
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                    **self._headers("backup-delete-txt"),
                )
                self.assertEqual(notes.status_code, 400)
                downstream = Client()
                login = downstream.post(
                    reverse("accounts:downstream_login"),
                    {"username": "backup-downstream", "password": "Downstream-password-123"},
                )
                self.assertEqual(login.status_code, 302)
                forbidden = downstream.post(
                    reverse("backup_control:api_delete_download", args=["keep-1.dump.enc"]),
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                    **self._headers("backup-delete-down"),
                )
                self.assertEqual(forbidden.status_code, 403)
                self.assertTrue(
                    AuditEvent.objects.filter(action="backup.download.delete", outcome="success").exists()
                )
                self.assertTrue(
                    AuditEvent.objects.filter(action="backup.download.delete", outcome="failure").exists()
                )
                only = root / "last.dump.enc"
                only.write_bytes(b"only")
                BackupPolicy.objects.filter(key="default").update(github_retention_count=1)
                for leftover in root.glob("keep-*.dump.enc"):
                    leftover.unlink()
                last = client.post(
                    reverse("backup_control:api_delete_download", args=["last.dump.enc"]),
                    data=json.dumps({"confirmed": True}),
                    content_type="application/json",
                    **self._headers("backup-delete-last"),
                )
                self.assertEqual(last.status_code, 409)
                self.assertTrue(only.exists())

    def test_runner_export_omits_secrets(self):
        update_policy(
            actor=self.admin,
            values={
                "full_time": "02:30",
                "github_enabled": True,
                "github_repository": "test/repo",
                "github_token": "ghp_secret_token",
            },
        )
        exported = json.dumps(runner_export())
        self.assertIn("02:30", exported)
        self.assertIn('"schedule_enabled": false', exported)
        self.assertNotIn("ghp_secret_token", exported)
        self.assertNotIn("telegram_enabled", exported)
        self.assertIn('"secret_values_exposed": false', exported)


class BackupRestoreApiTests(TestCase):
    def setUp(self):
        from django.core.cache import cache

        cache.clear()
        self.admin = User.objects.create_superuser(username="restore-admin", password="Admin-password-123")
        self.inspect_url = reverse("backup_control:api_restore_inspect")
        self.apply_url = reverse("backup_control:api_restore_apply")
        self.dashboard_url = reverse("backup_control:api_dashboard")

    def _admin_client(self) -> Client:
        client = Client()
        client.force_login(self.admin)
        return client

    def _headers(self, key: str) -> dict[str, str]:
        return {"HTTP_IDEMPOTENCY_KEY": key, "HTTP_X_REQUEST_ID": f"restore-{key}"}

    def _encrypted_upload(self, *, name="authorization-platform-enc-20260904-090000.dump.enc", passphrase="restore-pass-phrase"):
        from django.core.files.uploadedfile import SimpleUploadedFile

        from authorization_platform.backup_control.services import openssl_encrypt_aes256_cbc

        blob = openssl_encrypt_aes256_cbc(b"PGDMP\x01fake-test-dump", passphrase)
        return SimpleUploadedFile(name, blob, content_type="application/octet-stream"), passphrase

    def test_github_url_is_normalized_and_token_can_be_changed(self):
        client = self._admin_client()
        saved = client.post(
            self.dashboard_url,
            data=json.dumps(
                {
                    "github_enabled": True,
                    "github_repository": "https://github.com/owner/new-backup-repo.git",
                    "github_token": "first-github-token",
                }
            ),
            content_type="application/json",
            **self._headers("github-save-1"),
        )
        self.assertEqual(saved.status_code, 200, saved.content)
        self.assertEqual(saved.json()["policy"]["github_repository"], "owner/new-backup-repo")
        kept = client.post(
            self.dashboard_url,
            data=json.dumps(
                {
                    "github_enabled": True,
                    "github_repository": "owner/new-backup-repo",
                    "full_time": "02:10",
                }
            ),
            content_type="application/json",
            **self._headers("github-save-2"),
        )
        self.assertEqual(kept.status_code, 200, kept.content)
        self.assertTrue(kept.json()["policy"]["github_token_configured"])
        exported = json.dumps(runner_export())
        self.assertIn("owner/new-backup-repo", exported)
        self.assertNotIn("first-github-token", exported)

    def test_github_can_be_turned_off_without_repository(self):
        client = self._admin_client()
        response = client.post(
            self.dashboard_url,
            data=json.dumps({"github_enabled": False, "full_time": "04:20"}),
            content_type="application/json",
            **self._headers("github-off-1"),
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.json()["policy"]["github_enabled"])

    def test_anonymous_cannot_inspect_restore(self):
        upload, passphrase = self._encrypted_upload()
        response = self.client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
        self.assertEqual(response.status_code, 401)

    def test_inspect_returns_beijing_time_on_empty_site(self):
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                response = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(response.status_code, 200, response.content)
                payload = response.json()
                self.assertTrue(payload["site_empty"])
                self.assertFalse(payload["can_restore"])
                self.assertIn("PostgreSQL", payload["message"])
                self.assertEqual(payload["backup_time_beijing"], "2026-09-04 17:00:00")
                self.assertTrue(payload["staging_id"])
                listing = client.get(self.dashboard_url)
                self.assertTrue(listing.json()["restore"]["site_empty"])

    def test_inspect_shows_time_but_refuses_when_site_has_downstream(self):
        create_downstream_direct(
            actor=self.admin,
            username="restore-downstream",
            password="Downstream-password-123",
        )
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                response = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(response.status_code, 200, response.content)
                payload = response.json()
                self.assertFalse(payload["site_empty"])
                self.assertFalse(payload["can_restore"])
                self.assertEqual(payload["backup_time_beijing"], "2026-09-04 17:00:00")
                self.assertEqual(payload.get("staging_id"), "")
                self.assertEqual(payload["message"], "文件和口令对，但当前有业务数据，不能导入。")

    def test_tombstone_only_site_is_not_empty(self):
        DownstreamTombstone.objects.create(public_id=uuid.uuid4(), username_digest="a" * 64)
        status = site_restore_status()
        self.assertFalse(status["site_empty"])
        self.assertGreater(status["blocking_counts"]["accounts.DownstreamTombstone"], 0)
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                response = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(response.status_code, 200, response.content)
                payload = response.json()
                self.assertFalse(payload["site_empty"])
                self.assertFalse(payload["can_restore"])
                self.assertEqual(payload["message"], "文件和口令对，但当前有业务数据，不能导入。")
                self.assertEqual(payload.get("staging_id"), "")

    def test_quota_account_or_ledger_only_site_is_not_empty(self):
        account = QuotaAccount.objects.create(downstream_public_id=uuid.uuid4(), available_balance=0)
        status = site_restore_status()
        self.assertFalse(status["site_empty"])
        self.assertGreater(status["blocking_counts"]["credits.QuotaAccount"], 0)
        QuotaLedgerEntry.objects.create(
            account=account,
            downstream_public_id=account.downstream_public_id,
            direction=QuotaLedgerDirection.CREDIT,
            amount=1,
            operation_type=QuotaLedgerOperation.MANUAL_CREDIT,
            source_type="round4-empty-site",
            idempotency_key="round4-ledger-only",
            request_hash="b" * 64,
            balance_before=0,
            balance_after=1,
        )
        status = site_restore_status()
        self.assertFalse(status["site_empty"])
        self.assertGreater(status["blocking_counts"]["credits.QuotaLedgerEntry"], 0)

    def test_audit_and_admin_rows_stay_ignored_by_design(self):
        """The documented rule (F-023) is that administrator accounts, audit
        rows and backup bookkeeping do not make a site "non-empty"; everything
        else must block the import."""

        from authorization_platform.backup_control.services import RESTORE_IGNORED_MODELS

        self.assertIn("audit.AuditEvent", RESTORE_IGNORED_MODELS)
        self.assertIn("auth.User", RESTORE_IGNORED_MODELS)
        self.assertIn("backup_control.BackupRunRequest", RESTORE_IGNORED_MODELS)

    def test_device_only_site_is_not_empty(self):
        from authorization_platform.catalog.models import Software, SoftwareProfile

        software = Software.objects.create(software_id="restore-guard", name="恢复守卫")
        profile = SoftwareProfile.objects.create(
            software=software,
            profile_id="stable",
            client_id="restore-guard-windows",
            status=ProfileStatus.ACTIVE,
        )
        Device.objects.create(
            software=software,
            profile=profile,
            installation_hash="d" * 64,
            installation_id="install-restore-guard",
        )
        status = site_restore_status()
        self.assertFalse(status["site_empty"])
        self.assertGreater(status["blocking_counts"]["licensing.Device"], 0)

    def test_restore_guard_covers_every_application_model(self):
        """The guard must be model-driven so a new model cannot silently escape."""

        from django.apps import apps

        from authorization_platform.backup_control.services import (
            RESTORE_IGNORED_APP_LABELS,
            RESTORE_IGNORED_MODELS,
        )

        guarded = {
            f"{model._meta.app_label}.{model.__name__}"
            for model in apps.get_models()
            if model._meta.app_label not in RESTORE_IGNORED_APP_LABELS
        }
        self.assertTrue(guarded)
        # The ignored set is exactly the documented non-business set.
        self.assertEqual(guarded & RESTORE_IGNORED_MODELS, set(RESTORE_IGNORED_MODELS) - {"admin.LogEntry", "auth.Group", "auth.Permission", "auth.User", "contenttypes.ContentType", "sessions.Session"})
        for label in (
            "licensing.LicenseCard",
            "licensing.LicenseInstance",
            "licensing.Device",
            "licensing.DeviceBinding",
            "licensing.LicenseCardBatch",
            "releases.Release",
            "accounts.InvitationBatch",
            "storage_cleanup.StorageCleanupState",
        ):
            self.assertNotIn(label, RESTORE_IGNORED_MODELS)

    def test_admin_user_and_inspect_audit_do_not_count_as_business_data(self):
        status = site_restore_status()
        self.assertTrue(status["site_empty"])
        self.assertGreater(User.objects.filter(is_superuser=True).count(), 0)
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                response = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(response.status_code, 200, response.content)
                self.assertTrue(response.json()["site_empty"])
                self.assertTrue(AuditEvent.objects.filter(action="backup.restore.inspect").exists())
                listing = client.get(self.dashboard_url)
                self.assertTrue(listing.json()["restore"]["site_empty"])

    def test_restore_exclusion_lock_is_skipped_off_postgresql(self):
        """The advisory lock must key off the live connection, not the configured
        engine string; otherwise a settings override would try to open a real
        PostgreSQL connection against a SQLite test database."""

        from django.conf import settings as django_settings

        from authorization_platform.backup_control import services

        databases = {alias: {**config} for alias, config in django_settings.DATABASES.items()}
        databases["default"]["ENGINE"] = "django.db.backends.postgresql"
        body_ran = False
        with override_settings(DATABASES=databases):
            with patch.object(services.psycopg, "connect") as connect:
                with services._restore_exclusion_lock():
                    body_ran = True
        self.assertTrue(body_ran)
        # The live connection is SQLite, so no PostgreSQL connection may open.
        connect.assert_not_called()

    def _patch_lock_environment(self):
        """Force the PostgreSQL branch so the lock logic itself can be tested."""

        from authorization_platform.backup_control import services

        return (
            patch.object(services, "_live_database_vendor", return_value="postgresql"),
            patch.object(
                services.settings,
                "DATABASES",
                {"default": {"ENGINE": "django.db.backends.postgresql", "NAME": "x"}},
            ),
        )

    def test_restore_lock_uses_its_own_connection_not_the_managed_one(self):
        """pg_restore closes every managed connection, which would drop a lock
        held by the Django default connection; the lock must therefore live on
        its own connection and be released on that same connection."""

        from authorization_platform.backup_control import services

        class FakeCursor:
            def __init__(self, log):
                self.log = log

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                self.log.append(sql.strip())

            def fetchone(self):
                return (True,)

        class FakeConnection:
            def __init__(self):
                self.log = []
                self.closed = False

            def cursor(self):
                return FakeCursor(self.log)

            def close(self):
                self.closed = True

        fake = FakeConnection()
        vendor_patch, settings_patch = self._patch_lock_environment()
        entered = False
        with vendor_patch, settings_patch, patch.object(services, "psycopg") as fake_psycopg:
            fake_psycopg.connect.return_value = fake
            with services._restore_exclusion_lock():
                entered = True

        self.assertTrue(entered)
        fake_psycopg.connect.assert_called_once()
        statements = " ".join(fake.log)
        self.assertIn("pg_try_advisory_lock", statements)
        self.assertIn("pg_advisory_unlock", statements)
        self.assertTrue(fake.closed, "the lock connection must close to release the session lock")

    def test_restore_lock_refuses_when_another_restore_holds_it(self):
        """A second restore must fail closed with RESTORE_IN_PROGRESS."""

        from authorization_platform.backup_control import services

        class BusyCursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                pass

            def fetchone(self):
                return (False,)

        class BusyConnection:
            def cursor(self):
                return BusyCursor()

            def close(self):
                pass

        vendor_patch, settings_patch = self._patch_lock_environment()
        with vendor_patch, settings_patch, patch.object(services, "psycopg") as fake_psycopg:
            fake_psycopg.connect.return_value = BusyConnection()
            with self.assertRaises(BackupControlError) as caught:
                with services._restore_exclusion_lock():
                    pass
        self.assertEqual(caught.exception.code, "RESTORE_IN_PROGRESS")
        self.assertEqual(caught.exception.status, 409)

    def test_restore_lock_connection_failure_is_not_silently_skipped(self):
        """If the dedicated connection cannot be opened, the import must refuse
        rather than proceed unprotected."""

        from authorization_platform.backup_control import services

        vendor_patch, settings_patch = self._patch_lock_environment()
        with vendor_patch, settings_patch, patch.object(services, "psycopg") as fake_psycopg:
            fake_psycopg.connect.side_effect = OSError("no route to host")
            with self.assertRaises(BackupControlError) as caught:
                with services._restore_exclusion_lock():
                    pass
        self.assertEqual(caught.exception.code, "RESTORE_FAILED")

    def test_restore_lock_releases_on_body_exception(self):
        """An exception inside the guarded block must still unlock and close."""

        from authorization_platform.backup_control import services

        closed = {"value": False}
        unlocked = {"value": False}

        class FakeCursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                if "advisory_unlock" in sql:
                    unlocked["value"] = True

            def fetchone(self):
                return (True,)

        class FakeConnection:
            def cursor(self):
                return FakeCursor()

            def close(self):
                closed["value"] = True

        vendor_patch, settings_patch = self._patch_lock_environment()
        with vendor_patch, settings_patch, patch.object(services, "psycopg") as fake_psycopg:
            fake_psycopg.connect.return_value = FakeConnection()
            with self.assertRaises(RuntimeError):
                with services._restore_exclusion_lock():
                    raise RuntimeError("boom")
        self.assertTrue(unlocked["value"])
        self.assertTrue(closed["value"])

    def test_confirm_restore_rejects_when_tombstone_appears(self):
        actor = User.objects.create_superuser(username="restore-tombstone-admin", password="Admin-password-123")
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = Client()
                client.force_login(actor)
                upload, passphrase = self._encrypted_upload()
                inspected = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(inspected.status_code, 200, inspected.content)
                staging_id = inspected.json()["staging_id"]
                self.assertTrue(staging_id)
                DownstreamTombstone.objects.create(public_id=uuid.uuid4(), username_digest="c" * 64)
                confirmed = client.post(
                    self.apply_url,
                    data=json.dumps(
                        {
                            "staging_id": staging_id,
                            "passphrase": passphrase,
                            "confirmed_backup_time": "2026-09-04 17:00:00",
                        }
                    ),
                    content_type="application/json",
                    **self._headers("restore-apply-tombstone"),
                )
                self.assertEqual(confirmed.status_code, 409, confirmed.content)
                self.assertEqual(confirmed.json()["error"]["code"], "SITE_NOT_EMPTY")

    def test_confirm_requires_matching_time_and_sqlite_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                inspected = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(inspected.status_code, 200, inspected.content)
                staging_id = inspected.json()["staging_id"]
                mismatch = client.post(
                    self.apply_url,
                    data=json.dumps(
                        {
                            "staging_id": staging_id,
                            "passphrase": passphrase,
                            "confirmed_backup_time": "2020-01-01 00:00:00",
                        }
                    ),
                    content_type="application/json",
                    **self._headers("restore-apply-1"),
                )
                self.assertEqual(mismatch.status_code, 400)
                self.assertEqual(mismatch.json()["error"]["code"], "BACKUP_TIME_MISMATCH")
                confirmed = client.post(
                    self.apply_url,
                    data=json.dumps(
                        {
                            "staging_id": staging_id,
                            "passphrase": passphrase,
                            "confirmed_backup_time": "2026-09-04 17:00:00",
                        }
                    ),
                    content_type="application/json",
                    **self._headers("restore-apply-2"),
                )
                self.assertEqual(confirmed.status_code, 400, confirmed.content)
                self.assertEqual(confirmed.json()["error"]["code"], "RESTORE_REQUIRES_POSTGRESQL")
                self.assertEqual(User.objects.filter(username="restore-admin").count(), 1)

    def test_concurrent_confirm_restore_is_blocked_by_lock(self):
        from django.core.files.locks import LOCK_EX, lock, unlock

        with tempfile.TemporaryDirectory() as directory:
            staging_dir = Path(directory)
            with override_settings(BACKUP_RESTORE_STAGING_DIR=staging_dir):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                inspected = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(inspected.status_code, 200, inspected.content)
                staging_id = inspected.json()["staging_id"]

                lock_path = staging_dir / ".restore.lock"
                lock_path.touch(exist_ok=True)
                with lock_path.open("a+b") as lock_handle:
                    self.assertTrue(lock(lock_handle, LOCK_EX))
                    try:
                        confirmed = client.post(
                            self.apply_url,
                            data=json.dumps(
                                {
                                    "staging_id": staging_id,
                                    "passphrase": passphrase,
                                    "confirmed_backup_time": "2026-09-04 17:00:00",
                                }
                            ),
                            content_type="application/json",
                            **self._headers("restore-apply-concurrent"),
                        )
                        self.assertEqual(confirmed.status_code, 409, confirmed.content)
                        self.assertEqual(confirmed.json()["error"]["code"], "RESTORE_IN_PROGRESS")
                    finally:
                        unlock(lock_handle)

    def test_wrong_passphrase_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, _passphrase = self._encrypted_upload()
                response = client.post(self.inspect_url, data={"passphrase": "wrong-pass", "file": upload})
                self.assertEqual(response.status_code, 400)
                self.assertIn(response.json()["error"]["code"], {"INVALID_BACKUP_PASSPHRASE", "INVALID_BACKUP_FILE"})

    def test_restore_apply_audit_does_not_claim_inventory_compared(self):
        client = self._admin_client()
        with patch(
            "authorization_platform.backup_control.views.confirm_restore",
            return_value={"backup_time_beijing": "2026-09-04 17:00:00", "message": "命令已结束"},
        ):
            response = client.post(
                self.apply_url,
                data=json.dumps(
                    {
                        "staging_id": "11111111-1111-1111-1111-111111111111",
                        "passphrase": "unused",
                        "confirmed_backup_time": "2026-09-04 17:00:00",
                    }
                ),
                content_type="application/json",
                **self._headers("restore-apply-audit-1"),
            )
        self.assertEqual(response.status_code, 200, response.content)
        event = AuditEvent.objects.filter(action="backup.restore.apply").latest("occurred_at")
        self.assertEqual(event.metadata.get("restore_command_finished"), True)
        self.assertEqual(event.metadata.get("inventory_compared"), False)

    def test_confirm_restore_json_does_not_claim_restored_or_compared(self):
        from django.conf import settings

        with tempfile.TemporaryDirectory() as directory:
            with override_settings(BACKUP_RESTORE_STAGING_DIR=Path(directory)):
                client = self._admin_client()
                upload, passphrase = self._encrypted_upload()
                inspected = client.post(self.inspect_url, data={"passphrase": passphrase, "file": upload})
                self.assertEqual(inspected.status_code, 200, inspected.content)
                staging_id = inspected.json()["staging_id"]
                databases = {
                    alias: {**config} for alias, config in settings.DATABASES.items()
                }
                databases["default"]["ENGINE"] = "django.db.backends.postgresql"
                with override_settings(DATABASES=databases), patch(
                    "authorization_platform.backup_control.views.allow_rate",
                    return_value=True,
                ), patch(
                    "authorization_platform.backup_control.services._apply_postgres_restore"
                ) as apply_restore:
                    apply_restore.side_effect = lambda plaintext: None
                    response = client.post(
                        self.apply_url,
                        data=json.dumps(
                            {
                                "staging_id": staging_id,
                                "passphrase": passphrase,
                                "confirmed_backup_time": inspected.json()["backup_time_beijing"],
                            }
                        ),
                        content_type="application/json",
                        **self._headers("restore-json-no-restored"),
                    )
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertNotIn("restored", payload)
        self.assertTrue(payload.get("restore_command_finished"))
        self.assertIs(payload.get("inventory_compared"), False)
        apply_restore.assert_called_once()


class OpensslPassphraseCompatibilityTests(SimpleTestCase):
    def test_ui_passphrase_decrypts_openssl_file_crlf_secret(self):
        secret = "a" * 64
        plaintext = b"PGDMP-test-payload"
        salt = b"12345678"
        key, iv = _openssl_key_iv(secret + "\r", salt)
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len]) * pad_len
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        blob = OPENSSL_MAGIC + salt + encryptor.update(padded) + encryptor.finalize()
        self.assertEqual(openssl_decrypt_aes256_cbc(blob, secret), plaintext)
        self.assertEqual(openssl_decrypt_aes256_cbc(blob, secret + "\r\n"), plaintext)

    def test_stripped_secret_still_decrypts_platform_files(self):
        secret = "b" * 64
        blob = openssl_encrypt_aes256_cbc(b"PGDMP-ok", secret + "\n")
        self.assertEqual(openssl_decrypt_aes256_cbc(blob, secret), b"PGDMP-ok")


class BackupDestinationExecutionTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="runner-admin", password="Admin-password-123")
        self.stamp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.stamp_dir.cleanup)
        stamp_override = override_settings(BACKUP_SCHEDULE_STAMP_DIR=Path(self.stamp_dir.name))
        stamp_override.enable()
        self.addCleanup(stamp_override.disable)

    def _schedule(self, now: datetime, root: Path) -> dict:
        with override_settings(BACKUP_ROOT=root):
            with self.captureOnCommitCallbacks(execute=True):
                return schedule_due_backups(now=now)

    def _enable_schedule(self, *, full_time: str = "02:15", diff_interval_hours: int = 6) -> None:
        update_policy(
            actor=self.admin,
            values={
                "enabled": True,
                "schedule_enabled": True,
                "full_time": full_time,
                "diff_interval_hours": diff_interval_hours,
            },
        )

    def test_schedule_queues_full_when_full_time_has_passed(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 2, 20, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
            self.assertTrue(result["queued"])
            self.assertEqual(result["backup_type"], BackupRunRequest.BackupType.FULL)
            self.assertEqual(result["reason"], "full_due")
            row = BackupRunRequest.objects.get()
            self.assertEqual(row.status, BackupRunRequest.Status.PENDING)
            self.assertIsNone(row.actor)
            self.assertEqual(
                row.scheduled_for,
                datetime(2026, 9, 4, 2, 15, tzinfo=ZoneInfo("Asia/Shanghai")).astimezone(ZoneInfo("UTC")),
            )
            self.assertTrue((Path(directory) / "queue" / "need-run").is_file())

    def test_scheduled_full_slot_survives_completion_after_midnight(self):
        self._enable_schedule(full_time="23:45")
        queued_at = datetime(2026, 9, 4, 23, 50, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(queued_at, Path(directory))
        self.assertTrue(result["queued"])
        row = BackupRunRequest.objects.get()
        planned_slot = datetime(2026, 9, 4, 23, 45, tzinfo=ZoneInfo("Asia/Shanghai"))
        self.assertEqual(row.scheduled_for, planned_slot.astimezone(ZoneInfo("UTC")))

        row.status = BackupRunRequest.Status.SUCCEEDED
        row.save(update_fields=["status"])
        completed_at = datetime(2026, 9, 5, 0, 10, tzinfo=ZoneInfo("Asia/Shanghai"))
        mark_schedule_stamp("full", now=row.scheduled_for)
        mark_schedule_stamp(
            "diff",
            now=completed_at,
        )
        with tempfile.TemporaryDirectory() as directory:
            next_day = self._schedule(
                datetime(2026, 9, 5, 23, 45, tzinfo=ZoneInfo("Asia/Shanghai")),
                Path(directory),
            )
        self.assertTrue(next_day["queued"])
        self.assertEqual(next_day["backup_type"], BackupRunRequest.BackupType.FULL)
        self.assertEqual(BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).count(), 1)

    def test_manual_full_completion_does_not_claim_schedule_slot(self):
        self._enable_schedule(full_time="02:15")
        # A manual full completed at 01:00 Beijing must not satisfy the 02:15 slot.
        (Path(self.stamp_dir.name) / "last-full").write_text(
            "2026-09-03T17:00:00+00:00",
            encoding="utf-8",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(
                datetime(2026, 9, 4, 2, 15, tzinfo=ZoneInfo("Asia/Shanghai")),
                Path(directory),
            )
        self.assertTrue(result["queued"])
        self.assertEqual(result["backup_type"], BackupRunRequest.BackupType.FULL)

    def test_changed_full_time_creates_a_new_schedule_slot(self):
        self._enable_schedule(full_time="02:15")
        first_poll = datetime(2026, 9, 4, 2, 20, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            first = self._schedule(first_poll, Path(directory))
        self.assertTrue(first["queued"])
        first_row = BackupRunRequest.objects.get()
        mark_schedule_stamp("full", now=first_row.scheduled_for)
        first_row.status = BackupRunRequest.Status.SUCCEEDED
        first_row.save(update_fields=["status"])

        update_policy(
            actor=self.admin,
            values={
                "enabled": True,
                "schedule_enabled": True,
                "full_time": "23:45",
                "diff_interval_hours": 6,
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            second = self._schedule(
                datetime(2026, 9, 4, 23, 50, tzinfo=ZoneInfo("Asia/Shanghai")),
                Path(directory),
            )
        self.assertTrue(second["queued"])
        self.assertEqual(second["backup_type"], BackupRunRequest.BackupType.FULL)
        self.assertEqual(
            BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).get().scheduled_for,
            datetime(2026, 9, 4, 23, 45, tzinfo=ZoneInfo("Asia/Shanghai")).astimezone(ZoneInfo("UTC")),
        )

    def test_legacy_full_completion_stamp_does_not_claim_a_new_slot(self):
        self._enable_schedule(full_time="23:45")
        legacy_stamp = Path(self.stamp_dir.name) / "last-full"
        legacy_stamp.write_text("2026-09-05T00:10:00+08:00", encoding="utf-8")
        now = datetime(2026, 9, 5, 23, 45, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertTrue(result["queued"])
        self.assertEqual(result["backup_type"], BackupRunRequest.BackupType.FULL)

    def test_schedule_does_not_queue_when_full_and_diff_are_not_due(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 1, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        mark_schedule_stamp("diff", now=now)
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertFalse(result["queued"])
        self.assertEqual(result["reason"], "not_due")
        self.assertEqual(BackupRunRequest.objects.count(), 0)

    def test_schedule_does_not_repeat_full_on_the_same_beijing_day(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        mark_schedule_stamp(
            "full",
            now=datetime(2026, 9, 4, 2, 15, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        mark_schedule_stamp("diff", now=now)
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertFalse(result["queued"])
        self.assertEqual(result["reason"], "not_due")

    def test_schedule_queues_diff_after_diff_interval(self):
        self._enable_schedule(diff_interval_hours=6)
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        mark_schedule_stamp(
            "full",
            now=datetime(2026, 9, 4, 2, 15, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        mark_schedule_stamp("diff", now=datetime(2026, 9, 4, 6, 0, tzinfo=ZoneInfo("Asia/Shanghai")))
        with tempfile.TemporaryDirectory() as directory:
            before = self._schedule(datetime(2026, 9, 4, 11, 59, tzinfo=ZoneInfo("Asia/Shanghai")), Path(directory))
        self.assertFalse(before["queued"])
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertTrue(result["queued"])
        self.assertEqual(result["backup_type"], BackupRunRequest.BackupType.DIFF)
        self.assertEqual(result["reason"], "diff_due")
        self.assertIsNone(BackupRunRequest.objects.get().scheduled_for)

    def test_schedule_without_diff_stamp_keeps_existing_due_behavior(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        mark_schedule_stamp(
            "full",
            now=datetime(2026, 9, 4, 2, 15, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertTrue(result["queued"])
        self.assertEqual(result["backup_type"], BackupRunRequest.BackupType.DIFF)

    def test_schedule_does_not_create_when_master_switch_is_off(self):
        update_policy(actor=self.admin, values={"enabled": False, "schedule_enabled": True})
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertFalse(result["queued"])
        self.assertEqual(result["reason"], "disabled")
        self.assertEqual(BackupRunRequest.objects.count(), 0)

    def test_schedule_does_not_create_when_schedule_switch_is_off(self):
        update_policy(actor=self.admin, values={"enabled": True, "schedule_enabled": False})
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertFalse(result["queued"])
        self.assertEqual(result["reason"], "schedule_disabled")

    def test_schedule_is_idempotent_for_existing_pending_and_restores_trigger(self):
        self._enable_schedule()
        row = BackupRunRequest.objects.create(
            backup_type=BackupRunRequest.BackupType.DIFF,
            status=BackupRunRequest.Status.PENDING,
            message="已有排队",
        )
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._schedule(now, root)
            second = self._schedule(now, root)
            self.assertTrue((root / "queue" / "need-run").is_file())
        self.assertFalse(result["queued"])
        self.assertEqual(result["reason"], "pending")
        self.assertEqual(result["pending_id"], str(row.public_id))
        self.assertFalse(second["queued"])
        self.assertEqual(BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).count(), 1)

    def test_schedule_waits_for_fresh_running_backup(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        BackupRunRequest.objects.create(
            backup_type=BackupRunRequest.BackupType.DIFF,
            status=BackupRunRequest.Status.RUNNING,
            message="备份程序正在执行。",
            updated_at=datetime(2026, 9, 4, 11, 30, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertFalse(result["queued"])
        self.assertEqual(result["reason"], "running")

    def test_schedule_fails_stale_running_then_queues(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        stale = BackupRunRequest.objects.create(
            backup_type=BackupRunRequest.BackupType.DIFF,
            status=BackupRunRequest.Status.RUNNING,
            message="备份程序正在执行。",
            updated_at=datetime(2026, 9, 4, 9, 0, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        stale.refresh_from_db()
        self.assertEqual(stale.status, BackupRunRequest.Status.FAILED)
        self.assertTrue(result["queued"])
        self.assertEqual(result["stale_running_failed"], 1)

    def test_full_has_priority_when_full_and_diff_are_due(self):
        self._enable_schedule()
        now = datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        with tempfile.TemporaryDirectory() as directory:
            result = self._schedule(now, Path(directory))
        self.assertTrue(result["queued"])
        self.assertEqual(result["backup_type"], BackupRunRequest.BackupType.FULL)
        self.assertEqual(BackupRunRequest.objects.count(), 1)

    def test_schedule_management_command_outputs_redacted_json(self):
        self._enable_schedule()
        with tempfile.TemporaryDirectory() as directory:
            output = StringIO()
            with override_settings(BACKUP_ROOT=Path(directory)):
                with self.captureOnCommitCallbacks(execute=True):
                    call_command(
                        "backup_policy",
                        "--schedule",
                        stdout=output,
                    )
            payload = json.loads(output.getvalue())
        self.assertTrue(payload["secret_values_exposed"] is False)
        self.assertIn(payload["reason"], {"full_due", "diff_due"})
        self.assertNotIn("token", output.getvalue().lower())

    def test_clock_does_not_run_without_a_queued_change(self):
        update_policy(
            actor=self.admin,
            values={"enabled": True, "schedule_enabled": True, "full_time": "02:15", "diff_interval_hours": 6},
        )
        skipped = decide_backup_run(
            backup_type="full",
            now=datetime(2026, 9, 4, 2, 20, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        self.assertFalse(skipped["execute"])
        self.assertEqual(skipped["reason"], "idle")
        request_backup_run(actor=self.admin, backup_type="full")
        queued = decide_backup_run(
            backup_type="full",
            now=datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        self.assertTrue(queued["execute"])
        self.assertEqual(queued["reason"], "pending")
        self.assertTrue(queued["pending_id"])
        self.assertEqual(BackupRunRequest.objects.get().status, BackupRunRequest.Status.RUNNING)
        finish_backup_run(
            run_id=queued["pending_id"],
            result="succeeded",
            attempt_token=queued["attempt_token"],
            message="全量备份已完成。",
        )
        self.assertEqual(BackupRunRequest.objects.get().status, BackupRunRequest.Status.SUCCEEDED)

    def test_auto_backup_off_still_runs_pending(self):
        update_policy(actor=self.admin, values={"enabled": True, "full_time": "02:15"})
        request_backup_run(actor=self.admin, backup_type="full")
        update_policy(actor=self.admin, values={"enabled": False})
        decision = decide_backup_run(
            backup_type="full",
            now=datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        self.assertTrue(decision["execute"])
        self.assertEqual(decision["reason"], "pending")

    def test_fresh_policy_master_switch_is_off(self):
        policy = get_policy()
        self.assertFalse(policy.enabled)
        self.assertFalse(policy.schedule_enabled)

    def test_immediate_backup_requires_master_switch(self):
        update_policy(actor=self.admin, values={"enabled": False})
        with self.assertRaises(BackupControlError) as raised:
            request_backup_run(actor=self.admin, backup_type="full")
        self.assertEqual(raised.exception.code, "BACKUP_DISABLED")

    def test_enabled_without_queue_stays_idle(self):
        update_policy(
            actor=self.admin,
            values={"enabled": True, "schedule_enabled": False, "full_time": "02:15"},
        )
        decision = decide_backup_run(
            backup_type="full",
            now=datetime(2026, 9, 4, 2, 20, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        self.assertFalse(decision["execute"])
        self.assertEqual(decision["reason"], "idle")

    def test_change_backup_queues_once_when_master_is_on(self):
        update_policy(actor=self.admin, values={"enabled": True})
        first = enqueue_change_backup(actor=self.admin)
        second = enqueue_change_backup(actor=self.admin)
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).count(), 1)

    def test_change_backup_skips_when_master_is_off(self):
        update_policy(actor=self.admin, values={"enabled": False})
        self.assertIsNone(enqueue_change_backup(actor=self.admin))
        self.assertEqual(BackupRunRequest.objects.count(), 0)

    def test_request_and_change_backup_touch_trigger_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with override_settings(BACKUP_ROOT=str(root)):
                update_policy(actor=self.admin, values={"enabled": True})
                trigger = root / "queue" / "need-run"
                with self.captureOnCommitCallbacks(execute=True):
                    enqueue_change_backup(actor=self.admin)
                self.assertTrue(trigger.is_file())
                trigger.unlink()
                BackupRunRequest.objects.all().delete()
                with self.captureOnCommitCallbacks(execute=True):
                    request_backup_run(actor=self.admin, backup_type="full")
                self.assertTrue(trigger.is_file())
                trigger.unlink()
                with self.captureOnCommitCallbacks(execute=True):
                    raised = None
                    try:
                        request_backup_run(actor=self.admin, backup_type="full")
                    except BackupControlError as exc:
                        raised = exc
                self.assertIsNotNone(raised)
                self.assertEqual(raised.code, "BACKUP_RUN_PENDING")
                self.assertTrue(trigger.is_file())
                self.assertIn("叫醒", raised.message)

    def test_auto_backup_off_without_queue_does_not_run(self):
        update_policy(actor=self.admin, values={"enabled": False, "full_time": "02:15"})
        decision = decide_backup_run(
            backup_type="full",
            now=datetime(2026, 9, 4, 2, 15, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        self.assertFalse(decision["execute"])
        self.assertEqual(decision["reason"], "disabled")

    def test_github_enabled_without_token_cannot_write_file(self):
        with self.assertRaises(BackupControlError):
            update_policy(actor=self.admin, values={"github_enabled": True, "github_repository": "owner/repo"})

    def test_telegram_channel_is_completely_removed(self):
        policy = get_policy()
        self.assertFalse(hasattr(policy, "telegram_enabled"))
        self.assertFalse(hasattr(policy, "telegram_chat_id"))
        self.assertFalse(hasattr(policy, "telegram_token_ciphertext"))
        updated = update_policy(
            actor=self.admin,
            values={
                "telegram_enabled": True,
                "telegram_chat_id": "123456",
                "telegram_bot_token": "secret-bot-token",
            },
        )
        self.assertFalse(hasattr(updated, "telegram_enabled"))
        self.assertFalse(hasattr(updated, "telegram_chat_id"))
        self.assertFalse(hasattr(updated, "telegram_token_ciphertext"))
        decision = decide_backup_run(backup_type="full")
        self.assertNotIn("telegram_enabled", decision)

    def test_netdisk_channel_is_completely_removed(self):
        policy = get_policy()
        self.assertFalse(hasattr(policy, "netdisk_preset"))
        self.assertFalse(hasattr(policy, "s3_enabled"))
        self.assertFalse(hasattr(policy, "webdav_enabled"))
        with self.assertRaises(BackupControlError) as raised:
            update_policy(
                actor=self.admin,
                values={
                    "netdisk_preset": "s3_r2",
                    "s3_endpoint": "https://abc.r2.cloudflarestorage.com",
                    "s3_bucket": "auth-backups",
                    "s3_access_key_id": "ak",
                    "s3_secret": "sk",
                },
            )
        self.assertEqual(raised.exception.code, "INVALID_POLICY")
        decision = decide_backup_run(backup_type="full")
        self.assertEqual(decision["netdisk"], "disabled")
        exported = runner_export()
        self.assertNotIn("netdisk_preset", exported)
        self.assertNotIn("s3_enabled", exported)
        self.assertNotIn("webdav_enabled", exported)

    def test_secret_files_cannot_escape_keys_dir(self):
        update_policy(
            actor=self.admin,
            values={"github_enabled": True, "github_repository": "owner/repo", "github_token": "ghp_escape-token-value"},
        )
        with tempfile.TemporaryDirectory() as directory:
            keys = Path(directory) / "keys"
            keys.mkdir()
            outside = Path(directory) / "github-token.txt"
            with override_settings(BACKUP_KEYS_DIR=keys):
                with self.assertRaises(BackupControlError):
                    write_github_token_file(outside)
            self.assertFalse(outside.exists())

    def test_github_disabled_does_not_keep_token_file(self):
        update_policy(
            actor=self.admin,
            values={"github_enabled": True, "github_repository": "owner/repo", "github_token": "ghp_kept-then-cleared"},
        )
        with tempfile.TemporaryDirectory() as directory:
            keys = Path(directory)
            token_path = keys / "github-token.txt"
            with override_settings(BACKUP_KEYS_DIR=keys):
                self.assertEqual(write_github_token_file(token_path), "written")
                self.assertTrue(token_path.read_text(encoding="utf-8"))
            update_policy(actor=self.admin, values={"github_enabled": False})
            with override_settings(BACKUP_KEYS_DIR=keys):
                self.assertEqual(write_github_token_file(token_path), "disabled")
            self.assertEqual(token_path.read_text(encoding="utf-8"), "")

    def test_encrypted_backup_upload_is_always_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "authorization-platform-enc-20260904-090000.dump.enc"
            artifact.write_bytes(b"ciphertext")
            with override_settings(BACKUP_DOWNLOAD_DIR=root):
                self.assertEqual(upload_encrypted_backup(artifact), "skipped")

    def test_stale_running_backup_is_failed_so_queue_can_move(self):
        update_policy(actor=self.admin, values={"enabled": True, "full_time": "02:15"})
        stale = BackupRunRequest.objects.create(
            backup_type=BackupRunRequest.BackupType.FULL,
            status=BackupRunRequest.Status.RUNNING,
            actor=self.admin,
            message="备份程序正在执行。",
        )
        BackupRunRequest.objects.filter(pk=stale.pk).update(
            updated_at=datetime(2026, 9, 1, 8, 0, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        request_backup_run(actor=self.admin, backup_type="full")
        decision = decide_backup_run(
            backup_type="full",
            now=datetime(2026, 9, 4, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai")),
        )
        stale.refresh_from_db()
        self.assertEqual(stale.status, BackupRunRequest.Status.FAILED)
        self.assertTrue(decision["execute"])
        self.assertEqual(decision["reason"], "pending")


class PostgresRestoreCommandTests(SimpleTestCase):
    @patch("authorization_platform.backup_control.services.shutil.which", return_value="/usr/bin/pg_restore")
    @patch("authorization_platform.backup_control.services.subprocess.run")
    def test_apply_postgres_restore_uses_single_transaction(self, run, _which):
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with override_settings(
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.postgresql",
                    "NAME": "authorization_platform",
                    "HOST": "db",
                    "PORT": "5432",
                    "USER": "authorization_platform",
                    "PASSWORD": "",
                }
            }
        ):
            _apply_postgres_restore(b"PGDMP-test")
        argv = run.call_args[0][0]
        self.assertIn("--single-transaction", argv)
        self.assertIn("--exit-on-error", argv)


class BackupDestinationProbeTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="probe-admin", password="Admin-password-123")
        self.url = reverse("backup_control:api_destination_probe")

    def _admin_client(self) -> Client:
        client = Client()
        client.force_login(self.admin)
        return client

    def test_anonymous_cannot_probe(self):
        response = self.client.post(self.url, data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 401)

    def test_probe_without_destination_is_rejected(self):
        client = self._admin_client()
        response = client.post(self.url, data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["error"]["code"], "DESTINATION_NOT_CONFIGURED")

    def test_github_probe_gets_repo_and_does_not_queue_or_upload(self):
        update_policy(
            actor=self.admin,
            values={
                "github_enabled": True,
                "github_repository": "owner/backup-repo",
                "github_token": "ghp_probe-token",
            },
        )
        recorded: list[tuple[str, str]] = []

        class FakeResponse:
            status = 200

            def read(self, n=-1):
                return b'{"id":1}'

        class FakeConn:
            def __init__(self, *args, **kwargs):
                return None

            def putrequest(self, method, path, skip_accept_encoding=False):
                recorded.append((method, path))

            def putheader(self, *args):
                return None

            def endheaders(self):
                return None

            def send(self, body):
                recorded.append(("SEND", str(len(body) if body else 0)))

            def getresponse(self):
                return FakeResponse()

            def close(self):
                return None

        with (
            patch("authorization_platform.backup_control.services.http.client.HTTPSConnection", FakeConn),
            patch("authorization_platform.backup_control.services.request_backup_run") as queued,
            patch("authorization_platform.backup_control.services.upload_encrypted_backup") as uploaded,
            patch("authorization_platform.backup_control.services.decide_backup_run") as decided,
        ):
            client = self._admin_client()
            response = client.post(self.url, data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["uploaded"])
        self.assertEqual(payload["message"], "连通正常。没有上传备份。")
        self.assertEqual(recorded[0][0], "GET")
        self.assertTrue(recorded[0][1].startswith("/repos/owner/backup-repo"))
        self.assertFalse(any(item[0] == "PUT" for item in recorded))
        queued.assert_not_called()
        uploaded.assert_not_called()
        decided.assert_not_called()
        self.assertEqual(BackupRunRequest.objects.count(), 0)

    def test_probe_handlers_do_not_call_backup_run_or_upload(self):
        from authorization_platform.backup_control import services as backup_services
        from authorization_platform.backup_control import views as backup_views

        forbidden = ("request_backup_run(", "upload_encrypted_backup(", "decide_backup_run(")
        for name in ("probe_backup_destinations", "_probe_github"):
            source = inspect.getsource(getattr(backup_services, name))
            for token in forbidden:
                self.assertNotIn(token, source)
        self.assertFalse(hasattr(backup_services, "_probe_webdav"))
        self.assertFalse(hasattr(backup_services, "_probe_s3"))
        view_source = inspect.getsource(backup_views.api_backup_destination_probe)
        for token in forbidden:
            self.assertNotIn(token, view_source)
