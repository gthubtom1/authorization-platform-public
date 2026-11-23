from __future__ import annotations

import hashlib
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from authorization_platform.catalog.models import ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import create_profile, create_software
from authorization_platform.core.object_storage import ObjectStorageError, StoredObject
from authorization_platform.releases.models import Release, ReleaseSignatureStatus, ReleaseStatus
from authorization_platform.storage_cleanup.models import StorageCleanupState


User = get_user_model()


class StorageCleanupApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="cleanup-admin", password="Admin-password-123")
        self.client = Client()
        self.client.force_login(self.admin)
        self.software = create_software(actor=self.admin, software_id="cleanup-tool", name="Cleanup Tool", status=SoftwareStatus.ACTIVE)
        self.profile = create_profile(actor=self.admin, software_id="cleanup-tool", profile_id="stable", client_id="cleanup-tool-windows", status=ProfileStatus.ACTIVE)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "storage"
        self.release_root = self.root / "releases"
        self.release_root.mkdir(parents=True)
        self.old_file = self.release_root / "withdrawn.zip"
        self.old_file.write_bytes(b"old release")
        self.tmp_file = self.root / "tmp" / "old.txt"
        self.tmp_file.parent.mkdir(parents=True)
        self.tmp_file.write_bytes(b"old temp")
        old = timezone.now() - timedelta(days=31)
        import os

        os.utime(self.tmp_file, (old.timestamp(), old.timestamp()))
        self.release = Release.objects.create(
            software=self.software, profile=self.profile, version="1.0.0", target="windows", arch="x64", channel="stable",
            manifest={"schema": "client-release.v1"}, package_name="withdrawn.zip", package_path=str(self.old_file), package_size=self.old_file.stat().st_size,
            package_sha256=hashlib.sha256(self.old_file.read_bytes()).hexdigest(), signature_algorithm="ed25519", signature_key_id="key", signature_status=ReleaseSignatureStatus.DECLARED,
            status=ReleaseStatus.WITHDRAWN, created_by=self.admin, withdrawn_at=old,
        )
        self.settings_override = override_settings(STORAGE_ROOT=self.root, RELEASE_STORAGE_ROOT=self.release_root, STORAGE_CLEANUP_RETENTION_DAYS=30)
        self.settings_override.enable()

    def tearDown(self):
        self.settings_override.disable()
        self.temp.cleanup()

    def test_scan_and_execute_are_scoped_and_idempotent(self):
        scan = self.client.get(reverse("storage_cleanup:manage_cleanup"))
        self.assertEqual(scan.status_code, 200)
        self.assertEqual(scan.json()["candidate_count"], 2)
        executed = self.client.post(reverse("storage_cleanup:manage_cleanup"), data="{}", content_type="application/json", HTTP_IDEMPOTENCY_KEY="cleanup-1")
        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()["deleted_count"], 2)
        self.assertFalse(self.old_file.exists())
        self.assertFalse(self.tmp_file.exists())
        repeated = self.client.post(reverse("storage_cleanup:manage_cleanup"), data="{}", content_type="application/json", HTTP_IDEMPOTENCY_KEY="cleanup-1")
        self.assertTrue(repeated.json()["repeated"])
        self.assertEqual(repeated.json()["deleted_count"], 2)
        self.release.refresh_from_db()
        self.assertEqual(self.release.package_path, "")

    def test_tampered_release_package_is_skipped_and_state_timestamp_moves(self):
        state = StorageCleanupState.objects.create(key="default")
        timestamp_before = state.updated_at
        self.old_file.write_bytes(b"tampered release")
        executed = self.client.post(
            reverse("storage_cleanup:manage_cleanup"),
            data="{}",
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="cleanup-tampered",
        )
        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()["deleted_count"], 1)
        self.assertEqual(executed.json()["skipped_count"], 1)
        self.assertTrue(self.old_file.exists())
        self.assertFalse(self.tmp_file.exists())
        state.refresh_from_db()
        self.assertGreater(state.updated_at, timestamp_before)

    @override_settings(
        OBJECT_STORAGE_PROVIDER="s3-compatible",
        OBJECT_STORAGE_ENDPOINT="http://objects.internal:9000",
        OBJECT_STORAGE_BUCKET="authorization-platform",
        OBJECT_STORAGE_REGION="internal-1",
        OBJECT_STORAGE_ACCESS_KEY_ID="access-id",
        OBJECT_STORAGE_SECRET_ACCESS_KEY="object-secret",
    )
    def test_remote_release_cleanup_rechecks_metadata_and_updates_database(self):
        payload_hash = self.release.package_sha256
        payload_size = self.release.package_size
        self.release.package_path = "releases/withdrawn.zip"
        self.release.save(update_fields=("package_path",))

        class FakeRemoteStore:
            def __init__(self):
                self.deleted = []

            def head(self, key):
                self.assert_key = key
                return StoredObject(key=key, size=payload_size, sha256=payload_hash)

            def delete(self, key):
                self.deleted.append(key)
                return True

        store = FakeRemoteStore()
        with patch("authorization_platform.storage_cleanup.services.configured_object_store", return_value=store):
            scan = self.client.get(reverse("storage_cleanup:manage_cleanup"))
            self.assertEqual(scan.status_code, 200)
            self.assertEqual(scan.json()["candidate_count"], 2)
            executed = self.client.post(
                reverse("storage_cleanup:manage_cleanup"),
                data="{}",
                content_type="application/json",
                HTTP_IDEMPOTENCY_KEY="cleanup-remote-1",
            )

        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()["deleted_count"], 2)
        self.assertEqual(store.deleted, ["releases/withdrawn.zip"])
        self.assertFalse(self.tmp_file.exists())
        self.release.refresh_from_db()
        self.assertEqual(self.release.package_path, "")

    @override_settings(
        OBJECT_STORAGE_PROVIDER="s3-compatible",
        OBJECT_STORAGE_ENDPOINT="https://objects.internal:9000",
        OBJECT_STORAGE_BUCKET="authorization-platform",
        OBJECT_STORAGE_REGION="internal-1",
        OBJECT_STORAGE_ACCESS_KEY_ID="access-id",
        OBJECT_STORAGE_SECRET_ACCESS_KEY="object-secret",
    )
    def test_remote_cleanup_treats_missing_object_as_already_deleted(self):
        self.release.package_path = "releases/withdrawn.zip"
        self.release.save(update_fields=("package_path",))

        class MissingAfterScanStore:
            def __init__(self):
                self.head_calls = 0
                self.deleted = []

            def head(self, key):
                self.head_calls += 1
                if self.head_calls > 1:
                    raise ObjectStorageError("missing", status_code=404)
                return StoredObject(key=key, size=self.release_size, sha256=self.release_hash)

            def delete(self, key):
                self.deleted.append(key)
                return True

        store = MissingAfterScanStore()
        store.release_size = self.release.package_size
        store.release_hash = self.release.package_sha256
        with patch("authorization_platform.storage_cleanup.services.configured_object_store", return_value=store):
            executed = self.client.post(
                reverse("storage_cleanup:manage_cleanup"),
                data="{}",
                content_type="application/json",
                HTTP_IDEMPOTENCY_KEY="cleanup-remote-missing-1",
            )

        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()["deleted_count"], 2)
        self.assertFalse(self.tmp_file.exists())
        self.release.refresh_from_db()
        self.assertEqual(self.release.package_path, "")

    def test_scan_skips_oversize_file_and_keeps_later_small_files(self):
        import os

        logs = self.root / "logs"
        logs.mkdir(parents=True)
        oversized = logs / "aaa.log"
        later = logs / "zzz.log"
        oversized.write_bytes(b"x" * 50)
        later.write_bytes(b"y" * 8)
        old = timezone.now() - timedelta(days=31)
        os.utime(oversized, (old.timestamp(), old.timestamp()))
        os.utime(later, (old.timestamp(), old.timestamp()))
        with override_settings(STORAGE_CLEANUP_MAX_BYTES=20):
            scan = self.client.get(reverse("storage_cleanup:manage_cleanup"))
        self.assertEqual(scan.status_code, 200)
        payload = scan.json()
        paths = {item["path"] for item in payload["candidates"]}
        self.assertNotIn("logs/aaa.log", paths)
        self.assertIn("logs/zzz.log", paths)
        self.assertGreaterEqual(payload["candidate_count"], 1)
        self.assertTrue(payload["truncated"])

    def test_scan_reports_truncated_when_file_window_is_full(self):
        import os

        logs = self.root / "logs"
        logs.mkdir(parents=True)
        for name in ("a.log", "b.log", "c.log"):
            path = logs / name
            path.write_bytes(b"small")
            old = timezone.now() - timedelta(days=31)
            os.utime(path, (old.timestamp(), old.timestamp()))
        with override_settings(STORAGE_CLEANUP_MAX_FILES=1):
            scan = self.client.get(reverse("storage_cleanup:manage_cleanup"))
        self.assertEqual(scan.status_code, 200)
        payload = scan.json()
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["candidate_count"], 1)