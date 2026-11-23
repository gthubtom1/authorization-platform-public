from __future__ import annotations

import io
import base64
import hashlib
import json
import tempfile
import uuid
import zipfile
from pathlib import Path

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import create_plan, create_policy_version, create_profile, create_software, set_downstream_software_access
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY
from authorization_platform.licensing.models import AuthorizationState, LicenseCard, LicenseCardBatch, LicenseCardStatus, LicenseInstance
from authorization_platform.licensing.services import license_card_hash, normalize_license_card_code
from authorization_platform.releases.models import Release, ReleaseSignatureStatus, ReleaseStatus
from authorization_platform.releases.services import _canonical_manifest, latest_public_release
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


User = get_user_model()


class ReleaseApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="release-admin", password="Admin-password-123")
        self.client = Client()
        self.client.force_login(self.admin)
        self.software = create_software(actor=self.admin, software_id="release-tool", name="Release Tool", status=SoftwareStatus.ACTIVE)
        self.profile = create_profile(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id="stable",
            client_id="release-tool-windows",
            target="windows",
            arch="x64",
            channel="stable",
            status=ProfileStatus.ACTIVE,
        )
        self.temp = tempfile.TemporaryDirectory()
        self.storage_root = Path(self.temp.name) / "storage"
        self.release_root = self.storage_root / "releases"
        self.settings_override = override_settings(
            STORAGE_ROOT=self.storage_root,
            RELEASE_STORAGE_ROOT=self.release_root,
            RELEASE_REQUIRE_VERIFIED_SIGNATURE=False,
        )
        self.settings_override.enable()

    def tearDown(self):
        self.settings_override.disable()
        self.temp.cleanup()

    def _package(self, version="1.2.3", *, profile_id="stable", channel="stable", software_id="release-tool"):
        manifest = {
            "schema": "client-release.v1",
            "version": version,
            "software_id": software_id,
            "profile_id": profile_id,
            "target": "windows",
            "arch": "x64",
            "channel": channel,
            "minimum_client_version": "1.0.0",
            "signature": {"algorithm": "ed25519", "key_id": "test-key", "value": "declared-signature"},
            "debug_token": "must-not-appear-in-public-registry",
        }
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("client-release.v1.json", json.dumps(manifest, ensure_ascii=False))
            archive.writestr("payload/app.bin", b"safe test payload")
        return SimpleUploadedFile(
            f"release-v{version}.zip",
            output.getvalue(),
            content_type="application/zip",
        )

    def _signed_package(self, version="1.2.3"):
        payload_name = "payload/app.bin"
        payload = b"safe signed test payload"
        payload_digest = hashlib.sha256()
        payload_digest.update(payload_name.encode("utf-8"))
        payload_digest.update(b"\0")
        payload_digest.update(str(len(payload)).encode("ascii"))
        payload_digest.update(b"\0")
        payload_digest.update(payload)
        private_key = Ed25519PrivateKey.generate()
        manifest = {
            "schema": "client-release.v1",
            "version": version,
            "software_id": "release-tool",
            "profile_id": "stable",
            "target": "windows",
            "arch": "x64",
            "channel": "stable",
            "minimum_client_version": "1.0.0",
            "payload_sha256": payload_digest.hexdigest(),
            "signature": {"algorithm": "ed25519", "key_id": "signed-test-key", "value": "placeholder"},
        }
        signature = private_key.sign(_canonical_manifest(manifest))
        manifest["signature"]["value"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("client-release.v1.json", json.dumps(manifest, ensure_ascii=False))
            archive.writestr(payload_name, payload)
        public_key = base64.urlsafe_b64encode(private_key.public_key().public_bytes_raw()).decode("ascii").rstrip("=")
        return SimpleUploadedFile(f"release-v{version}.zip", output.getvalue(), content_type="application/zip"), public_key

    def _upload(self, *, key="upload-1", version="1.2.3"):
        return self.client.post(
            reverse("releases:manage_collection"),
            {
                "software_id": "release-tool",
                "channel": "stable",
                "release_package": self._package(version),
            },
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def _package_with_member(self, member_name, *, version="4.0.0", external_attr=None):
        manifest = {
            "schema": "client-release.v1",
            "version": version,
            "software_id": "release-tool",
            "profile_id": "stable",
            "target": "windows",
            "arch": "x64",
            "channel": "stable",
            "minimum_client_version": "1.0.0",
            "signature": {"algorithm": "ed25519", "key_id": "test-key", "value": "declared-signature"},
        }
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("client-release.v1.json", json.dumps(manifest, ensure_ascii=False))
            info = zipfile.ZipInfo(member_name)
            if external_attr is not None:
                info.external_attr = external_attr
            archive.writestr(info, b"payload")
        return SimpleUploadedFile(f"release-v{version}.zip", output.getvalue(), content_type="application/zip")

    def test_zip_member_with_windows_drive_prefix_is_rejected(self):
        """A "C:/evil.exe" member passes the POSIX ".." check but escapes the
        extraction root when the customer unzips the package on Windows."""

        response = self.client.post(
            reverse("releases:manage_collection"),
            {
                "software_id": "release-tool",
                "channel": "stable",
                "release_package": self._package_with_member("C:/evil.exe"),
            },
            HTTP_IDEMPOTENCY_KEY="zip-drive-prefix",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["error"]["code"], "PACKAGE_PATH_INVALID")

    def test_zip_member_with_symlink_mode_is_rejected(self):
        response = self.client.post(
            reverse("releases:manage_collection"),
            {
                "software_id": "release-tool",
                "channel": "stable",
                "release_package": self._package_with_member("payload/link", external_attr=0o120777 << 16),
            },
            HTTP_IDEMPOTENCY_KEY="zip-symlink-member",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["error"]["code"], "PACKAGE_PATH_INVALID")

    def test_external_release_reports_its_real_integrity_coverage(self):
        """A cloud-drive release carries no platform signature; the admin
        payload must not present it as verified."""

        plain = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "5.0.0",
                    "notes": "无哈希网盘发布",
                    "external_download_url": "https://pan.example.com/s/plain",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="coverage-plain",
        )
        self.assertEqual(plain.status_code, 201, plain.content)
        self.assertEqual(plain.json()["item"]["signature"]["coverage"], "external_unverified")

        hashed = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "5.0.1",
                    "notes": "带哈希网盘发布",
                    "external_download_url": "https://pan.example.com/s/hashed",
                    "package_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="coverage-hashed",
        )
        self.assertEqual(hashed.status_code, 201, hashed.content)
        self.assertEqual(hashed.json()["item"]["signature"]["coverage"], "external_sha256")

    def test_manage_release_page_is_admin_only_and_paginated(self):
        response = self.client.get(reverse("releases:manage_page"))
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, "上传客户端 ZIP", status_code=410)
        self.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)
        self.client.logout()
        anonymous = self.client.get(reverse("releases:manage_page"))
        self.assertEqual(anonymous.status_code, 302)

    def test_html_withdraw_does_not_change_release(self):
        uploaded = self._upload(key="html-withdraw-upload", version="9.9.9")
        self.assertEqual(uploaded.status_code, 201)
        item = uploaded.json()["item"]
        published = self.client.post(
            reverse("releases:publish", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"notes": "发布后再试旧页撤回"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="html-withdraw-publish",
        )
        self.assertEqual(published.status_code, 200)
        response = self.client.post(
            reverse("releases:manage_page"),
            {
                "action": "withdraw",
                "release_id": item["release_id"],
                "reason": "旧页撤回测试",
                "idempotency_key": "html-withdraw",
            },
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(Release.objects.get(pk=item["release_id"]).status, ReleaseStatus.PUBLISHED)

    def test_upload_publish_registry_and_download_are_real(self):
        uploaded = self._upload()
        self.assertEqual(uploaded.status_code, 201)
        item = uploaded.json()["item"]
        self.assertEqual(item["status"], ReleaseStatus.DRAFT)
        self.assertTrue(item["package_available"])
        self.assertNotEqual(item["package_sha256"], "")

        published = self.client.post(
            reverse("releases:publish", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"notes": "修复真实发布路径"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="publish-1",
        )
        self.assertEqual(published.status_code, 200)
        self.assertEqual(published.json()["item"]["status"], ReleaseStatus.PUBLISHED)

        registry = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(registry.status_code, 200)
        self.assertTrue(registry.json()["has_update"])
        self.assertEqual(registry.json()["release"]["version"], "1.2.3")
        self.assertNotIn("debug_token", registry.json()["release"]["manifest"])

        self.assertFalse(settings.RELEASE_DOWNLOAD_REQUIRE_AUTH)
        downloaded = self.client.get(registry.json()["release"]["download_url"])
        self.assertEqual(downloaded.status_code, 200)
        self.assertIn(b"client-release.v1.json", b"".join(downloaded.streaming_content))
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True):
            blocked = self.client.get(registry.json()["release"]["download_url"], REMOTE_ADDR="127.0.0.1")
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json()["error"]["code"], "DOWNLOAD_AUTH_REQUIRED")

    def test_external_download_url_publishes_without_zip_and_skips_platform_download(self):
        created = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.0.0",
                    "notes": "网盘更新说明足够长",
                    "external_download_url": "https://pan.example.com/s/godskin-2-0-0",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="external-1",
        )
        self.assertEqual(created.status_code, 201, created.content)
        item = created.json()["item"]
        self.assertEqual(item["status"], ReleaseStatus.PUBLISHED)
        self.assertEqual(item["distribution"], "external_url")
        self.assertEqual(item["external_download_url"], "https://pan.example.com/s/godskin-2-0-0")
        self.assertFalse(item["package_available"])
        replay = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.0.0",
                    "notes": "网盘更新说明足够长",
                    "external_download_url": "https://pan.example.com/s/godskin-2-0-0",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="external-1",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        rejected = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.0.1",
                    "notes": "带账号的地址应拒绝",
                    "external_download_url": "https://user:pass@pan.example.com/s/secret",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="external-bad-url",
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.json()["error"]["code"], "INVALID_DOWNLOAD_URL")
        bad_version = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.0.1-beta",
                    "notes": "带后缀的版本号应拒绝",
                    "external_download_url": "https://pan.example.com/s/ok",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="external-bad-version",
        )
        self.assertEqual(bad_version.status_code, 400)
        self.assertEqual(bad_version.json()["error"]["code"], "INVALID_VERSION")
        registry = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(registry.status_code, 200)
        self.assertTrue(registry.json()["has_update"])
        release = registry.json()["release"]
        self.assertEqual(release["update_open_url"], "https://pan.example.com/s/godskin-2-0-0")
        self.assertNotIn("download_url", release)
        updated = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/godskin-2-0-0-new"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="external-url-update-1",
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(updated.json()["item"]["external_download_url"], "https://pan.example.com/s/godskin-2-0-0-new")
        replay_update = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/godskin-2-0-0-new"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="external-url-update-1",
        )
        self.assertEqual(replay_update.status_code, 200)
        self.assertTrue(replay_update.json()["repeated"])
        registry_after = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(registry_after.json()["release"]["update_open_url"], "https://pan.example.com/s/godskin-2-0-0-new")
        with override_settings(RELEASE_REQUIRE_VERIFIED_SIGNATURE=True):
            _, selected, has_update = latest_public_release(
                software_id="release-tool",
                profile_id="stable",
                client_id="release-tool-windows",
                target="windows",
                arch="x64",
                channel="stable",
                current_version="1.0.0",
            )
        self.assertIsNotNone(selected)
        self.assertTrue(has_update)
        self.assertEqual(selected.external_download_url, "https://pan.example.com/s/godskin-2-0-0-new")

    def test_external_same_version_replaces_published_and_withdrawn(self):
        first = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.7.7",
                    "notes": "第一次发布网盘",
                    "external_download_url": "https://pan.example.com/s/first",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="replace-1",
        )
        self.assertEqual(first.status_code, 201, first.content)
        release_id = first.json()["item"]["release_id"]
        replaced_live = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.7.7",
                    "notes": "同一版本换链接",
                    "external_download_url": "https://pan.example.com/s/second",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="replace-2",
        )
        self.assertEqual(replaced_live.status_code, 200, replaced_live.content)
        self.assertTrue(replaced_live.json()["replaced"])
        self.assertEqual(replaced_live.json()["item"]["release_id"], release_id)
        self.assertEqual(replaced_live.json()["item"]["external_download_url"], "https://pan.example.com/s/second")
        withdrawn = self.client.post(
            reverse("releases:withdraw", kwargs={"release_id": release_id}),
            data=json.dumps({"reason": "误操作撤回重发"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="replace-withdraw",
        )
        self.assertEqual(withdrawn.status_code, 200, withdrawn.content)
        revived = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.7.7",
                    "notes": "撤回后再发同一版本",
                    "external_download_url": "https://pan.example.com/s/third",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="replace-3",
        )
        self.assertEqual(revived.status_code, 200, revived.content)
        self.assertTrue(revived.json()["replaced"])
        self.assertEqual(revived.json()["item"]["release_id"], release_id)
        self.assertEqual(revived.json()["item"]["status"], ReleaseStatus.PUBLISHED)
        self.assertEqual(revived.json()["item"]["external_download_url"], "https://pan.example.com/s/third")
        self.assertEqual(Release.objects.filter(software=self.software, version="2.7.7").count(), 1)
        registry = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(registry.json()["release"]["update_open_url"], "https://pan.example.com/s/third")

    def test_external_release_replaces_zip_package_clears_package_and_signature_fields(self):
        uploaded = self._upload(key="zip-to-external-upload", version="3.0.0")
        self.assertEqual(uploaded.status_code, 201)
        item = uploaded.json()["item"]
        published = self.client.post(
            reverse("releases:publish", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"notes": "原始 ZIP 发布"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="zip-to-external-publish",
        )
        self.assertEqual(published.status_code, 200)
        release_before = Release.objects.get(pk=item["release_id"])
        self.assertTrue(bool(release_before.package_path))
        self.assertGreater(release_before.package_size, 0)

        replaced = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.0.0",
                    "notes": "覆盖为网盘地址",
                    "external_download_url": "https://pan.example.com/s/zip-replaced",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="zip-to-external-replace",
        )
        self.assertEqual(replaced.status_code, 200)
        self.assertTrue(replaced.json()["replaced"])
        release_after = Release.objects.get(pk=item["release_id"])
        self.assertEqual(release_after.package_name, "")
        self.assertEqual(release_after.package_path, "")
        self.assertEqual(release_after.package_size, 0)
        self.assertEqual(release_after.package_sha256, "")
        self.assertIsNone(release_after.package_deleted_at)
        self.assertEqual(release_after.signature_algorithm, "")
        self.assertEqual(release_after.signature_key_id, "")
        self.assertEqual(release_after.signature_status, ReleaseSignatureStatus.DECLARED)
        self.assertEqual(release_after.external_download_url, "https://pan.example.com/s/zip-replaced")

        download_resp = self.client.get(
            reverse("releases:public_download", kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": item["release_id"]})
        )
        self.assertEqual(download_resp.status_code, 410)

    def test_external_release_draft_conflict_returns_409(self):
        uploaded = self._upload(key="draft-conflict-upload", version="3.1.0")
        self.assertEqual(uploaded.status_code, 201)

        conflict = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.1.0",
                    "notes": "试图覆盖草稿",
                    "external_download_url": "https://pan.example.com/s/draft-conflict",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="draft-conflict-ext",
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "RELEASE_ALREADY_EXISTS")

    def test_republish_older_version_does_not_create_circular_previous_release(self):
        first = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "1.0.0",
                    "notes": "发布1.0.0",
                    "external_download_url": "https://pan.example.com/s/v100",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="loop-v1-pub",
        )
        self.assertEqual(first.status_code, 201)
        v1_id = first.json()["item"]["release_id"]

        second = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "2.0.0",
                    "notes": "发布2.0.0",
                    "external_download_url": "https://pan.example.com/s/v200",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="loop-v2-pub",
        )
        self.assertEqual(second.status_code, 201)
        v2_id = second.json()["item"]["release_id"]

        v2_obj = Release.objects.get(pk=v2_id)
        self.assertEqual(str(v2_obj.previous_release_id), v1_id)

        republish_v1 = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "1.0.0",
                    "notes": "重发1.0.0换地址",
                    "external_download_url": "https://pan.example.com/s/v100-new",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="loop-v1-repub",
        )
        self.assertEqual(republish_v1.status_code, 200)
        v1_obj = Release.objects.get(pk=v1_id)
        self.assertNotEqual(str(v1_obj.previous_release_id), v2_id)
        self.assertIsNone(v1_obj.previous_release_id)

    def test_update_external_url_negative_cases(self):
        fake_uuid = str(uuid.uuid4())
        resp_404 = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": fake_uuid}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/nonexistent"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-404",
        )
        self.assertEqual(resp_404.status_code, 404)
        self.assertEqual(resp_404.json()["error"]["code"], "RELEASE_NOT_FOUND")

        uploaded = self._upload(key="neg-draft-upload", version="4.0.0")
        draft_id = uploaded.json()["item"]["release_id"]
        resp_draft = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": draft_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/draft-url"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-draft",
        )
        self.assertEqual(resp_draft.status_code, 409)
        self.assertEqual(resp_draft.json()["error"]["code"], "RELEASE_NOT_PUBLISHED")

        published = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "4.1.0",
                    "notes": "发布后撤回测试",
                    "external_download_url": "https://pan.example.com/s/v410",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-withdrawn-pub",
        )
        pub_id = published.json()["item"]["release_id"]
        self.client.post(
            reverse("releases:withdraw", kwargs={"release_id": pub_id}),
            data=json.dumps({"reason": "测试撤回"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-withdrawn-do",
        )
        resp_withdrawn = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": pub_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/v410-new"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-withdrawn-try",
        )
        self.assertEqual(resp_withdrawn.status_code, 409)
        self.assertEqual(resp_withdrawn.json()["error"]["code"], "RELEASE_NOT_PUBLISHED")

        zip_upload = self._upload(key="neg-zip-upload", version="4.2.0")
        zip_id = zip_upload.json()["item"]["release_id"]
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": zip_id}),
            data=json.dumps({"notes": "正常发布ZIP"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-zip-pub",
        )
        resp_zip = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": zip_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/zip-try"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-zip-try",
        )
        self.assertEqual(resp_zip.status_code, 409)
        self.assertEqual(resp_zip.json()["error"]["code"], "NOT_EXTERNAL_RELEASE")

        pub_ext = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "4.3.0",
                    "notes": "发布准备测坏URL",
                    "external_download_url": "https://pan.example.com/s/v430",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-url-pub",
        )
        ext_id = pub_ext.json()["item"]["release_id"]
        resp_bad_url = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": ext_id}),
            data=json.dumps({"external_download_url": "javascript:alert(1)"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-bad-url",
        )
        self.assertEqual(resp_bad_url.status_code, 400)
        self.assertEqual(resp_bad_url.json()["error"]["code"], "INVALID_DOWNLOAD_URL")

        self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": ext_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/v430-good"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-idem-key",
        )
        conflict_idem = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": ext_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/v430-different"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-idem-key",
        )
        self.assertEqual(conflict_idem.status_code, 409)
        self.assertEqual(conflict_idem.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

        self.client.logout()
        unauth = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": ext_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/v430-unauth"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-unauth",
        )
        self.assertEqual(unauth.status_code, 401)

        downstream = create_downstream_direct(
            actor=self.admin,
            username="non-admin-ds",
            password="Downstream-password-123",
        )
        self.client.force_login(downstream.user)
        session = self.client.session
        session["downstream_session_version"] = str(downstream.session_version)
        session.save()
        forbidden = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": ext_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/v430-forbidden"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="neg-forbidden",
        )
        self.assertEqual(forbidden.status_code, 403)

    def test_manifest_scope_failure_and_idempotency_conflict_are_fail_closed(self):
        wrong = self.client.post(
            reverse("releases:manage_collection"),
            {"software_id": "release-tool", "channel": "test", "release_package": self._package(channel="stable")},
            HTTP_IDEMPOTENCY_KEY="wrong-scope",
        )
        self.assertEqual(wrong.status_code, 422)
        self.assertEqual(Release.objects.count(), 0)

        first = self._upload(key="same-key", version="1.2.3")
        repeated = self._upload(key="same-key", version="1.2.3")
        conflict = self._upload(key="same-key", version="1.2.4")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(repeated.status_code, 200)
        self.assertTrue(repeated.json()["repeated"])
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(Release.objects.count(), 1)

    def test_discard_draft_frees_version_and_rejects_published(self):
        uploaded = self._upload(key="discard-upload", version="9.9.9")
        self.assertEqual(uploaded.status_code, 201, uploaded.content)
        release_id = uploaded.json()["item"]["release_id"]
        listed = self.client.get(reverse("releases:manage_collection"))
        self.assertEqual(listed.json()["count"], 1)
        discarded = self.client.post(
            reverse("releases:discard", kwargs={"release_id": release_id}),
            data="{}",
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="discard-1",
        )
        self.assertEqual(discarded.status_code, 200, discarded.content)
        self.assertEqual(discarded.json()["item"]["status"], ReleaseStatus.DISCARDED)
        listed = self.client.get(reverse("releases:manage_collection"))
        self.assertEqual(listed.json()["count"], 0)
        replay = self.client.post(
            reverse("releases:discard", kwargs={"release_id": release_id}),
            data="{}",
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="discard-1",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        again = self._upload(key="discard-reupload", version="9.9.9")
        self.assertEqual(again.status_code, 201, again.content)
        published = self.client.post(
            reverse("releases:publish", kwargs={"release_id": again.json()["item"]["release_id"]}),
            data=json.dumps({"notes": "发布后不可丢草稿"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="publish-after-discard",
        )
        self.assertEqual(published.status_code, 200, published.content)
        blocked = self.client.post(
            reverse("releases:discard", kwargs={"release_id": again.json()["item"]["release_id"]}),
            data="{}",
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="discard-published",
        )
        self.assertEqual(blocked.status_code, 409)
        self.assertEqual(blocked.json()["error"]["code"], "RELEASE_NOT_DRAFT")

    def test_delete_withdrawn_package_keeps_history_and_rejects_published(self):
        published_item = self._upload(key="delete-pkg-pub-upload", version="4.4.4").json()["item"]
        published = self.client.post(
            reverse("releases:publish", kwargs={"release_id": published_item["release_id"]}),
            data=json.dumps({"notes": "发布后禁止删安装包"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-publish",
        )
        self.assertEqual(published.status_code, 200, published.content)
        published_path = Path(Release.objects.get(pk=published_item["release_id"]).package_path)
        self.assertTrue(published_path.is_file())
        blocked_published = self.client.post(
            reverse("releases:delete_package", kwargs={"release_id": published_item["release_id"]}),
            data=json.dumps({"confirmed": True}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-published",
        )
        self.assertEqual(blocked_published.status_code, 409)
        self.assertEqual(blocked_published.json()["error"]["code"], "RELEASE_NOT_WITHDRAWN")
        self.assertTrue(published_path.is_file())
        self.assertEqual(Release.objects.get(pk=published_item["release_id"]).status, ReleaseStatus.PUBLISHED)

        uploaded = self._upload(key="delete-pkg-upload", version="5.5.5")
        self.assertEqual(uploaded.status_code, 201, uploaded.content)
        item = uploaded.json()["item"]
        published_target = self.client.post(
            reverse("releases:publish", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"notes": "发布后再撤回再删包"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-target-publish",
        )
        self.assertEqual(published_target.status_code, 200, published_target.content)
        withdrawn = self.client.post(
            reverse("releases:withdraw", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"reason": "撤回后安装包仍留盘"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-withdraw",
        )
        self.assertEqual(withdrawn.status_code, 200, withdrawn.content)
        release = Release.objects.get(pk=item["release_id"])
        package_path = Path(release.package_path)
        self.assertTrue(package_path.is_file())
        self.assertEqual(release.status, ReleaseStatus.WITHDRAWN)

        unconfirmed = self.client.post(
            reverse("releases:delete_package", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-unconfirmed",
        )
        self.assertEqual(unconfirmed.status_code, 400)
        self.assertEqual(unconfirmed.json()["error"]["code"], "CONFIRMATION_REQUIRED")
        self.assertTrue(package_path.is_file())

        draft_upload = self._upload(key="delete-pkg-draft-upload", version="5.5.6")
        self.assertEqual(draft_upload.status_code, 201, draft_upload.content)
        draft_id = draft_upload.json()["item"]["release_id"]
        blocked_draft = self.client.post(
            reverse("releases:delete_package", kwargs={"release_id": draft_id}),
            data=json.dumps({"confirmed": True}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-draft",
        )
        self.assertEqual(blocked_draft.status_code, 409)
        self.assertEqual(blocked_draft.json()["error"]["code"], "RELEASE_NOT_WITHDRAWN")
        self.assertTrue(Path(Release.objects.get(pk=draft_id).package_path).is_file())

        first = self.client.post(
            reverse("releases:delete_package", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"confirmed": True}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-1",
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(first.json()["item"]["status"], ReleaseStatus.WITHDRAWN)
        self.assertFalse(first.json()["item"]["package_available"])
        self.assertFalse(package_path.exists())
        release.refresh_from_db()
        self.assertEqual(release.status, ReleaseStatus.WITHDRAWN)
        self.assertEqual(release.package_path, "")
        self.assertIsNotNone(release.package_deleted_at)

        replay = self.client.post(
            reverse("releases:delete_package", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"confirmed": True}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-1",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        self.assertEqual(replay.json()["item"]["status"], ReleaseStatus.WITHDRAWN)

        empty_again = self.client.post(
            reverse("releases:delete_package", kwargs={"release_id": item["release_id"]}),
            data=json.dumps({"confirmed": True}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-empty",
        )
        self.assertEqual(empty_again.status_code, 200, empty_again.content)
        self.assertEqual(empty_again.json()["item"]["status"], ReleaseStatus.WITHDRAWN)

        reupload = self._upload(key="delete-pkg-reupload", version="5.5.5")
        self.assertEqual(reupload.status_code, 409)
        self.assertEqual(reupload.json()["error"]["code"], "RELEASE_ALREADY_EXISTS")

        discarded = self.client.post(
            reverse("releases:discard", kwargs={"release_id": item["release_id"]}),
            data="{}",
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="delete-pkg-discard-withdrawn",
        )
        self.assertEqual(discarded.status_code, 409)
        self.assertEqual(discarded.json()["error"]["code"], "RELEASE_NOT_DRAFT")
        self.assertEqual(Release.objects.get(pk=item["release_id"]).status, ReleaseStatus.WITHDRAWN)
        self.assertTrue(AuditEvent.objects.filter(action="release.package.delete", outcome="success").exists())

    def test_withdrawal_falls_back_to_highest_remaining_published_version(self):
        published_ids = {}
        for version, upload_key, publish_key in (
            ("1.0.0", "upload-v1", "publish-v1"),
            ("3.0.0", "upload-v3", "publish-v3"),
            ("2.0.0", "upload-v2", "publish-v2"),
        ):
            uploaded = self._upload(key=upload_key, version=version)
            self.assertEqual(uploaded.status_code, 201, uploaded.content)
            published_ids[version] = uploaded.json()["item"]["release_id"]
            published = self.client.post(
                reverse("releases:publish", kwargs={"release_id": published_ids[version]}),
                data=json.dumps({"notes": f"发布 {version}"}),
                content_type="application/json",
                HTTP_IDEMPOTENCY_KEY=publish_key,
            )
            self.assertEqual(published.status_code, 200, published.content)
        withdrawn = self.client.post(
            reverse("releases:withdraw", kwargs={"release_id": published_ids["3.0.0"]}),
            data=json.dumps({"reason": "回退应落到版本最高而不是发布时间上一条"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="withdraw-v3",
        )
        self.assertEqual(withdrawn.status_code, 200, withdrawn.content)
        self.assertEqual(withdrawn.json()["registry_fallback_version"], "2.0.0")
        self.assertNotEqual(withdrawn.json()["registry_fallback_version"], "1.0.0")
        registry = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(registry.json()["release"]["version"], "2.0.0")
        self.assertEqual(Release.objects.filter(status=ReleaseStatus.WITHDRAWN).count(), 1)

    def test_public_registry_rejects_forged_client_scope(self):
        response = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "other-client", "target": "windows", "arch": "x64", "channel": "stable"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "CLIENT_SCOPE_MISMATCH")

    def test_public_download_rejects_symlinked_package_outside_storage(self):
        first = self._upload(key="symlink-upload")
        release = Release.objects.get(release_id=first.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": release.release_id}),
            data=json.dumps({"notes": "符号链接边界"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="symlink-publish",
        )
        outside = self.storage_root.parent / "outside.zip"
        outside.write_bytes(b"outside")
        package_path = Path(release.package_path)
        package_path.unlink()
        try:
            package_path.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("当前 Windows 环境不允许创建符号链接")
        response = self.client.get(
            reverse("releases:public_download", kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": release.release_id})
        )
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json()["error"]["code"], "PACKAGE_UNAVAILABLE")

    def test_protected_public_download_requires_license_key(self):
        first = self._upload(key="protected-download")
        release = Release.objects.get(release_id=first.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": release.release_id}),
            data=json.dumps({"notes": "受保护下载"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="protected-publish",
        )
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True):
            response = self.client.get(
                reverse("releases:public_download", kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": release.release_id}),
                REMOTE_ADDR="127.0.0.1",
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "DOWNLOAD_AUTH_REQUIRED")

    def _seed_download_card(self, *, plaintext: str, status: str, expired: bool = False, suffix: str = "a"):
        downstream = getattr(self, "_download_downstream", None)
        if downstream is None:
            downstream = create_downstream_direct(
                actor=self.admin,
                username="release-download-ds",
                password="Downstream-password-123",
            )
            self._download_downstream = downstream
            self._download_policy = create_policy_version(
                actor=self.admin,
                software_id="release-tool",
                profile_id="stable",
                version="policy-dl",
                status=PolicyStatus.ACTIVE,
            )
            _plan, snapshot = create_plan(
                actor=self.admin,
                software_id="release-tool",
                profile_id="stable",
                policy_version="policy-dl",
                name="下载卡",
                duration_seconds=30 * 86400,
                quota_cost=15,
                status=PlanStatus.ACTIVE,
            )
            self._download_snapshot = snapshot
            set_downstream_software_access(
                actor=self.admin,
                downstream_public_id=downstream.public_id,
                software_id="release-tool",
                enabled=True,
                all_plans_allowed=True,
            )
        now = timezone.now()
        batch = LicenseCardBatch.objects.create(
            software=self.software,
            profile=self.profile,
            plan_snapshot=self._download_snapshot,
            original_downstream=downstream,
            current_downstream=downstream,
            original_downstream_public_id=downstream.public_id,
            current_downstream_public_id=downstream.public_id,
            quantity=1,
            quota_cost_per_card=15,
            total_quota_cost=15,
            idempotency_key=f"release-dl-{suffix}",
            request_hash=(suffix * 64)[:64],
            created_by=downstream.user,
            created_at=now,
        )
        card = LicenseCard.objects.create(
            batch=batch,
            software=self.software,
            profile=self.profile,
            plan_snapshot=self._download_snapshot,
            original_downstream=downstream,
            current_downstream=downstream,
            original_downstream_public_id=downstream.public_id,
            current_downstream_public_id=downstream.public_id,
            quota_cost=15,
            card_hash=license_card_hash(normalize_license_card_code(plaintext)),
            card_ciphertext=f"cipher-{suffix}",
            status=status,
            issued_by=downstream.user,
            issued_at=now,
            activated_at=None if status != LicenseCardStatus.ACTIVATED else now - timedelta(days=10),
        )
        if status == LicenseCardStatus.ACTIVATED:
            LicenseInstance.objects.create(
                license_card=card,
                software=self.software,
                profile=self.profile,
                plan_snapshot=self._download_snapshot,
                policy_version=self._download_policy,
                current_downstream_public_id=downstream.public_id,
                client_id=self.profile.client_id,
                contract_version="authorization.v1",
                target=self.profile.target,
                arch=self.profile.arch,
                channel=self.profile.channel,
                client_version="1.0.0",
                state=AuthorizationState.ACTIVE,
                activated_at=now - timedelta(days=10),
                expires_at=now - timedelta(days=1) if expired else now + timedelta(days=20),
            )
        return plaintext

    def test_protected_public_download_accepts_active_card_and_rejects_unused_expired_or_rate_limited(self):
        first = self._upload(key="protected-card-download")
        release = Release.objects.get(release_id=first.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": release.release_id}),
            data=json.dumps({"notes": "卡密下载门禁"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="protected-card-publish",
        )
        url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": release.release_id},
        )
        active_key = self._seed_download_card(plaintext="REL-CARD-ACTIVE-0001", status=LicenseCardStatus.ACTIVATED, suffix="a")
        unused_key = self._seed_download_card(plaintext="REL-CARD-UNUSED-0002", status=LicenseCardStatus.UNUSED, suffix="b")
        expired_key = self._seed_download_card(
            plaintext="REL-CARD-EXPIRED-0003",
            status=LicenseCardStatus.ACTIVATED,
            expired=True,
            suffix="c",
        )
        cache.clear()
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True, PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT=1):
            unused = self.client.get(url, HTTP_X_LICENSE_KEY=unused_key, REMOTE_ADDR="127.0.0.1")
            self.assertEqual(unused.status_code, 403)
            self.assertEqual(unused.json()["error"]["code"], "DOWNLOAD_FORBIDDEN")
            expired = self.client.get(url, HTTP_X_LICENSE_KEY=expired_key, REMOTE_ADDR="127.0.0.2")
            self.assertEqual(expired.status_code, 403)
            self.assertEqual(expired.json()["error"]["code"], "DOWNLOAD_FORBIDDEN")
            allowed = self.client.get(url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.3")
            self.assertEqual(allowed.status_code, 200)
            self.assertIn(b"client-release.v1.json", b"".join(allowed.streaming_content))
            limited = self.client.get(url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.3")
            self.assertEqual(limited.status_code, 429)
            self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")
            self.assertEqual(limited["Retry-After"], "1800")

    def test_protected_public_download_does_not_consume_rate_limit_when_package_unavailable(self):
        missing_upload = self._upload(key="missing-pkg-upload", version="1.0.0")
        good_upload = self._upload(key="good-pkg-upload", version="2.0.0")
        missing_release = Release.objects.get(release_id=missing_upload.json()["item"]["release_id"])
        good_release = Release.objects.get(release_id=good_upload.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": missing_release.release_id}),
            data=json.dumps({"notes": "空包不应扣次"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="missing-pkg-publish",
        )
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": good_release.release_id}),
            data=json.dumps({"notes": "好包仍可下"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="good-pkg-publish",
        )
        missing_release.refresh_from_db()
        missing_release.package_path = ""
        missing_release.save(update_fields=("package_path",))
        active_key = self._seed_download_card(
            plaintext="REL-CARD-GONE-0001",
            status=LicenseCardStatus.ACTIVATED,
            suffix="g",
        )
        cache.clear()
        missing_url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": missing_release.release_id},
        )
        good_url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": good_release.release_id},
        )
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True, PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT=1):
            gone = self.client.get(missing_url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.4")
            self.assertEqual(gone.status_code, 410)
            self.assertEqual(gone.json()["error"]["code"], "PACKAGE_UNAVAILABLE")
            allowed = self.client.get(good_url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.4")
            self.assertEqual(allowed.status_code, 200)
            self.assertIn(b"client-release.v1.json", b"".join(allowed.streaming_content))

    def test_protected_public_download_does_not_consume_rate_limit_when_sha_mismatches(self):
        from authorization_platform.releases.services import resolve_release_package_path

        bad_upload = self._upload(key="bad-sha-upload", version="3.0.0")
        good_upload = self._upload(key="good-sha-upload", version="4.0.0")
        bad_release = Release.objects.get(release_id=bad_upload.json()["item"]["release_id"])
        good_release = Release.objects.get(release_id=good_upload.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": bad_release.release_id}),
            data=json.dumps({"notes": "哈希不对不应扣次"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bad-sha-publish",
        )
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": good_release.release_id}),
            data=json.dumps({"notes": "好包仍可下"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="good-sha-after-mismatch-publish",
        )
        bad_release.refresh_from_db()
        package_path = resolve_release_package_path(bad_release.package_path)
        self.assertIsNotNone(package_path)
        original = package_path.read_bytes()
        tampered = bytes(byte ^ 0xFF for byte in original)
        if tampered == original:
            tampered = b"\x00" * len(original)
        package_path.write_bytes(tampered)
        active_key = self._seed_download_card(
            plaintext="REL-CARD-SHA-0001",
            status=LicenseCardStatus.ACTIVATED,
            suffix="h",
        )
        cache.clear()
        bad_url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": bad_release.release_id},
        )
        good_url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": good_release.release_id},
        )
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True, PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT=1):
            mismatch = self.client.get(bad_url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.8")
            self.assertEqual(mismatch.status_code, 410)
            self.assertEqual(mismatch.json()["error"]["code"], "PACKAGE_UNAVAILABLE")
            allowed = self.client.get(good_url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.8")
            self.assertEqual(allowed.status_code, 200)
            self.assertIn(b"client-release.v1.json", b"".join(allowed.streaming_content))

    def test_protected_public_download_honors_verified_signature_gate(self):
        first = self._upload(key="protected-signature-gate")
        release = Release.objects.get(release_id=first.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": release.release_id}),
            data=json.dumps({"notes": "签名门禁直链验收"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="protected-signature-publish",
        )
        release.refresh_from_db()
        release.signature_status = ReleaseSignatureStatus.DECLARED
        release.save(update_fields=("signature_status",))
        active_key = self._seed_download_card(plaintext="REL-CARD-SIGNED-0001", status=LicenseCardStatus.ACTIVATED, suffix="s")
        cache.clear()
        url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": release.release_id},
        )
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True, RELEASE_REQUIRE_VERIFIED_SIGNATURE=True):
            declared = self.client.get(url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.1")
        self.assertEqual(declared.status_code, 404)
        self.assertEqual(declared.json()["error"]["code"], "RELEASE_NOT_FOUND")
        release.signature_status = ReleaseSignatureStatus.VERIFIED
        release.save(update_fields=("signature_status",))
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True, RELEASE_REQUIRE_VERIFIED_SIGNATURE=True):
            allowed = self.client.get(url, HTTP_X_LICENSE_KEY=active_key, REMOTE_ADDR="127.0.0.1")
        self.assertEqual(allowed.status_code, 200)
        self.assertIn(b"client-release.v1.json", b"".join(allowed.streaming_content))

    def test_protected_public_download_rejects_card_from_another_software(self):
        first = self._upload(key="cross-software-download")
        release = Release.objects.get(release_id=first.json()["item"]["release_id"])
        self.client.post(
            reverse("releases:publish", kwargs={"release_id": release.release_id}),
            data=json.dumps({"notes": "跨软件下载门禁"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="cross-software-publish",
        )
        other = create_software(actor=self.admin, software_id="other-tool", name="Other Tool", status=SoftwareStatus.ACTIVE)
        other_profile = create_profile(
            actor=self.admin,
            software_id=other.software_id,
            profile_id="stable",
            client_id="other-tool-windows",
            target="windows",
            arch="x64",
            channel="stable",
            status=ProfileStatus.ACTIVE,
        )
        other_policy = create_policy_version(
            actor=self.admin,
            software_id=other.software_id,
            profile_id="stable",
            version="policy-other",
            status=PolicyStatus.ACTIVE,
        )
        _plan, snapshot = create_plan(
            actor=self.admin,
            software_id=other.software_id,
            profile_id="stable",
            policy_version="policy-other",
            name="外软件卡",
            duration_seconds=30 * 86400,
            quota_cost=15,
            status=PlanStatus.ACTIVE,
        )
        downstream = create_downstream_direct(
            actor=self.admin,
            username="release-other-ds",
            password="Downstream-password-123",
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=downstream.public_id,
            software_id=other.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        now = timezone.now()
        batch = LicenseCardBatch.objects.create(
            software=other,
            profile=other_profile,
            plan_snapshot=snapshot,
            original_downstream=downstream,
            current_downstream=downstream,
            original_downstream_public_id=downstream.public_id,
            current_downstream_public_id=downstream.public_id,
            quantity=1,
            quota_cost_per_card=15,
            total_quota_cost=15,
            idempotency_key="release-dl-other",
            request_hash="cross-software-download-hash".ljust(64, "0")[:64],
            created_by=downstream.user,
            created_at=now,
        )
        plaintext = "REL-CARD-OTHER-SW-01"
        card = LicenseCard.objects.create(
            batch=batch,
            software=other,
            profile=other_profile,
            plan_snapshot=snapshot,
            original_downstream=downstream,
            current_downstream=downstream,
            original_downstream_public_id=downstream.public_id,
            current_downstream_public_id=downstream.public_id,
            quota_cost=15,
            card_hash=license_card_hash(normalize_license_card_code(plaintext)),
            card_ciphertext="cipher-other",
            status=LicenseCardStatus.ACTIVATED,
            issued_by=downstream.user,
            issued_at=now,
            activated_at=now - timedelta(days=10),
        )
        LicenseInstance.objects.create(
            license_card=card,
            software=other,
            profile=other_profile,
            plan_snapshot=snapshot,
            policy_version=other_policy,
            current_downstream_public_id=downstream.public_id,
            client_id="other-tool-windows",
            contract_version="authorization.v1",
            target="windows",
            arch="x64",
            channel="stable",
            client_version="1.0.0",
            state=AuthorizationState.ACTIVE,
            activated_at=now - timedelta(days=10),
            expires_at=now + timedelta(days=20),
        )
        url = reverse(
            "releases:public_download",
            kwargs={"software_id": "release-tool", "profile_id": "stable", "release_id": release.release_id},
        )
        cache.clear()
        with override_settings(RELEASE_DOWNLOAD_REQUIRE_AUTH=True):
            forbidden = self.client.get(url, HTTP_X_LICENSE_KEY=plaintext, REMOTE_ADDR="127.0.0.9")
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json()["error"]["code"], "DOWNLOAD_FORBIDDEN")

    def test_public_registry_rejects_draft_profile(self):
        self.profile.status = ProfileStatus.DRAFT
        self.profile.save(update_fields=("status",))
        response = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable"},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "PROFILE_UNAVAILABLE")

    def test_publish_rechecks_that_the_stored_package_still_exists_and_matches(self):
        uploaded = self._upload(key="publish-missing-package")
        release = Release.objects.get(release_id=uploaded.json()["item"]["release_id"])
        Path(release.package_path).unlink()
        response = self.client.post(
            reverse("releases:publish", kwargs={"release_id": release.release_id}),
            data=json.dumps({"notes": "发布前重新核验包"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="publish-missing-package",
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "PACKAGE_UNAVAILABLE")
        release.refresh_from_db()
        self.assertEqual(release.status, ReleaseStatus.DRAFT)

    def test_public_registry_hides_declared_signature_when_verified_releases_are_required(self):
        uploaded = self._upload(key="declared-only")
        release = Release.objects.get(release_id=uploaded.json()["item"]["release_id"])
        release.status = ReleaseStatus.PUBLISHED
        release.published_at = release.created_at
        release.signature_status = ReleaseSignatureStatus.DECLARED
        release.save(update_fields=("status", "published_at", "signature_status"))
        with override_settings(RELEASE_REQUIRE_VERIFIED_SIGNATURE=True):
            _, selected, has_update = latest_public_release(
                software_id="release-tool",
                profile_id="stable",
                client_id="release-tool-windows",
                target="windows",
                arch="x64",
                channel="stable",
                current_version="1.0.0",
            )
        self.assertIsNone(selected)
        self.assertFalse(has_update)

    def test_production_signed_manifest_covers_payload_without_self_referential_package_hash(self):
        package, public_key = self._signed_package()
        with override_settings(
            RELEASE_REQUIRE_VERIFIED_SIGNATURE=True,
            RELEASE_SIGNING_PUBLIC_KEY=public_key,
            RELEASE_SIGNING_KEY_ID="signed-test-key",
        ):
            response = self.client.post(
                reverse("releases:manage_collection"),
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "release_package": package,
                },
                HTTP_IDEMPOTENCY_KEY="signed-upload-1",
            )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["item"]["signature"]["status"], ReleaseSignatureStatus.VERIFIED)

    # ------------------------------------------------------------------
    # 版本归档与就地改版本号（ADR-0016）
    # ------------------------------------------------------------------

    def _publish_external(self, *, version, key=None, url=None, notes="网盘更新说明足够长"):
        return self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": version,
                    "notes": notes,
                    "external_download_url": url or f"https://pan.example.com/s/release-tool-{version}",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=key or f"external-{version}",
        )

    def _archive(self, release_id, *, key, reason="整理历史版本"):
        return self.client.post(
            reverse("releases:archive", kwargs={"release_id": release_id}),
            data=json.dumps({"reason": reason}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def _rename(self, release_id, *, version, key, reason="同一个网盘地址换了文件"):
        return self.client.post(
            reverse("releases:update_version", kwargs={"release_id": release_id}),
            data=json.dumps({"version": version, "reason": reason}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def test_archive_hides_version_from_default_list_but_keeps_the_number(self):
        published = self._publish_external(version="3.0.0")
        self.assertEqual(published.status_code, 201, published.content)
        release_id = published.json()["item"]["release_id"]

        archived = self._archive(release_id, key="archive-1")
        self.assertEqual(archived.status_code, 200, archived.content)
        item = archived.json()["item"]
        self.assertEqual(item["status"], ReleaseStatus.ARCHIVED)
        self.assertEqual(item["archived_from_status"], ReleaseStatus.PUBLISHED)
        self.assertIsNotNone(item["archived_at"])
        self.assertIsNone(archived.json()["registry_fallback_version"])

        listed = self.client.get(reverse("releases:manage_collection"), {"software_id": "release-tool"})
        self.assertEqual(listed.json()["items"], [])
        archived_list = self.client.get(
            reverse("releases:manage_collection"),
            {"software_id": "release-tool", "status": "archived"},
        )
        self.assertEqual([entry["release_id"] for entry in archived_list.json()["items"]], [release_id])

        replay = self._archive(release_id, key="archive-1")
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        self.assertEqual(Release.objects.filter(software=self.software).count(), 1)

        # 版本号仍占用：重发同号走的是同一行，不再新增历史记录。
        reuse = self._publish_external(version="3.0.0", key="reuse-3-0-0")
        self.assertEqual(reuse.status_code, 200, reuse.content)
        self.assertTrue(reuse.json()["replaced"])
        self.assertEqual(reuse.json()["item"]["status"], ReleaseStatus.PUBLISHED)
        self.assertIsNone(reuse.json()["item"]["archived_at"])
        self.assertEqual(Release.objects.filter(software=self.software).count(), 1)

    def test_archive_published_release_reports_registry_fallback(self):
        self._publish_external(version="3.0.0")
        newer = self._publish_external(version="3.0.1")
        archived = self._archive(newer.json()["item"]["release_id"], key="archive-newer")
        self.assertEqual(archived.status_code, 200, archived.content)
        self.assertEqual(archived.json()["registry_fallback_version"], "3.0.0")
        registry = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(registry.json()["release"]["version"], "3.0.0")

    def test_archive_rejects_draft_and_requires_a_reason(self):
        draft = self._upload(version="3.0.2")
        self.assertEqual(draft.status_code, 201, draft.content)
        release_id = draft.json()["item"]["release_id"]
        rejected = self._archive(release_id, key="archive-draft")
        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(rejected.json()["error"]["code"], "RELEASE_NOT_ARCHIVABLE")

        published = self._publish_external(version="3.0.3")
        short = self._archive(published.json()["item"]["release_id"], key="archive-short", reason="短")
        self.assertEqual(short.status_code, 400)
        self.assertEqual(short.json()["error"]["code"], "INVALID_INPUT")

    def test_update_version_in_place_makes_clients_see_the_update(self):
        published = self._publish_external(version="2.0.8")
        self.assertEqual(published.status_code, 201, published.content)
        release_id = published.json()["item"]["release_id"]

        renamed = self._rename(release_id, version="2.0.9", key="rename-1")
        self.assertEqual(renamed.status_code, 200, renamed.content)
        item = renamed.json()["item"]
        self.assertEqual(item["version"], "2.0.9")
        self.assertEqual(item["manifest"]["version"], "2.0.9")
        self.assertEqual(renamed.json()["previous_version"], "2.0.8")
        self.assertEqual(item["external_download_url"], "https://pan.example.com/s/release-tool-2.0.8")
        self.assertEqual(Release.objects.filter(software=self.software).count(), 1)

        registry = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "2.0.8"},
        )
        self.assertTrue(registry.json()["has_update"])
        self.assertEqual(registry.json()["release"]["version"], "2.0.9")
        up_to_date = self.client.get(
            reverse("releases:public_registry", kwargs={"software_id": "release-tool", "profile_id": "stable"}),
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "2.0.9"},
        )
        self.assertFalse(up_to_date.json()["has_update"])

        replay = self._rename(release_id, version="2.0.9", key="rename-1")
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        audit = AuditEvent.objects.filter(action="release.version.update", outcome=AuditOutcome.SUCCESS).latest("occurred_at")
        self.assertEqual(audit.metadata["before_version"], "2.0.8")
        self.assertEqual(audit.metadata["after_version"], "2.0.9")

    def test_update_version_rejects_lower_number_conflict_and_draft(self):
        self._publish_external(version="2.0.0")
        newer = self._publish_external(version="2.0.1")
        release_id = newer.json()["item"]["release_id"]

        lower = self._rename(release_id, version="1.9.9", key="rename-lower")
        self.assertEqual(lower.status_code, 409)
        self.assertEqual(lower.json()["error"]["code"], "VERSION_NOT_HIGHEST")

        conflict = self._rename(release_id, version="2.0.0", key="rename-conflict")
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "VERSION_ALREADY_EXISTS")

        malformed = self._rename(release_id, version="2.1", key="rename-malformed")
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.json()["error"]["code"], "INVALID_VERSION")

        unchanged = self._rename(release_id, version="2.0.1", key="rename-same")
        self.assertEqual(unchanged.status_code, 409)
        self.assertEqual(unchanged.json()["error"]["code"], "VERSION_UNCHANGED")

        draft = self._upload(version="2.0.2")
        draft_rename = self._rename(draft.json()["item"]["release_id"], version="2.0.3", key="rename-draft")
        self.assertEqual(draft_rename.status_code, 409)
        self.assertEqual(draft_rename.json()["error"]["code"], "RELEASE_NOT_RENUMBERABLE")

    def test_publish_external_with_optional_package_sha256(self):
        invalid_res = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.1.0",
                    "notes": "带哈希发布测试",
                    "external_download_url": "https://pan.example.com/s/test-3-1-0",
                    "package_sha256": "not-a-valid-sha256",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-invalid",
        )
        self.assertEqual(invalid_res.status_code, 400)
        self.assertEqual(invalid_res.json()["error"]["code"], "INVALID_INPUT")

        valid_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        valid_res = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.1.0",
                    "notes": "带哈希发布测试",
                    "external_download_url": "https://pan.example.com/s/test-3-1-0",
                    "package_sha256": valid_sha.upper(),
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-valid",
        )
        self.assertEqual(valid_res.status_code, 201)
        item = valid_res.json()["item"]
        self.assertEqual(item["package_sha256"], valid_sha)

        public_url = reverse(
            "releases:public_registry",
            kwargs={"software_id": "release-tool", "profile_id": "stable"},
        )
        public_res = self.client.get(
            public_url,
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(public_res.status_code, 200)
        body = public_res.json()
        self.assertTrue(body["has_update"])
        self.assertEqual(body["release"]["package_sha256"], valid_sha)
        self.assertEqual(body["release"]["manifest"]["package_sha256"], valid_sha)

        new_sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
        release_id = item["release_id"]
        update_url_res = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": release_id}),
            data=json.dumps(
                {
                    "external_download_url": "https://pan.example.com/s/test-3-1-0-new",
                    "package_sha256": new_sha,
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-update-valid",
        )
        self.assertEqual(update_url_res.status_code, 200)
        updated_public = self.client.get(
            public_url,
            {"client_id": "release-tool-windows", "target": "windows", "arch": "x64", "channel": "stable", "version": "1.0.0"},
        )
        self.assertEqual(updated_public.status_code, 200)
        self.assertEqual(updated_public.json()["release"]["package_sha256"], new_sha)
        self.assertEqual(updated_public.json()["release"]["manifest"]["package_sha256"], new_sha)

    def test_cover_external_without_sha_retains_previous_hash(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        first = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.2.0",
                    "notes": "覆盖保留哈希测试",
                    "external_download_url": "https://pan.example.com/s/test-3-2-0",
                    "package_sha256": sha,
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-retain-first",
        )
        self.assertEqual(first.status_code, 201)

        cover = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.2.0",
                    "notes": "覆盖不带哈希测试",
                    "external_download_url": "https://pan.example.com/s/test-3-2-0",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-retain-cover",
        )
        self.assertEqual(cover.status_code, 200)
        self.assertTrue(cover.json()["replaced"])
        self.assertEqual(cover.json()["item"]["package_sha256"], sha)

    def test_update_url_missing_sha_is_not_confused_with_explicit_clear(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        created = self.client.post(
            reverse("releases:publish_external"),
            data=json.dumps(
                {
                    "software_id": "release-tool",
                    "channel": "stable",
                    "version": "3.3.0",
                    "notes": "幂等哨兵测试",
                    "external_download_url": "https://pan.example.com/s/test-3-3-0",
                    "package_sha256": sha,
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-sentinel-first",
        )
        self.assertEqual(created.status_code, 201)
        release_id = created.json()["item"]["release_id"]

        missing = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": release_id}),
            data=json.dumps({"external_download_url": "https://pan.example.com/s/test-3-3-0-new"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-sentinel-missing",
        )
        self.assertEqual(missing.status_code, 200)
        self.assertEqual(missing.json()["item"]["package_sha256"], sha)

        cleared = self.client.post(
            reverse("releases:update_external_url", kwargs={"release_id": release_id}),
            data=json.dumps(
                {
                    "external_download_url": "https://pan.example.com/s/test-3-3-0-new",
                    "package_sha256": "",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="sha-sentinel-clear",
        )
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.json()["item"]["package_sha256"], "")
