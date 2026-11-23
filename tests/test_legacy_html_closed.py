from __future__ import annotations

from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus
from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.backup_control.services import get_policy
from authorization_platform.catalog.models import DownstreamSoftware, Software, SoftwareStatus
from authorization_platform.catalog.services import create_software, set_downstream_software_access
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY
from authorization_platform.storage_cleanup.models import StorageCleanupOperation


User = get_user_model()


def _assert_closed(test, response):
    test.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
    test.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)
    test.assertNotContains(response, "撤销授权", status_code=410)
    test.assertNotContains(response, "阻断设备", status_code=410)


class LegacyHtmlWriteClosedTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="legacy-html-admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="legacy-html-down",
            password="Downstream-password-123",
        )
        self.admin_client = Client()
        self.admin_client.force_login(self.admin)
        self.down_client = Client()
        login = self.down_client.post(
            reverse("accounts:downstream_login"),
            {"username": "legacy-html-down", "password": "Downstream-password-123"},
        )
        self.assertEqual(login.status_code, 302)

    def test_read_dashboards_stay_open_while_html_writes_close(self):
        self.assertEqual(self.admin_client.get(reverse("accounts:manage_dashboard")).status_code, 200)
        self.assertEqual(self.admin_client.get(reverse("accounts:downstream_list")).status_code, 200)
        created = self.admin_client.post(
            reverse("accounts:downstream_create"),
            {"username": "should-not-exist", "password": "Downstream-password-123"},
        )
        _assert_closed(self, created)
        self.assertFalse(User.objects.filter(username="should-not-exist").exists())
        issue = self.admin_client.post(
            reverse("accounts:api_invitation_collection"),
            data={"quantity": 1},
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="legacy-html-api-still-writes",
        )
        self.assertEqual(issue.status_code, 201)
        self.assertTrue(issue.json()["items"][0]["code"])

    def test_html_archive_does_not_change_downstream(self):
        response = self.admin_client.post(
            reverse("accounts:downstream_archive", kwargs={"public_id": self.downstream.public_id}),
            {"reason": "旧页归档"},
        )
        _assert_closed(self, response)
        self.assertEqual(
            DownstreamProfile.objects.get(public_id=self.downstream.public_id).status,
            DownstreamStatus.ACTIVE,
        )

    def test_html_backup_dashboard_and_cleanup_do_not_write(self):
        policy = get_policy()
        before_enabled = policy.enabled
        before_retention = policy.retention_full
        before_updated = policy.updated_at
        get_page = self.admin_client.get(reverse("backup_control:dashboard"))
        _assert_closed(self, get_page)
        posted = self.admin_client.post(
            reverse("backup_control:dashboard"),
            {
                "enabled": "on",
                "database_enabled": "on",
                "cleanup_enabled": "on",
                "retention_full": "99",
                "retention_diff": "99",
                "retention_archive": "99",
                "github_retention_count": "99",
            },
        )
        _assert_closed(self, posted)
        policy.refresh_from_db()
        self.assertEqual(policy.enabled, before_enabled)
        self.assertEqual(policy.retention_full, before_retention)
        self.assertEqual(policy.updated_at, before_updated)
        cleanup_count = StorageCleanupOperation.objects.count()
        cleanup = self.admin_client.post(reverse("backup_control:cleanup"), {"confirmation": "1"})
        _assert_closed(self, cleanup)
        self.assertEqual(StorageCleanupOperation.objects.count(), cleanup_count)

    def test_html_catalog_status_and_access_and_profile_config_do_not_write(self):
        software = create_software(
            actor=self.admin,
            software_id="legacy-html-tool",
            name="旧页软件",
            status=SoftwareStatus.ACTIVE,
        )
        status_response = self.admin_client.post(
            reverse("catalog:software_status_update", kwargs={"software_id": software.software_id}),
            {"status": "archived"},
        )
        _assert_closed(self, status_response)
        self.assertEqual(Software.objects.get(pk=software.software_id).status, SoftwareStatus.ACTIVE)
        access_response = self.admin_client.post(
            reverse("catalog:software_access", kwargs={"software_id": software.software_id}),
            {"downstream": str(self.downstream.public_id), "enabled": "on"},
        )
        _assert_closed(self, access_response)
        self.assertFalse(
            DownstreamSoftware.objects.filter(
                software_id=software.software_id,
                downstream=self.downstream,
            ).exists()
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=software.software_id,
            enabled=True,
        )
        config_response = self.down_client.post(
            reverse("catalog:downstream_configuration", kwargs={"software_id": software.software_id}),
            {"purchase_url": "https://shop.example/legacy", "qq": "999"},
        )
        _assert_closed(self, config_response)
        access = DownstreamSoftware.objects.get(software=software, downstream=self.downstream)
        self.assertEqual(access.support_purchase_url, "")


class LegacyHtmlCopySourceTests(SimpleTestCase):
    def test_old_api_copy_is_not_served_from_html_views(self):
        root = Path(__file__).resolve().parents[1] / "src" / "authorization_platform"
        hits = []
        for path in root.rglob("views.py"):
            text = path.read_text(encoding="utf-8")
            if FORBIDDEN_API_COPY in text:
                hits.append(str(path.relative_to(root)))
        self.assertEqual(hits, [])
