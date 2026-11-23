from __future__ import annotations

import json
import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.catalog.models import (
    PlanStatus,
    PolicyStatus,
    ProfileStatus,
    SoftwareStatus,
)
from authorization_platform.catalog.services import (
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
)


User = get_user_model()


class ProfileConfigurationApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="cfg-admin", password="Admin-password-123"
        )
        software = create_software(
            actor=self.admin,
            software_id="cfg-tool",
            name="Cfg Tool",
            status=SoftwareStatus.ACTIVE,
        )
        profile = create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="cfg-tool-client",
            status=ProfileStatus.ACTIVE,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="Cfg 月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=5,
            status=PlanStatus.ACTIVE,
        )
        self.software_id = software.software_id
        self.profile_id = profile.profile_id

    def _url(self) -> str:
        return reverse(
            "catalog:api_manage_profile_configuration",
            kwargs={"software_id": self.software_id, "profile_id": self.profile_id},
        )

    def _admin_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.get(reverse("accounts:api_session"))
        client.force_login(self.admin)
        return client

    def test_get_default_configuration(self):
        response = self._admin_client().get(self._url())
        self.assertEqual(response.status_code, 200)
        config = response.json()["configuration"]
        self.assertEqual(config["purchase_url"], "")
        self.assertFalse(config["announcement_enabled"])

    def test_post_updates_configuration_and_version(self):
        client = self._admin_client()
        response = client.post(
            self._url(),
            data=json.dumps(
                {
                    "values": {
                        "purchase_url": "https://shop.example/profile",
                        "qq": "9527",
                        "announcement_enabled": True,
                        "announcement_title": "维护公告",
                        "announcement_body": "周六 02:00 维护",
                    }
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["configuration"]["purchase_url"], "https://shop.example/profile")
        self.assertEqual(payload["configuration"]["qq"], "9527")
        self.assertTrue(payload["configuration"]["announcement_enabled"])
        self.assertRegex(payload["config_version"], r"^cfg-")
        # 读取回读一致
        again = client.get(self._url())
        self.assertEqual(again.json()["configuration"]["announcement_body"], "周六 02:00 维护")

    def test_announcement_only_post_does_not_clear_purchase_url(self):
        client = self._admin_client()
        seeded = client.post(
            self._url(),
            data=json.dumps(
                {
                    "values": {
                        "purchase_url": "https://shop.example/keep",
                        "qq": "9527",
                        "announcement_enabled": False,
                    }
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(seeded.status_code, 200)
        response = client.post(
            self._url(),
            data=json.dumps(
                {
                    "values": {
                        "announcement_enabled": True,
                        "announcement_title": "公告",
                        "announcement_body": "只改公告",
                    }
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 200)
        config = response.json()["configuration"]
        self.assertEqual(config["purchase_url"], "https://shop.example/keep")
        self.assertEqual(config["qq"], "9527")
        self.assertEqual(config["announcement_body"], "只改公告")

    def test_invalid_field_rejected(self):
        client = self._admin_client()
        response = client.post(
            self._url(),
            data=json.dumps({"values": {"unknown_field": "x"}}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_CONFIGURATION")

    def test_missing_profile_404(self):
        url = reverse(
            "catalog:api_manage_profile_configuration",
            kwargs={"software_id": self.software_id, "profile_id": "missing"},
        )
        response = self._admin_client().get(url)
        self.assertEqual(response.status_code, 404)

    def test_non_admin_rejected(self):
        downstream = create_downstream_direct(
            actor=self.admin,
            username="cfg-downstream",
            password="Downstream-password-123",
        )
        client = Client()
        client.force_login(downstream.user)
        response = client.get(self._url())
        self.assertIn(response.status_code, (401, 403))