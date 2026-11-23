from __future__ import annotations

import json
import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.catalog.models import (
    DownstreamSoftware,
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
    set_downstream_software_access,
)


User = get_user_model()


class DownstreamSupportApiTests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(
            username="support-admin", password="Admin-password-123"
        )
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="support-downstream",
            password="Downstream-password-123",
        )
        software = create_software(
            actor=self.admin,
            software_id="support-tool",
            name="Support Tool",
            status=SoftwareStatus.ACTIVE,
        )
        profile = create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="support-tool-client",
            status=ProfileStatus.ACTIVE,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        self.plan, self.snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="Support 月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=5,
            status=PlanStatus.ACTIVE,
        )
        self.software_id = software.software_id
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software_id,
            enabled=True,
            all_plans_allowed=True,
        )

    def _downstream_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.get(reverse("accounts:api_session"))
        response = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": "support-downstream",
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 200)
        return client

    def _url(self, software_id: str = None) -> str:
        return reverse(
            "catalog:api_downstream_support",
            kwargs={"software_id": software_id or self.software_id},
        )

    def test_get_support_returns_empty_defaults(self):
        response = self._downstream_client().get(self._url())
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["support"]["purchase_url"], "")
        self.assertEqual(payload["support"]["qq"], "")
        self.assertEqual(payload["support"]["wechat"], "")

    def _post_support(self, client: Client, payload: dict, software_id: str | None = None) -> None:
        return client.post(
            self._url(software_id),
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )

    def test_post_support_updates_and_audits(self):
        client = self._downstream_client()
        response = self._post_support(
            client,
            {
                "values": {
                    "purchase_url": "https://shop.example/buy",
                    "qq": "10001",
                    "wechat": "wx_support",
                }
            },
        )
        self.assertEqual(response.status_code, 200)
        support = response.json()["support"]
        self.assertEqual(support["purchase_url"], "https://shop.example/buy")
        self.assertEqual(support["qq"], "10001")
        access = DownstreamSoftware.objects.select_related("software").get(
            downstream=self.downstream, software_id=self.software_id
        )
        self.assertEqual(access.support_purchase_url, "https://shop.example/buy")
        self.assertTrue(
            AuditEvent.objects.filter(
                action="downstream.configuration.update",
                object_public_id=f"{self.downstream.public_id}:{self.software_id}",
                outcome="success",
            ).exists()
        )

    def test_post_support_clear(self):
        client = self._downstream_client()
        self._post_support(
            client,
            {"values": {"purchase_url": "https://shop.example/buy"}},
        )
        cleared = self._post_support(client, {"clear": True})
        self.assertEqual(cleared.status_code, 200)
        support = cleared.json()["support"]
        self.assertEqual(support["purchase_url"], "")
        access = DownstreamSoftware.objects.get(
            downstream=self.downstream, software_id=self.software_id
        )
        self.assertFalse(access.configuration_enabled)

    def test_unopened_software_returns_404(self):
        response = self._downstream_client().get(self._url(software_id="not-open"))
        self.assertEqual(response.status_code, 404)

    def test_anonymous_and_admin_rejected(self):
        anonymous = self.client.get(self._url())
        self.assertIn(anonymous.status_code, (401, 403))
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_response = admin_client.get(self._url())
        self.assertEqual(admin_response.status_code, 403)

    def test_post_support_omits_wechat_without_clearing_stored_value(self):
        client = self._downstream_client()
        seeded = self._post_support(
            client,
            {
                "values": {
                    "purchase_url": "https://shop.example/buy",
                    "qq": "10001",
                    "wechat": "wx_keep",
                }
            },
        )
        self.assertEqual(seeded.status_code, 200)
        omitted = self._post_support(
            client,
            {
                "values": {
                    "purchase_url": "https://shop.example/new",
                    "qq": "10002",
                }
            },
        )
        self.assertEqual(omitted.status_code, 200)
        support = omitted.json()["support"]
        self.assertEqual(support["purchase_url"], "https://shop.example/new")
        self.assertEqual(support["qq"], "10002")
        self.assertEqual(support["wechat"], "wx_keep")
        access = DownstreamSoftware.objects.get(
            downstream=self.downstream, software_id=self.software_id
        )
        self.assertEqual(access.support_wechat, "wx_keep")

        cleared = self._post_support(client, {"values": {"wechat": ""}})
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.json()["support"]["wechat"], "")
        access.refresh_from_db()
        self.assertEqual(access.support_wechat, "")
        self.assertEqual(access.support_qq, "10002")
        self.assertEqual(access.support_purchase_url, "https://shop.example/new")