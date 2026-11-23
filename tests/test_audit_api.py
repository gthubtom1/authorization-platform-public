from __future__ import annotations

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.services import record_event
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import create_plan, create_policy_version, create_profile, create_software
from authorization_platform.licensing.models import AuthorizationState, LicenseCard, LicenseCardBatch, LicenseCardStatus, LicenseInstance


User = get_user_model()


class AuditApiTests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(
            username="audit-admin", password="Admin-password-123"
        )
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="audit-downstream",
            password="Downstream-password-123",
        )
        self.other_downstream = create_downstream_direct(
            actor=self.admin,
            username="audit-downstream-other",
            password="Downstream-password-123",
        )
        # 生成不同类型审计事件
        record_event(
            actor=self.downstream.user,
            action="license_card.issue",
            outcome=AuditOutcome.SUCCESS,
            object_type="LicenseCard",
            object_public_id="11111111-1111-1111-1111-111111111111",
            metadata={"downstream_public_id": str(self.downstream.public_id)},
        )
        record_event(
            actor=None,
            action="license.activate",
            outcome=AuditOutcome.SUCCESS,
            object_type="LicenseInstance",
            object_public_id="22222222-2222-2222-2222-222222222222",
            metadata={"current_downstream_public_id": str(self.downstream.public_id)},
        )
        record_event(
            actor=None,
            action="license.verify",
            outcome=AuditOutcome.FAILURE,
            object_type="LicenseInstance",
            object_public_id="33333333-3333-3333-3333-333333333333",
            metadata={"current_downstream_public_id": str(self.other_downstream.public_id)},
        )
        record_event(
            actor=self.admin,
            action="downstream.archive",
            outcome=AuditOutcome.SUCCESS,
            object_type="DownstreamProfile",
            object_public_id=str(self.other_downstream.public_id),
        )

    def _admin_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        return client

    def _downstream_client(self, user=None) -> Client:
        client = Client(enforce_csrf_checks=True)
        username = (user or self.downstream.user).username
        client.get(reverse("accounts:api_session"))
        response = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {"username": username, "password": "Downstream-password-123", "entrypoint": "downstream"}
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 200)
        return client

    def test_admin_sees_all_events(self):
        response = self._admin_client().get(reverse("audit:api_manage_audit"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        # 含账号创建等铺垫事件，所以是 >=4；且包含本测试的四类事件
        self.assertGreaterEqual(payload["count"], 4)
        actions = {item["action"] for item in payload["items"]}
        self.assertIn("license_card.issue", actions)
        self.assertIn("license.activate", actions)
        self.assertIn("downstream.archive", actions)
        first = payload["items"][0]
        for key in (
            "occurred_at",
            "actor_label",
            "actor_role",
            "action",
            "outcome",
            "object_type",
            "object_summary",
        ):
            self.assertIn(key, first)

    def test_admin_filter_outcome_and_role(self):
        client = self._admin_client()
        failed = client.get(reverse("audit:api_manage_audit"), {"outcome": "failure"})
        self.assertEqual(failed.json()["count"], 1)
        client_events = client.get(
            reverse("audit:api_manage_audit"), {"actor_role": "anonymous"}
        )
        self.assertGreaterEqual(client_events.json()["count"], 2)

    def test_admin_action_filter(self):
        response = self._admin_client().get(
            reverse("audit:api_manage_audit"), {"action": "license_card.issue"}
        )
        self.assertEqual(response.json()["count"], 1)

    def test_downstream_only_sees_owned_scope(self):
        response = self._downstream_client().get(reverse("audit:api_downstream_audit"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        # 归属过滤：自己发卡 + 自己客户的激活；不含其他下游的验证失败
        actions = {item["action"] for item in payload["items"]}
        self.assertIn("license_card.issue", actions)
        self.assertIn("license.activate", actions)
        self.assertNotIn("license.verify", actions)
        for item in payload["items"]:
            self.assertIn(item["ip_address"], {"未记录", "127.0.0.1"})

    def test_downstream_scope_mine_and_client(self):
        client = self._downstream_client()
        mine = client.get(reverse("audit:api_downstream_audit"), {"scope": "mine"})
        mine_actions = {item["action"] for item in mine.json()["items"]}
        self.assertIn("license_card.issue", mine_actions)
        client_scope = client.get(reverse("audit:api_downstream_audit"), {"scope": "client"})
        client_actions = {item["action"] for item in client_scope.json()["items"]}
        self.assertIn("license.activate", client_actions)
        self.assertNotIn("license_card.issue", client_actions)

    def test_downstream_invalid_scope_rejected(self):
        response = self._downstream_client().get(
            reverse("audit:api_downstream_audit"), {"scope": "other"}
        )
        self.assertEqual(response.status_code, 400)

    def test_anonymous_rejected(self):
        response = self.client.get(reverse("audit:api_manage_audit"))
        self.assertIn(response.status_code, (401, 403))
        response = self.client.get(reverse("audit:api_downstream_audit"))
        self.assertIn(response.status_code, (401, 403))

    def test_downstream_scope_from_date(self):
        from datetime import date

        response = self._downstream_client().get(
            reverse("audit:api_downstream_audit"),
            {"from_date": date.today().isoformat()},
        )
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json()["count"], 2)

    def test_downstream_export_csv(self):
        response = self._downstream_client().get(
            reverse("audit:api_downstream_audit_export"), {"scope": "all"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        content = response.content.decode("utf-8")
        self.assertIn("时间", content)
        self.assertIn("license_card.issue", content)
        self.assertIn("127.0.0.1", content)

    def test_admin_export_is_audited_and_invalid_filters_fail_closed(self):
        client = self._admin_client()
        invalid = client.get(reverse("audit:api_manage_audit_export"), {"from_date": "not-a-date"})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["error"]["code"], "INVALID_FILTER")
        self.assertTrue(AuditEvent.objects.filter(action="audit.export", outcome=AuditOutcome.FAILURE).exists())

        exported = client.get(reverse("audit:api_manage_audit_export"), {"action": "license_card.issue"})
        self.assertEqual(exported.status_code, 200)
        self.assertTrue(AuditEvent.objects.filter(action="audit.export", outcome=AuditOutcome.SUCCESS).exists())

    def test_admin_filter_by_downstream_and_software(self):
        client = self._admin_client()
        by_downstream = client.get(
            reverse("audit:api_manage_audit"),
            {"downstream_public_id": str(self.downstream.public_id)},
        )
        self.assertEqual(by_downstream.status_code, 200)
        actions = {item["action"] for item in by_downstream.json()["items"]}
        self.assertIn("license_card.issue", actions)
        by_software = client.get(
            reverse("audit:api_manage_audit"), {"software_id": "some-software"}
        )
        self.assertEqual(by_software.status_code, 200)

    def test_admin_downstream_filter_hits_real_login_and_activate_shapes(self):
        record_event(
            actor=self.downstream.user,
            action="auth.login",
            outcome=AuditOutcome.SUCCESS,
            object_type="DownstreamProfile",
            object_public_id=str(self.downstream.public_id),
            metadata={},
        )
        record_event(
            actor=self.other_downstream.user,
            action="auth.login",
            outcome=AuditOutcome.SUCCESS,
            object_type="DownstreamProfile",
            object_public_id=str(self.other_downstream.public_id),
            metadata={},
        )
        now = timezone.now()
        software = create_software(
            actor=self.admin,
            software_id="audit-activate-filter-tool",
            name="Audit Activate Filter",
            status=SoftwareStatus.ACTIVE,
        )
        profile = create_profile(
            actor=self.admin,
            software_id="audit-activate-filter-tool",
            profile_id="stable",
            client_id="audit-activate-filter-windows",
            status=ProfileStatus.ACTIVE,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id="audit-activate-filter-tool",
            profile_id="stable",
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        _, snapshot = create_plan(
            actor=self.admin,
            software_id="audit-activate-filter-tool",
            profile_id="stable",
            policy_version="policy-1",
            name="月卡",
            duration_seconds=30 * 86400,
            quota_cost=15,
            status=PlanStatus.ACTIVE,
        )
        batch = LicenseCardBatch.objects.create(
            software=software,
            profile=profile,
            plan_snapshot=snapshot,
            original_downstream=self.downstream,
            current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id,
            current_downstream_public_id=self.downstream.public_id,
            quantity=1,
            quota_cost_per_card=15,
            total_quota_cost=15,
            idempotency_key="audit-activate-filter-batch",
            request_hash="a" * 64,
            created_by=self.downstream.user,
            created_at=now,
        )
        card = LicenseCard.objects.create(
            batch=batch,
            software=software,
            profile=profile,
            plan_snapshot=snapshot,
            original_downstream=self.downstream,
            current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id,
            current_downstream_public_id=self.downstream.public_id,
            quota_cost=15,
            card_hash="b" * 64,
            card_ciphertext="cipher",
            status=LicenseCardStatus.ACTIVATED,
            issued_by=self.downstream.user,
            issued_at=now,
            activated_at=now,
            expires_at=now + timedelta(days=29),
        )
        instance = LicenseInstance.objects.create(
            license_card=card,
            software=software,
            profile=profile,
            plan_snapshot=snapshot,
            policy_version=policy,
            current_downstream_public_id=self.downstream.public_id,
            client_id=profile.client_id,
            contract_version="authorization.v1",
            target="windows",
            arch="x64",
            channel="stable",
            client_version="1.0.0",
            state=AuthorizationState.ACTIVE,
            activated_at=now,
            expires_at=now + timedelta(days=29),
        )
        record_event(
            actor=None,
            action="authorization.activate",
            outcome=AuditOutcome.SUCCESS,
            object_type="LicenseInstance",
            object_public_id=str(instance.authorization_id),
            metadata={
                "repeated": False,
                "authorization_revision": instance.authorization_revision,
                "device_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            },
        )
        record_event(
            actor=None,
            action="authorization.activate",
            outcome=AuditOutcome.SUCCESS,
            object_type="LicenseInstance",
            object_public_id="99999999-9999-9999-9999-999999999999",
            metadata={
                "repeated": False,
                "authorization_revision": 1,
                "device_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            },
        )
        client = self._admin_client()
        response = client.get(
            reverse("audit:api_manage_audit"),
            {"downstream_public_id": str(self.downstream.public_id), "page_size": 100},
        )
        self.assertEqual(response.status_code, 200)
        items = response.json()["items"]
        actions = {item["action"] for item in items}
        self.assertIn("auth.login", actions)
        self.assertIn("authorization.activate", actions)
        self.assertIn("license_card.issue", actions)
        login_ids = {item["object_public_id"] for item in items if item["action"] == "auth.login"}
        self.assertIn(str(self.downstream.public_id), login_ids)
        self.assertNotIn(str(self.other_downstream.public_id), login_ids)
        activate_ids = {
            item["object_public_id"] for item in items if item["action"] == "authorization.activate"
        }
        self.assertIn(str(instance.authorization_id), activate_ids)
        self.assertNotIn("99999999-9999-9999-9999-999999999999", activate_ids)
        four_key_activate = {
            item["object_public_id"] for item in items if item["action"] == "license.activate"
        }
        self.assertIn("22222222-2222-2222-2222-222222222222", four_key_activate)

    def test_admin_audit_honors_page_size_and_second_page(self):
        client = self._admin_client()
        first = client.get(reverse("audit:api_manage_audit"), {"page_size": 1, "page": 1})
        second = client.get(reverse("audit:api_manage_audit"), {"page_size": 1, "page": 2})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["page_size"], 1)
        self.assertEqual(len(first.json()["items"]), 1)
        self.assertEqual(len(second.json()["items"]), 1)
        self.assertGreaterEqual(first.json()["count"], 2)
        self.assertTrue(first.json()["has_next"])
        self.assertNotEqual(
            (first.json()["items"][0]["action"], first.json()["items"][0]["object_public_id"]),
            (second.json()["items"][0]["action"], second.json()["items"][0]["object_public_id"]),
        )

    def test_admin_audit_q_matches_action_label_and_code_without_suffix_search(self):
        client = self._admin_client()
        by_code = client.get(reverse("audit:api_manage_audit"), {"q": "license_card.issue", "page_size": 100})
        self.assertEqual(by_code.status_code, 200)
        actions = {item["action"] for item in by_code.json()["items"]}
        self.assertEqual(actions, {"license_card.issue"})
        by_label = client.get(reverse("audit:api_manage_audit"), {"q": "生成授权卡", "page_size": 100})
        self.assertEqual(by_label.status_code, 200)
        self.assertEqual({item["action"] for item in by_label.json()["items"]}, {"license_card.issue"})
        too_long = client.get(reverse("audit:api_manage_audit"), {"q": "x" * 129})
        self.assertEqual(too_long.status_code, 400)
        self.assertEqual(too_long.json()["error"]["code"], "INVALID_FILTER")

    def test_downstream_audit_uses_sql_scope_and_returns_plain_object_ids(self):
        client = self._downstream_client()
        response = client.get(reverse("audit:api_downstream_audit"), {"page_size": 100})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        actions = {item["action"] for item in payload["items"]}
        self.assertIn("license_card.issue", actions)
        self.assertIn("license.activate", actions)
        self.assertNotIn("license.verify", actions)
        self.assertNotIn("downstream.archive", actions)
        object_ids = {item["object_public_id"] for item in payload["items"]}
        self.assertIn("11111111-1111-1111-1111-111111111111", object_ids)
        self.assertIn("22222222-2222-2222-2222-222222222222", object_ids)
        self.assertTrue(all("…" not in item["object_public_id"] for item in payload["items"]))
        mine = client.get(reverse("audit:api_downstream_audit"), {"scope": "mine", "page_size": 100})
        mine_actions = {item["action"] for item in mine.json()["items"]}
        self.assertIn("license_card.issue", mine_actions)
        self.assertNotIn("license.activate", mine_actions)
        exported = client.get(reverse("audit:api_downstream_audit_export"))
        self.assertEqual(exported.status_code, 200)
        body = exported.content.decode("utf-8")
        self.assertIn("11111111-1111-1111-1111-111111111111", body)
        self.assertNotIn("1111…1111", body)