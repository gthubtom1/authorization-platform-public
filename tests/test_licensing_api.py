from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import (
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    set_downstream_software_access,
)
from authorization_platform.credits.models import QuotaLedgerEntry
from authorization_platform.credits.services import credit_quota, get_quota_account
from authorization_platform.licensing.models import (
    AuthorizationState,
    Device,
    DeviceBinding,
    DeviceBindingState,
    DeviceKey,
    LicenseCard,
    LicenseCardBatch,
    LicenseCardStatus,
    LicenseInstance,
    LicenseReclaimOperation,
)


User = get_user_model()
RECLAIM_REASON = "回收未激活授权卡密作废"


class LicensingApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(username="api-admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(
            actor=self.admin,
            username="api-downstream-a",
            password="Downstream-password-123",
        )
        self.downstream_b = create_downstream_direct(
            actor=self.admin,
            username="api-downstream-b",
            password="Downstream-password-123",
        )
        software = create_software(
            actor=self.admin,
            software_id="api-license-tool",
            name="API License Tool",
            status=SoftwareStatus.ACTIVE,
        )
        profile = create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="api-license-tool-client",
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
            name="API 月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=5,
            status=PlanStatus.ACTIVE,
        )
        self.software_id = software.software_id
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_b.public_id,
            software_id=self.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=100,
            reason="API 发卡测试准备",
            idempotency_key="api-license-credit-a",
        )
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_b,
            amount=100,
            reason="API 发卡测试准备",
            idempotency_key="api-license-credit-b",
        )

    def _csrf(self, client: Client) -> dict[str, str]:
        response = client.get(reverse("accounts:api_session"))
        self.assertEqual(response.status_code, 200)
        return {"HTTP_X_CSRFTOKEN": client.cookies["csrftoken"].value}

    def _post_json(self, client: Client, url: str, payload: dict, *, key: str):
        headers = self._csrf(client)
        headers["HTTP_IDEMPOTENCY_KEY"] = key
        return client.post(url, data=json.dumps(payload), content_type="application/json", **headers)

    def _admin_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        return client

    def _downstream_client(self, username: str = "api-downstream-a") -> Client:
        client = Client(enforce_csrf_checks=True)
        headers = self._csrf(client)
        response = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": username,
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 200)
        return client

    def _preview(self, client: Client, *, quantity: int = 1, key: str = "preview-1"):
        return self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": quantity},
            key=key,
        )

    def _issue(self, client: Client, preview: dict, *, quantity: int | None = None, key: str = "issue-1"):
        quantity = preview["quantity"] if quantity is None else quantity
        return self._post_json(
            client,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": preview["snapshot_id"],
                "quantity": quantity,
                "preview_token": preview["preview_token"],
            },
            key=key,
        )

    def test_anonymous_preview_and_list_are_rejected(self):
        preview = self.client.post(
            reverse("licensing:api_downstream_license_preview"),
            data=json.dumps({"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": 1}),
            content_type="application/json",
        )
        self.assertEqual(preview.status_code, 403)
        self.assertEqual(preview.json()["error"]["code"], "CSRF_FAILED")
        listed = self.client.get(reverse("licensing:api_downstream_license_cards"))
        self.assertEqual(listed.status_code, 401)

    def test_testing_software_only_exposes_test_only_plan_for_repeatable_issue_path(self):
        software = create_software(
            actor=self.admin,
            software_id="api-testing-tool",
            name="API Testing Tool",
            status=SoftwareStatus.TESTING,
        )
        profile = create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="api-testing-tool-client",
            status=ProfileStatus.TESTING,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        test_plan, _ = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="测试套餐",
            duration_seconds=60,
            quota_cost=1,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        production_plan, _ = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="错误正式套餐",
            duration_seconds=3600,
            quota_cost=1,
            test_only=False,
            status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        client = self._downstream_client()
        rejected = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": software.software_id, "plan_id": production_plan.pk, "quantity": 1},
            key="testing-production-plan",
        )
        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(rejected.json()["error"]["code"], "PLAN_NOT_AVAILABLE")
        accepted = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": software.software_id, "plan_id": test_plan.pk, "quantity": 1},
            key="testing-test-plan",
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertTrue(accepted.json()["test_only"])

    def test_preview_issue_list_and_replay_are_single_card_contract(self):
        client = self._downstream_client()
        preview_response = self._preview(client, quantity=2, key="preview-success")
        self.assertEqual(preview_response.status_code, 200)
        preview = preview_response.json()
        self.assertEqual(preview["total_quota_cost"], 10)
        self.assertTrue(preview["sufficient_balance"])
        self.assertEqual(preview["expires_in"], 600)
        self.assertNotIn("batch_id", preview)

        first = self._issue(client, preview, key="issue-success")
        repeated = self._issue(client, preview, key="issue-success")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(repeated.status_code, 201)
        self.assertFalse(first.json()["repeated"])
        self.assertTrue(repeated.json()["repeated"])
        self.assertEqual(
            [item["code"] for item in first.json()["items"]],
            [item["code"] for item in repeated.json()["items"]],
        )
        self.assertEqual(len(first.json()["items"]), 2)
        self.assertTrue(all(item["code"].startswith("LC-") for item in first.json()["items"]))
        self.assertNotIn("batch_id", first.json())
        self.assertEqual(LicenseCard.objects.count(), 2)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").count(), 1)
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 90)

        listed = client.get(reverse("licensing:api_downstream_license_cards"))
        self.assertEqual(listed.status_code, 200)
        payload = listed.json()
        self.assertEqual(payload["pagination"]["total"], 2)
        self.assertNotIn("batch_id", payload["items"][0])
        self.assertNotIn("code", payload["items"][0])
        self.assertTrue(payload["items"][0]["masked_code"].startswith("••••-••••-"))

    def test_insufficient_balance_and_preview_mismatch_do_not_create_cards(self):
        client = self._downstream_client()
        preview_response = self._preview(client, quantity=21, key="preview-insufficient")
        self.assertEqual(preview_response.status_code, 200)
        preview = preview_response.json()
        self.assertFalse(preview["sufficient_balance"])
        insufficient = self._issue(client, preview, key="issue-insufficient")
        self.assertEqual(insufficient.status_code, 409)
        self.assertEqual(insufficient.json()["error"]["code"], "INSUFFICIENT_QUOTA")
        self.assertEqual(LicenseCard.objects.count(), 0)

        fresh_preview = self._preview(client, quantity=1, key="preview-mismatch")
        mismatch = self._issue(client, fresh_preview.json(), quantity=2, key="issue-mismatch")
        self.assertEqual(mismatch.status_code, 409)
        self.assertEqual(mismatch.json()["error"]["code"], "PREVIEW_MISMATCH")
        self.assertEqual(LicenseCard.objects.count(), 0)

    def test_admin_license_scope_separates_archived_cards(self):
        cache.clear()
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="admin-scope-preview").json()
        issued = self._issue(downstream, preview, key="admin-scope-issue").json()["items"][0]
        admin = self._admin_client()
        reclaimed = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": [issued["public_id"]], "reason": RECLAIM_REASON},
            key="admin-scope-reclaim",
        )
        self.assertEqual(reclaimed.status_code, 200)
        archived = self._post_json(
            admin,
            reverse("licensing:api_manage_license_archive"),
            {"card_ids": [issued["public_id"]], "reason": "分类测试"},
            key="admin-scope-archive",
        )
        self.assertEqual(archived.status_code, 200)
        url = reverse("licensing:api_manage_license_cards")
        current = admin.get(url, {"scope": "current"}).json()
        archived_page = admin.get(url, {"scope": "archived"}).json()
        all_cards = admin.get(url, {"scope": "all"}).json()
        self.assertEqual(current["pagination"]["total"], 0)
        self.assertEqual(archived_page["pagination"]["total"], 1)
        self.assertEqual(all_cards["pagination"]["total"], 1)
        self.assertEqual(archived_page["items"][0]["status"], LicenseCardStatus.ARCHIVED)
        downstream_list = downstream.get(reverse("licensing:api_downstream_license_cards"))
        self.assertEqual(downstream_list.status_code, 200)
        self.assertEqual(downstream_list.json()["pagination"]["total"], 0)
        archived_filter = downstream.get(
            reverse("licensing:api_downstream_license_cards"),
            {"status": LicenseCardStatus.ARCHIVED},
        )
        self.assertEqual(archived_filter.status_code, 400)
        self.assertEqual(archived_filter.json()["error"]["code"], "INVALID_STATUS")
        disabled_filter = admin.get(url, {"status": "disabled"})
        self.assertEqual(disabled_filter.status_code, 400)
        self.assertEqual(disabled_filter.json()["error"]["code"], "INVALID_STATUS")
        archived_scope = downstream.get(
            reverse("licensing:api_downstream_license_cards"),
            {"scope": "archived"},
        )
        self.assertEqual(archived_scope.status_code, 400)
        self.assertEqual(archived_scope.json()["error"]["code"], "INVALID_QUERY")
        archived_search = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_card_search"),
            {"code": issued["code"]},
            key="admin-scope-archived-search",
        )
        self.assertEqual(archived_search.status_code, 404)
        self.assertEqual(archived_search.json()["error"]["code"], "LICENSE_CARD_NOT_FOUND")
        archived_reveal = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reveal", kwargs={"public_id": issued["public_id"]}),
            {},
            key="admin-scope-archived-reveal",
        )
        self.assertEqual(archived_reveal.status_code, 404)
        self.assertEqual(archived_reveal.json()["error"]["code"], "LICENSE_CARD_NOT_FOUND")

    def test_license_card_list_and_search_expose_bound_device_id_and_ip(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="mask-device-preview").json()
        issued = self._issue(downstream, preview, key="mask-device-issue").json()["items"][0]
        card = LicenseCard.objects.get(public_id=issued["public_id"])
        now = timezone.now()
        card.status = LicenseCardStatus.ACTIVATED
        card.activated_at = now
        card.save(update_fields=("status", "activated_at"), _allow_mutation=True)
        profile = card.profile
        instance = LicenseInstance.objects.create(
            license_card=card,
            software=card.software,
            profile=profile,
            plan_snapshot=card.plan_snapshot,
            policy_version=card.plan_snapshot.policy_version,
            current_downstream_public_id=card.current_downstream_public_id,
            client_id=profile.client_id,
            target=profile.target,
            arch=profile.arch,
            channel=profile.channel,
            client_version="1.0.0",
            state=AuthorizationState.ACTIVE,
            activated_at=now,
            expires_at=now + timedelta(days=20),
        )
        device = Device.objects.create(
            software=card.software,
            profile=profile,
            installation_hash="a" * 64,
            installation_id="GS-65FB-F502-B439-270C",
            last_ip="203.0.113.24",
        )
        device_key = DeviceKey.objects.create(
            key_id="license-list-mask-key",
            device=device,
            public_key="test-public-key",
        )
        DeviceBinding.objects.create(
            authorization=instance,
            device=device,
            device_key=device_key,
            state=DeviceBindingState.ACTIVE,
        )
        listed = downstream.get(reverse("licensing:api_downstream_license_cards"))
        self.assertEqual(listed.status_code, 200)
        item = listed.json()["items"][0]
        encoded = json.dumps(item)
        self.assertIn(str(device.public_id), encoded)
        self.assertIn("203.0.113.24", encoded)
        self.assertEqual(item["device"], "GS-65FB-F502-B439-270C · 已绑定")
        self.assertEqual(item["device_code"], "GS-65FB-F502-B439-270C")
        self.assertEqual(item["installation_id"], "GS-65FB-F502-B439-270C")
        self.assertEqual(item["device_uuid"], str(device.public_id))
        self.assertEqual(item["ip"], "203.0.113.24")
        admin = self._admin_client()
        admin_listed = admin.get(reverse("licensing:api_manage_license_cards"))
        self.assertEqual(admin_listed.status_code, 200)
        admin_item = admin_listed.json()["items"][0]
        self.assertIn(str(device.public_id), json.dumps(admin_item))
        self.assertEqual(admin_item["device"], "GS-65FB-F502-B439-270C · 已绑定")
        self.assertEqual(admin_item["device_code"], "GS-65FB-F502-B439-270C")
        self.assertEqual(admin_item["device_uuid"], str(device.public_id))
        self.assertEqual(admin_item["ip"], "203.0.113.24")
        by_device_code = downstream.get(reverse("licensing:api_downstream_license_cards"), {"q": "GS-65FB-F502-B439-270C"})
        self.assertEqual(by_device_code.status_code, 200)
        self.assertEqual(by_device_code.json()["pagination"]["total"], 1)
        admin_by_device_code = admin.get(reverse("licensing:api_manage_license_cards"), {"q": "GS-65FB-F502-B439-270C"})
        self.assertEqual(admin_by_device_code.status_code, 200)
        self.assertEqual(admin_by_device_code.json()["pagination"]["total"], 1)
        searched = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_card_search"),
            {"code": issued["code"]},
            key="mask-device-search",
        )
        self.assertEqual(searched.status_code, 200)
        self.assertIn(str(device.public_id), json.dumps(searched.json()))
        self.assertEqual(searched.json()["item"]["device"], "GS-65FB-F502-B439-270C · 已绑定")
        self.assertEqual(searched.json()["item"]["device_code"], "GS-65FB-F502-B439-270C")
        self.assertEqual(searched.json()["item"]["ip"], "203.0.113.24")
        admin_searched = self._post_json(
            admin,
            reverse("licensing:api_manage_license_card_search"),
            {"code": issued["code"]},
            key="mask-device-admin-search",
        )
        self.assertEqual(admin_searched.status_code, 200)
        self.assertIn(str(device.public_id), json.dumps(admin_searched.json()))
        self.assertEqual(admin_searched.json()["item"]["device"], "GS-65FB-F502-B439-270C · 已绑定")
        self.assertEqual(admin_searched.json()["item"]["device_code"], "GS-65FB-F502-B439-270C")
        self.assertEqual(admin_searched.json()["item"]["ip"], "203.0.113.24")

    def test_card_details_keep_latest_expired_binding_and_plain_device_ip(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="expired-binding-preview").json()
        issued = self._issue(downstream, preview, key="expired-binding-issue").json()["items"][0]
        card = LicenseCard.objects.get(public_id=issued["public_id"])
        profile = card.profile
        now = timezone.now()
        card.status = LicenseCardStatus.EXPIRED
        card.activated_at = now - timedelta(minutes=2)
        card.expires_at = now - timedelta(minutes=1)
        card.save(update_fields=("status", "activated_at", "expires_at"), _allow_mutation=True)
        instance = LicenseInstance.objects.create(
            license_card=card,
            software=card.software,
            profile=profile,
            plan_snapshot=card.plan_snapshot,
            policy_version=card.plan_snapshot.policy_version,
            current_downstream_public_id=card.current_downstream_public_id,
            client_id=profile.client_id,
            target=profile.target,
            arch=profile.arch,
            channel=profile.channel,
            client_version="1.0.0",
            state=AuthorizationState.EXPIRED,
            activated_at=card.activated_at,
            expires_at=card.expires_at,
            last_verified_at=card.activated_at,
        )
        device = Device.objects.create(
            software=card.software,
            profile=profile,
            installation_hash="b" * 64,
            last_ip="198.51.100.42",
        )
        device_key = DeviceKey.objects.create(
            key_id="expired-binding-key",
            device=device,
            public_key="expired-binding-public-key",
        )
        DeviceBinding.objects.create(
            authorization=instance,
            device=device,
            device_key=device_key,
            state=DeviceBindingState.EXPIRED,
            bound_at=card.activated_at,
            unbound_at=card.expires_at,
        )

        downstream_list = downstream.get(reverse("licensing:api_downstream_license_cards"))
        self.assertEqual(downstream_list.status_code, 200)
        downstream_item = downstream_list.json()["items"][0]
        self.assertEqual(downstream_item["device"], f"{device.public_id} · 已过期")
        self.assertEqual(downstream_item["ip"], "198.51.100.42")

        admin = self._admin_client()
        admin_list = admin.get(reverse("licensing:api_manage_license_cards"))
        self.assertEqual(admin_list.status_code, 200)
        admin_item = admin_list.json()["items"][0]
        self.assertEqual(admin_item["device"], f"{device.public_id} · 已过期")
        self.assertEqual(admin_item["ip"], "198.51.100.42")

    def test_admin_can_list_all_cards_but_cannot_issue_and_lists_do_not_expose_batch(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="admin-list-preview").json()
        issued = self._issue(downstream, preview, key="admin-list-issue").json()["items"][0]
        admin = self._admin_client()

        listed = admin.get(reverse("licensing:api_manage_license_cards"))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["pagination"]["total"], 1)
        item = listed.json()["items"][0]
        self.assertEqual(item["current_downstream_public_id"], str(self.downstream_a.public_id))
        self.assertNotIn("batch_id", item)
        self.assertNotIn("code", item)

        forbidden = self._post_json(
            admin,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": str(self.snapshot.snapshot_id),
                "quantity": 1,
                "preview_token": preview["preview_token"],
            },
            key="admin-cannot-issue",
        )
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json()["error"]["code"], "FORBIDDEN")
        self.assertEqual(LicenseCard.objects.count(), 1)
        card = LicenseCard.objects.get()
        self.assertEqual(issued["public_id"], str(card.public_id))
        with self.assertRaises(ValueError):
            LicenseCard.objects.filter(pk=card.pk).update(status=LicenseCardStatus.ARCHIVED)
        with self.assertRaises(ValueError):
            LicenseCard.objects.filter(pk=card.pk).delete()
        with self.assertRaises(ValueError):
            LicenseCardBatch.objects.filter(pk=card.batch_id).update(quantity=2)
        with self.assertRaises(ValueError):
            LicenseCardBatch.objects.filter(pk=card.batch_id).delete()

    def test_admin_list_tolerates_activated_card_without_instance_and_filters_by_scope(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=2, key="admin-filter-preview").json()
        issued = self._issue(downstream, preview, key="admin-filter-issue").json()["items"]
        activated = LicenseCard.objects.get(public_id=issued[0]["public_id"])
        activated.status = LicenseCardStatus.ACTIVATED
        activated.activated_at = timezone.now()
        activated.save(update_fields=("status", "activated_at"), _allow_mutation=True)

        admin = self._admin_client()
        url = reverse("licensing:api_manage_license_cards")
        filtered = admin.get(
            url,
            {
                "status": LicenseCardStatus.ACTIVATED,
                "software_id": self.software_id,
                "downstream_public_id": str(self.downstream_a.public_id),
            },
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(filtered.json()["pagination"]["total"], 1)
        self.assertEqual(filtered.json()["items"][0]["status"], LicenseCardStatus.ACTIVATED)
        self.assertNotIn("code", filtered.json()["items"][0])
        self.assertNotIn("batch_id", filtered.json()["items"][0])

        other_scope = admin.get(url, {"downstream_public_id": str(self.downstream_b.public_id)})
        self.assertEqual(other_scope.status_code, 200)
        self.assertEqual(other_scope.json()["pagination"]["total"], 0)

    def test_admin_reclaim_keeps_reason_in_card_and_audit(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="admin-reclaim-preview").json()
        issued = self._issue(downstream, preview, key="admin-reclaim-issue").json()["items"][0]
        admin = self._admin_client()
        response = self._post_json(
            admin,
            reverse("licensing:api_manage_license_reclaim"),
            {"card_ids": [issued["public_id"]], "reason": "人工复核后回收"},
            key="admin-reclaim-reason",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["status_reason"], "人工复核后回收")
        card = LicenseCard.objects.get(public_id=issued["public_id"])
        self.assertEqual(card.status, LicenseCardStatus.RECLAIMED)
        self.assertEqual(card.status_reason, "人工复核后回收")
        event = AuditEvent.objects.get(action="license_card.reclaim", object_public_id=issued["public_id"], outcome="success")
        self.assertEqual(event.metadata["reason"], "人工复核后回收")

    def test_reclaim_same_key_with_different_cards_is_a_conflict(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=2, key="reclaim-conflict-preview").json()
        issued = self._issue(downstream, preview, key="reclaim-conflict-issue").json()["items"]
        url = reverse("licensing:api_downstream_license_reclaim")
        first = self._post_json(
            downstream,
            url,
            {"card_ids": [issued[0]["public_id"]], "reason": RECLAIM_REASON},
            key="reclaim-same-key",
        )
        self.assertEqual(first.status_code, 200)
        conflict = self._post_json(
            downstream,
            url,
            {"card_ids": [issued[1]["public_id"]], "reason": RECLAIM_REASON},
            key="reclaim-same-key",
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(LicenseCard.objects.get(public_id=issued[1]["public_id"]).status, LicenseCardStatus.UNUSED)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").count(), 1)

    def test_expired_preview_token_returns_stable_error(self):
        client = self._downstream_client()
        preview = self._preview(client, key="expired-preview").json()
        with override_settings(LICENSE_CARD_PREVIEW_TTL_SECONDS=0):
            response = self._issue(client, preview, key="expired-preview-issue")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "PREVIEW_EXPIRED")
        self.assertEqual(LicenseCard.objects.count(), 0)

    def test_reveal_rate_limit_returns_retryable_error(self):
        client = self._downstream_client()
        preview = self._preview(client, quantity=2, key="reveal-rate-preview").json()
        issued = self._issue(client, preview, key="reveal-rate-issue").json()["items"]
        cache.clear()
        reveal_url = reverse("licensing:api_downstream_license_reveal", kwargs={"public_id": issued[0]["public_id"]})
        other_reveal_url = reverse("licensing:api_downstream_license_reveal", kwargs={"public_id": issued[1]["public_id"]})
        with override_settings(LICENSE_CARD_REVEAL_RATE_LIMIT=1):
            first = self._post_json(client, reveal_url, {}, key="reveal-rate-first")
            limited = self._post_json(client, other_reveal_url, {}, key="reveal-rate-second")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")
        self.assertEqual(limited.headers["Retry-After"], str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS))

    def test_preview_rate_limit_returns_retryable_error(self):
        client = self._downstream_client()
        cache.clear()
        with override_settings(LICENSE_CARD_PREVIEW_RATE_LIMIT=1):
            first = self._preview(client, key="preview-rate-first")
            limited = self._preview(client, key="preview-rate-second")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")
        self.assertEqual(limited.headers["Retry-After"], str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS))

    def test_downstream_scope_and_post_search_are_server_enforced(self):
        owner = self._downstream_client()
        preview = self._preview(owner, key="scope-preview").json()
        issued = self._issue(owner, preview, key="scope-issue").json()["items"][0]

        other = self._downstream_client("api-downstream-b")
        listed = other.get(reverse("licensing:api_downstream_license_cards"))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["items"], [])
        searched = self._post_json(
            other,
            reverse("licensing:api_downstream_license_card_search"),
            {"code": issued["code"]},
            key="scope-search-other",
        )
        self.assertEqual(searched.status_code, 404)
        self.assertEqual(searched.json()["error"]["code"], "LICENSE_CARD_NOT_FOUND")

        found = self._post_json(
            owner,
            reverse("licensing:api_downstream_license_card_search"),
            {"code": issued["code"]},
            key="scope-search-owner",
        )
        self.assertEqual(found.status_code, 200)
        self.assertEqual(found.json()["item"]["public_id"], issued["public_id"])
        self.assertNotIn("code", found.json()["item"])

    def test_reveal_is_post_only_rate_limited_path_and_not_success_audited(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="reveal-preview").json()
        issued = self._issue(downstream, preview, key="reveal-issue").json()["items"][0]
        reveal_url = reverse(
            "licensing:api_downstream_license_reveal",
            kwargs={"public_id": issued["public_id"]},
        )
        self.assertEqual(downstream.get(reveal_url).status_code, 405)
        revealed = self._post_json(downstream, reveal_url, {}, key="reveal-request")
        self.assertEqual(revealed.status_code, 200)
        self.assertEqual(revealed.json()["code"], issued["code"])
        self.assertFalse(
            AuditEvent.objects.filter(
                action="license_card.reveal",
                outcome="success",
                object_public_id=issued["public_id"],
            ).exists()
        )

    def test_bulk_reclaim_refunds_once_and_mixed_failure_is_atomic(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=2, key="reclaim-preview").json()
        issued = self._issue(downstream, preview, key="reclaim-issue").json()["items"]
        reclaim_url = reverse("licensing:api_downstream_license_reclaim")
        first = self._post_json(
            downstream,
            reclaim_url,
            {"card_ids": [item["public_id"] for item in issued], "reason": RECLAIM_REASON},
            key="reclaim-bulk",
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["reclaimed_count"], 2)
        self.assertEqual(first.json()["refunded_quota"], 10)
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 100)
        self.assertEqual(LicenseCard.objects.filter(status=LicenseCardStatus.RECLAIMED).count(), 2)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").count(), 2)

        repeated = self._post_json(
            downstream,
            reclaim_url,
            {"card_ids": [item["public_id"] for item in issued], "reason": RECLAIM_REASON},
            key="reclaim-bulk-retry",
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json()["refunded_quota"], 0)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").count(), 2)

        invalid = self._post_json(
            downstream,
            reclaim_url,
            {"card_ids": [issued[0]["public_id"], "00000000-0000-0000-0000-000000000000"], "reason": RECLAIM_REASON},
            key="reclaim-mixed-invalid",
        )
        self.assertEqual(invalid.status_code, 404)
        self.assertEqual(LicenseCard.objects.filter(status=LicenseCardStatus.RECLAIMED).count(), 2)

    def test_reclaim_same_key_is_order_insensitive_on_retry(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=2, key="reclaim-order-preview").json()
        issued = self._issue(downstream, preview, key="reclaim-order-issue").json()["items"]
        reclaim_url = reverse("licensing:api_downstream_license_reclaim")
        card_ids = [item["public_id"] for item in issued]

        first = self._post_json(
            downstream,
            reclaim_url,
            {"card_ids": card_ids, "reason": RECLAIM_REASON},
            key="reclaim-order-insensitive",
        )
        repeated = self._post_json(
            downstream,
            reclaim_url,
            {"card_ids": list(reversed(card_ids)), "reason": RECLAIM_REASON},
            key="reclaim-order-insensitive",
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json()["items"], first.json()["items"])
        self.assertEqual(repeated.json()["refunded_quota"], 10)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").count(), 2)

    def test_filtered_reclaim_preview_and_reclaim_only_touch_unused_cards(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=2, key="reclaim-filtered-preview").json()
        issued = self._issue(downstream, preview, key="reclaim-filtered-issue").json()["items"]
        activated = LicenseCard.objects.get(public_id=issued[0]["public_id"])
        activated.status = LicenseCardStatus.ACTIVATED
        activated.activated_at = timezone.now()
        activated.save(update_fields=("status", "activated_at"), _allow_mutation=True)

        preview_url = reverse("licensing:api_downstream_license_reclaim_preview")
        filters = {"status": LicenseCardStatus.UNUSED, "plan_name": "API 月卡"}
        preview_response = downstream.get(preview_url, filters)
        self.assertEqual(preview_response.status_code, 200)
        self.assertEqual(preview_response.json()["reclaimable_count"], 1)
        self.assertEqual(preview_response.json()["refundable_quota"], 5)
        self.assertEqual(preview_response.json()["card_ids"], [issued[1]["public_id"]])

        reclaim_response = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": preview_response.json()["card_ids"], "reason": RECLAIM_REASON},
            key="reclaim-filtered",
        )
        self.assertEqual(reclaim_response.status_code, 200)
        self.assertEqual(reclaim_response.json()["reclaimed_count"], 1)
        self.assertEqual(reclaim_response.json()["refunded_quota"], 5)
        self.assertEqual(
            LicenseCard.objects.get(public_id=issued[0]["public_id"]).status,
            LicenseCardStatus.ACTIVATED,
        )
        self.assertEqual(
            LicenseCard.objects.get(public_id=issued[1]["public_id"]).status,
            LicenseCardStatus.RECLAIMED,
        )

    def test_admin_filtered_reclaim_respects_downstream_scope(self):
        owner_a = self._downstream_client()
        issued_a = self._issue(
            owner_a,
            self._preview(owner_a, key="admin-filter-owner-a-preview").json(),
            key="admin-filter-owner-a-issue",
        ).json()["items"][0]
        owner_b = self._downstream_client("api-downstream-b")
        issued_b = self._issue(
            owner_b,
            self._preview(owner_b, key="admin-filter-owner-b-preview").json(),
            key="admin-filter-owner-b-issue",
        ).json()["items"][0]
        admin = self._admin_client()
        filters = {
            "status": LicenseCardStatus.UNUSED,
            "downstream_public_id": str(self.downstream_b.public_id),
        }
        preview = admin.get(reverse("licensing:api_manage_license_reclaim_preview"), filters)
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json()["reclaimable_count"], 1)
        self.assertEqual(preview.json()["card_ids"], [issued_b["public_id"]])

        response = self._post_json(
            admin,
            reverse("licensing:api_manage_license_reclaim"),
            {"card_ids": preview.json()["card_ids"], "reason": "管理员筛选回收"},
            key="admin-filtered-reclaim",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["reclaimed_count"], 1)
        self.assertEqual(LicenseCard.objects.get(public_id=issued_a["public_id"]).status, LicenseCardStatus.UNUSED)
        self.assertEqual(LicenseCard.objects.get(public_id=issued_b["public_id"]).status, LicenseCardStatus.RECLAIMED)

    def test_filtered_reclaim_plan_name_matches_list_exactly(self):
        month_plan, _ = create_plan(
            actor=self.admin,
            software_id=self.software_id,
            profile_id="stable",
            policy_version="policy-1",
            name="月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=5,
            status=PlanStatus.ACTIVE,
        )
        super_plan, _ = create_plan(
            actor=self.admin,
            software_id=self.software_id,
            profile_id="stable",
            policy_version="policy-1",
            name="超级月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=8,
            status=PlanStatus.ACTIVE,
        )
        downstream = self._downstream_client()
        month_preview = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": month_plan.pk, "quantity": 1},
            key="exact-month-preview",
        ).json()
        month_card = self._issue(downstream, month_preview, key="exact-month-issue").json()["items"][0]
        super_preview = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": super_plan.pk, "quantity": 1},
            key="exact-super-preview",
        ).json()
        super_card = self._issue(downstream, super_preview, key="exact-super-issue").json()["items"][0]
        preview_url = reverse("licensing:api_downstream_license_reclaim_preview")
        month_filters = {"status": LicenseCardStatus.UNUSED, "plan_name": "月卡"}
        preview = downstream.get(preview_url, month_filters)
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json()["reclaimable_count"], 1)
        self.assertEqual(preview.json()["card_ids"], [month_card["public_id"]])
        reclaim = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": preview.json()["card_ids"], "reason": RECLAIM_REASON},
            key="exact-month-reclaim",
        )
        self.assertEqual(reclaim.status_code, 200)
        self.assertEqual(reclaim.json()["reclaimed_count"], 1)
        self.assertEqual(LicenseCard.objects.get(public_id=month_card["public_id"]).status, LicenseCardStatus.RECLAIMED)
        self.assertEqual(LicenseCard.objects.get(public_id=super_card["public_id"]).status, LicenseCardStatus.UNUSED)

    def test_filtered_reclaim_software_name_matches_list_exactly(self):
        super_software = create_software(
            actor=self.admin,
            software_id="api-license-tool-super",
            name="API License Tool Super",
            status=SoftwareStatus.ACTIVE,
        )
        super_profile = create_profile(
            actor=self.admin,
            software_id=super_software.software_id,
            profile_id="stable",
            client_id="api-license-tool-super-client",
            status=ProfileStatus.ACTIVE,
        )
        super_policy = create_policy_version(
            actor=self.admin,
            software_id=super_software.software_id,
            profile_id=super_profile.profile_id,
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        super_plan, _ = create_plan(
            actor=self.admin,
            software_id=super_software.software_id,
            profile_id=super_profile.profile_id,
            policy_version=super_policy.version,
            name="API 月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=5,
            status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=super_software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        downstream = self._downstream_client()
        short_card = self._issue(
            downstream,
            self._preview(downstream, key="exact-software-short-preview").json(),
            key="exact-software-short-issue",
        ).json()["items"][0]
        long_preview_response = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": super_software.software_id, "plan_id": super_plan.pk, "quantity": 1},
            key="exact-software-long-preview",
        )
        self.assertEqual(long_preview_response.status_code, 200)
        long_preview = long_preview_response.json()
        long_issue = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": super_software.software_id,
                "plan_snapshot_id": long_preview["snapshot_id"],
                "quantity": 1,
                "preview_token": long_preview["preview_token"],
            },
            key="exact-software-long-issue",
        )
        self.assertEqual(long_issue.status_code, 201)
        long_card = long_issue.json()["items"][0]
        listed = downstream.get(
            reverse("licensing:api_downstream_license_cards"),
            {"software_name": "API License Tool"},
        )
        self.assertEqual(listed.status_code, 200)
        listed_ids = {item["public_id"] for item in listed.json()["items"]}
        self.assertEqual(listed_ids, {short_card["public_id"]})
        filters = {"status": LicenseCardStatus.UNUSED, "software_name": "API License Tool"}
        preview = downstream.get(reverse("licensing:api_downstream_license_reclaim_preview"), filters)
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json()["reclaimable_count"], 1)
        self.assertEqual(preview.json()["card_ids"], [short_card["public_id"]])
        reclaim = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": preview.json()["card_ids"], "reason": RECLAIM_REASON},
            key="exact-software-reclaim",
        )
        self.assertEqual(reclaim.status_code, 200)
        self.assertEqual(reclaim.json()["reclaimed_count"], 1)
        self.assertEqual(LicenseCard.objects.get(public_id=short_card["public_id"]).status, LicenseCardStatus.RECLAIMED)
        self.assertEqual(LicenseCard.objects.get(public_id=long_card["public_id"]).status, LicenseCardStatus.UNUSED)

    def test_admin_filtered_reclaim_archived_scope_does_not_touch_unused(self):
        downstream = self._downstream_client()
        issued = self._issue(
            downstream,
            self._preview(downstream, key="archived-scope-preview").json(),
            key="archived-scope-issue",
        ).json()["items"][0]
        admin = self._admin_client()
        filters = {"status": LicenseCardStatus.UNUSED, "scope": "archived"}
        preview = admin.get(reverse("licensing:api_manage_license_reclaim_preview"), filters)
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json()["reclaimable_count"], 0)
        self.assertEqual(preview.json()["card_ids"], [])
        response = self._post_json(
            admin,
            reverse("licensing:api_manage_license_reclaim"),
            {"selection": "filtered", "filters": filters, "reason": "归档分类不得回收未归档卡"},
            key="archived-scope-reclaim",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(LicenseCard.objects.get(public_id=issued["public_id"]).status, LicenseCardStatus.UNUSED)

    def test_filtered_reclaim_without_card_ids_is_rejected(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="reject-live-query-preview").json()
        issued = self._issue(downstream, preview, key="reject-live-query-issue").json()["items"][0]
        response = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"selection": "filtered", "filters": {"status": LicenseCardStatus.UNUSED}, "reason": RECLAIM_REASON},
            key="reject-live-query",
        )
        self.assertNotEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(LicenseCard.objects.get(public_id=issued["public_id"]).status, LicenseCardStatus.UNUSED)

    def test_downstream_reclaim_without_reason_is_rejected(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="reject-no-reason-preview").json()
        issued = self._issue(downstream, preview, key="reject-no-reason-issue").json()["items"][0]
        response = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": [issued["public_id"]]},
            key="reject-no-reason",
        )
        self.assertNotEqual(response.status_code, 200)
        self.assertIn(response.json()["error"]["code"], {"INVALID_REQUEST", "INVALID_REASON"})
        self.assertEqual(LicenseCard.objects.get(public_id=issued["public_id"]).status, LicenseCardStatus.UNUSED)

    def test_reclaim_confirm_does_not_sweep_cards_issued_after_preview(self):
        downstream = self._downstream_client()
        first_preview = self._preview(downstream, key="lock-ids-first-preview").json()
        first = self._issue(downstream, first_preview, key="lock-ids-first-issue").json()["items"][0]
        reclaim_preview = downstream.get(
            reverse("licensing:api_downstream_license_reclaim_preview"),
            {"status": LicenseCardStatus.UNUSED},
        )
        self.assertEqual(reclaim_preview.status_code, 200)
        locked_ids = reclaim_preview.json()["card_ids"]
        self.assertEqual(locked_ids, [first["public_id"]])
        extra_preview = self._preview(downstream, key="lock-ids-extra-preview").json()
        extra = self._issue(downstream, extra_preview, key="lock-ids-extra-issue").json()["items"][0]
        response = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": locked_ids, "reason": RECLAIM_REASON},
            key="lock-ids-confirm",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["reclaimed_count"], 1)
        self.assertEqual(LicenseCard.objects.get(public_id=first["public_id"]).status, LicenseCardStatus.RECLAIMED)
        self.assertEqual(LicenseCard.objects.get(public_id=extra["public_id"]).status, LicenseCardStatus.UNUSED)

    def test_reclaim_operation_is_immutable_through_queryset(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, key="reclaim-immutable-preview").json()
        issued = self._issue(downstream, preview, key="reclaim-immutable-issue").json()["items"][0]
        response = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_reclaim"),
            {"card_ids": [issued["public_id"]], "reason": RECLAIM_REASON},
            key="reclaim-immutable",
        )
        self.assertEqual(response.status_code, 200)
        operation = LicenseReclaimOperation.objects.get(actor=self.downstream_a.user, idempotency_key="reclaim-immutable")
        with self.assertRaises(ValueError):
            LicenseReclaimOperation.objects.filter(pk=operation.pk).update(response_payload={"code": issued["code"]})

    def test_mutating_license_api_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(
            reverse("licensing:api_manage_license_reclaim"),
            data=json.dumps({"card_ids": []}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="license-csrf-missing",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "CSRF_FAILED")

    def test_license_card_filters_apply_before_pagination(self):
        downstream = self._downstream_client()
        alternate_plan, _ = create_plan(
            actor=self.admin,
            software_id=self.software_id,
            profile_id="stable",
            policy_version="policy-1",
            name="API 周卡",
            duration_seconds=7 * 24 * 60 * 60,
            quota_cost=3,
            status="active",
        )
        alternate_preview = self._post_json(
            downstream,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": alternate_plan.pk, "quantity": 1},
            key="license-filter-alternate-preview",
        ).json()
        alternate_issue = self._issue(downstream, alternate_preview, key="license-filter-alternate-issue")
        self.assertEqual(alternate_issue.status_code, 201)
        base_preview = self._preview(downstream, quantity=10, key="license-filter-base-preview").json()
        self.assertEqual(self._issue(downstream, base_preview, key="license-filter-base-issue").status_code, 201)

        admin = self._admin_client()
        filtered = admin.get(
            reverse("licensing:api_manage_license_cards"),
            {"page_size": 5, "page": 1, "plan_name": "API 周卡"},
        )
        self.assertEqual(filtered.status_code, 200)
        body = filtered.json()
        self.assertEqual(body["pagination"]["total"], 1)
        self.assertEqual(body["pagination"]["total_pages"], 1)
        self.assertFalse(body["pagination"]["has_next"])
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(body["items"][0]["plan_name"], "API 周卡")

    def test_license_card_list_paginates_beyond_one_server_page(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=11, key="license-page-preview").json()
        issued = self._issue(downstream, preview, key="license-page-issue")
        self.assertEqual(issued.status_code, 201)
        admin = self._admin_client()
        first = admin.get(reverse("licensing:api_manage_license_cards"), {"page_size": 5, "page": 1})
        third = admin.get(reverse("licensing:api_manage_license_cards"), {"page_size": 5, "page": 3})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(third.status_code, 200)
        self.assertEqual(len(first.json()["items"]), 5)
        self.assertEqual(len(third.json()["items"]), 1)
        self.assertEqual(first.json()["pagination"]["total"], 11)
        self.assertEqual(first.json()["pagination"]["total_pages"], 3)
        self.assertTrue(first.json()["pagination"]["has_next"])
        self.assertFalse(third.json()["pagination"]["has_next"])

    def test_admin_license_export_is_audited_and_uses_current_filters(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=2, key="license-export-preview").json()
        issued = self._issue(downstream, preview, key="license-export-issue")
        self.assertEqual(issued.status_code, 201)
        admin = self._admin_client()
        exported = admin.get(reverse("licensing:api_manage_license_export"))
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported["Content-Type"], "text/csv; charset=utf-8")
        self.assertNotIn("X-Export-Truncated", exported)
        body = exported.content.decode("utf-8")
        self.assertIn("尾号", body)
        self.assertTrue(AuditEvent.objects.filter(action="license_card.export", outcome="success").exists())
        unused_only = admin.get(
            reverse("licensing:api_manage_license_export"),
            {"status": "unused"},
        )
        self.assertEqual(unused_only.status_code, 200)
        self.assertGreaterEqual(unused_only.content.decode("utf-8").count("\n"), 3)

    def test_license_export_expiry_uses_beijing_wall_clock(self):
        instant = datetime(2026, 9, 5, 16, 0, 0, tzinfo=dt_timezone.utc)
        activated_at = datetime(2026, 9, 1, 0, 0, 0, tzinfo=dt_timezone.utc)
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=1, key="license-export-beijing-preview").json()
        issued = self._issue(downstream, preview, key="license-export-beijing-issue")
        self.assertEqual(issued.status_code, 201)
        public_id = issued.json()["items"][0]["public_id"]
        card = LicenseCard.objects.get(public_id=public_id)
        card.status = LicenseCardStatus.ACTIVATED
        card.activated_at = activated_at
        card.expires_at = instant
        card.save(update_fields=("status", "activated_at", "expires_at"), _allow_mutation=True)
        admin = self._admin_client()
        exported = admin.get(reverse("licensing:api_manage_license_export"), {"status": "expired"})
        self.assertEqual(exported.status_code, 200)
        rows = list(csv.reader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0][10], "到期时间")
        self.assertEqual(rows[1][10], "2026-09-06 00:00:00")
        self.assertEqual(rows[1][9], "2026-09-01 08:00:00")
        self.assertNotIn("2026-09-05 16:00:00", exported.content.decode("utf-8-sig"))
        listed = admin.get(reverse("licensing:api_manage_license_cards"), {"status": "expired"})
        self.assertEqual(listed.status_code, 200)
        item = next(row for row in listed.json()["items"] if row["public_id"] == public_id)
        self.assertEqual(item["status"], "activated")
        self.assertIn("2026-09-05T16:00:00", item["expires_at"])
        self.assertNotIn("2026-09-06T00:00:00", item["expires_at"])
        still_activated = LicenseCard.objects.get(public_id=public_id)
        self.assertEqual(still_activated.status, LicenseCardStatus.ACTIVATED)

    def test_license_list_expired_filter_includes_activated_past_expiry_without_writing_status(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=3, key="license-wall-clock-preview").json()
        issued = self._issue(downstream, preview, key="license-wall-clock-issue")
        self.assertEqual(issued.status_code, 201)
        public_ids = [item["public_id"] for item in issued.json()["items"]]
        now = timezone.now()
        past = LicenseCard.objects.get(public_id=public_ids[0])
        past.status = LicenseCardStatus.ACTIVATED
        past.activated_at = now - timedelta(days=10)
        past.expires_at = now - timedelta(days=1)
        past.save(update_fields=("status", "activated_at", "expires_at"), _allow_mutation=True)
        future = LicenseCard.objects.get(public_id=public_ids[1])
        future.status = LicenseCardStatus.ACTIVATED
        future.activated_at = now
        future.expires_at = now + timedelta(days=20)
        future.save(update_fields=("status", "activated_at", "expires_at"), _allow_mutation=True)
        enum_expired = LicenseCard.objects.get(public_id=public_ids[2])
        enum_expired.status = LicenseCardStatus.EXPIRED
        enum_expired.activated_at = now - timedelta(days=30)
        enum_expired.expires_at = now - timedelta(days=5)
        enum_expired.save(update_fields=("status", "activated_at", "expires_at"), _allow_mutation=True)
        admin = self._admin_client()
        expired_ids = {
            row["public_id"]
            for row in admin.get(
                reverse("licensing:api_manage_license_cards"), {"status": "expired"}
            ).json()["items"]
        }
        activated_ids = {
            row["public_id"]
            for row in admin.get(
                reverse("licensing:api_manage_license_cards"), {"status": "activated"}
            ).json()["items"]
        }
        expiry_state_ids = {
            row["public_id"]
            for row in admin.get(
                reverse("licensing:api_manage_license_cards"), {"expiry_state": "expired"}
            ).json()["items"]
        }
        self.assertIn(str(past.public_id), expired_ids)
        self.assertIn(str(enum_expired.public_id), expired_ids)
        self.assertNotIn(str(future.public_id), expired_ids)
        self.assertIn(str(future.public_id), activated_ids)
        self.assertNotIn(str(past.public_id), activated_ids)
        self.assertNotIn(str(enum_expired.public_id), activated_ids)
        self.assertEqual(expired_ids, expiry_state_ids)
        past_row = next(
            row
            for row in admin.get(
                reverse("licensing:api_manage_license_cards"), {"status": "expired"}
            ).json()["items"]
            if row["public_id"] == str(past.public_id)
        )
        self.assertEqual(past_row["status"], "activated")
        past.refresh_from_db()
        self.assertEqual(past.status, LicenseCardStatus.ACTIVATED)
        enum_expired.refresh_from_db()
        self.assertEqual(enum_expired.status, LicenseCardStatus.EXPIRED)

    def test_license_list_q_matches_software_and_plan_not_card_suffix(self):
        downstream = self._downstream_client()
        preview = self._preview(downstream, quantity=1, key="license-fuzzy-preview").json()
        issued = self._issue(downstream, preview, key="license-fuzzy-issue")
        self.assertEqual(issued.status_code, 201)
        public_id = issued.json()["items"][0]["public_id"]
        suffix = issued.json()["items"][0]["masked_code"][-4:]
        admin = self._admin_client()
        by_software = admin.get(reverse("licensing:api_manage_license_cards"), {"q": "API License Tool"})
        self.assertEqual(by_software.status_code, 200)
        self.assertIn(public_id, {row["public_id"] for row in by_software.json()["items"]})
        by_plan = admin.get(reverse("licensing:api_manage_license_cards"), {"q": "API 月卡"})
        self.assertEqual(by_plan.status_code, 200)
        self.assertIn(public_id, {row["public_id"] for row in by_plan.json()["items"]})
        by_downstream = admin.get(reverse("licensing:api_manage_license_cards"), {"q": "api-downstream-a"})
        self.assertEqual(by_downstream.status_code, 200)
        self.assertIn(public_id, {row["public_id"] for row in by_downstream.json()["items"]})
        by_suffix = admin.get(reverse("licensing:api_manage_license_cards"), {"q": suffix})
        self.assertEqual(by_suffix.status_code, 200)
        self.assertNotIn(public_id, {row["public_id"] for row in by_suffix.json()["items"]})
        full_code = issued.json()["items"][0].get("code")
        self.assertTrue(full_code)
        by_code = admin.get(reverse("licensing:api_manage_license_cards"), {"q": full_code})
        self.assertEqual(by_code.status_code, 200)
        self.assertIn(public_id, {row["public_id"] for row in by_code.json()["items"]})
        too_long = admin.get(reverse("licensing:api_manage_license_cards"), {"q": "x" * 129})
        self.assertEqual(too_long.status_code, 400)
        self.assertEqual(too_long.json()["error"]["code"], "INVALID_QUERY")
