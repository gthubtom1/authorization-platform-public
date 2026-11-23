from __future__ import annotations

import base64
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.catalog.models import Plan, PlanCreateOperation, PolicyVersion, Software, SoftwareProfile
from authorization_platform.catalog.services import create_profile
from authorization_platform.licensing.authorization import authorization_signing_public_key

User = get_user_model()
COLLECTION = "/api/v1/manage/catalog/"


@override_settings(AUTHORIZATION_PUBLIC_BASE_URL="https://platform.example.test")
class SoftwareIntegrationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(username="integration-admin", password="Isolated-password-123")
        self.downstream = create_downstream_direct(actor=self.admin, username="integration-downstream", password="Isolated-password-456")
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.admin)

    def create(self, payload=None, key="integration-create"):
        self.client.get("/api/v1/session/")
        return self.client.post(COLLECTION, json.dumps(payload if payload is not None else {"name": "新软件"}), content_type="application/json", HTTP_X_CSRFTOKEN=self.client.cookies["csrftoken"].value, HTTP_IDEMPOTENCY_KEY=key)

    def export(self, identity, **params):
        return self.client.get(f"{COLLECTION}software/{identity}/integration-config/", params)

    def test_name_only_creates_complete_identity_without_plan_or_downstream_scope(self):
        response = self.create()
        self.assertEqual(response.status_code, 201, response.content)
        payload = response.json()
        identity = payload["software"]["software_id"]
        self.assertRegex(identity, r"^sw-[0-9a-f]{32}$")
        self.assertEqual(payload["profile"]["profile_id"], "stable")
        self.assertEqual(payload["profile"]["client_id"], identity + "-windows")
        self.assertIsNone(payload["plan"])
        self.assertIsNone(payload["snapshot"])
        self.assertEqual(Plan.objects.count(), 0)
        policy = PolicyVersion.objects.get()
        self.assertEqual((policy.max_devices, policy.verify_interval_seconds, policy.offline_grace_seconds, policy.device_switch_limit), (1, 60, 0, 5))
        self.assertTrue(policy.allow_device_switch)
        self.assertTrue(policy.device_proof_required)
        self.assertFalse(Software.objects.get().downstream_accesses.exists())
        self.assertEqual(payload["software"]["client_connection"], "not_connected")

    def test_same_key_survives_cache_loss_and_name_collision_does_not_reuse_identity(self):
        first = self.create()
        cache.clear()
        self.assertEqual(self.create().json(), first.json())
        self.assertEqual(Software.objects.count(), 1)
        self.assertEqual(PlanCreateOperation.objects.filter(namespace="software-create").count(), 1)
        other = self.create(key="another-create")
        self.assertNotEqual(first.json()["software"]["software_id"], other.json()["software"]["software_id"])
        conflict = self.create({"name": "另一个名字"})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_failed_optional_plan_rolls_back_then_same_key_can_retry(self):
        invalid = {"name": "回滚软件", "create_plan": True, "plan_name": "正式", "duration_value": 1, "duration_unit": "day", "quota_cost": 0}
        self.assertEqual(self.create(invalid).status_code, 400)
        self.assertEqual((Software.objects.count(), SoftwareProfile.objects.count(), PolicyVersion.objects.count(), PlanCreateOperation.objects.count()), (0, 0, 0, 0))
        invalid["quota_cost"] = 2
        good = self.create(invalid)
        self.assertEqual(good.status_code, 201)
        self.assertEqual(good.json()["plan"]["latest_snapshot"]["quota_cost"], 2)
        self.assertEqual(Plan.objects.count(), 1)

    def test_false_plan_flag_rejects_conflicting_fields_and_empty_name_is_rejected(self):
        self.assertEqual(self.create({"name": "软件", "create_plan": False, "plan_name": "不能忽略"}).status_code, 400)
        self.assertEqual(self.create({"name": "   "}).status_code, 400)
        self.assertEqual(Software.objects.count(), 0)

    def test_legacy_explicit_identity_and_plan_are_compatible(self):
        response = self.create({"name": "旧接入", "software_id": "legacy-tool", "profile_id": "desktop", "client_id": "legacy-client", "policy_version": "legacy-policy", "plan_name": "日卡", "duration_value": 1, "duration_unit": "day", "quota_cost": 1})
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["software"]["software_id"], "legacy-tool")
        self.assertEqual(response.json()["plan"]["name"], "日卡")

    def test_create_requires_csrf_and_administrator(self):
        self.assertEqual(self.client.post(COLLECTION, '{"name":"软件"}', content_type="application/json").status_code, 403)
        self.client.force_login(self.downstream.user)
        self.assertIn(self.create().status_code, (401, 403))
        self.client.logout()
        self.assertIn(self.create().status_code, (401, 403))
        self.assertEqual(Software.objects.count(), 0)

    def test_export_is_exact_single_profile_with_current_public_key_and_original_contracts(self):
        identity = self.create().json()["software"]["software_id"]
        response = self.export(identity)
        self.assertEqual(response.status_code, 200, response.content)
        payload = json.loads(response.content)
        self.assertEqual(payload["schema"], "software-bind.v2")
        self.assertEqual(payload["software"]["software_id"], identity)
        self.assertEqual(payload["platform"]["authorization_public_key"], authorization_signing_public_key())
        self.assertEqual(len(base64.urlsafe_b64decode(payload["platform"]["authorization_public_key"] + "=")), 32)
        self.assertEqual(payload["platform"]["base_url"], "https://platform.example.test")
        self.assertEqual(payload["platform"]["authorization_public_key_id"], settings.AUTHORIZATION_SIGNING_KEY_ID)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn(identity + "-stable-integration.json", response["Content-Disposition"])
        for name, protocol in payload["contracts"].items():
            self.assertEqual(protocol, json.loads((Path(settings.BASE_DIR) / "protocol" / name).read_text(encoding="utf-8")))
        self.assertEqual(payload["ai_handoff"], (Path(settings.BASE_DIR) / "接入说明" / "09-给软件项目AI的接入指令.md").read_text(encoding="utf-8"))
        self.assertEqual(AuditEvent.objects.filter(action="software.integration_config.export", object_public_id=identity).count(), 1)
        self.assertFalse(payload["core"]["talks_to_platform"])
        self.assertIn("issued", payload["launch_ticket_contract"])
        self.assertIn("consumed", payload["launch_ticket_contract"])
        self.assertIn("audience", payload["launch_ticket_contract"])
        self.assertIn("do not apply", payload["response_contracts"]["launch_ticket_and_consume"])

    def test_compatible_software_identifier_with_dot_can_download(self):
        response = self.create({"name": "带点标识", "software_id": "tool.v1"})
        self.assertEqual(response.status_code, 201, response.content)
        exported = self.export("tool.v1")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(json.loads(exported.content)["software"]["software_id"], "tool.v1")

    def test_missing_ticket_section_refuses_incomplete_handoff(self):
        identity = self.create().json()["software"]["software_id"]
        original = Path.read_text
        def read_without_ticket(path, *args, **kwargs):
            if path.name == "API-CONTRACT.md":
                return "# Missing ticket contract\n"
            return original(path, *args, **kwargs)
        from unittest.mock import patch
        with patch.object(Path, "read_text", read_without_ticket):
            self.assertEqual(self.export(identity).status_code, 503)

    def test_export_does_not_mutate_business_or_contain_secrets(self):
        identity = self.create().json()["software"]["software_id"]
        before = (Software.objects.count(), SoftwareProfile.objects.count(), Plan.objects.count(), PolicyVersion.objects.count(), PlanCreateOperation.objects.count())
        response = self.export(identity, base_url="https://attacker.example", public_key="attacker", software_id="other")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["software"]["software_id"], identity)
        self.assertEqual(data["platform"]["base_url"], "https://platform.example.test")
        self.assertNotIn("attacker", response.content.decode())
        self.assertNotIn(settings.SECRET_KEY, response.content.decode())
        def keys(value):
            if isinstance(value, dict):
                return set(value).union(*(keys(child) for child in value.values()))
            if isinstance(value, list):
                return set().union(*(keys(child) for child in value))
            return set()
        # Schema property names are public documentation, not live credentials.
        public_config = {key: value for key, value in data.items() if key != "contracts"}
        self.assertFalse({"private_key", "password", "admin_token", "license_key", "downstream_id", "expires_at", "current_client_version"}.intersection(keys(public_config)))
        self.assertEqual(before, (Software.objects.count(), SoftwareProfile.objects.count(), Plan.objects.count(), PolicyVersion.objects.count(), PlanCreateOperation.objects.count()))

    def test_other_software_and_profiles_do_not_leak_into_export(self):
        first = self.create().json()["software"]["software_id"]
        second = self.create({"name": "另一软件"}, key="other-software").json()["software"]["software_id"]
        self.assertNotIn(second, self.export(first).content.decode())
        create_profile(actor=self.admin, software_id=first, profile_id="arm", client_id="arm-client", status="active", arch="arm64")
        self.assertEqual(self.export(first).json()["error"]["code"], "PROFILE_REQUIRED")
        self.assertEqual(self.export(first, profile_id="stable").status_code, 200)
        self.assertEqual(self.export(first, profile_id="not-this-profile").status_code, 404)

    def test_export_requires_administrator_and_an_available_saved_profile(self):
        identity = self.create().json()["software"]["software_id"]
        self.assertEqual(self.export("does-not-exist").status_code, 404)
        Software.objects.filter(pk=identity).update(status="archived")
        self.assertEqual(self.export(identity).status_code, 400)
        self.client.force_login(self.downstream.user)
        self.assertIn(self.export(identity).status_code, (401, 403))
        self.client.logout()
        self.assertIn(self.export(identity).status_code, (401, 403))

    def test_missing_guide_and_bad_signing_key_fail_closed(self):
        identity = self.create().json()["software"]["software_id"]
        with TemporaryDirectory() as folder, override_settings(BASE_DIR=Path(folder)):
            self.assertEqual(self.export(identity).status_code, 503)
        with override_settings(AUTHORIZATION_SIGNING_PRIVATE_KEY="malformed"):
            self.assertEqual(self.export(identity).status_code, 503)
        self.assertEqual(AuditEvent.objects.filter(action="software.integration_config.export").count(), 0)

    def test_public_url_rejects_credentials_http_production_and_arbitrary_prefix(self):
        identity = self.create().json()["software"]["software_id"]
        for origin in ("https://user:password@platform.example.test", "http://platform.example.test", "https://platform.example.test/prefix", "https://platform.example.test?token=secret", "https://[invalid"):
            with self.subTest(origin=origin), override_settings(AUTHORIZATION_PUBLIC_BASE_URL=origin):
                self.assertEqual(self.export(identity).status_code, 503)
        with override_settings(AUTHORIZATION_PUBLIC_BASE_URL="", APP_ENV="local"):
            self.assertEqual(self.client.get(f"{COLLECTION}software/{identity}/integration-config/", HTTP_HOST="127.0.0.1").status_code, 200)
