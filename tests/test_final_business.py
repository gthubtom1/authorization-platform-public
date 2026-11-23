from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection, connections, close_old_connections
from django.test import Client, TestCase, SimpleTestCase, TransactionTestCase
from django.urls import resolve, reverse
from django.utils import timezone

from authorization_platform.accounts.models import InvitationBatch, InvitationCode
from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.audit.queries import audit_events_for_user, paginate_audit_events, present_event
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.models import Software, SoftwareProfile
from authorization_platform.catalog.services import create_profile, create_policy_version, create_capability_definition
from authorization_platform.credits.models import QuotaLedgerEntry
from authorization_platform.credits.services import credit_quota
from authorization_platform.core.time import FixedClock
from authorization_platform.licensing.admin import block_physical_device
from authorization_platform.licensing.authorization import activate_license, deactivate_license
from authorization_platform.licensing.models import DeviceBinding, LicenseCard
from authorization_platform.licensing.services import generate_license_batch, decrypt_license_card
from tests import test_authorization as auth_tests


def csv_rows(response):
    return list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))


class FinalBusinessTests(TestCase):
    setUp = auth_tests.AuthorizationServiceTests.setUp
    _user_admin = staticmethod(auth_tests.AuthorizationServiceTests._user_admin)
    _public_key = staticmethod(auth_tests.AuthorizationServiceTests._public_key)
    _request = auth_tests.AuthorizationServiceTests._request

    def admin_client(self):
        client = Client()
        client.force_login(self.admin)
        return client

    def downstream_client(self):
        client = Client()
        client.force_login(self.downstream.user)
        session = client.session
        session["downstream_session_version"] = self.downstream.session_version
        session.save()
        return client

    def post(self, client, path, body, key=None):
        headers = {"HTTP_IDEMPOTENCY_KEY": key} if key else {}
        return client.post(path, data=json.dumps(body), content_type="application/json", **headers)

    def profile_url(self):
        return reverse("catalog:api_manage_profile_configuration", kwargs={"software_id": self.software.pk, "profile_id": self.profile.profile_id})

    def support_url(self):
        return reverse("catalog:api_downstream_support", kwargs={"software_id": self.software.pk})

    def test_b1_shared_device_uses_event_authorization_and_safe_projection(self):
        request, key = self._request(action="activate", request_id="shared-a")
        first = activate_license(request=request, clock=FixedClock(self.now))
        authorization_a = first.payload["authorization_id"]
        request, _ = self._request(action="deactivate", request_id="unbind-a", authorization_id=authorization_a, private_key=key)
        deactivate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=1)))
        other = create_downstream_direct(actor=self.admin, username="private-owner-b", password="Another-password-123")
        from authorization_platform.catalog.services import set_downstream_software_access
        set_downstream_software_access(actor=self.admin, downstream_public_id=other.public_id, software_id=self.software.pk, enabled=True)
        issued = generate_license_batch(actor=other.user, software_id=self.software.pk, plan_snapshot_id=self.snapshot.pk, quantity=1, idempotency_key="issue-b")
        card_b = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        request, _ = self._request(action="activate", request_id="shared-b", private_key=key, license_key=decrypt_license_card(card_b.card_ciphertext))
        second = activate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=2)))
        authorization_b = second.payload["authorization_id"]
        binding = DeviceBinding.objects.get(authorization_id=authorization_b)
        block_physical_device(actor=self.admin, device_id=binding.device_id, reason="共享设备封禁测试")
        # A physical-device event belongs to the device, never the latest reseller.
        event = AuditEvent.objects.filter(object_type="Device", object_public_id=str(binding.device_id)).latest("occurred_at")
        self.assertNotEqual(present_event(event).object_label, other.user.username)
        # Even historical/malformed metadata must not expose another authorization.
        record_event(actor=self.admin, action="test.shared_projection", outcome="success", object_type="Device", object_public_id=str(binding.device_id), metadata={"authorization_id": authorization_b, "current_downstream_public_id": str(other.public_id), "downstream_public_id": str(self.downstream.public_id)})
        record_event(actor=self.admin, action="test.shared_generic_projection", outcome="success", object_type="Device", object_public_id=str(binding.device_id), metadata={"current_downstream_public_id": str(other.public_id), "downstream_public_id": str(self.downstream.public_id)})
        client = self.downstream_client()
        response = client.get(reverse("audit:api_downstream_audit"))
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertNotIn(other.user.username, text)
        self.assertNotIn(authorization_b, text)
        self.assertNotIn(str(other.public_id), text)
        actions = {item["action"] for item in response.json()["items"]}
        self.assertIn("device.block_physical", actions)
        self.assertIn("test.shared_generic_projection", actions)
        self.assertNotIn("test.shared_projection", actions)
        exported = client.get(reverse("audit:api_downstream_audit_export"))
        self.assertNotIn(authorization_b, exported.content.decode())
        self.assertNotIn(other.user.username, exported.content.decode())
        self.assertNotIn(str(other.public_id), exported.content.decode())
        # An authorization-scoped device event resolves the recorded owner, not B.
        scoped = record_event(action="test.scoped_device", outcome="success", object_type="Device", object_public_id=str(binding.device_id), metadata={"authorization_id": authorization_a})
        self.assertEqual(present_event(scoped).object_label, self.downstream.user.username)
        # Projection does not rewrite the stored audit fact.
        stored = AuditEvent.objects.get(action="test.shared_generic_projection")
        self.assertEqual(stored.metadata["current_downstream_public_id"], str(other.public_id))

    def test_b1_authorization_scoped_device_query_paginates_and_exports(self):
        request, _ = self._request(action="activate", request_id="audit-scoped-device")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        self.assertEqual(activated.status_code, 200)
        own_authorization_id = activated.payload["authorization_id"]
        binding = DeviceBinding.objects.get(authorization_id=own_authorization_id)
        foreign_authorization_id = "11111111-1111-4111-8111-111111111111"
        action = "test.device_owner_projection"
        expected = set()
        for label, metadata in [
            ("own", {"authorization_id": own_authorization_id}),
            ("generic", {}),
            ("empty", {"authorization_id": ""}),
            ("foreign", {"authorization_id": foreign_authorization_id}),
            ("malformed", {"authorization_id": "not-a-uuid"}),
        ]:
            event = record_event(
                actor=self.admin, action=action, outcome="success", object_type="Device",
                object_public_id=str(binding.device_id),
                metadata={"downstream_public_id": str(self.downstream.public_id), **metadata},
            )
            if label in {"own", "generic", "empty"}:
                expected.add(event.pk)
        events = audit_events_for_user(user=self.downstream.user, filters={"action": action})
        # The own-authorization row forces the text IN predicate to run during
        # COUNT as well as row selection; UUID strings are not JSON documents.
        self.assertEqual(events.count(), 3)
        self.assertEqual(set(events.values_list("pk", flat=True)), expected)
        page = paginate_audit_events(events, page_number=2, page_size=1)
        self.assertEqual(page.paginator.count, 3)
        self.assertEqual(page.number, 2)
        self.assertEqual(len(list(page.object_list)), 1)
        client = self.downstream_client()
        response = client.get(reverse("audit:api_downstream_audit"), {"action": action, "page_size": 1, "page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(len(response.json()["items"]), 1)
        response = client.get(reverse("audit:api_downstream_audit_export"), {"action": action})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(csv_rows(response)), 4)
        self.assertNotIn(foreign_authorization_id, response.content.decode())

    def _configuration_replay(self, client, url, model, target):
        a, b = {"values": {"qq": "saved-a"}}, {"values": {"qq": "saved-b"}}
        first = self.post(client, url, a, "config-a")
        self.assertEqual(first.status_code, 200)
        second = self.post(client, url, b, "config-b")
        self.assertEqual(second.status_code, 200)
        cache.clear()  # durability must not depend on process-local cache
        replay = self.post(client, url, a, "config-a")
        self.assertEqual(replay.json(), first.json())
        current = model.objects.get(pk=target.pk)
        self.assertEqual(current.support_qq, "saved-b")
        self.assertEqual(self.post(client, url, b, "config-a").status_code, 409)
        self.assertEqual(model.objects.get(pk=target.pk).config_version, current.config_version)

    def test_b4_profile_persistent_replay_and_conflict(self):
        self._configuration_replay(self.admin_client(), self.profile_url(), SoftwareProfile, self.profile)

    def test_b4_downstream_persistent_replay_and_conflict(self):
        from authorization_platform.catalog.models import DownstreamSoftware
        access = DownstreamSoftware.objects.get(downstream=self.downstream, software=self.software)
        self._configuration_replay(self.downstream_client(), self.support_url(), DownstreamSoftware, access)

    def test_b4_configuration_requires_key(self):
        for client, url in [(self.admin_client(), self.profile_url()), (self.downstream_client(), self.support_url())]:
            with self.subTest(url=url):
                self.assertEqual(self.post(client, url, {"values": {"qq": "x"}}).status_code, 400)

    def test_b4_key_cannot_be_reused_for_another_profile(self):
        other = create_profile(actor=self.admin, software_id=self.software.pk, profile_id="other", client_id="other-client", status="active")
        client = self.admin_client()
        body = {"values": {"qq": "same-body"}}
        self.assertEqual(self.post(client, self.profile_url(), body, "shared-key").status_code, 200)
        url = reverse("catalog:api_manage_profile_configuration", kwargs={"software_id": self.software.pk, "profile_id": other.profile_id})
        response = self.post(client, url, body, "shared-key")
        self.assertEqual(response.status_code, 409)
        other.refresh_from_db()
        self.assertEqual(other.support_qq, "")

    def test_b4_downstream_clear_replay_does_not_clear_a_later_save(self):
        client, url = self.downstream_client(), self.support_url()
        first = self.post(client, url, {"clear": True}, "clear-key")
        second = self.post(client, url, {"values": {"qq": "later"}}, "later-key")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self.post(client, url, {"clear": True}, "clear-key").json(), first.json())
        self.assertEqual(client.get(url).json()["support"]["qq"], "later")

    def test_b4_saved_configuration_keeps_fact_after_downstream_deletion(self):
        from authorization_platform.accounts.services import archive_downstream, delete_archived_downstream
        from authorization_platform.catalog.models import ConfigurationOperation

        response = self.post(self.downstream_client(), self.support_url(), {"values": {"qq": "saved"}}, "survives-delete")
        self.assertEqual(response.status_code, 200)
        archive_downstream(actor=self.admin, public_id=self.downstream.public_id, reason="归档下游测试")
        delete_archived_downstream(actor=self.admin, public_id=self.downstream.public_id, reason="删除下游测试")
        operation = ConfigurationOperation.objects.get(idempotency_key="survives-delete")
        self.assertIsNone(operation.actor_id)
        self.assertIn(str(self.downstream.public_id), operation.target)
        self.assertEqual(operation.response_payload, response.json())

    def test_b4_atomic_rollback_leaves_key_retryable(self):
        url, client = self.profile_url(), self.admin_client()
        before = AuditEvent.objects.count()
        with patch("authorization_platform.catalog.configuration.record_event", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.post(client, url, {"values": {"qq": "value"}}, "atomic")
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.support_qq, "")
        self.assertEqual(AuditEvent.objects.count(), before)
        self.assertEqual(self.post(client, url, {"values": {"qq": "value"}}, "atomic").status_code, 200)

    def test_b5_invitation_export_matches_filters_and_expiry(self):
        batch = InvitationBatch.objects.create(created_by=self.admin, quantity=4)
        for index, (status, username, expires) in enumerate([("consumed", "chosen", None), ("issued", "", None), ("issued", "", timezone.now()-timedelta(days=1)), ("archived", "chosen", None)]):
            InvitationCode.objects.create(batch=batch, status=status, code_hash=f"{index:064}", code_ciphertext="", consumed_username=username, expires_at=expires)
        client = self.admin_client()
        for params in ({"status": "consumed", "q": "chosen"}, {"status": "expired"}, {"scope": "archived"}):
            with self.subTest(params=params):
                listed = client.get(reverse("accounts:api_invitation_collection"), params).json()
                exported = csv_rows(client.get(reverse("accounts:api_invitation_export"), params))
                self.assertEqual({r[0] for r in exported[1:]}, {r["public_id"] for r in listed["items"]})

    def test_b5_invitation_export_cap_and_invalid_filter(self):
        batch = InvitationBatch.objects.create(created_by=self.admin, quantity=1001)
        InvitationCode.objects.bulk_create([InvitationCode(batch=batch, code_hash=f"{i:064}", code_ciphertext="") for i in range(1001)])
        client = self.admin_client()
        response = client.get(reverse("accounts:api_invitation_export"))
        self.assertEqual(len(csv_rows(response)), 1001)
        self.assertEqual(response.get("X-Export-Truncated"), "1")
        self.assertEqual(response.get("X-Export-Total"), "1001")
        self.assertEqual(client.get(reverse("accounts:api_invitation_export"), {"status": "wrong"}).status_code, 400)

    def test_b5_ledger_export_uses_list_search(self):
        credit_quota(actor=self.admin, downstream=self.downstream, amount=11, reason="chosen-ledger", idempotency_key="chosen")
        credit_quota(actor=self.admin, downstream=self.downstream, amount=12, reason="excluded-ledger", idempotency_key="excluded")
        client = self.admin_client()
        response = client.get(reverse("credits:api_manage_credit_ledger_export"), {"ledger_q": "chosen-ledger"})
        rows = csv_rows(response)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][-1], "chosen-ledger")
        self.assertEqual(client.get(reverse("credits:api_manage_credit_ledger_export"), {"ledger_q": "x"*129}).status_code, 400)

    def test_b5_catalog_export_deleted_plan_count_and_cap(self):
        self.plan.status = "deleted"
        self.plan.save(update_fields=["status"])
        client = self.admin_client()
        response = client.get(reverse("catalog:api_manage_catalog_export"))
        self.assertEqual(csv_rows(response)[1][-1], "0")
        Software.objects.bulk_create([Software(software_id=f"extra-{i}", name=f"Extra {i}") for i in range(1000)])
        response = client.get(reverse("catalog:api_manage_catalog_export"))
        self.assertEqual(len(csv_rows(response)), 1001)
        self.assertEqual(response.get("X-Export-Truncated"), "1")
        self.assertEqual(response.get("X-Export-Total"), "1001")

    def test_b6_three_management_routes_accept_dots(self):
        paths = [
            ("/api/v1/manage/catalog/software/tool.v1/status/", "api_catalog_software_status"),
            ("/api/v1/manage/catalog/software/tool.v1/profiles/stable.v1/policy/revise/", "api_catalog_policy_revise"),
            ("/api/v1/manage/software/tool.v1/profiles/stable.v1/configuration/", "api_manage_profile_configuration"),
        ]
        for path, name in paths:
            with self.subTest(path=path):
                self.assertEqual(resolve(path).url_name, name)
        software = Software.objects.create(software_id="tool.v1", name="Dotted software", status="active")
        profile = create_profile(actor=self.admin, software_id=software.pk, profile_id="stable.v1", client_id="dotted-client", status="active")
        create_policy_version(actor=self.admin, software_id=software.pk, profile_id=profile.profile_id, version="policy-1", status="active")
        client = self.admin_client()
        self.assertEqual(self.post(client, paths[2][0], {"values": {"qq": "dotted"}}, "dot-config").status_code, 200)
        self.assertEqual(self.post(client, paths[1][0], {"max_devices": 2}, "dot-policy").status_code, 200)
        self.assertEqual(self.post(client, paths[0][0], {"status": "archived", "reason": "点号软件下架测试"}, "dot-status").status_code, 200)

    def test_b7_lone_surrogate_username_is_json_400(self):
        for route in ["accounts:api_login", "accounts:api_register"]:
            with self.subTest(route=route):
                response = self.post(Client(), reverse(route), {"username": "bad\ud800", "password": "Any-password-123", "entrypoint": "downstream", "invitation_code": "invalid"})
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.json())

    def test_b7_invalid_tombstone_uuid_is_json_400(self):
        before = QuotaLedgerEntry.objects.count()
        response = self.post(self.admin_client(), reverse("credits:api_recover_deleted_credits"), {"downstream_public_id": "bad-uuid", "amount": 1, "reason": "invalid uuid test"}, "bad-uuid")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())
        self.assertEqual(QuotaLedgerEntry.objects.count(), before)

    def test_b7_malformed_ipv6_url_is_json_400(self):
        response = self.post(self.admin_client(), self.profile_url(), {"values": {"purchase_url": "https://[broken"}}, "bad-url")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.support_purchase_url, "")

    def test_b9_maximum_composite_audit_references_are_not_truncated(self):
        software = Software.objects.create(software_id="s"*64, name="Long identity", status="active")
        profile = create_profile(actor=self.admin, software_id=software.pk, profile_id="p"*64, client_id="long-client", status="active")
        policy = create_policy_version(actor=self.admin, software_id=software.pk, profile_id=profile.profile_id, version="v"*64, status="active")
        capability = create_capability_definition(actor=self.admin, software_id=software.pk, profile_id=profile.profile_id, capability_key="namespace."+"c"*118, value_type="boolean", default_value=True)
        self.assertEqual(len(f"{profile}/{capability.capability_key}"), 258)
        for action, reference in [("software_profile.create", str(profile)), ("policy_version.create", f"{profile}/{policy.version}"), ("capability_definition.create", f"{profile}/{capability.capability_key}")]:
            with self.subTest(action=action):
                self.assertTrue(AuditEvent.objects.filter(action=action, object_public_id=reference).exists(), reference)


@skipUnless(connection.vendor == "postgresql", "requires PostgreSQL row locking")
class ConfigurationConcurrencyTests(TransactionTestCase):
    setUp = FinalBusinessTests.setUp
    _user_admin = staticmethod(FinalBusinessTests._user_admin)

    def _race(self, *, downstream, different_bodies):
        user = self.downstream.user if downstream else self.admin
        url = FinalBusinessTests.support_url(self) if downstream else FinalBusinessTests.profile_url(self)
        clients = []
        for _ in range(2):
            client = Client()
            client.force_login(user)
            if downstream:
                session = client.session
                session["downstream_session_version"] = self.downstream.session_version
                session.save()
            clients.append(client)
        barrier = threading.Barrier(2)

        def write(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                body = {"values": {"qq": f"value-{index if different_bodies else 0}"}}
                response = clients[index].post(url, data=json.dumps(body), content_type="application/json", HTTP_IDEMPOTENCY_KEY="race-key")
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(write, [0, 1]))
        from authorization_platform.catalog.models import ConfigurationOperation
        self.assertEqual(ConfigurationOperation.objects.filter(actor=user, idempotency_key="race-key").count(), 1)
        action = "downstream.configuration.update" if downstream else "profile.configuration.update"
        self.assertEqual(AuditEvent.objects.filter(action=action).count(), 1)
        if different_bodies:
            self.assertEqual(sorted(result[0] for result in results), [200, 409])
            self.assertEqual(next(body for status, body in results if status == 409)["error"]["code"], "IDEMPOTENCY_CONFLICT")
        else:
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0][0], 200)

    def test_b4_profile_concurrent_same_request_commits_once(self):
        self._race(downstream=False, different_bodies=False)

    def test_b4_downstream_concurrent_same_request_commits_once(self):
        self._race(downstream=True, different_bodies=False)

    def test_b4_profile_concurrent_different_body_conflicts(self):
        self._race(downstream=False, different_bodies=True)

    def test_b4_downstream_concurrent_different_body_conflicts(self):
        self._race(downstream=True, different_bodies=True)


@skipUnless(connection.vendor == "postgresql", "requires isolated PostgreSQL migration database")
class HistoricalBusinessMigrationTests(SimpleTestCase):
    def test_b2_pg_0008_data_upgrades_with_original_snapshot_semantics(self):
        import psycopg
        from psycopg import sql

        config = connection.settings_dict
        if config["HOST"] != "127.0.0.1" or str(config["PORT"]) != "55439" or config["USER"] != "final_review":
            self.skipTest("only the final-review temporary PostgreSQL is authorized")
        db = "business_writer_upgrade_" + uuid.uuid4().hex[:12]
        with psycopg.connect(dbname="postgres", user=config["USER"], host=config["HOST"], port=config["PORT"], autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db)))
            try:
                env = dict(os.environ, DATABASE_ENGINE="postgresql", DATABASE_NAME=db, DATABASE_USER=config["USER"], DATABASE_HOST=config["HOST"], DATABASE_PORT=str(config["PORT"]), DATABASE_PASSWORD="", PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"), DJANGO_SETTINGS_MODULE="authorization_platform.settings")
                script = '''
import django
django.setup()
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone
from datetime import timedelta
ex = MigrationExecutor(connection)
targets = [("catalog", "0008_policy_revision_operation"), ("auth", "0012_alter_user_first_name_max_length"), ("audit", "0001_initial")]
ex.migrate(targets)
apps = ex.loader.project_state(targets).apps
User = apps.get_model("auth", "User")
actor = User.objects.create(username="migration-admin", is_staff=True, is_superuser=True, is_active=True)
Software = apps.get_model("catalog", "Software")
Profile = apps.get_model("catalog", "SoftwareProfile")
Policy = apps.get_model("catalog", "PolicyVersion")
Plan = apps.get_model("catalog", "Plan")
Snapshot = apps.get_model("catalog", "PlanSnapshot")
s = Software.objects.create(software_id="old-tool", name="Old", status="active")
p = Profile.objects.create(software=s, profile_id="stable", client_id="old-client", status="active")
old = Policy.objects.create(profile=p, version="policy-1", status="active", allow_device_switch=False, device_switch_limit=0, max_devices=2, verify_interval_seconds=180, offline_grace_seconds=23, device_proof_required=False, created_by=actor)
plan = Plan.objects.create(software=s, profile=p, name="Current plan", duration_seconds=7200, quota_cost=7, capability_values={"x": True}, status="active")
snap = Snapshot.objects.create(plan=plan, software=s, profile=p, policy_version=old, snapshot_version=1, name="Old snapshot", duration_seconds=3600, quota_cost=3, capability_values={"x": False})
# Archived Profile must not be revised, even with an eligible active policy.
archived = Profile.objects.create(software=s, profile_id="archived", client_id="archived-client", status="archived")
Policy.objects.create(profile=archived, version="policy-1", status="active", allow_device_switch=False, device_switch_limit=0)
# Most recent active policy determines eligibility, not any older active row.
newer = Profile.objects.create(software=s, profile_id="newer", client_id="newer-client", status="active")
Policy.objects.create(profile=newer, version="policy-1", status="active", allow_device_switch=False, device_switch_limit=0, effective_at=timezone.now()-timedelta(days=2))
Policy.objects.create(profile=newer, version="policy-2", status="active", allow_device_switch=True, device_switch_limit=9)
ex = MigrationExecutor(connection)
ex.migrate([("catalog", "0009_backfill_default_daily_device_switch")])
apps = ex.loader.project_state([("catalog", "0009_backfill_default_daily_device_switch")]).apps
Policy = apps.get_model("catalog", "PolicyVersion")
Snapshot = apps.get_model("catalog", "PlanSnapshot")
current = Policy.objects.get(profile_id=p.pk, status="active")
assert (current.allow_device_switch, current.device_switch_limit, current.max_devices, current.verify_interval_seconds, current.offline_grace_seconds, current.device_proof_required) == (True, 5, 2, 180, 23, False)
assert Policy.objects.get(pk=old.pk).status == "archived"
assert Snapshot.objects.get(pk=snap.pk).duration_seconds == 3600
new = Snapshot.objects.get(plan_id=plan.pk, snapshot_version=2)
assert (new.name, new.duration_seconds, new.quota_cost, new.capability_values, new.policy_version_id) == ("Current plan", 7200, 7, {"x": True}, current.pk)
assert Policy.objects.filter(profile_id=archived.pk).count() == 1
assert Policy.objects.filter(profile_id=newer.pk).count() == 2
assert apps.get_model("audit", "AuditEvent").objects.filter(action="policy_version.revise").count() == 1
print("PG_0008_TO_0009_SEMANTICS_OK")
# Expand the real old audit table and keep its existing facts intact.
ex = MigrationExecutor(connection)
ex.migrate(ex.loader.graph.leaf_nodes())
apps = ex.loader.project_state(ex.loader.graph.leaf_nodes()).apps
Audit = apps.get_model("audit", "AuditEvent")
assert Audit.objects.filter(action="policy_version.revise").count() == 1
assert Audit._meta.get_field("object_public_id").max_length == 512
reference = "s"*64 + "/" + "p"*64 + "/" + "c"*128
row = Audit.objects.create(action="test.maximum_reference", outcome="success", request_id="migration-long-ref", object_type="CapabilityDefinition", object_public_id=reference)
assert Audit.objects.get(pk=row.pk).object_public_id == reference
with connection.cursor() as cursor:
    cursor.execute("SELECT character_maximum_length FROM information_schema.columns WHERE table_name='audit_auditevent' AND column_name='object_public_id'")
    assert cursor.fetchone()[0] == 512
print("PG_AUDIT_EXPANSION_PRESERVES_ROWS_AND_258_CHAR_REF_OK")
'''
                result = subprocess.run([sys.executable, "-c", script], env=env, cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PG_0008_TO_0009_SEMANTICS_OK", result.stdout)
                self.assertIn("PG_AUDIT_EXPANSION_PRESERVES_ROWS_AND_258_CHAR_REF_OK", result.stdout)
            finally:
                admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(db)))
