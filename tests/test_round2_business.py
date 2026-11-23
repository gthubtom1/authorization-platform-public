"""R2A-01/02: deterministic public-request and persisted-history regressions."""
import csv
import io
import json
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import OperationalError, close_old_connections, connection, connections
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

from authorization_platform.audit.models import AuditEvent
from authorization_platform.licensing import authorization as services
from authorization_platform.licensing.models import DeviceBinding, LicenseInstance
from tests.test_final_authorization import FinalFixture


LOW = uuid.UUID(int=1)
HIGH = uuid.UUID(int=(1 << 128) - 1)


class BindingFixture(FinalFixture):
    def public_at(self, action, label, key=None, authid=None, second=0, binding_id=None):
        body, private_key = self._request(action=action, request_id=label,
                                         private_key=key, authorization_id=authid)
        original = DeviceBinding.save

        def save(binding, *args, **kwargs):
            if binding._state.adding and binding_id is not None:
                binding.binding_id = binding_id
            return original(binding, *args, **kwargs)

        with patch.object(services, "_server_now", return_value=self.now + timedelta(seconds=second)):
            with patch.object(DeviceBinding, "save", save):
                response = self.public(action, body)
        return response, private_key

    def start(self, binding_id=HIGH):
        response, key = self.public_at("activate", "first", binding_id=binding_id)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["authorization_id"], key

    def exit(self, label, key, authid, second=0):
        response, _ = self.public_at("deactivate", label, key, authid, second)
        self.assertEqual(response.status_code, 200, response.content)

    def assert_current_readers(self, authid):
        for state, expected in (("bound", 1), ("unbound", 0)):
            filters = {"q": authid, "device_state": state}
            response = self.client.get(reverse("licensing:api_manage_authorizations"), filters)
            self.assertEqual(response.status_code, 200, response.content)
            self.assertEqual(response.json()["pagination"]["total"], expected)
            if expected:
                device = response.json()["items"][0]["devices"][0]
                self.assertEqual(device["binding_state"], "active")
                self.assertEqual(device["binding_history"][0]["binding_state"], "active")
                current = DeviceBinding.objects.get(authorization_id=authid, state="active")
                self.assertEqual(device["binding_order_known"], current.binding_order > 0)
            preview = self.client.get(reverse("licensing:api_manage_authorization_renew_preview"),
                                      {**filters, "unit": "hour", "amount": 1})
            self.assertEqual(preview.status_code, 200, preview.content)
            self.assertEqual(preview.json()["renewable_count"], expected)
            export = self.client.get(reverse("licensing:api_manage_authorizations_export"), filters)
            self.assertEqual(export.status_code, 200, export.content)
            rows = list(csv.reader(io.StringIO(export.content.decode("utf-8-sig"))))
            self.assertEqual(len(rows) - 1, expected)
        instance = LicenseInstance.objects.get(pk=authid)
        detail = self.client.post(reverse("licensing:api_manage_license_card_search"),
                                  data=json.dumps({"code": self.license_key}), content_type="application/json")
        self.assertEqual(detail.status_code, 200, detail.content)
        self.assertEqual(detail.json()["item"]["device_state"], "已绑定")
        downstream = Client()
        downstream.force_login(self.downstream.user)
        session = downstream.session
        session["downstream_session_version"] = str(self.downstream.session_version)
        session.save()
        devices = downstream.get(reverse("licensing:api_downstream_devices"), {"q": authid})
        self.assertEqual(devices.status_code, 200, devices.content)
        self.assertEqual(devices.json()["pagination"]["total"], 1)
        self.assertEqual(devices.json()["items"][0]["binding_state"], "active")
        preview = self.client.get(reverse("licensing:api_manage_authorization_renew_preview"),
                                  {"q": authid, "device_state": "bound", "unit": "hour", "amount": 1})
        renew = self.post("renew", {"authorization_ids": preview.json()["authorization_ids"],
                                    "unit": "hour", "amount": 1, "reason": "同秒恢复续期"})
        self.assertEqual(renew.status_code, 200, renew.content)
        self.assertEqual(renew.json()["renewed_count"], 1)
        instance.refresh_from_db()
        self.assertEqual(instance.expires_at, self.now + timedelta(seconds=self.snapshot.duration_seconds, hours=1))


class BindingOrderTests(BindingFixture, TestCase):
    def old_new_old(self, first_id, second_id, step=0):
        self._revise_daily_switch(allow=True, limit=1)
        authid, old = self.start(first_id)
        self.exit("old-exit", old, authid, step)
        response, new = self.public_at("activate", "new", second=2 * step, binding_id=second_id)
        self.assertEqual(response.status_code, 200, response.content)
        self.exit("new-exit", new, authid, 3 * step)
        response, _ = self.public_at("activate", "old-return", old, second=4 * step)
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(response.json()["error"]["code"], "DEVICE_SWITCH_LIMIT_REACHED")
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)
        response, _ = self.public_at("activate", "current-return", new, second=5 * step)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIs(type(response.json()["server_time"]), int)
        self.assertIs(type(response.json()["expires_at"]), int)
        self.assertEqual(DeviceBinding.objects.filter(authorization_id=authid, state="active").count(), 1)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)

    def test_same_second_old_uuid_larger_than_new(self):
        self.old_new_old(HIGH, LOW)

    def test_same_second_old_uuid_smaller_than_new(self):
        self.old_new_old(LOW, HIGH)

    def test_different_second_control(self):
        self.old_new_old(HIGH, LOW, step=1)

    def test_same_key_restore_all_readers_and_real_renewal(self):
        self._revise_daily_switch(allow=True, limit=1)
        authid, key = self.start()
        self.exit("exit", key, authid)
        response, _ = self.public_at("activate", "restore", key, binding_id=LOW)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 0)
        self.assertEqual(DeviceBinding.objects.filter(authorization_id=authid, state="active").count(), 1)
        self.assert_current_readers(authid)

    def test_active_key_rotation_advances_order_past_newer_history(self):
        self._revise_daily_switch(allow=True, limit=5)
        authid, key = self.start()
        self.exit("first-exit", key, authid)
        restored, _ = self.public_at("activate", "restore-same", key, binding_id=LOW)
        self.assertEqual(restored.status_code, 200)
        before = DeviceBinding.objects.get(authorization_id=authid, state="active").binding_order
        rotated, new = self.public_at("activate", "rotate-live")
        self.assertEqual(rotated.status_code, 200)
        self.assertGreater(DeviceBinding.objects.get(authorization_id=authid, state="active").binding_order, before)
        self.exit("rotate-exit", new, authid)
        returned, _ = self.public_at("activate", "restore-old", key)
        self.assertEqual(returned.status_code, 200)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 2)

    def test_reset_targets_current_same_second_binding(self):
        authid, key = self.start()
        self.exit("reset-exit", key, authid)
        response, _ = self.public_at("activate", "reset-restore", key, binding_id=LOW)
        self.assertEqual(response.status_code, 200)
        listed = self.client.get(reverse("licensing:api_manage_authorizations"), {"q": authid}).json()
        ref = listed["items"][0]["devices"][0]["device_action_ref"]
        response = self.client.post(reverse("licensing:api_manage_authorization_device_reset", args=[authid, ref]),
                                    data=json.dumps({"reason": "同秒当前绑定重置"}), content_type="application/json",
                                    HTTP_IDEMPOTENCY_KEY="round2-reset")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(DeviceBinding.objects.filter(authorization_id=authid, state="active").exists())


class LegacyBindingMigrationTests(BindingFixture, TransactionTestCase):
    def migrate_legacy(self):
        target = [("licensing", "0012_launchticket")]
        executor = MigrationExecutor(connection)
        executor.migrate(target)
        old = executor.loader.project_state(target).apps.get_model("licensing", "DeviceBinding")
        self.assertNotIn("binding_order", [field.name for field in old._meta.fields])
        fields = [field.attname for field in old._meta.fields]
        before = list(old.objects.order_by("binding_id").values(*fields))
        try:
            MigrationExecutor(connection).migrate([("licensing", "0013_devicebinding_binding_order")])
        finally:
            # Always restore the current schema for teardown and following tests.
            MigrationExecutor(connection).migrate(executor.loader.graph.leaf_nodes())
        after = list(DeviceBinding.objects.order_by("binding_id").values(*fields))
        self.assertEqual(after, before, "migration must preserve keys, states, timestamps and authorization facts")
        self.assertEqual(set(DeviceBinding.objects.values_list("binding_order", flat=True)), {0})

    def ambiguous_keys(self, old_id, new_id):
        self._revise_daily_switch(allow=True, limit=1)
        authid, old = self.start(old_id)
        self.exit("exit-old", old, authid)
        response, new = self.public_at("activate", "legacy-new", binding_id=new_id)
        self.assertEqual(response.status_code, 200)
        self.exit("exit-new", new, authid)
        self.migrate_legacy()
        for label, key in (("ambiguous-old", old), ("ambiguous-new", new)):
            response, _ = self.public_at("activate", label, key)
            self.assertEqual(response.status_code, 403, response.content)
            self.assertEqual(response.json()["error"]["code"], "DEVICE_SWITCH_LIMIT_REACHED")
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)
        # Next Beijing day a single conservative charge establishes an exact
        # event, and further same-key recovery is free even at the daily limit.
        response, _ = self.public_at("activate", "next-day", new, second=86400)
        self.assertEqual(response.status_code, 200)
        event = AuditEvent.objects.filter(action="device.key_rotate").order_by("-occurred_at").first()
        self.assertTrue(event.metadata["legacy_key_order_ambiguous"])
        self.assertEqual(event.metadata["old_key_id"], "")
        self.exit("next-day-exit", new, authid, 86400)
        response, _ = self.public_at("activate", "known-again", new, second=86400)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)

    def test_legacy_multi_key_old_uuid_high_is_conservative(self):
        self.ambiguous_keys(HIGH, LOW)

    def test_legacy_multi_key_old_uuid_low_is_conservative(self):
        self.ambiguous_keys(LOW, HIGH)

    def test_legacy_single_key_tie_is_free_and_active_history_agrees(self):
        self._revise_daily_switch(allow=True, limit=1)
        authid, key = self.start()
        self.exit("legacy-exit", key, authid)
        response, _ = self.public_at("activate", "legacy-restore", key, binding_id=LOW)
        self.assertEqual(response.status_code, 200)
        self.migrate_legacy()
        self.assert_current_readers(authid)
        self.exit("legacy-exit-again", key, authid)
        response, _ = self.public_at("activate", "legacy-free", key)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 0)

    def test_legacy_different_second_latest_key_stays_free(self):
        self._revise_daily_switch(allow=True, limit=1)
        authid, old = self.start()
        self.exit("legacy-old-exit", old, authid)
        response, new = self.public_at("activate", "legacy-second-new", second=2, binding_id=LOW)
        self.assertEqual(response.status_code, 200)
        self.exit("legacy-new-exit", new, authid, 3)
        self.migrate_legacy()
        response, _ = self.public_at("activate", "legacy-current-free", new, second=4)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)

    def test_legacy_multi_key_active_is_authoritative_for_history_and_free_recovery(self):
        self._revise_daily_switch(allow=True, limit=1)
        authid, old = self.start()
        self.exit("legacy-active-exit", old, authid)
        response, new = self.public_at("activate", "legacy-active-new", binding_id=LOW)
        self.assertEqual(response.status_code, 200)
        self.migrate_legacy()
        response, _ = self.public_at("activate", "legacy-active-same", new)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)
        self.assert_current_readers(authid)
        response, _ = self.public_at("activate", "legacy-active-old", old)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "DEVICE_SWITCH_LIMIT_REACHED")


@skipUnless(connection.vendor == "postgresql", "requires real PostgreSQL row locks")
class BindingConcurrencyTests(BindingFixture, TransactionTestCase):
    def concurrent(self, requests):
        gate = Barrier(len(requests))

        def worker(body):
            close_old_connections()
            try:
                gate.wait(timeout=10)
                response = Client().post(reverse("licensing:public_license_activate"),
                                          data=json.dumps(body), content_type="application/json")
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with patch.object(services, "_server_now", return_value=self.now):
            with ThreadPoolExecutor(max_workers=len(requests)) as pool:
                return list(pool.map(worker, requests))

    def test_parallel_new_keys_cannot_both_spend_final_daily_slot(self):
        self._revise_daily_switch(allow=True, limit=1)
        authid, old = self.start()
        self.exit("concurrent-exit", old, authid)
        bodies = [self._request(action="activate", request_id=f"concurrent-{index}")[0] for index in range(2)]
        results = self.concurrent(bodies)
        self.assertEqual(sorted(status for status, _ in results), [200, 403], results)
        self.assertEqual([body["error"]["code"] for status, body in results if status == 403], ["DEVICE_SWITCH_LIMIT_REACHED"])
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 1)
        self.assertEqual(DeviceBinding.objects.filter(authorization_id=authid, state="active").count(), 1)
        self.assertEqual(list(DeviceBinding.objects.filter(authorization_id=authid).order_by("binding_order").values_list("binding_order", flat=True)), [1, 2])

    def test_parallel_same_key_recovery_is_free_and_creates_one_active(self):
        self._revise_daily_switch(allow=True, limit=1)
        authid, key = self.start()
        self.exit("concurrent-same-exit", key, authid)
        bodies = [self._request(action="activate", request_id=f"same-{index}", private_key=key)[0] for index in range(2)]
        results = self.concurrent(bodies)
        self.assertEqual([status for status, _ in results], [200, 200], results)
        self.assertEqual(LicenseInstance.objects.get(pk=authid).device_switch_count, 0)
        self.assertEqual(DeviceBinding.objects.filter(authorization_id=authid, state="active").count(), 1)
        self.assertEqual(DeviceBinding.objects.filter(authorization_id=authid).count(), 2)


class AccountJsonTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client(enforce_csrf_checks=True, raise_request_exception=False)
        self.assertEqual(self.client.get(reverse("accounts:api_session")).status_code, 200)
        self.password = "Round2-only-fixture-933!"
        self.user = get_user_model().objects.create_superuser(username="round2-admin", password=self.password)

    def post_raw(self, raw):
        return self.client.post(reverse("accounts:api_login"), data=raw, content_type="application/json",
                                HTTP_X_CSRFTOKEN=self.client.cookies["csrftoken"].value)

    def assert_invalid(self, raw):
        before = (get_user_model().objects.count(), AuditEvent.objects.count())
        limit = sys.getrecursionlimit()
        response = self.post_raw(raw)
        self.assertEqual(response.status_code, 400, response.content[:200])
        self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
        self.assertFalse(response.json()["error"]["retryable"])
        self.assertIsNone(response.exc_info)
        self.assertEqual(sys.getrecursionlimit(), limit)
        self.assertEqual((get_user_model().objects.count(), AuditEvent.objects.count()), before)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_600_levels_parseable_json_is_structured_400(self):
        raw = '{"username":"round2-admin","password":"' + self.password + '","padding":' + '[' * 600 + '0' + ']' * 600 + '}'
        self.assertIsInstance(json.loads(raw), dict)
        self.assert_invalid(raw)

    def test_parser_recursion_is_structured_400(self):
        raw = '{"padding":' + '[' * 2000 + '0' + ']' * 2000 + '}'
        with self.assertRaises(RecursionError):
            json.loads(raw)
        self.assert_invalid(raw)

    def test_invalid_unicode_json_and_size_controls(self):
        for raw in (b'{"username":"\xff"}', '{bad', '[]', '{"username":"\\ud800"}',
                    '{"\\udfff":"key"}', '{"padding":[{"value":"\\udc00"}]}',
                    '{"padding":"' + 'a' * (32 * 1024) + '"}'):
            with self.subTest(raw=raw[:40]):
                self.assert_invalid(raw)

    def test_unicode_and_surrogate_pair_and_32k_boundary_login(self):
        body = {"username": "round2-admin", "password": self.password, "entrypoint": "admin",
                "padding": "中文😀"}
        raw = json.dumps(body, ensure_ascii=True)
        self.assertIn("\\ud83d\\ude00", raw)
        self.assertEqual(self.post_raw(raw).status_code, 200)
        self.client.logout()
        self.client.get(reverse("accounts:api_session"))
        raw = json.dumps({**body, "padding": "中文"}, ensure_ascii=False)
        raw += ' ' * (32 * 1024 - len(raw.encode("utf-8")))
        self.assertEqual(len(raw.encode("utf-8")), 32 * 1024)
        self.assertEqual(self.post_raw(raw).status_code, 200)

    def test_nested_objects_and_explicit_depth_budget(self):
        self.assert_invalid('{"padding":' + '{"x":' * 600 + '0' + '}' * 600 + '}')
        raw = '{"username":"round2-admin","password":"' + self.password + '","entrypoint":"admin","padding":'
        self.assert_invalid(raw + '[' * 64 + '0' + ']' * 64 + '}')
        response = self.post_raw(raw + '[' * 63 + '0' + ']' * 63 + '}')
        self.assertEqual(response.status_code, 200)

    def test_database_failure_is_not_disguised_as_invalid_json(self):
        body = json.dumps({"username": "round2-admin", "password": self.password, "entrypoint": "admin"})
        self.client.raise_request_exception = True
        with patch("authorization_platform.accounts.api_views.LoginForm.is_valid", side_effect=OperationalError("injected database failure")):
            with self.assertRaises(OperationalError):
                self.post_raw(body)
