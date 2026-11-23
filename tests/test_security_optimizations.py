from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase, SimpleTestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.rate_limit import allow, blocked, reset, _cache_key
from authorization_platform.catalog.models import DownstreamSoftware, DownstreamSoftwareStatus, PolicyVersion
from authorization_platform.licensing.admin import revoke_authorization, reset_device_binding
from authorization_platform.licensing.authorization import AuthorizationOperationError, issue_launch_ticket, consume_launch_ticket
from authorization_platform.licensing.models import DeviceBinding, DeviceRiskState, LaunchTicket
from authorization_platform.core.time import FixedClock
from tests import test_launch_ticket as ticket_fixtures
from tests import test_catalog as catalog_fixtures


class AuthenticationBudgetTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client(enforce_csrf_checks=True)
        self.client.get(reverse("accounts:api_session"))
        self.headers = {"HTTP_X_CSRFTOKEN": self.client.cookies["csrftoken"].value, "REMOTE_ADDR": "192.0.2.46"}
        get_user_model().objects.create_superuser(username="admin", password="Review-pass-9276")

    def post(self, action, body, **extra):
        return self.client.post(reverse("accounts:api_" + action), json.dumps(body), content_type="application/json", **{**self.headers, **extra})

    @override_settings(AUTH_LOGIN_RATE_LIMIT=1)
    def test_normalized_aliases_cannot_refresh_login_budget(self):
        for i, name in enumerate(("admin", "ａｄｍｉｎ", "ａdmin")):
            response = self.post("login", {"entrypoint": "admin", "username": name, "password": "Wrong-password-123"})
            self.assertEqual(response.status_code, 401 if i == 0 else 429)
        self.assertEqual(self.post("login", {"entrypoint": "admin", "username": "admin", "password": "Review-pass-9276"}, REMOTE_ADDR="192.0.2.47").status_code, 200)

    @override_settings(AUTH_LOGIN_RATE_LIMIT=1)
    def test_changing_username_cannot_refresh_source_budget(self):
        for i, name in enumerate(("nonexistent-a", "nonexistent-b")):
            response = self.post("login", {"entrypoint": "admin", "username": name, "password": "Wrong-password-123"})
            self.assertEqual(response.status_code, 401 if i == 0 else 429)

    @override_settings(AUTH_REGISTER_RATE_LIMIT=1)
    def test_changing_invite_cannot_refresh_source_budget(self):
        for i, code in enumerate(("INVALID-INVITE-A", "INVALID-INVITE-B", "INVALID-INVITE-C")):
            response = self.post("register", {"invitation_code": code, "username": "review-account", "password": "Review-pass-9276", "password_confirm": "Review-pass-9276"})
            self.assertEqual(response.status_code, 400 if i == 0 else 429)


class TicketCurrentFactsTests(TestCase):
    _request = ticket_fixtures.LaunchTicketTests._request
    _activate = ticket_fixtures.LaunchTicketTests._activate
    _issue = ticket_fixtures.LaunchTicketTests._issue

    def setUp(self):
        ticket_fixtures.LaunchTicketTests.setUp(self)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def prepare(self):
        instance, key = self._activate()
        issued, request = self._issue(instance=instance, private_key=key, request_id="current-facts-issue")
        self.ticket_id = issued.payload["ticket"]["ticket_id"]
        return instance, key, request

    def consume_request(self, instance, key, request_id="current-facts-consume"):
        return self._request(action="ticket-consume", request_id=request_id, private_key=key, authorization_id=str(instance.authorization_id))[0]

    def assert_denied(self, call, request):
        with self.assertRaises(AuthorizationOperationError) as caught:
            call(request=request, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertIn(caught.exception.code, {"LICENSE_REVOKED", "LICENSE_EXPIRED", "LICENSE_BLOCKED", "DEVICE_NOT_BOUND", "RISK_BLOCKED", "LAUNCH_TICKET_DISABLED", "IDEMPOTENCY_CONFLICT", "TICKET_EXPIRED", "TICKET_ALREADY_CONSUMED", "LICENSE_NOT_ACTIVE"})

    def test_issue_replay_after_revoke_is_denied(self):
        instance, key, req = self.prepare()
        revoke_authorization(actor=self.admin, authorization_id=instance.authorization_id, reason="audit revoke", request_id="revoke")
        self.assert_denied(issue_launch_ticket, req)
        self.assertEqual(LaunchTicket.objects.count(), 1)

    def test_consume_after_revoke_is_denied_without_consuming(self):
        instance, key, req = self.prepare()
        revoke_authorization(actor=self.admin, authorization_id=instance.authorization_id, reason="audit revoke", request_id="revoke")
        self.assert_denied(consume_launch_ticket, self.consume_request(instance, key))
        self.assertIsNone(LaunchTicket.objects.get(ticket_id=self.ticket_id).consumed_at)

    def test_issue_and_consume_after_unbind_are_denied(self):
        instance, key, req = self.prepare()
        binding = DeviceBinding.objects.get(authorization=instance)
        reset_device_binding(actor=self.admin, authorization_id=instance.authorization_id, device_id=binding.device_id, reason="audit unbind", request_id="unbind")
        self.assert_denied(issue_launch_ticket, req)
        self.assert_denied(consume_launch_ticket, self.consume_request(instance, key))

    def test_issue_and_consume_after_device_block_are_denied(self):
        instance, key, req = self.prepare()
        device = DeviceBinding.objects.get(authorization=instance).device
        device.risk_state = DeviceRiskState.BLOCKED
        device.save(update_fields=("risk_state",), _allow_mutation=True)
        self.assert_denied(issue_launch_ticket, req)
        self.assert_denied(consume_launch_ticket, self.consume_request(instance, key))

    def test_issue_and_consume_after_policy_disabled_are_denied(self):
        instance, key, req = self.prepare()
        from authorization_platform.catalog.services import revise_policy_version
        revise_policy_version(actor=self.admin, software_id=self.software.pk, profile_id=self.profile.profile_id, max_devices=1, allow_device_switch=False, device_switch_limit=0, device_proof_required=True, verify_interval_seconds=60, offline_grace_seconds=0, launch_ticket_enabled=False)
        self.assert_denied(issue_launch_ticket, req)
        self.assert_denied(consume_launch_ticket, self.consume_request(instance, key))

    def test_expired_ticket_replay_does_not_issue_a_new_ticket(self):
        instance, key, req = self.prepare()
        with self.assertRaises(AuthorizationOperationError):
            issue_launch_ticket(request=req, clock=FixedClock(self.now + timedelta(seconds=181)))
        self.assertEqual(LaunchTicket.objects.count(), 1)

    def test_consumed_receipt_does_not_restore_allow_after_revoke(self):
        instance, key, req = self.prepare()
        consume_req = self.consume_request(instance, key)
        self.assertEqual(consume_launch_ticket(request=consume_req, clock=FixedClock(self.now)).status_code, 200)
        revoke_authorization(actor=self.admin, authorization_id=instance.authorization_id, reason="audit revoke", request_id="revoke")
        self.assert_denied(consume_launch_ticket, consume_req)

    def test_ticket_expiry_is_capped_by_license_expiry(self):
        instance, key = self._activate()
        issued, _ = self._issue(instance=instance, private_key=key, request_id="expiry-cap", clock=FixedClock(instance.expires_at - timedelta(seconds=1)))
        self.assertEqual(issued.payload["ticket"]["expires_at"], int(instance.expires_at.timestamp()))


class SoftwareRestoreTests(TestCase):
    setUp = catalog_fixtures.CatalogApiTests.setUp
    csrf_headers = catalog_fixtures.CatalogApiTests.csrf_headers
    post_json = catalog_fixtures.CatalogApiTests.post_json
    bundle_payload = staticmethod(catalog_fixtures.CatalogApiTests.bundle_payload)
    create_bundle = catalog_fixtures.CatalogApiTests.create_bundle

    def test_restore_is_durable_and_does_not_reopen_downstream_access(self):
        payload = self.bundle_payload("restore-tool")
        self.assertEqual(self.create_bundle(payload, key="restore-create").status_code, 201)
        from authorization_platform.catalog.services import set_downstream_software_access
        set_downstream_software_access(actor=self.admin, downstream_public_id=self.downstream_a.public_id, software_id="restore-tool", enabled=True, all_plans_allowed=True)
        url = reverse("catalog:api_catalog_software_status", kwargs={"software_id": "restore-tool"})
        def status(value, key):
            return self.post_json(url, {"status": value, "reason": "audit status change"}, headers={"HTTP_IDEMPOTENCY_KEY": key})
        self.assertEqual(status("archived", "archive-first").status_code, 200)
        restored = status("active", "restore-first")
        self.assertEqual(restored.status_code, 200, restored.content)
        cache.clear()
        self.assertEqual(status("active", "restore-first").json(), restored.json())
        self.assertEqual(status("archived", "restore-first").status_code, 409)
        self.assertEqual(DownstreamSoftware.objects.get(software_id="restore-tool", downstream=self.downstream_a).status, DownstreamSoftwareStatus.CLOSED)
        self.assertEqual(status("draft", "invalid-draft").status_code, 400)


class LocalAtomicBudgetTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def test_parallel_requests_cannot_spend_same_slot(self):
        self.assertTrue(allow("atomic-local", "same", limit=2))
        start = Barrier(8)
        def attempt(_):
            start.wait(timeout=5)
            return allow("atomic-local", "same", limit=2)
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(outcomes), 1)
        self.assertTrue(blocked("atomic-local", "same", limit=2))
        reset("atomic-local", "same")
        self.assertTrue(allow("atomic-local", "same", limit=2))

    def test_backend_failure_is_denied(self):
        with patch("django.core.cache.backends.locmem.LocMemCache.add", side_effect=RuntimeError("unavailable")):
            self.assertFalse(allow("atomic-local", "failure", limit=2))


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.db.DatabaseCache", "LOCATION": "optimization_atomic_cache", "TIMEOUT": 300}})
class DatabaseAtomicBudgetTests(TransactionTestCase):
    def setUp(self):
        call_command("createcachetable", verbosity=0)
        cache.clear()

    def tearDown(self):
        cache.clear()

    def race(self, scope, *, seed=False, expired=False):
        import time
        if seed:
            self.assertTrue(allow(scope, "same", limit=2, timeout=30))
        if expired:
            cache.set(_cache_key(scope, "same"), {"count": 200, "expires_at": time.time() - 1}, timeout=30)
        start = Barrier(2)
        def attempt(_):
            connection = connections["default"]
            first = True
            def simultaneous_read(execute, sql, params, many, context):
                nonlocal first
                result = execute(sql, params, many, context)
                # Force two actual readers to observe the same old row or lack
                # of row. Later CAS retries must not wait for the other reader.
                if first and "SELECT" in sql and "optimization_atomic_cache" in sql and "WHERE" in sql and "cache_key" in sql and "value" in sql:
                    first = False
                    start.wait(timeout=5)
                return result
            try:
                with connection.execute_wrapper(simultaneous_read):
                    return allow(scope, "same", limit=2, timeout=30)
            finally:
                connection.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, range(2)))
        self.assertLessEqual(int(seed) + sum(outcomes), 2)
        self.assertGreaterEqual(sum(outcomes), 1)
        return outcomes

    def test_two_readers_do_not_lose_increment(self):
        self.assertEqual(sum(self.race("atomic-db-live", seed=True)), 1)
        self.assertTrue(blocked("atomic-db-live", "same", limit=2))

    def test_first_creation_competition(self):
        self.race("atomic-db-first")
        self.assertFalse(allow("atomic-db-first", "same", limit=1))

    def test_expired_window_reset_competition(self):
        self.race("atomic-db-expired", expired=True)
        self.assertFalse(allow("atomic-db-expired", "same", limit=1))

    def test_rejected_cas_is_never_counted_as_allow(self):
        self.assertTrue(allow("atomic-db-cas", "same", limit=1))
        self.assertFalse(allow("atomic-db-cas", "same", limit=1))
        reset("atomic-db-cas", "same")
        self.assertTrue(allow("atomic-db-cas", "same", limit=1))


class PolicyUiBehaviorTests(SimpleTestCase):
    def test_committed_save_and_unknown_retry(self):
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("Node is required for actual policy handler behavior")
        result = subprocess.run([node, "scripts/test_security_optimizations_ui.cjs"], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
