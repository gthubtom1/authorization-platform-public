"""Final reviewed authorization defects; concurrent row locking requires PostgreSQL."""
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection, connections
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

import tests.test_authorization as auth_fixture
import tests.test_launch_ticket as ticket_fixture
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.core.time import FixedClock
from authorization_platform.licensing import api_views, authorization as services
from authorization_platform.licensing.admin import block_physical_device, unblock_device
from authorization_platform.licensing.models import (
    AuthorizationAdminOperation, AuthorizationNonce, AuthorizationRequestRecord,
    AuthorizationState, DeviceBinding, DeviceBindingState, DeviceRiskState,
    LaunchTicket, LicenseCard, LicenseInstance,
)
from authorization_platform.licensing.services import decrypt_license_card, generate_license_batch


class FinalFixture:
    _request = ticket_fixture.LaunchTicketTests._request
    _activate = ticket_fixture.LaunchTicketTests._activate
    _issue = ticket_fixture.LaunchTicketTests._issue
    _revise_daily_switch = auth_fixture.AuthorizationServiceTests._revise_daily_switch

    def setUp(self):
        ticket_fixture.LaunchTicketTests.setUp(self)
        self.now = timezone.now().replace(microsecond=0)
        self.client = Client()
        self.client.force_login(self.admin)

    def post(self, action, payload, key="final-batch"):
        return self.client.post(
            reverse(f"licensing:api_manage_authorization_{action}"),
            data=json.dumps(payload), content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def public(self, action, payload):
        return Client().post(
            reverse(f"licensing:public_license_{action}"),
            data=json.dumps(payload), content_type="application/json",
        )


class FinalAuthorizationTests(FinalFixture, TestCase):
    def test_a1_clock_recovery_never_restores_kicked_seat(self):
        self._revise_daily_switch(allow=True)
        instance, key_a = self._activate()
        incoming, _ = self._request(action="activate", request_id="incoming", installation_id="install-b")
        services.activate_license(request=incoming, clock=FixedClock(self.now + timedelta(seconds=2)))
        historical = DeviceBinding.objects.get(authorization=instance, state=DeviceBindingState.UNBOUND)
        verify, _ = self._request(action="verify", request_id="old-clock", private_key=key_a,
                                  authorization_id=str(instance.pk))
        services.verify_license(request=verify, clock=FixedClock(self.now - timedelta(seconds=30)))
        unblock_device(actor=self.admin, authorization_id=instance.pk, reason="时钟恢复",
                       now=self.now + timedelta(seconds=3))
        historical.refresh_from_db()
        self.assertEqual(historical.state, DeviceBindingState.UNBOUND)
        self.assertEqual(DeviceBinding.objects.filter(authorization=instance, state="active").count(), 1)

    def test_a1_recovery_respects_snapshot_seat_limit(self):
        self._revise_daily_switch(allow=True)
        instance, _ = self._activate()
        incoming, key_b = self._request(action="activate", request_id="seat-b", installation_id="install-b")
        services.activate_license(request=incoming, clock=FixedClock(self.now + timedelta(seconds=2)))
        verify, _ = self._request(action="verify", request_id="clock-b", private_key=key_b,
                                  installation_id="install-b", authorization_id=str(instance.pk))
        services.verify_license(request=verify, clock=FixedClock(self.now - timedelta(seconds=30)))
        # Legacy rows previously mislabeled by the faulty rollback path.
        old = DeviceBinding.objects.get(authorization=instance, state="unbound")
        old.state, old.reason = DeviceBindingState.BLOCKED, services.TIME_ROLLBACK_BINDING_REASON
        old.save(update_fields=("state", "reason"), _allow_mutation=True)
        unblock_device(actor=self.admin, authorization_id=instance.pk, reason="恢复旧数据时钟")
        self.assertLessEqual(DeviceBinding.objects.filter(authorization=instance, state="active").count(), 1)

    def test_a3_ticket_advances_both_watermarks_and_rejects_large_rollback(self):
        instance, private_key = self._activate()
        self._issue(instance=instance, private_key=private_key, request_id="future",
                    clock=FixedClock(self.now + timedelta(seconds=100)))
        instance.refresh_from_db()
        binding = DeviceBinding.objects.get(authorization=instance, state="active")
        expected = self.now + timedelta(seconds=100)
        self.assertEqual((instance.last_server_time, binding.last_server_time), (expected, expected))
        with self.assertRaises(services.AuthorizationOperationError) as caught:
            self._issue(instance=instance, private_key=private_key, request_id="back30",
                        clock=FixedClock(self.now + timedelta(seconds=70)))
        self.assertEqual(caught.exception.code, "TIME_ROLLBACK_DETECTED")
        instance.refresh_from_db()
        binding.refresh_from_db()
        self.assertEqual((instance.state, binding.state), ("active", "active"))

    def test_a3_tolerance_uses_high_water_for_issue_and_consume(self):
        instance, private_key = self._activate()
        result, request = self._issue(instance=instance, private_key=private_key, request_id="t100",
                                      clock=FixedClock(self.now + timedelta(seconds=100)))
        second, _ = self._issue(instance=instance, private_key=private_key, request_id="t85",
                                clock=FixedClock(self.now + timedelta(seconds=85)))
        self.assertEqual(second.payload["ticket"]["issued_at"], result.payload["ticket"]["issued_at"])
        self.ticket_id = result.payload["ticket"]["ticket_id"]
        consume, _ = self._request(action="ticket-consume", request_id="consume85", private_key=private_key,
                                   authorization_id=str(instance.pk))
        consumed = services.consume_launch_ticket(request=consume, clock=FixedClock(self.now + timedelta(seconds=85)))
        self.assertGreaterEqual(consumed.payload["server_time"], result.payload["ticket"]["not_before"])
        ticket = LaunchTicket.objects.get(pk=self.ticket_id)
        self.assertEqual(ticket.consumed_at, self.now + timedelta(seconds=100))
        binding = DeviceBinding.objects.get(authorization=instance, state="active")
        self.assertEqual(binding.last_server_time, ticket.consumed_at)

    def test_a3_replay_ttl_and_expiry_are_exclusive(self):
        instance, private_key = self._activate()
        result, request = self._issue(instance=instance, private_key=private_key, request_id="ttl",
                                      clock=FixedClock(self.now))
        replay = services.issue_launch_ticket(request=request, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertEqual(replay.payload, result.payload)
        self.ticket_id = result.payload["ticket"]["ticket_id"]
        consume, _ = self._request(action="ticket-consume", request_id="expiry", private_key=private_key,
                                   authorization_id=str(instance.pk))
        with self.assertRaises(services.AuthorizationOperationError) as caught:
            services.consume_launch_ticket(request=consume, clock=FixedClock(self.now + timedelta(seconds=180)))
        self.assertEqual(caught.exception.code, "TICKET_EXPIRED")

    def test_a3_consume_does_not_accept_future_not_before(self):
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="not-before")
        self.ticket_id = result.payload["ticket"]["ticket_id"]
        ticket = LaunchTicket.objects.get(pk=self.ticket_id)
        # A pre-existing future ticket must not silently pass a raw-clock check.
        ticket.issued_at = self.now + timedelta(seconds=1)
        ticket.save(update_fields=("issued_at",))
        request, _ = self._request(action="ticket-consume", request_id="too-early", private_key=private_key,
                                   authorization_id=str(instance.pk))
        with self.assertRaises(services.AuthorizationOperationError) as caught:
            services.consume_launch_ticket(request=request, clock=FixedClock(self.now))
        self.assertEqual(caught.exception.code, "TICKET_NOT_YET_VALID")
        ticket.refresh_from_db()
        self.assertIsNone(ticket.consumed_at)

    def test_a4_unbind_reinstall_cannot_bypass_key_rotation_quota(self):
        self._revise_daily_switch(allow=True, limit=1)
        instance, _ = self._activate()
        rotate, new_key = self._request(action="activate", request_id="rotate")
        services.activate_license(request=rotate, clock=FixedClock(self.now))
        deactivate, _ = self._request(action="deactivate", request_id="unbind", private_key=new_key,
                                      authorization_id=str(instance.pk))
        services.deactivate_license(request=deactivate, clock=FixedClock(self.now))
        reinstall, _ = self._request(action="activate", request_id="reinstall")
        with self.assertRaises(services.AuthorizationOperationError) as caught:
            services.activate_license(request=reinstall, clock=FixedClock(self.now))
        self.assertEqual(caught.exception.code, "DEVICE_SWITCH_LIMIT_REACHED")
        same, _ = self._request(action="activate", request_id="same-key", private_key=new_key)
        self.assertEqual(services.activate_license(request=same, clock=FixedClock(self.now)).status_code, 200)
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 1)

    def test_a4_unbound_new_key_consumes_one_rotation(self):
        self._revise_daily_switch(allow=True, limit=5)
        instance, key = self._activate()
        deactivate, _ = self._request(action="deactivate", request_id="exit", private_key=key,
                                      authorization_id=str(instance.pk))
        services.deactivate_license(request=deactivate, clock=FixedClock(self.now))
        reinstall, _ = self._request(action="activate", request_id="new-key")
        services.activate_license(request=reinstall, clock=FixedClock(self.now))
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 1)

    def test_a6_malformed_uuid_is_400_for_all_public_instance_actions(self):
        for action in ("verify", "deactivate", "launch-ticket", "ticket-consume"):
            with self.subTest(action=action):
                self.ticket_id = str(uuid.uuid4())
                request, _ = self._request(action=action, request_id="uuid-" + action, authorization_id="bad-uuid")
                route = {"launch-ticket": "launch_ticket", "ticket-consume": "launch_ticket_consume"}.get(action, action)
                response = self.public(route, request)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
        request, _ = self._request(action="verify", request_id="missing-id", authorization_id=str(uuid.uuid4()))
        response = self.public("verify", request)
        self.assertEqual((response.status_code, response.json()["error"]["code"]), (403, "AUTHORIZATION_NOT_FOUND"))

    def assert_preview_matches_list(self, filters, expected):
        listed = self.client.get(reverse("licensing:api_manage_authorizations"), {**filters, "page_size": 1})
        preview = self.client.get(reverse("licensing:api_manage_authorization_renew_preview"),
                                  {**filters, "unit": "hour", "amount": 1})
        self.assertEqual(preview.status_code, 200, preview.content)
        self.assertEqual(listed.status_code, 200, listed.content)
        self.assertEqual(preview.json()["renewable_count"], expected)
        self.assertEqual(listed.json()["pagination"]["total"], expected)

    def test_a7_preview_search_supports_name_uuid_and_multiple_tokens(self):
        instance, _ = self._activate()
        for query in ("Ticket", str(instance.pk), "Ticket install-ticket", self.software.software_id):
            with self.subTest(query=query):
                self.assert_preview_matches_list({"q": query}, 1)

    def test_a8_preview_uses_latest_binding_per_device(self):
        instance, key = self._activate()
        deactivate, _ = self._request(action="deactivate", request_id="exit-latest", private_key=key,
                                      authorization_id=str(instance.pk))
        services.deactivate_license(request=deactivate, clock=FixedClock(self.now))
        again, _ = self._request(action="activate", request_id="again-latest", private_key=key)
        services.activate_license(request=again, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assert_preview_matches_list({"device_state": "unbound"}, 0)
        self.assert_preview_matches_list({"device_state": "bound"}, 1)

    def test_a8_filter_and_search_must_match_the_same_device_row(self):
        self._revise_daily_switch(allow=True)
        self._activate()
        incoming, _ = self._request(action="activate", request_id="switch-search", installation_id="second-device")
        services.activate_license(request=incoming, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assert_preview_matches_list({"device_state": "bound", "q": "install-ticket"}, 0)
        self.assert_preview_matches_list({"device_state": "bound", "q": "second-device"}, 1)
        old_device = DeviceBinding.objects.get(state="unbound").device
        old_device.risk_state = DeviceRiskState.BLOCKED
        old_device.save(update_fields=("risk_state",), _allow_mutation=True)
        self.assert_preview_matches_list({"device_state": "bound", "risk_state": "blocked"}, 0)
        self.assert_preview_matches_list({"device_state": "bound", "risk_state": "normal", "q": "second-device"}, 1)

    def test_a8_preview_projects_all_pages_and_deduplicates_authorizations(self):
        self._activate()
        issued = generate_license_batch(actor=self.downstream.user, software_id=self.software.pk,
                                       plan_snapshot_id=self.snapshot.pk, quantity=1, idempotency_key="page2")
        self.card = LicenseCard.objects.get(pk=issued.cards[0].public_id)
        self.license_key = decrypt_license_card(self.card.card_ciphertext)
        self._activate(installation_id="page2", request_id="activate-page2")
        self.assert_preview_matches_list({}, 2)

    def test_a9_api_failure_audit_survives_outer_rollback_once(self):
        instance, private_key = self._activate()
        binding = DeviceBinding.objects.get(authorization=instance)
        binding.state = DeviceBindingState.UNBOUND
        binding.save(update_fields=("state",), _allow_mutation=True)
        request, _ = self._request(action="launch-ticket", request_id="failed-api-ticket", private_key=private_key,
                                   authorization_id=str(instance.pk))
        response = self.public("launch_ticket", request)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuditEvent.objects.filter(action="authorization.launch-ticket", outcome=AuditOutcome.FAILURE).count(), 1)
        self.assertEqual(LaunchTicket.objects.count(), 0)

    def test_a9_429_rolls_back_all_ticket_success_effects(self):
        instance, key = self._activate()
        request, _ = self._request(action="launch-ticket", request_id="limited", private_key=key,
                                   authorization_id=str(instance.pk))
        before = (AuthorizationNonce.objects.count(), AuthorizationRequestRecord.objects.count(), AuditEvent.objects.count())
        with patch("authorization_platform.licensing.api._consume_public_license_rate", return_value=False), \
             patch.object(services, "_server_now", return_value=self.now + timedelta(seconds=10)):
            response = self.public("launch_ticket", request)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(LaunchTicket.objects.count(), 0)
        self.assertEqual(before, (AuthorizationNonce.objects.count(), AuthorizationRequestRecord.objects.count(), AuditEvent.objects.count()))
        instance.refresh_from_db()
        self.assertEqual(instance.last_server_time, self.now)

    def test_a9_consume_failure_audit_once_and_429_keeps_ticket_unused(self):
        instance, key = self._activate()
        result, _ = self._issue(instance=instance, private_key=key, request_id="consume-audit")
        self.ticket_id = result.payload["ticket"]["ticket_id"]
        request, _ = self._request(action="ticket-consume", request_id="limited-consume", private_key=key,
                                   authorization_id=str(instance.pk))
        before = (AuthorizationNonce.objects.count(), AuthorizationRequestRecord.objects.count(), AuditEvent.objects.count())
        with patch("authorization_platform.licensing.api._consume_public_license_rate", return_value=False):
            response = self.public("launch_ticket_consume", request)
        self.assertEqual(response.status_code, 429)
        self.assertIsNone(LaunchTicket.objects.get(pk=self.ticket_id).consumed_at)
        self.assertEqual(before, (AuthorizationNonce.objects.count(), AuthorizationRequestRecord.objects.count(), AuditEvent.objects.count()))
        self.ticket_id = str(uuid.uuid4())
        missing, _ = self._request(action="ticket-consume", request_id="missing-consume", private_key=key,
                                   authorization_id=str(instance.pk))
        self.assertEqual(self.public("launch_ticket_consume", missing).status_code, 404)
        self.assertEqual(AuditEvent.objects.filter(action="authorization.ticket-consume", outcome=AuditOutcome.FAILURE).count(), 1)
        direct, _ = self._request(action="ticket-consume", request_id="direct-missing", private_key=key,
                                  authorization_id=str(instance.pk))
        with self.assertRaises(services.AuthorizationOperationError):
            services.consume_launch_ticket(request=direct, clock=FixedClock(self.now))
        self.assertEqual(AuditEvent.objects.filter(action="authorization.ticket-consume", outcome=AuditOutcome.FAILURE).count(), 2)


class FinalBatchRecoveryTests(FinalFixture, TransactionTestCase):
    def prepare_batch(self, action):
        issued = generate_license_batch(actor=self.downstream.user, software_id=self.software.pk,
                                       plan_snapshot_id=self.snapshot.pk, quantity=2, idempotency_key="two-cards")
        instances = []
        for index, issued_card in enumerate(issued.cards):
            card = LicenseCard.objects.get(pk=issued_card.public_id)
            self.card = card
            self.license_key = decrypt_license_card(card.card_ciphertext)
            instance, _ = self._activate(installation_id=f"batch-{index}", request_id=f"batch-{index}")
            instances.append(instance)
            if action == "bulk_unblock":
                binding = DeviceBinding.objects.get(authorization=instance)
                block_physical_device(actor=self.admin, device_id=binding.device_id, reason="准备解封")
        body = {"authorization_ids": [str(instance.pk) for instance in instances], "reason": "最终回归测试"}
        if action == "renew":
            body.update(unit="hour", amount=1)
        return instances, body

    def assert_resume(self, action, service_name):
        instances, body = self.prepare_batch(action)
        original = getattr(api_views, service_name)
        calls = []

        def interrupt(**kwargs):
            calls.append(kwargs)
            if len(calls) == 2:
                raise RuntimeError("simulated process interruption")
            return original(**kwargs)

        with patch.object(api_views, service_name, side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "process interruption"):
                self.post(action, body)
        first_expiry = LicenseInstance.objects.get(pk=instances[0].pk).expires_at
        first_revision = LicenseInstance.objects.get(pk=instances[0].pk).authorization_revision
        with patch.object(api_views, service_name, wraps=original) as resumed:
            response = self.post(action, body)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(resumed.call_count, 1, "completed item must not execute again")
        first = LicenseInstance.objects.get(pk=instances[0].pk)
        self.assertEqual((first.expires_at, first.authorization_revision), (first_expiry, first_revision))
        replay = self.post(action, body)
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        conflict = self.post(action, {**body, "reason": "不同的原因"})
        self.assertEqual(conflict.status_code, 409)

    def test_a2_renew_resumes_only_unfinished(self):
        self.assert_resume("renew", "extend_authorization")

    def test_a2_revoke_resumes_only_unfinished(self):
        self.assert_resume("bulk_revoke", "revoke_authorization")

    def test_a2_block_resumes_only_unfinished(self):
        self.assert_resume("bulk_block", "block_physical_device")

    def test_a2_unblock_resumes_only_unfinished(self):
        self.assert_resume("bulk_unblock", "unblock_physical_device")

    def test_a2_business_commit_rolls_back_when_result_persistence_fails(self):
        instances, body = self.prepare_batch("renew")
        expiry = instances[0].expires_at
        original = AuthorizationAdminOperation.save

        def fail_result(operation, *args, **kwargs):
            if operation.response_payload.get("_batch", {}).get("results"):
                raise RuntimeError("result write failed")
            return original(operation, *args, **kwargs)

        with patch.object(AuthorizationAdminOperation, "save", fail_result):
            with self.assertRaisesRegex(RuntimeError, "result write failed"):
                self.post("renew", body)
        instances[0].refresh_from_db()
        self.assertEqual(instances[0].expires_at, expiry)
        self.assertFalse(AuditEvent.objects.filter(action="authorization.extend", outcome=AuditOutcome.SUCCESS).exists())
        response = self.post("renew", body)
        self.assertEqual(response.status_code, 200)
        instances[0].refresh_from_db()
        self.assertEqual(instances[0].expires_at, expiry + timedelta(hours=1))

    def test_a2_persisted_failure_is_not_retried_after_interruption(self):
        instances, body = self.prepare_batch("renew")
        with patch.object(api_views, "extend_authorization", side_effect=[
            services.AuthorizationOperationError("AUTHORIZATION_BLOCKED", "业务拒绝", http_status=409),
            RuntimeError("pause after refusal"),
        ]):
            with self.assertRaisesRegex(RuntimeError, "pause after refusal"):
                self.post("renew", body)
        original = api_views.extend_authorization
        with patch.object(api_views, "extend_authorization", wraps=original) as called:
            response = self.post("renew", body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(called.call_count, 1)
        self.assertEqual(called.call_args.kwargs["authorization_id"], str(instances[1].pk))
        self.assertEqual(response.json()["failed_count"], 1)
        self.assertEqual(response.json()["renewed_count"], 1)
        self.assertEqual(AuditEvent.objects.filter(action="authorization.extend", outcome=AuditOutcome.FAILURE).count(), 1)

    def test_a2_block_resume_uses_original_physical_mapping(self):
        instances, body = self.prepare_batch("bulk_block")
        original = api_views.block_physical_device
        devices = [DeviceBinding.objects.get(authorization=value).device for value in instances]
        calls = []

        def interrupt(**kwargs):
            calls.append(kwargs)
            if len(calls) == 2:
                raise RuntimeError("pause")
            return original(**kwargs)

        with patch.object(api_views, "block_physical_device", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "pause"):
                self.post("bulk_block", body)
        self._revise_daily_switch(allow=True)
        self.card = LicenseCard.objects.get(pk=instances[1].license_card_id)
        self.license_key = decrypt_license_card(self.card.card_ciphertext)
        self._activate(installation_id="replacement", request_id="replacement")
        replacement = DeviceBinding.objects.get(authorization=instances[1], state="active").device
        response = self.post("bulk_block", body)
        self.assertEqual(response.status_code, 200)
        devices[1].refresh_from_db()
        replacement.refresh_from_db()
        self.assertEqual(devices[1].risk_state, DeviceRiskState.BLOCKED)
        self.assertEqual(replacement.risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(response.json()["items"][1]["device_id"], str(devices[1].pk))

    def test_a2_overlapping_authorizations_share_one_physical_action(self):
        instances, body = self.prepare_batch("bulk_block")
        shared = DeviceBinding.objects.get(authorization=instances[0])
        other = DeviceBinding.objects.get(authorization=instances[1])
        other.device, other.device_key = shared.device, shared.device_key
        other.save(update_fields=("device", "device_key"), _allow_mutation=True)
        original = api_views.block_physical_device
        with patch.object(api_views, "block_physical_device", wraps=original) as called:
            response = self.post("bulk_block", body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(called.call_count, 1)
        self.assertEqual(response.json()["blocked_count"], 2)
        self.assertEqual(response.json()["failed_count"], 0)

    @skipUnless(connection.vendor == "postgresql", "Concurrent row-lock test requires PostgreSQL")
    def test_a2_two_workers_same_key_extend_each_item_once(self):
        instances, body = self.prepare_batch("renew")
        expiry = instances[0].expires_at
        barrier = Barrier(2)

        def submit():
            close_old_connections()
            try:
                client = Client()
                client.force_login(self.admin)
                barrier.wait(timeout=10)
                response = client.post(reverse("licensing:api_manage_authorization_renew"),
                                       data=json.dumps(body), content_type="application/json",
                                       HTTP_IDEMPOTENCY_KEY="concurrent-batch")
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(submit) for _ in range(2)]
            responses = [future.result(timeout=25) for future in futures]
        self.assertEqual([status for status, _ in responses], [200, 200])
        for instance in instances:
            instance.refresh_from_db()
            self.assertEqual(instance.expires_at, expiry + timedelta(hours=1))
        self.assertEqual(AuditEvent.objects.filter(action="authorization.extend", outcome=AuditOutcome.SUCCESS).count(), 2)
