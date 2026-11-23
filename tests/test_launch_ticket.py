from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from django.conf import settings
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import (
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    set_downstream_software_access,
)
from authorization_platform.core.time import FixedClock
from authorization_platform.licensing import authorization as authorization_service
from authorization_platform.licensing.admin import revoke_authorization
from authorization_platform.licensing.authorization import (
    AuthorizationOperationError,
    activate_license,
    authorization_signing_public_key,
    canonicalize_jcs,
    consume_launch_ticket,
    device_proof_message,
    issue_launch_ticket,
)
from authorization_platform.licensing.models import (
    AuthorizationState,
    Device,
    DeviceBinding,
    DeviceBindingState,
    DeviceKey,
    LaunchTicket,
    LicenseCard,
    LicenseCardStatus,
    LicenseInstance,
)
from authorization_platform.licensing.services import decrypt_license_card, generate_license_batch


UTC = timezone.utc


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _platform_public_key() -> Ed25519PublicKey:
    raw = base64.urlsafe_b64decode(authorization_signing_public_key() + "==")
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_ticket_signature(payload: dict) -> None:
    """客户端视角验签：只去掉 integrity.signature，其余全部参与。"""

    integrity = payload["integrity"]
    signable = dict(payload)
    signable_integrity = dict(integrity)
    signable_integrity.pop("signature")
    signable["integrity"] = signable_integrity
    signature = base64.urlsafe_b64decode(integrity["signature"] + "==")
    _platform_public_key().verify(signature, canonicalize_jcs(signable))


class LaunchTicketTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model

        self.admin = get_user_model().objects.create_superuser(
            username="ticket-admin", password="Admin-password-123"
        )
        self.downstream = create_downstream_direct(
            actor=self.admin, username="ticket-downstream", password="Downstream-password-123"
        )
        self.software = create_software(
            actor=self.admin, software_id="ticket-tool", name="Ticket Tool",
            status=SoftwareStatus.ACTIVE,
        )
        self.profile = create_profile(
            actor=self.admin, software_id=self.software.software_id, profile_id="stable",
            client_id="ticket-tool-windows", target="windows", arch="x64",
            channel="stable", status=ProfileStatus.ACTIVE,
        )
        self.policy = create_policy_version(
            actor=self.admin, software_id=self.software.software_id,
            profile_id=self.profile.profile_id, version="policy-1",
            max_devices=1, allow_device_switch=False, device_proof_required=True,
            verify_interval_seconds=60, offline_grace_seconds=0,
            status=PolicyStatus.ACTIVE,
        )
        self.plan, self.snapshot = create_plan(
            actor=self.admin, software_id=self.software.software_id,
            profile_id=self.profile.profile_id, policy_version=self.policy.version,
            name="测试票据卡", duration_seconds=366 * 86400, quota_cost=0,
            test_only=True, status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin, downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id, enabled=True, all_plans_allowed=True,
        )
        issued = generate_license_batch(
            actor=self.downstream.user, software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id, quantity=1,
            idempotency_key="ticket-test-issue",
        )
        self.card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        self.license_key = decrypt_license_card(self.card.card_ciphertext)
        self.now = datetime(2026, 8, 19, 8, 0, tzinfo=UTC)

    def _request(self, *, action, request_id, installation_id="install-ticket",
                 private_key=None, nonce=None, authorization_id=None):
        private_key = private_key or Ed25519PrivateKey.generate()
        nonce = nonce or f"nonce-{request_id}-random"
        payload = {
            "request_id": request_id,
            "idempotency_key": request_id,
            "software_id": self.software.software_id,
            "profile_id": self.profile.profile_id,
            "client_id": self.profile.client_id,
            "contract_version": "authorization.v1",
            "target": self.profile.target,
            "arch": self.profile.arch,
            "channel": self.profile.channel,
            "installation_id": installation_id,
            "device_public_key": _public_key(private_key),
            "client_version": "1.0.0",
            "nonce": nonce,
        }
        if action == "activate":
            payload["license_key"] = self.license_key
        else:
            payload["authorization_id"] = authorization_id
        if action == "ticket-consume":
            payload["ticket_id"] = self.ticket_id
        signed = dict(payload)
        signed["action"] = action
        proof = private_key.sign(device_proof_message(signed))
        payload["device_proof"] = base64.urlsafe_b64encode(proof).decode("ascii").rstrip("=")
        return payload, private_key

    def _activate(self, *, installation_id="install-ticket", request_id="ticket-activate"):
        request, private_key = self._request(
            action="activate", request_id=request_id, installation_id=installation_id)
        result = activate_license(request=request, clock=FixedClock(self.now))
        self.assertEqual(result.status_code, 200)
        instance = LicenseInstance.objects.get(license_card=self.card)
        return instance, private_key

    def _issue(self, *, instance, private_key, request_id, clock=None):
        request, _ = self._request(
            action="launch-ticket", request_id=request_id,
            installation_id="install-ticket", private_key=private_key,
            authorization_id=str(instance.authorization_id))
        return issue_launch_ticket(
            request=request, clock=clock or FixedClock(self.now)), request

    def test_issue_happy_path_and_signature_verifies_with_platform_pubkey(self):
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="ticket-1")
        self.assertEqual(result.status_code, 200)
        payload = result.payload
        self.assertEqual(payload["decision"], "issued")
        ticket = payload["ticket"]
        self.assertEqual(ticket["software_id"], "ticket-tool")
        self.assertEqual(ticket["audience"], "ticket-tool-core")
        self.assertEqual(ticket["expires_at"] - ticket["issued_at"], 180)
        self.assertEqual(ticket["not_before"], ticket["issued_at"])
        self.assertEqual(payload["integrity"]["key_id"],
                         settings.AUTHORIZATION_SIGNING_KEY_ID)
        uuid.UUID(ticket["ticket_id"])
        _verify_ticket_signature(payload)
        self.assertEqual(LaunchTicket.objects.count(), 1)

    def test_wrong_scope_delete_integrity_fails_and_correct_scope_passes(self):
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="ticket-scope")
        _verify_ticket_signature(result.payload)
        broken = dict(result.payload)
        del broken["integrity"]
        with self.assertRaises(Exception):
            _verify_ticket_signature(broken)

    def test_tampered_expires_at_fails_verification(self):
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="ticket-tamper")
        tampered = dict(result.payload)
        tampered["ticket"] = dict(tampered["ticket"])
        tampered["ticket"]["expires_at"] = tampered["ticket"]["expires_at"] + 10_000_000
        with self.assertRaises(Exception):
            _verify_ticket_signature(tampered)

    def test_expired_revoked_kicked_cards_are_refused(self):
        from datetime import timezone as _tz

        instance, private_key = self._activate()
        # 已撤销（用真实时钟，避免撤销写入的服务端时间被判回退）
        revoke_authorization(actor=self.admin, authorization_id=instance.authorization_id,
                             reason="测试撤销票据", request_id="ticket-revoke")
        request, _ = self._request(action="launch-ticket", request_id="ticket-revoked",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        with self.assertRaises(AuthorizationOperationError) as ctx:
            issue_launch_ticket(request=request, clock=FixedClock(datetime.now(_tz.utc)))
        self.assertEqual(ctx.exception.code, "LICENSE_REVOKED")

    def test_expired_card_is_refused(self):
        instance, private_key = self._activate()
        request, _ = self._request(action="launch-ticket", request_id="ticket-expired",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        with self.assertRaises(AuthorizationOperationError) as ctx:
            issue_launch_ticket(request=request, clock=FixedClock(self.now + timedelta(days=400)))
        self.assertEqual(ctx.exception.code, "LICENSE_EXPIRED")

    def test_kicked_device_is_refused(self):
        from authorization_platform.catalog.services import revise_policy_version

        revise_policy_version(
            actor=self.admin, software_id=self.software.software_id,
            profile_id=self.profile.profile_id, max_devices=1,
            allow_device_switch=True, device_switch_limit=5,
            device_proof_required=True, verify_interval_seconds=60,
            offline_grace_seconds=0, request_id="ticket-allow-switch",
        )
        instance, private_key = self._activate()
        other_key = Ed25519PrivateKey.generate()
        other_request, _ = self._request(action="activate", request_id="ticket-activate-b",
                                         installation_id="install-b", private_key=other_key)
        activate_license(request=other_request, clock=FixedClock(self.now))
        request, _ = self._request(action="launch-ticket", request_id="ticket-kicked",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        with self.assertRaises(AuthorizationOperationError) as ctx:
            issue_launch_ticket(request=request, clock=FixedClock(self.now))
        self.assertEqual(ctx.exception.code, "DEVICE_NOT_BOUND")

    def test_consume_single_use(self):
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="ticket-c1")
        self.ticket_id = result.payload["ticket"]["ticket_id"]
        request, _ = self._request(action="ticket-consume", request_id="ticket-consume-1",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        consumed = consume_launch_ticket(request=request, clock=FixedClock(self.now))
        self.assertEqual(consumed.status_code, 200)
        self.assertEqual(consumed.payload["decision"], "consumed")
        request2, _ = self._request(action="ticket-consume", request_id="ticket-consume-2",
                                    private_key=private_key,
                                    authorization_id=str(instance.authorization_id))
        with self.assertRaises(AuthorizationOperationError) as ctx:
            consume_launch_ticket(request=request2, clock=FixedClock(self.now))
        self.assertEqual(ctx.exception.code, "TICKET_ALREADY_CONSUMED")

    def test_consume_idempotent_replay_returns_consumed(self):
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="ticket-cr")
        self.ticket_id = result.payload["ticket"]["ticket_id"]
        request, _ = self._request(action="ticket-consume", request_id="ticket-consume-r",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        first = consume_launch_ticket(request=request, clock=FixedClock(self.now))
        self.assertEqual(first.payload["decision"], "consumed")
        replay = dict(request)
        second = consume_launch_ticket(request=replay, clock=FixedClock(self.now))
        self.assertEqual(second.payload["decision"], "consumed")
        self.assertEqual(second.payload["ticket_id"], first.payload["ticket_id"])

    def test_disabled_policy_refuses(self):
        from authorization_platform.catalog.services import revise_policy_version

        revise_policy_version(
            actor=self.admin, software_id=self.software.software_id,
            profile_id=self.profile.profile_id, max_devices=1,
            allow_device_switch=False, device_switch_limit=0,
            device_proof_required=True, verify_interval_seconds=60,
            offline_grace_seconds=0, launch_ticket_enabled=False,
            request_id="ticket-disable",
        )
        instance, private_key = self._activate()
        request, _ = self._request(action="launch-ticket", request_id="ticket-disabled",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        with self.assertRaises(AuthorizationOperationError) as ctx:
            issue_launch_ticket(request=request, clock=FixedClock(self.now))
        self.assertEqual(ctx.exception.code, "LAUNCH_TICKET_DISABLED")

    def test_ttl_follows_policy(self):
        from authorization_platform.catalog.services import revise_policy_version

        revise_policy_version(
            actor=self.admin, software_id=self.software.software_id,
            profile_id=self.profile.profile_id, max_devices=1,
            allow_device_switch=False, device_switch_limit=0,
            device_proof_required=True, verify_interval_seconds=60,
            offline_grace_seconds=0, launch_ticket_ttl_seconds=300,
            request_id="ticket-ttl",
        )
        instance, private_key = self._activate()
        result, _ = self._issue(instance=instance, private_key=private_key, request_id="ticket-ttl-1")
        ticket = result.payload["ticket"]
        self.assertEqual(ticket["expires_at"] - ticket["issued_at"], 300)

    def test_idempotent_replay_returns_same_ticket(self):
        instance, private_key = self._activate()
        result1, request = self._issue(instance=instance, private_key=private_key, request_id="ticket-dedupe")
        request2 = dict(request)
        result2 = issue_launch_ticket(request=request2, clock=FixedClock(self.now))
        self.assertEqual(result1.payload["ticket"]["ticket_id"],
                         result2.payload["ticket"]["ticket_id"])
        self.assertEqual(LaunchTicket.objects.count(), 1)

    def test_http_happy_path_and_error_shape(self):
        instance, private_key = self._activate()
        request, _ = self._request(action="launch-ticket", request_id="ticket-http-1",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        response = Client().post(
            reverse("licensing:public_license_launch_ticket"),
            data=json.dumps(request), content_type="application/json",
            HTTP_X_REQUEST_ID=request["request_id"],
            HTTP_IDEMPOTENCY_KEY=request["idempotency_key"],
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body["decision"], "issued")
        _verify_ticket_signature(body)
        bad, _ = self._request(action="launch-ticket", request_id="ticket-http-bad",
                                private_key=private_key,
                                authorization_id=str(uuid.uuid4()))
        denied = Client().post(
            reverse("licensing:public_license_launch_ticket"),
            data=json.dumps(bad), content_type="application/json",
            HTTP_X_REQUEST_ID=bad["request_id"],
            HTTP_IDEMPOTENCY_KEY=bad["idempotency_key"],
        )
        denied_body = json.loads(denied.content)
        self.assertIn("error", denied_body)
        self.assertIn("code", denied_body["error"])
        self.assertIn("retryable", denied_body["error"])

    @override_settings(PUBLIC_LICENSE_RATE_LIMIT=2)
    def test_rate_limit_only_replaces_would_be_success(self):        # 独立出口 IP，避免与其他测试共享限流桶。
        remote = {"REMOTE_ADDR": "10.9.9.9"}
        instance, private_key = self._activate()
        for index in range(2):
            request, _ = self._request(action="launch-ticket", request_id=f"ticket-rate-{index}",
                                       private_key=private_key,
                                       authorization_id=str(instance.authorization_id))
            response = Client().post(
                reverse("licensing:public_license_launch_ticket"),
                data=json.dumps(request), content_type="application/json",
                HTTP_X_REQUEST_ID=request["request_id"],
                HTTP_IDEMPOTENCY_KEY=request["idempotency_key"],
                **remote,
            )
            self.assertEqual(response.status_code, 200)
        request, _ = self._request(action="launch-ticket", request_id="ticket-rate-limited",
                                   private_key=private_key,
                                   authorization_id=str(instance.authorization_id))
        limited = Client().post(
            reverse("licensing:public_license_launch_ticket"),
            data=json.dumps(request), content_type="application/json",
            HTTP_X_REQUEST_ID=request["request_id"],
            HTTP_IDEMPOTENCY_KEY=request["idempotency_key"],
            **remote,
        )
        self.assertEqual(limited.status_code, 429)
        # 被限流挡下的签发不得留下票据行，换新键重试即新票。
        self.assertEqual(LaunchTicket.objects.count(), 2)
        bad, _ = self._request(action="launch-ticket", request_id="ticket-rate-hard",
                                private_key=private_key,
                                authorization_id=str(uuid.uuid4()))
        hard = Client().post(
            reverse("licensing:public_license_launch_ticket"),
            data=json.dumps(bad), content_type="application/json",
            HTTP_X_REQUEST_ID=bad["request_id"],
            HTTP_IDEMPOTENCY_KEY=bad["idempotency_key"],
            **remote,
        )
        self.assertNotEqual(hard.status_code, 429)
        self.assertIn("error", json.loads(hard.content))

    def test_float_in_response_never_gets_signed(self):
        # 契约铁律：响应里不得出现 JSON 浮点数。规范化遇到浮点直接失败，
        # 服务端签不出、客户端验不过，一个浮点字段同时打死两端。
        with self.assertRaises(ValueError):
            authorization_service.canonicalize_jcs({"expires_at": 1790900000.0})
        with self.assertRaises(AuthorizationOperationError) as ctx:
            authorization_service.sign_launch_ticket({
                "ticket": {"expires_at": 1790900000.0},
                "integrity": {
                    "algorithm": "ed25519", "key_id": "k",
                    "canonicalization": "JCS-RFC8785",
                    "origin": "authorization-platform", "audience": "x-core",
                },
            })
        self.assertEqual(ctx.exception.code, "SIGNATURE_UNAVAILABLE")
