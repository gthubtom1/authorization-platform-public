from __future__ import annotations

import base64
import hashlib
import json
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import csv
import io
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.models import DownstreamStatus
from authorization_platform.accounts.rate_limit import reset as reset_rate_limit
from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.audit.queries import present_event
from authorization_platform.catalog.configuration import update_downstream_configuration, update_profile_configuration
from authorization_platform.catalog.models import DownstreamSoftware, PlanStatus, PolicyStatus, PolicyVersion, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import (
    backfill_default_daily_device_switch,
    create_capability_definition,
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    delete_plan,
    revise_plan,
    revise_policy_version,
    set_downstream_software_access,
    set_plan_status,
    update_software_status,
)
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY
from authorization_platform.core.time import FixedClock, to_beijing
from authorization_platform.credits.models import QuotaLedgerEntry, QuotaLedgerOperation
from authorization_platform.credits.services import credit_quota, get_quota_account
from authorization_platform.licensing.admin import (
    MAX_RENEWAL_SECONDS,
    MAX_RENEWAL_TOTAL_SECONDS,
    authorization_card_is_frozen,
    block_device,
    extend_authorization,
    list_risk_signals_for_admin,
    redact_request_id,
    renewal_blocker,
    renewal_seconds,
    reset_device_binding,
    revoke_authorization,
    unblock_device,
)
from authorization_platform.licensing.device_codes import compact_device_code
from authorization_platform.licensing.authorization import (
    AuthorizationOperationError,
    _build_response,
    _request_fingerprint,
    activate_license,
    authorization_signing_public_key,
    canonicalize_jcs,
    deactivate_license,
    device_proof_message,
    verify_authorization_response,
    verify_license,
)
from authorization_platform.licensing import authorization as authorization_service
from authorization_platform.licensing.models import (
    AuthorizationNonce,
    AuthorizationRequestRecord,
    AuthorizationState,
    Device,
    DeviceBinding,
    DeviceBindingState,
    DeviceKey,
    DeviceRiskState,
    AuthorizationAdminOperation,
    LicenseCard,
    LicenseCardStatus,
    LicenseInstance,
)
from authorization_platform.licensing.services import (
    LicenseOperationError,
    decrypt_license_card,
    generate_license_batch,
    reclaim_license_card,
    set_authorization_configuration_override,
)


UTC = timezone.utc


class AuthorizationServiceTests(TestCase):
    def setUp(self):
        self.admin = self._user_admin()
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="authorization-downstream",
            password="Downstream-password-123",
        )
        self.software = create_software(
            actor=self.admin,
            software_id="generic-tool",
            name="Generic Tool",
            status=SoftwareStatus.ACTIVE,
        )
        self.profile = create_profile(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id="stable",
            client_id="generic-tool-windows",
            target="windows",
            arch="x64",
            channel="stable",
            status=ProfileStatus.ACTIVE,
        )
        self.policy = create_policy_version(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            version="policy-1",
            max_devices=1,
            allow_device_switch=False,
            device_proof_required=True,
            verify_interval_seconds=60,
            offline_grace_seconds=0,
            status=PolicyStatus.ACTIVE,
        )
        create_capability_definition(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            capability_key="internal.server.flag",
            value_type="boolean",
            default_value=False,
            is_public=False,
        )
        self.plan, self.snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="一分钟测试卡",
            duration_seconds=60,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="authorization-test-issue",
        )
        self.card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        self.license_key = decrypt_license_card(self.card.card_ciphertext)
        self.now = datetime(2026, 8, 19, 8, 0, tzinfo=UTC)

    @staticmethod
    def _user_admin():
        from django.contrib.auth import get_user_model

        return get_user_model().objects.create_superuser(
            username="authorization-admin",
            password="Admin-password-123",
        )

    @staticmethod
    def _public_key(private_key: Ed25519PrivateKey) -> str:
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def _request(
        self,
        *,
        action: str,
        request_id: str,
        installation_id: str = "install-a",
        private_key: Ed25519PrivateKey | None = None,
        nonce: str | None = None,
        authorization_id: str | None = None,
        client_version: str = "1.0.0",
        proof_override: str | None = None,
        known_authorization_revision: int | None = None,
        known_config_version: str | None = None,
        license_key: str | None = None,
    ) -> tuple[dict, Ed25519PrivateKey]:
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
            "device_public_key": self._public_key(private_key),
            "client_version": client_version,
            "nonce": nonce,
        }
        if action == "activate":
            payload["license_key"] = license_key or self.license_key
        else:
            payload["authorization_id"] = authorization_id
        if known_authorization_revision is not None:
            payload["known_authorization_revision"] = known_authorization_revision
        if known_config_version is not None:
            payload["known_config_version"] = known_config_version
        signed = dict(payload)
        signed["action"] = action
        proof = private_key.sign(device_proof_message(signed))
        payload["device_proof"] = proof_override if proof_override is not None else base64.urlsafe_b64encode(proof).decode("ascii").rstrip("=")
        return payload, private_key

    def _post_public_action(self, action: str, payload: dict, *, remote_addr=None):
        extra = {}
        if remote_addr:
            extra["REMOTE_ADDR"] = remote_addr
        return Client().post(
            reverse(f"licensing:public_license_{action}"),
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_REQUEST_ID=payload["request_id"],
            HTTP_IDEMPOTENCY_KEY=payload["idempotency_key"],
            **extra,
        )

    def _revise_daily_switch(self, *, allow=True, limit=5, request_id="revise-daily-switch"):
        return revise_policy_version(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            max_devices=self.policy.max_devices,
            allow_device_switch=allow,
            device_switch_limit=limit,
            device_proof_required=True,
            verify_interval_seconds=60,
            offline_grace_seconds=0,
            request_id=request_id,
        )

    def test_activate_creates_one_instance_and_real_signed_response(self):
        request, private_key = self._request(action="activate", request_id="activate-1")
        result = activate_license(request=request, clock=FixedClock(self.now))

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.payload["decision"], "active")
        self.assertEqual(result.payload["state_code"], "active")
        self.assertEqual(result.payload["software_id"], "generic-tool")
        self.assertEqual(result.payload["profile_id"], "stable")
        self.assertEqual(result.payload["target"], "windows")
        self.assertNotIn("internal.server.flag", result.payload["capabilities"])
        self.assertEqual(result.payload["expires_at"], int((self.now + timedelta(seconds=60)).timestamp()))
        self.assertEqual(LicenseInstance.objects.count(), 1)
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceKey.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.ACTIVATED)
        activation_audit = AuditEvent.objects.get(action="authorization.activate", outcome=AuditOutcome.SUCCESS)
        self.assertEqual(activation_audit.metadata["installation_id"], request["installation_id"])
        self.assertNotIn(self.license_key, json.dumps(activation_audit.metadata, ensure_ascii=False))

        verify_authorization_response(
            result.payload,
            {settings.AUTHORIZATION_SIGNING_KEY_ID: authorization_signing_public_key()},
        )

    def test_deleting_archived_plan_invalidates_unused_and_activated_cards(self):
        unused_issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="plan-delete-unused",
        )
        unused_card = LicenseCard.objects.get(public_id=unused_issued.cards[0].public_id)
        unused_key = decrypt_license_card(unused_card.card_ciphertext)

        activate_request, private_key = self._request(action="activate", request_id="plan-delete-activate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        self.assertEqual(activated.status_code, 200)
        authorization_id = activated.payload["authorization_id"]

        set_plan_status(actor=self.admin, plan_id=self.plan.pk, status=PlanStatus.ARCHIVED, reason="下线测试套餐")
        deleted = delete_plan(
            actor=self.admin,
            plan_id=self.plan.pk,
            reason="清理测试套餐堆积",
            now=self.now + timedelta(seconds=2),
        )
        self.assertTrue(deleted.changed)
        self.assertEqual(deleted.unused_invalidated, 1)
        self.assertEqual(deleted.activated_revoked, 1)

        self.card.refresh_from_db()
        unused_card.refresh_from_db()
        self.assertEqual(self.card.status, LicenseCardStatus.REVOKED)
        self.assertEqual(unused_card.status, LicenseCardStatus.RECLAIMED)

        verify_request, _ = self._request(
            action="verify",
            request_id="plan-delete-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        verify_result = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(verify_result.status_code, 403)
        self.assertEqual(verify_result.payload["error"]["code"], "LICENSE_REVOKED")

        unused_activate, _ = self._request(
            action="activate",
            request_id="plan-delete-unused-activate",
            license_key=unused_key,
        )
        with self.assertRaises(AuthorizationOperationError) as unused_error:
            activate_license(request=unused_activate, clock=FixedClock(self.now + timedelta(seconds=4)))
        self.assertEqual(unused_error.exception.code, "LICENSE_NOT_ACTIVE")

    def test_plan_revision_keeps_old_card_snapshot_and_uses_new_snapshot_for_new_cards(self):
        old_snapshot_id = self.snapshot.snapshot_id
        old_duration = self.snapshot.duration_seconds
        old_name = self.snapshot.name

        _, new_snapshot = revise_plan(
            actor=self.admin,
            plan_id=self.plan.pk,
            policy_version=self.policy.version,
            name="两分钟测试卡",
            duration_seconds=120,
            quota_cost=0,
            test_only=True,
            capability_values={},
            status=PlanStatus.ACTIVE,
        )
        self.assertNotEqual(new_snapshot.snapshot_id, old_snapshot_id)
        self.assertEqual(new_snapshot.duration_seconds, 120)
        self.assertEqual(new_snapshot.name, "两分钟测试卡")

        with self.assertRaises(LicenseOperationError) as stale_snapshot:
            generate_license_batch(
                actor=self.downstream.user,
                software_id=self.software.software_id,
                plan_snapshot_id=old_snapshot_id,
                quantity=1,
                idempotency_key="authorization-test-stale-snapshot",
            )
        self.assertEqual(stale_snapshot.exception.code, "PLAN_SNAPSHOT_STALE")
        self.assertEqual(LicenseCard.objects.count(), 1)

        new_batch = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=new_snapshot.snapshot_id,
            quantity=2,
            idempotency_key="authorization-test-issue-after-revision",
        )
        new_cards = list(LicenseCard.objects.filter(batch=new_batch.batch).order_by("public_id"))
        self.assertEqual(len(new_cards), 2)
        self.assertTrue(all(card.plan_snapshot_id == new_snapshot.snapshot_id for card in new_cards))
        new_license_key = decrypt_license_card(new_cards[0].card_ciphertext)

        old_request, _ = self._request(
            action="activate",
            request_id="activate-old-snapshot-after-revision",
            installation_id="old-snapshot-install",
        )
        old_result = activate_license(request=old_request, clock=FixedClock(self.now))
        old_instance = LicenseInstance.objects.get(license_card_id=self.card.public_id)
        old_card = LicenseCard.objects.get(pk=self.card.public_id)

        self.assertEqual(old_card.status, LicenseCardStatus.ACTIVATED)
        self.assertEqual(old_card.plan_snapshot_id, old_snapshot_id)
        self.assertEqual(old_instance.plan_snapshot_id, old_snapshot_id)
        self.assertEqual(old_instance.plan_snapshot.name, old_name)
        self.assertEqual(old_instance.plan_snapshot.duration_seconds, old_duration)
        self.assertEqual(old_result.payload["entitlements"]["plan_name"], old_name)
        self.assertEqual(old_result.payload["entitlements"]["duration_seconds"], old_duration)
        self.assertEqual(old_result.payload["expires_at"], int((self.now + timedelta(seconds=old_duration)).timestamp()))

        new_request, _ = self._request(
            action="activate",
            request_id="activate-new-snapshot-after-revision",
            installation_id="new-snapshot-install",
            license_key=new_license_key,
        )
        new_now = self.now + timedelta(seconds=1)
        new_result = activate_license(request=new_request, clock=FixedClock(new_now))
        new_instance = LicenseInstance.objects.get(license_card_id=new_cards[0].public_id)
        new_card = LicenseCard.objects.get(pk=new_cards[0].public_id)

        self.assertEqual(new_card.status, LicenseCardStatus.ACTIVATED)
        self.assertEqual(new_card.plan_snapshot_id, new_snapshot.snapshot_id)
        self.assertEqual(new_instance.plan_snapshot_id, new_snapshot.snapshot_id)
        self.assertEqual(new_instance.plan_snapshot.name, new_snapshot.name)
        self.assertEqual(new_instance.plan_snapshot.duration_seconds, new_snapshot.duration_seconds)
        self.assertEqual(new_result.payload["entitlements"]["plan_name"], new_snapshot.name)
        self.assertEqual(new_result.payload["entitlements"]["duration_seconds"], new_snapshot.duration_seconds)
        self.assertEqual(new_result.payload["expires_at"], int((new_now + timedelta(seconds=120)).timestamp()))

    def test_configuration_resolution_uses_profile_downstream_and_authorization_override(self):
        profile_values = {
            "purchase_url": "https://profile.example.test/buy",
            "qq": "profile-qq",
            "wechat": "profile-wechat",
            "announcement_enabled": True,
            "announcement_title": "Profile公告",
            "announcement_body": "Profile内容",
        }
        downstream_values = {
            "purchase_url": "https://downstream.example.test/buy",
            "qq": "downstream-qq",
            "wechat": "downstream-wechat",
            "announcement_enabled": True,
            "announcement_title": "下游公告",
            "announcement_body": "下游内容",
        }
        override_values = {
            "purchase_url": "https://customer.example.test/buy",
            "qq": "customer-qq",
            "wechat": "customer-wechat",
            "announcement_enabled": True,
            "announcement_title": "客户公告",
            "announcement_body": "客户内容",
        }
        update_profile_configuration(actor=self.admin, profile=self.profile, values=profile_values)
        update_downstream_configuration(
            actor=self.downstream.user,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            values=downstream_values,
        )

        activation_request, private_key = self._request(action="activate", request_id="config-activate")
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get()
        self.assertEqual(activated.payload["support"]["qq"], "downstream-qq")
        self.assertEqual(activated.payload["announcement"]["title"], "下游公告")
        self.assertEqual(activated.payload["modules"]["contact"], activated.payload["support"])
        self.assertEqual(activated.payload["modules"]["notice"], activated.payload["announcement"])

        overridden = set_authorization_configuration_override(
            actor=self.admin,
            authorization_id=instance.authorization_id,
            values=override_values,
        )
        override_version = overridden.config_version
        self.assertNotEqual(override_version, activated.payload["config_version"])
        verify_request, _ = self._request(
            action="verify",
            request_id="config-verify-override",
            authorization_id=str(instance.authorization_id),
            private_key=private_key,
        )
        overridden_result = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertEqual(overridden_result.payload["config_version"], override_version)
        self.assertEqual(overridden_result.payload["support"]["qq"], "customer-qq")
        self.assertEqual(overridden_result.payload["announcement"]["title"], "客户公告")

        update_profile_configuration(
            actor=self.admin,
            profile=self.profile,
            values={**profile_values, "qq": "profile-latest-qq"},
        )
        update_downstream_configuration(
            actor=self.downstream.user,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            clear=True,
        )
        self.profile.refresh_from_db()
        cleared = set_authorization_configuration_override(
            actor=self.admin,
            authorization_id=instance.authorization_id,
            clear=True,
        )
        self.assertEqual(cleared.config_version, self.profile.config_version)
        self.assertFalse(cleared.configuration_override)
        verify_request, _ = self._request(
            action="verify",
            request_id="config-verify-cleared",
            authorization_id=str(instance.authorization_id),
            private_key=private_key,
        )
        cleared_result = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=20)))
        self.assertEqual(cleared_result.payload["config_version"], self.profile.config_version)
        self.assertIsNone(cleared_result.payload["support"])
        self.assertIsNone(cleared_result.payload["modules"]["contact"])
        self.assertEqual(cleared_result.payload["announcement"]["title"], "Profile公告")

    def test_unset_downstream_channel_support_is_empty_not_profile(self):
        update_profile_configuration(
            actor=self.admin,
            profile=self.profile,
            values={
                "purchase_url": "https://profile.example.test/buy",
                "qq": "profile-qq",
                "wechat": "profile-wechat",
                "announcement_enabled": True,
                "announcement_title": "Profile公告",
                "announcement_body": "Profile内容",
            },
        )
        activation_request, _ = self._request(
            action="activate",
            request_id="config-activate-no-downstream-support",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        self.assertIsNone(activated.payload["support"])
        self.assertIsNone(activated.payload["modules"]["contact"])
        self.assertEqual(activated.payload["announcement"]["title"], "Profile公告")

    def test_stale_config_version_forces_fresh_response_instead_of_not_modified(self):
        initial_values = {
            "purchase_url": "https://initial.example.test/buy",
            "qq": "initial-qq",
            "wechat": "initial-wechat",
            "announcement_enabled": False,
        }
        update_downstream_configuration(
            actor=self.downstream.user,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            values=initial_values,
        )
        activation_request, private_key = self._request(action="activate", request_id="config-cache-activate")
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        old_config_version = activated.payload["config_version"]
        old_revision = activated.payload["authorization_revision"]

        unchanged_request, _ = self._request(
            action="verify",
            request_id="config-cache-unchanged",
            authorization_id=activated.payload["authorization_id"],
            private_key=private_key,
            known_authorization_revision=old_revision,
            known_config_version=old_config_version,
        )
        unchanged = verify_license(request=unchanged_request, clock=FixedClock(self.now + timedelta(seconds=5)))
        self.assertEqual(unchanged.payload["decision"], "not_modified")

        update_downstream_configuration(
            actor=self.downstream.user,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            values={**initial_values, "qq": "fresh-qq"},
        )
        stale_request, _ = self._request(
            action="verify",
            request_id="config-cache-stale",
            authorization_id=activated.payload["authorization_id"],
            private_key=private_key,
            known_authorization_revision=old_revision,
            known_config_version=old_config_version,
        )
        refreshed = verify_license(request=stale_request, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertNotEqual(refreshed.payload["decision"], "not_modified")
        self.assertEqual(refreshed.payload["support"]["qq"], "fresh-qq")
        self.assertNotEqual(refreshed.payload["config_version"], old_config_version)

    def test_historical_closed_downstream_access_keeps_configuration_for_existing_authorization(self):
        update_downstream_configuration(
            actor=self.downstream.user,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            values={
                "purchase_url": "https://history.example.test/buy",
                "qq": "history-qq",
                "wechat": "history-wechat",
                "announcement_enabled": False,
            },
        )
        activation_request, private_key = self._request(action="activate", request_id="config-history-activate")
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get()
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            enabled=False,
        )

        verify_request, _ = self._request(
            action="verify",
            request_id="config-history-verify",
            authorization_id=str(instance.authorization_id),
            private_key=private_key,
        )
        verified = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertEqual(activated.payload["support"]["qq"], "history-qq")
        self.assertEqual(verified.payload["decision"], "active")
        self.assertEqual(verified.payload["support"]["qq"], "history-qq")
        self.assertIsNone(verified.payload["announcement"])

    def test_closed_downstream_access_blocks_unused_activate_without_creating_instance(self):
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            enabled=False,
        )
        request, _ = self._request(action="activate", request_id="closed-scope-unused-activate")
        with self.assertRaises(AuthorizationOperationError) as blocked:
            activate_license(request=request, clock=FixedClock(self.now))
        self.assertEqual(blocked.exception.code, "LICENSE_NOT_ACTIVE")
        self.assertEqual(blocked.exception.http_status, 403)
        http_request, _ = self._request(action="activate", request_id="closed-scope-unused-activate-http")
        http_response = self._post_public_action("activate", http_request)
        self.assertEqual(http_response.status_code, 403)
        self.assertEqual(http_response.json()["error"]["code"], "LICENSE_NOT_ACTIVE")
        self.card.refresh_from_db()
        self.assertEqual(self.card.status, LicenseCardStatus.UNUSED)
        self.assertEqual(LicenseInstance.objects.count(), 0)
        failure = (
            AuditEvent.objects.filter(action="authorization.activate", outcome=AuditOutcome.FAILURE)
            .order_by("-occurred_at")
            .first()
        )
        self.assertIsNotNone(failure)
        self.assertEqual(failure.metadata.get("software_id"), self.software.software_id)
        self.assertEqual(failure.metadata.get("installation_id"), request["installation_id"])
        self.assertIn("card_digest", failure.metadata)
        self.assertNotIn(self.license_key, json.dumps(failure.metadata, ensure_ascii=False))
        failure_row = present_event(failure)
        self.assertEqual(failure_row.actor_label, request["installation_id"])
        self.assertEqual(failure_row.actor_role_label, "客户端设备")
        self.assertEqual(failure_row.object_label, self.downstream.user.username)
        self.assertIn("retryable", failure.metadata)
        DownstreamSoftware.objects.filter(downstream=self.downstream, software=self.software).delete()
        request, _ = self._request(action="activate", request_id="missing-scope-unused-activate")
        with self.assertRaises(AuthorizationOperationError) as blocked:
            activate_license(request=request, clock=FixedClock(self.now))
        self.assertEqual(blocked.exception.code, "LICENSE_NOT_ACTIVE")
        self.assertEqual(blocked.exception.http_status, 403)
        self.card.refresh_from_db()
        self.assertEqual(self.card.status, LicenseCardStatus.UNUSED)
        self.assertEqual(LicenseInstance.objects.count(), 0)

    def test_archived_software_blocks_unused_activate_but_keeps_activated_verify(self):
        activation_request, private_key = self._request(
            action="activate",
            request_id="archive-software-keep-verify",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        self.assertEqual(activated.payload["decision"], "active")
        instance = LicenseInstance.objects.get()
        unused_issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="archive-software-unused-issue",
        )
        unused_card = LicenseCard.objects.get(public_id=unused_issued.cards[0].public_id)
        unused_key = decrypt_license_card(unused_card.card_ciphertext)
        update_software_status(
            actor=self.admin,
            software_id=self.software.software_id,
            status=SoftwareStatus.ARCHIVED,
        )
        unused_request, _ = self._request(
            action="activate",
            request_id="archive-software-unused-activate",
            license_key=unused_key,
        )
        with self.assertRaises(AuthorizationOperationError) as blocked:
            activate_license(request=unused_request, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(blocked.exception.code, "LICENSE_NOT_ACTIVE")
        self.assertEqual(blocked.exception.http_status, 403)
        unused_card.refresh_from_db()
        self.assertEqual(unused_card.status, LicenseCardStatus.UNUSED)
        http_request, _ = self._request(
            action="activate",
            request_id="archive-software-unused-activate-http",
            license_key=unused_key,
        )
        http_response = self._post_public_action("activate", http_request)
        self.assertEqual(http_response.status_code, 403)
        self.assertEqual(http_response.json()["error"]["code"], "LICENSE_NOT_ACTIVE")
        verify_request, _ = self._request(
            action="verify",
            request_id="archive-software-keep-verify-check",
            authorization_id=str(instance.authorization_id),
            private_key=private_key,
        )
        verified = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertEqual(verified.payload["decision"], "active")

    def test_closed_downstream_access_device_switch_is_not_scope_rejection(self):
        activate_request, _ = self._request(action="activate", request_id="close-scope-then-switch-activate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        self.assertEqual(activated.payload["decision"], "active")
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            enabled=False,
        )
        new_device, _ = self._request(
            action="activate",
            request_id="close-scope-new-device-activate",
            installation_id="install-b",
        )
        with self.assertRaises(AuthorizationOperationError) as blocked:
            activate_license(request=new_device, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(blocked.exception.code, "DEVICE_LIMIT_REACHED")
        self.assertNotEqual(blocked.exception.code, "LICENSE_NOT_ACTIVE")

    def test_closed_downstream_access_still_allows_unused_reclaim_refund(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=20,
            reason="关范围后回收准备",
            idempotency_key="closed-scope-reclaim-credit",
        )
        _, paid_snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="关范围回收套餐",
            duration_seconds=60,
            quota_cost=10,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=paid_snapshot.snapshot_id,
            quantity=1,
            idempotency_key="closed-scope-reclaim-issue",
        )
        paid_card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software.software_id,
            enabled=False,
        )
        result = reclaim_license_card(
            actor=self.downstream.user,
            card_public_id=paid_card.public_id,
            idempotency_key="closed-scope-reclaim",
        )
        self.assertFalse(result.repeated)
        paid_card.refresh_from_db()
        self.assertEqual(paid_card.status, LicenseCardStatus.RECLAIMED)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 20)
        self.assertEqual(LicenseInstance.objects.count(), 0)

    def test_cache_and_next_verify_are_capped_at_signed_expiry(self):
        activate_request, private_key = self._request(action="activate", request_id="cache-expiry-activate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        verify_request, _ = self._request(
            action="verify",
            request_id="cache-expiry-verify",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )

        result = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=59)))

        self.assertEqual(result.payload["cache_until"], result.payload["expires_at"])
        self.assertEqual(result.payload["next_verify_at"], result.payload["expires_at"])
        self.assertLessEqual(result.payload["cache_until"], result.payload["expires_at"])
        self.assertLessEqual(result.payload["next_verify_at"], result.payload["expires_at"])

    def test_grace_state_fails_closed_at_signed_expiry(self):
        activate_request, private_key = self._request(action="activate", request_id="grace-expiry-activate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        instance.state = AuthorizationState.GRACE
        instance.save(update_fields=("state",), _allow_mutation=True)

        verify_request, _ = self._request(
            action="verify",
            request_id="grace-expiry-verify",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        result = verify_license(
            request=verify_request,
            clock=FixedClock(self.now + timedelta(seconds=60)),
        )

        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.payload["decision"], "expired")
        self.assertEqual(result.payload["state_code"], "expired")
        self.assertEqual(LicenseInstance.objects.get(pk=instance.pk).state, AuthorizationState.EXPIRED)

    def test_same_request_is_idempotent_without_reusing_nonce(self):
        request, _ = self._request(action="activate", request_id="activate-repeat")
        first = activate_license(request=request, clock=FixedClock(self.now))
        repeated = activate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=1)))

        self.assertTrue(repeated.repeated)
        self.assertEqual(first.payload, repeated.payload)
        self.assertEqual(LicenseInstance.objects.count(), 1)
        self.assertEqual(AuthorizationNonce.objects.count(), 1)
        self.assertEqual(AuthorizationRequestRecord.objects.count(), 1)

    def test_idempotent_replay_after_revoke_never_returns_old_allow(self):
        request, _ = self._request(action="activate", request_id="activate-stale-after-revoke")
        first = activate_license(request=request, clock=FixedClock(self.now))
        revoke_authorization(
            actor=self.admin,
            authorization_id=first.payload["authorization_id"],
            reason="幂等旧响应安全验收",
            now=self.now + timedelta(seconds=1),
        )

        with self.assertRaises(AuthorizationOperationError) as raised:
            activate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=2)))

        self.assertEqual(raised.exception.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(LicenseInstance.objects.get(pk=first.payload["authorization_id"]).state, AuthorizationState.REVOKED)

    def test_different_request_with_used_nonce_is_rejected(self):
        request, private_key = self._request(action="activate", request_id="activate-nonce-a")
        activate_license(request=request, clock=FixedClock(self.now))
        replay, _ = self._request(
            action="activate",
            request_id="activate-nonce-b",
            private_key=private_key,
            nonce=request["nonce"],
        )
        with self.assertRaises(Exception) as raised:
            activate_license(request=replay, clock=FixedClock(self.now))
        self.assertEqual(raised.exception.code, "REPLAY_DETECTED")
        self.assertEqual(LicenseInstance.objects.count(), 1)

    def test_invalid_device_proof_does_not_create_device_or_instance(self):
        request, _ = self._request(action="activate", request_id="activate-bad-proof", proof_override="invalid-proof")
        with self.assertRaises(Exception) as raised:
            activate_license(request=request, clock=FixedClock(self.now))
        self.assertEqual(raised.exception.code, "DEVICE_PROOF_INVALID")
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(LicenseInstance.objects.count(), 0)

    def test_invalid_activation_proof_during_server_rollback_cannot_freeze_card(self):
        request, private_key = self._request(action="activate", request_id="proof-before-clock-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        revision = instance.authorization_revision
        for index in range(5):
            invalid, _ = self._request(
                action="activate", request_id=f"proof-before-clock-invalid-{index}",
                private_key=private_key, proof_override="invalid-proof",
            )
            with self.assertRaises(AuthorizationOperationError) as raised:
                activate_license(request=invalid, clock=FixedClock(self.now - timedelta(seconds=30)))
            self.assertEqual(raised.exception.code, "DEVICE_PROOF_INVALID")
        instance.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(instance.state, AuthorizationState.ACTIVE)
        self.assertEqual(instance.authorization_revision, revision)
        self.assertEqual(self.card.status, LicenseCardStatus.ACTIVATED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        self.assertEqual(Device.objects.get().risk_state, DeviceRiskState.NORMAL)
        self.assertFalse(AuditEvent.objects.filter(reason_code="TIME_ROLLBACK_DETECTED").exists())

    def test_valid_activation_proof_during_server_rollback_still_blocks(self):
        request, private_key = self._request(action="activate", request_id="valid-clock-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        retry, _ = self._request(action="activate", request_id="valid-clock-recheck", private_key=private_key)
        result = activate_license(request=retry, clock=FixedClock(self.now - timedelta(seconds=30)))
        self.assertEqual(result.payload["error"]["code"], "TIME_ROLLBACK_DETECTED")
        self.assertEqual(LicenseInstance.objects.get(pk=activated.payload["authorization_id"]).state, AuthorizationState.BLOCKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)

    def test_repeated_untrusted_verify_failures_do_not_punish_valid_customer(self):
        request, private_key = self._request(action="activate", request_id="customer-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        instance = LicenseInstance.objects.get(pk=authorization_id)
        revision, expiry = instance.authorization_revision, instance.expires_at
        for index in range(12):
            invalid, _ = self._request(
                action="verify", request_id=f"untrusted-verify-{index}",
                authorization_id=authorization_id, proof_override="invalid-proof",
            )
            with self.assertRaises(AuthorizationOperationError) as raised:
                verify_license(request=invalid, clock=FixedClock(self.now + timedelta(seconds=1)))
            self.assertEqual(raised.exception.code, "DEVICE_PROOF_INVALID")
        instance.refresh_from_db()
        self.assertEqual((instance.state, instance.authorization_revision, instance.expires_at), (AuthorizationState.ACTIVE, revision, expiry))
        valid, _ = self._request(action="verify", request_id="customer-valid-after-noise", authorization_id=authorization_id, private_key=private_key)
        self.assertEqual(verify_license(request=valid, clock=FixedClock(self.now + timedelta(seconds=2))).payload["decision"], "active")
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)

    def test_admin_read_distinguishes_clock_recovery_from_card_freeze(self):
        request, private_key = self._request(action="activate", request_id="clock-read-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        verify, _ = self._request(action="verify", request_id="clock-read-rollback", authorization_id=authorization_id, private_key=private_key)
        verify_license(request=verify, clock=FixedClock(self.now - timedelta(seconds=30)))
        client = Client()
        client.force_login(self.admin)
        response = client.get(reverse("licensing:api_manage_authorizations"))
        self.assertEqual(response.status_code, 200)
        item = response.json()["items"][0]
        self.assertTrue(item["time_rollback_blocked"])
        self.assertFalse(item["card_frozen"])
        recovered = client.post(
            reverse("licensing:api_manage_authorization_device_unblock", kwargs={"authorization_id": authorization_id, "device_id": item["devices"][0]["device_action_ref"]}),
            data=json.dumps({"reason": "服务器时间核对后恢复"}), content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="clock-read-recovery",
        )
        self.assertEqual(recovered.status_code, 200)
        item = recovered.json()["item"]
        self.assertFalse(item["time_rollback_blocked"])
        self.assertFalse(item["card_frozen"])
        self.assertEqual(item["status"], "active")
        self.assertTrue(AuditEvent.objects.filter(action="device.unblock", metadata__rollback_recovery=True).exists())

    def test_request_rejects_unrecognized_device_scope_instead_of_ignoring_it(self):
        request, _ = self._request(action="activate", request_id="request-device-scope")
        request["device_scope"] = {"scope": "current_device"}

        with self.assertRaises(AuthorizationOperationError) as raised:
            activate_license(request=request, clock=FixedClock(self.now))

        self.assertEqual(raised.exception.code, "INVALID_REQUEST")
        self.assertEqual(LicenseInstance.objects.count(), 0)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.UNUSED)

    def test_cross_profile_identity_is_rejected_before_card_lookup(self):
        request, _ = self._request(action="activate", request_id="activate-cross-profile")
        request["profile_id"] = "other-profile"
        with self.assertRaises(Exception) as raised:
            activate_license(request=request, clock=FixedClock(self.now))
        self.assertEqual(raised.exception.code, "PROFILE_MISMATCH")
        self.assertEqual(LicenseInstance.objects.count(), 0)

    def test_device_limit_is_enforced_and_failed_attempt_rolls_back_device(self):
        first, _ = self._request(action="activate", request_id="activate-device-a", installation_id="install-a")
        activate_license(request=first, clock=FixedClock(self.now))
        second, _ = self._request(action="activate", request_id="activate-device-b", installation_id="install-b")

        with self.assertRaises(Exception) as raised:
            activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(raised.exception.code, "DEVICE_LIMIT_REACHED")
        self.assertIn("当前不允许新电脑挤掉旧电脑", raised.exception.message)
        self.assertNotIn("已达到当前授权的设备上限", raised.exception.message)
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_same_installation_id_second_activate_reuses_device(self):
        first, private_key = self._request(
            action="activate",
            request_id="activate-same-fingerprint-1",
            installation_id="install-a",
        )
        activate_license(request=first, clock=FixedClock(self.now))
        first_device = Device.objects.get()
        second, _ = self._request(
            action="activate",
            request_id="activate-same-fingerprint-2",
            installation_id="install-a",
            private_key=private_key,
        )
        activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(Device.objects.get().public_id, first_device.public_id)

    def test_active_binding_rejects_a_different_registered_device_key(self):
        first, first_private_key = self._request(
            action="activate",
            request_id="activate-bound-key-a",
            installation_id="install-a",
        )
        activated = activate_license(request=first, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        binding = DeviceBinding.objects.get(authorization_id=authorization_id, device=device)

        # 1. 在未重新激活前，直接拿未绑定的 second key 进行 verify 和 deactivate，必须严格拒绝并抛出 DEVICE_KEY_MISMATCH
        second, second_private_key = self._request(
            action="activate",
            request_id="activate-bound-key-b",
            installation_id="install-a",
        )
        second_raw_key = base64.urlsafe_b64decode(second["device_public_key"] + "===")
        second_key_id = f"device-ed25519-{hashlib.sha256(second_raw_key).hexdigest()[:32]}"
        unbound_key_obj = DeviceKey.objects.create(
            key_id=second_key_id,
            device=device,
            public_key=second["device_public_key"],
            created_at=self.now,
        )

        verify_unbound, _ = self._request(
            action="verify",
            request_id="verify-unbound-key-b",
            installation_id="install-a",
            private_key=second_private_key,
            authorization_id=authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as verify_error:
            verify_license(request=verify_unbound, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(verify_error.exception.code, "DEVICE_KEY_MISMATCH")

        deactivate_unbound, _ = self._request(
            action="deactivate",
            request_id="deactivate-unbound-key-b",
            installation_id="install-a",
            private_key=second_private_key,
            authorization_id=authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as deactivate_error:
            deactivate_license(request=deactivate_unbound, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(deactivate_error.exception.code, "DEVICE_KEY_MISMATCH")

        # 2. 同机重装场景：携带合法卡密与新公钥签名重新激活，自愈轮换绑定公钥并写审计（计入一次换机额度防乒乓劫持）
        self._revise_daily_switch(request_id="revise-rotate-quota", allow=True, limit=5)
        reactivated = activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(reactivated.payload["decision"], "active")
        binding.refresh_from_db()
        self.assertEqual(binding.device_key_id, unbound_key_obj.pk)
        self.assertTrue(
            AuditEvent.objects.filter(action="device.key_rotate", object_public_id=binding.binding_id).exists()
        )
        rotated_instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(rotated_instance.device_switch_count, 1)

        # 3. 轮换后，使用新的 second_private_key 验证成功
        verify_new, _ = self._request(
            action="verify",
            request_id="verify-rotated-key-b",
            installation_id="install-a",
            private_key=second_private_key,
            authorization_id=authorization_id,
        )
        verified_new = verify_license(request=verify_new, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(verified_new.payload["decision"], "active")

        # 4. 轮换后，失效的旧 first_private_key 调用 verify / deactivate 均抛出 DEVICE_KEY_MISMATCH
        verify_old, _ = self._request(
            action="verify",
            request_id="verify-rotated-old-key",
            installation_id="install-a",
            private_key=first_private_key,
            authorization_id=authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as old_verify_err:
            verify_license(request=verify_old, clock=FixedClock(self.now + timedelta(seconds=4)))
        self.assertEqual(old_verify_err.exception.code, "DEVICE_KEY_MISMATCH")

        deactivate_old, _ = self._request(
            action="deactivate",
            request_id="deactivate-rotated-old-key",
            installation_id="install-a",
            private_key=first_private_key,
            authorization_id=authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as old_deactivate_err:
            deactivate_license(request=deactivate_old, clock=FixedClock(self.now + timedelta(seconds=5)))
        self.assertEqual(old_deactivate_err.exception.code, "DEVICE_KEY_MISMATCH")

    def test_exact_server_expiry_marks_authorization_and_card_expired(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-expiry")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        verify_request, _ = self._request(
            action="verify",
            request_id="verify-expiry",
            private_key=private_key,
            authorization_id=authorization_id,
            installation_id="install-a",
        )
        result = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=60)))

        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.payload["decision"], "expired")
        self.assertEqual(result.payload["error"]["code"], "LICENSE_EXPIRED")
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.EXPIRED)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.EXPIRED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.EXPIRED)

    def test_time_rollback_fails_closed_and_blocks_instance(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-rollback")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        verify_request, _ = self._request(
            action="verify",
            request_id="verify-rollback",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        result = verify_license(request=verify_request, clock=FixedClock(self.now - timedelta(seconds=30)))

        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.payload["error"]["code"], "TIME_ROLLBACK_DETECTED")
        self.assertEqual(result.payload["decision"], "blocked")
        self.assertEqual(LicenseInstance.objects.get(pk=activated.payload["authorization_id"]).state, AuthorizationState.BLOCKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        self.assertEqual(result.payload["server_time"], int(self.now.timestamp()))
        self.assertGreaterEqual(result.payload["server_time"], result.payload["issued_at"])
        self.assertEqual(result.payload["cache_until"], result.payload["next_verify_at"])
        self.assertLessEqual(result.payload["cache_until"], result.payload["expires_at"])
        self.assertEqual(DeviceBinding.objects.get().unbound_at, self.now)

    def test_time_rollback_block_is_recoverable_by_admin_unblock(self):
        """Server clock rollback blocks the instance AND every binding, so the
        card-freeze definition ("blocked with seats still occupied") cannot see
        it.  Before this fix the only recovery was revoking the card."""

        activate_request, private_key = self._request(action="activate", request_id="activate-rollback-recover")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()

        verify_request, _ = self._request(
            action="verify",
            request_id="verify-rollback-recover",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        rolled = verify_license(request=verify_request, clock=FixedClock(self.now - timedelta(seconds=30)))
        self.assertEqual(rolled.payload["error"]["code"], "TIME_ROLLBACK_DETECTED")
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.BLOCKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        self.assertFalse(
            authorization_card_is_frozen(LicenseInstance.objects.get(pk=authorization_id))
        )

        recovered = unblock_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="确认是服务器时钟问题，恢复",
            now=self.now + timedelta(seconds=1),
            request_id="admin-rollback-recover",
        )
        self.assertFalse(recovered.repeated)
        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.state, AuthorizationState.ACTIVE)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        self.assertIsNone(DeviceBinding.objects.get().unbound_at)

        event = AuditEvent.objects.get(
            action="device.unblock", outcome="success", object_public_id=str(authorization_id)
        )
        self.assertTrue(event.metadata["rollback_recovery"])
        self.assertEqual(event.metadata["bindings_restored"], 1)

        restored_request, _ = self._request(
            action="verify",
            request_id="verify-after-rollback-recover",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        restored = verify_license(
            request=restored_request, clock=FixedClock(self.now + timedelta(seconds=2))
        )
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.payload["decision"], "active")

    def test_unblock_refuses_other_security_blocks(self):
        """Only the rollback marker may be recovered through unblock_device;
        a card frozen by the risk console keeps its own semantics."""

        activate_request, _private_key = self._request(action="activate", request_id="activate-blocked-refuse")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()

        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="冻卡占座",
            now=self.now + timedelta(seconds=1),
            request_id="admin-block-then-rollback-refuse",
        )
        # Freeze the instance without any active seat so it is neither "frozen"
        # by the card definition nor a rollback block.
        binding = DeviceBinding.objects.get(authorization_id=authorization_id)
        binding.state = DeviceBindingState.UNBOUND
        binding.unbound_at = self.now + timedelta(seconds=1)
        binding.reason = "测试解绑"
        binding.save(update_fields=("state", "unbound_at", "reason"), _allow_mutation=True)
        with self.assertRaises(AuthorizationOperationError) as caught:
            unblock_device(
                actor=self.admin,
                authorization_id=authorization_id,
                device_id=device.public_id,
                reason="不应通过",
                now=self.now + timedelta(seconds=2),
                request_id="admin-unblock-refuse",
            )
        self.assertEqual(caught.exception.code, "AUTHORIZATION_BLOCKED")

    def test_time_drift_within_tolerance_is_allowed_without_blocking(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-drift")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        verify_request, _ = self._request(
            action="verify",
            request_id="verify-drift",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        # 回退 5 秒（处于 15 秒容差范围内，模拟服务端 NTP 校准）
        result = verify_license(request=verify_request, clock=FixedClock(self.now - timedelta(seconds=5)))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.payload["decision"], "active")
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        self.assertEqual(instance.state, AuthorizationState.ACTIVE)
        # 响应的时间戳单调不后退，保持在激活时的高水位时间
        self.assertEqual(result.payload["server_time"], int(self.now.timestamp()))
        # 数据库持久化的高水位线绝不后退，依然保持 self.now
        self.assertEqual(instance.last_server_time, self.now)

    def _assert_lock_then_time_does_not_false_positive_rollback(self, action: str):
        initial_request, private_key = self._request(action="activate", request_id=f"lock-time-{action}-initial")
        activated = activate_license(request=initial_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        older_now = self.now + timedelta(seconds=1)
        newer_now = self.now + timedelta(seconds=2)
        old_request, _ = self._request(
            action=action,
            request_id=f"lock-time-{action}-older",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        newer_request, _ = self._request(
            action="verify",
            request_id=f"lock-time-{action}-newer",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        state = {"newer_finished": False}

        class LockAwareClock:
            def now(self):
                return newer_now if state["newer_finished"] else older_now

        lock_name = "_lock_card_by_license_key" if action == "activate" else "_lock_card_for_instance"
        original_lock = getattr(authorization_service, lock_name)

        def run_newer_before_old_lock(*args, **kwargs):
            if not state["newer_finished"]:
                state["newer_finished"] = True
                newer = verify_license(request=newer_request, clock=FixedClock(newer_now))
                self.assertEqual(newer.status_code, 200)
                self.assertEqual(newer.payload["decision"], "active")
            return original_lock(*args, **kwargs)

        with patch.object(authorization_service, lock_name, side_effect=run_newer_before_old_lock):
            result = getattr(authorization_service, f"{action}_license")(
                request=old_request,
                clock=LockAwareClock(),
            )

        self.assertEqual(result.status_code, 200)
        self.assertNotIn("error", result.payload)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.ACTIVE)
        if action == "deactivate":
            self.assertEqual(result.payload["state_code"], DeviceBindingState.UNBOUND)
        else:
            self.assertEqual(result.payload["decision"], "active")

    def test_activate_reads_time_after_card_lock(self):
        self._assert_lock_then_time_does_not_false_positive_rollback("activate")

    def test_verify_reads_time_after_authorization_lock(self):
        self._assert_lock_then_time_does_not_false_positive_rollback("verify")

    def test_deactivate_reads_time_after_authorization_lock(self):
        self._assert_lock_then_time_does_not_false_positive_rollback("deactivate")

    def test_admin_revoke_invalidates_card_binding_and_retries(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-admin-revoke")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision

        first = revoke_authorization(
            actor=self.admin,
            authorization_id=authorization_id,
            reason="人工安全处置",
            now=self.now + timedelta(seconds=1),
            request_id="admin-revoke-1",
        )
        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertFalse(first.repeated)
        self.assertEqual(instance.state, AuthorizationState.REVOKED)
        self.assertEqual(instance.authorization_revision, before_revision + 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.REVOKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        self.assertTrue(AuditEvent.objects.filter(action="authorization.revoke", outcome="success").exists())

        repeated = revoke_authorization(
            actor=self.admin,
            authorization_id=authorization_id,
            reason="重复撤销",
            now=self.now + timedelta(seconds=2),
            request_id="admin-revoke-2",
        )
        self.assertTrue(repeated.repeated)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, before_revision + 1)

        verify_request, _ = self._request(
            action="verify",
            request_id="verify-after-admin-revoke",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        result = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.payload["decision"], "revoked")
        self.assertEqual(result.payload["error"]["code"], "LICENSE_REVOKED")

    def test_admin_device_block_and_unblock_keep_active_binding_occupied(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-device-risk")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision

        blocked = block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="异常设备行为",
            now=self.now + timedelta(seconds=1),
            request_id="admin-device-block-1",
        )
        self.assertFalse(blocked.repeated)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, "normal")
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        self.assertIsNone(DeviceBinding.objects.get().unbound_at)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.BLOCKED)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, before_revision + 1)

        verify_request, _ = self._request(
            action="verify",
            request_id="verify-blocked-device",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        blocked_verify = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(blocked_verify.status_code, 403)
        self.assertEqual(blocked_verify.payload["error"]["code"], "LICENSE_BLOCKED")
        self.assertEqual(blocked_verify.payload["decision"], "blocked")
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)

        unblocked = unblock_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="复核后解除",
            now=self.now + timedelta(seconds=3),
            request_id="admin-device-unblock-1",
        )
        self.assertFalse(unblocked.repeated)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, "normal")
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.ACTIVE)
        unblock_event = AuditEvent.objects.get(action="device.unblock", outcome="success", object_public_id=str(authorization_id))
        self.assertEqual(unblock_event.metadata["reason"], "复核后解除")
        self.assertEqual(unblock_event.metadata["effective_at"], (self.now + timedelta(seconds=3)).isoformat())

        restored_verify_request, _ = self._request(
            action="verify",
            request_id="verify-after-unblock",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        restored = verify_license(request=restored_verify_request, clock=FixedClock(self.now + timedelta(seconds=4)))
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.payload["decision"], "active")
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)
        self.assertEqual(DeviceBinding.objects.count(), 1)

        repeated = unblock_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="重复解除",
            now=self.now + timedelta(seconds=5),
            request_id="admin-device-unblock-2",
        )
        self.assertTrue(repeated.repeated)

    def test_frozen_card_rejects_new_installation_without_vacating_seat(self):
        activate_request, private_key = self._request(action="activate", request_id="freeze-new-install-activate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="冻卡占座",
            now=self.now + timedelta(seconds=1),
            request_id="freeze-new-install-block",
        )
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

        new_install, _ = self._request(
            action="activate",
            request_id="freeze-new-install-retry",
            private_key=private_key,
            installation_id="install-new",
        )
        refused = activate_license(request=new_install, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(refused.payload["error"]["code"], "LICENSE_BLOCKED")
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)
        self.assertEqual(DeviceBinding.objects.count(), 1)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, DeviceRiskState.NORMAL)

    def test_frozen_card_keeps_other_card_on_same_device_usable(self):
        first_request, first_key = self._request(action="activate", request_id="freeze-other-card-first")
        first = activate_license(request=first_request, clock=FixedClock(self.now))
        first_authorization_id = first.payload["authorization_id"]
        device = Device.objects.get()
        _, second_snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="同机第二张卡套餐",
            duration_seconds=60,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=second_snapshot.snapshot_id,
            quantity=1,
            idempotency_key="freeze-other-card-issue",
        )
        second_card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        second_key = decrypt_license_card(second_card.card_ciphertext)
        second_request, second_private = self._request(
            action="activate",
            request_id="freeze-other-card-second",
            license_key=second_key,
            installation_id="install-a",
        )
        second = activate_license(request=second_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(second.status_code, 200)
        second_authorization_id = second.payload["authorization_id"]

        block_device(
            actor=self.admin,
            authorization_id=first_authorization_id,
            device_id=device.public_id,
            reason="只冻第一张卡",
            now=self.now + timedelta(seconds=2),
            request_id="freeze-other-card-block",
        )
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(
            DeviceBinding.objects.get(authorization_id=first_authorization_id).state,
            DeviceBindingState.ACTIVE,
        )
        self.assertEqual(
            DeviceBinding.objects.get(authorization_id=second_authorization_id).state,
            DeviceBindingState.ACTIVE,
        )

        second_verify, _ = self._request(
            action="verify",
            request_id="freeze-other-card-second-verify",
            private_key=second_private,
            authorization_id=second_authorization_id,
            installation_id="install-a",
        )
        usable = verify_license(request=second_verify, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(usable.status_code, 200)
        self.assertEqual(usable.payload["decision"], "active")

        first_verify, _ = self._request(
            action="verify",
            request_id="freeze-other-card-first-verify",
            private_key=first_key,
            authorization_id=first_authorization_id,
        )
        frozen = verify_license(request=first_verify, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(frozen.status_code, 403)
        self.assertEqual(frozen.payload["error"]["code"], "LICENSE_BLOCKED")

    def test_unfreeze_keeps_original_active_binding_without_reactivate(self):
        activate_request, private_key = self._request(action="activate", request_id="unfreeze-keep-binding")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="先冻后解",
            now=self.now + timedelta(seconds=1),
            request_id="unfreeze-keep-binding-block",
        )
        unblock_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="解冻不重建绑定",
            now=self.now + timedelta(seconds=2),
            request_id="unfreeze-keep-binding-unblock",
        )
        binding = DeviceBinding.objects.get()
        self.assertEqual(binding.state, DeviceBindingState.ACTIVE)
        self.assertEqual(DeviceBinding.objects.count(), 1)
        verify_request, _ = self._request(
            action="verify",
            request_id="unfreeze-keep-binding-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        restored = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.payload["decision"], "active")
        self.assertEqual(DeviceBinding.objects.count(), 1)

    def test_admin_reset_device_unbinds_current_binding_without_changing_expiry(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-device-reset")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        instance_before = LicenseInstance.objects.get(pk=authorization_id)
        expires_at = instance_before.expires_at
        revision_before = instance_before.authorization_revision
        activated_at = instance_before.activated_at

        first = reset_device_binding(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="客户申请换机",
            now=self.now + timedelta(seconds=1),
            request_id="admin-device-reset-1",
        )
        self.assertFalse(first.repeated)
        instance = LicenseInstance.objects.get(pk=authorization_id)
        binding = DeviceBinding.objects.get(authorization=instance, device=device)
        self.assertEqual(binding.state, DeviceBindingState.UNBOUND)
        self.assertEqual(binding.reason, "客户申请换机")
        self.assertEqual(binding.unbound_at, self.now + timedelta(seconds=1))
        self.assertEqual(instance.state, AuthorizationState.ACTIVE)
        self.assertEqual(instance.authorization_revision, revision_before + 1)
        self.assertEqual(instance.expires_at, expires_at)
        self.assertEqual(instance.activated_at, activated_at)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.ACTIVATED)
        self.assertTrue(AuditEvent.objects.filter(action="device.reset", outcome=AuditOutcome.SUCCESS).exists())

        verify_request, _ = self._request(
            action="verify",
            request_id="verify-after-device-reset",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as unbound:
            verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(unbound.exception.code, "DEVICE_NOT_BOUND")

        repeated = reset_device_binding(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="重复换机申请",
            now=self.now + timedelta(seconds=2),
            request_id="admin-device-reset-2",
        )
        self.assertTrue(repeated.repeated)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, revision_before + 1)
        self.assertEqual(DeviceBinding.objects.filter(authorization=instance).count(), 1)

        reactivate_request, _ = self._request(
            action="activate",
            request_id="activate-after-device-reset",
            private_key=private_key,
            installation_id="install-a",
        )
        reactivated = activate_license(request=reactivate_request, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(reactivated.payload["decision"], "active")
        self.assertEqual(DeviceBinding.objects.filter(authorization=instance, state=DeviceBindingState.ACTIVE).count(), 1)

    def test_admin_reset_allows_a_fresh_device_key_to_rebind_same_installation(self):
        first_request, first_private_key = self._request(action="activate", request_id="fresh-key-reset-first")
        activated = activate_license(request=first_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        reset_device_binding(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="换机并更新设备密钥",
            now=self.now + timedelta(seconds=1),
            request_id="fresh-key-reset",
        )

        second_request, second_private_key = self._request(
            action="activate",
            request_id="fresh-key-reset-second",
            installation_id="install-a",
        )
        reactivated = activate_license(request=second_request, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(reactivated.status_code, 200)
        self.assertEqual(reactivated.payload["decision"], "active")
        active_binding = DeviceBinding.objects.get(authorization_id=authorization_id, state=DeviceBindingState.ACTIVE)
        old_binding = DeviceBinding.objects.get(authorization_id=authorization_id, state=DeviceBindingState.UNBOUND)
        self.assertNotEqual(active_binding.binding_id, old_binding.binding_id)
        self.assertEqual(DeviceKey.objects.filter(device=device).count(), 2)
        second_raw_key = base64.urlsafe_b64decode(second_request["device_public_key"] + "===")
        expected_key_id = f"device-ed25519-{hashlib.sha256(second_raw_key).hexdigest()[:32]}"
        self.assertEqual(active_binding.device_key_id, expected_key_id)

        second_verify, _ = self._request(
            action="verify",
            request_id="fresh-key-reset-verify-new",
            installation_id="install-a",
            private_key=second_private_key,
            authorization_id=authorization_id,
        )
        self.assertEqual(verify_license(request=second_verify, clock=FixedClock(self.now + timedelta(seconds=3))).status_code, 200)

        old_verify, _ = self._request(
            action="verify",
            request_id="fresh-key-reset-verify-old",
            installation_id="install-a",
            private_key=first_private_key,
            authorization_id=authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as old_key_error:
            verify_license(request=old_verify, clock=FixedClock(self.now + timedelta(seconds=4)))
        self.assertEqual(old_key_error.exception.code, "DEVICE_KEY_MISMATCH")

    def test_suspended_downstream_blocks_new_binding_but_keeps_existing_verification(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-downstream-policy")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))

        self.downstream.status = DownstreamStatus.SUSPENDED
        self.downstream.save(update_fields=("status", "updated_at"))

        verify_request, _ = self._request(
            action="verify",
            request_id="verify-existing-after-suspend",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        existing = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(existing.payload["decision"], "active")

        new_device, _ = self._request(
            action="activate",
            request_id="activate-new-device-after-suspend",
            installation_id="install-b",
        )
        with self.assertRaises(AuthorizationOperationError) as blocked:
            activate_license(request=new_device, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(blocked.exception.code, "DOWNSTREAM_NOT_ACTIVE")
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_admin_risk_signal_queue_is_bounded_and_admin_only(self):
        request, _ = self._request(action="activate", request_id="risk-signal-proof", proof_override="invalid-proof")
        with self.assertRaises(AuthorizationOperationError):
            activate_license(request=request, request_id=request["request_id"], clock=FixedClock(self.now))

        signals = list_risk_signals_for_admin(actor=self.admin, limit=1)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].reason_code, "DEVICE_PROOF_INVALID")
        self.assertNotIn(self.license_key, signals[0].request_id)
        self.assertTrue(signals[0].request_id.startswith("auth-"))
        self.assertEqual(redact_request_id(signals[0].request_id), f"sha256:{hashlib.sha256(signals[0].request_id.encode()).hexdigest()[:16]}")

        self.client.force_login(self.admin)
        dashboard = self.client.get(reverse("licensing:authorization_admin"))
        self.assertContains(dashboard, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(dashboard, "待复核异常信号", status_code=410)
        self.assertNotContains(dashboard, "risk-signal-proof", status_code=410)
        self.assertNotContains(dashboard, "撤销授权", status_code=410)
        self.assertNotContains(dashboard, "阻断设备", status_code=410)

        with self.assertRaises(AuthorizationOperationError) as forbidden:
            list_risk_signals_for_admin(actor=self.downstream.user)
        self.assertEqual(forbidden.exception.code, "FORBIDDEN")

    def test_admin_risk_actions_require_admin_and_reason(self):
        activate_request, _ = self._request(action="activate", request_id="activate-admin-guard")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        device = Device.objects.get()

        with self.assertRaises(AuthorizationOperationError) as forbidden:
            block_device(
                actor=self.downstream.user,
                authorization_id=activated.payload["authorization_id"],
                device_id=device.public_id,
                reason="越权",
            )
        self.assertEqual(forbidden.exception.code, "FORBIDDEN")
        with self.assertRaises(AuthorizationOperationError) as invalid_reason:
            revoke_authorization(actor=self.admin, authorization_id=activated.payload["authorization_id"], reason=" ")
        self.assertEqual(invalid_reason.exception.code, "INVALID_REASON")

    def test_terminal_activation_does_not_echo_unconfirmed_device_scope(self):
        activate_request, _ = self._request(action="activate", request_id="activate-terminal-scope")
        activate_license(request=activate_request, clock=FixedClock(self.now))
        self.card.status = LicenseCardStatus.REVOKED
        self.card.save(update_fields=("status",), _allow_mutation=True)

        request, _ = self._request(
            action="activate",
            request_id="activate-terminal-scope-retry",
            installation_id="attacker-installation",
            proof_override="invalid-proof",
        )
        result = activate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=1)))

        self.assertEqual(result.payload["error"]["code"], "LICENSE_REVOKED")
        self.assertEqual(
            result.payload["device_scope"],
            {"scope": "current_device", "device_id": None, "installation_id": None},
        )

    def test_signed_response_with_invalid_shape_fails_closed(self):
        request, _ = self._request(action="activate", request_id="shape-check")
        result = activate_license(request=request, clock=FixedClock(self.now))
        malformed = dict(result.payload)
        malformed["device_scope"] = "device-a"

        with self.assertRaises(AuthorizationOperationError) as raised:
            verify_authorization_response(
                malformed,
                {settings.AUTHORIZATION_SIGNING_KEY_ID: authorization_signing_public_key()},
            )
        self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

    def test_non_object_response_fails_closed_before_integrity_access(self):
        with self.assertRaises(AuthorizationOperationError) as raised:
            verify_authorization_response([], {})
        self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

    def test_deactivate_preserves_history_and_is_idempotent(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-deactivate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        request, _ = self._request(
            action="deactivate",
            request_id="deactivate-1",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        first = deactivate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=1)))
        repeated = deactivate_license(request=request, clock=FixedClock(self.now + timedelta(seconds=2)))

        self.assertEqual(first.payload["state_code"], "unbound")
        self.assertEqual(first.payload["decision"], "unbound")
        self.assertNotEqual(first.payload["decision"], "active")
        self.assertEqual(first.payload["cache_until"], first.payload["server_time"])
        self.assertTrue(repeated.repeated)
        self.assertEqual(first.payload, repeated.payload)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.UNBOUND)
        self.assertEqual(DeviceBinding.objects.count(), 1)
        self.assertEqual(LicenseInstance.objects.get().authorization_revision, 2)

    def test_public_api_returns_contract_response(self):
        private_key = Ed25519PrivateKey.generate()
        request, _ = self._request(action="activate", request_id="api-activate", private_key=private_key)
        response = Client(enforce_csrf_checks=True).post(
            reverse("licensing:public_license_activate"),
            data=json.dumps(request),
            content_type="application/json",
            HTTP_X_REQUEST_ID="api-activate",
            HTTP_IDEMPOTENCY_KEY="api-activate",
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["schema_version"], "authorization.v1")
        self.assertEqual(body["integrity"]["algorithm"], "ed25519")
        self.assertEqual(body["integrity"]["canonicalization"], "JCS-RFC8785")

    def test_public_api_rejects_non_post_with_structured_no_store_error(self):
        response = Client().get(
            reverse("licensing:public_license_verify"),
            HTTP_X_REQUEST_ID="method-check",
        )

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Allow"], "POST")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["Pragma"], "no-cache")
        self.assertEqual(response.json()["error"]["code"], "METHOD_NOT_ALLOWED")
        self.assertEqual(response.json()["error"]["request_id"], "method-check")

    @override_settings(PUBLIC_LICENSE_RATE_LIMIT=1)
    def test_public_verify_rate_limit_only_when_still_bound(self):
        identity = "10.0.0.91"
        reset_rate_limit("public-license-verify", identity)
        activate_request, private_key = self._request(action="activate", request_id="rate-bound-activate")
        activated = activate_license(request=activate_request)
        authorization_id = activated.payload["authorization_id"]

        first_payload, _ = self._request(
            action="verify",
            request_id="rate-bound-v1",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        first = self._post_public_action("verify", first_payload, remote_addr=identity)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["decision"], "active")

        second_payload, _ = self._request(
            action="verify",
            request_id="rate-bound-v2",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        second = self._post_public_action("verify", second_payload, remote_addr=identity)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second["Cache-Control"], "no-store")
        self.assertEqual(second["Retry-After"], "300")
        self.assertEqual(second.json()["error"]["code"], "RATE_LIMITED")
        self.assertTrue(second.json()["error"]["retryable"])
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.ACTIVE)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)

    @override_settings(PUBLIC_LICENSE_RATE_LIMIT=1)
    def test_public_verify_returns_device_not_bound_after_kick_even_when_rate_limited(self):
        identity = "10.0.0.92"
        reset_rate_limit("public-license-verify", identity)
        self._revise_daily_switch(request_id="revise-rate-kick")
        first_request, first_key = self._request(
            action="activate",
            request_id="rate-kick-a",
            installation_id="install-rate-a",
        )
        activated = activate_license(request=first_request)
        authorization_id = activated.payload["authorization_id"]

        first_verify, _ = self._request(
            action="verify",
            request_id="rate-kick-v1",
            private_key=first_key,
            authorization_id=authorization_id,
            installation_id="install-rate-a",
        )
        first = self._post_public_action("verify", first_verify, remote_addr=identity)
        self.assertEqual(first.status_code, 200)

        second_request, _ = self._request(
            action="activate",
            request_id="rate-kick-b",
            installation_id="install-rate-b",
        )
        switched = activate_license(request=second_request)
        self.assertEqual(switched.payload["decision"], "active")

        kicked_verify, _ = self._request(
            action="verify",
            request_id="rate-kick-v2",
            private_key=first_key,
            authorization_id=authorization_id,
            installation_id="install-rate-a",
        )
        unbound = self._post_public_action("verify", kicked_verify, remote_addr=identity)
        self.assertEqual(unbound.status_code, 403)
        self.assertEqual(unbound.json()["error"]["code"], "DEVICE_NOT_BOUND")
        self.assertNotEqual(unbound.status_code, 429)

    @override_settings(PUBLIC_LICENSE_RATE_LIMIT=1)
    def test_public_verify_returns_device_not_bound_after_unbind_even_when_rate_limited(self):
        identity = "10.0.0.93"
        reset_rate_limit("public-license-verify", identity)
        activate_request, private_key = self._request(action="activate", request_id="rate-unbind-activate")
        activated = activate_license(request=activate_request)
        authorization_id = activated.payload["authorization_id"]

        first_verify, _ = self._request(
            action="verify",
            request_id="rate-unbind-v1",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        first = self._post_public_action("verify", first_verify, remote_addr=identity)
        self.assertEqual(first.status_code, 200)

        deactivate_request, _ = self._request(
            action="deactivate",
            request_id="rate-unbind-off",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        deactivate_license(request=deactivate_request)

        unbound_verify, _ = self._request(
            action="verify",
            request_id="rate-unbind-v2",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        unbound = self._post_public_action("verify", unbound_verify, remote_addr=identity)
        self.assertEqual(unbound.status_code, 403)
        self.assertEqual(unbound.json()["error"]["code"], "DEVICE_NOT_BOUND")
        self.assertNotEqual(unbound.status_code, 429)

    @override_settings(PUBLIC_LICENSE_RATE_LIMIT=1)
    def test_public_verify_hard_request_error_is_not_covered_by_rate_limit(self):
        identity = "10.0.0.94"
        reset_rate_limit("public-license-verify", identity)
        first = Client().post(
            reverse("licensing:public_license_verify"),
            data=json.dumps({"request_id": "rate-hard-first"}),
            content_type="application/json",
            REMOTE_ADDR=identity,
            HTTP_X_REQUEST_ID="rate-hard-first",
        )
        second = Client().post(
            reverse("licensing:public_license_verify"),
            data=json.dumps({"request_id": "rate-hard-second"}),
            content_type="application/json",
            REMOTE_ADDR=identity,
            HTTP_X_REQUEST_ID="rate-hard-second",
        )
        self.assertEqual(first.status_code, 400)
        self.assertEqual(second.status_code, 400)
        self.assertNotEqual(second.status_code, 429)
        self.assertNotEqual(second.json()["error"]["code"], "RATE_LIMITED")

    def test_hard_failures_are_never_replaced_by_rate_limiting(self):
        """The frozen client contract requires a hard failure to be returned
        as-is even after the caller has tripped a ceiling; a 429 would make the
        launcher treat a real kick as retryable and leave the software open."""

        from authorization_platform.accounts.rate_limit import reset as reset_rate_limit
        from authorization_platform.licensing.api import (
            FAILED_VERIFY_OBSERVATION_LIMIT,
            _consume_failed_verify_rate,
            _failed_verify_budget_exhausted,
        )

        identity = "10.0.0.95"
        reset_rate_limit("public-license-verify-failed", identity)
        reset_rate_limit("public-license-verify", identity)

        # Saturate the observation counter the way repeated bad input would.
        for _ in range(FAILED_VERIFY_OBSERVATION_LIMIT):
            _consume_failed_verify_rate(identity)
        self.assertTrue(_failed_verify_budget_exhausted(identity))

        # A malformed request must still get its own structured error, not 429.
        saturated = Client().post(
            reverse("licensing:public_license_verify"),
            data=json.dumps({"request_id": "rate-failed-budget"}),
            content_type="application/json",
            REMOTE_ADDR=identity,
            HTTP_X_REQUEST_ID="rate-failed-budget",
        )
        self.assertEqual(saturated.status_code, 400)
        self.assertEqual(saturated.json()["error"]["code"], "MISSING_REQUIRED_FIELD")
        self.assertNotEqual(saturated.status_code, 429)
        reset_rate_limit("public-license-verify-failed", identity)

    def test_kicked_device_still_gets_device_not_bound_after_saturation(self):
        """The contract's own wording: after being kicked or unbound, the
        endpoint must return DEVICE_NOT_BOUND even when the IP is limited."""

        from authorization_platform.accounts.rate_limit import reset as reset_rate_limit
        from authorization_platform.licensing.api import (
            FAILED_VERIFY_OBSERVATION_LIMIT,
            _consume_failed_verify_rate,
        )

        identity = "10.0.0.101"
        reset_rate_limit("public-license-verify-failed", identity)
        reset_rate_limit("public-license-verify", identity)

        # This test drives the HTTP view (real clock) while activation uses the
        # fixed clock, so the plan must still be live when the request runs.
        _plan, snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="饱和后合同验收",
            duration_seconds=365 * 86400,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="saturate-issue",
        )
        card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        license_key = decrypt_license_card(card.card_ciphertext)

        activate_request, private_key = self._request(
            action="activate", request_id="saturate-activate", license_key=license_key
        )
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]

        for _ in range(FAILED_VERIFY_OBSERVATION_LIMIT):
            _consume_failed_verify_rate(identity)

        deactivate_request, _ = self._request(
            action="deactivate",
            request_id="saturate-deactivate",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        deactivate_license(request=deactivate_request)

        unbound_verify, _ = self._request(
            action="verify",
            request_id="saturate-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        response = self._post_public_action("verify", unbound_verify, remote_addr=identity)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "DEVICE_NOT_BOUND")
        self.assertNotEqual(response.status_code, 429)
        reset_rate_limit("public-license-verify-failed", identity)

    def test_successful_verify_does_not_consume_the_failure_budget(self):
        from authorization_platform.licensing.api import _failed_verify_budget_exhausted
        from authorization_platform.accounts.rate_limit import reset as reset_rate_limit

        identity = "10.0.0.96"
        reset_rate_limit("public-license-verify-failed", identity)
        # This test drives the HTTP view, which uses the real clock, while the
        # instance is activated on the fixed clock.  Use a long plan so the
        # authorization is still live when the request runs.
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="失败预算验收",
            duration_seconds=365 * 86400,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="budget-issue",
        )
        card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        license_key = decrypt_license_card(card.card_ciphertext)
        activate_request, private_key = self._request(
            action="activate",
            request_id="budget-activate",
            installation_id="install-budget",
            license_key=license_key,
        )
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        for index in range(5):
            verify_request, _ = self._request(
                action="verify",
                request_id=f"budget-verify-{index}",
                private_key=private_key,
                authorization_id=activated.payload["authorization_id"],
                installation_id="install-budget",
            )
            response = self._post_public_action("verify", verify_request, remote_addr=identity)
            self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(_failed_verify_budget_exhausted(identity))
    def test_public_license_body_size_and_depth_are_capped(self):
        identity = "10.0.0.97"
        oversized = Client().post(
            reverse("licensing:public_license_verify"),
            data=json.dumps({"request_id": "body-size", "padding": "x" * (40 * 1024)}),
            content_type="application/json",
            REMOTE_ADDR=identity,
        )
        self.assertEqual(oversized.status_code, 400)
        self.assertEqual(oversized.json()["error"]["code"], "INVALID_REQUEST")

        nested = {"request_id": "body-depth"}
        cursor = nested
        for _ in range(20):
            cursor["child"] = {}
            cursor = cursor["child"]
        deep = Client().post(
            reverse("licensing:public_license_verify"),
            data=json.dumps(nested),
            content_type="application/json",
            REMOTE_ADDR=identity,
        )
        self.assertEqual(deep.status_code, 400)
        self.assertEqual(deep.json()["error"]["code"], "INVALID_REQUEST")

    def test_lone_surrogate_in_request_returns_400_not_500(self):
        identity = "10.0.0.98"
        response = Client().post(
            reverse("licensing:public_license_verify"),
            data='{"request_id": "\\ud800"}',
            content_type="application/json",
            REMOTE_ADDR=identity,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")

    def test_deeply_nested_body_is_rejected_before_the_parser_recurses(self):
        """32KB is enough for thousands of opening brackets, which trips
        json.loads' own recursion limit and used to escape as an unhandled 500.
        The raw pre-parse scan must reject it as a structured 400."""

        import json as json_module

        with self.assertRaises(RecursionError):
            json_module.loads("[" * 12000 + "]" * 12000)

        identity = "10.0.0.99"
        for count, label in ((12000, "24000B"), (16000, "32000B")):
            body = "[" * count + "]" * count
            self.assertLessEqual(len(body), 32 * 1024, label)
            response = Client().post(
                reverse("licensing:public_license_verify"),
                data=body,
                content_type="application/json",
                REMOTE_ADDR=identity,
            )
            self.assertEqual(response.status_code, 400, label)
            self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST", label)

    def test_brackets_inside_a_string_do_not_trip_the_raw_depth_guard(self):
        from authorization_platform.licensing.api import _raw_nesting_depth

        body = json.dumps(
            {"request_id": "a" + "[" * 200 + "b", "software_id": "x"}
        ).encode("utf-8")
        self.assertLessEqual(_raw_nesting_depth(body), 8)
        response = Client().post(
            reverse("licensing:public_license_verify"),
            data=body.decode("utf-8"),
            content_type="application/json",
            REMOTE_ADDR="10.0.0.100",
        )
        # Rejected for a missing field, not for nesting depth.
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("嵌套", response.json()["error"]["message"])

    def test_verify_after_interval_still_succeeds_for_bound_device(self):
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="一小时间隔验收",
            duration_seconds=3600,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="interval-ok-issue",
        )
        card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        license_key = decrypt_license_card(card.card_ciphertext)
        activate_request, private_key = self._request(
            action="activate",
            request_id="interval-ok-activate",
            license_key=license_key,
        )
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        later, _ = self._request(
            action="verify",
            request_id="interval-ok-verify",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        result = verify_license(request=later, clock=FixedClock(self.now + timedelta(seconds=90)))
        self.assertEqual(result.payload["decision"], "active")
        self.assertGreater(result.payload["expires_at"], result.payload["server_time"])
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)

    def test_admin_risk_dashboard_and_routes_are_scoped(self):
        request, _ = self._request(action="activate", request_id="admin-dashboard-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]

        self.client.force_login(self.admin)
        page = self.client.get(reverse("licensing:authorization_admin"))
        self.assertContains(page, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(page, "授权风险控制", status_code=410)
        self.assertNotContains(page, "撤销授权", status_code=410)
        self.assertNotContains(page, "阻断设备", status_code=410)
        self.assertNotContains(page, FORBIDDEN_API_COPY, status_code=410)

        response = self.client.post(
            reverse("licensing:admin_revoke_authorization", kwargs={"authorization_id": authorization_id}),
            {"reason": "页面安全处置"},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, "历史管理写入口已停用", status_code=410)
        self.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.ACTIVE)

        self.client.force_login(self.downstream.user)
        denied = self.client.get(reverse("licensing:authorization_admin"))
        self.assertEqual(denied.status_code, 403)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="admin.access",
                outcome="failure",
                reason_code="FORBIDDEN",
            ).exists()
        )

    def test_html_authorization_configuration_does_not_write(self):
        request, _ = self._request(action="activate", request_id="html-config-closed")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        instance = LicenseInstance.objects.get(pk=authorization_id)
        before = instance.configuration_override
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("licensing:admin_authorization_configuration", kwargs={"authorization_id": authorization_id}),
            {"purchase_url": "https://evil.example/buy", "qq": "123456"},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)
        instance.refresh_from_db()
        self.assertEqual(instance.configuration_override, before)

    def test_admin_risk_routes_are_post_only_csrf_protected_and_scoped(self):
        request, _ = self._request(action="activate", request_id="admin-http-guards")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        revoke_url = reverse("licensing:admin_revoke_authorization", kwargs={"authorization_id": authorization_id})
        block_url = reverse("licensing:admin_block_device", kwargs={"device_id": device.public_id})

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        dashboard = admin_client.get(reverse("licensing:authorization_admin"))
        self.assertContains(dashboard, CONTROL_ROOM_COPY, status_code=410)
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)

        self.assertEqual(admin_client.get(revoke_url).status_code, 405)
        self.assertEqual(admin_client.get(block_url).status_code, 405)
        self.assertEqual(admin_client.get(reverse("licensing:admin_unblock_device", kwargs={"device_id": device.public_id})).status_code, 405)
        self.assertEqual(admin_client.post(block_url, {"reason": "无 CSRF"}).status_code, 403)
        self.assertEqual(admin_client.post(revoke_url, {"reason": "无 CSRF"}).status_code, 403)
        self.assertEqual(
            admin_client.post(
                reverse("licensing:admin_unblock_device", kwargs={"device_id": device.public_id}),
                {"reason": "无 CSRF"},
            ).status_code,
            403,
        )
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, "normal")

        invalid_reason = admin_client.post(
            block_url,
            {"reason": " "},
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(invalid_reason.status_code, 410)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, "normal")

        revoked = admin_client.post(
            revoke_url,
            {"reason": "HTTP 撤销验收"},
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(revoked.status_code, 410)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.ACTIVE)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.ACTIVATED)
        self.assertEqual(DeviceBinding.objects.get(device=device).state, DeviceBindingState.ACTIVE)

        repeated_revoke = admin_client.post(
            revoke_url,
            {"reason": "HTTP 重复撤销"},
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(repeated_revoke.status_code, 410)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, 1)

        downstream_client = Client()
        downstream_client.force_login(self.downstream.user)
        self.assertEqual(downstream_client.get(reverse("licensing:authorization_admin")).status_code, 403)
        self.assertEqual(downstream_client.post(block_url, {"reason": "越权"}).status_code, 403)
        self.assertEqual(downstream_client.post(revoke_url, {"reason": "越权"}).status_code, 403)
        self.assertEqual(
            downstream_client.post(
                reverse("licensing:admin_unblock_device", kwargs={"device_id": device.public_id}),
                {"reason": "越权"},
            ).status_code,
            403,
        )
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, "normal")

    def test_legacy_admin_risk_routes_fail_closed_without_state_change(self):
        request, _ = self._request(action="activate", request_id="admin-http-device-risk")
        activate_license(request=request, clock=FixedClock(self.now))
        device = Device.objects.get()
        authorization_id = LicenseInstance.objects.get().authorization_id
        block_url = reverse("licensing:admin_block_device", kwargs={"device_id": device.public_id})
        unblock_url = reverse("licensing:admin_unblock_device", kwargs={"device_id": device.public_id})
        revoke_url = reverse("licensing:admin_revoke_authorization", kwargs={"authorization_id": authorization_id})

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("licensing:authorization_admin"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)

        for url, reason in (
            (revoke_url, "HTTP 旧撤销入口"),
            (block_url, "HTTP 旧阻断入口"),
            (unblock_url, "HTTP 旧解除入口"),
        ):
            retired = admin_client.post(url, {"reason": reason}, HTTP_X_CSRFTOKEN=csrf_cookie.value)
            self.assertEqual(retired.status_code, 410)
            self.assertContains(retired, CONTROL_ROOM_COPY, status_code=410)
            self.assertNotContains(retired, "历史管理写入口已停用", status_code=410)
            self.assertNotContains(retired, FORBIDDEN_API_COPY, status_code=410)

        self.assertEqual(LicenseInstance.objects.get().state, AuthorizationState.ACTIVE)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, "normal")
        self.assertEqual(DeviceBinding.objects.get(device=device).state, DeviceBindingState.ACTIVE)

    def test_management_authorization_api_is_admin_only_and_exposes_device_facts(self):
        request, _ = self._request(action="activate", request_id="admin-api-list-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        device.last_ip = "203.0.113.24"
        device.save(update_fields=("last_ip",), _allow_mutation=True)

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        session = admin_client.get(reverse("accounts:api_session"))
        self.assertEqual(session.status_code, 200)
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)

        list_url = reverse("licensing:api_manage_authorizations")
        listed = admin_client.get(list_url, {"page_size": 10})
        self.assertEqual(listed.status_code, 200)
        body = listed.json()
        self.assertEqual(body["pagination"]["page"], 1)
        self.assertFalse(body["pagination"]["has_next"])
        self.assertEqual(len(body["items"]), 1)
        item = body["items"][0]
        self.assertEqual(item["authorization_id"], str(authorization_id))
        device_id = str(device.public_id)
        self.assertEqual(item["device_id"], device_id)
        self.assertEqual(item["device_code"], "install-a")
        self.assertEqual(item["installation_id"], "install-a")
        self.assertEqual(item["device_uuid"], device_id)
        self.assertTrue(item["device_action_ref"])
        self.assertEqual(item["device_ip"], "203.0.113.24")
        self.assertEqual([entry["device_id"] for entry in item["devices"]], [device_id])
        self.assertTrue(item["devices"][0]["device_action_ref"])
        self.assertNotIn(str(device.public_id), item["device_action_ref"])
        padded = item["device_action_ref"] + "=" * ((4 - len(item["device_action_ref"]) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        self.assertNotIn(str(device.public_id).encode("ascii"), decoded)
        self.assertNotIn(b"device_id", decoded)
        self.assertTrue(item["masked_code"].startswith("••••-••••-"))
        for forbidden in ("installation_hash", "device_public_key", "card_ciphertext", "code", "request_id"):
            self.assertNotIn(forbidden, item)
        for device_entry in item["devices"]:
            for forbidden in ("installation_hash", "device_public_key", "public_key", "card_ciphertext", "code"):
                self.assertNotIn(forbidden, device_entry)

        by_device = admin_client.get(list_url, {"q": str(device.public_id)})
        self.assertEqual(by_device.status_code, 200)
        self.assertEqual([entry["authorization_id"] for entry in by_device.json()["items"]], [str(authorization_id)])
        exported = admin_client.get(reverse("licensing:api_manage_authorizations_export"), {"q": str(device.public_id)})
        self.assertEqual(exported.status_code, 200)
        self.assertIn(self.license_key[-4:], exported.content.decode("utf-8"))
        self.assertNotIn("X-Export-Truncated", exported)
        self.assertTrue(AuditEvent.objects.filter(action="authorization.export", outcome="success").exists())
        filtered = admin_client.get(
            list_url,
            {"software_id": "generic-tool", "device_state": "bound", "risk_state": "normal"},
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(len(filtered.json()["items"]), 1)
        by_plan = admin_client.get(list_url, {"q": "一分钟测试卡"})
        self.assertEqual(by_plan.status_code, 200)
        self.assertEqual(len(by_plan.json()["items"]), 1)
        by_plain_device = admin_client.get(list_url, {"q": device_id})
        self.assertEqual(by_plain_device.status_code, 200)
        self.assertEqual(len(by_plain_device.json()["items"]), 1)
        by_client_device = admin_client.get(list_url, {"q": "install-a"})
        self.assertEqual(by_client_device.status_code, 200)
        self.assertEqual(len(by_client_device.json()["items"]), 1)
        by_masked_device_spaces = admin_client.get(
            list_url,
            {"q": f"{str(device.public_id)[:4]} {str(device.public_id)[-4:]}"},
        )
        self.assertEqual(by_masked_device_spaces.status_code, 200)
        self.assertEqual(len(by_masked_device_spaces.json()["items"]), 1)
        by_card = admin_client.get(list_url, {"q": self.license_key})
        self.assertEqual(by_card.status_code, 200)
        self.assertEqual(len(by_card.json()["items"]), 1)
        too_long = admin_client.get(list_url, {"q": "x" * 129})
        self.assertEqual(too_long.status_code, 400)
        self.assertEqual(too_long.json()["error"]["code"], "INVALID_QUERY")

        downstream_client = Client()
        downstream_client.force_login(self.downstream.user)
        downstream_session = downstream_client.session
        downstream_session["downstream_session_version"] = str(self.downstream.session_version)
        downstream_session.save()
        self.assertEqual(downstream_client.get(list_url).status_code, 403)

        revoke_url = reverse("licensing:api_manage_authorization_revoke", kwargs={"authorization_id": authorization_id})
        self.assertEqual(admin_client.get(revoke_url).status_code, 405)
        without_csrf = admin_client.post(
            revoke_url,
            data=json.dumps({"reason": "API 安全处置"}),
            content_type="application/json",
        )
        self.assertEqual(without_csrf.status_code, 403)
        self.assertEqual(without_csrf.json()["error"]["code"], "CSRF_FAILED")

        invalid_reason = admin_client.post(
            revoke_url,
            data=json.dumps({}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
            HTTP_IDEMPOTENCY_KEY="api-revoke-invalid-reason",
        )
        self.assertEqual(invalid_reason.status_code, 400)
        self.assertEqual(invalid_reason.json()["error"]["code"], "INVALID_REASON")

        revoked = admin_client.post(
            revoke_url,
            data=json.dumps({"reason": "API 安全处置"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
            HTTP_IDEMPOTENCY_KEY="api-revoke-1",
            HTTP_X_REQUEST_ID="admin-api-revoke",
        )
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(revoked.json()["item"]["status"], AuthorizationState.REVOKED)
        revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision
        repeated = admin_client.post(
            revoke_url,
            data=json.dumps({"reason": "API 安全处置"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
            HTTP_IDEMPOTENCY_KEY="api-revoke-2",
            HTTP_X_REQUEST_ID="admin-api-revoke-repeat",
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertTrue(repeated.json()["repeated"])
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, revision)

    def test_authorization_export_expiry_uses_beijing_wall_clock(self):
        request, _ = self._request(action="activate", request_id="export-beijing-activate")
        activate_license(request=request, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get()
        instant = datetime(2026, 9, 5, 16, 0, 0, tzinfo=UTC)
        instance.activated_at = datetime(2026, 9, 1, 0, 0, 0, tzinfo=UTC)
        instance.expires_at = instant
        instance.save(update_fields=("activated_at", "expires_at"), _allow_mutation=True)
        admin_client = Client()
        admin_client.force_login(self.admin)
        exported = admin_client.get(reverse("licensing:api_manage_authorizations_export"))
        self.assertEqual(exported.status_code, 200)
        rows = list(csv.reader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0][9], "到期时间")
        self.assertEqual(rows[1][9], "2026-09-06 00:00:00")
        self.assertEqual(rows[1][8], "2026-09-01 08:00:00")
        self.assertNotIn("2026-09-05 16:00:00", exported.content.decode("utf-8-sig"))
        listed = admin_client.get(reverse("licensing:api_manage_authorizations"))
        self.assertEqual(listed.status_code, 200)
        self.assertIn("2026-09-05T16:00:00", listed.json()["items"][0]["expires_at"])
        self.assertNotIn("2026-09-06T00:00:00", listed.json()["items"][0]["expires_at"])

    def test_management_authorizations_expired_filter_includes_active_past_expiry_without_writing_state(self):
        request, _ = self._request(action="activate", request_id="wall-clock-expired-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = str(activated.payload["authorization_id"])
        instance = LicenseInstance.objects.get(pk=authorization_id)
        now = datetime.now(UTC)
        instance.expires_at = now + timedelta(days=20)
        instance.save(update_fields=("expires_at",), _allow_mutation=True)
        admin_client = Client()
        admin_client.force_login(self.admin)
        url = reverse("licensing:api_manage_authorizations")
        future_active = admin_client.get(url, {"status": "active", "page_size": 10})
        future_expired = admin_client.get(url, {"status": "expired", "page_size": 10})
        self.assertEqual(future_active.status_code, 200)
        self.assertEqual(future_expired.status_code, 200)
        self.assertIn(authorization_id, {row["authorization_id"] for row in future_active.json()["items"]})
        self.assertNotIn(authorization_id, {row["authorization_id"] for row in future_expired.json()["items"]})
        instance.expires_at = now - timedelta(days=1)
        instance.save(update_fields=("expires_at",), _allow_mutation=True)
        past_expired = admin_client.get(url, {"status": "expired", "page_size": 10})
        past_active = admin_client.get(url, {"status": "active", "page_size": 10})
        self.assertEqual(past_expired.status_code, 200)
        self.assertEqual(past_active.status_code, 200)
        expired_item = next(row for row in past_expired.json()["items"] if row["authorization_id"] == authorization_id)
        self.assertEqual(expired_item["status"], AuthorizationState.ACTIVE)
        self.assertNotIn(authorization_id, {row["authorization_id"] for row in past_active.json()["items"]})
        instance.refresh_from_db()
        self.assertEqual(instance.state, AuthorizationState.ACTIVE)

    def test_management_device_actions_use_csrf_and_preserve_binding_history(self):
        request, _ = self._request(action="activate", request_id="admin-api-device-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        headers = {"HTTP_X_CSRFTOKEN": csrf_cookie.value}
        listed = admin_client.get(reverse("licensing:api_manage_authorizations"))
        self.assertEqual(listed.status_code, 200)
        action_ref = listed.json()["items"][0]["devices"][0]["device_action_ref"]

        reset_url = reverse(
            "licensing:api_manage_authorization_device_reset",
            kwargs={"authorization_id": authorization_id, "device_id": action_ref},
        )
        block_url = reverse(
            "licensing:api_manage_authorization_device_block",
            kwargs={"authorization_id": authorization_id, "device_id": action_ref},
        )
        unblock_url = reverse(
            "licensing:api_manage_authorization_device_unblock",
            kwargs={"authorization_id": authorization_id, "device_id": action_ref},
        )
        self.assertEqual(admin_client.get(reset_url).status_code, 405)
        self.assertEqual(admin_client.get(block_url).status_code, 405)
        self.assertEqual(admin_client.post(reset_url, data=json.dumps({"reason": "设备重置"}), content_type="application/json").status_code, 403)

        raw_block = admin_client.post(
            reverse(
                "licensing:api_manage_authorization_device_block",
                kwargs={"authorization_id": authorization_id, "device_id": device.public_id},
            ),
            data=json.dumps({"reason": "拒绝原始设备标识"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="api-block-raw-uuid",
            **headers,
        )
        self.assertEqual(raw_block.status_code, 400)
        self.assertEqual(raw_block.json()["error"]["code"], "DEVICE_ACTION_REF_INVALID")

        blocked = admin_client.post(
            block_url,
            data=json.dumps({"reason": "设备风险复核"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="api-block-1",
            **headers,
        )
        self.assertEqual(blocked.status_code, 200)
        self.assertTrue(blocked.json()["item"]["card_frozen"])
        self.assertEqual(blocked.json()["item"]["status"], AuthorizationState.BLOCKED)
        self.assertEqual(blocked.json()["device"]["risk_state"], DeviceRiskState.NORMAL)
        self.assertEqual(blocked.json()["device"]["device_id"], str(device.public_id))
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(DeviceBinding.objects.get(authorization_id=authorization_id).state, DeviceBindingState.ACTIVE)

        unblocked = admin_client.post(
            unblock_url,
            data=json.dumps({"reason": "复核后解除"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="api-unblock-1",
            **headers,
        )
        self.assertEqual(unblocked.status_code, 200)
        self.assertFalse(unblocked.json()["item"]["card_frozen"])
        self.assertEqual(unblocked.json()["device"]["risk_state"], DeviceRiskState.NORMAL)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(DeviceBinding.objects.get(authorization_id=authorization_id).state, DeviceBindingState.ACTIVE)

        reset = admin_client.post(
            reset_url,
            data=json.dumps({"reason": "客户申请重置"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="api-reset-1",
            **headers,
        )
        self.assertEqual(reset.status_code, 200)
        self.assertFalse(reset.json()["repeated"])
        self.assertEqual(DeviceBinding.objects.get(authorization_id=authorization_id).state, DeviceBindingState.UNBOUND)
        self.assertTrue(AuditEvent.objects.filter(action="device.reset", outcome=AuditOutcome.SUCCESS).exists())
        self.assertTrue(AuditEvent.objects.filter(action="device.block", outcome=AuditOutcome.SUCCESS).exists())
        self.assertTrue(AuditEvent.objects.filter(action="device.unblock", outcome=AuditOutcome.SUCCESS).exists())

    def test_management_api_requires_durable_idempotency_and_exact_reset_scope(self):
        request, _ = self._request(action="activate", request_id="admin-api-idempotency-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        action_ref = admin_client.get(reverse("licensing:api_manage_authorizations")).json()["items"][0]["devices"][0]["device_action_ref"]
        reset_url = reverse(
            "licensing:api_manage_authorization_device_reset",
            kwargs={"authorization_id": authorization_id, "device_id": action_ref},
        )
        body = {"reason": "客户申请精确重置"}
        csrf_headers = {"HTTP_X_CSRFTOKEN": csrf_cookie.value}

        missing_key = admin_client.post(
            reset_url,
            data=json.dumps(body),
            content_type="application/json",
            **csrf_headers,
        )
        self.assertEqual(missing_key.status_code, 400)
        self.assertEqual(missing_key.json()["error"]["code"], "IDEMPOTENCY_REQUIRED")

        first = admin_client.post(
            reset_url,
            data=json.dumps(body),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="admin-api-reset-durable-1",
            HTTP_X_REQUEST_ID="admin-api-reset-durable-request",
            **csrf_headers,
        )
        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.json()["repeated"])

        reset_audit = AuditEvent.objects.filter(
            action="device.reset",
            outcome=AuditOutcome.SUCCESS,
        ).order_by("-occurred_at").first()
        self.assertIsNotNone(reset_audit)
        self.assertEqual(reset_audit.metadata["binding_active_before"], 1)
        self.assertEqual(reset_audit.metadata["binding_active_after"], 0)

        replay = admin_client.post(
            reset_url,
            data=json.dumps(body),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="admin-api-reset-durable-1",
            HTTP_X_REQUEST_ID="admin-api-reset-durable-request",
            **csrf_headers,
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), first.json())
        self.assertTrue(replay.json()["repeated"] is False)

        conflict = admin_client.post(
            reset_url,
            data=json.dumps({"reason": "同键不同目标内容"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="admin-api-reset-durable-1",
            HTTP_X_REQUEST_ID="admin-api-reset-durable-conflict",
            **csrf_headers,
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

        self.assertEqual(
            AuthorizationAdminOperation.objects.filter(
                actor=self.admin,
                idempotency_key="admin-api-reset-durable-1",
            ).count(),
            1,
        )
        self.assertEqual(
            DeviceBinding.objects.get(authorization_id=authorization_id, device=device).state,
            DeviceBindingState.UNBOUND,
        )
        operation = AuthorizationAdminOperation.objects.get(
            actor=self.admin,
            idempotency_key="admin-api-reset-durable-1",
        )
        with self.assertRaises(ValueError):
            AuthorizationAdminOperation.objects.filter(pk=operation.pk).update(response_payload={"tampered": True})
        with self.assertRaises(ValueError):
            AuthorizationAdminOperation.objects.filter(pk=operation.pk).delete()

        missing_target = admin_client.post(
            reverse(
                "licensing:api_manage_authorization_device_reset",
                kwargs={"authorization_id": uuid.uuid4(), "device_id": device.public_id},
            ),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="admin-api-reset-missing-target",
            **csrf_headers,
        )
        self.assertEqual(missing_target.status_code, 400)
        self.assertEqual(missing_target.json()["error"]["code"], "DEVICE_ACTION_REF_INVALID")

    def test_admin_reset_shared_device_only_unbinds_target_authorization(self):
        first_request, private_key = self._request(action="activate", request_id="shared-device-auth-one")
        first = activate_license(request=first_request, clock=FixedClock(self.now))
        first_authorization_id = first.payload["authorization_id"]

        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="shared-device-auth-two-card",
        )
        second_card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        second_request, _ = self._request(
            action="activate",
            request_id="shared-device-auth-two",
            private_key=private_key,
            installation_id="install-a",
            license_key=decrypt_license_card(second_card.card_ciphertext),
        )
        second = activate_license(request=second_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        second_authorization_id = second.payload["authorization_id"]
        self.assertNotEqual(first_authorization_id, second_authorization_id)
        device = Device.objects.get()
        self.assertEqual(DeviceBinding.objects.filter(device=device, state=DeviceBindingState.ACTIVE).count(), 2)

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        listed = admin_client.get(reverse("licensing:api_manage_authorizations")).json()["items"]
        action_ref = next(item for item in listed if item["authorization_id"] == str(first_authorization_id))["devices"][0]["device_action_ref"]
        reset = admin_client.post(
            reverse(
                "licensing:api_manage_authorization_device_reset",
                kwargs={"authorization_id": first_authorization_id, "device_id": action_ref},
            ),
            data=json.dumps({"reason": "只重置第一份授权"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="shared-device-reset-one",
            HTTP_X_REQUEST_ID="shared-device-reset-one-request",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(reset.status_code, 200)
        self.assertFalse(reset.json()["repeated"])
        self.assertEqual(
            DeviceBinding.objects.get(authorization_id=first_authorization_id, device=device).state,
            DeviceBindingState.UNBOUND,
        )
        self.assertEqual(
            DeviceBinding.objects.get(authorization_id=second_authorization_id, device=device).state,
            DeviceBindingState.ACTIVE,
        )
        first_verify, _ = self._request(
            action="verify",
            request_id="shared-device-verify-reset-target",
            private_key=private_key,
            authorization_id=first_authorization_id,
        )
        with self.assertRaises(AuthorizationOperationError) as unbound:
            verify_license(request=first_verify, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(unbound.exception.code, "DEVICE_NOT_BOUND")
        sibling_verify, _ = self._request(
            action="verify",
            request_id="shared-device-verify-sibling",
            private_key=private_key,
            authorization_id=second_authorization_id,
        )
        sibling = verify_license(request=sibling_verify, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(sibling.payload["decision"], "active")

    def test_management_list_exposes_all_devices_for_one_authorization(self):
        self.policy.max_devices = 2
        self.policy.save(update_fields=("max_devices",), _allow_mutation=True)
        first_request, _ = self._request(action="activate", request_id="multi-device-first")
        activated = activate_license(request=first_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        second_request, _ = self._request(
            action="activate",
            request_id="multi-device-second",
            installation_id="install-b",
        )
        activate_license(request=second_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(DeviceBinding.objects.filter(authorization_id=authorization_id, state=DeviceBindingState.ACTIVE).count(), 2)

        admin_client = Client()
        admin_client.force_login(self.admin)
        response = admin_client.get(reverse("licensing:api_manage_authorizations"))
        self.assertEqual(response.status_code, 200)
        item = response.json()["items"][0]
        self.assertEqual(item["authorization_id"], str(authorization_id))
        self.assertEqual(item["verify_interval_seconds"], self.policy.verify_interval_seconds)
        expected_device_ids = {str(device.public_id) for device in Device.objects.all()}
        self.assertEqual({entry["device_id"] for entry in item["devices"]}, expected_device_ids)
        self.assertTrue(all(entry["device_action_ref"] for entry in item["devices"]))

    def test_management_authorization_pagination_is_auth_scoped_and_never_splits_devices(self):
        self.policy.max_devices = 2
        self.policy.save(update_fields=("max_devices",), _allow_mutation=True)
        first_request, _ = self._request(action="activate", request_id="device-page-first")
        activated = activate_license(request=first_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        second_request, _ = self._request(action="activate", request_id="device-page-second", installation_id="install-b")
        activate_license(request=second_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        bindings = list(
            DeviceBinding.objects.filter(authorization_id=authorization_id, state=DeviceBindingState.ACTIVE)
            .select_related("device")
            .order_by("binding_id")
        )
        self.assertEqual(len(bindings), 2)

        admin_client = Client()
        admin_client.force_login(self.admin)
        url = reverse("licensing:api_manage_authorizations")
        first_page = admin_client.get(url, {"page_size": 1, "page": 1})
        second_page = admin_client.get(url, {"page_size": 1, "page": 2})
        self.assertEqual(first_page.status_code, 200)
        self.assertEqual(second_page.status_code, 200)
        # One authorization renders one row: total counts authorizations and both
        # devices stay on the same page instead of splitting across pages.
        self.assertEqual(first_page.json()["pagination"]["total"], 1)
        self.assertEqual(first_page.json()["pagination"]["total_pages"], 1)
        self.assertEqual(len(first_page.json()["items"]), 1)
        self.assertEqual(len(first_page.json()["items"][0]["devices"]), 2)
        self.assertEqual(
            {entry["device_id"] for entry in first_page.json()["items"][0]["devices"]},
            {str(binding.device.public_id) for binding in bindings},
        )
        self.assertEqual(second_page.json()["pagination"]["page"], 1)
        self.assertEqual(
            [entry["authorization_id"] for entry in second_page.json()["items"]],
            [entry["authorization_id"] for entry in first_page.json()["items"]],
        )

        reset_device_binding(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=bindings[0].device.public_id,
            reason="分页筛选设备重置",
        )
        bound_only = admin_client.get(url, {"device_state": "bound", "page_size": 10})
        unbound_only = admin_client.get(url, {"device_state": "unbound", "page_size": 10})
        self.assertEqual(bound_only.status_code, 200)
        self.assertEqual(unbound_only.status_code, 200)
        self.assertEqual(bound_only.json()["pagination"]["total"], 1)
        self.assertEqual(unbound_only.json()["pagination"]["total"], 1)
        self.assertEqual(bound_only.json()["items"][0]["devices"][0]["binding_state"], DeviceBindingState.ACTIVE)
        self.assertEqual(unbound_only.json()["items"][0]["devices"][0]["binding_state"], DeviceBindingState.UNBOUND)

    def test_management_authorizations_keeps_frozen_card_out_of_unbound_filter(self):
        activate_request, _ = self._request(action="activate", request_id="activate-filter-block")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="异常设备行为",
            now=self.now + timedelta(seconds=1),
            request_id="admin-device-block-filter",
        )
        admin_client = Client()
        admin_client.force_login(self.admin)
        url = reverse("licensing:api_manage_authorizations")
        unbound = admin_client.get(url, {"device_state": "unbound", "page_size": 10})
        blocked_binding = admin_client.get(url, {"device_state": "blocked", "page_size": 10})
        risk_blocked = admin_client.get(url, {"risk_state": "blocked", "page_size": 10})
        status_blocked = admin_client.get(url, {"status": "blocked", "page_size": 10})
        self.assertEqual(unbound.status_code, 200)
        self.assertEqual(unbound.json()["pagination"]["total"], 0)
        self.assertEqual(blocked_binding.status_code, 200)
        self.assertEqual(blocked_binding.json()["pagination"]["total"], 0)
        self.assertEqual(risk_blocked.status_code, 200)
        self.assertEqual(risk_blocked.json()["pagination"]["total"], 0)
        self.assertEqual(status_blocked.status_code, 200)
        self.assertEqual(status_blocked.json()["pagination"]["total"], 1)
        self.assertEqual(status_blocked.json()["items"][0]["status"], AuthorizationState.BLOCKED)
        self.assertTrue(status_blocked.json()["items"][0]["card_frozen"])
        self.assertEqual(
            status_blocked.json()["items"][0]["devices"][0]["binding_state"],
            DeviceBindingState.ACTIVE,
        )
        self.assertEqual(
            status_blocked.json()["items"][0]["devices"][0]["risk_state"],
            DeviceRiskState.NORMAL,
        )

    def test_management_authorizations_separates_instance_block_from_device_risk(self):
        activate_request, private_key = self._request(action="activate", request_id="activate-filter-rollback")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        verify_request, _ = self._request(
            action="verify",
            request_id="verify-filter-rollback",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        verify_license(request=verify_request, clock=FixedClock(self.now - timedelta(seconds=30)))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        self.assertEqual(instance.state, AuthorizationState.BLOCKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        self.assertEqual(Device.objects.get().risk_state, DeviceRiskState.NORMAL)

        admin_client = Client()
        admin_client.force_login(self.admin)
        url = reverse("licensing:api_manage_authorizations")
        status_blocked = admin_client.get(url, {"status": "blocked", "page_size": 10})
        unbound = admin_client.get(url, {"device_state": "unbound", "page_size": 10})
        risk_blocked = admin_client.get(url, {"risk_state": "blocked", "page_size": 10})
        binding_blocked = admin_client.get(url, {"device_state": "blocked", "page_size": 10})
        self.assertEqual(status_blocked.status_code, 200)
        self.assertEqual(status_blocked.json()["pagination"]["total"], 1)
        self.assertEqual(status_blocked.json()["items"][0]["status"], AuthorizationState.BLOCKED)
        self.assertEqual(unbound.json()["pagination"]["total"], 0)
        self.assertEqual(risk_blocked.json()["pagination"]["total"], 0)
        self.assertEqual(binding_blocked.json()["pagination"]["total"], 1)
        self.assertEqual(
            binding_blocked.json()["items"][0]["devices"][0]["binding_state"],
            DeviceBindingState.BLOCKED,
        )

    def test_management_api_reset_audit_counts_remaining_active_bindings(self):
        self.policy.max_devices = 2
        self.policy.save(update_fields=("max_devices",), _allow_mutation=True)
        first_request, _ = self._request(action="activate", request_id="reset-audit-two-active-first")
        activated = activate_license(request=first_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        second_request, _ = self._request(
            action="activate",
            request_id="reset-audit-two-active-second",
            installation_id="install-b",
        )
        activate_license(request=second_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        bindings = list(
            DeviceBinding.objects.filter(authorization_id=authorization_id, state=DeviceBindingState.ACTIVE)
            .select_related("device")
            .order_by("binding_id")
        )
        self.assertEqual(len(bindings), 2)
        target_device = bindings[0].device

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        listed = admin_client.get(reverse("licensing:api_manage_authorizations")).json()["items"]
        target_suffix = str(target_device.public_id)[-4:]
        action_ref = next(
            device_item["device_action_ref"]
            for item in listed
            if item["authorization_id"] == str(authorization_id)
            for device_item in item["devices"]
            if device_item["device_id"].endswith(target_suffix)
        )
        response = admin_client.post(
            reverse(
                "licensing:api_manage_authorization_device_reset",
                kwargs={"authorization_id": authorization_id, "device_id": action_ref},
            ),
            data=json.dumps({"reason": "审计剩余绑定数量"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="reset-audit-two-active-key",
            HTTP_X_REQUEST_ID="reset-audit-two-active-request",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(response.status_code, 200)
        reset_audit = AuditEvent.objects.filter(
            action="device.reset",
            outcome=AuditOutcome.SUCCESS,
        ).order_by("-occurred_at").first()
        self.assertIsNotNone(reset_audit)
        self.assertEqual(reset_audit.metadata["binding_active_before"], 2)
        self.assertEqual(reset_audit.metadata["binding_active_after"], 1)
        self.assertEqual(
            DeviceBinding.objects.get(authorization_id=authorization_id, device=target_device).state,
            DeviceBindingState.UNBOUND,
        )
        self.assertEqual(
            DeviceBinding.objects.filter(authorization_id=authorization_id, state=DeviceBindingState.ACTIVE).count(),
            1,
        )

    def test_public_verify_reports_revoked_authorization_over_http(self):
        activate_request, private_key = self._request(action="activate", request_id="http-revoke-activate")
        activated = activate_license(request=activate_request)
        authorization_id = activated.payload["authorization_id"]
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        revoked = admin_client.post(
            reverse("licensing:api_manage_authorization_revoke", kwargs={"authorization_id": authorization_id}),
            data=json.dumps({"reason": "HTTP 撤销传播验收"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="http-revoke-admin-key",
            HTTP_X_REQUEST_ID="http-revoke-admin",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(revoked.json()["item"]["status"], AuthorizationState.REVOKED)

        verify_request, _ = self._request(
            action="verify",
            request_id="http-revoke-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        response = self._post_public_action("verify", verify_request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["Pragma"], "no-cache")
        payload = response.json()
        self.assertEqual(payload["decision"], "revoked")
        self.assertEqual(payload["state_code"], "revoked")
        self.assertEqual(payload["error"]["code"], "LICENSE_REVOKED")
        self.assertEqual(payload["error"]["request_id"], "http-revoke-verify")
        self.assertFalse(payload["error"]["retryable"])
        self.assertEqual(payload["device_scope"]["installation_id"], "install-a")

    def test_public_verify_reports_blocked_device_over_http(self):
        activate_request, private_key = self._request(action="activate", request_id="http-block-activate")
        activated = activate_license(request=activate_request)
        authorization_id = activated.payload["authorization_id"]
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        action_ref = admin_client.get(reverse("licensing:api_manage_authorizations")).json()["items"][0]["devices"][0]["device_action_ref"]
        blocked = admin_client.post(
            reverse(
                "licensing:api_manage_authorization_device_block",
                kwargs={"authorization_id": authorization_id, "device_id": action_ref},
            ),
            data=json.dumps({"reason": "HTTP 阻断传播验收"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="http-block-admin-key",
            HTTP_X_REQUEST_ID="http-block-admin",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(blocked.status_code, 200)
        self.assertTrue(blocked.json()["item"]["card_frozen"])
        self.assertEqual(blocked.json()["device"]["risk_state"], DeviceRiskState.NORMAL)

        verify_request, _ = self._request(
            action="verify",
            request_id="http-block-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        response = self._post_public_action("verify", verify_request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["Pragma"], "no-cache")
        payload = response.json()
        self.assertEqual(payload["error"]["code"], "LICENSE_BLOCKED")
        self.assertEqual(payload["decision"], "blocked")
        self.assertEqual(payload["error"]["request_id"], "http-block-verify")
        self.assertFalse(payload["error"]["retryable"])
        self.assertIn("integrity", payload)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)

    def test_public_verify_reports_unbound_after_admin_reset_over_http(self):
        activate_request, private_key = self._request(action="activate", request_id="http-reset-activate")
        activated = activate_license(request=activate_request)
        authorization_id = activated.payload["authorization_id"]
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        admin_client.get(reverse("accounts:api_session"))
        csrf_cookie = admin_client.cookies.get("csrftoken")
        self.assertIsNotNone(csrf_cookie)
        action_ref = admin_client.get(reverse("licensing:api_manage_authorizations")).json()["items"][0]["devices"][0]["device_action_ref"]
        reset = admin_client.post(
            reverse(
                "licensing:api_manage_authorization_device_reset",
                kwargs={"authorization_id": authorization_id, "device_id": action_ref},
            ),
            data=json.dumps({"reason": "HTTP 重置后验证必须失败"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="http-reset-admin-key",
            HTTP_X_REQUEST_ID="http-reset-admin",
            HTTP_X_CSRFTOKEN=csrf_cookie.value,
        )
        self.assertEqual(reset.status_code, 200)
        self.assertFalse(reset.json()["repeated"])

        verify_request, _ = self._request(
            action="verify",
            request_id="http-reset-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        response = self._post_public_action("verify", verify_request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response["Pragma"], "no-cache")
        payload = response.json()
        self.assertEqual(payload["error"]["code"], "DEVICE_NOT_BOUND")
        self.assertEqual(payload["error"]["request_id"], "http-reset-verify")
        self.assertFalse(payload["error"]["retryable"])
        self.assertNotIn("decision", payload)
        self.assertNotIn("integrity", payload)

    def test_tampering_and_unknown_key_fail_closed(self):
        request, _ = self._request(action="activate", request_id="signature-check")
        result = activate_license(request=request, clock=FixedClock(self.now))
        trusted = {settings.AUTHORIZATION_SIGNING_KEY_ID: authorization_signing_public_key()}
        tampered = dict(result.payload)
        tampered["server_time"] += 1
        with self.assertRaises(AuthorizationOperationError) as invalid:
            verify_authorization_response(tampered, trusted)
        self.assertEqual(invalid.exception.code, "SIGNATURE_INVALID")

        unknown = dict(result.payload)
        unknown["integrity"] = dict(result.payload["integrity"])
        unknown["integrity"]["key_id"] = "unknown-key"
        with self.assertRaises(AuthorizationOperationError) as missing:
            verify_authorization_response(unknown, trusted)
        self.assertEqual(missing.exception.code, "KEY_UNKNOWN")

    def test_admin_can_export_current_public_signing_key_without_secret_material(self):
        url = reverse("licensing:api_authorization_signing_key")
        self.assertEqual(Client().get(url).status_code, 401)

        downstream_client = Client()
        downstream_client.force_login(self.downstream.user)
        session = downstream_client.session
        session["downstream_session_version"] = self.downstream.session_version
        session.save()
        self.assertEqual(downstream_client.get(url).status_code, 403)

        admin_client = Client()
        admin_client.force_login(self.admin)
        response = admin_client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        payload = response.json()
        self.assertEqual(payload["key_id"], settings.AUTHORIZATION_SIGNING_KEY_ID)
        self.assertEqual(payload["public_key"], authorization_signing_public_key())
        self.assertEqual(payload["algorithm"], "ed25519")
        self.assertEqual(payload["encoding"], "base64url-no-padding")
        self.assertEqual(payload["canonicalization"], "JCS-RFC8785")
        self.assertNotIn("private_key", payload)
        self.assertNotIn("signature", payload)
        audit = AuditEvent.objects.get(action="authorization.signing_key.export")
        self.assertEqual(audit.object_public_id, settings.AUTHORIZATION_SIGNING_KEY_ID)
        self.assertNotIn("public_key", audit.metadata)

    def test_public_activate_verify_deactivate_return_verifiable_signed_envelopes(self):
        activate_request, private_key = self._request(action="activate", request_id="http-real-activate")
        activated = self._post_public_action("activate", activate_request)
        self.assertEqual(activated.status_code, 200)
        trusted = {settings.AUTHORIZATION_SIGNING_KEY_ID: authorization_signing_public_key()}
        activated_payload = activated.json()
        verify_authorization_response(activated_payload, trusted)

        verify_request, _ = self._request(
            action="verify",
            request_id="http-real-verify",
            private_key=private_key,
            authorization_id=activated_payload["authorization_id"],
        )
        verified = self._post_public_action("verify", verify_request)
        self.assertEqual(verified.status_code, 200)
        verify_authorization_response(verified.json(), trusted)

        deactivate_request, _ = self._request(
            action="deactivate",
            request_id="http-real-deactivate",
            private_key=private_key,
            authorization_id=activated_payload["authorization_id"],
        )
        deactivated = self._post_public_action("deactivate", deactivate_request)
        self.assertEqual(deactivated.status_code, 200)
        self.assertEqual(deactivated.json()["state_code"], "unbound")
        self.assertEqual(deactivated.json()["decision"], "unbound")
        self.assertNotEqual(deactivated.json()["decision"], "active")
        verify_authorization_response(deactivated.json(), trusted)

    @override_settings(APP_ENV="production", AUTHORIZATION_SIGNING_PRIVATE_KEY="")
    def test_production_never_uses_local_signing_fallback(self):
        with self.assertRaises(AuthorizationOperationError) as error:
            activate_license(request=self._request(action="activate", request_id="production-key-check")[0], clock=FixedClock(self.now))
        self.assertEqual(error.exception.code, "SIGNING_KEY_UNAVAILABLE")


    def test_client_device_code_is_persisted_and_legacy_verify_backfills_it(self):
        installation_id = "GS-65FB-F502-B439-270C"
        activate_request, private_key = self._request(
            action="activate",
            request_id="device-code-persist",
            installation_id=installation_id,
        )
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        device = Device.objects.get()
        self.assertEqual(device.installation_id, installation_id)
        self.assertEqual(device.device_code, installation_id)

        # Simulate a pre-migration row, then let a trusted verify request fill it.
        device.installation_id = None
        device.save(update_fields=("installation_id",), _allow_mutation=True)
        verify_request, _ = self._request(
            action="verify",
            request_id="device-code-backfill",
            installation_id=installation_id,
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        device.refresh_from_db()
        self.assertEqual(device.installation_id, installation_id)
        self.assertEqual(device.device_code, installation_id)

    def test_long_hardware_fingerprint_gets_compact_display_code_without_changing_identity(self):
        installation_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        activate_request, _ = self._request(
            action="activate",
            request_id="device-code-long-fingerprint",
            installation_id=installation_id,
        )
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        device = Device.objects.get()
        expected = compact_device_code(installation_id)
        self.assertEqual(device.installation_id, installation_id)
        self.assertEqual(device.device_code, expected)
        self.assertEqual(activated.payload["device_scope"]["installation_id"], installation_id)

        admin = Client()
        admin.force_login(self.admin)
        listed = admin.get(reverse("licensing:api_manage_authorizations"), {"q": expected})
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["pagination"]["total"], 1)
        self.assertEqual(listed.json()["items"][0]["device_code"], expected)


    def test_downstream_device_list_and_reset_are_scoped_and_idempotent(self):
        activate_request, _ = self._request(action="activate", request_id="downstream-device-list")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        device.last_ip = "198.51.100.10"
        device.save(update_fields=("last_ip",), _allow_mutation=True)

        client = Client(enforce_csrf_checks=True)
        session = client.get(reverse("accounts:api_session"))
        self.assertEqual(session.status_code, 200)
        csrf = client.cookies["csrftoken"].value
        login = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": "authorization-downstream",
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(login.status_code, 200)
        csrf = client.cookies["csrftoken"].value

        listed = client.get(reverse("licensing:api_downstream_devices"))
        self.assertEqual(listed.status_code, 200)
        payload = listed.json()
        self.assertEqual(payload["pagination"]["total"], 1)
        item = payload["items"][0]
        self.assertEqual(item["authorization_id"], str(authorization_id))
        self.assertEqual(item["device_id"], str(device.public_id))
        self.assertEqual(item["device_code"], "install-a")
        self.assertEqual(item["installation_id"], "install-a")
        self.assertEqual(item["device_uuid"], str(device.public_id))
        self.assertEqual(item["device_ip"], "198.51.100.10")
        self.assertNotEqual(item["device_action_ref"], str(device.public_id))
        padded = item["device_action_ref"] + "=" * ((4 - len(item["device_action_ref"]) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        self.assertNotIn(str(device.public_id).encode("ascii"), decoded)
        self.assertNotIn(b"device_id", decoded)
        by_device = client.get(reverse("licensing:api_downstream_devices"), {"q": str(device.public_id)})
        self.assertEqual(by_device.status_code, 200)
        self.assertEqual(by_device.json()["pagination"]["total"], 1)
        by_plain = client.get(reverse("licensing:api_downstream_devices"), {"q": item["device_id"]})
        self.assertEqual(by_plain.status_code, 200)
        self.assertEqual(by_plain.json()["pagination"]["total"], 1)
        by_client_code = client.get(reverse("licensing:api_downstream_devices"), {"q": "install-a"})
        self.assertEqual(by_client_code.status_code, 200)
        self.assertEqual(by_client_code.json()["pagination"]["total"], 1)
        by_card = client.get(reverse("licensing:api_downstream_devices"), {"q": self.license_key})
        self.assertEqual(by_card.status_code, 200)
        self.assertEqual(by_card.json()["pagination"]["total"], 1)

        reset_url = reverse(
            "licensing:api_downstream_device_reset",
            kwargs={"authorization_id": authorization_id, "device_id": item["device_action_ref"]},
        )
        first = client.post(
            reset_url,
            data=json.dumps({"reason": "客户申请换机"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_IDEMPOTENCY_KEY="downstream-device-reset-1",
        )
        replay = client.post(
            reset_url,
            data=json.dumps({"reason": "客户申请换机"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_IDEMPOTENCY_KEY="downstream-device-reset-1",
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(first.json(), replay.json())
        self.assertEqual(first.json()["device"]["binding_state"], DeviceBindingState.UNBOUND)
        self.assertEqual(first.json()["device"]["binding_state_label"], "已解绑")
        self.assertEqual(DeviceBinding.objects.get(authorization_id=authorization_id, device=device).state, DeviceBindingState.UNBOUND)

        other = create_downstream_direct(
            actor=self.admin,
            username="authorization-other-downstream",
            password="Downstream-password-123",
        )
        other_client = Client(enforce_csrf_checks=True)
        other_client.force_login(other.user)
        denied = other_client.post(
            reset_url,
            data=json.dumps({"reason": "越权重置"}),
            content_type="application/json",
            HTTP_X_IDEMPOTENCY_KEY="downstream-device-reset-forbidden",
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["error"]["code"], "CSRF_FAILED")
        other_client.get(reverse("accounts:api_session"))
        other_csrf = other_client.cookies["csrftoken"].value
        other_login = other_client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": "authorization-other-downstream",
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=other_csrf,
        )
        self.assertEqual(other_login.status_code, 200)
        other_csrf = other_client.cookies["csrftoken"].value
        denied = other_client.post(
            reset_url,
            data=json.dumps({"reason": "越权重置"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=other_csrf,
            HTTP_IDEMPOTENCY_KEY="downstream-device-reset-forbidden-2",
        )
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(denied.json()["error"]["code"], "DEVICE_ACTION_REF_INVALID")
        self.assertTrue(
            AuditEvent.objects.filter(
                action="device.reset",
                outcome=AuditOutcome.FAILURE,
                reason_code="DEVICE_ACTION_REF_INVALID",
            ).exists()
        )
        admin_list = self.client.get(reverse("licensing:api_downstream_devices"))
        self.assertEqual(admin_list.status_code, 401)

    def test_downstream_reset_after_block_reports_blocked_not_unbound(self):
        activate_request, private_key = self._request(action="activate", request_id="downstream-reset-after-block")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="异常设备行为",
            now=self.now + timedelta(seconds=1),
            request_id="admin-device-block-before-downstream-reset",
        )
        binding = DeviceBinding.objects.get(authorization_id=authorization_id, device=device)
        self.assertEqual(binding.state, DeviceBindingState.ACTIVE)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.BLOCKED)

        client = Client(enforce_csrf_checks=True)
        session = client.get(reverse("accounts:api_session"))
        self.assertEqual(session.status_code, 200)
        csrf = client.cookies["csrftoken"].value
        login = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": "authorization-downstream",
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        self.assertEqual(login.status_code, 200)
        csrf = client.cookies["csrftoken"].value

        listed = client.get(reverse("licensing:api_downstream_devices"))
        self.assertEqual(listed.status_code, 200)
        item = listed.json()["items"][0]
        self.assertEqual(item["binding_state"], DeviceBindingState.ACTIVE)
        self.assertEqual(item["status"], AuthorizationState.BLOCKED)
        self.assertFalse(item["reset_allowed"])
        self.assertTrue(item["device_action_ref"])

        reset = client.post(
            reverse(
                "licensing:api_downstream_device_reset",
                kwargs={"authorization_id": authorization_id, "device_id": item["device_action_ref"]},
            ),
            data=json.dumps({"reason": "客户申请换机"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
            HTTP_IDEMPOTENCY_KEY="downstream-device-reset-blocked",
        )
        self.assertEqual(reset.status_code, 409, reset.content)
        self.assertEqual(reset.json()["error"]["code"], "CARD_FROZEN")
        binding.refresh_from_db()
        self.assertEqual(binding.state, DeviceBindingState.ACTIVE)
        self.assertEqual(Device.objects.get(pk=device.public_id).risk_state, DeviceRiskState.NORMAL)

        blocked_activate, _ = self._request(
            action="activate",
            request_id="activate-after-blocked-downstream-reset",
            private_key=private_key,
            installation_id="install-a",
        )
        refused = activate_license(request=blocked_activate, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(refused.payload["error"]["code"], "LICENSE_BLOCKED")
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_downstream_scope_mismatch_is_recorded_as_a_failed_device_action(self):
        activate_request, _ = self._request(action="activate", request_id="downstream-device-scope-audit")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        device = Device.objects.get()
        with self.assertRaises(AuthorizationOperationError) as error:
            reset_device_binding(
                actor=self.downstream.user,
                authorization_id=activated.payload["authorization_id"],
                device_id=device.public_id,
                reason="越权设备重置",
                request_id="downstream-device-scope-audit-request",
                scope_downstream_public_id=uuid.uuid4(),
            )
        self.assertEqual(error.exception.code, "FORBIDDEN")

    def test_verify_interval_hot_reads_current_policy_for_sold_cards(self):
        revise_policy_version(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            max_devices=1,
            allow_device_switch=False,
            device_switch_limit=0,
            device_proof_required=True,
            verify_interval_seconds=21600,
            offline_grace_seconds=0,
            request_id="revise-sold-interval-long",
        )
        _plan, snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=PolicyVersion.objects.filter(profile=self.profile, status=PolicyStatus.ACTIVE)
            .order_by("-effective_at", "-created_at")
            .first()
            .version,
            name="已售长间隔月卡",
            duration_seconds=2592000,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="sold-interval-issue",
        )
        card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        license_key = decrypt_license_card(card.card_ciphertext)
        first, private_key = self._request(
            action="activate",
            request_id="sold-interval-activate",
            license_key=license_key,
        )
        activated = activate_license(request=first, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        snapshot_policy_id = instance.policy_version_id
        self.assertEqual(instance.policy_version.verify_interval_seconds, 21600)
        self.assertEqual(activated.payload["next_verify_at"] - activated.payload["server_time"], 21600)
        revised = revise_policy_version(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            max_devices=1,
            allow_device_switch=False,
            device_switch_limit=0,
            device_proof_required=True,
            verify_interval_seconds=60,
            offline_grace_seconds=0,
            request_id="revise-sold-interval-sixty",
        )
        self.assertEqual(revised.verify_interval_seconds, 60)
        instance.refresh_from_db()
        self.assertEqual(instance.policy_version_id, snapshot_policy_id)
        self.assertEqual(instance.policy_version.verify_interval_seconds, 21600)
        later = self.now + timedelta(seconds=1)
        verify_request, _ = self._request(
            action="verify",
            request_id="sold-interval-verify",
            authorization_id=activated.payload["authorization_id"],
            private_key=private_key,
        )
        verified = verify_license(request=verify_request, clock=FixedClock(later))
        self.assertEqual(verified.payload["decision"], "active")
        self.assertEqual(verified.payload["next_verify_at"] - verified.payload["server_time"], 60)
        self.assertEqual(verified.payload["cache_until"] - verified.payload["server_time"], 60)
        self.assertEqual(verified.payload["expires_at"], int((self.now + timedelta(seconds=2592000)).timestamp()))

    def test_activate_switch_hot_reads_current_policy_without_replacing_instance_policy(self):
        first, _ = self._request(action="activate", request_id="switch-hot-a", installation_id="install-a")
        activated = activate_license(request=first, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        snapshot_policy_id = instance.policy_version_id
        self.assertFalse(instance.policy_version.allow_device_switch)
        revised = self._revise_daily_switch()
        self.assertTrue(revised.allow_device_switch)
        self.assertEqual(revised.device_switch_limit, 5)
        second, _ = self._request(action="activate", request_id="switch-hot-b", installation_id="install-b")
        switched = activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(switched.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.policy_version_id, snapshot_policy_id)
        self.assertEqual(instance.device_switch_count, 1)
        self.assertEqual(instance.device_switch_day, to_beijing(self.now + timedelta(seconds=1)).date())
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.UNBOUND).count(), 1)
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_kick_records_who_kicked_whom_into_the_audit_trail(self):
        """客户说「我被踢了」时，平台侧必须查得出是谁、什么时候、用哪台机顶的。

        以前挤机只改绑定状态、不写任何审计：唯一痕迹是被踢设备下次 verify 报出的
        DEVICE_NOT_BOUND，看不出起因。管理员只能靠猜，或者去问客户。
        """
        from authorization_platform.audit.queries import _audit_query_action_codes

        # 默认策略不允许换机；先开成「满员允许挤机、每日 5 次」。
        self._revise_daily_switch(request_id="kick-audit-policy")
        first, _ = self._request(action="activate", request_id="kick-audit-a", installation_id="install-a")
        activate_license(request=first, clock=FixedClock(self.now))
        second, _ = self._request(action="activate", request_id="kick-audit-b", installation_id="install-b")
        activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))

        kicked_binding = DeviceBinding.objects.get(state=DeviceBindingState.UNBOUND)
        events = list(
            AuditEvent.objects.filter(
                action="device.kicked",
                object_public_id=kicked_binding.binding_id,
            )
        )
        self.assertEqual(len(events), 1)
        metadata = events[0].metadata
        self.assertEqual(metadata["kicked_installation_id"], "install-a")
        self.assertEqual(metadata["incoming_installation_id"], "install-b")
        self.assertEqual(metadata["reason"], "设备切换")
        self.assertEqual(metadata["max_devices"], 1)
        self.assertTrue(metadata["kicked_device_id"])
        self.assertTrue(metadata["incoming_device_id"])
        self.assertNotEqual(metadata["kicked_device_id"], metadata["incoming_device_id"])
        # 必须能被管理端的自由文本搜索按中文标签找到，否则写了也等于没写。
        self.assertIn("device.kicked", _audit_query_action_codes("挤掉旧设备"))

    def test_daily_switch_exhaustion_uses_switch_error_not_device_limit(self):
        self._revise_daily_switch(request_id="revise-daily-exhaust")
        first, _ = self._request(action="activate", request_id="daily-switch-a", installation_id="install-a")
        activate_license(request=first, clock=FixedClock(self.now))
        for index in range(1, 6):
            kicked, _ = self._request(
                action="activate",
                request_id=f"daily-switch-kick-{index}",
                installation_id=f"install-kick-{index}",
            )
            result = activate_license(request=kicked, clock=FixedClock(self.now + timedelta(seconds=index)))
            self.assertEqual(result.payload["decision"], "active")
        instance = LicenseInstance.objects.get()
        self.assertEqual(instance.device_switch_count, 5)
        sixth, _ = self._request(action="activate", request_id="daily-switch-sixth", installation_id="install-kick-6")
        with self.assertRaises(AuthorizationOperationError) as raised:
            activate_license(request=sixth, clock=FixedClock(self.now + timedelta(seconds=6)))
        self.assertEqual(raised.exception.code, "DEVICE_SWITCH_LIMIT_REACHED")
        self.assertNotEqual(raised.exception.code, "DEVICE_LIMIT_REACHED")
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_full_devices_without_current_switch_still_device_limit(self):
        first, _ = self._request(action="activate", request_id="limit-no-switch-a", installation_id="install-a")
        activate_license(request=first, clock=FixedClock(self.now))
        second, _ = self._request(action="activate", request_id="limit-no-switch-b", installation_id="install-b")
        with self.assertRaises(AuthorizationOperationError) as raised:
            activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(raised.exception.code, "DEVICE_LIMIT_REACHED")
        self.assertIn("当前不允许新电脑挤掉旧电脑", raised.exception.message)
        self.assertNotIn("已达到当前授权的设备上限", raised.exception.message)

    def test_beijing_day_boundary_resets_daily_switch_count(self):
        before_midnight = datetime(2026, 8, 19, 15, 59, 30, tzinfo=UTC)
        next_day = datetime(2026, 8, 19, 16, 0, 10, tzinfo=UTC)
        self.assertEqual(before_midnight.date(), next_day.date())
        self.assertNotEqual(to_beijing(before_midnight).date(), to_beijing(next_day).date())
        self._revise_daily_switch(request_id="revise-daily-boundary")
        first, _ = self._request(action="activate", request_id="boundary-a", installation_id="install-a")
        activate_license(request=first, clock=FixedClock(before_midnight))
        for index in range(1, 6):
            kicked, _ = self._request(
                action="activate",
                request_id=f"boundary-kick-{index}",
                installation_id=f"install-boundary-{index}",
            )
            activate_license(request=kicked, clock=FixedClock(before_midnight + timedelta(seconds=index)))
        sixth, _ = self._request(action="activate", request_id="boundary-sixth", installation_id="install-boundary-6")
        with self.assertRaises(AuthorizationOperationError) as raised:
            activate_license(request=sixth, clock=FixedClock(before_midnight + timedelta(seconds=6)))
        self.assertEqual(raised.exception.code, "DEVICE_SWITCH_LIMIT_REACHED")
        seventh, _ = self._request(action="activate", request_id="boundary-next-day", installation_id="install-boundary-7")
        switched = activate_license(request=seventh, clock=FixedClock(next_day))
        self.assertEqual(switched.payload["decision"], "active")
        instance = LicenseInstance.objects.get()
        self.assertEqual(instance.device_switch_count, 1)
        self.assertEqual(instance.device_switch_day, to_beijing(next_day).date())

    def test_empty_switch_day_does_not_treat_old_lifetime_count_as_exhausted(self):
        self._revise_daily_switch(request_id="revise-daily-legacy-count")
        first, _ = self._request(action="activate", request_id="legacy-count-a", installation_id="install-a")
        activated = activate_license(request=first, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        instance.device_switch_count = 9
        instance.device_switch_day = None
        instance.save(update_fields=("device_switch_count", "device_switch_day", "updated_at"), _allow_mutation=True)
        second, _ = self._request(action="activate", request_id="legacy-count-b", installation_id="install-b")
        switched = activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(switched.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 1)
        self.assertEqual(instance.device_switch_day, to_beijing(self.now + timedelta(seconds=1)).date())

    def test_reset_and_deactivate_do_not_consume_daily_switch(self):
        self._revise_daily_switch(request_id="revise-daily-reset")
        first, _ = self._request(action="activate", request_id="reset-switch-a", installation_id="install-a")
        activated = activate_license(request=first, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        second, key_b = self._request(action="activate", request_id="reset-switch-b", installation_id="install-b")
        activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=1)))
        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.device_switch_count, 1)

        # 1. 管理员重置设备：reset 动作本身不消耗换机次数
        active = DeviceBinding.objects.get(authorization=instance, state=DeviceBindingState.ACTIVE)
        reset_device_binding(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=active.device_id,
            reason="管理员重置设备",
            now=self.now + timedelta(seconds=2),
            request_id="admin-reset-daily-switch",
        )
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 1)

        # 2. 原设备 install-b 在解绑后重新登录（原机恢复）：零消耗
        second_relogin, _ = self._request(
            action="activate",
            request_id="reset-switch-b-relogin",
            installation_id="install-b",
            private_key=key_b,
        )
        relogin_res = activate_license(request=second_relogin, clock=FixedClock(self.now + timedelta(seconds=3)))
        self.assertEqual(relogin_res.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 1)

        # 3. 换全新设备 install-c 介入：严格校验并消耗当日换机额度（计数 1 -> 2）
        third, key_c = self._request(action="activate", request_id="reset-switch-c", installation_id="install-c")
        emptied = activate_license(request=third, clock=FixedClock(self.now + timedelta(seconds=4)))
        self.assertEqual(emptied.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 2)

        # 4. 主动调用 deactivate 解绑：deactivate 动作本身不消耗换机次数
        deactivate_request, _ = self._request(
            action="deactivate",
            request_id="reset-switch-deactivate",
            private_key=key_c,
            authorization_id=authorization_id,
            installation_id="install-c",
        )
        deactivate_license(request=deactivate_request, clock=FixedClock(self.now + timedelta(seconds=5)))
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 2)

        # 5. 原设备 install-c 重新登录（原机恢复）：零消耗
        third_relogin, _ = self._request(
            action="activate",
            request_id="reset-switch-c-relogin",
            installation_id="install-c",
            private_key=key_c,
        )
        relogin_c_res = activate_license(request=third_relogin, clock=FixedClock(self.now + timedelta(seconds=6)))
        self.assertEqual(relogin_c_res.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 2)

        # 6. 换全新设备 install-d 介入：再次严格消耗当日换机额度（计数 2 -> 3）
        fourth, key_d = self._request(action="activate", request_id="reset-switch-d", installation_id="install-d")
        rebound = activate_license(request=fourth, clock=FixedClock(self.now + timedelta(seconds=7)))
        self.assertEqual(rebound.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 3)

        # 7. 对抗测试：历史设备 install-d 在解绑后，历史旧设备 install-b 重新介入激活：
        # 虽然 install-b 在历史记录中，但发生了物理设备切换（从 d 切换到 b），必须严格计入换机次数（计数 3 -> 4）
        deactivate_d, _ = self._request(
            action="deactivate",
            request_id="reset-switch-deactivate-d",
            authorization_id=authorization_id,
            installation_id="install-d",
            private_key=key_d,
        )
        deactivate_license(request=deactivate_d, clock=FixedClock(self.now + timedelta(seconds=8)))
        second_alternate, _ = self._request(
            action="activate",
            request_id="reset-switch-b-alternate",
            installation_id="install-b",
            private_key=key_b,
        )
        alt_res = activate_license(request=second_alternate, clock=FixedClock(self.now + timedelta(seconds=9)))
        self.assertEqual(alt_res.payload["decision"], "active")
        instance.refresh_from_db()
        self.assertEqual(instance.device_switch_count, 4)

    def test_verify_does_not_unbind_to_free_device_slot(self):
        activate_request, private_key = self._request(action="activate", request_id="verify-no-kick-a")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        verify_request, _ = self._request(
            action="verify",
            request_id="verify-no-kick",
            private_key=private_key,
            authorization_id=activated.payload["authorization_id"],
        )
        verified = verify_license(request=verify_request, clock=FixedClock(self.now + timedelta(seconds=1)))
        self.assertEqual(verified.payload["decision"], "active")
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)
        second, _ = self._request(action="activate", request_id="verify-no-kick-b", installation_id="install-b")
        with self.assertRaises(AuthorizationOperationError) as raised:
            activate_license(request=second, clock=FixedClock(self.now + timedelta(seconds=2)))
        self.assertEqual(raised.exception.code, "DEVICE_LIMIT_REACHED")
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_backfill_closed_switch_does_not_rewrite_issued_card_or_instance_policy(self):
        first, _ = self._request(action="activate", request_id="backfill-issued-a")
        activated = activate_license(request=first, clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(pk=activated.payload["authorization_id"])
        card = LicenseCard.objects.get(pk=self.card.pk)
        old_snapshot_id = card.plan_snapshot_id
        old_policy_id = instance.policy_version_id
        old_policy = PolicyVersion.objects.get(pk=old_policy_id)
        self.assertFalse(old_policy.allow_device_switch)
        self.assertEqual(old_policy.device_switch_limit, 0)
        revised = backfill_default_daily_device_switch(actor=self.admin)
        self.assertEqual(len(revised), 1)
        self.assertTrue(revised[0].allow_device_switch)
        self.assertEqual(revised[0].device_switch_limit, 5)
        old_policy.refresh_from_db()
        self.assertEqual(old_policy.status, PolicyStatus.ARCHIVED)
        card.refresh_from_db()
        instance.refresh_from_db()
        self.assertEqual(card.plan_snapshot_id, old_snapshot_id)
        self.assertEqual(instance.policy_version_id, old_policy_id)
        self.assertEqual(instance.plan_snapshot_id, old_snapshot_id)
        latest = self.plan.latest_snapshot
        self.assertNotEqual(latest.snapshot_id, old_snapshot_id)
        self.assertEqual(latest.policy_version_id, revised[0].pk)

    # ------------------------------------------------------------------
    # 卡密续期（ADR-0016）
    # ------------------------------------------------------------------

    def _activate_for_renewal(self, *, request_id="renew-activate", clock=None, license_key=None, installation_id="install-a"):
        request, private_key = self._request(
            action="activate",
            request_id=request_id,
            installation_id=installation_id,
            license_key=license_key,
        )
        result = activate_license(request=request, clock=clock)
        self.assertEqual(result.status_code, 200, result.payload)
        return result.payload["authorization_id"], private_key

    def _issue_extra_card(self, *, key):
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key=key,
        )
        card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        return card, decrypt_license_card(card.card_ciphertext)

    def test_renewal_seconds_translates_units_and_enforces_limits(self):
        self.assertEqual(renewal_seconds("hour", 3), 10800)
        self.assertEqual(renewal_seconds("DAY", 2), 172800)
        self.assertEqual(renewal_seconds("天", 1), 86400)
        for unit, amount, code in (
            ("minute", 1, "INVALID_RENEWAL_UNIT"),
            ("day", 0, "INVALID_RENEWAL_AMOUNT"),
            ("day", 999, "RENEWAL_TOO_LONG"),
        ):
            with self.assertRaises(AuthorizationOperationError) as error:
                renewal_seconds(unit, amount)
            self.assertEqual(error.exception.code, code)
        self.assertLessEqual(MAX_RENEWAL_SECONDS, 366 * 86400)

    def test_renewal_pushes_expiry_bumps_revision_and_writes_no_ledger(self):
        authorization_id, _ = self._activate_for_renewal(clock=FixedClock(self.now))
        instance = LicenseInstance.objects.get(authorization_id=authorization_id)
        before_expires = instance.expires_at
        before_revision = instance.authorization_revision
        before_ledger = QuotaLedgerEntry.objects.count()

        result = extend_authorization(
            actor=self.admin,
            authorization_id=authorization_id,
            added_seconds=86400,
            reason="游戏更新，给客户补一天",
            now=self.now + timedelta(seconds=10),
        )
        self.assertEqual(result.previous_expires_at, before_expires)
        self.assertEqual(result.new_expires_at, before_expires + timedelta(seconds=86400))

        instance.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(instance.expires_at, before_expires + timedelta(seconds=86400))
        self.assertEqual(instance.authorization_revision, before_revision + 1)
        self.assertEqual(self.card.expires_at, instance.expires_at)
        self.assertEqual(self.card.status, LicenseCardStatus.ACTIVATED)
        self.assertEqual(QuotaLedgerEntry.objects.count(), before_ledger)
        audit = AuditEvent.objects.filter(action="authorization.extend", outcome=AuditOutcome.SUCCESS).latest("occurred_at")
        self.assertEqual(audit.metadata["added_seconds"], 86400)
        self.assertTrue(audit.metadata["quota_cost_unchanged"])
        self.assertEqual(audit.metadata["before_revision"], before_revision)

    def test_verify_after_renewal_returns_the_new_expiry(self):
        authorization_id, private_key = self._activate_for_renewal(clock=FixedClock(self.now))
        extend_authorization(
            actor=self.admin,
            authorization_id=authorization_id,
            added_seconds=3600,
            reason="补一小时",
            now=self.now + timedelta(seconds=10),
        )
        request, _ = self._request(
            action="verify",
            request_id="renew-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        result = verify_license(request=request, clock=FixedClock(self.now + timedelta(seconds=20)))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.payload["expires_at"], int((self.now + timedelta(seconds=60 + 3600)).timestamp()))
        self.assertEqual(result.payload["decision"], "active")

    def test_renewal_refuses_expired_revoked_blocked_and_missing(self):
        with self.assertRaises(AuthorizationOperationError) as missing:
            extend_authorization(
                actor=self.admin,
                authorization_id=uuid.uuid4(),
                added_seconds=3600,
                reason="实例不存在不该续期",
            )
        self.assertEqual(missing.exception.code, "AUTHORIZATION_NOT_FOUND")

        authorization_id, _ = self._activate_for_renewal(clock=FixedClock(self.now))
        with self.assertRaises(AuthorizationOperationError) as expired:
            extend_authorization(
                actor=self.admin,
                authorization_id=authorization_id,
                added_seconds=3600,
                reason="过期不该续期",
                now=self.now + timedelta(seconds=61),
            )
        self.assertEqual(expired.exception.code, "AUTHORIZATION_EXPIRED")

        instance = LicenseInstance.objects.get(authorization_id=authorization_id)
        self.card.refresh_from_db()
        self.assertIsNone(renewal_blocker(self.card, instance, self.now + timedelta(seconds=10)))
        self.assertEqual(
            renewal_blocker(self.card, instance, self.now + timedelta(seconds=61)),
            "AUTHORIZATION_EXPIRED",
        )

        device = Device.objects.get()
        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="测试冻卡",
        )
        instance.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(renewal_blocker(self.card, instance, self.now + timedelta(seconds=30)), "AUTHORIZATION_BLOCKED")
        with self.assertRaises(AuthorizationOperationError) as blocked:
            extend_authorization(
                actor=self.admin,
                authorization_id=authorization_id,
                added_seconds=3600,
                reason="冻卡不该续期",
                now=self.now + timedelta(seconds=30),
            )
        self.assertEqual(blocked.exception.code, "AUTHORIZATION_BLOCKED")

        unblock_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="解冻测试",
        )
        revoke_authorization(
            actor=self.admin,
            authorization_id=authorization_id,
            reason="撤销测试",
        )
        instance.refresh_from_db()
        with self.assertRaises(AuthorizationOperationError) as revoked:
            extend_authorization(
                actor=self.admin,
                authorization_id=authorization_id,
                added_seconds=3600,
                reason="撤销不该续期",
                now=self.now + timedelta(seconds=40),
            )
        self.assertEqual(revoked.exception.code, "AUTHORIZATION_REVOKED")

    def test_renewal_refuses_unused_card_without_instance(self):
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="renew-unused-issue",
        )
        card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        self.assertEqual(card.status, LicenseCardStatus.UNUSED)
        with self.assertRaises(AuthorizationOperationError) as error:
            extend_authorization(
                actor=self.admin,
                authorization_id=card.public_id,
                added_seconds=86400,
                reason="未激活卡不该续期",
            )
        self.assertEqual(error.exception.code, "AUTHORIZATION_NOT_FOUND")
        card.refresh_from_db()
        self.assertIsNone(card.expires_at)
        self.assertEqual(card.status, LicenseCardStatus.UNUSED)

    def test_renewal_api_preview_freezes_ids_and_confirm_only_accepts_them(self):
        authorization_id, _ = self._activate_for_renewal(request_id="renew-api-activate")
        client = Client()
        client.force_login(self.admin)

        preview = client.get(
            reverse("licensing:api_manage_authorization_renew_preview"),
            {"status": "active", "unit": "day", "amount": "1"},
        )
        self.assertEqual(preview.status_code, 200, preview.content)
        body = preview.json()
        self.assertEqual(body["renewable_count"], 1)
        self.assertEqual(body["authorization_ids"], [authorization_id])
        self.assertEqual(body["added_seconds"], 86400)
        self.assertEqual(body["items"][0]["new_expires_at"] > body["items"][0]["expires_at"], True)

        empty = client.post(
            reverse("licensing:api_manage_authorization_renew"),
            data=json.dumps({"authorization_ids": [], "unit": "day", "amount": 1, "reason": "空选择"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="renew-api-empty",
        )
        self.assertEqual(empty.status_code, 400)

        no_reason = client.post(
            reverse("licensing:api_manage_authorization_renew"),
            data=json.dumps({"authorization_ids": [authorization_id], "unit": "day", "amount": 1}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="renew-api-no-reason",
        )
        self.assertEqual(no_reason.status_code, 400)
        self.assertEqual(no_reason.json()["error"]["code"], "INVALID_REASON")

        confirmed = client.post(
            reverse("licensing:api_manage_authorization_renew"),
            data=json.dumps(
                {
                    "authorization_ids": [authorization_id],
                    "unit": "day",
                    "amount": 1,
                    "reason": "批量补一天",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="renew-api-1",
        )
        self.assertEqual(confirmed.status_code, 200, confirmed.content)
        self.assertEqual(confirmed.json()["renewed_count"], 1)
        self.assertEqual(confirmed.json()["failed_count"], 0)
        first_expires = LicenseInstance.objects.get(authorization_id=authorization_id).expires_at

        replay = client.post(
            reverse("licensing:api_manage_authorization_renew"),
            data=json.dumps(
                {
                    "authorization_ids": [authorization_id],
                    "unit": "day",
                    "amount": 1,
                    "reason": "批量补一天",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="renew-api-1",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["repeated"])
        self.assertEqual(
            LicenseInstance.objects.get(authorization_id=authorization_id).expires_at,
            first_expires,
        )

    def test_renewal_api_reports_partial_failure_without_hiding_the_success(self):
        revoked_id, _ = self._activate_for_renewal(
            request_id="renew-partial-revoked",
            installation_id="install-revoked",
        )
        revoke_authorization(
            actor=self.admin,
            authorization_id=revoked_id,
            reason="测试撤销后不该续期",
        )
        _, extra_key = self._issue_extra_card(key="renew-partial-extra-card")
        good_id, _ = self._activate_for_renewal(
            request_id="renew-partial-good",
            installation_id="install-good",
            license_key=extra_key,
        )
        missing_id = str(uuid.uuid4())
        client = Client()
        client.force_login(self.admin)
        confirmed = client.post(
            reverse("licensing:api_manage_authorization_renew"),
            data=json.dumps(
                {
                    "authorization_ids": [good_id, revoked_id, missing_id],
                    "unit": "hour",
                    "amount": 2,
                    "reason": "批量补两小时",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="renew-api-partial",
        )
        self.assertEqual(confirmed.status_code, 200, confirmed.content)
        body = confirmed.json()
        self.assertEqual(body["renewed_count"], 1)
        self.assertEqual(body["failed_count"], 2)
        codes = {failure["authorization_id"]: failure["code"] for failure in body["failures"]}
        self.assertEqual(codes[revoked_id], "AUTHORIZATION_REVOKED")
        self.assertEqual(codes[missing_id], "AUTHORIZATION_NOT_FOUND")
        self.assertEqual(
            LicenseInstance.objects.get(authorization_id=good_id).authorization_revision,
            2,
        )
        self.assertEqual(
            LicenseInstance.objects.get(authorization_id=revoked_id).authorization_revision,
            2,
        )

    def test_renewal_api_preview_follows_device_and_risk_filters(self):
        authorization_id, _ = self._activate_for_renewal(
            request_id="renew-filter-activate",
            installation_id="install-filter",
        )
        client = Client()
        client.force_login(self.admin)
        url = reverse("licensing:api_manage_authorization_renew_preview")

        bound = client.get(url, {"device_state": "bound", "unit": "day", "amount": "1"})
        self.assertEqual(bound.status_code, 200, bound.content)
        self.assertEqual(bound.json()["renewable_count"], 1)
        unbound = client.get(url, {"device_state": "unbound", "unit": "day", "amount": "1"})
        self.assertEqual(unbound.json()["renewable_count"], 0)

        normal = client.get(url, {"risk_state": "normal", "unit": "day", "amount": "1"})
        self.assertEqual(normal.json()["renewable_count"], 1)

        device = Device.objects.get(installation_id="install-filter")
        block_device(
            actor=self.admin,
            authorization_id=authorization_id,
            device_id=device.public_id,
            reason="测试封禁后的续期筛选",
        )
        # 封禁设备会把实例一并打成 blocked，而 blocked 的授权本来就不在续期范围里，
        # 所以两个风险筛选都应当是空。列表看到什么，预览就必须看到什么。
        blocked = client.get(url, {"risk_state": "blocked", "unit": "day", "amount": "1"})
        self.assertEqual(blocked.json()["renewable_count"], 0)
        still_normal = client.get(url, {"risk_state": "normal", "unit": "day", "amount": "1"})
        self.assertEqual(still_normal.json()["renewable_count"], 0)

    def test_renewal_refuses_when_it_would_pass_the_lifetime_ceiling(self):
        authorization_id, _ = self._activate_for_renewal(
            request_id="renew-ceiling-activate",
            installation_id="install-ceiling",
        )
        instance = LicenseInstance.objects.get(authorization_id=authorization_id)
        ceiling = instance.activated_at + timedelta(seconds=MAX_RENEWAL_TOTAL_SECONDS)
        self.assertGreater(ceiling, instance.expires_at)
        # 直接把到期时间顶到上限前一天，再续一次 366 天就会越界。
        instance.expires_at = ceiling - timedelta(days=1)
        instance.save(update_fields=("expires_at",), _allow_mutation=True)
        with self.assertRaises(AuthorizationOperationError) as error:
            extend_authorization(
                actor=self.admin,
                authorization_id=authorization_id,
                added_seconds=MAX_RENEWAL_SECONDS,
                reason="越界续期应当被拒",
                now=self.now + timedelta(seconds=10),
            )
        self.assertEqual(error.exception.code, "RENEWAL_LIMIT_EXCEEDED")
        instance.refresh_from_db()
        self.assertEqual(instance.expires_at, ceiling - timedelta(days=1))

    def test_renewal_api_requires_platform_admin(self):
        downstream_user = self.downstream.user
        client = Client()
        client.force_login(downstream_user)
        response = client.post(
            reverse("licensing:api_manage_authorization_renew"),
            data=json.dumps(
                {
                    "authorization_ids": [str(uuid.uuid4())],
                    "unit": "day",
                    "amount": 1,
                    "reason": "越权尝试",
                }
            ),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="renew-api-forbidden",
        )
        self.assertIn(response.status_code, {401, 403})

    def test_bulk_revoke_api_and_idempotency(self):
        auth_id_1, _ = self._activate_for_renewal(request_id="bulk-revoke-act-1")
        _, extra_key = self._issue_extra_card(key="bulk-revoke-card-2")
        auth_id_2, _ = self._activate_for_renewal(
            request_id="bulk-revoke-act-2",
            installation_id="install-bulk-2",
            license_key=extra_key,
        )

        client = Client()
        anon_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_revoke"),
            data=json.dumps({"authorization_ids": [auth_id_1], "reason": "测试未授权"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-revoke-anon",
        )
        self.assertIn(anon_res.status_code, {401, 403})

        client.force_login(self.admin)
        no_key = client.post(
            reverse("licensing:api_manage_authorization_bulk_revoke"),
            data=json.dumps({"authorization_ids": [auth_id_1], "reason": "测试缺少key"}),
            content_type="application/json",
        )
        self.assertEqual(no_key.status_code, 400)

        empty_ids_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_revoke"),
            data=json.dumps({"authorization_ids": [], "reason": "测试空列表"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-revoke-empty",
        )
        self.assertEqual(empty_ids_res.status_code, 400)
        self.assertIn("请先选择要撤销的授权", empty_ids_res.json()["error"]["message"])

        res = client.post(
            reverse("licensing:api_manage_authorization_bulk_revoke"),
            data=json.dumps({"authorization_ids": [auth_id_1, auth_id_2], "reason": "批量违规撤销"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-revoke-key-1",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["revoked_count"], 2)
        self.assertEqual(data["failed_count"], 0)
        self.assertEqual(data["repeated"], False)

        inst1 = LicenseInstance.objects.get(pk=auth_id_1)
        inst2 = LicenseInstance.objects.get(pk=auth_id_2)
        self.assertEqual(inst1.state, AuthorizationState.REVOKED)
        self.assertEqual(inst2.state, AuthorizationState.REVOKED)

        replay_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_revoke"),
            data=json.dumps({"authorization_ids": [auth_id_1, auth_id_2], "reason": "批量违规撤销"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-revoke-key-1",
        )
        self.assertEqual(replay_res.status_code, 200)
        self.assertEqual(replay_res.json()["repeated"], True)
        self.assertEqual(replay_res.json()["revoked_count"], 2)

    def test_bulk_block_api_and_idempotency(self):
        auth_id_1, _ = self._activate_for_renewal(request_id="bulk-block-act-1")
        fake_auth_id = str(uuid.uuid4())

        client = Client()
        client.force_login(self.admin)
        empty_block_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [], "reason": "测试空列表"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-empty",
        )
        self.assertEqual(empty_block_res.status_code, 400)
        self.assertIn("请先选择要封禁设备的授权", empty_block_res.json()["error"]["message"])

        res = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [auth_id_1, fake_auth_id], "reason": "批量机器拉黑"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-key-1",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["blocked_count"], 1)
        self.assertEqual(data["failed_count"], 1)
        self.assertEqual(data["repeated"], False)

        inst = LicenseInstance.objects.get(pk=auth_id_1)
        self.assertEqual(inst.state, AuthorizationState.BLOCKED)
        device = inst.device_bindings.first().device
        self.assertEqual(device.risk_state, "blocked")

        # 验证该物理设备换新卡激活被直接拦截（RISK_BLOCKED）
        _, new_card_key = self._issue_extra_card(key="bulk-block-new-card")
        new_act_req, _ = self._request(
            action="activate",
            request_id="bulk-block-new-act",
            installation_id="install-a",
            license_key=new_card_key,
        )
        with self.assertRaises(AuthorizationOperationError) as blocked_err:
            activate_license(request=new_act_req, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertEqual(blocked_err.exception.code, "RISK_BLOCKED")

        replay = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [auth_id_1, fake_auth_id], "reason": "批量机器拉黑"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-key-1",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["repeated"], True)
        self.assertEqual(replay.json()["blocked_count"], 1)

    def test_bulk_block_dedupes_repeated_ids_and_enforces_limit(self):
        import uuid as uuid_module

        auth_id, _ = self._activate_for_renewal(request_id="bulk-block-dedup-act")
        client = Client()
        client.force_login(self.admin)

        dup_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [auth_id, auth_id], "reason": "重复勾选去重"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-dedup",
        )
        self.assertEqual(dup_res.status_code, 200)
        self.assertEqual(dup_res.json()["blocked_count"], 1)
        self.assertEqual(dup_res.json()["failed_count"], 0)

        many_ids = [str(uuid_module.uuid4()) for _ in range(501)]
        over_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": many_ids, "reason": "超限测试"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-over-limit",
        )
        self.assertEqual(over_res.status_code, 400)
        self.assertEqual(over_res.json()["error"]["code"], "BLOCK_TOO_MANY")

        bad_res = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [auth_id, "not-a-uuid"], "reason": "坏标识测试"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-bad-id",
        )
        self.assertEqual(bad_res.status_code, 400)
        self.assertIn("第 2 条", bad_res.json()["error"]["message"])

    def test_bulk_block_skips_authorization_without_active_binding(self):
        auth_id, private_key = self._activate_for_renewal(request_id="bulk-block-hist-act")
        device = Device.objects.get(
            authorization_bindings__authorization_id=auth_id,
            authorization_bindings__state=DeviceBindingState.ACTIVE,
        )
        deactivate_request, _ = self._request(
            action="deactivate",
            request_id="bulk-block-hist-deact",
            installation_id="install-a",
            private_key=private_key,
            authorization_id=auth_id,
        )
        deactivate_license(request=deactivate_request, clock=FixedClock(self.now + timedelta(seconds=1)))

        client = Client()
        client.force_login(self.admin)
        res = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [auth_id], "reason": "历史设备不追溯"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-block-hist-skip",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["blocked_count"], 0)
        self.assertEqual(data["failed_count"], 1)
        self.assertEqual(data["failures"][0]["code"], "DEVICE_NOT_BOUND")
        device.refresh_from_db()
        self.assertEqual(device.risk_state, DeviceRiskState.NORMAL)

    def test_bulk_unblock_restores_device_without_resurrecting_seats(self):
        auth_id, _ = self._activate_for_renewal(request_id="bulk-unblock-act")
        client = Client()
        client.force_login(self.admin)
        blocked = client.post(
            reverse("licensing:api_manage_authorization_bulk_block"),
            data=json.dumps({"authorization_ids": [auth_id], "reason": "误封演练拉黑"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-unblock-block",
        )
        self.assertEqual(blocked.status_code, 200)
        self.assertEqual(blocked.json()["blocked_count"], 1)

        device = Device.objects.get(
            authorization_bindings__authorization_id=auth_id,
            authorization_bindings__state=DeviceBindingState.BLOCKED,
        )
        self.assertEqual(device.risk_state, DeviceRiskState.BLOCKED)

        unblocked = client.post(
            reverse("licensing:api_manage_authorization_bulk_unblock"),
            data=json.dumps({"authorization_ids": [auth_id], "reason": "申诉通过解封"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-unblock-confirm",
        )
        self.assertEqual(unblocked.status_code, 200)
        data = unblocked.json()
        self.assertEqual(data["unblocked_count"], 1)
        self.assertEqual(data["failed_count"], 0)

        device.refresh_from_db()
        self.assertEqual(device.risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(
            DeviceBinding.objects.filter(authorization_id=auth_id, state=DeviceBindingState.BLOCKED).count(),
            1,
        )
        self.assertEqual(
            DeviceBinding.objects.filter(authorization_id=auth_id, state=DeviceBindingState.ACTIVE).count(),
            0,
        )

        _, new_card_key = self._issue_extra_card(key="bulk-unblock-new-card")
        new_act_req, _ = self._request(
            action="activate",
            request_id="bulk-unblock-new-act",
            installation_id="install-a",
            license_key=new_card_key,
        )
        new_act = activate_license(request=new_act_req, clock=FixedClock(self.now + timedelta(seconds=10)))
        self.assertEqual(new_act.payload["decision"], "active")

        replay = client.post(
            reverse("licensing:api_manage_authorization_bulk_unblock"),
            data=json.dumps({"authorization_ids": [auth_id], "reason": "申诉通过解封"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="bulk-unblock-confirm",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["repeated"], True)


@unittest.skipUnless(connection.vendor == "postgresql", "SQLite 不提供 PostgreSQL 行锁语义；在 PostgreSQL 环境运行授权并发验收")
class AuthorizationConcurrencyTests(TransactionTestCase):
    """Exercise authorization state transitions under real row-lock semantics."""

    reset_sequences = True

    # Reuse the product-neutral fixture without making the regular TestCase
    # fixture the base class of this TransactionTestCase.
    _user_admin = staticmethod(AuthorizationServiceTests._user_admin)
    _public_key = staticmethod(AuthorizationServiceTests._public_key)
    _request = AuthorizationServiceTests._request

    def setUp(self):
        AuthorizationServiceTests.setUp(self)

    def _run_parallel(self, callback):
        barrier = threading.Barrier(2)

        def worker(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                try:
                    return callback(index)
                except AuthorizationOperationError as exc:
                    return exc.code
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            return list(pool.map(worker, (0, 1)))

    def _assert_ordered_concurrent_request_reads_time_after_lock(self, action: str):
        initial_request, private_key = self._request(
            action="activate",
            request_id=f"ordered-time-{action}-initial",
        )
        activated = activate_license(request=initial_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        older_now = self.now + timedelta(seconds=1)
        newer_now = self.now + timedelta(seconds=2)
        older_request, _ = self._request(
            action=action,
            request_id=f"ordered-time-{action}-older",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        newer_request, _ = self._request(
            action="verify",
            request_id=f"ordered-time-{action}-newer",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        newer_lock_acquired = threading.Event()
        release_newer = threading.Event()
        older_lock_attempted = threading.Event()
        older_finished = threading.Event()
        newer_finished = threading.Event()
        thread_roles = {}
        older_result = []
        newer_result = []
        errors = []

        class GateAwareClock:
            def now(self):
                return newer_now if newer_finished.is_set() else older_now

        original_card_lock = authorization_service._lock_card_by_license_key
        original_instance_lock = authorization_service._lock_card_for_instance

        def make_gated_lock(original_lock):
            def gated_lock(*args, **kwargs):
                role = thread_roles.get(threading.get_ident())
                if role == "older":
                    older_lock_attempted.set()
                result = original_lock(*args, **kwargs)
                if role == "newer":
                    newer_lock_acquired.set()
                    release_newer.wait(timeout=10)
                return result

            return gated_lock

        def run_older():
            close_old_connections()
            thread_roles[threading.get_ident()] = "older"
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET SESSION lock_timeout = '10000ms'")
                older_result.append(
                    getattr(authorization_service, f"{action}_license")(
                        request=older_request,
                        clock=GateAwareClock(),
                    )
                )
            except Exception as exc:
                errors.append(("older", exc))
            finally:
                older_finished.set()
                close_old_connections()

        def run_newer():
            close_old_connections()
            thread_roles[threading.get_ident()] = "newer"
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET SESSION lock_timeout = '10000ms'")
                newer_result.append(verify_license(request=newer_request, clock=FixedClock(newer_now)))
            except Exception as exc:
                errors.append(("newer", exc))
            finally:
                newer_finished.set()
                close_old_connections()

        newer_thread = threading.Thread(target=run_newer)
        older_thread = threading.Thread(target=run_older)
        with patch.object(
            authorization_service,
            "_lock_card_by_license_key",
            side_effect=make_gated_lock(original_card_lock),
        ), patch.object(
            authorization_service,
            "_lock_card_for_instance",
            side_effect=make_gated_lock(original_instance_lock),
        ):
            newer_thread.start()
            try:
                self.assertTrue(newer_lock_acquired.wait(timeout=10))
                older_thread.start()
                self.assertTrue(older_lock_attempted.wait(timeout=10))
                self.assertFalse(older_finished.is_set())
            finally:
                release_newer.set()
                newer_thread.join(timeout=15)
                older_thread.join(timeout=15)

        self.assertFalse(older_thread.is_alive())
        self.assertFalse(newer_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(newer_result), 1)
        self.assertEqual(len(older_result), 1)
        self.assertEqual(newer_result[0].status_code, 200)
        self.assertEqual(newer_result[0].payload["decision"], "active")
        self.assertEqual(older_result[0].status_code, 200)
        self.assertNotIn("error", older_result[0].payload)
        if action == "deactivate":
            self.assertEqual(older_result[0].payload["state_code"], DeviceBindingState.UNBOUND)
        else:
            self.assertEqual(older_result[0].payload["decision"], "active")
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.ACTIVE)

    def test_concurrent_activate_reads_time_after_card_lock(self):
        self._assert_ordered_concurrent_request_reads_time_after_lock("activate")

    def test_concurrent_verify_reads_time_after_authorization_lock(self):
        self._assert_ordered_concurrent_request_reads_time_after_lock("verify")

    def test_concurrent_deactivate_reads_time_after_authorization_lock(self):
        self._assert_ordered_concurrent_request_reads_time_after_lock("deactivate")

    def test_concurrent_activation_creates_one_instance_and_one_binding(self):
        requests = [
            self._request(
                action="activate",
                request_id=f"parallel-activate-{index}",
                installation_id=f"parallel-install-{index}",
            )[0]
            for index in (0, 1)
        ]

        results = self._run_parallel(
            lambda index: (
                "success",
                activate_license(request=requests[index], clock=FixedClock(self.now)).payload["decision"],
            )
        )

        self.assertEqual(sum(result[0] == "success" for result in results if isinstance(result, tuple)), 1)
        self.assertIn("DEVICE_LIMIT_REACHED", results)
        self.assertEqual(LicenseInstance.objects.count(), 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.ACTIVATED)
        self.assertEqual(DeviceBinding.objects.filter(state=DeviceBindingState.ACTIVE).count(), 1)

    def test_concurrent_revoke_and_verify_never_resurrects_authorization(self):
        activation_request, private_key = self._request(
            action="activate",
            request_id="parallel-revoke-verify-activate",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision
        verify_request, _ = self._request(
            action="verify",
            request_id="parallel-revoke-verify-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )

        def verify_or_revoke(index):
            if index == 0:
                try:
                    result = verify_license(
                        request=verify_request,
                        clock=FixedClock(self.now + timedelta(seconds=1)),
                    )
                    error = result.payload.get("error") or {}
                    return (
                        "verify",
                        "response",
                        result.status_code,
                        result.payload["decision"],
                        error.get("code"),
                    )
                except AuthorizationOperationError as exc:
                    return ("verify", "error", exc.code)

            actor = get_user_model().objects.get(pk=self.admin.pk)
            try:
                result = revoke_authorization(
                    actor=actor,
                    authorization_id=authorization_id,
                    reason="并发撤销与验证验收",
                    now=self.now + timedelta(seconds=1),
                    request_id="parallel-revoke-verify-revoke",
                )
                return ("revoke", "ok", result.repeated)
            except AuthorizationOperationError as exc:
                return ("revoke", "error", exc.code)

        results = self._run_parallel(verify_or_revoke)
        verify_result = next(result for result in results if result[0] == "verify")
        revoke_result = next(result for result in results if result[0] == "revoke")
        self.assertEqual(revoke_result, ("revoke", "ok", False))
        if verify_result[1] == "response":
            self.assertIn(
                verify_result[2:],
                [
                    (200, "active", None),
                    (403, "revoked", "LICENSE_REVOKED"),
                ],
            )
        else:
            self.assertEqual(verify_result, ("verify", "error", "LICENSE_REVOKED"))

        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.state, AuthorizationState.REVOKED)
        self.assertEqual(instance.authorization_revision, before_revision + 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.REVOKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        fresh_verify_request, _ = self._request(
            action="verify",
            request_id="parallel-revoke-verify-fresh",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        fresh_result = verify_license(
            request=fresh_verify_request,
            clock=FixedClock(self.now + timedelta(seconds=2)),
        )
        self.assertEqual(fresh_result.status_code, 403)
        self.assertEqual(fresh_result.payload["decision"], "revoked")
        self.assertEqual(fresh_result.payload["error"]["code"], "LICENSE_REVOKED")

    def test_concurrent_renewal_and_revoke_never_resurrects_authorization(self):
        activation_request, _ = self._request(
            action="activate",
            request_id="parallel-renew-revoke-activate",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]

        def renew_or_revoke(index):
            actor = get_user_model().objects.get(pk=self.admin.pk)
            if index == 0:
                try:
                    result = extend_authorization(
                        actor=actor,
                        authorization_id=authorization_id,
                        added_seconds=86400,
                        reason="并发续期与撤销验收",
                        now=self.now + timedelta(seconds=1),
                        request_id="parallel-renew-revoke-renew",
                    )
                    return ("renew", "ok", result.added_seconds)
                except AuthorizationOperationError as exc:
                    return ("renew", "error", exc.code)
            try:
                result = revoke_authorization(
                    actor=actor,
                    authorization_id=authorization_id,
                    reason="并发撤销与续期验收",
                    now=self.now + timedelta(seconds=1),
                    request_id="parallel-renew-revoke-revoke",
                )
                return ("revoke", "ok", result.repeated)
            except AuthorizationOperationError as exc:
                return ("revoke", "error", exc.code)

        results = self._run_parallel(renew_or_revoke)
        renew_result = next(result for result in results if result[0] == "renew")
        revoke_result = next(result for result in results if result[0] == "revoke")
        self.assertEqual(revoke_result, ("revoke", "ok", False))
        # 续期要么在撤销之前成功（随后被撤销覆盖），要么看到已撤销而拒绝。
        # 两种结果都不允许把授权拉回可用状态。
        if renew_result[1] == "ok":
            self.assertEqual(renew_result, ("renew", "ok", 86400))
        else:
            self.assertEqual(renew_result, ("renew", "error", "AUTHORIZATION_REVOKED"))

        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.state, AuthorizationState.REVOKED)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.REVOKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        # 撤销之后不许再续期
        with self.assertRaises(AuthorizationOperationError) as after:
            extend_authorization(
                actor=get_user_model().objects.get(pk=self.admin.pk),
                authorization_id=authorization_id,
                added_seconds=86400,
                reason="撤销后不该再续期",
                now=self.now + timedelta(seconds=3),
            )
        self.assertEqual(after.exception.code, "AUTHORIZATION_REVOKED")

    def test_concurrent_double_renewal_adds_time_twice_exactly(self):
        activation_request, _ = self._request(
            action="activate",
            request_id="parallel-double-renew-activate",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        before_expires = LicenseInstance.objects.get(pk=authorization_id).expires_at

        def renew(index):
            actor = get_user_model().objects.get(pk=self.admin.pk)
            try:
                result = extend_authorization(
                    actor=actor,
                    authorization_id=authorization_id,
                    added_seconds=3600,
                    reason=f"并发双续期验收 {index}",
                    now=self.now + timedelta(seconds=1),
                    request_id=f"parallel-double-renew-{index}",
                )
                return ("renew", "ok", result.added_seconds)
            except AuthorizationOperationError as exc:
                return ("renew", "error", exc.code)

        results = self._run_parallel(renew)
        # 两个不同的幂等键就是两次运营动作：两次都成功，正好加两小时，
        # revision 也必须正好走两步，不能因为并发丢掉其中一次。
        self.assertEqual(results, [("renew", "ok", 3600), ("renew", "ok", 3600)])
        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.expires_at, before_expires + timedelta(seconds=7200))
        self.assertEqual(instance.authorization_revision, 3)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).expires_at, instance.expires_at)

    def test_concurrent_device_block_and_verify_never_resurrects_binding(self):
        activation_request, private_key = self._request(
            action="activate",
            request_id="parallel-block-verify-activate",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision
        verify_request, _ = self._request(
            action="verify",
            request_id="parallel-block-verify-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )

        def verify_or_block(index):
            if index == 0:
                try:
                    result = verify_license(
                        request=verify_request,
                        clock=FixedClock(self.now + timedelta(seconds=1)),
                    )
                    return (
                        "verify",
                        "response",
                        result.status_code,
                        result.payload["decision"],
                    )
                except AuthorizationOperationError as exc:
                    return ("verify", "error", exc.code)

            actor = get_user_model().objects.get(pk=self.admin.pk)
            try:
                result = block_device(
                    actor=actor,
                    authorization_id=authorization_id,
                    device_id=device.public_id,
                    reason="并发设备阻断与验证验收",
                    now=self.now + timedelta(seconds=1),
                    request_id="parallel-block-verify-block",
                )
                return ("block", "ok", result.repeated)
            except AuthorizationOperationError as exc:
                return ("block", "error", exc.code)

        results = self._run_parallel(verify_or_block)
        verify_result = next(result for result in results if result[0] == "verify")
        block_result = next(result for result in results if result[0] == "block")
        self.assertEqual(block_result, ("block", "ok", False))
        self.assertIn(
            verify_result,
            [
                ("verify", "response", 200, "active"),
                ("verify", "response", 403, "blocked"),
            ],
        )

        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(Device.objects.get(pk=device.pk).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(instance.state, AuthorizationState.BLOCKED)
        self.assertEqual(instance.authorization_revision, before_revision + 1)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        fresh_verify_request, _ = self._request(
            action="verify",
            request_id="parallel-block-verify-fresh",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        fresh_result = verify_license(
            request=fresh_verify_request,
            clock=FixedClock(self.now + timedelta(seconds=2)),
        )
        self.assertEqual(fresh_result.status_code, 403)
        self.assertEqual(fresh_result.payload["error"]["code"], "LICENSE_BLOCKED")
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)

    def test_concurrent_duplicate_activation_and_verify_keep_one_active_instance(self):
        activation_request, private_key = self._request(
            action="activate",
            request_id="parallel-duplicate-activate-verify-initial",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        duplicate_activation_request, _ = self._request(
            action="activate",
            request_id="parallel-duplicate-activate-verify-activate",
            private_key=private_key,
        )
        verify_request, _ = self._request(
            action="verify",
            request_id="parallel-duplicate-activate-verify-verify",
            private_key=private_key,
            authorization_id=authorization_id,
        )

        def duplicate_activate_or_verify(index):
            try:
                if index == 0:
                    result = activate_license(
                        request=duplicate_activation_request,
                        clock=FixedClock(self.now + timedelta(seconds=1)),
                    )
                    return ("activate", "ok", result.status_code, result.payload["decision"])
                result = verify_license(
                    request=verify_request,
                    clock=FixedClock(self.now + timedelta(seconds=1)),
                )
                return ("verify", "ok", result.status_code, result.payload["decision"])
            except AuthorizationOperationError as exc:
                return ("activate" if index == 0 else "verify", "error", exc.code)

        results = self._run_parallel(duplicate_activate_or_verify)
        self.assertCountEqual(
            results,
            [
                ("activate", "ok", 200, "active"),
                ("verify", "ok", 200, "active"),
            ],
        )
        self.assertEqual(LicenseInstance.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.ACTIVATED)
        fresh_verify_request, _ = self._request(
            action="verify",
            request_id="parallel-duplicate-activate-verify-fresh",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        fresh_result = verify_license(
            request=fresh_verify_request,
            clock=FixedClock(self.now + timedelta(seconds=2)),
        )
        self.assertEqual(fresh_result.status_code, 200)
        self.assertEqual(fresh_result.payload["decision"], "active")

    def test_concurrent_revoke_and_duplicate_activation_never_resurrects_authorization(self):
        activation_request, private_key = self._request(
            action="activate",
            request_id="parallel-revoke-activate-activate",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision
        duplicate_activation_request, _ = self._request(
            action="activate",
            request_id="parallel-revoke-activate-retry",
            private_key=private_key,
        )

        def duplicate_activate_or_revoke(index):
            if index == 0:
                try:
                    result = activate_license(
                        request=duplicate_activation_request,
                        clock=FixedClock(self.now + timedelta(seconds=1)),
                    )
                    error = result.payload.get("error") or {}
                    return (
                        "activate",
                        "response",
                        result.status_code,
                        result.payload["decision"],
                        error.get("code"),
                    )
                except AuthorizationOperationError as exc:
                    return ("activate", "error", exc.code)

            actor = get_user_model().objects.get(pk=self.admin.pk)
            try:
                result = revoke_authorization(
                    actor=actor,
                    authorization_id=authorization_id,
                    reason="并发撤销与重复激活验收",
                    now=self.now + timedelta(seconds=1),
                    request_id="parallel-revoke-activate-revoke",
                )
                return ("revoke", "ok", result.repeated)
            except AuthorizationOperationError as exc:
                return ("revoke", "error", exc.code)

        results = self._run_parallel(duplicate_activate_or_revoke)
        activate_result = next(result for result in results if result[0] == "activate")
        revoke_result = next(result for result in results if result[0] == "revoke")
        self.assertEqual(revoke_result, ("revoke", "ok", False))
        if activate_result[1] == "response":
            self.assertIn(
                activate_result[2:],
                [
                    (200, "active", None),
                    (403, "revoked", "LICENSE_REVOKED"),
                ],
            )
        else:
            self.assertEqual(activate_result, ("activate", "error", "LICENSE_REVOKED"))

        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.state, AuthorizationState.REVOKED)
        self.assertEqual(instance.authorization_revision, before_revision + 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.REVOKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)
        fresh_verify_request, _ = self._request(
            action="verify",
            request_id="parallel-revoke-activate-fresh",
            private_key=private_key,
            authorization_id=authorization_id,
        )
        fresh_result = verify_license(
            request=fresh_verify_request,
            clock=FixedClock(self.now + timedelta(seconds=2)),
        )
        self.assertEqual(fresh_result.status_code, 403)
        self.assertEqual(fresh_result.payload["error"]["code"], "LICENSE_REVOKED")

    def test_concurrent_device_block_and_new_activation_never_resurrects_binding(self):
        activation_request, private_key = self._request(
            action="activate",
            request_id="parallel-block-new-activate-initial",
        )
        activated = activate_license(request=activation_request, clock=FixedClock(self.now))
        first_authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        _, second_snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="并发阻断新激活套餐",
            duration_seconds=60,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=second_snapshot.snapshot_id,
            quantity=1,
            idempotency_key="parallel-block-new-activate-issue",
        )
        second_card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        second_key = decrypt_license_card(second_card.card_ciphertext)
        second_activation_request, _ = self._request(
            action="activate",
            request_id="parallel-block-new-activate-retry",
            private_key=private_key,
            license_key=second_key,
            installation_id="install-a",
        )

        def block_or_new_activate(index):
            if index == 0:
                actor = get_user_model().objects.get(pk=self.admin.pk)
                try:
                    result = block_device(
                        actor=actor,
                        authorization_id=first_authorization_id,
                        device_id=device.public_id,
                        reason="并发阻断新激活验收",
                        now=self.now + timedelta(seconds=1),
                        request_id="parallel-block-new-activate-block",
                    )
                    return ("block", "ok", result.repeated)
                except AuthorizationOperationError as exc:
                    return ("block", "error", exc.code)

            try:
                result = activate_license(
                    request=second_activation_request,
                    clock=FixedClock(self.now + timedelta(seconds=1)),
                )
                return ("activate", "ok", result.status_code, result.payload["decision"])
            except AuthorizationOperationError as exc:
                return ("activate", "error", exc.code)

        results = self._run_parallel(block_or_new_activate)
        block_result = next(result for result in results if result[0] == "block")
        activate_result = next(result for result in results if result[0] == "activate")
        self.assertEqual(block_result, ("block", "ok", False))
        self.assertEqual(activate_result, ("activate", "ok", 200, "active"))
        self.assertEqual(Device.objects.get(pk=device.pk).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(
            DeviceBinding.objects.filter(device=device, state=DeviceBindingState.ACTIVE).count(),
            2,
        )
        self.assertEqual(
            DeviceBinding.objects.filter(authorization_id=first_authorization_id).first().state,
            DeviceBindingState.ACTIVE,
        )
        self.assertEqual(
            LicenseInstance.objects.get(pk=first_authorization_id).state,
            AuthorizationState.BLOCKED,
        )

    def test_concurrent_activation_and_reclaim_have_one_linearized_winner(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=5,
            reason="激活回收竞态准备",
            idempotency_key="parallel-activation-reclaim-credit",
        )
        _, paid_snapshot = create_plan(
            actor=self.admin,
            software_id=self.software.software_id,
            profile_id=self.profile.profile_id,
            policy_version=self.policy.version,
            name="激活回收竞态套餐",
            duration_seconds=60,
            quota_cost=5,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        issued = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software.software_id,
            plan_snapshot_id=paid_snapshot.snapshot_id,
            quantity=1,
            idempotency_key="parallel-activation-reclaim-issue",
        )
        paid_card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
        paid_license_key = decrypt_license_card(paid_card.card_ciphertext)
        activation_request, _ = self._request(
            action="activate",
            request_id="parallel-activation-reclaim-activate",
            installation_id="parallel-activation-reclaim-install",
            license_key=paid_license_key,
        )

        def activate_or_reclaim(index):
            if index == 0:
                try:
                    result = activate_license(request=activation_request, clock=FixedClock(self.now))
                    return ("activate", "ok", result.payload["authorization_id"])
                except AuthorizationOperationError as exc:
                    return ("activate", "error", exc.code)

            actor = get_user_model().objects.get(pk=self.downstream.user.pk)
            try:
                result = reclaim_license_card(
                    actor=actor,
                    card_public_id=paid_card.public_id,
                    idempotency_key="parallel-activation-reclaim-request",
                )
                return ("reclaim", "ok", str(result.entry.public_id) if result.entry else "zero-cost")
            except LicenseOperationError as exc:
                return ("reclaim", "error", exc.code)

        results = self._run_parallel(activate_or_reclaim)
        activation_result, reclaim_result = results
        self.assertEqual(sum(result[1] == "ok" for result in results), 1)
        card = LicenseCard.objects.get(pk=paid_card.pk)
        reclaim_entries = QuotaLedgerEntry.objects.filter(
            operation_type=QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
            source_public_id=str(paid_card.public_id),
        )

        if activation_result[1] == "ok":
            self.assertEqual(reclaim_result, ("reclaim", "error", "CARD_NOT_RECLAIMABLE"))
            self.assertEqual(card.status, LicenseCardStatus.ACTIVATED)
            self.assertEqual(LicenseInstance.objects.filter(license_card_id=paid_card.public_id).count(), 1)
            self.assertEqual(reclaim_entries.count(), 0)
            self.assertEqual(get_quota_account(self.downstream).available_balance, 0)
        else:
            self.assertEqual(activation_result, ("activate", "error", "LICENSE_NOT_ACTIVE"))
            self.assertEqual(reclaim_result[0:2], ("reclaim", "ok"))
            self.assertEqual(card.status, LicenseCardStatus.RECLAIMED)
            self.assertEqual(LicenseInstance.objects.filter(license_card_id=paid_card.public_id).count(), 0)
            self.assertEqual(reclaim_entries.count(), 1)
            self.assertEqual(get_quota_account(self.downstream).available_balance, 5)

    def test_concurrent_revoke_increments_revision_once_and_blocks_binding(self):
        request, _ = self._request(action="activate", request_id="parallel-revoke-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision

        def revoke(index):
            actor = get_user_model().objects.get(pk=self.admin.pk)
            result = revoke_authorization(
                actor=actor,
                authorization_id=authorization_id,
                reason="并发撤销验收",
                now=self.now + timedelta(seconds=index + 1),
                request_id=f"parallel-revoke-{index}",
            )
            return result.repeated

        self.assertCountEqual(self._run_parallel(revoke), [False, True])
        instance = LicenseInstance.objects.get(pk=authorization_id)
        self.assertEqual(instance.state, AuthorizationState.REVOKED)
        self.assertEqual(instance.authorization_revision, before_revision + 1)
        self.assertEqual(LicenseCard.objects.get(pk=self.card.pk).status, LicenseCardStatus.REVOKED)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.BLOCKED)

    def test_concurrent_device_block_is_idempotent_and_keeps_active_binding(self):
        request, _ = self._request(action="activate", request_id="parallel-block-activate")
        activated = activate_license(request=request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        device = Device.objects.get()
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision

        def block(index):
            actor = get_user_model().objects.get(pk=self.admin.pk)
            result = block_device(
                actor=actor,
                authorization_id=authorization_id,
                device_id=device.public_id,
                reason="并发设备阻断验收",
                now=self.now + timedelta(seconds=index + 1),
                request_id=f"parallel-block-{index}",
            )
            return result.repeated

        self.assertCountEqual(self._run_parallel(block), [False, True])
        self.assertEqual(Device.objects.get(pk=device.pk).risk_state, DeviceRiskState.NORMAL)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.ACTIVE)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).state, AuthorizationState.BLOCKED)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, before_revision + 1)

    def test_concurrent_deactivate_unbinds_once_and_keeps_history(self):
        activate_request, private_key = self._request(action="activate", request_id="parallel-deactivate-activate")
        activated = activate_license(request=activate_request, clock=FixedClock(self.now))
        authorization_id = activated.payload["authorization_id"]
        before_revision = LicenseInstance.objects.get(pk=authorization_id).authorization_revision
        requests = [
            self._request(
                action="deactivate",
                request_id=f"parallel-deactivate-{index}",
                private_key=private_key,
                authorization_id=authorization_id,
            )[0]
            for index in (0, 1)
        ]

        results = self._run_parallel(
            lambda index: (
                "success",
                deactivate_license(request=requests[index], clock=FixedClock(self.now + timedelta(seconds=index + 1))).payload["state_code"],
            )
        )

        self.assertEqual(sum(result[0] == "success" for result in results if isinstance(result, tuple)), 1)
        self.assertIn("DEVICE_NOT_BOUND", results)
        self.assertEqual(DeviceBinding.objects.count(), 1)
        self.assertEqual(DeviceBinding.objects.get().state, DeviceBindingState.UNBOUND)
        self.assertEqual(LicenseInstance.objects.get(pk=authorization_id).authorization_revision, before_revision + 1)


class AuthorizationCanonicalizationTests(TestCase):
    def test_supported_values_are_deterministic_and_sorted(self):
        self.assertEqual(canonicalize_jcs({"b": 1, "a": "中文"}), '{"a":"中文","b":1}'.encode("utf-8"))

    def test_object_keys_follow_utf16_code_unit_order(self):
        """RFC 8785 sorts keys by UTF-16 code units, which differs from the
        Python code-point order once a key contains an astral character."""

        bmp = "\uffff"
        astral = "\U00010000"
        self.assertEqual(
            canonicalize_jcs({bmp: 1, astral: 2}),
            f'{{"{astral}":2,"{bmp}":1}}'.encode("utf-8"),
        )

    def test_lone_surrogate_is_rejected_before_it_reaches_the_wire(self):
        with self.assertRaises(ValueError):
            canonicalize_jcs({"\ud800": 1})
        with self.assertRaises(ValueError):
            canonicalize_jcs({"value": "\ud800"})

    def test_unsafe_or_ambiguous_values_fail_closed(self):
        with self.assertRaises(ValueError):
            canonicalize_jcs({"value": MAX_SAFE_INTEGER + 1})
        with self.assertRaises(ValueError):
            canonicalize_jcs({"value": 1.5})


MAX_SAFE_INTEGER = 9_007_199_254_740_991
