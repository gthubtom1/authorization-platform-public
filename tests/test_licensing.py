from __future__ import annotations

import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import connection
from django.db import close_old_connections
from django.core.exceptions import PermissionDenied
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django.urls import reverse

from authorization_platform.accounts.services import (
    archive_downstream,
    create_downstream_direct,
    delete_archived_downstream,
)
from authorization_platform.audit.models import AuditEvent
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import (
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    set_downstream_software_access,
)
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY
from authorization_platform.credits.models import QuotaAccount, QuotaLedgerEntry, QuotaLedgerOperation
from authorization_platform.credits.services import QuotaOperationError, _refund_license_card_quota, credit_quota, debit_quota, get_quota_account
from authorization_platform.licensing.models import LicenseCard, LicenseCardBatch, LicenseCardLifecycleOperation
from authorization_platform.licensing.services import (
    LicenseOperationError,
    archive_license_cards,
    decrypt_license_card,
    encrypt_license_card,
    generate_license_batch,
    preview_license_batch,
    reclaim_license_card,
)


User = get_user_model()


class LicenseBatchServiceTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(actor=self.admin, username="downstream-a", password="Downstream-password-123")
        self.downstream_b = create_downstream_direct(actor=self.admin, username="downstream-b", password="Downstream-password-123")
        self.software, self.profile, self.policy, self.plan, self.snapshot = self._create_plan_graph(
            software_id="software-a",
            quota_cost=5,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )

    def _create_plan_graph(
        self,
        *,
        software_id: str,
        quota_cost: int,
        test_only: bool = False,
        software_status: str = SoftwareStatus.ACTIVE,
        profile_status: str = ProfileStatus.ACTIVE,
    ):
        software = create_software(actor=self.admin, software_id=software_id, name=software_id, status=software_status)
        profile = create_profile(
            actor=self.admin,
            software_id=software_id,
            profile_id="stable",
            client_id=f"{software_id}-windows",
            status=profile_status,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id=software_id,
            profile_id="stable",
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=software_id,
            profile_id="stable",
            policy_version=policy.version,
            name=f"{software_id} 套餐",
            duration_seconds=60 if test_only else 86400,
            quota_cost=quota_cost,
            test_only=test_only,
            status=PlanStatus.ACTIVE,
        )
        return software, profile, policy, plan, snapshot

    def _credit(self, amount: int = 100):
        return credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=amount,
            reason="授权卡密测试额度",
            idempotency_key=f"credit-{amount}-{QuotaLedgerEntry.objects.count()}",
        )

    def _generate(self, *, quantity=1, key="license-1", snapshot=None):
        return generate_license_batch(
            actor=self.downstream_a.user,
            software_id=self.software.software_id,
            plan_snapshot_id=(snapshot or self.snapshot).snapshot_id,
            quantity=quantity,
            idempotency_key=key,
        )

    def test_license_card_encryption_uses_dedicated_key_and_reads_explicit_legacy_version(self):
        current_key = Fernet.generate_key().decode("ascii")
        legacy_key = Fernet.generate_key().decode("ascii")
        legacy_ciphertext = Fernet(legacy_key).encrypt(b"LC-LEGACY-TEST").decode("ascii")
        with override_settings(
            LICENSE_CARD_ENCRYPTION_KEY=current_key,
            LICENSE_CARD_ENCRYPTION_KEY_VERSION="v2",
            LICENSE_CARD_LEGACY_ENCRYPTION_KEY=legacy_key,
        ):
            self.assertEqual(
                decrypt_license_card(legacy_ciphertext, key_version="v1"),
                "LC-LEGACY-TEST",
            )
            current_ciphertext = encrypt_license_card("LC-CURRENT-TEST")
            self.assertEqual(decrypt_license_card(current_ciphertext, key_version="v2"), "LC-CURRENT-TEST")

    def test_generation_reuses_one_snapshot_and_debits_once(self):
        self._credit(100)
        result = self._generate(quantity=3)

        self.assertFalse(result.repeated)
        self.assertEqual(len(result.cards), 3)
        batch = LicenseCardBatch.objects.get(batch_id=result.batch.batch_id)
        self.assertEqual(batch.plan_snapshot_id, self.snapshot.snapshot_id)
        self.assertEqual(batch.total_quota_cost, 15)
        self.assertEqual(LicenseCard.objects.filter(batch=batch).count(), 3)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").count(), 1)
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 85)
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        self.assertEqual(card.plan_snapshot_id, self.snapshot.snapshot_id)
        self.assertNotEqual(card.card_hash, result.cards[0].code)
        self.assertEqual(decrypt_license_card(card.card_ciphertext), result.cards[0].code)

    def test_same_key_is_idempotent_and_different_request_conflicts(self):
        self._credit(100)
        first = self._generate(quantity=2, key="same-key")
        repeated = self._generate(quantity=2, key="same-key")
        self.assertTrue(repeated.repeated)
        self.assertEqual(first.batch.batch_id, repeated.batch.batch_id)
        self.assertEqual([item.code for item in first.cards], [item.code for item in repeated.cards])
        self.assertEqual(LicenseCardBatch.objects.count(), 1)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").count(), 1)

        with self.assertRaises(LicenseOperationError) as conflict:
            self._generate(quantity=3, key="same-key")
        self.assertEqual(conflict.exception.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 90)

    def test_insufficient_quota_does_not_create_batch_or_debit(self):
        self._credit(9)
        with self.assertRaises(LicenseOperationError) as insufficient:
            self._generate(quantity=2, key="not-enough")

        self.assertEqual(insufficient.exception.code, "INSUFFICIENT_QUOTA")
        self.assertEqual(LicenseCardBatch.objects.count(), 0)
        self.assertEqual(LicenseCard.objects.count(), 0)
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 9)
        self.assertFalse(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").exists())
        self.assertTrue(AuditEvent.objects.filter(action="license_batch.issue", outcome="failure").exists())

    def test_partial_card_failure_rolls_back_batch_cards_and_debit(self):
        self._credit(100)
        with patch(
            "authorization_platform.licensing.services._issue_cards",
            side_effect=LicenseOperationError("CARD_GENERATION_FAILED", "注入失败"),
        ):
            with self.assertRaises(LicenseOperationError):
                self._generate(quantity=3, key="partial-failure")

        self.assertEqual(LicenseCardBatch.objects.count(), 0)
        self.assertEqual(LicenseCard.objects.count(), 0)
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 100)
        self.assertFalse(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").exists())

    def test_zero_cost_test_plan_has_same_batch_state_without_fake_debit(self):
        software, profile, policy, plan, snapshot = self._create_plan_graph(
            software_id="test-tool",
            quota_cost=0,
            test_only=True,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        result = generate_license_batch(
            actor=self.downstream_a.user,
            software_id=software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="free-test-card",
        )
        self.assertEqual(result.batch.total_quota_cost, 0)
        self.assertEqual(result.cards[0].plan_snapshot_id, snapshot.snapshot_id)
        self.assertFalse(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").exists())

    def test_testing_software_can_issue_only_test_only_plan_for_its_opened_downstream(self):
        software, profile, policy, _, test_snapshot = self._create_plan_graph(
            software_id="integration-tool",
            quota_cost=0,
            test_only=True,
            software_status=SoftwareStatus.TESTING,
            profile_status=ProfileStatus.TESTING,
        )
        normal_plan, normal_snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="正式套餐",
            duration_seconds=86400,
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

        issued = generate_license_batch(
            actor=self.downstream_a.user,
            software_id=software.software_id,
            plan_snapshot_id=test_snapshot.snapshot_id,
            quantity=1,
            idempotency_key="testing-software-test-card",
        )
        self.assertEqual(issued.cards[0].plan_snapshot_id, test_snapshot.snapshot_id)
        with self.assertRaises(LicenseOperationError) as rejected:
            generate_license_batch(
                actor=self.downstream_a.user,
                software_id=software.software_id,
                plan_snapshot_id=normal_snapshot.snapshot_id,
                quantity=1,
                idempotency_key="testing-software-normal-card",
            )
        self.assertEqual(rejected.exception.code, "PLAN_NOT_AVAILABLE")
        self.assertEqual(normal_plan.status, PlanStatus.ACTIVE)

    def test_cross_software_and_downstream_scope_is_rejected(self):
        with self.assertRaises(LicenseOperationError) as not_open:
            preview_license_batch(
                actor=self.downstream_a.user,
                software_id="software-b",
                plan_id=self.plan.pk,
                quantity=1,
            )
        self.assertEqual(not_open.exception.code, "PLAN_NOT_AVAILABLE")
        self.assertEqual(not_open.exception.message, "套餐当前不可生成授权卡密。")
        with self.assertRaises(LicenseOperationError) as missing:
            preview_license_batch(
                actor=self.downstream_a.user,
                software_id=self.software.software_id,
                plan_id="00000000-0000-0000-0000-000000000000",
                quantity=1,
            )
        self.assertEqual(missing.exception.code, not_open.exception.code)
        self.assertEqual(missing.exception.message, not_open.exception.message)

        with self.assertRaises(LicenseOperationError) as wrong_downstream:
            generate_license_batch(
                actor=self.downstream_b.user,
                software_id=self.software.software_id,
                plan_snapshot_id=self.snapshot.snapshot_id,
                quantity=1,
                idempotency_key="wrong-owner",
            )
        self.assertEqual(wrong_downstream.exception.code, "SOFTWARE_NOT_OPEN")

    def test_future_effective_plan_cannot_be_previewed_or_generated(self):
        self.plan.effective_at = timezone.now() + timedelta(hours=1)
        self.plan.save(update_fields=("effective_at", "updated_at"))
        with self.assertRaises(LicenseOperationError) as future:
            preview_license_batch(
                actor=self.downstream_a.user,
                software_id=self.software.software_id,
                plan_id=self.plan.pk,
                quantity=1,
            )
        self.assertEqual(future.exception.code, "PLAN_NOT_AVAILABLE")
        self.assertEqual(future.exception.message, "套餐当前不可生成授权卡密。")

    def test_collision_is_retried_inside_savepoint(self):
        self._credit(100)
        with patch(
            "authorization_platform.licensing.services._new_license_card_code",
            side_effect=["LC-COLLISION", "LC-COLLISION", "LC-UNIQUE"],
        ):
            first = self._generate(key="collision-first")
        with patch(
            "authorization_platform.licensing.services._new_license_card_code",
            side_effect=["LC-COLLISION", "LC-UNIQUE-2"],
        ):
            second = self._generate(key="collision-second")
        self.assertNotEqual(first.cards[0].code, second.cards[0].code)
        self.assertEqual(LicenseCard.objects.count(), 2)

    def test_unused_card_reclaim_refunds_original_cost_once(self):
        self._credit(20)
        result = self._generate(key="reclaim-once")
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        first = reclaim_license_card(actor=self.downstream_a.user, card_public_id=card.public_id, idempotency_key="reclaim-request-1")
        repeated = reclaim_license_card(actor=self.downstream_a.user, card_public_id=card.public_id, idempotency_key="reclaim-request-1")

        self.assertFalse(first.repeated)
        self.assertTrue(repeated.repeated)
        self.assertEqual(first.card.status, "reclaimed")
        self.assertEqual(repeated.card.status, "reclaimed")
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 20)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").count(), 1)
        reclaim_audits = AuditEvent.objects.filter(action="license_card.reclaim", outcome="success")
        self.assertEqual(reclaim_audits.count(), 2)
        repeated_audit = reclaim_audits.order_by("-occurred_at").first()
        self.assertTrue(repeated_audit.metadata["repeated"])
        self.assertEqual(repeated_audit.metadata["balance_before"], 15)
        self.assertEqual(repeated_audit.metadata["balance_after"], 20)

    def test_non_unused_card_cannot_be_reclaimed_or_refunded(self):
        self._credit(20)
        result = self._generate(key="reclaim-activated")
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        card.status = "activated"
        card.activated_at = timezone.now()
        with self.assertRaises(ValueError):
            card.save(update_fields=("status", "activated_at"))
        card.save(update_fields=("status", "activated_at"), _allow_mutation=True)

        with self.assertRaises(LicenseOperationError) as error:
            reclaim_license_card(actor=self.downstream_a.user, card_public_id=card.public_id, idempotency_key="reclaim-request-activated")
        self.assertEqual(error.exception.code, "CARD_NOT_RECLAIMABLE")
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 15)
        self.assertFalse(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").exists())

    def test_refund_primitive_requires_a_real_owned_card(self):
        self._credit(20)
        with self.assertRaises(QuotaOperationError) as missing:
            _refund_license_card_quota(
                actor=self.downstream_a.user,
                license_card_public_id=uuid.uuid4(),
                idempotency_key="forged-card",
            )
        self.assertEqual(missing.exception.code, "LICENSE_CARD_NOT_FOUND")
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 20)

        result = self._generate(key="owned-card-check")
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        with self.assertRaises(PermissionDenied):
            _refund_license_card_quota(
                actor=self.downstream_b.user,
                license_card_public_id=card.public_id,
                idempotency_key="wrong-owner-card",
            )
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 15)
        self.assertEqual(LicenseCard.objects.get(public_id=card.public_id).status, "unused")

    def test_license_card_cannot_be_deleted_directly(self):
        self._credit(5)
        result = self._generate(key="delete-card-guard")
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        with self.assertRaises(ValueError):
            card.delete()
        with self.assertRaises(ValueError):
            LicenseCard.objects.filter(public_id=card.public_id).update(status="reclaimed")
        with self.assertRaises(ValueError):
            LicenseCard.objects.filter(public_id=card.public_id).delete()

    def test_zero_cost_card_reclaim_has_no_fake_refund_entry(self):
        software, _, _, _, snapshot = self._create_plan_graph(software_id="free-reclaim-tool", quota_cost=0, test_only=True)
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        result = generate_license_batch(
            actor=self.downstream_a.user,
            software_id=software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="free-reclaim",
        )
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        reclaim_license_card(actor=self.downstream_a.user, card_public_id=card.public_id, idempotency_key="reclaim-request-free")
        self.assertEqual(LicenseCard.objects.get(public_id=card.public_id).status, "reclaimed")
        self.assertFalse(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").exists())

    def test_admin_can_reclaim_after_downstream_profile_is_deleted(self):
        self._credit(20)
        result = self._generate(key="reclaim-after-delete")
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        public_id = self.downstream_a.public_id
        leftover = get_quota_account(self.downstream_a).available_balance
        if leftover:
            debit_quota(
                actor=self.admin,
                downstream=self.downstream_a,
                amount=leftover,
                reason="删除前扣光",
                idempotency_key="reclaim-after-delete-clear",
                operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
            )
        archive_downstream(actor=self.admin, public_id=public_id, reason="删除前归档")
        delete_archived_downstream(actor=self.admin, public_id=public_id, reason="删除测试账号")
        reclaim_license_card(actor=self.admin, card_public_id=card.public_id, idempotency_key="reclaim-request-deleted")
        self.assertEqual(QuotaAccount.objects.get(downstream_public_id=public_id).available_balance, 5)
        self.assertEqual(LicenseCard.objects.get(public_id=card.public_id).status, "reclaimed")


class LicenseBatchViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(actor=self.admin, username="demo_downstream", password="Downstream-password-123")
        self.software = create_software(actor=self.admin, software_id="page-tool", name="Page Tool", status=SoftwareStatus.ACTIVE)
        create_profile(actor=self.admin, software_id="page-tool", profile_id="stable", client_id="page-tool-windows", status=ProfileStatus.ACTIVE)
        policy = create_policy_version(actor=self.admin, software_id="page-tool", profile_id="stable", version="policy-1", status=PolicyStatus.ACTIVE)
        self.plan, self.snapshot = create_plan(
            actor=self.admin,
            software_id="page-tool",
            profile_id="stable",
            policy_version=policy.version,
            name="页面测试卡",
            duration_seconds=60,
            quota_cost=10,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id="page-tool",
            enabled=True,
            all_plans_allowed=True,
        )
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=20,
            reason="页面授权卡密测试额度",
            idempotency_key="page-credit",
        )

    def test_production_legacy_batch_view_is_gone(self):
        client = Client()
        client.post(reverse("accounts:downstream_login"), {"username": "demo_downstream", "password": "Downstream-password-123"})
        response = client.get(reverse("licensing:batch_list"))
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)
        self.assertNotContains(response, "旧批次入口已停用", status_code=410)

    def test_downstream_can_preview_confirm_and_reveal_card(self):
        client = Client()
        login_response = client.post(
            reverse("accounts:downstream_login"),
            {"username": "demo_downstream", "password": "Downstream-password-123"},
        )
        self.assertEqual(login_response.status_code, 302)
        preview_response = client.post(
            reverse("licensing:batch_list"),
            {"action": "preview", "software": "page-tool", "plan": self.plan.pk, "quantity": 2},
        )
        self.assertContains(preview_response, CONTROL_ROOM_COPY, status_code=410)
        generated = client.post(
            reverse("licensing:batch_list"),
            {"action": "confirm", "software_id": "page-tool", "plan_snapshot_id": "1", "quantity": 2, "idempotency_key": "x", "preview_token": "x"},
        )
        self.assertContains(generated, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(LicenseCard.objects.count(), 0)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 20)
        result = generate_license_batch(
            actor=self.downstream.user,
            software_id="page-tool",
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="html-reveal-closed",
        )
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        reveal = client.post(reverse("licensing:card_reveal", kwargs={"public_id": card.public_id}))
        self.assertContains(reveal, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(reveal, "LC-", status_code=410)

    def test_confirm_cannot_change_quantity_after_preview(self):
        client = Client()
        login_response = client.post(
            reverse("accounts:downstream_login"),
            {"username": "demo_downstream", "password": "Downstream-password-123"},
        )
        self.assertEqual(login_response.status_code, 302)
        preview_response = client.post(
            reverse("licensing:batch_list"),
            {"action": "preview", "software": "page-tool", "plan": self.plan.pk, "quantity": 2},
        )
        self.assertContains(preview_response, CONTROL_ROOM_COPY, status_code=410)
        response = client.post(
            reverse("licensing:batch_list"),
            {
                "action": "confirm",
                "software_id": "page-tool",
                "plan_snapshot_id": str(self.snapshot.snapshot_id),
                "quantity": 1,
                "idempotency_key": "tamper",
                "preview_token": "tamper",
            },
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(LicenseCardBatch.objects.count(), 0)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 20)

    def test_downstream_can_reclaim_unused_card_from_batch_page(self):
        client = Client()
        client.post(
            reverse("accounts:downstream_login"),
            {"username": "demo_downstream", "password": "Downstream-password-123"},
        )
        result = generate_license_batch(
            actor=self.downstream.user,
            software_id="page-tool",
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="html-reclaim-closed",
        )
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        response = client.post(
            reverse("licensing:card_reclaim", kwargs={"public_id": card.public_id}),
            {"idempotency_key": str(card.public_id)},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(LicenseCard.objects.get(public_id=card.public_id).status, "unused")
        self.assertEqual(get_quota_account(self.downstream).available_balance, 10)

    def test_export_is_audited_and_contains_only_redacted_metadata(self):
        client = Client()
        client.post(
            reverse("accounts:downstream_login"),
            {"username": "demo_downstream", "password": "Downstream-password-123"},
        )
        result = generate_license_batch(
            actor=self.downstream.user,
            software_id="page-tool",
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="html-export-closed",
        )
        card = LicenseCard.objects.get(public_id=result.cards[0].public_id)
        plaintext = decrypt_license_card(card.card_ciphertext)
        response = client.post(reverse("licensing:batch_export", kwargs={"batch_id": card.batch.batch_id}))
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotIn(plaintext.encode("utf-8"), response.content)
        self.assertFalse(AuditEvent.objects.filter(action="license_batch.export").exists())

    def test_admin_cannot_open_downstream_license_page(self):
        client = Client()
        client.force_login(self.admin)
        self.assertEqual(client.get(reverse("licensing:batch_list")).status_code, 403)


class LicenseSnapshotImmutabilityTests(TestCase):
    def test_snapshot_and_policy_cannot_be_mutated_or_deleted(self):
        admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        software = create_software(actor=admin, software_id="immutable-tool", name="Immutable Tool", status=SoftwareStatus.ACTIVE)
        profile = create_profile(actor=admin, software_id=software.software_id, profile_id="stable", client_id="immutable-tool-windows", status=ProfileStatus.ACTIVE)
        policy = create_policy_version(actor=admin, software_id=software.software_id, profile_id=profile.profile_id, version="policy-1", status=PolicyStatus.ACTIVE)
        _, snapshot = create_plan(actor=admin, software_id=software.software_id, profile_id=profile.profile_id, policy_version=policy.version, name="固定快照", duration_seconds=60, quota_cost=1, status=PlanStatus.ACTIVE)

        policy.status = PolicyStatus.ARCHIVED
        with self.assertRaises(ValueError):
            policy.save()
        with self.assertRaises(ValueError):
            policy.delete()
        snapshot.duration_seconds = 3600
        with self.assertRaises(ValueError):
            snapshot.save()
        with self.assertRaises(ValueError):
            snapshot.delete()


@unittest.skipUnless(connection.vendor == "postgresql", "SQLite 不提供 PostgreSQL 行锁语义；在 PostgreSQL 环境运行并发验收")
class LicenseConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(actor=self.admin, username="parallel-downstream", password="Downstream-password-123")
        software = create_software(actor=self.admin, software_id="parallel-tool", name="Parallel Tool", status=SoftwareStatus.ACTIVE)
        create_profile(actor=self.admin, software_id=software.software_id, profile_id="stable", client_id="parallel-tool-windows", status=ProfileStatus.ACTIVE)
        policy = create_policy_version(actor=self.admin, software_id=software.software_id, profile_id="stable", version="policy-1", status=PolicyStatus.ACTIVE)
        self.plan, self.snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            policy_version=policy.version,
            name="并发套餐",
            duration_seconds=60,
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

    def _worker(self, barrier: threading.Barrier, *, key: str):
        close_old_connections()
        try:
            actor = User.objects.get(pk=self.downstream.user.pk)
            barrier.wait(timeout=10)
            try:
                result = generate_license_batch(
                    actor=actor,
                    software_id=self.software_id,
                    plan_snapshot_id=self.snapshot.snapshot_id,
                    quantity=1,
                    idempotency_key=key,
                )
                return str(result.batch.batch_id)
            except LicenseOperationError as exc:
                return exc.code
        finally:
            close_old_connections()

    def test_same_key_concurrent_generation_returns_one_batch(self):
        credit_quota(actor=self.admin, downstream=self.downstream, amount=20, reason="并发发卡准备", idempotency_key="parallel-credit")
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self._worker(barrier, key="parallel-same-key"), (1, 2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(LicenseCardBatch.objects.count(), 1)
        self.assertEqual(LicenseCard.objects.count(), 1)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_issue").count(), 1)

    def test_different_keys_cannot_overspend_one_account(self):
        credit_quota(actor=self.admin, downstream=self.downstream, amount=5, reason="额度刚好一张", idempotency_key="parallel-exact-credit")
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda key: self._worker(barrier, key=key), ("parallel-key-a", "parallel-key-b")))
        self.assertEqual(sum(result.startswith("INSUFFICIENT") for result in results), 1)
        self.assertEqual(LicenseCardBatch.objects.count(), 1)
        self.assertEqual(LicenseCard.objects.count(), 1)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 0)

    def test_concurrent_reclaim_refunds_one_entry(self):
        credit_quota(actor=self.admin, downstream=self.downstream, amount=10, reason="并发回收准备", idempotency_key="parallel-reclaim-credit")
        result = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="parallel-reclaim-issue",
        )
        card_id = result.cards[0].public_id
        barrier = threading.Barrier(2)

        def reclaim(_index):
            close_old_connections()
            try:
                actor = User.objects.get(pk=self.downstream.user.pk)
                barrier.wait(timeout=10)
                result = reclaim_license_card(actor=actor, card_public_id=card_id, idempotency_key=f"parallel-reclaim-request-{_index}")
                return str(result.entry.public_id) if result.entry else "zero-cost"
            except LicenseOperationError as exc:
                return exc.code
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reclaim, (1, 2)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="license_card_reclaim").count(), 1)
    def test_concurrent_same_lifecycle_key_archives_one_license_card(self):
        credit_quota(actor=self.admin, downstream=self.downstream, amount=5, reason="并发归档授权卡准备", idempotency_key="parallel-lifecycle-license-credit")
        result = generate_license_batch(
            actor=self.downstream.user,
            software_id=self.software_id,
            plan_snapshot_id=self.snapshot.snapshot_id,
            quantity=1,
            idempotency_key="parallel-lifecycle-license-issue",
        )
        card = LicenseCard.objects.get(pk=result.cards[0].public_id)
        card.status = "revoked"
        card.revoked_at = timezone.now() - timedelta(days=1)
        card.save(_allow_mutation=True)
        barrier = threading.Barrier(2)

        def archive(_index):
            close_old_connections()
            try:
                actor = User.objects.get(pk=self.admin.pk)
                barrier.wait(timeout=10)
                result = archive_license_cards(
                    actor=actor,
                    card_ids=[card.public_id],
                    reason="并发归档授权卡",
                    idempotency_key="parallel-lifecycle-license-archive",
                )
                return ("ok", bool(result.get("repeated")))
            except LicenseOperationError as exc:
                return ("error", exc.code)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(archive, (1, 2)))
        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertEqual(LicenseCard.objects.get(pk=card.pk).status, "archived")
        self.assertEqual(LicenseCardLifecycleOperation.objects.filter(idempotency_key="parallel-lifecycle-license-archive").count(), 1)
