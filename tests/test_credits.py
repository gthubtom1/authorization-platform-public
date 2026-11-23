from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection
from django.core.cache import cache
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.services import (
    AccountOperationError,
    archive_downstream,
    create_downstream_direct,
    delete_archived_downstream,
)
from authorization_platform.accounts.models import DownstreamProfile
from authorization_platform.audit.models import AuditEvent
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY
from authorization_platform.credits.models import (
    QuotaAccount,
    QuotaCard,
    QuotaCardBatch,
    QuotaCardLifecycleOperation,
    QuotaCardStatus,
    QuotaLedgerEntry,
    QuotaLedgerOperation,
    QuotaPurchaseUrlOperation,
)
from authorization_platform.credits.services import (
    QuotaOperationError,
    archive_quota_cards,
    credit_quota,
    debit_quota,
    decrypt_quota_card,
    get_quota_platform_settings,
    get_quota_account,
    issue_quota_card_batch,
    migrate_quota_card_encryption_keys,
    recover_downstream_credits,
    rebuild_quota_balance,
    redeem_quota_card,
    revoke_quota_card,
    update_quota_purchase_url,
)
from authorization_platform.accounts import services as account_services


User = get_user_model()


class CreditServiceTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(actor=self.admin, username="downstream-a", password="Downstream-password-123")
        self.downstream_b = create_downstream_direct(actor=self.admin, username="downstream-b", password="Downstream-password-123")

    def _issue(self, *, amount=100, key="issue-1"):
        batch, issued = issue_quota_card_batch(
            actor=self.admin,
            amount=amount,
            quantity=1,
            idempotency_key=key,
        )
        return batch, issued[0]

    def test_issue_stores_hash_and_ciphertext_and_is_idempotent(self):
        batch, issued = self._issue()
        card = QuotaCard.objects.get(public_id=issued.public_id)

        self.assertNotEqual(card.card_hash, issued.code)
        self.assertNotEqual(card.card_ciphertext, issued.code)
        self.assertEqual(decrypt_quota_card(card.card_ciphertext), issued.code)
        self.assertIsNone(card.target_downstream_public_id)
        self.assertEqual(batch.quantity, 1)

        repeated_batch, repeated_cards = issue_quota_card_batch(
            actor=self.admin,
            amount=100,
            quantity=1,
            idempotency_key="issue-1",
        )
        self.assertEqual(repeated_batch.public_id, batch.public_id)
        self.assertEqual(repeated_cards[0].code, issued.code)
        self.assertEqual(QuotaCard.objects.count(), 1)

    def test_issue_idempotency_key_is_scoped_to_creator(self):
        other_admin = User.objects.create_superuser(username="admin-2", password="Admin-password-456")
        batch_a, issued_a = issue_quota_card_batch(
            actor=self.admin,
            amount=100,
            quantity=1,
            idempotency_key="shared-key",
        )
        batch_b, issued_b = issue_quota_card_batch(
            actor=other_admin,
            amount=100,
            quantity=1,
            idempotency_key="shared-key",
        )
        self.assertNotEqual(batch_a.public_id, batch_b.public_id)
        self.assertNotEqual(issued_a[0].code, issued_b[0].code)
        self.assertEqual(QuotaCard.objects.count(), 2)

    def test_quota_card_dedicated_key_and_legacy_rotation_are_repeatable(self):
        current_key = Fernet.generate_key().decode("ascii")
        legacy_key = Fernet.generate_key().decode("ascii")
        with override_settings(
            QUOTA_CARD_ENCRYPTION_KEY=current_key,
            QUOTA_CARD_ENCRYPTION_KEY_VERSION="v2",
            QUOTA_CARD_LEGACY_ENCRYPTION_KEY=legacy_key,
            QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION="v1",
        ):
            _, issued = self._issue(key="quota-key-rotation-1")
            card = QuotaCard.objects.get(public_id=issued.public_id)
            self.assertEqual(card.encryption_key_version, "v2")
            legacy_ciphertext = Fernet(legacy_key.encode("ascii")).encrypt(issued.code.encode("utf-8")).decode("ascii")
            card.card_ciphertext = legacy_ciphertext
            card.encryption_key_version = "v1"
            card.save(update_fields=("card_ciphertext", "encryption_key_version"), _allow_mutation=True)

            dry_run = migrate_quota_card_encryption_keys(from_version="v1", to_version="v2", dry_run=True)
            self.assertEqual((dry_run.scanned, dry_run.migrated), (1, 0))
            card.refresh_from_db()
            self.assertEqual(card.encryption_key_version, "v1")
            self.assertEqual(decrypt_quota_card(card.card_ciphertext, key_version="v1"), issued.code)

            applied = migrate_quota_card_encryption_keys(from_version="v1", to_version="v2", dry_run=False)
            self.assertEqual((applied.scanned, applied.migrated), (1, 1))
            card.refresh_from_db()
            self.assertEqual(card.encryption_key_version, "v2")
            self.assertEqual(decrypt_quota_card(card.card_ciphertext, key_version="v2"), issued.code)

            repeated = migrate_quota_card_encryption_keys(from_version="v1", to_version="v2", dry_run=False)
            self.assertEqual((repeated.scanned, repeated.migrated), (0, 0))
            with self.assertRaises(QuotaOperationError) as downgrade:
                migrate_quota_card_encryption_keys(from_version="v2", to_version="v1", dry_run=False)
            self.assertEqual(downgrade.exception.code, "KEY_ROTATION_INVALID")

    def test_quota_card_key_rotation_rolls_back_on_corrupt_ciphertext(self):
        current_key = Fernet.generate_key().decode("ascii")
        legacy_key = Fernet.generate_key().decode("ascii")
        with override_settings(
            QUOTA_CARD_ENCRYPTION_KEY=current_key,
            QUOTA_CARD_ENCRYPTION_KEY_VERSION="v2",
            QUOTA_CARD_LEGACY_ENCRYPTION_KEY=legacy_key,
            QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION="v1",
        ):
            _, issued = issue_quota_card_batch(actor=self.admin, amount=10, quantity=2, idempotency_key="quota-key-rotation-corrupt")
            cards = list(QuotaCard.objects.order_by("issued_at", "public_id"))
            for card in cards:
                card.encryption_key_version = "v1"
                card.card_ciphertext = Fernet(legacy_key.encode("ascii")).encrypt(
                    decrypt_quota_card(card.card_ciphertext, key_version="v2").encode("utf-8")
                ).decode("ascii")
                card.save(update_fields=("card_ciphertext", "encryption_key_version"), _allow_mutation=True)
            original_ciphertext = cards[0].card_ciphertext
            cards[1].card_ciphertext = "not-a-fernet-token"
            cards[1].save(update_fields=("card_ciphertext",), _allow_mutation=True)

            with self.assertRaises(QuotaOperationError) as error:
                migrate_quota_card_encryption_keys(from_version="v1", to_version="v2", dry_run=False)
            self.assertEqual(error.exception.code, "CREDENTIAL_UNAVAILABLE")
            cards[0].refresh_from_db()
            self.assertEqual(cards[0].encryption_key_version, "v1")
            self.assertEqual(cards[0].card_ciphertext, original_ciphertext)

    def test_issue_rejects_target_downstream(self):
        with self.assertRaises(QuotaOperationError) as error:
            issue_quota_card_batch(
                actor=self.admin,
                amount=100,
                quantity=1,
                target_downstream=self.downstream_a,
                idempotency_key="targeted-issue",
            )
        self.assertEqual(error.exception.code, "TARGET_DOWNSTREAM_FORBIDDEN")
        self.assertEqual(QuotaCard.objects.count(), 0)

    def test_issue_requires_an_idempotency_key(self):
        with self.assertRaises(QuotaOperationError) as error:
            issue_quota_card_batch(actor=self.admin, amount=100, quantity=1, idempotency_key=None)
        self.assertEqual(error.exception.code, "IDEMPOTENCY_REQUIRED")

    def test_redeem_creates_one_entry_and_repeated_same_key_does_not_change_balance(self):
        _, issued = self._issue()

        first = redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code)
        second = redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code)
        account = get_quota_account(self.downstream_a)

        self.assertFalse(first.repeated)
        self.assertTrue(second.repeated)
        self.assertEqual(account.available_balance, 100)
        self.assertEqual(QuotaLedgerEntry.objects.filter(account=account).count(), 1)
        self.assertEqual(first.entry.public_id, second.entry.public_id)
        self.assertEqual(QuotaCard.objects.get(public_id=issued.public_id).status, QuotaCardStatus.REDEEMED)

    def test_redeem_same_card_with_different_key_is_rejected(self):
        _, issued = self._issue()
        redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code, idempotency_key="redeem-a")

        with self.assertRaises(QuotaOperationError) as error:
            redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code, idempotency_key="redeem-b")
        self.assertEqual(error.exception.code, "QUOTA_CARD_UNAVAILABLE")
        self.assertEqual(QuotaLedgerEntry.objects.count(), 1)

    def test_any_active_downstream_can_redeem_and_archived_downstream_cannot(self):
        _, issued = self._issue()
        result = redeem_quota_card(actor=self.downstream_b.user, card_code=issued.code, ip_address="203.0.113.18")
        self.assertEqual(result.entry.balance_after, 100)
        card = QuotaCard.objects.get(public_id=issued.public_id)
        self.assertEqual(card.redeemed_by_public_id, self.downstream_b.public_id)
        self.assertNotEqual(card.redeemed_ip_digest, "203.0.113.18")

        self.downstream_a.status = "closed"
        self.downstream_a.user.is_active = False
        self.downstream_a.user.save(update_fields=("is_active",))
        self.downstream_a.save(update_fields=("status", "updated_at"))
        with self.assertRaises(QuotaOperationError) as archived:
            redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code)
        self.assertEqual(archived.exception.code, "DOWNSTREAM_NOT_ACTIVE")

    def test_manual_credit_is_idempotent_and_conflicting_retry_is_rejected(self):
        first = credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=50,
            reason="浏览器验收",
            idempotency_key="manual-1",
        )
        repeated = credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=50,
            reason="浏览器验收",
            idempotency_key="manual-1",
        )
        self.assertEqual(first.public_id, repeated.public_id)
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 50)
        with self.assertRaises(QuotaOperationError) as conflict:
            credit_quota(
                actor=self.admin,
                downstream=self.downstream_a,
                amount=60,
                reason="改写请求",
                idempotency_key="manual-1",
            )
        self.assertEqual(conflict.exception.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(QuotaLedgerEntry.objects.count(), 1)

    def test_credit_rechecks_downstream_after_archive_before_service(self):
        stale_profile = DownstreamProfile.objects.get(pk=self.downstream_a.pk)
        archive_downstream(
            actor=self.admin,
            public_id=stale_profile.public_id,
            reason="先归档再测试充值",
        )

        with self.assertRaises(QuotaOperationError) as error:
            credit_quota(
                actor=self.admin,
                downstream=stale_profile,
                amount=17,
                reason="归档后不应充值",
                idempotency_key="credit-after-archive",
            )

        self.assertEqual(error.exception.code, "DOWNSTREAM_NOT_ACTIVE")
        self.assertFalse(QuotaAccount.objects.filter(downstream_public_id=stale_profile.public_id).exists())
        self.assertEqual(QuotaLedgerEntry.objects.count(), 0)

    def test_balance_is_rebuilt_from_ledger_and_ledger_is_immutable(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=25, reason="初始额度", idempotency_key="manual-2")
        account = get_quota_account(self.downstream_a)
        entry = account.entries.get()
        self.assertEqual(rebuild_quota_balance(account), account.available_balance)
        entry.reason = "尝试改写"
        with self.assertRaises(ValueError):
            entry.save()
        with self.assertRaises(ValueError):
            entry.delete()
        with self.assertRaises(ValueError):
            QuotaLedgerEntry.objects.filter(public_id=entry.public_id).update(reason="绕过服务改写")
        with self.assertRaises(ValueError):
            QuotaLedgerEntry.objects.filter(public_id=entry.public_id).delete()

    def test_account_and_card_lifecycle_cannot_be_mutated_directly(self):
        _, issued = self._issue()
        card = QuotaCard.objects.get(public_id=issued.public_id)
        with self.assertRaises(ValueError):
            card.save()
        with self.assertRaises(ValueError):
            card.delete()
        account = get_quota_account(self.downstream_a)
        account.available_balance = 99
        with self.assertRaises(ValueError):
            account.save()

    def test_debit_uses_same_ledger_and_refuses_negative_balance(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=50, reason="准备扣除", idempotency_key="manual-debit-credit")
        entry = debit_quota(
            actor=self.downstream_a.user,
            downstream=self.downstream_a,
            amount=30,
            reason="生成授权卡密",
            idempotency_key="license-batch-1",
        )
        self.assertEqual(entry.direction, "debit")
        self.assertEqual(entry.balance_after, 20)
        with self.assertRaises(QuotaOperationError) as insufficient:
            debit_quota(
                actor=self.downstream_a.user,
                downstream=self.downstream_a,
                amount=21,
                reason="额度不足测试",
                idempotency_key="license-batch-2",
            )
        self.assertEqual(insufficient.exception.code, "INSUFFICIENT_QUOTA")
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 20)

    def test_admin_recovery_is_idempotent_and_refuses_overspend(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=50, reason="准备管理员回收", idempotency_key="recovery-credit")
        first = recover_downstream_credits(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=30,
            reason="异常额度回收",
            idempotency_key="recovery-1",
        )
        repeated = recover_downstream_credits(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=30,
            reason="异常额度回收",
            idempotency_key="recovery-1",
        )
        self.assertEqual(first.public_id, repeated.public_id)
        self.assertEqual(first.operation_type, "admin_adjustment")
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 20)
        with self.assertRaises(QuotaOperationError) as conflict:
            recover_downstream_credits(
                actor=self.admin,
                downstream=self.downstream_a,
                amount=20,
                reason="改写管理员回收请求",
                idempotency_key="recovery-1",
            )
        self.assertEqual(conflict.exception.code, "IDEMPOTENCY_CONFLICT")
        with self.assertRaises(QuotaOperationError) as insufficient:
            recover_downstream_credits(
                actor=self.admin,
                downstream=self.downstream_a,
                amount=21,
                reason="超额回收测试",
                idempotency_key="recovery-2",
            )
        self.assertEqual(insufficient.exception.code, "INSUFFICIENT_QUOTA")
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type="admin_adjustment").count(), 1)

    def test_downstream_cannot_use_admin_recovery_action(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=20, reason="权限测试", idempotency_key="recovery-permission-credit")
        with self.assertRaises(PermissionDenied):
            recover_downstream_credits(
                actor=self.downstream_a.user,
                downstream=self.downstream_a,
                amount=1,
                reason="越权回收",
                idempotency_key="recovery-forbidden",
            )
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 20)

    def test_downstream_cannot_call_admin_adjustment_through_debit_primitive(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=20, reason="底层权限测试", idempotency_key="debit-permission-credit")
        with self.assertRaises(PermissionDenied):
            debit_quota(
                actor=self.downstream_a.user,
                downstream=self.downstream_a,
                amount=1,
                reason="伪装管理员扣额",
                idempotency_key="debit-permission-forbidden",
                operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
            )
        self.assertEqual(get_quota_account(self.downstream_a).available_balance, 20)

    def test_audit_events_cannot_be_modified_or_deleted(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=5, reason="审计不可变测试", idempotency_key="audit-immutable-credit")
        event = AuditEvent.objects.get(action="quota.manual_credit", outcome="success")
        with self.assertRaises(ValueError):
            event.save()
        with self.assertRaises(ValueError):
            event.delete()
        with self.assertRaises(ValueError):
            AuditEvent.objects.filter(public_id=event.public_id).update(reason_code="tampered")
        with self.assertRaises(ValueError):
            AuditEvent.objects.filter(public_id=event.public_id).delete()

    def test_archive_and_delete_reject_unclear_balance_then_keep_history_after_clearing(self):
        credit_quota(actor=self.admin, downstream=self.downstream_a, amount=25, reason="保留历史", idempotency_key="manual-3")
        public_id = self.downstream_a.public_id
        with self.assertRaises(AccountOperationError) as ctx:
            archive_downstream(actor=self.admin, public_id=public_id, reason="停用测试")
        self.assertEqual(ctx.exception.code, "BALANCE_NOT_CLEARED")
        debit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=25,
            reason="归档前扣光",
            idempotency_key="clear-before-archive",
            operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
        )
        archive_downstream(actor=self.admin, public_id=public_id, reason="停用测试")
        account = QuotaAccount.objects.get(downstream_public_id=public_id)
        account.available_balance = 25
        account.save(update_fields=("available_balance", "updated_at"), _allow_mutation=True)
        with self.assertRaises(AccountOperationError) as leftover_delete:
            delete_archived_downstream(actor=self.admin, public_id=public_id, reason="清理账号")
        self.assertEqual(leftover_delete.exception.code, "BALANCE_NOT_CLEARED")
        account.available_balance = 0
        account.save(update_fields=("available_balance", "updated_at"), _allow_mutation=True)
        delete_archived_downstream(actor=self.admin, public_id=public_id, reason="清理账号")
        account = QuotaAccount.objects.get(downstream_public_id=public_id)
        self.assertIsNone(account.downstream)
        self.assertEqual(account.available_balance, 0)
        self.assertGreaterEqual(account.entries.count(), 2)

    def test_failed_redemption_does_not_log_plaintext_card(self):
        _, issued = self._issue()
        with self.assertRaises(QuotaOperationError):
            redeem_quota_card(actor=self.downstream_b.user, card_code="QC-INVALID")
        audit_text = json.dumps(list(AuditEvent.objects.values("action", "metadata")), ensure_ascii=False)
        self.assertNotIn(issued.code, audit_text)

    def test_admin_can_revoke_unredeemed_card_once(self):
        _, issued = self._issue(key="revoke-issue")
        first = revoke_quota_card(
            actor=self.admin,
            card_public_id=issued.public_id,
            reason="误发作废",
            idempotency_key="revoke-1",
        )
        repeated = revoke_quota_card(
            actor=self.admin,
            card_public_id=issued.public_id,
            reason="误发作废",
            idempotency_key="revoke-1",
        )
        self.assertEqual(first.public_id, repeated.public_id)
        self.assertEqual(QuotaCard.objects.get(public_id=issued.public_id).status, QuotaCardStatus.REVOKED)
        with self.assertRaises(QuotaOperationError) as redeem_error:
            redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code)
        self.assertEqual(redeem_error.exception.code, "QUOTA_CARD_UNAVAILABLE")

    def test_revoke_requires_admin_and_rejects_redeemed_card(self):
        _, issued = self._issue(key="revoke-permission-issue")
        with self.assertRaises(PermissionDenied):
            revoke_quota_card(
                actor=self.downstream_a.user,
                card_public_id=issued.public_id,
                reason="越权作废",
                idempotency_key="revoke-forbidden",
            )
        redeem_quota_card(actor=self.downstream_a.user, card_code=issued.code)
        with self.assertRaises(QuotaOperationError) as revoke_error:
            revoke_quota_card(
                actor=self.admin,
                card_public_id=issued.public_id,
                reason="已兑换不能作废",
                idempotency_key="revoke-redeemed",
            )
        self.assertEqual(revoke_error.exception.code, "QUOTA_CARD_UNAVAILABLE")

    def test_purchase_link_is_persisted_and_validated(self):
        updated = update_quota_purchase_url(
            actor=self.admin,
            purchase_url="https://shop.example/quota",
            idempotency_key="settings-service-1",
        )
        self.assertEqual(updated.purchase_url, "https://shop.example/quota")
        self.assertEqual(get_quota_platform_settings().purchase_url, "https://shop.example/quota")
        with self.assertRaises(QuotaOperationError) as invalid:
            update_quota_purchase_url(
                actor=self.admin,
                purchase_url="javascript:alert(1)",
                idempotency_key="settings-service-2",
            )
        self.assertEqual(invalid.exception.code, "INVALID_PURCHASE_URL")

    def test_purchase_link_replays_old_key_without_overwriting_newer_setting(self):
        first = update_quota_purchase_url(
            actor=self.admin,
            purchase_url="https://first.example/quota",
            idempotency_key="settings-service-first",
        )
        update_quota_purchase_url(
            actor=self.admin,
            purchase_url="https://second.example/quota",
            idempotency_key="settings-service-second",
        )

        replay = update_quota_purchase_url(
            actor=self.admin,
            purchase_url="https://first.example/quota",
            idempotency_key="settings-service-first",
        )

        self.assertEqual(first.purchase_url, "https://first.example/quota")
        self.assertEqual(replay.purchase_url, "https://first.example/quota")
        self.assertEqual(get_quota_platform_settings().purchase_url, "https://second.example/quota")

    def test_purchase_link_conflict_and_scope_are_persistent(self):
        update_quota_purchase_url(
            actor=self.admin,
            purchase_url="https://first.example/quota",
            idempotency_key="settings-service-scoped",
        )
        with self.assertRaises(QuotaOperationError) as conflict:
            update_quota_purchase_url(
                actor=self.admin,
                purchase_url="https://different.example/quota",
                idempotency_key="settings-service-scoped",
            )
        self.assertEqual(conflict.exception.code, "IDEMPOTENCY_CONFLICT")

        other_admin = User.objects.create_superuser(username="admin-b", password="Admin-password-123")
        other_result = update_quota_purchase_url(
            actor=other_admin,
            purchase_url="https://different.example/quota",
            idempotency_key="settings-service-scoped",
        )
        self.assertEqual(other_result.purchase_url, "https://different.example/quota")
        operations = QuotaPurchaseUrlOperation.objects.filter(idempotency_key="settings-service-scoped")
        self.assertEqual(operations.count(), 2)
        operation = operations.first()
        with self.assertRaises(ValueError):
            operation.purchase_url = "https://tampered.example/quota"
            operation.save()
        with self.assertRaises(ValueError):
            operations.update(purchase_url="https://tampered.example/quota")
        with self.assertRaises(ValueError):
            operations.delete()


class CreditViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(actor=self.admin, username="demo_downstream", password="Downstream-password-123")

    def test_admin_can_issue_from_credit_center_and_reveal_is_post_only(self):
        client = Client()
        client.force_login(self.admin)
        page = client.get(reverse("credits:admin_dashboard"))
        self.assertContains(page, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(page, FORBIDDEN_API_COPY, status_code=410)
        response = client.post(
            reverse("credits:admin_dashboard"),
            {"action": "issue_cards", "issue_token": "unused", "amount": 100, "quantity": 1},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(QuotaCard.objects.count(), 0)
        _, issued_cards = issue_quota_card_batch(actor=self.admin, amount=100, quantity=1, idempotency_key="html-reveal-closed")
        card = issued_cards[0]
        self.assertEqual(client.get(reverse("credits:card_reveal", kwargs={"public_id": card.public_id})).status_code, 405)
        reveal = client.post(reverse("credits:card_reveal", kwargs={"public_id": card.public_id}))
        self.assertContains(reveal, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(reveal, card.code, status_code=410)

    def test_admin_can_recover_downstream_credits_from_credit_center(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=40,
            reason="页面回收准备",
            idempotency_key="page-recovery-credit",
        )
        client = Client()
        client.force_login(self.admin)
        page = client.get(reverse("credits:admin_dashboard"))
        self.assertContains(page, CONTROL_ROOM_COPY, status_code=410)
        response = client.post(
            reverse("credits:admin_dashboard"),
            {
                "action": "recover_credits",
                "recovery_token": "unused",
                "downstream": str(self.downstream.public_id),
                "amount": 15,
                "reason": "页面确认回收",
            },
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 40)
        self.assertFalse(AuditEvent.objects.filter(action="quota.admin_recovery", outcome="success").exists())

    def test_downstream_can_redeem_and_cannot_open_admin_center(self):
        batch, issued_cards = issue_quota_card_batch(actor=self.admin, amount=100, quantity=1, idempotency_key="view-issue")
        issued = issued_cards[0]
        self.assertEqual(batch.quantity, 1)
        client = Client()
        client.post(reverse("accounts:downstream_login"), {"username": "demo_downstream", "password": "Downstream-password-123"})
        self.assertEqual(client.get(reverse("credits:admin_dashboard")).status_code, 403)
        page = client.get(reverse("credits:downstream_ledger"))
        self.assertContains(page, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(page, "当前可用额度", status_code=410)
        response = client.post(reverse("credits:downstream_ledger"), {"card_code": issued.code})
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(QuotaCard.objects.get(public_id=issued.public_id).status, QuotaCardStatus.ISSUED)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 0)

    def test_admin_cannot_open_downstream_ledger_without_losing_session(self):
        client = Client()
        client.force_login(self.admin)
        self.assertEqual(client.get(reverse("credits:downstream_ledger")).status_code, 403)
        self.assertEqual(client.get(reverse("accounts:manage_dashboard")).status_code, 200)

    @override_settings(QUOTA_REDEEM_RATE_LIMIT=1)
    def test_downstream_redemption_is_rate_limited(self):
        cache.clear()
        client = Client()
        client.post(reverse("accounts:downstream_login"), {"username": "demo_downstream", "password": "Downstream-password-123"})
        first = client.post(reverse("credits:downstream_ledger"), {"card_code": "QC-INVALID"})
        self.assertContains(first, CONTROL_ROOM_COPY, status_code=410)
        second = client.post(reverse("credits:downstream_ledger"), {"card_code": "QC-INVALID-2"})
        self.assertContains(second, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(second, "兑换尝试过于频繁", status_code=410)
        cache.clear()

    def test_client_request_id_is_hashed_before_credit_audit(self):
        cache.clear()
        client = Client()
        client.post(reverse("accounts:downstream_login"), {"username": "demo_downstream", "password": "Downstream-password-123"})
        supplied = "QC-SENSITIVE-REQUEST-ID"
        response = client.post(
            reverse("credits:api_downstream_credits"),
            data=json.dumps({"card_code": "QC-INVALID"}),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="html-closed-request-id",
            HTTP_X_REQUEST_ID=supplied,
        )
        self.assertIn(response.status_code, {400, 404, 409})
        event = AuditEvent.objects.filter(action="quota_card.redeem").latest("occurred_at")
        self.assertNotIn(supplied, event.request_id)
        self.assertTrue(event.request_id.startswith("client-"))
        cache.clear()

    @override_settings(QUOTA_CARD_REVEAL_RATE_LIMIT=1)
    def test_card_reveal_is_rate_limited(self):
        cache.clear()
        _, issued_cards = issue_quota_card_batch(
            actor=self.admin,
            amount=100,
            quantity=1,
            idempotency_key="reveal-rate-limit",
        )
        client = Client()
        client.force_login(self.admin)
        first = client.post(reverse("credits:card_reveal", kwargs={"public_id": issued_cards[0].public_id}))
        self.assertContains(first, CONTROL_ROOM_COPY, status_code=410)
        second = client.post(
            reverse("credits:card_reveal", kwargs={"public_id": issued_cards[0].public_id}),
            follow=True,
        )
        self.assertContains(second, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(second, "查看额度卡过于频繁", status_code=410)
        cache.clear()


@unittest.skipUnless(connection.vendor == "postgresql", "SQLite 不提供 PostgreSQL 行锁语义；在 PostgreSQL 环境运行并发验收")
class CreditConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(actor=self.admin, username="parallel-downstream", password="Downstream-password-123")
        _, self.issued = issue_quota_card_batch(actor=self.admin, amount=100, quantity=1, idempotency_key="parallel-issue")

    def _recover(self, barrier: threading.Barrier, *, key: str, amount: int, reason: str):
        from django.db import close_old_connections

        close_old_connections()
        try:
            actor = User.objects.get(pk=self.admin.pk)
            downstream = DownstreamProfile.objects.get(pk=self.downstream.pk)
            barrier.wait(timeout=10)
            try:
                entry = recover_downstream_credits(
                    actor=actor,
                    downstream=downstream,
                    amount=amount,
                    reason=reason,
                    idempotency_key=key,
                )
                return ("ok", str(entry.public_id))
            except QuotaOperationError as exc:
                return ("error", exc.code)
        finally:
            close_old_connections()

    def test_concurrent_archive_and_credit_linearize_on_downstream_profile(self):
        get_quota_account(self.downstream)
        stale_profile = DownstreamProfile.objects.get(pk=self.downstream.pk)
        archive_lock_acquired = threading.Event()
        release_archive = threading.Event()
        archive_result = []
        credit_result = []
        errors = []
        original_balance_check = account_services._require_cleared_downstream_balance

        def gated_balance_check(profile):
            archive_lock_acquired.set()
            if not release_archive.wait(timeout=10):
                raise AssertionError("归档测试锁等待超时")
            return original_balance_check(profile)

        def run_archive():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET SESSION lock_timeout = '10000ms'")
                actor = User.objects.get(pk=self.admin.pk)
                archive_downstream(
                    actor=actor,
                    public_id=self.downstream.public_id,
                    reason="并发归档与充值",
                    request_id="parallel-archive-credit-archive",
                )
                archive_result.append("ok")
            except Exception as exc:
                errors.append(("archive", exc))
            finally:
                close_old_connections()

        def run_credit():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET SESSION lock_timeout = '10000ms'")
                actor = User.objects.get(pk=self.admin.pk)
                try:
                    credit_quota(
                        actor=actor,
                        downstream=stale_profile,
                        amount=17,
                        reason="并发归档与充值",
                        idempotency_key="parallel-archive-credit-credit",
                        request_id="parallel-archive-credit-credit",
                    )
                    credit_result.append(("ok", None))
                except QuotaOperationError as exc:
                    credit_result.append(("error", exc.code))
            except Exception as exc:
                errors.append(("credit", exc))
            finally:
                close_old_connections()

        with patch.object(account_services, "_require_cleared_downstream_balance", side_effect=gated_balance_check):
            archive_thread = threading.Thread(target=run_archive)
            credit_thread = threading.Thread(target=run_credit)
            archive_thread.start()
            self.assertTrue(archive_lock_acquired.wait(timeout=10))
            credit_thread.start()
            release_archive.set()
            archive_thread.join(timeout=15)
            credit_thread.join(timeout=15)

        self.assertFalse(archive_thread.is_alive())
        self.assertFalse(credit_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(archive_result, ["ok"])
        self.assertEqual(credit_result, [("error", "DOWNSTREAM_NOT_ACTIVE")])
        self.assertEqual(DownstreamProfile.objects.get(pk=self.downstream.pk).status, "closed")
        self.assertEqual(QuotaAccount.objects.get(downstream_public_id=self.downstream.public_id).available_balance, 0)
        self.assertEqual(QuotaLedgerEntry.objects.count(), 0)

    def test_concurrent_same_card_redeems_once(self):
        barrier = threading.Barrier(2)

        def redeem(index):
            from django.db import close_old_connections

            close_old_connections()
            try:
                actor = User.objects.get(pk=self.downstream.user.pk)
                barrier.wait(timeout=10)
                try:
                    result = redeem_quota_card(actor=actor, card_code=self.issued[0].code, idempotency_key=f"parallel-{index}")
                    return result.entry.public_id
                except QuotaOperationError:
                    return None
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(redeem, (1, 2)))
        self.assertEqual(len([result for result in results if result]), 1)
        self.assertEqual(QuotaLedgerEntry.objects.count(), 1)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 100)

    def test_concurrent_same_issue_key_returns_one_batch(self):
        barrier = threading.Barrier(2)

        def issue(_index):
            from django.db import close_old_connections

            close_old_connections()
            try:
                actor = User.objects.get(pk=self.admin.pk)
                barrier.wait(timeout=10)
                batch, cards = issue_quota_card_batch(
                    actor=actor,
                    amount=100,
                    quantity=1,
                    idempotency_key="parallel-same-issue-key",
                )
                return str(batch.public_id), cards[0].code
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(issue, (1, 2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(QuotaCardBatch.objects.filter(idempotency_key="parallel-same-issue-key").count(), 1)
        self.assertEqual(QuotaCard.objects.filter(batch__idempotency_key="parallel-same-issue-key").count(), 1)

    def test_concurrent_admin_recovery_with_same_key_debits_once(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=50,
            reason="并发管理员回收准备",
            idempotency_key="parallel-admin-recovery-credit",
        )
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: self._recover(
                        barrier,
                        key="parallel-admin-recovery-same-key",
                        amount=30,
                        reason="并发管理员回收",
                    ),
                    (1, 2),
                )
            )

        self.assertEqual(results[0][0], "ok")
        self.assertEqual(results[1][0], "ok")
        self.assertEqual(results[0][1], results[1][1])
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT).count(), 1)
        self.assertEqual(get_quota_account(self.downstream).available_balance, 20)

    def test_concurrent_admin_recovery_with_different_keys_cannot_overspend(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=50,
            reason="不同键并发管理员回收准备",
            idempotency_key="parallel-admin-recovery-overspend-credit",
        )
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda key: self._recover(
                        barrier,
                        key=key,
                        amount=50,
                        reason="不同键并发管理员回收",
                    ),
                    ("parallel-admin-recovery-key-a", "parallel-admin-recovery-key-b"),
                )
            )

        self.assertEqual(sum(result[0] == "ok" for result in results), 1)
        self.assertEqual(sum(result == ("error", "INSUFFICIENT_QUOTA") for result in results), 1)
        self.assertEqual(QuotaLedgerEntry.objects.filter(operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT).count(), 1)
    def test_concurrent_same_lifecycle_key_archives_one_quota_card(self):
        revoke_quota_card(
            actor=self.admin,
            card_public_id=self.issued[0].public_id,
            reason="并发归档前作废",
            idempotency_key="parallel-lifecycle-revoke",
        )
        barrier = threading.Barrier(2)

        def archive(_index):
            close_old_connections()
            try:
                actor = User.objects.get(pk=self.admin.pk)
                barrier.wait(timeout=10)
                result = archive_quota_cards(
                    actor=actor,
                    card_ids=[self.issued[0].public_id],
                    reason="并发归档额度码",
                    idempotency_key="parallel-lifecycle-archive",
                )
                return ("ok", bool(result.get("repeated")))
            except QuotaOperationError as exc:
                return ("error", exc.code)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(archive, (1, 2)))
        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertEqual(QuotaCard.objects.get(pk=self.issued[0].public_id).status, QuotaCardStatus.ARCHIVED)
        self.assertEqual(QuotaCardLifecycleOperation.objects.filter(idempotency_key="parallel-lifecycle-archive").count(), 1)
