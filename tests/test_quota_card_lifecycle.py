from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.credits.models import (
    QuotaCard,
    QuotaCardBatch,
    QuotaCardStatus,
    QuotaCardTombstone,
    QuotaLedgerEntry,
)
from authorization_platform.credits.services import issue_quota_card_batch
from authorization_platform.credits.models import QuotaLedgerOperation


User = get_user_model()


class QuotaCardLifecycleApiTests(TestCase):
    """Archive/delete lifecycle for quota cards (admin-only)."""

    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(
            username="qc-lifecycle-admin", password="Admin-password-123"
        )
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="qc-lifecycle-downstream",
            password="Downstream-password-123",
        )

    def _issue_one(self) -> QuotaCard:
        batch, issued = issue_quota_card_batch(
            actor=self.admin,
            amount=100,
            quantity=1,
            idempotency_key=f"qc-lifecycle-issue-{issued_nonce()}",
        )
        return QuotaCard.objects.get(public_id=issued[0].public_id)

    def _admin_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.get(reverse("accounts:api_session"))
        client.force_login(self.admin)
        return client

    def _downstream_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.get(reverse("accounts:api_session"))
        response = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": "qc-lifecycle-downstream",
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 200)
        return client

    def _post(self, client: Client, url: str, payload: dict, *, key: str):
        return client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def _archive(self, client: Client, card_ids, *, key: str):
        return self._post(
            client,
            reverse("credits:api_manage_quota_card_archive"),
            {"card_ids": [str(c) for c in card_ids], "reason": "测试归档额度兑换码"},
            key=key,
        )

    def _delete(self, client: Client, card_ids, *, key: str):
        return self._post(
            client,
            reverse("credits:api_manage_quota_card_delete"),
            {"card_ids": [str(c) for c in card_ids], "reason": "测试删除额度兑换码"},
            key=key,
        )

    def _revoke(self, client: Client, card: QuotaCard, *, key: str):
        return self._post(
            client,
            reverse("credits:api_revoke_quota_card", kwargs={"public_id": card.public_id}),
            {"reason": "测试作废额度兑换码"},
            key=key,
        )

    def _make_terminal(self, card: QuotaCard, status: str, *, days_ago: int = 31) -> QuotaCard:
        terminal_at = timezone.now() - timezone.timedelta(days=days_ago)
        if status == QuotaCardStatus.REVOKED:
            card.status = QuotaCardStatus.REVOKED
            card.revoked_at = terminal_at
        elif status == QuotaCardStatus.REDEEMED:
            card.status = QuotaCardStatus.REDEEMED
            card.redeemed_at = terminal_at
        card.save(_allow_mutation=True)
        card.refresh_from_db()
        return card

    def test_quota_card_and_batch_querysets_are_immutable(self):
        card = self._issue_one()
        with self.assertRaises(ValueError):
            QuotaCard.objects.filter(pk=card.pk).update(status=QuotaCardStatus.ARCHIVED)
        with self.assertRaises(ValueError):
            QuotaCard.objects.filter(pk=card.pk).delete()
        with self.assertRaises(ValueError):
            QuotaCardBatch.objects.filter(pk=card.batch_id).update(quantity=2)
        with self.assertRaises(ValueError):
            QuotaCardBatch.objects.filter(pk=card.batch_id).delete()


        card = self._issue_one()
        self._revoke(self._admin_client(), card, key="revoke-early")
        self._make_terminal(card, QuotaCardStatus.REVOKED, days_ago=1)
        response = self._archive(self._admin_client(), [card.public_id], key="early-archive")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["archived_count"], 1)

    def test_archive_revoked_card_after_grace_then_delete(self):
        card = self._issue_one()
        self._revoke(self._admin_client(), card, key="revoke-ok")
        self._make_terminal(card, QuotaCardStatus.REVOKED)
        archived = self._archive(self._admin_client(), [card.public_id], key="arc-one")
        self.assertEqual(archived.status_code, 200)
        self.assertEqual(archived.json()["archived_count"], 1)
        deleted = self._delete(self._admin_client(), [card.public_id], key="del-one")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json()["deleted_count"], 1)
        card.refresh_from_db()
        self.assertEqual(card.status, QuotaCardStatus.DELETED_TOMBSTONE)
        self.assertTrue(
            QuotaCardTombstone.objects.filter(card_public_id=card.public_id).exists()
        )
        self.assertTrue(
            AuditEvent.objects.filter(
                action="quota_card.delete", object_public_id=str(card.public_id)
            ).exists()
        )
        # 已删除卡从库存列表排除
        listing = self._admin_client().get(reverse("credits:api_manage_credits"))
        body = listing.json()
        visible = [item["public_id"] for item in body["cards"]]
        self.assertNotIn(str(card.public_id), visible)

    def test_archive_unissued_card_requires_revoke_first(self):
        card = self._issue_one()
        response = self._archive(self._admin_client(), [card.public_id], key="arc-unissued")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "QUOTA_CARD_NOT_ARCHIVABLE")

    def test_delete_requires_archived_first(self):
        card = self._issue_one()
        self._revoke(self._admin_client(), card, key="revoke-del")
        self._make_terminal(card, QuotaCardStatus.REVOKED)
        response = self._delete(self._admin_client(), [card.public_id], key="del-unarchived")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "QUOTA_CARD_NOT_DELETABLE")

    def test_idempotent_replay_and_conflict(self):
        card = self._issue_one()
        self._revoke(self._admin_client(), card, key="revoke-ip")
        self._make_terminal(card, QuotaCardStatus.REVOKED)
        first = self._archive(self._admin_client(), [card.public_id], key="ip-key")
        self.assertEqual(first.status_code, 200)
        second = self._archive(self._admin_client(), [card.public_id], key="ip-key")
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["repeated"])
        other = self._issue_one()
        self._revoke(self._admin_client(), other, key="revoke-ip2")
        self._make_terminal(other, QuotaCardStatus.REVOKED)
        conflict = self._archive(self._admin_client(), [other.public_id], key="ip-key")
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_downstream_rejected(self):
        card = self._issue_one()
        self._revoke(self._admin_client(), card, key="revoke-down")
        self._make_terminal(card, QuotaCardStatus.REVOKED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-down").status_code, 200)
        response = self._delete(self._downstream_client(), [card.public_id], key="down-del")
        self.assertEqual(response.status_code, 403)

    def test_reveal_rejected_after_delete(self):
        card = self._issue_one()
        self._revoke(self._admin_client(), card, key="revoke-rev")
        self._make_terminal(card, QuotaCardStatus.REVOKED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-rev").status_code, 200)
        self.assertEqual(self._delete(self._admin_client(), [card.public_id], key="del-rev").status_code, 200)
        from authorization_platform.credits.services import decrypt_quota_card

        search = self._post(
            self._admin_client(),
            reverse("credits:api_search_quota_card"),
            {"code": decrypt_quota_card(card.card_ciphertext)},
            key="search-after-delete",
        )
        self.assertEqual(search.status_code, 404)
        response = self._post(
            self._admin_client(),
            reverse("credits:api_reveal_quota_card", kwargs={"public_id": card.public_id}),
            {},
            key="reveal-after-delete",
        )
        self.assertEqual(response.status_code, 404)

    def test_issue_replay_after_delete_does_not_return_plaintext(self):
        issue_key = "qc-lifecycle-issue-replay-deleted"
        admin = self._admin_client()
        issued = self._post(
            admin,
            reverse("credits:api_issue_quota_cards"),
            {"amount": 100, "quantity": 1},
            key=issue_key,
        )
        self.assertEqual(issued.status_code, 201)
        plaintext = issued.json()["items"][0]["code"]
        card = QuotaCard.objects.get(public_id=issued.json()["items"][0]["public_id"])
        self._revoke(admin, card, key="revoke-issue-replay")
        self._make_terminal(card, QuotaCardStatus.REVOKED)
        self.assertEqual(self._archive(admin, [card.public_id], key="arc-issue-replay").status_code, 200)
        self.assertEqual(self._delete(admin, [card.public_id], key="del-issue-replay").status_code, 200)
        card_count = QuotaCard.objects.count()
        replay = self._post(
            admin,
            reverse("credits:api_issue_quota_cards"),
            {"amount": 100, "quantity": 1},
            key=issue_key,
        )
        self.assertEqual(replay.status_code, 404)
        self.assertEqual(replay.json()["error"]["code"], "QUOTA_CARD_NOT_FOUND")
        self.assertNotIn(plaintext, json.dumps(replay.json()))
        self.assertEqual(QuotaCard.objects.count(), card_count)
        card.refresh_from_db()
        self.assertEqual(card.status, QuotaCardStatus.DELETED_TOMBSTONE)
        self.assertTrue(card.card_ciphertext)

    def test_redeemed_card_delete_keeps_ledger(self):
        from authorization_platform.credits.models import QuotaLedgerDirection
        from authorization_platform.credits.services import get_quota_account

        card = self._issue_one()
        self._make_terminal(card, QuotaCardStatus.REDEEMED)
        card.redeemed_by_public_id = self.downstream.public_id
        card.save(_allow_mutation=True)
        account = get_quota_account(self.downstream)
        # 模拟兑换流水已产生
        QuotaLedgerEntry.objects.create(
            account=account,
            downstream_public_id=self.downstream.public_id,
            direction=QuotaLedgerDirection.CREDIT,
            amount=100,
            operation_type=QuotaLedgerOperation.CARD_REDEEM,
            source_type="quota_card",
            source_public_id=str(card.public_id),
            idempotency_key=f"redeem-ledger-{card.public_id}",
            request_hash="test-hash",
            balance_before=0,
            balance_after=100,
        )
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-red").status_code, 200)
        deleted = self._delete(self._admin_client(), [card.public_id], key="del-red")
        self.assertEqual(deleted.status_code, 200)
        # 流水保留、墓碑保留
        self.assertTrue(
            QuotaLedgerEntry.objects.filter(source_public_id=str(card.public_id)).exists()
        )
        self.assertTrue(
            QuotaCardTombstone.objects.filter(card_public_id=card.public_id).exists()
        )


def issued_nonce():
    import uuid

    return uuid.uuid4().hex[:10]
