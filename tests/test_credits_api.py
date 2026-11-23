from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.services import (
    AccountOperationError,
    archive_downstream,
    create_downstream_direct,
    delete_archived_downstream,
    set_downstream_status,
)
from authorization_platform.accounts.models import DownstreamStatus
from authorization_platform.audit.models import AuditEvent
from authorization_platform.credits.models import QuotaAccount, QuotaCard, QuotaCardStatus, QuotaLedgerEntry, QuotaLedgerOperation
from authorization_platform.credits.services import credit_quota, debit_quota


User = get_user_model()


class CreditApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(
            actor=self.admin,
            username="downstream-a",
            password="Downstream-password-123",
        )
        self.downstream_b = create_downstream_direct(
            actor=self.admin,
            username="downstream-b",
            password="Downstream-password-123",
        )
        self.manage_url = reverse("credits:api_manage_credits")
        self.issue_url = reverse("credits:api_issue_quota_cards")
        self.search_url = reverse("credits:api_search_quota_card")
        self.settings_url = reverse("credits:api_update_quota_settings")
        self.public_settings_url = reverse("credits:api_public_quota_settings")
        self.downstream_url = reverse("credits:api_downstream_credits")

    def _admin_client(self) -> Client:
        client = Client()
        client.force_login(self.admin)
        return client

    def _downstream_client(self, username: str = "downstream-a") -> Client:
        client = Client()
        response = client.post(
            reverse("accounts:downstream_login"),
            {"username": username, "password": "Downstream-password-123"},
        )
        self.assertEqual(response.status_code, 302)
        return client

    @staticmethod
    def _headers(key: str) -> dict[str, str]:
        return {"HTTP_IDEMPOTENCY_KEY": key, "HTTP_X_REQUEST_ID": f"api-{key}"}

    def test_public_purchase_link_is_empty_until_admin_saves_it(self):
        self.assertIsNone(self.client.get(self.public_settings_url).json()["purchase_url"])
        response = self._admin_client().post(
            self.settings_url,
            data={"purchase_url": "https://shop.example/quota"},
            content_type="application/json",
            **self._headers("settings-1"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get(self.public_settings_url).json()["purchase_url"], "https://shop.example/quota")

    def test_purchase_link_old_idempotency_key_replays_without_overwriting_newer_value(self):
        client = self._admin_client()
        first = client.post(
            self.settings_url,
            data={"purchase_url": "https://first.example/quota"},
            content_type="application/json",
            **self._headers("settings-first"),
        )
        self.assertEqual(first.status_code, 200)
        newer = client.post(
            self.settings_url,
            data={"purchase_url": "https://second.example/quota"},
            content_type="application/json",
            **self._headers("settings-second"),
        )
        self.assertEqual(newer.status_code, 200)

        replay = client.post(
            self.settings_url,
            data={"purchase_url": "https://first.example/quota"},
            content_type="application/json",
            **self._headers("settings-first"),
        )

        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["purchase_url"], "https://first.example/quota")
        self.assertEqual(self.client.get(self.public_settings_url).json()["purchase_url"], "https://second.example/quota")

    def test_purchase_link_conflict_and_idempotency_scope_are_enforced(self):
        client = self._admin_client()
        first = client.post(
            self.settings_url,
            data={"purchase_url": "https://first.example/quota"},
            content_type="application/json",
            **self._headers("settings-scoped"),
        )
        self.assertEqual(first.status_code, 200)
        conflict = client.post(
            self.settings_url,
            data={"purchase_url": "https://different.example/quota"},
            content_type="application/json",
            **self._headers("settings-scoped"),
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

        other_admin = User.objects.create_superuser(username="admin-b", password="Admin-password-123")
        other_client = Client()
        other_client.force_login(other_admin)
        other = other_client.post(
            self.settings_url,
            data={"purchase_url": "https://different.example/quota"},
            content_type="application/json",
            **self._headers("settings-scoped"),
        )
        self.assertEqual(other.status_code, 200)
        self.assertEqual(other.json()["purchase_url"], "https://different.example/quota")

    def test_admin_issue_is_unbound_and_idempotent_without_batch_payload(self):
        client = self._admin_client()
        response = client.post(
            self.issue_url,
            data={"amount": 100, "quantity": 2},
            content_type="application/json",
            **self._headers("issue-1"),
        )
        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertEqual(len(payload["items"]), 2)
        self.assertNotIn("batch_id", payload)
        self.assertTrue(all(item["code"].startswith("QC-") for item in payload["items"]))
        self.assertEqual(QuotaCard.objects.filter(target_downstream_public_id__isnull=True).count(), 2)

        repeated = client.post(
            self.issue_url,
            data={"amount": 100, "quantity": 2},
            content_type="application/json",
            **self._headers("issue-1"),
        )
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual([item["code"] for item in repeated.json()["items"]], [item["code"] for item in payload["items"]])
        self.assertEqual(QuotaCard.objects.count(), 2)

        conflicting = client.post(
            self.issue_url,
            data={"amount": 200, "quantity": 2},
            content_type="application/json",
            **self._headers("issue-1"),
        )
        self.assertEqual(conflicting.status_code, 409)

    def test_admin_can_search_quota_code_without_returning_plaintext(self):
        client = self._admin_client()
        issued = client.post(
            self.issue_url,
            data={"amount": 100, "quantity": 1},
            content_type="application/json",
            **self._headers("search-code"),
        )
        self.assertEqual(issued.status_code, 201)
        code = issued.json()["items"][0]["code"]

        response = client.post(
            self.search_url,
            data={"code": code},
            content_type="application/json",
            **self._headers("search-request"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["item"]["amount"], 100)
        self.assertNotIn("code", response.json()["item"])

    def test_any_logged_in_downstream_redeems_and_cannot_issue(self):
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 125, "quantity": 1},
            content_type="application/json",
            **self._headers("issue-redeem"),
        ).json()["items"][0]

        downstream_b = self._downstream_client("downstream-b")
        self.assertEqual(
            downstream_b.post(
                self.issue_url,
                data={"amount": 1, "quantity": 1},
                content_type="application/json",
                **self._headers("downstream-forbidden"),
            ).status_code,
            403,
        )
        redeemed = downstream_b.post(
            self.downstream_url,
            data={"card_code": issued["code"]},
            content_type="application/json",
            **self._headers("redeem-b"),
            HTTP_X_FORWARDED_FOR="198.51.100.12",
        )
        self.assertEqual(redeemed.status_code, 200)
        self.assertEqual(redeemed.json()["account"]["available_balance"], 125)
        self.assertEqual(QuotaLedgerEntry.objects.count(), 1)
        card = QuotaCard.objects.get()
        self.assertEqual(card.status, QuotaCardStatus.REDEEMED)
        self.assertEqual(card.redeemed_by_public_id, self.downstream_b.public_id)

        data = downstream_b.get(self.downstream_url).json()
        self.assertEqual(data["account"]["available_balance"], 125)
        self.assertEqual(data["ledger_pagination"]["total"], 1)
        self.assertEqual(data["today_consumed"], 0)
        by_type = downstream_b.get(self.downstream_url, {"ledger_q": "兑换"}).json()
        self.assertEqual(by_type["ledger_pagination"]["total"], 1)
        missing = downstream_b.get(self.downstream_url, {"ledger_q": "不存在的流水"}).json()
        self.assertEqual(missing["ledger_pagination"]["total"], 0)

    def test_downstream_cannot_read_or_change_admin_credits_and_admin_can_revoke(self):
        downstream = self._downstream_client()
        self.assertEqual(downstream.get(self.manage_url).status_code, 403)
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 50, "quantity": 1},
            content_type="application/json",
            **self._headers("issue-revoke"),
        ).json()["items"][0]
        revoke_url = reverse("credits:api_revoke_quota_card", kwargs={"public_id": issued["public_id"]})
        revoked = admin.post(
            revoke_url,
            data={"reason": "误发作废"},
            content_type="application/json",
            **self._headers("revoke-1"),
        )
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(revoked.json()["item"]["status"], QuotaCardStatus.REVOKED)

    def test_admin_read_returns_single_card_rows_and_fixed_page_metadata(self):
        admin = self._admin_client()
        admin.post(
            self.issue_url,
            data={"amount": 10, "quantity": 6},
            content_type="application/json",
            **self._headers("issue-six"),
        )
        payload = admin.get(self.manage_url).json()
        self.assertEqual(len(payload["cards"]), 5)
        self.assertEqual(payload["cards_pagination"]["total"], 6)
        self.assertEqual(payload["cards_pagination"]["total_pages"], 2)
        self.assertNotIn("batch", payload["cards"][0])

    def test_admin_read_returns_current_and_archived_quota_scopes(self):
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 10, "quantity": 2},
            content_type="application/json",
            **self._headers("issue-scope"),
        ).json()["items"]
        revoke = admin.post(
            reverse("credits:api_revoke_quota_card", kwargs={"public_id": issued[0]["public_id"]}),
            data={"reason": "分类测试"},
            content_type="application/json",
            **self._headers("revoke-scope"),
        )
        self.assertEqual(revoke.status_code, 200)
        archive = admin.post(
            reverse("credits:api_manage_quota_card_archive"),
            data={"card_ids": [issued[0]["public_id"]], "reason": "分类测试"},
            content_type="application/json",
            **self._headers("archive-scope"),
        )
        self.assertEqual(archive.status_code, 200)
        current = admin.get(self.manage_url, {"scope": "current"}).json()
        archived = admin.get(self.manage_url, {"scope": "archived"}).json()
        all_cards = admin.get(self.manage_url, {"scope": "all"}).json()
        self.assertEqual(current["cards_pagination"]["total"], 1)
        self.assertEqual(archived["cards_pagination"]["total"], 1)
        self.assertEqual(all_cards["cards_pagination"]["total"], 2)
        self.assertEqual(archived["cards"][0]["status"], QuotaCardStatus.ARCHIVED)

    def test_admin_read_filters_quota_cards_by_redeemed_username(self):
        cache.clear()
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 20, "quantity": 1},
            content_type="application/json",
            **self._headers("issue-downstream-filter"),
        ).json()["items"][0]
        downstream = self._downstream_client("downstream-a")
        redeemed = downstream.post(
            self.downstream_url,
            data=json.dumps({"card_code": issued["code"]}),
            content_type="application/json",
            **self._headers("redeem-downstream-filter"),
        )
        self.assertEqual(redeemed.status_code, 200)
        filtered = admin.get(self.manage_url, {"redeemed_by": "downstream-a"}).json()
        self.assertEqual(filtered["cards_pagination"]["total"], 1)
        self.assertEqual(filtered["cards"][0]["redeemed_by"], "downstream-a")

    def test_admin_quota_list_q_matches_username_and_amount_not_suffix(self):
        cache.clear()
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 20, "quantity": 1},
            content_type="application/json",
            **self._headers("issue-quota-q"),
        ).json()["items"][0]
        downstream = self._downstream_client("downstream-a")
        redeemed = downstream.post(
            self.downstream_url,
            data=json.dumps({"card_code": issued["code"]}),
            content_type="application/json",
            **self._headers("redeem-quota-q"),
        )
        self.assertEqual(redeemed.status_code, 200)
        public_id = issued["public_id"]
        suffix = issued["code"][-4:]
        by_name = admin.get(self.manage_url, {"q": "downstream-a"}).json()
        self.assertIn(public_id, {row["public_id"] for row in by_name["cards"]})
        by_amount = admin.get(self.manage_url, {"q": "20"}).json()
        self.assertIn(public_id, {row["public_id"] for row in by_amount["cards"]})
        by_suffix = admin.get(self.manage_url, {"q": suffix}).json()
        self.assertNotIn(public_id, {row["public_id"] for row in by_suffix["cards"]})
        by_code = admin.get(self.manage_url, {"q": issued["code"]}).json()
        self.assertIn(public_id, {row["public_id"] for row in by_code["cards"]})
        too_long = admin.get(self.manage_url, {"q": "x" * 129})
        self.assertEqual(too_long.status_code, 400)
        self.assertEqual(too_long.json()["error"]["code"], "INVALID_QUERY")

    def test_admin_can_reveal_quota_code_again_after_list_refresh(self):
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 100, "quantity": 1},
            content_type="application/json",
            **self._headers("issue-reveal-again"),
        ).json()["items"][0]
        reveal_url = reverse("credits:api_reveal_quota_card", kwargs={"public_id": issued["public_id"]})

        listing = admin.get(self.manage_url)
        self.assertNotIn("code", listing.json()["cards"][0])
        self.assertEqual(listing.json()["cards"][0]["code_suffix"], issued["code"][-4:])
        self.assertTrue(listing.json()["cards"][0]["masked_code"].endswith(issued["code"][-4:]))
        self.assertEqual(admin.get(reveal_url).status_code, 405)
        first = admin.post(reveal_url, data="{}", content_type="application/json")
        second = admin.post(reveal_url, data="{}", content_type="application/json")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["code"], issued["code"])
        self.assertEqual(second.json()["code"], issued["code"])
        self.assertNotIn("code", first.json()["item"])
        self.assertEqual(first["Cache-Control"], "no-store")
        self.assertFalse(
            AuditEvent.objects.filter(
                action="quota_card.reveal",
                outcome="success",
                object_public_id=issued["public_id"],
            ).exists()
        )

    def test_quota_reveal_is_admin_scoped_and_rate_limited(self):
        cache.clear()
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 100, "quantity": 1},
            content_type="application/json",
            **self._headers("issue-reveal-rate"),
        ).json()["items"][0]
        reveal_url = reverse("credits:api_reveal_quota_card", kwargs={"public_id": issued["public_id"]})
        downstream = self._downstream_client()
        self.assertEqual(downstream.post(reveal_url, data="{}", content_type="application/json").status_code, 403)

        with override_settings(QUOTA_CARD_REVEAL_RATE_LIMIT=1):
            first = admin.post(reveal_url, data="{}", content_type="application/json")
            limited = admin.post(reveal_url, data="{}", content_type="application/json")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")
        cache.clear()

    def test_mutating_api_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(
            self.issue_url,
            data='{"amount": 10, "quantity": 1}',
            content_type="application/json",
            **self._headers("csrf-1"),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(QuotaCard.objects.count(), 0)

    def test_admin_adjust_api_credits_and_recovers_with_idempotency(self):
        admin = self._admin_client()
        url = reverse("credits:api_adjust_credits")
        first = admin.post(
            url,
            data={
                "downstream_public_id": str(self.downstream_a.public_id),
                "adjustment_type": "credit",
                "amount": 80,
                "reason": "人工充值验收",
            },
            content_type="application/json",
            **self._headers("adjust-credit-1"),
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["item"]["operation_type"], "manual_credit")
        self.assertEqual(first.json()["item"]["delta"], 80)
        replay = admin.post(
            url,
            data={
                "downstream_public_id": str(self.downstream_a.public_id),
                "adjustment_type": "credit",
                "amount": 80,
                "reason": "人工充值验收",
            },
            content_type="application/json",
            **self._headers("adjust-credit-1"),
        )
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["item"]["public_id"], first.json()["item"]["public_id"])
        recovered = admin.post(
            url,
            data={
                "downstream_public_id": str(self.downstream_a.public_id),
                "adjustment_type": "debit",
                "amount": 30,
                "reason": "管理员扣回验收",
            },
            content_type="application/json",
            **self._headers("adjust-debit-1"),
        )
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered.json()["item"]["operation_type"], "admin_adjustment")
        self.assertEqual(recovered.json()["item"]["delta"], -30)
        consumed = self._downstream_client("downstream-a").get(self.downstream_url).json()
        self.assertEqual(consumed["today_consumed"], 30)
        forbidden = self._downstream_client().post(
            url,
            data={
                "downstream_public_id": str(self.downstream_a.public_id),
                "adjustment_type": "credit",
                "amount": 10,
                "reason": "下游越权",
            },
            content_type="application/json",
            **self._headers("adjust-forbidden"),
        )
        self.assertEqual(forbidden.status_code, 403)

    def test_admin_credit_exports_are_audited_and_capped(self):
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 10, "quantity": 2},
            content_type="application/json",
            **self._headers("export-issue"),
        )
        self.assertEqual(issued.status_code, 201)
        public_id = issued.json()["items"][0]["public_id"]
        revoked = admin.post(
            reverse("credits:api_revoke_quota_card", kwargs={"public_id": public_id}),
            data={"reason": "导出筛选验收"},
            content_type="application/json",
            **self._headers("export-revoke"),
        )
        self.assertEqual(revoked.status_code, 200)
        ledger = admin.get(reverse("credits:api_manage_credit_ledger_export"))
        cards = admin.get(reverse("credits:api_manage_quota_card_export"))
        issued_only = admin.get(reverse("credits:api_manage_quota_card_export"), {"status": "issued"})
        revoked_only = admin.get(reverse("credits:api_manage_quota_card_export"), {"status": "revoked"})
        self.assertEqual(ledger.status_code, 200)
        self.assertEqual(cards.status_code, 200)
        self.assertEqual(issued_only.status_code, 200)
        self.assertEqual(revoked_only.status_code, 200)
        self.assertIn("text/csv", ledger["Content-Type"])
        issued_body = issued_only.content.decode("utf-8")
        revoked_body = revoked_only.content.decode("utf-8")
        self.assertEqual(len([line for line in issued_body.splitlines() if line.strip()]), 2)
        self.assertEqual(len([line for line in revoked_body.splitlines() if line.strip()]), 2)
        self.assertIn("未兑换", issued_body)
        self.assertNotIn("已作废", issued_body)
        self.assertIn("已作废", revoked_body)
        self.assertTrue(AuditEvent.objects.filter(action="quota.ledger.export").exists())
        self.assertTrue(AuditEvent.objects.filter(action="quota_card.export").exists())

    def test_admin_credit_csv_times_use_beijing_wall_clock(self):
        instant = datetime(2026, 9, 5, 16, 0, 0, tzinfo=timezone.utc)
        admin = self._admin_client()
        issued = admin.post(
            self.issue_url,
            data={"amount": 50, "quantity": 1},
            content_type="application/json",
            **self._headers("export-beijing-issue"),
        ).json()["items"][0]
        redeemed = self._downstream_client("downstream-b").post(
            self.downstream_url,
            data={"card_code": issued["code"]},
            content_type="application/json",
            **self._headers("export-beijing-redeem"),
        )
        self.assertEqual(redeemed.status_code, 200)
        card = QuotaCard.objects.get(public_id=issued["public_id"])
        card.issued_at = instant
        card.redeemed_at = instant
        card.save(update_fields=("issued_at", "redeemed_at"), _allow_mutation=True)
        entry = QuotaLedgerEntry.objects.get()
        entry.occurred_at = instant
        entry.save(update_fields=("occurred_at",), _allow_mutation=True)

        cards = admin.get(reverse("credits:api_manage_quota_card_export"))
        ledger = admin.get(reverse("credits:api_manage_credit_ledger_export"))
        self.assertEqual(cards.status_code, 200)
        self.assertEqual(ledger.status_code, 200)
        card_rows = list(csv.reader(io.StringIO(cards.content.decode("utf-8-sig"))))
        ledger_rows = list(csv.reader(io.StringIO(ledger.content.decode("utf-8-sig"))))
        issued_at = card_rows[1][3]
        redeemed_at = card_rows[1][5]
        occurred_at = ledger_rows[1][0]
        self.assertEqual(issued_at, "2026-09-06 00:00:00")
        self.assertEqual(redeemed_at, "2026-09-06 00:00:00")
        self.assertEqual(occurred_at, "2026-09-06 00:00:00")
        self.assertNotIn("2026-09-05 16:00:00", cards.content.decode("utf-8-sig"))
        self.assertNotIn("2026-09-05 16:00:00", ledger.content.decode("utf-8-sig"))

        listing = admin.get(self.manage_url)
        self.assertEqual(listing.status_code, 200)
        listed_card = next(item for item in listing.json()["cards"] if item["public_id"] == issued["public_id"])
        listed_entry = listing.json()["ledger"][0]
        self.assertIn("2026-09-05T16:00:00", listed_card["issued_at"])
        self.assertIn("2026-09-05T16:00:00", listed_card["redeemed_at"])
        self.assertIn("2026-09-05T16:00:00", listed_entry["occurred_at"])
        self.assertNotIn("2026-09-06T00:00:00", listed_card["issued_at"])

    def test_admin_operating_balance_excludes_deleted_downstream_accounts(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=80,
            reason="墓碑合计对照 A",
            idempotency_key="operating-a",
        )
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_b,
            amount=30,
            reason="墓碑合计对照 B",
            idempotency_key="operating-b",
        )
        admin = self._admin_client()
        before = admin.get(self.manage_url).json()
        self.assertEqual(before["operating_available_balance"], 110)
        self.assertEqual(sum(item["available_balance"] for item in before["accounts"]), 110)
        with self.assertRaises(AccountOperationError) as leftover_archive:
            archive_downstream(actor=self.admin, public_id=self.downstream_b.public_id, reason="归档仍应计入合计")
        self.assertEqual(leftover_archive.exception.code, "BALANCE_NOT_CLEARED")
        debit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=80,
            reason="删除前扣光",
            idempotency_key="operating-clear-a",
            operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
        )
        public_id = self.downstream_a.public_id
        archive_downstream(actor=self.admin, public_id=public_id, reason="删除前归档")
        delete_archived_downstream(actor=self.admin, public_id=public_id, reason="清理账号")
        after = admin.get(self.manage_url).json()
        self.assertEqual(after["operating_available_balance"], 30)
        self.assertEqual(sum(item["available_balance"] for item in after["accounts"]), 30)
        deleted = next(item for item in after["accounts"] if item["status"] == "deleted")
        self.assertEqual(deleted["available_balance"], 0)
        self.assertIsNone(deleted["username"])
        self.assertEqual(deleted["downstream_public_id"], str(public_id))
        live_b = next(item for item in after["accounts"] if item["downstream_public_id"] == str(self.downstream_b.public_id))
        self.assertEqual(live_b["available_balance"], 30)
        account = QuotaAccount.objects.get(downstream_public_id=public_id)
        self.assertIsNone(account.downstream)
        self.assertEqual(account.available_balance, 0)

    def test_admin_credits_lists_active_downstream_without_quota_account(self):
        zero = create_downstream_direct(
            actor=self.admin,
            username="downstream-zero",
            password="Downstream-password-123",
        )
        paused = create_downstream_direct(
            actor=self.admin,
            username="downstream-paused",
            password="Downstream-secret-456",
        )
        set_downstream_status(
            actor=self.admin,
            public_id=paused.public_id,
            status=DownstreamStatus.SUSPENDED,
            reason="暂停后不应进现调额窗",
        )
        self.assertFalse(QuotaAccount.objects.filter(downstream_public_id=zero.public_id).exists())
        self.assertFalse(QuotaAccount.objects.filter(downstream_public_id=paused.public_id).exists())
        admin = self._admin_client()
        payload = admin.get(self.manage_url).json()
        listed = next(item for item in payload["accounts"] if item["downstream_public_id"] == str(zero.public_id))
        self.assertEqual(listed["username"], "downstream-zero")
        self.assertEqual(listed["status"], "active")
        self.assertEqual(listed["available_balance"], 0)
        self.assertFalse(QuotaAccount.objects.filter(downstream_public_id=zero.public_id).exists())
        self.assertFalse(
            any(item["downstream_public_id"] == str(paused.public_id) for item in payload["accounts"])
        )
        adjust = admin.post(
            reverse("credits:api_adjust_credits"),
            data={
                "downstream_public_id": str(zero.public_id),
                "adjustment_type": "credit",
                "amount": 15,
                "reason": "零账户下游首次调额",
            },
            content_type="application/json",
            **self._headers("adjust-zero-account"),
        )
        self.assertEqual(adjust.status_code, 200)
        self.assertTrue(QuotaAccount.objects.filter(downstream_public_id=zero.public_id).exists())
        self.assertEqual(QuotaAccount.objects.get(downstream_public_id=zero.public_id).available_balance, 15)

    def test_recover_deleted_credits_debits_tombstone_and_live_adjust_stays_404(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=80,
            reason="墓碑扣回准备",
            idempotency_key="recover-credit-a",
        )
        public_id = self.downstream_a.public_id
        with self.assertRaises(AccountOperationError) as leftover_archive:
            archive_downstream(actor=self.admin, public_id=public_id, reason="删除前归档")
        self.assertEqual(leftover_archive.exception.code, "BALANCE_NOT_CLEARED")
        debit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=80,
            reason="删除前扣光",
            idempotency_key="recover-clear-a",
            operation_type=QuotaLedgerOperation.ADMIN_ADJUSTMENT,
        )
        archive_downstream(actor=self.admin, public_id=public_id, reason="删除前归档")
        delete_archived_downstream(actor=self.admin, public_id=public_id, reason="清理账号")
        admin = self._admin_client()
        live = admin.post(
            reverse("credits:api_adjust_credits"),
            data={
                "downstream_public_id": str(public_id),
                "adjustment_type": "debit",
                "amount": 10,
                "reason": "现窗不该扣墓碑",
            },
            content_type="application/json",
            **self._headers("recover-live-adjust"),
        )
        self.assertEqual(live.status_code, 404)
        recovered = admin.post(
            reverse("credits:api_recover_deleted_credits"),
            data={
                "downstream_public_id": str(public_id),
                "amount": 80,
                "reason": "扣回已删除下游余额",
            },
            content_type="application/json",
            **self._headers("recover-deleted-1"),
        )
        self.assertEqual(recovered.status_code, 409)
        self.assertEqual(recovered.json()["error"]["code"], "INSUFFICIENT_QUOTA")
        account = QuotaAccount.objects.get(downstream_public_id=public_id)
        self.assertEqual(account.available_balance, 0)
