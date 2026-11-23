from __future__ import annotations

import json
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import (
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    set_downstream_software_access,
)
from authorization_platform.credits.services import credit_quota
from authorization_platform.licensing.models import (
    LicenseCard,
    LicenseCardLifecycleOperation,
    LicenseCardStatus,
    LicenseCardTombstone,
    LicenseInstance,
)


User = get_user_model()


class LicenseLifecycleApiTests(TestCase):
    """Archive/delete lifecycle for terminal license cards (admin-only)."""

    def setUp(self):
        cache.clear()
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(
            username="lifecycle-admin", password="Admin-password-123"
        )
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="lifecycle-downstream",
            password="Downstream-password-123",
        )
        software = create_software(
            actor=self.admin,
            software_id="lifecycle-tool",
            name="Lifecycle Tool",
            status=SoftwareStatus.ACTIVE,
        )
        profile = create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="lifecycle-tool-client",
            status=ProfileStatus.ACTIVE,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        self.plan, self.snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="Lifecycle 月卡",
            duration_seconds=30 * 24 * 60 * 60,
            quota_cost=5,
            status=PlanStatus.ACTIVE,
        )
        self.software_id = software.software_id
        self.profile = profile
        self.policy = policy
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id=self.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        credit_quota(
            actor=self.admin,
            downstream=self.downstream,
            amount=100,
            reason="lifecycle 测试准备",
            idempotency_key="lifecycle-credit",
        )

    def _csrf(self, client: Client) -> dict[str, str]:
        response = client.get(reverse("accounts:api_session"))
        self.assertEqual(response.status_code, 200)
        return {"HTTP_X_CSRFTOKEN": client.cookies["csrftoken"].value}

    def _admin_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        return client

    def _downstream_client(self) -> Client:
        client = Client(enforce_csrf_checks=True)
        headers = self._csrf(client)
        response = client.post(
            reverse("accounts:api_login"),
            data=json.dumps(
                {
                    "username": "lifecycle-downstream",
                    "password": "Downstream-password-123",
                    "entrypoint": "downstream",
                }
            ),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 200)
        return client

    def _issue_one_card(self) -> LicenseCard:
        client = self._downstream_client()
        nonce = uuid.uuid4().hex[:10]
        preview = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": 1},
            key=f"lifecycle-preview-{nonce}",
        )
        self.assertEqual(preview.status_code, 200)
        payload = preview.json()
        issued = self._post_json(
            client,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": payload["snapshot_id"],
                "quantity": 1,
                "preview_token": payload["preview_token"],
            },
            key=f"lifecycle-issue-{nonce}",
        )
        self.assertIn(issued.status_code, (200, 201))
        public_id = issued.json()["items"][0]["public_id"]
        return LicenseCard.objects.get(public_id=public_id)

    def _post_json(self, client: Client, url: str, payload: dict, *, key: str):
        headers = self._csrf(client)
        headers["HTTP_IDEMPOTENCY_KEY"] = key
        return client.post(url, data=json.dumps(payload), content_type="application/json", **headers)

    def _archive(self, client: Client, card_ids, *, key: str, reason: str = "测试归档原因"):
        return self._post_json(
            client,
            reverse("licensing:api_manage_license_archive"),
            {"card_ids": [str(c) for c in card_ids], "reason": reason},
            key=key,
        )

    def _delete(self, client: Client, card_ids, *, key: str, reason: str = "测试删除原因"):
        return self._post_json(
            client,
            reverse("licensing:api_manage_license_delete"),
            {"card_ids": [str(c) for c in card_ids], "reason": reason},
            key=key,
        )

    def _make_terminal(self, card: LicenseCard, status: str, *, days_ago: int = 31) -> LicenseCard:
        now = timezone.now()
        terminal_at = now - timezone.timedelta(days=days_ago)
        if status == LicenseCardStatus.RECLAIMED:
            card.status = LicenseCardStatus.RECLAIMED
            card.reclaimed_at = terminal_at
        elif status == LicenseCardStatus.REVOKED:
            card.status = LicenseCardStatus.REVOKED
            card.revoked_at = terminal_at
        elif status == LicenseCardStatus.EXPIRED:
            card.status = LicenseCardStatus.EXPIRED
            card.expires_at = terminal_at
        card.save(_allow_mutation=True)
        card.refresh_from_db()
        return card

    def test_activated_card_past_expiry_can_archive_without_revalidation(self):
        card = self._issue_one_card()
        card.status = LicenseCardStatus.ACTIVATED
        card.activated_at = timezone.now() - timezone.timedelta(days=2)
        card.expires_at = timezone.now() - timezone.timedelta(days=1)
        card.save(_allow_mutation=True)
        response = self._archive(self._admin_client(), [card.public_id], key="archive-stale-expired")
        self.assertEqual(response.status_code, 200)
        card.refresh_from_db()
        self.assertEqual(card.status, LicenseCardStatus.ARCHIVED)

    def test_archive_terminal_card_is_immediate(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED, days_ago=1)
        response = self._archive(self._admin_client(), [card.public_id], key="early-archive")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["archived_count"], 1)

    def test_archive_reclaimed_card_after_grace(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        response = self._archive(self._admin_client(), [card.public_id], key="archive-reclaimed")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["archived_count"], 1)
        card.refresh_from_db()
        self.assertEqual(card.status, LicenseCardStatus.ARCHIVED)
        self.assertIsNotNone(card.archived_at)
        self.assertTrue(
            AuditEvent.objects.filter(action="license_card.archive", object_public_id=str(card.public_id)).exists()
        )

    def test_archive_expired_and_revoked_cards(self):
        expired = self._make_terminal(self._issue_one_card(), LicenseCardStatus.EXPIRED)
        revoked = self._make_terminal(self._issue_one_card(), LicenseCardStatus.REVOKED)
        response = self._archive(
            self._admin_client(),
            [expired.public_id, revoked.public_id],
            key="archive-both",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["archived_count"], 2)
        expired.refresh_from_db()
        revoked.refresh_from_db()
        self.assertEqual(expired.archived_from_status, LicenseCardStatus.EXPIRED)
        self.assertEqual(revoked.archived_from_status, LicenseCardStatus.REVOKED)

    def test_archive_unused_card_requires_reclaim_first(self):
        card = self._issue_one_card()
        response = self._archive(self._admin_client(), [card.public_id], key="archive-unused")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "CARD_NOT_ARCHIVABLE")

    def test_archive_card_with_active_authorization_rejected(self):
        card = self._issue_one_card()
        card.status = LicenseCardStatus.ACTIVATED
        card.activated_at = timezone.now()
        card.save(_allow_mutation=True)
        LicenseInstance.objects.create(
            license_card=card,
            software=card.software,
            profile=card.profile,
            plan_snapshot=card.plan_snapshot,
            policy_version=self.policy,
            current_downstream_public_id=card.current_downstream_public_id,
            client_id="lifecycle-client",
            target="desktop",
            arch="amd64",
            channel="stable",
            client_version="1.0.0",
            expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        response = self._archive(self._admin_client(), [card.public_id], key="archive-active")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "CARD_NOT_ARCHIVABLE")

    def test_archive_requires_admin(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        response = self._archive(self._downstream_client(), [card.public_id], key="downstream-archive")
        self.assertEqual(response.status_code, 403)

    def test_archive_idempotent_replay_and_conflict(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        first = self._archive(self._admin_client(), [card.public_id], key="replay-key")
        self.assertEqual(first.status_code, 200)
        second = self._archive(self._admin_client(), [card.public_id], key="replay-key")
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["repeated"])
        other = self._issue_one_card()
        self._make_terminal(other, LicenseCardStatus.RECLAIMED)
        conflict = self._archive(self._admin_client(), [other.public_id], key="replay-key")
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_delete_requires_archived_first(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        response = self._delete(self._admin_client(), [card.public_id], key="delete-unarchived")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "CARD_NOT_DELETABLE")

    def test_delete_archived_card_keeps_tombstone_and_audit(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-del").status_code, 200)
        response = self._delete(self._admin_client(), [card.public_id], key="del-1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted_count"], 1)
        card.refresh_from_db()
        self.assertEqual(card.status, LicenseCardStatus.DELETED_TOMBSTONE)
        tombstone = LicenseCardTombstone.objects.get(card_public_id=card.public_id)
        self.assertEqual(tombstone.card_hash, card.card_hash)
        self.assertEqual(tombstone.quota_cost, card.quota_cost)
        self.assertEqual(tombstone.terminal_status, LicenseCardStatus.RECLAIMED)
        self.assertEqual(
            str(tombstone.original_downstream_public_id),
            str(card.original_downstream_public_id),
        )
        self.assertTrue(
            AuditEvent.objects.filter(
                action="license_card.delete", object_public_id=str(card.public_id)
            ).exists()
        )
        entry = LicenseCardLifecycleOperation.objects.get(action="delete", idempotency_key="del-1")
        # 墓碑与幂等记录不可删除
        with self.assertRaises(ValueError):
            tombstone.delete()
        with self.assertRaises(ValueError):
            entry.delete()
        # 已删除卡从库存列表 API 排除
        listing = self._admin_client().get(reverse("licensing:api_manage_license_cards"))
        visible = [item["public_id"] for item in listing.json()["items"]]
        self.assertNotIn(str(card.public_id), visible)

    def test_delete_card_with_authorization_history_keeps_history(self):
        """Used cards (with an authorization instance) may also be deleted after
        the terminal grace; the card row becomes a tombstone while the
        authorization instance, devices, audit and quota ledger survive."""
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.REVOKED)
        instance = LicenseInstance.objects.create(
            license_card=card,
            software=card.software,
            profile=card.profile,
            plan_snapshot=card.plan_snapshot,
            policy_version=self.policy,
            current_downstream_public_id=card.current_downstream_public_id,
            client_id="lifecycle-client",
            target="desktop",
            arch="amd64",
            channel="stable",
            client_version="1.0.0",
            expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-h").status_code, 200)
        response = self._delete(self._admin_client(), [card.public_id], key="del-history")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted_count"], 1)
        card.refresh_from_db()
        self.assertEqual(card.status, LicenseCardStatus.DELETED_TOMBSTONE)
        # 授权实例保留（历史可追责），墓碑保留
        instance.refresh_from_db()
        self.assertEqual(instance.license_card_id, card.public_id)
        self.assertTrue(
            LicenseCardTombstone.objects.filter(card_public_id=card.public_id).exists()
        )
        self.assertTrue(
            AuditEvent.objects.filter(
                action="license_card.delete", object_public_id=str(card.public_id)
            ).exists()
        )

    def test_delete_idempotent_replay(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.REVOKED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-rep").status_code, 200)
        first = self._delete(self._admin_client(), [card.public_id], key="del-rep")
        self.assertEqual(first.status_code, 200)
        second = self._delete(self._admin_client(), [card.public_id], key="del-rep")
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["repeated"])

    def test_delete_requires_admin(self):
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-dmin").status_code, 200)
        response = self._delete(self._downstream_client(), [card.public_id], key="downstream-delete")
        self.assertEqual(response.status_code, 403)

    def test_reveal_rejected_after_delete(self):
        """A deleted card must no longer reveal its plaintext code."""
        card = self._issue_one_card()
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-rev").status_code, 200)
        self.assertEqual(self._delete(self._admin_client(), [card.public_id], key="del-rev").status_code, 200)
        from authorization_platform.licensing.services import decrypt_license_card

        search = self._post_json(
            self._admin_client(),
            reverse("licensing:api_manage_license_card_search"),
            {"code": decrypt_license_card(card.card_ciphertext)},
            key="search-after-delete",
        )
        self.assertEqual(search.status_code, 404)
        response = self._post_json(
            self._admin_client(),
            reverse("licensing:api_manage_license_reveal", kwargs={"public_id": card.public_id}),
            {},
            key="reveal-after-delete",
        )
        self.assertEqual(response.status_code, 404)

    def test_issue_replay_after_delete_does_not_return_plaintext(self):
        client = self._downstream_client()
        issue_key = "lifecycle-issue-replay-deleted"
        preview = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": 1},
            key="lifecycle-preview-replay-deleted",
        )
        self.assertEqual(preview.status_code, 200)
        issued = self._post_json(
            client,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": preview.json()["snapshot_id"],
                "quantity": 1,
                "preview_token": preview.json()["preview_token"],
            },
            key=issue_key,
        )
        self.assertIn(issued.status_code, (200, 201))
        plaintext = issued.json()["items"][0]["code"]
        card = LicenseCard.objects.get(public_id=issued.json()["items"][0]["public_id"])
        self._make_terminal(card, LicenseCardStatus.RECLAIMED)
        self.assertEqual(self._archive(self._admin_client(), [card.public_id], key="arc-issue-replay").status_code, 200)
        self.assertEqual(self._delete(self._admin_client(), [card.public_id], key="del-issue-replay").status_code, 200)
        card_count = LicenseCard.objects.count()
        preview_again = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": 1},
            key="lifecycle-preview-replay-deleted-2",
        )
        self.assertEqual(preview_again.status_code, 200)
        replay = self._post_json(
            client,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": preview_again.json()["snapshot_id"],
                "quantity": 1,
                "preview_token": preview_again.json()["preview_token"],
            },
            key=issue_key,
        )
        self.assertEqual(replay.status_code, 404)
        self.assertEqual(replay.json()["error"]["code"], "LICENSE_CARD_NOT_FOUND")
        self.assertNotIn(plaintext, json.dumps(replay.json()))
        self.assertEqual(LicenseCard.objects.count(), card_count)
        card.refresh_from_db()
        self.assertEqual(card.status, LicenseCardStatus.DELETED_TOMBSTONE)
        self.assertTrue(card.card_ciphertext)

    def test_issue_replay_after_partial_delete_omits_tombstone_code(self):
        client = self._downstream_client()
        issue_key = "lifecycle-issue-replay-partial"
        preview = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": 2},
            key="lifecycle-preview-replay-partial",
        )
        self.assertEqual(preview.status_code, 200)
        issued = self._post_json(
            client,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": preview.json()["snapshot_id"],
                "quantity": 2,
                "preview_token": preview.json()["preview_token"],
            },
            key=issue_key,
        )
        self.assertIn(issued.status_code, (200, 201))
        items = issued.json()["items"]
        self.assertEqual(len(items), 2)
        deleted_card = LicenseCard.objects.get(public_id=items[0]["public_id"])
        kept_card = LicenseCard.objects.get(public_id=items[1]["public_id"])
        deleted_code = items[0]["code"]
        kept_code = items[1]["code"]
        self._make_terminal(deleted_card, LicenseCardStatus.RECLAIMED)
        self._make_terminal(kept_card, LicenseCardStatus.RECLAIMED)
        self.assertEqual(
            self._archive(self._admin_client(), [deleted_card.public_id, kept_card.public_id], key="arc-issue-partial").status_code,
            200,
        )
        self.assertEqual(self._delete(self._admin_client(), [deleted_card.public_id], key="del-issue-partial").status_code, 200)
        preview_again = self._post_json(
            client,
            reverse("licensing:api_downstream_license_preview"),
            {"software_id": self.software_id, "plan_id": self.plan.pk, "quantity": 2},
            key="lifecycle-preview-replay-partial-2",
        )
        self.assertEqual(preview_again.status_code, 200)
        replay = self._post_json(
            client,
            reverse("licensing:api_downstream_license_issue"),
            {
                "software_id": self.software_id,
                "plan_snapshot_id": preview_again.json()["snapshot_id"],
                "quantity": 2,
                "preview_token": preview_again.json()["preview_token"],
            },
            key=issue_key,
        )
        self.assertEqual(replay.status_code, 201)
        replay_codes = [item.get("code") for item in replay.json().get("items", [])]
        self.assertNotIn(deleted_code, replay_codes)
        self.assertNotIn(deleted_code, json.dumps(replay.json()))
        self.assertIn(kept_code, replay_codes)
        self.assertEqual(LicenseCard.objects.filter(status=LicenseCardStatus.DELETED_TOMBSTONE).count(), 1)