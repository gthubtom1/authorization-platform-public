from __future__ import annotations

import json
import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.models import (
    InvitationCode,
    InvitationCodeTombstone,
    InvitationStatus,
)
from authorization_platform.accounts.services import create_downstream_direct, issue_invitation_batch
from authorization_platform.audit.models import AuditEvent


User = get_user_model()


class InvitationLifecycleApiTests(TestCase):
    """Archive/delete lifecycle for invitation codes (admin-only)."""

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="inv-lifecycle-admin", password="Admin-password-123"
        )
        self.downstream = create_downstream_direct(
            actor=self.admin,
            username="inv-lifecycle-downstream",
            password="Downstream-password-123",
        )

    def _issue_one(self) -> InvitationCode:
        batch, issued = issue_invitation_batch(
            actor=self.admin,
            quantity=1,
            idempotency_key=f"inv-lifecycle-issue-{uuid.uuid4().hex[:10]}",
        )
        return InvitationCode.objects.get(public_id=issued[0].public_id)

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
                    "username": "inv-lifecycle-downstream",
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

    def _revoke(self, code: InvitationCode):
        from authorization_platform.accounts.services import revoke_invitation

        return revoke_invitation(
            actor=self.admin,
            public_id=code.public_id,
            reason="测试撤销邀请码",
        )

    def _archive(self, client: Client, code_ids, *, key: str):
        return self._post(
            client,
            reverse("accounts:api_invitation_archive"),
            {"code_ids": [str(c) for c in code_ids], "reason": "测试归档邀请码"},
            key=key,
        )

    def _delete(self, client: Client, code_ids, *, key: str):
        return self._post(
            client,
            reverse("accounts:api_invitation_delete"),
            {"code_ids": [str(c) for c in code_ids], "reason": "测试删除邀请码"},
            key=key,
        )

    def _make_terminal(self, code: InvitationCode, status: str, *, days_ago: int = 31) -> InvitationCode:
        terminal_at = timezone.now() - timezone.timedelta(days=days_ago)
        if status == InvitationStatus.REVOKED:
            code.status = InvitationStatus.REVOKED
            code.revoked_at = terminal_at
        elif status == InvitationStatus.CONSUMED:
            code.status = InvitationStatus.CONSUMED
            code.consumed_at = terminal_at
            code.consumed_username = "consumed-user"
            code.consumed_username_digest = "digest"
        code.save(_allow_mutation=True)
        code.refresh_from_db()
        return code

    def test_archive_requires_revoke_for_unused(self):
        code = self._issue_one()
        response = self._archive(self._admin_client(), [code.public_id], key="arc-unused")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "INVITATION_NOT_ARCHIVABLE")

    def test_expired_invitation_can_archive_without_revoke(self):
        code = self._issue_one()
        code.expires_at = timezone.now() - timezone.timedelta(hours=1)
        code.save(update_fields=("expires_at",), _allow_mutation=True)
        archived = self._archive(self._admin_client(), [code.public_id], key="arc-expired")
        self.assertEqual(archived.status_code, 200)
        code.refresh_from_db()
        self.assertEqual(code.status, InvitationStatus.ARCHIVED)
        self.assertIsNotNone(code.archived_at)
        current_listing = self._admin_client().get(reverse("accounts:api_invitation_collection"))
        self.assertEqual(current_listing.status_code, 200)
        self.assertEqual(current_listing.json()["items"], [])
        archived_listing = self._admin_client().get(
            reverse("accounts:api_invitation_collection"), {"scope": "archived"}
        )
        self.assertEqual(archived_listing.status_code, 200)
        self.assertEqual(archived_listing.json()["items"][0]["status"], InvitationStatus.ARCHIVED)
        deleted = self._delete(self._admin_client(), [code.public_id], key="del-expired")
        self.assertEqual(deleted.status_code, 200)

    def test_archive_terminal_code_is_immediate(self):
        code = self._issue_one()
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED, days_ago=1)
        response = self._archive(self._admin_client(), [code.public_id], key="early-arc")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["archived_count"], 1)

    def test_archive_then_delete_revoked_code(self):
        code = self._issue_one()
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED)
        archived = self._archive(self._admin_client(), [code.public_id], key="arc-one")
        self.assertEqual(archived.status_code, 200)
        self.assertEqual(archived.json()["archived_count"], 1)
        deleted = self._delete(self._admin_client(), [code.public_id], key="del-one")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json()["deleted_count"], 1)
        code.refresh_from_db()
        self.assertEqual(code.status, InvitationStatus.DELETED_TOMBSTONE)
        self.assertTrue(
            InvitationCodeTombstone.objects.filter(code_public_id=code.public_id).exists()
        )
        self.assertTrue(
            AuditEvent.objects.filter(
                action="invitation.delete", object_public_id=str(code.public_id)
            ).exists()
        )
        listing = self._admin_client().get(reverse("accounts:api_invitation_collection"))
        visible = [item["public_id"] for item in listing.json()["items"]]
        self.assertNotIn(str(code.public_id), visible)

    def test_delete_requires_archived(self):
        code = self._issue_one()
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED)
        response = self._delete(self._admin_client(), [code.public_id], key="del-unarchived")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "INVITATION_NOT_DELETABLE")

    def test_consumed_code_archive_delete_keeps_tombstone(self):
        code = self._issue_one()
        self._make_terminal(code, InvitationStatus.CONSUMED)
        self.assertEqual(self._archive(self._admin_client(), [code.public_id], key="arc-cons").status_code, 200)
        deleted = self._delete(self._admin_client(), [code.public_id], key="del-cons")
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(
            InvitationCodeTombstone.objects.filter(code_public_id=code.public_id).exists()
        )

    def test_idempotent_replay_and_conflict(self):
        code = self._issue_one()
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED)
        first = self._archive(self._admin_client(), [code.public_id], key="ip-key")
        self.assertEqual(first.status_code, 200)
        second = self._archive(self._admin_client(), [code.public_id], key="ip-key")
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["repeated"])
        other = self._issue_one()
        conflict = self._archive(self._admin_client(), [other.public_id], key="ip-key")
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_downstream_rejected(self):
        code = self._issue_one()
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED)
        self.assertEqual(self._archive(self._admin_client(), [code.public_id], key="arc-down").status_code, 200)
        response = self._delete(self._downstream_client(), [code.public_id], key="down-del")
        self.assertEqual(response.status_code, 403)

    def test_reveal_rejected_after_delete(self):
        code = self._issue_one()
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED)
        self.assertEqual(self._archive(self._admin_client(), [code.public_id], key="arc-rev").status_code, 200)
        self.assertEqual(self._delete(self._admin_client(), [code.public_id], key="del-rev").status_code, 200)
        from authorization_platform.accounts.services import decrypt_invitation_code

        search = self._post(
            self._admin_client(),
            reverse("accounts:api_invitation_search"),
            {"code": decrypt_invitation_code(code.code_ciphertext)},
            key="search-after-delete",
        )
        self.assertEqual(search.status_code, 404)
        response = self._post(
            self._admin_client(),
            reverse("accounts:api_invitation_reveal", kwargs={"public_id": code.public_id}),
            {},
            key="reveal-after-delete",
        )
        self.assertEqual(response.status_code, 404)

    def test_issue_replay_after_delete_does_not_return_plaintext(self):
        issue_key = "inv-lifecycle-issue-replay-deleted"
        admin = self._admin_client()
        issued = self._post(
            admin,
            reverse("accounts:api_invitation_collection"),
            {"quantity": 1},
            key=issue_key,
        )
        self.assertEqual(issued.status_code, 201)
        plaintext = issued.json()["items"][0]["code"]
        code = InvitationCode.objects.get(public_id=issued.json()["items"][0]["public_id"])
        self._revoke(code)
        self._make_terminal(code, InvitationStatus.REVOKED)
        self.assertEqual(self._archive(admin, [code.public_id], key="arc-issue-replay").status_code, 200)
        self.assertEqual(self._delete(admin, [code.public_id], key="del-issue-replay").status_code, 200)
        code_count = InvitationCode.objects.count()
        replay = self._post(
            admin,
            reverse("accounts:api_invitation_collection"),
            {"quantity": 1},
            key=issue_key,
        )
        self.assertEqual(replay.status_code, 404)
        self.assertEqual(replay.json()["error"]["code"], "INVITATION_NOT_FOUND")
        self.assertNotIn(plaintext, json.dumps(replay.json()))
        self.assertEqual(InvitationCode.objects.count(), code_count)
        code.refresh_from_db()
        self.assertEqual(code.status, InvitationStatus.DELETED_TOMBSTONE)
        self.assertTrue(code.code_ciphertext)