from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import threading
import unittest
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import close_old_connections, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.models import (
    DownstreamProfile,
    DownstreamStatus,
    DownstreamTombstone,
    InvitationCode,
    InvitationLifecycleOperation,
    InvitationStatus,
)
from authorization_platform.audit.models import AuditEvent
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY
from authorization_platform.accounts.services import (
    AccountOperationError,
    archive_downstream,
    archive_invitations,
    create_downstream_direct,
    delete_archived_downstream,
    invitation_code_hash,
    issue_invitation_batch,
    register_downstream,
    revoke_invitation,
)


User = get_user_model()


class AccountFlowTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        batch, issued = issue_invitation_batch(actor=self.admin, quantity=2)
        self.batch = batch
        self.first_code = issued[0].code
        self.second_code = issued[1].code

    def test_successful_invitation_registration_consumes_once(self):
        result = register_downstream(
            invitation_code=self.first_code,
            username="Alice",
            password="Downstream-password-123",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.profile.status, DownstreamStatus.ACTIVE)
        invitation = self.batch.codes.get(status=InvitationStatus.CONSUMED)
        self.assertEqual(self.batch.codes.filter(status=InvitationStatus.CONSUMED).count(), 1)
        self.assertEqual(invitation.status, InvitationStatus.CONSUMED)
        self.assertIsNone(invitation.expires_at)
        self.assertEqual(invitation.consumed_username, "alice")
        repeated = register_downstream(
            invitation_code=self.first_code,
            username="another-user",
            password="Downstream-password-123",
        )
        self.assertFalse(repeated.success)
        self.assertEqual(User.objects.filter(username="another-user").count(), 0)

    def test_same_identity_reregistration_is_success_not_fake_failure(self):
        first = register_downstream(
            invitation_code=self.first_code,
            username="Alice",
            password="Downstream-password-123",
        )
        self.assertTrue(first.success)
        repeated = register_downstream(
            invitation_code=self.first_code,
            username="Alice",
            password="Downstream-password-123",
        )
        self.assertTrue(repeated.success)
        self.assertEqual(User.objects.filter(username="alice").count(), 1)
        self.assertEqual(self.batch.codes.filter(status=InvitationStatus.CONSUMED).count(), 1)
        wrong_password = register_downstream(
            invitation_code=self.first_code,
            username="Alice",
            password="Another-password-123",
        )
        self.assertFalse(wrong_password.success)

    def test_register_lock_query_does_not_for_update_nullable_outer_join(self):
        source = (Path(__file__).resolve().parents[1] / "src/authorization_platform/accounts/services.py").read_text(encoding="utf-8")
        self.assertNotIn(
            'select_for_update().select_related("consumed_profile__user")',
            source,
        )
        sql = str(InvitationCode.objects.select_for_update().filter(code_hash="deadbeef").query)
        self.assertNotIn("JOIN", sql.upper())

    def test_html_register_shows_success_and_goes_to_login(self):
        page = self.client.get(reverse("accounts:downstream_register"))
        self.assertContains(page, "注册并前往登录")
        self.assertNotContains(page, "进入工作台")
        self.assertContains(page, "至少 10 位")
        self.assertContains(page, "不能全是数字")
        self.assertContains(page, "常见密码")
        response = self.client.post(
            reverse("accounts:downstream_register"),
            {
                "invitation_code": self.first_code,
                "username": "alice",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
            follow=True,
        )
        self.assertContains(response, "账号已创建")
        self.assertContains(response, "请使用刚才的用户名登录")

    def test_failed_registration_does_not_create_user_or_consume_invitation(self):
        result = register_downstream(invitation_code=self.first_code, username="alice", password="weak")
        self.assertFalse(result.success)
        self.assertEqual(User.objects.filter(username="alice").count(), 0)
        self.assertEqual(self.batch.codes.filter(status=InvitationStatus.ISSUED).count(), 2)

    def test_registration_rejects_password_too_similar_to_username(self):
        result = register_downstream(
            invitation_code=self.first_code,
            username="testuser12345",
            password="testuser123456",
        )
        self.assertFalse(result.success)
        self.assertEqual(User.objects.filter(username="testuser12345").count(), 0)

    def test_duplicate_username_is_case_insensitive_and_invitation_remains_issued(self):
        create_downstream_direct(actor=self.admin, username="Alice", password="Downstream-password-123")
        result = register_downstream(
            invitation_code=self.first_code,
            username="alice",
            password="Downstream-password-123",
        )
        self.assertFalse(result.success)
        invitation = self.batch.codes.filter(status=InvitationStatus.ISSUED).first()
        self.assertEqual(invitation.attempt_count, 0)
        self.assertEqual(User.objects.filter(username__iexact="alice").count(), 1)

    def test_historical_ttl_invitation_is_not_consumed(self):
        expired_at = timezone.now() - timedelta(days=1)
        expired_batch, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        for row in expired_batch.codes.all():
            row.expires_at = expired_at
            row.save(_allow_mutation=True)
        code = issued[0].code
        result = register_downstream(invitation_code=code, username="late-user", password="Downstream-password-123")
        self.assertFalse(result.success)
        invitation = expired_batch.codes.get()
        self.assertEqual(invitation.status, InvitationStatus.EXPIRED)

    def test_admin_can_revoke_invitation_and_registration_cannot_use_it(self):
        invitation = self.batch.codes.get(code_hash=invitation_code_hash(self.first_code))
        revoked = revoke_invitation(actor=self.admin, public_id=invitation.public_id, reason="测试撤销")
        self.assertEqual(revoked.status, InvitationStatus.REVOKED)
        self.assertEqual(revoked.revoke_reason, "测试撤销")
        result = register_downstream(
            invitation_code=self.first_code,
            username="revoked-user",
            password="Downstream-password-123",
        )
        self.assertFalse(result.success)
        self.assertFalse(User.objects.filter(username="revoked-user").exists())
        self.assertTrue(
            AuditEvent.objects.filter(
                action="invitation.revoke",
                outcome="success",
                object_public_id=str(invitation.public_id),
            ).exists()
        )

    def test_direct_create_login_and_scope_guard(self):
        own = create_downstream_direct(actor=self.admin, username="downstream-a", password="Downstream-password-123")
        other = create_downstream_direct(actor=self.admin, username="downstream-b", password="Downstream-password-123")
        client = Client()
        login_response = client.post(reverse("accounts:downstream_login"), {"username": "downstream-a", "password": "Downstream-password-123"})
        self.assertRedirects(login_response, reverse("accounts:downstream_dashboard"))
        self.assertEqual(client.get(reverse("accounts:downstream_profile", kwargs={"public_id": own.public_id})).status_code, 200)
        self.assertEqual(client.get(reverse("accounts:downstream_profile", kwargs={"public_id": other.public_id})).status_code, 404)

    def test_archive_invalidates_existing_session_and_delete_requires_archive(self):
        profile = create_downstream_direct(actor=self.admin, username="lifecycle-user", password="Downstream-password-123")
        downstream_client = Client()
        self.assertEqual(
            downstream_client.post(reverse("accounts:downstream_login"), {"username": "lifecycle-user", "password": "Downstream-password-123"}).status_code,
            302,
        )
        with self.assertRaises(AccountOperationError):
            delete_archived_downstream(actor=self.admin, public_id=profile.public_id, reason="错误顺序")
        archive_downstream(actor=self.admin, public_id=profile.public_id, reason="测试归档")
        self.assertEqual(downstream_client.get(reverse("accounts:downstream_dashboard")).status_code, 302)
        tombstone = delete_archived_downstream(actor=self.admin, public_id=profile.public_id, reason="测试删除")
        self.assertTrue(DownstreamTombstone.objects.filter(public_id=tombstone.public_id).exists())
        self.assertFalse(User.objects.filter(username="lifecycle-user").exists())
        self.assertFalse(DownstreamProfile.objects.filter(public_id=profile.public_id).exists())


class AccountViewSecurityTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")

    def test_admin_can_generate_code_refresh_stays_redacted_and_detail_reveals_again(self):
        client = Client()
        client.force_login(self.admin)
        page = client.get(reverse("accounts:invitations"))
        self.assertContains(page, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(page, FORBIDDEN_API_COPY, status_code=410)
        response = client.post(
            reverse("accounts:invitations"),
            {"quantity": 1, "submission_token": "unused"},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(InvitationCode.objects.count(), 0)
        reveal_url = reverse("accounts:invitation_reveal", kwargs={"public_id": "00000000-0000-0000-0000-000000000001"})
        first_reveal = client.post(reveal_url)
        second_reveal = client.post(reveal_url)
        self.assertContains(first_reveal, CONTROL_ROOM_COPY, status_code=410)
        self.assertContains(second_reveal, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(first_reveal, "INV-", status_code=410)

    def test_replaying_invitation_issue_token_does_not_create_another_batch(self):
        client = Client()
        client.force_login(self.admin)
        page = client.get(reverse("accounts:invitations"))
        self.assertContains(page, CONTROL_ROOM_COPY, status_code=410)
        payload = {"quantity": 1, "submission_token": "replay-token"}
        first = client.post(reverse("accounts:invitations"), payload)
        self.assertContains(first, CONTROL_ROOM_COPY, status_code=410)
        second = client.post(reverse("accounts:invitations"), payload)
        self.assertContains(second, CONTROL_ROOM_COPY, status_code=410)
        self.assertEqual(self.admin.invitation_batches.count(), 0)

    def test_authorized_invitation_reveal_is_post_only_and_audited(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        client = Client()
        client.force_login(self.admin)
        reveal_url = reverse("accounts:invitation_reveal", kwargs={"public_id": issued[0].public_id})
        self.assertEqual(client.get(reveal_url).status_code, 405)
        response = client.post(reveal_url)
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, issued[0].code, status_code=410)
        self.assertFalse(AuditEvent.objects.filter(action="invitation.reveal", outcome="success", object_public_id=str(issued[0].public_id)).exists())

    def test_admin_can_revoke_invitation_from_management_page(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        client = Client()
        client.force_login(self.admin)
        response = client.post(
            reverse("accounts:invitation_revoke", kwargs={"public_id": issued[0].public_id}),
            {"reason": "页面测试撤销"},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        invitation = InvitationCode.objects.get(public_id=issued[0].public_id)
        self.assertEqual(invitation.status, InvitationStatus.ISSUED)

    def test_delete_page_requires_explicit_confirmation(self):
        profile = create_downstream_direct(actor=self.admin, username="delete-page-user", password="Downstream-password-123")
        client = Client()
        client.force_login(self.admin)
        archive_downstream(actor=self.admin, public_id=profile.public_id, reason="先归档")
        delete_url = reverse("accounts:downstream_delete", kwargs={"public_id": profile.public_id})
        rejected = client.post(delete_url, {"reason": "没有勾选"})
        self.assertContains(rejected, CONTROL_ROOM_COPY, status_code=410)
        self.assertTrue(DownstreamProfile.objects.filter(public_id=profile.public_id).exists())
        accepted = client.post(delete_url, {"confirmation": "1", "reason": "页面确认删除"})
        self.assertContains(accepted, CONTROL_ROOM_COPY, status_code=410)
        self.assertTrue(DownstreamProfile.objects.filter(public_id=profile.public_id).exists())

    def test_platform_admin_group_drives_navigation_and_audit_role(self):
        grouped_admin = User.objects.create_user(username="group-admin", password="Admin-password-123", is_staff=False)
        grouped_admin.groups.add(Group.objects.create(name="platform_admin"))
        client = Client()
        client.force_login(grouped_admin)
        self.assertEqual(client.get(reverse("accounts:manage_dashboard")).status_code, 200)
        issue_invitation_batch(actor=grouped_admin, quantity=1)
        event = AuditEvent.objects.filter(action="invitation.issue").latest("occurred_at")
        self.assertEqual(event.actor_role, "platform_admin")

    def test_csrf_is_required_for_logout(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 403)

    def test_admin_route_is_not_an_uncontrolled_business_entrypoint(self):
        self.assertEqual(self.client.get("/admin/").status_code, 404)

    def test_auth_login_is_only_an_entry_chooser(self):
        response = self.client.get(reverse("accounts:login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("accounts:manage_login"))
        self.assertContains(response, reverse("accounts:downstream_login"))
        self.assertEqual(self.client.post(reverse("accounts:login"), {}).status_code, 405)
        self.assertRedirects(self.client.get(reverse("accounts:register")), reverse("accounts:downstream_register"))

    def test_management_and_downstream_login_entries_enforce_roles(self):
        downstream = create_downstream_direct(actor=self.admin, username="entry-downstream", password="Downstream-password-123")

        admin_client = Client()
        self.assertRedirects(
            admin_client.post(reverse("accounts:manage_login"), {"username": "admin", "password": "Admin-password-123"}),
            reverse("accounts:manage_dashboard"),
        )

        downstream_client = Client()
        rejected_admin = downstream_client.post(
            reverse("accounts:downstream_login"),
            {"username": "admin", "password": "Admin-password-123"},
        )
        self.assertEqual(rejected_admin.status_code, 200)
        self.assertContains(rejected_admin, "用户名或密码不正确")
        self.assertNotIn("_auth_user_id", downstream_client.session)

        wrong_entry_client = Client()
        rejected_downstream = wrong_entry_client.post(
            reverse("accounts:manage_login"),
            {"username": downstream.user.username, "password": "Downstream-password-123"},
        )
        self.assertEqual(rejected_downstream.status_code, 200)
        self.assertContains(rejected_downstream, "用户名或密码不正确")
        self.assertNotIn("_auth_user_id", wrong_entry_client.session)

    def test_an_authenticated_login_replaces_the_current_session(self):
        downstream = create_downstream_direct(actor=self.admin, username="entry-wrong-role", password="Downstream-password-123")
        other = create_downstream_direct(actor=self.admin, username="entry-switch-b", password="Downstream-password-123")

        admin_client = Client()
        admin_client.force_login(self.admin)
        self.assertEqual(admin_client.get(reverse("accounts:downstream_login")).status_code, 200)
        failed = admin_client.post(
            reverse("accounts:downstream_login"),
            {"username": downstream.user.username, "password": "wrong-password"},
        )
        self.assertEqual(failed.status_code, 200)
        self.assertContains(failed, "用户名或密码不正确")
        self.assertEqual(int(admin_client.session["_auth_user_id"]), self.admin.pk)
        switched = admin_client.post(
            reverse("accounts:downstream_login"),
            {"username": downstream.user.username, "password": "Downstream-password-123"},
        )
        self.assertRedirects(switched, reverse("accounts:downstream_dashboard"))
        self.assertEqual(int(admin_client.session["_auth_user_id"]), downstream.user.pk)

        downstream_client = Client()
        downstream_client.force_login(downstream.user)
        downstream_client.session["downstream_session_version"] = downstream.session_version
        downstream_client.session.save()
        self.assertEqual(downstream_client.get(reverse("accounts:manage_login")).status_code, 200)
        to_admin = downstream_client.post(
            reverse("accounts:manage_login"),
            {"username": "admin", "password": "Admin-password-123"},
        )
        self.assertRedirects(to_admin, reverse("accounts:manage_dashboard"))
        self.assertEqual(int(downstream_client.session["_auth_user_id"]), self.admin.pk)

        switch_client = Client()
        switch_client.force_login(downstream.user)
        switch_client.session["downstream_session_version"] = downstream.session_version
        switch_client.session.save()
        to_other = switch_client.post(
            reverse("accounts:downstream_login"),
            {"username": other.user.username, "password": "Downstream-password-123"},
        )
        self.assertRedirects(to_other, reverse("accounts:downstream_dashboard"))
        self.assertEqual(int(switch_client.session["_auth_user_id"]), other.user.pk)

    def test_stale_authenticated_account_does_not_loop_on_chooser(self):
        downstream = create_downstream_direct(actor=self.admin, username="entry-stale", password="Downstream-password-123")
        downstream.status = DownstreamStatus.CLOSED
        downstream.save(update_fields=["status"])
        client = Client()
        client.force_login(downstream.user)
        response = client.get(reverse("accounts:login"))
        self.assertEqual(response.status_code, 403)

    def test_protected_pages_redirect_to_the_matching_login_entry(self):
        manage_response = self.client.get(reverse("accounts:manage_dashboard"))
        self.assertRedirects(manage_response, f"{reverse('accounts:manage_login')}?next={reverse('accounts:manage_dashboard')}")
        downstream_response = self.client.get(reverse("accounts:downstream_dashboard"))
        self.assertRedirects(downstream_response, f"{reverse('accounts:downstream_login')}?next={reverse('accounts:downstream_dashboard')}")

    def test_login_next_is_same_site_and_role_scoped(self):
        downstream = create_downstream_direct(actor=self.admin, username="entry-next", password="Downstream-password-123")
        profile_path = reverse("accounts:downstream_profile", kwargs={"public_id": downstream.public_id})
        client = Client()
        response = client.post(
            f"{reverse('accounts:downstream_login')}?next={profile_path}",
            {"username": downstream.user.username, "password": "Downstream-password-123"},
        )
        self.assertRedirects(response, profile_path)

        client = Client()
        response = client.post(
            f"{reverse('accounts:downstream_login')}?next=https://evil.example/steal",
            {"username": downstream.user.username, "password": "Downstream-password-123"},
        )
        self.assertRedirects(response, reverse("accounts:downstream_dashboard"))

    def test_logout_returns_to_the_role_specific_login_entry(self):
        admin_client = Client()
        admin_client.force_login(self.admin)
        self.assertRedirects(admin_client.post(reverse("accounts:logout")), reverse("accounts:manage_login"))
        downstream = create_downstream_direct(actor=self.admin, username="entry-logout", password="Downstream-password-123")
        downstream_client = Client()
        downstream_client.force_login(downstream.user)
        downstream_client.session["downstream_session_version"] = downstream.session_version
        downstream_client.session.save()
        self.assertRedirects(downstream_client.post(reverse("accounts:logout")), reverse("accounts:downstream_login"))

    def test_login_error_does_not_reveal_user_existence(self):
        User.objects.create_user(username="known-user", password="Downstream-password-123")
        known = self.client.post(reverse("accounts:downstream_login"), {"username": "known-user", "password": "wrong-password"})
        unknown = self.client.post(reverse("accounts:downstream_login"), {"username": "missing-user", "password": "wrong-password"})
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertContains(known, "用户名或密码不正确")
        self.assertContains(unknown, "用户名或密码不正确")

    def test_failed_login_is_audited_without_password_data(self):
        User.objects.create_user(username="known-user", password="Downstream-password-123")
        self.client.post(reverse("accounts:downstream_login"), {"username": "known-user", "password": "wrong-password"})
        event = AuditEvent.objects.filter(action="auth.login", outcome="failure").latest("occurred_at")
        self.assertEqual(event.reason_code, "AUTHENTICATION_FAILED")
        self.assertNotIn("wrong-password", str(event.metadata))


class InvitationStateMachineTests(TransactionTestCase):
    """SQLite proves the sequential state machine; PostgreSQL must prove the row-lock contract."""

    reset_sequences = True

    def test_invitation_has_single_consumption_state_machine(self):
        admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        batch, issued = issue_invitation_batch(actor=admin, quantity=1)
        result = register_downstream(
            invitation_code=issued[0].code,
            username="transaction-user",
            password="Downstream-password-123",
        )
        self.assertTrue(result.success)
        self.assertEqual(batch.codes.get().status, InvitationStatus.CONSUMED)


@unittest.skipUnless(connection.vendor == "postgresql", "SQLite 不提供 PostgreSQL 行锁语义；在 PostgreSQL 环境运行邀请码并发验收")
class InvitationConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.admin = User.objects.create_superuser(username="parallel-admin", password="Admin-password-123")
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        self.invitation_code = issued[0].code
        self.invitation_public_id = issued[0].public_id

    def _register(self, barrier: threading.Barrier, *, username: str):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            result = register_downstream(
                invitation_code=self.invitation_code,
                username=username,
                password="Downstream-password-123",
                request_id=f"parallel-registration-{username}",
            )
            return result.success, str(result.profile.public_id) if result.profile else None
        finally:
            close_old_connections()

    def test_same_invitation_concurrent_registration_consumes_once(self):
        usernames = ("parallel-a", "parallel-b")
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda username: self._register(barrier, username=username),
                    usernames,
                )
            )

        self.assertEqual(sum(result[0] for result in results), 1)
        self.assertEqual(sum(not result[0] for result in results), 1)
        winning_username = usernames[next(index for index, result in enumerate(results) if result[0])]
        invitation = InvitationCode.objects.get(public_id=self.invitation_public_id)
        self.assertEqual(invitation.status, InvitationStatus.CONSUMED)
        self.assertEqual(invitation.consumed_username, winning_username)
        self.assertIsNotNone(invitation.consumed_at)
        self.assertIsNotNone(invitation.consumed_profile_id)
        self.assertEqual(InvitationCode.objects.filter(status=InvitationStatus.CONSUMED).count(), 1)
        self.assertEqual(User.objects.filter(username__in=usernames).count(), 1)
        self.assertEqual(
            DownstreamProfile.objects.filter(
                user__username__in=usernames,
                status=DownstreamStatus.ACTIVE,
                registration_source="invitation",
            ).count(),
            1,
        )
        self.assertEqual(
            AuditEvent.objects.filter(
                action="downstream.register",
                outcome="success",
                reason_code="INVITATION_CONSUMED",
            ).count(),
            1,
        )
        self.assertEqual(
            AuditEvent.objects.filter(
                action="downstream.register",
                outcome="failure",
                reason_code="INVITATION_UNAVAILABLE",
            ).count(),
            1,
        )
    def test_same_lifecycle_key_concurrent_archive_replays_one_response(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1, idempotency_key="parallel-archive-issue")
        invitation = InvitationCode.objects.get(public_id=issued[0].public_id)
        invitation.status = InvitationStatus.REVOKED
        invitation.revoked_at = timezone.now() - timedelta(days=1)
        invitation.save(_allow_mutation=True)
        barrier = threading.Barrier(2)

        def archive(_index):
            close_old_connections()
            try:
                actor = User.objects.get(pk=self.admin.pk)
                barrier.wait(timeout=10)
                result = archive_invitations(
                    actor=actor,
                    code_ids=[invitation.public_id],
                    reason="并发归档邀请码",
                    idempotency_key="parallel-archive-same-key",
                )
                return ("ok", bool(result.get("repeated")))
            except AccountOperationError as exc:
                return ("error", exc.code)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(archive, (1, 2)))
        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertEqual(InvitationCode.objects.get(public_id=invitation.public_id).status, InvitationStatus.ARCHIVED)
        self.assertEqual(InvitationLifecycleOperation.objects.filter(idempotency_key="parallel-archive-same-key").count(), 1)


class InvitationPublicIdMigrationTests(TransactionTestCase):
    """Verify that a legacy InvitationCode row survives the public UUID migration."""

    reset_sequences = True

    def setUp(self):
        super().setUp()
        # Reversing accounts also reverses dependent apps. Register restoration
        # before changing schema so it runs even when historical setup fails.
        self.addCleanup(self._restore_latest_schema)
        self.executor = MigrationExecutor(connection)
        self.executor.migrate([("accounts", "0001_initial")])
        old_apps = self.executor.loader.project_state([("accounts", "0001_initial")]).apps
        old_user_model = old_apps.get_model("auth", "User")
        old_batch_model = old_apps.get_model("accounts", "InvitationBatch")
        old_invitation_model = old_apps.get_model("accounts", "InvitationCode")
        user = old_user_model.objects.create(username="legacy-admin", password="not-a-real-hash")
        batch = old_batch_model.objects.create(created_by=user, quantity=1, created_at=timezone.now())
        old_invitation_model.objects.create(
            batch=batch,
            code_hash="legacy-code-hash",
            code_ciphertext="legacy-ciphertext",
            status="issued",
            created_at=timezone.now(),
            expires_at=timezone.now() + timedelta(days=1),
            max_attempts=5,
            attempt_count=0,
            consumed_username_digest="",
            revoke_reason="",
        )
        self.executor = MigrationExecutor(connection)
        self.executor.migrate([("accounts", "0002_invitationcode_public_id")])

    def _restore_latest_schema(self):
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())

    def test_cleanup_restores_dependent_app_schema(self):
        self.doCleanups()
        executor = MigrationExecutor(connection)
        self.assertEqual(executor.migration_plan(executor.loader.graph.leaf_nodes()), [])
        from authorization_platform.catalog.models import Software
        from authorization_platform.licensing.models import LicenseInstance

        self.assertFalse(Software.objects.exists())
        self.assertFalse(LicenseInstance.objects.exists())

    def test_legacy_rows_receive_unique_public_ids_and_keep_state(self):
        apps = self.executor.loader.project_state([("accounts", "0002_invitationcode_public_id")]).apps
        invitation_model = apps.get_model("accounts", "InvitationCode")
        rows = list(invitation_model.objects.all())
        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0].public_id)
        self.assertEqual(rows[0].status, "issued")
        self.assertEqual(rows[0].code_hash, "legacy-code-hash")
