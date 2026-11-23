from __future__ import annotations

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from authorization_platform.audit.models import AuditEvent
from authorization_platform.accounts.models import (
    DownstreamAdminOperation,
    DownstreamProfile,
    DownstreamStatus,
    InvitationStatus,
    PasswordOperation,
)
from authorization_platform.accounts.services import create_downstream_direct, issue_invitation_batch, normalize_invitation_code
from authorization_platform.credits.services import credit_quota


User = get_user_model()


class AccountApiTests(TestCase):
    def setUp(self):
        # TestCase rolls back database rows, but source rate budgets live in cache.
        cache.clear()
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream = User.objects.create_user(username="downstream-a", password="Downstream-password-123")
        profile = DownstreamProfile.objects.create(user=self.downstream, registration_source="direct")
        self.downstream.groups.create(name="downstream")
        self.downstream_profile = profile

    def csrf_headers(self):
        response = self.client.get(reverse("accounts:api_session"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("csrftoken", self.client.cookies)
        return {"HTTP_X_CSRFTOKEN": self.client.cookies["csrftoken"].value}

    def post_json(self, url_name, payload, *, headers=None):
        return self.post_json_url(reverse(url_name), payload, headers=headers)

    def post_json_url(self, url, payload, *, headers=None):
        request_headers = self.csrf_headers()
        request_headers.update(headers or {})
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            **request_headers,
        )

    def login_api(self, username, password, entrypoint):
        return self.post_json(
            "accounts:api_login",
            {"username": username, "password": password, "entrypoint": entrypoint},
        )

    def test_anonymous_session_returns_role_and_csrf_cookie(self):
        response = self.client.get(reverse("accounts:api_session"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"authenticated": False, "role": "anonymous", "user": None})
        self.assertIn("csrftoken", self.client.cookies)

    def test_login_is_role_scoped_and_does_not_enumerate_accounts(self):
        admin_response = self.login_api("admin", "Admin-password-123", "admin")
        self.assertEqual(admin_response.status_code, 200)
        self.assertEqual(admin_response.json()["role"], "platform_admin")

        self.client = Client(enforce_csrf_checks=True)
        wrong_role = self.login_api("admin", "Admin-password-123", "downstream")
        self.assertEqual(wrong_role.status_code, 401)
        self.assertEqual(wrong_role.json()["error"]["code"], "AUTHENTICATION_FAILED")
        self.assertNotIn("_auth_user_id", self.client.session)

        known = self.login_api("missing", "Admin-password-123", "admin")
        self.assertEqual(known.status_code, 401)
        self.assertEqual(known.json()["error"]["message"], wrong_role.json()["error"]["message"])

    def test_valid_login_replaces_the_current_browser_session(self):
        other = create_downstream_direct(actor=self.admin, username="downstream-b", password="Downstream-password-123")

        admin_login = self.login_api("admin", "Admin-password-123", "admin")
        self.assertEqual(admin_login.status_code, 200)
        failed_downstream = self.login_api("downstream-a", "wrong-password", "downstream")
        self.assertEqual(failed_downstream.status_code, 401)
        self.assertEqual(failed_downstream.json()["error"]["code"], "AUTHENTICATION_FAILED")
        still_admin = self.client.get(reverse("accounts:api_session"))
        self.assertEqual(still_admin.json()["role"], "platform_admin")
        self.assertEqual(still_admin.json()["user"]["username"], "admin")

        to_downstream = self.login_api("downstream-a", "Downstream-password-123", "downstream")
        self.assertEqual(to_downstream.status_code, 200)
        self.assertEqual(to_downstream.json()["role"], "downstream")
        self.assertEqual(to_downstream.json()["user"]["username"], "downstream-a")
        session = self.client.get(reverse("accounts:api_session"))
        self.assertEqual(session.json()["role"], "downstream")
        self.assertEqual(session.json()["user"]["username"], "downstream-a")

        failed_other = self.login_api(other.user.username, "wrong-password", "downstream")
        self.assertEqual(failed_other.status_code, 401)
        still_a = self.client.get(reverse("accounts:api_session"))
        self.assertEqual(still_a.json()["user"]["username"], "downstream-a")

        to_other = self.login_api(other.user.username, "Downstream-password-123", "downstream")
        self.assertEqual(to_other.status_code, 200)
        self.assertEqual(to_other.json()["user"]["username"], other.user.username)

        to_admin = self.login_api("admin", "Admin-password-123", "admin")
        self.assertEqual(to_admin.status_code, 200)
        self.assertEqual(to_admin.json()["role"], "platform_admin")
        again = self.login_api("admin", "Admin-password-123", "admin")
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json()["role"], "platform_admin")
        final_session = self.client.get(reverse("accounts:api_session"))
        self.assertEqual(final_session.json()["role"], "platform_admin")
        self.assertEqual(final_session.json()["user"]["username"], "admin")

    def test_login_accepts_the_same_username_case_as_registration(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        created = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "ShopA",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["redirect"], "downstream-login.html")

        mixed = self.login_api("ShopA", "Downstream-password-123", "downstream")
        self.assertEqual(mixed.status_code, 200)
        self.assertEqual(mixed.json()["role"], "downstream")
        self.assertEqual(User.objects.get(username="shopa").username, "shopa")

    def test_login_finds_legacy_mixed_case_admin_username(self):
        User.objects.create_superuser(username="ExampleAdmin", password="Admin-password-123")
        mixed = self.login_api("ExampleAdmin", "Admin-password-123", "admin")
        self.assertEqual(mixed.status_code, 200)
        self.assertEqual(mixed.json()["role"], "platform_admin")
        self.client = Client(enforce_csrf_checks=True)
        folded = self.login_api("exampleadmin", "Admin-password-123", "admin")
        self.assertEqual(folded.status_code, 200)
        self.assertEqual(folded.json()["role"], "platform_admin")
        self.assertEqual(User.objects.filter(username="ExampleAdmin").count(), 1)

    def test_client_request_id_is_hashed_before_account_audit(self):
        supplied = "account-client-request-secret"
        response = self.post_json_url(
            reverse("accounts:api_login"),
            {"username": "missing", "password": "Admin-password-123", "entrypoint": "admin"},
            headers={"HTTP_X_REQUEST_ID": supplied},
        )
        self.assertEqual(response.status_code, 401)
        event = AuditEvent.objects.filter(action="auth.login").latest("occurred_at")
        self.assertNotIn(supplied, event.request_id)
        self.assertTrue(event.request_id.startswith("client-"))

    def test_logout_requires_csrf_and_clears_session(self):
        self.client.force_login(self.admin)
        no_csrf = self.client.post(reverse("accounts:api_logout"), data="{}", content_type="application/json")
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(no_csrf.json()["error"]["code"], "CSRF_FAILED")
        response = self.post_json("accounts:api_logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["authenticated"])
        self.assertEqual(response.json()["redirect"], "manage-login.html")

    def test_logout_never_returns_hidden_entry(self):
        admin = self.login_api("admin", "Admin-password-123", "admin")
        self.assertEqual(admin.status_code, 200)
        admin_out = self.post_json("accounts:api_logout", {})
        self.assertEqual(admin_out.status_code, 200)
        self.assertEqual(admin_out.json()["redirect"], "manage-login.html")
        self.assertNotIn("entry.html", admin_out.json()["redirect"])

        downstream = self.login_api("downstream-a", "Downstream-password-123", "downstream")
        self.assertEqual(downstream.status_code, 200)
        down_out = self.post_json("accounts:api_logout", {})
        self.assertEqual(down_out.status_code, 200)
        self.assertEqual(down_out.json()["redirect"], "downstream-login.html")

        anonymous = self.post_json("accounts:api_logout", {})
        self.assertEqual(anonymous.status_code, 200)
        self.assertEqual(anonymous.json()["redirect"], "downstream-login.html")
        self.assertNotIn("entry.html", anonymous.json()["redirect"])

    def test_downstream_cannot_write_catalog_access(self):
        login = self.login_api("downstream-a", "Downstream-password-123", "downstream")
        self.assertEqual(login.status_code, 200)
        response = self.post_json_url(
            reverse("catalog:api_catalog_access", kwargs={"downstream_public_id": str(self.downstream_profile.public_id)}),
            {"software_id": "any-software", "enabled": True, "all_plans_allowed": True, "allowed_plan_ids": []},
            headers={"HTTP_IDEMPOTENCY_KEY": "downstream-catalog-forbidden"},
        )
        self.assertEqual(response.status_code, 403)

    def test_login_requires_csrf(self):
        response = self.client.post(
            reverse("accounts:api_login"),
            data=json.dumps({"username": "admin", "password": "Admin-password-123", "entrypoint": "admin"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "CSRF_FAILED")

    def test_frozen_8123_origin_is_allowed_for_same_origin_proxy(self):
        response = self.post_json_url(
            reverse("accounts:api_login"),
            {"username": "admin", "password": "Admin-password-123", "entrypoint": "admin"},
            headers={
                "HTTP_ORIGIN": "http://127.0.0.1:8123",
                "HTTP_REFERER": "http://127.0.0.1:8123/manage-login.html",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["authenticated"])
        self.assertEqual(response.json()["role"], "platform_admin")

    def test_registration_rejects_illegal_username_with_400_not_500(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        for username in ("not valid!", "测试员"):
            with self.subTest(username=username):
                response = self.post_json(
                    "accounts:api_register",
                    {
                        "invitation_code": issued[0].code,
                        "username": username,
                        "password": "Downstream-password-123",
                        "password_confirm": "Downstream-password-123",
                    },
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "REGISTRATION_FAILED")
                self.assertFalse(User.objects.filter(username__iexact=username).exists())
        from authorization_platform.accounts.models import InvitationCode

        row = InvitationCode.objects.get(public_id=issued[0].public_id)
        self.assertEqual(row.status, InvitationStatus.ISSUED)
        self.assertEqual(row.attempt_count, 0)

    def test_registration_failure_keeps_invitation_and_does_not_create_account(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        response = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "new-downstream",
                "password": "weak",
                "password_confirm": "weak",
            },
        )

        self.assertEqual(response.status_code, 400)
        invitation = issued[0]
        from authorization_platform.accounts.models import InvitationCode

        row = InvitationCode.objects.get(public_id=invitation.public_id)
        self.assertEqual(row.status, InvitationStatus.ISSUED)
        self.assertEqual(row.attempt_count, 0)
        self.assertFalse(User.objects.filter(username="new-downstream").exists())

    def test_registration_success_consumes_invitation_once_and_requires_login(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        response = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "new-downstream",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["redirect"], "downstream-login.html")
        self.assertNotIn("_auth_user_id", self.client.session)
        row = issued[0]
        from authorization_platform.accounts.models import InvitationCode

        invitation = InvitationCode.objects.get(public_id=row.public_id)
        self.assertEqual(invitation.status, InvitationStatus.CONSUMED)
        self.assertEqual(User.objects.filter(username="new-downstream").count(), 1)

        repeated = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "another-downstream",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
        )
        self.assertEqual(repeated.status_code, 400)
        self.assertFalse(User.objects.filter(username="another-downstream").exists())

        same_identity = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "new-downstream",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
        )
        self.assertEqual(same_identity.status_code, 201)
        self.assertEqual(same_identity.json()["redirect"], "downstream-login.html")
        self.assertEqual(User.objects.filter(username="new-downstream").count(), 1)

    def test_invitation_list_includes_consumed_username_without_plain_code(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        response = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "registered-account",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
        )
        self.assertEqual(response.status_code, 201)

        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        listing = admin_client.get(reverse("accounts:api_invitation_collection"))
        self.assertEqual(listing.status_code, 200)
        item = listing.json()["items"][0]
        self.assertEqual(item["consumed_username"], "registered-account")
        self.assertNotIn("code", item)
        self.assertEqual(item["code_suffix"], normalize_invitation_code(issued[0].code)[-4:])
        self.assertTrue(item["masked_code"].endswith(item["code_suffix"]))

    def test_invitation_list_q_matches_username_not_code_suffix(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        response = self.post_json(
            "accounts:api_register",
            {
                "invitation_code": issued[0].code,
                "username": "registered-account",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
            },
        )
        self.assertEqual(response.status_code, 201)
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        public_id = str(issued[0].public_id)
        suffix = normalize_invitation_code(issued[0].code)[-4:]
        by_name = admin_client.get(reverse("accounts:api_invitation_collection"), {"q": "registered"})
        self.assertEqual(by_name.status_code, 200)
        self.assertIn(public_id, {item["public_id"] for item in by_name.json()["items"]})
        by_suffix = admin_client.get(reverse("accounts:api_invitation_collection"), {"q": suffix})
        self.assertEqual(by_suffix.status_code, 200)
        self.assertNotIn(public_id, {item["public_id"] for item in by_suffix.json()["items"]})
        by_code = admin_client.get(reverse("accounts:api_invitation_collection"), {"q": issued[0].code})
        self.assertEqual(by_code.status_code, 200)
        self.assertIn(public_id, {item["public_id"] for item in by_code.json()["items"]})
        too_long = admin_client.get(reverse("accounts:api_invitation_collection"), {"q": "x" * 129})
        self.assertEqual(too_long.status_code, 400)
        self.assertEqual(too_long.json()["error"]["code"], "INVALID_QUERY")

    def test_admin_can_search_an_older_invitation_without_returning_plaintext(self):
        _, old_issued = issue_invitation_batch(
            actor=self.admin,
            quantity=1,
            now=timezone.now() - timedelta(days=1),
        )
        issue_invitation_batch(actor=self.admin, quantity=100, now=timezone.now())
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        listing = admin_client.get(reverse("accounts:api_invitation_collection"))
        self.assertNotIn(str(old_issued[0].public_id), {item["public_id"] for item in listing.json()["items"]})

        self.client = admin_client
        response = self.post_json_url(
            reverse("accounts:api_invitation_search"),
            {"code": old_issued[0].code},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["item"]["public_id"], str(old_issued[0].public_id))
        self.assertNotIn("code", response.json()["item"])

    def test_admin_can_reveal_invitation_again_after_list_refresh(self):
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        self.client.force_login(self.admin)
        reveal_url = reverse("accounts:api_invitation_reveal", kwargs={"public_id": issued[0].public_id})

        listing = self.client.get(reverse("accounts:api_invitation_collection"))
        self.assertEqual(listing.status_code, 200)
        self.assertNotIn("code", listing.json()["items"][0])
        self.assertEqual(self.client.get(reveal_url).status_code, 405)
        missing_csrf = self.client.post(reveal_url, data="{}", content_type="application/json")
        self.assertEqual(missing_csrf.status_code, 403)

        first = self.post_json_url(reveal_url, {})
        second = self.post_json_url(reveal_url, {})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()["code"], issued[0].code)
        self.assertEqual(second.json()["code"], issued[0].code)
        self.assertNotIn("code", first.json()["item"])
        self.assertEqual(first["Cache-Control"], "no-store")
        self.assertFalse(
            AuditEvent.objects.filter(
                action="invitation.reveal",
                outcome="success",
                object_public_id=str(issued[0].public_id),
            ).exists()
        )

    def test_invitation_reveal_is_admin_scoped_and_rate_limited(self):
        cache.clear()
        _, issued = issue_invitation_batch(actor=self.admin, quantity=1)
        reveal_url = reverse("accounts:api_invitation_reveal", kwargs={"public_id": issued[0].public_id})
        downstream_client = Client()
        downstream_client.force_login(self.downstream)
        session = downstream_client.session
        session["downstream_session_version"] = self.downstream_profile.session_version
        session.save()
        self.assertEqual(downstream_client.post(reveal_url, data="{}", content_type="application/json").status_code, 403)

        admin_client = Client()
        admin_client.force_login(self.admin)
        with override_settings(INVITATION_REVEAL_RATE_LIMIT=1):
            first = admin_client.post(reveal_url, data="{}", content_type="application/json")
            limited = admin_client.post(reveal_url, data="{}", content_type="application/json")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")
        cache.clear()

    def test_admin_list_and_direct_create_are_server_scoped(self):
        forbidden = self.client.get(reverse("accounts:api_downstream_collection"))
        self.assertEqual(forbidden.status_code, 401)

        login = self.login_api("admin", "Admin-password-123", "admin")
        self.assertEqual(login.status_code, 200)
        created = self.post_json(
            "accounts:api_downstream_collection",
            {"username": "created-via-api", "password": "Downstream-password-123", "downstream_id": str(self.downstream_profile.public_id)},
            headers={"HTTP_IDEMPOTENCY_KEY": "create-via-api-1"},
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["profile"]["username"], "created-via-api")
        listing = self.client.get(reverse("accounts:api_downstream_collection"))
        self.assertEqual(listing.status_code, 200)
        usernames = {item["username"] for item in listing.json()["items"]}
        self.assertEqual(usernames, {"downstream-a", "created-via-api"})

    def test_downstream_collection_is_server_paginated(self):
        for index in range(25):
            create_downstream_direct(
                actor=self.admin,
                username=f"page-downstream-{index}",
                password="Downstream-password-123",
                request_id=f"page-downstream-{index}",
            )
        self.client.force_login(self.admin)
        first = self.client.get(reverse("accounts:api_downstream_collection"), {"page": 1, "page_size": 10})
        third = self.client.get(reverse("accounts:api_downstream_collection"), {"page": 3, "page_size": 10})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["pagination"]["total"], 26)
        self.assertEqual(len(first.json()["items"]), 10)
        self.assertEqual(third.json()["pagination"]["total_pages"], 3)
        self.assertEqual(len(third.json()["items"]), 6)

    def test_downstream_collection_status_filter_rejects_unknown_and_scopes_rows(self):
        self.client.force_login(self.admin)
        invalid = self.client.get(reverse("accounts:api_downstream_collection"), {"status": "deleted"})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["error"]["code"], "INVALID_STATUS")
        status_url = reverse("accounts:api_downstream_status", kwargs={"public_id": self.downstream_profile.public_id})
        suspended = self.post_json_url(
            status_url,
            {"status": "suspended", "reason": "筛选核对"},
            headers={"HTTP_IDEMPOTENCY_KEY": "collection-status-filter-1"},
        )
        self.assertEqual(suspended.status_code, 200)
        active = self.client.get(reverse("accounts:api_downstream_collection"), {"status": "active"})
        suspended_list = self.client.get(reverse("accounts:api_downstream_collection"), {"status": "suspended"})
        self.assertEqual(active.status_code, 200)
        self.assertEqual(suspended_list.status_code, 200)
        self.assertNotIn(self.downstream_profile.user.username, {item["username"] for item in active.json()["items"]})
        self.assertIn(self.downstream_profile.user.username, {item["username"] for item in suspended_list.json()["items"]})

    def test_direct_create_rejects_invalid_username_and_audits_failure(self):
        self.client.force_login(self.admin)
        response = self.post_json(
            "accounts:api_downstream_collection",
            {"username": "not valid!", "password": "Downstream-password-123"},
            headers={"HTTP_IDEMPOTENCY_KEY": "create-invalid-1"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "ACCOUNT_CREATION_FAILED")
        self.assertFalse(User.objects.filter(username__iexact="not valid!").exists())
        self.assertTrue(
            AuditEvent.objects.filter(
                action="downstream.create_direct",
                outcome="failure",
                reason_code="ACCOUNT_CREATION_FAILED",
            ).exists()
        )

    def test_hybrid_admin_downstream_account_cannot_enter_downstream_role(self):
        hybrid = User.objects.create_user(username="hybrid-account", password="Downstream-password-123")
        DownstreamProfile.objects.create(user=hybrid, registration_source="direct")
        hybrid.groups.add(Group.objects.get(name="downstream"))
        hybrid.groups.add(Group.objects.get_or_create(name="platform_admin")[0])

        rejected = self.login_api("hybrid-account", "Downstream-password-123", "downstream")
        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(rejected.json()["error"]["code"], "AUTHENTICATION_FAILED")
        self.assertNotIn("_auth_user_id", self.client.session)

        accepted = self.login_api("hybrid-account", "Downstream-password-123", "admin")
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["role"], "platform_admin")

    def test_invitation_collection_paginates_before_returning_old_codes(self):
        issue_invitation_batch(actor=self.admin, quantity=100, idempotency_key="inv-page-first")
        issue_invitation_batch(actor=self.admin, quantity=1, idempotency_key="inv-page-second")
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        first = admin_client.get(reverse("accounts:api_invitation_collection"), {"page": 1})
        last = admin_client.get(reverse("accounts:api_invitation_collection"), {"page": 21})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(last.status_code, 200)
        self.assertEqual(first.json()["pagination"]["page_size"], 5)
        self.assertEqual(first.json()["pagination"]["total"], 101)
        self.assertEqual(first.json()["pagination"]["total_pages"], 21)
        self.assertEqual(len(first.json()["items"]), 5)
        self.assertEqual(len(last.json()["items"]), 1)
        self.assertFalse(last.json()["pagination"]["has_next"])

    def test_collection_paths_reject_unsupported_methods_and_do_not_expose_internal_fields(self):
        self.client.force_login(self.admin)
        downstreams = self.client.get(reverse("accounts:api_downstream_collection"))
        self.assertEqual(downstreams.status_code, 200)
        listed = downstreams.json()["items"][0]
        self.assertNotIn("session_version", listed)
        self.assertEqual(listed["active_authorization_count"], 0)
        self.assertEqual(listed["unused_card_count"], 0)
        self.assertEqual(listed["available_balance"], 0)

        invitations = self.client.get(reverse("accounts:api_invitation_collection"))
        self.assertEqual(invitations.status_code, 200)
        self.assertEqual(
            invitations.json(),
            {
                "items": [],
                "scope": "current",
                "pagination": {
                    "page": 1,
                    "page_size": 5,
                    "total": 0,
                    "total_pages": 1,
                    "has_previous": False,
                    "has_next": False,
                },
            },
        )

        method_not_allowed = self.client.put(
            reverse("accounts:api_downstream_collection"),
            data="{}",
            content_type="application/json",
            **self.csrf_headers(),
        )
        self.assertEqual(method_not_allowed.status_code, 405)
        self.assertEqual(method_not_allowed.json()["error"]["code"], "METHOD_NOT_ALLOWED")

    def test_status_and_lifecycle_actions_validate_string_fields(self):
        self.client.force_login(self.admin)
        profile_url = reverse(
            "accounts:api_downstream_status",
            kwargs={"public_id": self.downstream_profile.public_id},
        )
        invalid_status = self.post_json_url(profile_url, {"status": None, "reason": "类型校验"}, headers={"HTTP_IDEMPOTENCY_KEY": "status-invalid-1"})
        self.assertEqual(invalid_status.status_code, 400)
        self.assertEqual(invalid_status.json()["error"]["code"], "INVALID_REQUEST")

        archive_url = reverse(
            "accounts:api_downstream_archive",
            kwargs={"public_id": self.downstream_profile.public_id},
        )
        invalid_reason = self.post_json_url(archive_url, {"reason": {}}, headers={"HTTP_IDEMPOTENCY_KEY": "archive-invalid-1"})
        self.assertEqual(invalid_reason.status_code, 400)
        self.assertEqual(invalid_reason.json()["error"]["code"], "INVALID_REQUEST")

    def test_invitation_issue_reuses_one_request_id(self):
        self.client.force_login(self.admin)
        response = self.post_json_url(
            reverse("accounts:api_invitation_collection"),
            {"quantity": 1},
            headers={"HTTP_IDEMPOTENCY_KEY": "request-id-check"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["request_id"])

    def test_invitation_issue_is_single_code_list_and_idempotent(self):
        self.client.force_login(self.admin)
        headers = {**self.csrf_headers(), "HTTP_IDEMPOTENCY_KEY": "b1-invitation-issue-1"}
        payload = json.dumps({"quantity": 2})
        first = self.client.post(
            reverse("accounts:api_invitation_collection"),
            data=payload,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(first.status_code, 201)
        self.assertEqual(len(first.json()["items"]), 2)
        self.assertTrue(all(item["expires_at"] is None for item in first.json()["items"]))
        from authorization_platform.accounts.models import InvitationBatch

        self.assertEqual(InvitationBatch.objects.filter(created_by=self.admin).count(), 1)
        # Durable idempotency must survive cache eviction/restart; the retry
        # must re-decrypt the stored ciphertext instead of issuing new codes.
        cache.clear()
        repeated = self.client.post(
            reverse("accounts:api_invitation_collection"),
            data=payload,
            content_type="application/json",
            **headers,
        )
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json()["items"], first.json()["items"])
        self.assertEqual(InvitationBatch.objects.filter(created_by=self.admin).count(), 1)
        conflict = self.client.post(
            reverse("accounts:api_invitation_collection"),
            data=json.dumps({"quantity": 1}),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_invitation_issue_is_rate_limited(self):
        cache.clear()
        self.client.force_login(self.admin)
        from authorization_platform.accounts.models import InvitationBatch

        with override_settings(INVITATION_ISSUE_RATE_LIMIT=1):
            first = self.post_json_url(
                reverse("accounts:api_invitation_collection"),
                {"quantity": 1},
                headers={"HTTP_IDEMPOTENCY_KEY": "invite-issue-rate-1"},
            )
            limited = self.post_json_url(
                reverse("accounts:api_invitation_collection"),
                {"quantity": 1},
                headers={"HTTP_IDEMPOTENCY_KEY": "invite-issue-rate-2"},
            )
        self.assertEqual(first.status_code, 201)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")
        self.assertEqual(InvitationBatch.objects.filter(created_by=self.admin).count(), 1)
        cache.clear()

    def test_status_and_delete_api_require_server_lifecycle_order(self):
        self.client.force_login(self.admin)
        status_url = reverse("accounts:api_downstream_status", kwargs={"public_id": self.downstream_profile.public_id})
        suspended = self.post_json_url(status_url, {"status": "suspended", "reason": "暂停售后核对"}, headers={"HTTP_IDEMPOTENCY_KEY": "status-lifecycle-1"})
        self.assertEqual(suspended.status_code, 200)
        self.assertEqual(suspended.json()["profile"]["status"], "suspended")

        delete_url = reverse("accounts:api_downstream_delete", kwargs={"public_id": self.downstream_profile.public_id})
        not_confirmed = self.post_json_url(delete_url, {"confirmation": False, "reason": "误操作"}, headers={"HTTP_IDEMPOTENCY_KEY": "delete-not-confirmed-1"})
        self.assertEqual(not_confirmed.status_code, 400)
        self.assertEqual(not_confirmed.json()["error"]["code"], "CONFIRMATION_REQUIRED")

        archive_url = reverse("accounts:api_downstream_archive", kwargs={"public_id": self.downstream_profile.public_id})
        archived = self.post_json_url(archive_url, {"reason": "完成归档测试"}, headers={"HTTP_IDEMPOTENCY_KEY": "archive-lifecycle-1"})
        self.assertEqual(archived.status_code, 200)
        deleted = self.post_json_url(delete_url, {"confirmation": True, "reason": "删除归档测试"}, headers={"HTTP_IDEMPOTENCY_KEY": "delete-lifecycle-1"})
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["deleted"])

    def test_archive_and_delete_api_reject_unclear_balance(self):
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_profile,
            amount=12,
            reason="归档前余额闸",
            idempotency_key="archive-balance-credit",
        )
        self.client.force_login(self.admin)
        archive_url = reverse("accounts:api_downstream_archive", kwargs={"public_id": self.downstream_profile.public_id})
        leftover = self.post_json_url(archive_url, {"reason": "未清余额归档"}, headers={"HTTP_IDEMPOTENCY_KEY": "archive-balance-1"})
        self.assertEqual(leftover.status_code, 409)
        self.assertEqual(leftover.json()["error"]["code"], "BALANCE_NOT_CLEARED")
        listing = self.client.get(reverse("accounts:api_downstream_collection"))
        item = next(row for row in listing.json()["items"] if row["username"] == "downstream-a")
        self.assertEqual(item["available_balance"], 12)
        self.assertEqual(item["active_authorization_count"], 0)
        self.assertEqual(item["unused_card_count"], 0)

    def test_downstream_cannot_use_admin_scope_or_read_another_profile(self):
        response = self.login_api("downstream-a", "Downstream-password-123", "downstream")
        self.assertEqual(response.status_code, 200)
        list_response = self.client.get(reverse("accounts:api_downstream_collection"))
        self.assertEqual(list_response.status_code, 403)
        self.assertEqual(list_response.json()["error"]["code"], "FORBIDDEN")

    def test_archive_invalidates_existing_downstream_session(self):
        downstream_client = Client(enforce_csrf_checks=True)
        downstream_client.force_login(self.downstream)
        downstream_client.session["downstream_session_version"] = self.downstream_profile.session_version
        downstream_client.session.save()

        self.client.force_login(self.admin)
        archive = self.post_json_url(
            reverse("accounts:api_downstream_archive", kwargs={"public_id": self.downstream_profile.public_id}),
            {"reason": "B1 生命周期测试"},
            headers={"HTTP_IDEMPOTENCY_KEY": "archive-session-1"},
        )
        self.assertEqual(archive.status_code, 200)
        self.assertEqual(archive.json()["profile"]["status"], "closed")

        stale = downstream_client.get(reverse("accounts:api_session"))
        self.assertEqual(stale.status_code, 200)
        self.assertEqual(stale.json()["role"], "anonymous")
        self.assertFalse(stale.json()["authenticated"])

    def test_suspended_downstream_cannot_login_or_keep_session(self):
        downstream_client = Client(enforce_csrf_checks=True)
        login = self.login_api("downstream-a", "Downstream-password-123", "downstream")
        self.assertEqual(login.status_code, 200)
        downstream_client.force_login(self.downstream)
        downstream_client.session["downstream_session_version"] = self.downstream_profile.session_version
        downstream_client.session.save()

        self.client.force_login(self.admin)
        paused = self.post_json_url(
            reverse("accounts:api_downstream_status", kwargs={"public_id": self.downstream_profile.public_id}),
            {"status": "suspended", "reason": "暂停登录验收"},
            headers={"HTTP_IDEMPOTENCY_KEY": "pause-login-1"},
        )
        self.assertEqual(paused.status_code, 200)
        self.assertEqual(paused.json()["profile"]["status"], "suspended")

        stale = downstream_client.get(reverse("accounts:api_session"))
        self.assertEqual(stale.status_code, 200)
        self.assertFalse(stale.json()["authenticated"])
        self.client.logout()
        blocked = self.login_api("downstream-a", "Downstream-password-123", "downstream")
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json()["error"]["code"], "ACCOUNT_SUSPENDED")
        self.assertIn("账号已暂停", blocked.json()["error"]["message"])
        wrong_password = self.login_api("downstream-a", "Wrong-password-123", "downstream")
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(wrong_password.json()["error"]["code"], "AUTHENTICATION_FAILED")
        self.assertIn("用户名或密码不正确", wrong_password.json()["error"]["message"])

    def test_invitation_revoke_json_stops_issued_code_from_registering(self):
        self.client.force_login(self.admin)
        issued = self.post_json_url(
            reverse("accounts:api_invitation_collection"),
            {"quantity": 1},
            headers={"HTTP_IDEMPOTENCY_KEY": "invite-revoke-issue-1"},
        )
        self.assertEqual(issued.status_code, 201, issued.content)
        item = issued.json()["items"][0]
        code = item["code"]
        public_id = item["public_id"]
        revoked = self.post_json_url(
            reverse("accounts:api_invitation_revoke", kwargs={"public_id": public_id}),
            {"reason": "发错码作废"},
        )
        self.assertEqual(revoked.status_code, 200, revoked.content)
        self.assertEqual(revoked.json()["item"]["status"], "revoked")
        self.client.logout()
        register = self.post_json(
            "accounts:api_register",
            {
                "username": "revoke-shop",
                "password": "Downstream-password-123",
                "password_confirm": "Downstream-password-123",
                "invitation_code": code,
            },
        )
        self.assertIn(register.status_code, (400, 409))
        self.assertFalse(User.objects.filter(username="revoke-shop").exists())


class DownstreamAdminOperationApiTests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(username="operation-admin", password="Admin-password-123")
        self.downstream = User.objects.create_user(username="operation-downstream", password="Downstream-password-123")
        self.profile = DownstreamProfile.objects.create(user=self.downstream, registration_source="direct")
        self.downstream.groups.create(name="downstream")

    def post_url(self, url, payload, *, key):
        self.client.get(reverse("accounts:api_session"))
        self.client.force_login(self.admin)
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.client.cookies["csrftoken"].value,
            HTTP_IDEMPOTENCY_KEY=key,
        )

    def test_create_replay_and_conflict_are_durable_and_password_is_not_stored(self):
        payload = {"username": "durable-created", "password": "Cedar!Orbit-71-Blue"}
        first = self.post_url(reverse("accounts:api_downstream_collection"), payload, key="downstream-create-durable-1")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(first.json()["profile"]["username"], "durable-created")
        self.assertEqual(first.json()["profile"]["available_balance"], 0)
        self.assertEqual(first.json()["profile"]["active_authorization_count"], 0)
        self.assertEqual(first.json()["profile"]["unused_card_count"], 0)
        repeated = self.post_url(reverse("accounts:api_downstream_collection"), payload, key="downstream-create-durable-1")
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json(), first.json())
        self.assertEqual(User.objects.filter(username="durable-created").count(), 1)
        operation = DownstreamAdminOperation.objects.get(actor=self.admin, idempotency_key="downstream-create-durable-1")
        self.assertNotIn("Cedar!Orbit-71-Blue", str(operation.__dict__))
        self.assertNotIn("Cedar!Orbit-71-Blue", first.content.decode())

        conflict = self.post_url(
            reverse("accounts:api_downstream_collection"),
            {"username": "durable-created", "password": "Different!Orbit-72-Blue"},
            key="downstream-create-durable-1",
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(DownstreamAdminOperation.objects.filter(actor=self.admin, idempotency_key="downstream-create-durable-1").count(), 1)

    def test_status_archive_delete_replay_do_not_repeat_lifecycle_or_create_half_results(self):
        status_url = reverse("accounts:api_downstream_status", kwargs={"public_id": self.profile.public_id})
        status_payload = {"status": "suspended", "reason": "持久幂等状态测试"}
        first_status = self.post_url(status_url, status_payload, key="downstream-status-durable-1")
        self.assertEqual(first_status.status_code, 200)
        repeated_status = self.post_url(status_url, status_payload, key="downstream-status-durable-1")
        self.assertEqual(repeated_status.status_code, 200)
        self.assertEqual(repeated_status.json(), first_status.json())

        conflict = self.post_url(
            status_url,
            {"status": "active", "reason": "同键不同状态"},
            key="downstream-status-durable-1",
        )
        self.assertEqual(conflict.status_code, 409)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.status, DownstreamStatus.SUSPENDED)

        archive_url = reverse("accounts:api_downstream_archive", kwargs={"public_id": self.profile.public_id})
        archived = self.post_url(archive_url, {"reason": "持久幂等归档测试"}, key="downstream-archive-durable-1")
        self.assertEqual(archived.status_code, 200)
        repeated_archive = self.post_url(archive_url, {"reason": "持久幂等归档测试"}, key="downstream-archive-durable-1")
        self.assertEqual(repeated_archive.json(), archived.json())

        delete_url = reverse("accounts:api_downstream_delete", kwargs={"public_id": self.profile.public_id})
        deleted = self.post_url(delete_url, {"confirmation": True, "reason": "持久幂等删除测试"}, key="downstream-delete-durable-1")
        self.assertEqual(deleted.status_code, 200)
        repeated_delete = self.post_url(delete_url, {"confirmation": True, "reason": "持久幂等删除测试"}, key="downstream-delete-durable-1")
        self.assertEqual(repeated_delete.status_code, 200)
        self.assertEqual(repeated_delete.json(), deleted.json())
        self.assertFalse(DownstreamProfile.objects.filter(public_id=self.profile.public_id).exists())
        self.assertEqual(
            DownstreamAdminOperation.objects.filter(actor=self.admin).count(),
            3,
        )

    def test_missing_key_and_immutable_operation_guard(self):
        self.client.get(reverse("accounts:api_session"))
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("accounts:api_downstream_collection"),
            data=json.dumps({"username": "missing-key-user", "password": "Cedar!Orbit-71-Blue"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.client.cookies["csrftoken"].value,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "IDEMPOTENCY_REQUIRED")
        self.assertFalse(User.objects.filter(username="missing-key-user").exists())
        self.assertEqual(DownstreamAdminOperation.objects.count(), 0)

        operation = DownstreamAdminOperation.objects.create(
            actor=self.admin,
            action="status",
            target_profile_public_id=self.profile.public_id,
            idempotency_key="immutable-operation-fixture",
            request_hash="a" * 64,
            response_payload={"ok": True},
        )
        with self.assertRaises(ValueError):
            DownstreamAdminOperation.objects.filter(public_id=operation.public_id).update(request_hash="b" * 64)
        with self.assertRaises(ValueError):
            operation.delete()


class PasswordLifecycleApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="password-admin", password="Admin-password-123")
        self.downstream = User.objects.create_user(username="password-downstream", password="Downstream-password-123")
        self.profile = DownstreamProfile.objects.create(user=self.downstream, registration_source="direct")
        self.downstream.groups.create(name="downstream")

    def csrf_headers(self, client):
        response = client.get(reverse("accounts:api_session"))
        self.assertEqual(response.status_code, 200)
        return {"HTTP_X_CSRFTOKEN": client.cookies["csrftoken"].value}

    def post_json(self, client, url, payload, *, key):
        headers = self.csrf_headers(client)
        headers["HTTP_IDEMPOTENCY_KEY"] = key
        return client.post(url, data=json.dumps(payload), content_type="application/json", **headers)

    def login_as_downstream(self, client):
        client.force_login(self.downstream)
        session = client.session
        session["downstream_session_version"] = self.profile.session_version
        session.save()

    def test_admin_can_change_own_password_and_current_session_survives(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        old_session = Client(enforce_csrf_checks=True)
        old_session.force_login(self.admin)

        response = self.post_json(
            client,
            reverse("accounts:api_password_change"),
            {
                "current_password": "Admin-password-123",
                "new_password": "Quartz!River-42-Mango",
                "new_password_confirm": "Quartz!River-42-Mango",
            },
            key="admin-change-1",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["changed"])
        self.assertNotIn("Admin-password-123", response.content.decode())
        self.assertNotIn("Quartz!River-42-Mango", response.content.decode())
        self.assertTrue(User.objects.get(pk=self.admin.pk).check_password("Quartz!River-42-Mango"))
        self.assertEqual(PasswordOperation.objects.filter(action="change").count(), 1)
        self.assertEqual(client.get(reverse("accounts:api_session")).json()["role"], "platform_admin")
        self.assertFalse(old_session.get(reverse("accounts:api_session")).json()["authenticated"])

        replay = self.post_json(
            client,
            reverse("accounts:api_password_change"),
            {
                "current_password": "Admin-password-123",
                "new_password": "Quartz!River-42-Mango",
                "new_password_confirm": "Quartz!River-42-Mango",
            },
            key="admin-change-1",
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.json()["replayed"])
        self.assertEqual(PasswordOperation.objects.filter(action="change").count(), 1)

    def test_downstream_change_bumps_version_and_invalidates_other_sessions(self):
        client = Client(enforce_csrf_checks=True)
        self.login_as_downstream(client)
        old_session = Client(enforce_csrf_checks=True)
        self.login_as_downstream(old_session)
        previous_version = self.profile.session_version

        response = self.post_json(
            client,
            reverse("accounts:api_password_change"),
            {
                "current_password": "Downstream-password-123",
                "new_password": "Nimbus!Cedar-73-Fox",
                "new_password_confirm": "Nimbus!Cedar-73-Fox",
            },
            key="downstream-change-1",
        )
        self.assertEqual(response.status_code, 200)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.session_version, previous_version + 1)
        self.assertEqual(client.get(reverse("accounts:api_session")).json()["role"], "downstream")
        self.assertFalse(old_session.get(reverse("accounts:api_session")).json()["authenticated"])
        self.assertTrue(User.objects.get(pk=self.downstream.pk).check_password("Nimbus!Cedar-73-Fox"))

    def test_admin_reset_invalidates_target_sessions_and_is_durable_idempotent(self):
        downstream_session = Client(enforce_csrf_checks=True)
        self.login_as_downstream(downstream_session)
        admin_client = Client(enforce_csrf_checks=True)
        admin_client.force_login(self.admin)
        previous_version = self.profile.session_version
        reset_url = reverse("accounts:api_downstream_password_reset", kwargs={"public_id": self.profile.public_id})
        payload = {
            "new_password": "Maple!Orbit-91-Slate",
            "new_password_confirm": "Maple!Orbit-91-Slate",
            "reason": "管理员协助恢复登录",
        }

        response = self.post_json(admin_client, reset_url, payload, key="admin-reset-1")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["reset"])
        self.assertNotIn("Maple!Orbit-91-Slate", response.content.decode())
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.session_version, previous_version + 1)
        self.assertFalse(downstream_session.get(reverse("accounts:api_session")).json()["authenticated"])
        self.assertTrue(User.objects.get(pk=self.downstream.pk).check_password("Maple!Orbit-91-Slate"))
        operation = PasswordOperation.objects.get(action="reset")
        self.assertNotIn("管理员协助恢复登录", str(operation.response_payload))
        with self.assertRaises(ValueError):
            operation.save()
        with self.assertRaises(ValueError):
            PasswordOperation.objects.filter(public_id=operation.public_id).update(request_hash="tampered")
        with self.assertRaises(ValueError):
            operation.delete()

        repeated = self.post_json(admin_client, reset_url, payload, key="admin-reset-1")
        self.assertEqual(repeated.status_code, 200)
        self.assertTrue(repeated.json()["replayed"])
        self.assertEqual(PasswordOperation.objects.filter(action="reset").count(), 1)

        conflict = self.post_json(
            admin_client,
            reset_url,
            {**payload, "new_password": "Harbor!Mint-58-Cloud", "new_password_confirm": "Harbor!Mint-58-Cloud"},
            key="admin-reset-1",
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_password_endpoints_cover_csrf_missing_key_wrong_password_and_rate_limit(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        no_csrf = client.post(
            reverse("accounts:api_password_change"),
            data=json.dumps(
                {
                    "current_password": "Admin-password-123",
                    "new_password": "Quartz!River-42-Mango",
                    "new_password_confirm": "Quartz!River-42-Mango",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(no_csrf.json()["error"]["code"], "CSRF_FAILED")
        missing_key = self.post_json(
            client,
            reverse("accounts:api_password_change"),
            {
                "current_password": "Admin-password-123",
                "new_password": "Quartz!River-42-Mango",
                "new_password_confirm": "Quartz!River-42-Mango",
            },
            key="",
        )
        self.assertEqual(missing_key.status_code, 400)
        self.assertEqual(missing_key.json()["error"]["code"], "IDEMPOTENCY_REQUIRED")
        wrong = self.post_json(
            client,
            reverse("accounts:api_password_change"),
            {
                "current_password": "wrong-current-password",
                "new_password": "Quartz!River-42-Mango",
                "new_password_confirm": "Quartz!River-42-Mango",
            },
            key="admin-change-wrong",
        )
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(wrong.json()["error"]["code"], "CURRENT_PASSWORD_INVALID")
        cache.clear()
        with override_settings(AUTH_PASSWORD_CHANGE_RATE_LIMIT=1):
            first = self.post_json(
                client,
                reverse("accounts:api_password_change"),
                {
                    "current_password": "wrong-current-password",
                    "new_password": "Quartz!River-42-Mango",
                    "new_password_confirm": "Quartz!River-42-Mango",
                },
                key="admin-change-rate-1",
            )
            limited = self.post_json(
                client,
                reverse("accounts:api_password_change"),
                {
                    "current_password": "wrong-current-password",
                    "new_password": "Quartz!River-42-Mango",
                    "new_password_confirm": "Quartz!River-42-Mango",
                },
                key="admin-change-rate-2",
            )
        self.assertEqual(first.status_code, 400)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["error"]["code"], "RATE_LIMITED")

    def test_downstream_cannot_reset_password_and_password_audit_has_no_secret(self):
        downstream_client = Client(enforce_csrf_checks=True)
        self.login_as_downstream(downstream_client)
        url = reverse("accounts:api_downstream_password_reset", kwargs={"public_id": self.profile.public_id})
        response = self.post_json(
            downstream_client,
            url,
            {
                "new_password": "Maple!Orbit-91-Slate",
                "new_password_confirm": "Maple!Orbit-91-Slate",
                "reason": "越权测试",
            },
            key="downstream-reset-1",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "FORBIDDEN")
        self.assertFalse(PasswordOperation.objects.exists())
        events = AuditEvent.objects.filter(action__in=["auth.password_change", "auth.password_reset"])
        self.assertFalse(any(secret in str(event.metadata) for event in events for secret in (
            "Downstream-password-123",
            "Maple!Orbit-91-Slate",
            "越权测试",
        )))
