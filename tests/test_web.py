from __future__ import annotations

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse


class FoundationWebTests(TestCase):
    def test_health_check_reports_database_and_time_contract(self):
        response = self.client.get("/healthz/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["database"], "ok")
        self.assertEqual(payload["display_timezone"], "Asia/Shanghai")
        self.assertTrue(payload["server_time"].endswith("Z"))

    def test_health_check_reports_migration_and_cache_state(self):
        """A connectivity-only probe cannot see the two failures that actually
        break requests: pending migrations (code referencing a column the
        database does not have yet) and an unusable shared cache (every rate
        limit is built on it)."""
        payload = self.client.get("/healthz/").json()
        self.assertIn("migrations", payload)
        self.assertIn("cache", payload)
        self.assertIn("disk", payload)
        self.assertEqual(payload["migrations"], "ok")

    def test_health_check_turns_red_when_migrations_are_pending(self):
        with mock.patch(
            "authorization_platform.core.views._unapplied_migrations",
            return_value=["catalog", "licensing"],
        ):
            response = self.client.get("/healthz/")
        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertEqual(payload["status"], "error")
        self.assertIn("migrations_pending", payload["blockers"])
        # Internal labels must not leak through an unauthenticated endpoint.
        self.assertNotIn("catalog", str(payload))

    def test_health_check_does_not_write_the_cache_for_external_callers(self):
        broken = mock.Mock()
        broken.set.side_effect = AssertionError("an anonymous caller must not be able to write the cache")
        with mock.patch("authorization_platform.core.views.cache", broken):
            response = self.client.get("/healthz/", REMOTE_ADDR="203.0.113.9")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["cache"], "skipped")

    def test_health_check_reports_an_unusable_cache_for_internal_callers(self):
        broken = mock.Mock()
        broken.set.side_effect = RuntimeError("cache table is gone")
        with mock.patch("authorization_platform.core.views.cache", broken):
            response = self.client.get("/healthz/", REMOTE_ADDR="127.0.0.1")
        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertIn("cache_unavailable", payload["blockers"])
        self.assertEqual(payload["cache"], "unavailable")

    def test_unapplied_migration_detection_sees_a_real_missing_record(self):
        """The contract test above mocks the detector; this one exercises it.

        "New code, old schema" is the failure mode the plain connectivity probe
        could never see, so the detection itself needs a test.
        """
        from django.db import connection
        from django.db.migrations.recorder import MigrationRecorder

        from authorization_platform.core.views import _unapplied_migrations

        self.assertEqual(_unapplied_migrations(), [])

        recorder = MigrationRecorder(connection)
        victim = sorted(
            key for key in recorder.applied_migrations() if key[0] == "licensing"
        )[-1]
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM django_migrations WHERE app = %s AND name = %s",
                [victim[0], victim[1]],
            )
        self.assertIn(victim, [tuple(item) for item in _unapplied_migrations()])

    def test_home_is_a_chinese_ui_shell(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "授权平台总览")
        self.assertContains(response, "1 分钟测试卡为 60 秒")
        self.assertContains(response, "Asia/Shanghai")

    @override_settings(DEBUG=False)
    def test_permission_denied_uses_the_role_aware_error_page(self):
        user = get_user_model().objects.create_user(username="web-denied", password="Web-denied-123")
        self.client.force_login(user)

        response = self.client.get(reverse("accounts:manage_dashboard"))

        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "当前账号没有访问权限", status_code=403)
        self.assertContains(response, "返回总览", status_code=403)
        self.assertNotContains(response, "Traceback", status_code=403)
