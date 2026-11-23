from __future__ import annotations

import json
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from authorization_platform.accounts.models import DownstreamProfile
from authorization_platform.accounts.roles import is_platform_admin_user
from authorization_platform.accounts.services import is_platform_admin


class SeedDemoTests(TestCase):
    demo_env = {
        "DEMO_ADMIN_PASSWORD": "Admin-password-123",
        "DEMO_DOWNSTREAM_PASSWORD": "Downstream-pass-123",
    }

    def test_seed_demo_creates_admin_and_downstream_roles_without_printing_passwords(self):
        output = self.capture_output()
        with patch.dict("os.environ", self.demo_env):
            call_command("seed_demo", stdout=output)
        user_model = get_user_model()
        admin = user_model.objects.get(username="admin")
        downstream = user_model.objects.get(username="demo_downstream")
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.check_password("Admin-password-123"))
        self.assertFalse(downstream.is_staff)
        self.assertTrue(downstream.check_password("Downstream-pass-123"))
        self.assertTrue(admin.groups.filter(name="platform_admin").exists())
        self.assertTrue(downstream.groups.filter(name="downstream").exists())
        self.assertTrue(Group.objects.filter(name="platform_admin").exists())
        self.assertNotIn("Admin-password-123", output.getvalue())
        self.assertNotIn("Downstream-pass-123", output.getvalue())

    def test_seed_demo_refuses_existing_downstream_named_admin_without_promoting(self):
        user_model = get_user_model()
        existing = user_model.objects.create_user(
            username="admin",
            password="Existing-downstream-123",
            is_staff=False,
            is_superuser=False,
        )
        existing.groups.add(Group.objects.get_or_create(name="downstream")[0])
        DownstreamProfile.objects.create(user=existing, registration_source="direct")

        with patch.dict("os.environ", self.demo_env):
            with self.assertRaises(CommandError) as raised:
                call_command("seed_demo", stdout=self.capture_output())

        existing.refresh_from_db()
        self.assertIn("用户名已存在", str(raised.exception))
        self.assertFalse(existing.is_superuser)
        self.assertFalse(existing.is_staff)
        self.assertFalse(existing.groups.filter(name="platform_admin").exists())
        self.assertTrue(existing.groups.filter(name="downstream").exists())
        self.assertTrue(existing.check_password("Existing-downstream-123"))
        self.assertFalse(is_platform_admin(existing))
        self.assertFalse(is_platform_admin_user(existing))
        self.assertFalse(user_model.objects.filter(username="demo_downstream").exists())
        self.assertEqual(self.login_api("admin", "Existing-downstream-123", "admin").status_code, 401)
        self.assertEqual(self.login_api("admin", "Existing-downstream-123", "downstream").status_code, 200)

    def test_seed_demo_refuses_admin_username_demo_without_promoting_existing_downstream(self):
        user_model = get_user_model()
        existing = user_model.objects.create_user(
            username="demo",
            password="Existing-downstream-123",
            is_staff=False,
            is_superuser=False,
        )
        existing.groups.add(Group.objects.get_or_create(name="downstream")[0])
        DownstreamProfile.objects.create(user=existing, registration_source="direct")

        with patch.dict("os.environ", self.demo_env):
            with self.assertRaises(CommandError):
                call_command("seed_demo", "--admin-username=demo", stdout=self.capture_output())

        existing.refresh_from_db()
        self.assertFalse(existing.is_superuser)
        self.assertFalse(existing.is_staff)
        self.assertFalse(existing.groups.filter(name="platform_admin").exists())
        self.assertTrue(existing.check_password("Existing-downstream-123"))
        self.assertFalse(is_platform_admin(existing))
        self.assertFalse(user_model.objects.filter(username="admin").exists())

    def test_seed_demo_refuses_downstream_username_colliding_with_superuser(self):
        user_model = get_user_model()
        boss = user_model.objects.create_superuser(username="boss", password="Boss-password-123")

        with patch.dict("os.environ", self.demo_env):
            with self.assertRaises(CommandError):
                call_command("seed_demo", "--downstream-username=boss", stdout=self.capture_output())

        boss.refresh_from_db()
        self.assertTrue(boss.is_superuser)
        self.assertTrue(boss.is_staff)
        self.assertFalse(boss.groups.filter(name="downstream").exists())
        self.assertTrue(is_platform_admin(boss))
        self.assertFalse(user_model.objects.filter(username="admin").exists())
        self.assertFalse(user_model.objects.filter(username="demo_downstream").exists())

    def test_seed_demo_refuses_identical_admin_and_downstream_usernames(self):
        with patch.dict("os.environ", self.demo_env):
            with self.assertRaises(CommandError) as raised:
                call_command(
                    "seed_demo",
                    "--admin-username=same-user",
                    "--downstream-username=same-user",
                    stdout=self.capture_output(),
                )
        self.assertIn("同一用户名", str(raised.exception))
        self.assertFalse(get_user_model().objects.filter(username="same-user").exists())

    def test_seed_demo_refuses_second_run_without_changing_existing_roles(self):
        user_model = get_user_model()
        with patch.dict("os.environ", self.demo_env):
            call_command("seed_demo", stdout=self.capture_output())
            with self.assertRaises(CommandError):
                call_command("seed_demo", stdout=self.capture_output())

        admin = user_model.objects.get(username="admin")
        downstream = user_model.objects.get(username="demo_downstream")
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.groups.filter(name="platform_admin").exists())
        self.assertFalse(downstream.is_superuser)
        self.assertFalse(downstream.is_staff)
        self.assertFalse(downstream.groups.filter(name="platform_admin").exists())
        self.assertTrue(downstream.check_password("Downstream-pass-123"))

    @override_settings(APP_ENV="production")
    def test_seed_demo_refuses_production_without_creating_accounts(self):
        with patch.dict("os.environ", self.demo_env):
            with self.assertRaises(CommandError) as raised:
                call_command("seed_demo", stdout=self.capture_output())
        self.assertIn("production", str(raised.exception))
        self.assertFalse(get_user_model().objects.filter(username="admin").exists())
        self.assertFalse(get_user_model().objects.filter(username="demo_downstream").exists())

    def login_api(self, username, password, entrypoint):
        client = Client(enforce_csrf_checks=True)
        session = client.get(reverse("accounts:api_session"))
        self.assertEqual(session.status_code, 200)
        return client.post(
            reverse("accounts:api_login"),
            data=json.dumps({"username": username, "password": password, "entrypoint": entrypoint}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        )

    def capture_output(self):
        return StringIO()
