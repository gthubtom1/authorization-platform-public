from __future__ import annotations

import base64
import ipaddress
import os
import subprocess
import sys
from pathlib import Path

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from authorization_platform.core.middleware import TrustedProxyHeadersMiddleware

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_SRC = REPO_ROOT / "src"


def production_settings_env(**overrides: str) -> dict[str, str]:
    """A complete, valid non-local environment; callers override one thing."""

    values = {
        "APP_ENV": "production",
        "DJANGO_DEBUG": "false",
        "DJANGO_SECRET_KEY": "django-secret-unique-1234567890-pad-to-fifty-chars!!!!",
        "ALLOWED_HOSTS": "auth.example.com",
        "CSRF_TRUSTED_ORIGINS": "https://auth.example.com",
        "TRUSTED_PROXY_IPS": "10.0.0.0/8",
        "TRUST_PROXY_SSL_HEADER": "true",
        "SECURE_SSL_REDIRECT": "true",
        "SECURE_HSTS_SECONDS": "31536000",
        "SECURE_HSTS_INCLUDE_SUBDOMAINS": "true",
        "DATABASE_ENGINE": "postgresql",
        "DATABASE_NAME": "authorization_platform",
        "DATABASE_USER": "authorization_platform",
        "DATABASE_PASSWORD": "database-secret",
        "DATABASE_HOST": "db.internal",
        "DATABASE_PORT": "5432",
        "DJANGO_CACHE_BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "AUTHORIZATION_PLATFORM_WORKERS": "2",
        "AUTHORIZATION_SIGNING_KEY_ID": "platform-prod-v1",
        "RELEASE_SIGNING_PUBLIC_KEY": base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("="),
        "RELEASE_SIGNING_KEY_ID": "release-prod-v1",
        "RELEASE_REQUIRE_VERIFIED_SIGNATURE": "true",
        "OBJECT_STORAGE_PROVIDER": "s3-compatible",
        "OBJECT_STORAGE_ENDPOINT": "https://objects.example.invalid",
        "OBJECT_STORAGE_BUCKET": "authorization-platform",
        "OBJECT_STORAGE_REGION": "test-1",
        "OBJECT_STORAGE_ACCESS_KEY_ID": "access-id",
        "OBJECT_STORAGE_SECRET_ACCESS_KEY": "object-secret",
        "BACKUP_PROVIDER": "pgbackrest",
        "BACKUP_STANZA": "authorization-platform",
        "BACKUP_REPOSITORY_COUNT": "2",
        "BACKUP_REPOSITORY_1": "s3://primary/authorization-platform",
        "BACKUP_REPOSITORY_2": "s3://secondary/authorization-platform",
        "BACKUP_REPOSITORY_FAILURE_DOMAIN_1": "primary-provider",
        "BACKUP_REPOSITORY_FAILURE_DOMAIN_2": "secondary-provider",
        "BACKUP_REPOSITORIES_INDEPENDENT": "true",
        "BACKUP_ENCRYPTION": "aes-256-cbc",
        "BACKUP_CIPHER_PASSWORD_FILE": "/run/secrets/pgbackrest-cipher-pass",
        "BACKUP_REMOTE_TLS": "true",
        "BACKUP_WAL_ARCHIVING": "on",
        "BACKUP_ARCHIVE_COMMAND_CONFIGURED": "true",
        "BACKUP_RETENTION_FULL": "7",
        "BACKUP_RETENTION_DIFF": "14",
        "BACKUP_RETENTION_ARCHIVE": "14",
        "BACKUP_RPO_MINUTES": "15",
        "BACKUP_RTO_MINUTES": "60",
        "BACKUP_STATUS_FILE": "/var/lib/authorization-platform/backup-status.json",
        "BACKUP_FAILURE_ALERTING": "true",
        "BACKUP_FAILURE_HANDLER": "/usr/local/sbin/authorization-platform-backup-alert",
        "BACKUP_WARN_FREE_PERCENT": "25",
        "BACKUP_CRITICAL_FREE_PERCENT": "15",
        "PYTHONPATH": str(SETTINGS_SRC),
    }
    for index, name in enumerate(
        (
            "INVITATION_ENCRYPTION_KEY",
            "PASSWORD_OPERATION_HASH_KEY",
            "ACCOUNT_OPERATION_HASH_KEY",
            "QUOTA_CARD_HASH_KEY",
            "QUOTA_REDEEM_IP_HASH_KEY",
            "QUOTA_CARD_ENCRYPTION_KEY",
            "LICENSE_CARD_HASH_KEY",
            "LICENSE_CARD_ENCRYPTION_KEY",
            "AUTHORIZATION_NONCE_HASH_KEY",
            "AUTHORIZATION_DEVICE_HASH_KEY",
            "AUTHORIZATION_SIGNING_PRIVATE_KEY",
        )
    ):
        values[name] = f"secret-{index}-unique-value"
    values.update(overrides)
    return values


def import_settings(env: dict[str, str]) -> subprocess.CompletedProcess:
    clean = {key: value for key, value in os.environ.items() if not key.startswith(("APP_ENV", "DJANGO_", "AUTHORIZATION_", "RELEASE_", "OBJECT_", "BACKUP_", "TRUSTED_", "TRUST_", "SECURE_", "DATABASE_", "PUBLIC_", "QUOTA_", "LICENSE_", "INVITATION_", "PASSWORD_", "ACCOUNT_", "DISABLE_", "AUTH_"))}
    clean.update(env)
    clean.pop("DJANGO_SETTINGS_MODULE", None)
    return subprocess.run(
        [sys.executable, "-c", "import authorization_platform.settings; print('SETTINGS_OK')"],
        env=clean,
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )


class TrustedProxyHeadersTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _response(self, request):
        return HttpResponse(
            f"{request.META.get('REMOTE_ADDR')}|{request.META.get('HTTP_X_FORWARDED_PROTO', '')}"
        )

    @override_settings(TRUSTED_PROXY_NETWORKS=())
    def test_untrusted_peer_cannot_spoof_forwarded_identity_or_https(self):
        request = self.factory.get(
            "/healthz/",
            REMOTE_ADDR="198.51.100.10",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
            HTTP_X_FORWARDED_PROTO="https",
        )
        response = TrustedProxyHeadersMiddleware(self._response)(request)
        self.assertEqual(response.content.decode(), "198.51.100.10|")

    @override_settings(TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),))
    def test_trusted_peer_resolves_single_forwarded_client_and_proto(self):
        request = self.factory.get(
            "/healthz/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
            HTTP_X_FORWARDED_PROTO="https",
        )
        response = TrustedProxyHeadersMiddleware(self._response)(request)
        self.assertEqual(response.content.decode(), "203.0.113.9|https")

    @override_settings(TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),))
    def test_malformed_or_multiple_forwarded_proto_is_removed(self):
        request = self.factory.get(
            "/healthz/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
            HTTP_X_FORWARDED_PROTO="https, http",
        )
        response = TrustedProxyHeadersMiddleware(self._response)(request)
        self.assertEqual(response.content.decode(), "203.0.113.9|")

    @override_settings(TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),))
    def test_fully_trusted_chain_does_not_accept_client_supplied_identity(self):
        """A request whose whole chain is inside the trusted range must not be
        able to pick its own rate-limit identity via X-Forwarded-For."""

        request = self.factory.get(
            "/healthz/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="10.0.0.9",
            HTTP_X_FORWARDED_PROTO="https",
        )
        response = TrustedProxyHeadersMiddleware(self._response)(request)
        self.assertEqual(response.content.decode(), "10.0.0.5|https")


class ProductionSettingsGateTests(SimpleTestCase):
    """The published example values must never satisfy a non-local gate."""

    def test_complete_non_local_environment_imports(self):
        result = import_settings(production_settings_env())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SETTINGS_OK", result.stdout)

    def test_published_placeholder_secret_key_is_rejected(self):
        result = import_settings(
            production_settings_env(DJANGO_SECRET_KEY="replace-with-a-long-random-production-secret-value")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_SECRET_KEY", result.stderr)

    def test_repeated_character_secret_key_is_rejected(self):
        result = import_settings(production_settings_env(DJANGO_SECRET_KEY="a" * 60))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_SECRET_KEY", result.stderr)

    def test_reused_password_operation_key_is_rejected(self):
        result = import_settings(
            production_settings_env(PASSWORD_OPERATION_HASH_KEY="secret-2-unique-value", ACCOUNT_OPERATION_HASH_KEY="secret-2-unique-value")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("independent", result.stderr)

    def test_dummy_cache_backend_is_rejected(self):
        result = import_settings(
            production_settings_env(DJANGO_CACHE_BACKEND="django.core.cache.backends.dummy.DummyCache")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cache backend", result.stderr)

    def test_locmem_cache_backend_is_rejected(self):
        result = import_settings(
            production_settings_env(DJANGO_CACHE_BACKEND="django.core.cache.backends.locmem.LocMemCache")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cache backend", result.stderr)

    def test_zero_login_rate_limit_is_rejected(self):
        result = import_settings(production_settings_env(AUTH_LOGIN_RATE_LIMIT="0"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTH_LOGIN_RATE_LIMIT", result.stderr)

    def test_one_second_auth_window_is_rejected(self):
        result = import_settings(production_settings_env(AUTH_RATE_LIMIT_WINDOW_SECONDS="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTH_RATE_LIMIT_WINDOW_SECONDS", result.stderr)

    def test_missing_trusted_proxy_is_rejected(self):
        result = import_settings(production_settings_env(TRUSTED_PROXY_IPS="", TRUST_PROXY_SSL_HEADER="false"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TRUSTED_PROXY_IPS", result.stderr)

    def test_debug_true_is_rejected_outside_local(self):
        result = import_settings(production_settings_env(DJANGO_DEBUG="true"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_DEBUG", result.stderr)

    def test_test_environment_requires_explicit_signing_key(self):
        result = import_settings(
            production_settings_env(
                APP_ENV="test",
                AUTHORIZATION_SIGNING_PRIVATE_KEY="",
                AUTHORIZATION_SIGNING_KEY_ID="platform-dev-v1",
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTHORIZATION_SIGNING_PRIVATE_KEY", result.stderr)

    def test_test_environment_requires_non_default_signing_key_id(self):
        result = import_settings(
            production_settings_env(APP_ENV="test", AUTHORIZATION_SIGNING_KEY_ID="platform-dev-v1")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTHORIZATION_SIGNING_KEY_ID", result.stderr)

    def test_local_environment_still_starts_without_injected_keys(self):
        env = {"APP_ENV": "local", "DJANGO_DEBUG": "1", "PYTHONPATH": str(SETTINGS_SRC)}
        result = import_settings(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SETTINGS_OK", result.stdout)

    def test_cache_ceiling_is_configured_above_django_default(self):
        from django.conf import settings as django_settings

        options = django_settings.CACHES["default"].get("OPTIONS") or {}
        self.assertGreaterEqual(int(options.get("MAX_ENTRIES", 0)), 10_000)

    def test_request_errors_are_logged(self):
        """An unhandled 500 must leave a trace; the container logs used to be
        six gunicorn startup lines with nothing for the failing request."""

        from django.conf import settings as django_settings

        logging_config = django_settings.LOGGING
        self.assertIn("console", logging_config["handlers"])
        self.assertEqual(logging_config["loggers"]["django.request"]["level"], "ERROR")
        self.assertIn("console", logging_config["loggers"]["django.request"]["handlers"])
        self.assertIn("authorization_platform", logging_config["loggers"])
