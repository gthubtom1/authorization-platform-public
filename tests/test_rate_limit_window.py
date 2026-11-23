from __future__ import annotations

import time
from datetime import timezone as datetime_timezone

from django.core.cache import cache
from django.core.management import call_command
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.rate_limit import _cache_key, allow, reset

_CACHE_TABLE = "rate_limit_window_cache"
_DATABASE_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": _CACHE_TABLE,
        "TIMEOUT": 300,
    }
}


def _as_epoch(value):
    if timezone.is_aware(value):
        return value.timestamp()
    return value.replace(tzinfo=datetime_timezone.utc).timestamp()


def _database_expires(scope: str, identity: str):
    backend = cache
    cache_key = backend.make_and_validate_key(_cache_key(scope, identity))
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT expires FROM %s WHERE cache_key = %%s"
            % connection.ops.quote_name(backend._table),
            [cache_key],
        )
        row = cursor.fetchone()
    return row[0] if row else None


@override_settings(CACHES=_DATABASE_CACHE)
class DatabaseCacheRateWindowTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        call_command("createcachetable", verbosity=0)

    def setUp(self):
        cache.clear()

    def test_defaults_were_not_raised_to_hide_the_bug(self):
        from django.conf import settings

        self.assertEqual(settings.PUBLIC_RELEASE_REGISTRY_RATE_LIMIT, 60)
        self.assertEqual(settings.PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS, 60)
        self.assertEqual(settings.PUBLIC_LICENSE_RATE_LIMIT, 120)
        self.assertEqual(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS, 300)
        self.assertEqual(settings.CACHES["default"]["BACKEND"], "django.core.cache.backends.db.DatabaseCache")
        self.assertEqual(settings.CACHES["default"]["TIMEOUT"], 300)

    def test_same_identity_is_blocked_inside_window_then_allowed_after_expiry(self):
        identity = "58.242.67.77:toutiao-matrix:stable"
        self.assertTrue(allow("public-release-registry", identity, limit=2, timeout=1))
        self.assertTrue(allow("public-release-registry", identity, limit=2, timeout=1))
        self.assertFalse(allow("public-release-registry", identity, limit=2, timeout=1))
        self.assertFalse(allow("public-release-registry", identity, limit=2, timeout=1))
        time.sleep(1.2)
        self.assertTrue(allow("public-release-registry", identity, limit=2, timeout=1))

    def test_different_identities_do_not_share_one_pool(self):
        first = "10.0.0.1:toutiao-matrix:stable"
        second = "10.0.0.2:toutiao-matrix:stable"
        self.assertTrue(allow("public-release-registry", first, limit=1, timeout=30))
        self.assertFalse(allow("public-release-registry", first, limit=1, timeout=30))
        self.assertTrue(allow("public-release-registry", second, limit=1, timeout=30))

    def test_increment_keeps_django_ttl_near_this_window_not_default_300(self):
        identity = "58.242.67.77:verify"
        window = 8
        before = timezone.now()
        self.assertTrue(allow("public-license-verify", identity, limit=5, timeout=window))
        self.assertTrue(allow("public-license-verify", identity, limit=5, timeout=window))
        self.assertTrue(allow("public-license-verify", identity, limit=5, timeout=window))
        expires = _database_expires("public-license-verify", identity)
        self.assertIsNotNone(expires)
        remaining = _as_epoch(expires) - time.time()
        elapsed = (timezone.now() - before).total_seconds()
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, window + 1)
        self.assertGreaterEqual(remaining, window - elapsed - 1)
        self.assertLess(remaining, 60)

    def test_legacy_integer_counter_starts_a_fresh_window(self):
        identity = "58.242.67.77:legacy"
        cache.set(_cache_key("public-license-verify", identity), 2232, timeout=300)
        self.assertTrue(allow("public-license-verify", identity, limit=2, timeout=8))
        self.assertTrue(allow("public-license-verify", identity, limit=2, timeout=8))
        self.assertFalse(allow("public-license-verify", identity, limit=2, timeout=8))

    def test_reset_clears_the_identity(self):
        identity = "10.0.0.8:reset"
        self.assertTrue(allow("login", identity, limit=1, timeout=30))
        self.assertFalse(allow("login", identity, limit=1, timeout=30))
        reset("login", identity)
        self.assertTrue(allow("login", identity, limit=1, timeout=30))


class _RegistryClientTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        call_command("createcachetable", verbosity=0)

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.url = reverse(
            "releases:public_registry",
            kwargs={"software_id": "toutiao-matrix", "profile_id": "stable"},
        )
        self.params = {
            "client_id": "toutiao-matrix-windows",
            "target": "windows",
            "arch": "x64",
            "channel": "stable",
            "version": "2.0.1",
        }

    def _get(self, *, remote_addr: str):
        return self.client.get(self.url, self.params, REMOTE_ADDR=remote_addr)


@override_settings(
    CACHES=_DATABASE_CACHE,
    PUBLIC_RELEASE_REGISTRY_RATE_LIMIT=1,
    PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS=1,
)
class DatabaseCachePublicRegistryExpiryTests(_RegistryClientTests):
    def test_same_ip_hits_429_then_is_allowed_after_window(self):
        identity = "58.242.67.77"
        first = self._get(remote_addr=identity)
        self.assertNotEqual(first.status_code, 429)
        second = self._get(remote_addr=identity)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.json()["error"]["code"], "RATE_LIMITED")
        self.assertTrue(second.json()["error"]["retryable"])
        third = self._get(remote_addr=identity)
        self.assertEqual(third.status_code, 429)
        time.sleep(1.2)
        after = self._get(remote_addr=identity)
        self.assertNotEqual(after.status_code, 429)


@override_settings(
    CACHES=_DATABASE_CACHE,
    PUBLIC_RELEASE_REGISTRY_RATE_LIMIT=1,
    PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS=30,
)
class DatabaseCachePublicRegistryIsolationTests(_RegistryClientTests):
    def test_two_ips_do_not_block_each_other(self):
        first = self._get(remote_addr="10.0.0.11")
        blocked = self._get(remote_addr="10.0.0.11")
        other = self._get(remote_addr="10.0.0.12")
        self.assertNotEqual(first.status_code, 429)
        self.assertEqual(blocked.status_code, 429)
        self.assertNotEqual(other.status_code, 429)
