from __future__ import annotations

from unittest import TestCase

from scripts.shared_rate_limit_probe import (
    ProbeConfigurationError,
    evaluate_phase,
    validate_probe_environment,
)


def valid_environment() -> dict[str, str]:
    return {
        "APP_ENV": "local",
        "DATABASE_ENGINE": "postgresql",
        "DATABASE_HOST": "127.0.0.1",
        "DATABASE_PORT": "55432",
        "DATABASE_NAME": "auth_b72_source",
        "DATABASE_USER": "auth_b72_test",
        "DATABASE_PASSWORD": "ephemeral-test-password",
        "DJANGO_CACHE_BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "DJANGO_CACHE_LOCATION": "django_cache",
    }


class SharedRateLimitProbeTests(TestCase):
    def test_valid_isolated_postgresql_database_cache_configuration_is_accepted(self):
        validate_probe_environment(valid_environment(), confirm_isolated_target=True)

    def test_locmem_cache_is_rejected(self):
        values = valid_environment()
        values["DJANGO_CACHE_BACKEND"] = "django.core.cache.backends.locmem.LocMemCache"
        with self.assertRaises(ProbeConfigurationError):
            validate_probe_environment(values, confirm_isolated_target=True)

    def test_non_loopback_or_production_targets_are_rejected(self):
        values = valid_environment()
        values["DATABASE_HOST"] = "db.internal"
        with self.assertRaises(ProbeConfigurationError):
            validate_probe_environment(values, confirm_isolated_target=True)

        values = valid_environment()
        values["APP_ENV"] = "production"
        with self.assertRaises(ProbeConfigurationError):
            validate_probe_environment(values, confirm_isolated_target=True)

    def test_phase_evaluation_requires_one_shared_identity_allow_and_all_distinct_allows(self):
        same = evaluate_phase(
            name="same_identity",
            workers=2,
            results=[
                {"allowed": True, "error": None},
                {"allowed": False, "error": None},
            ],
            timed_out=False,
            exit_codes=[0, 0],
            expected_allowed=1,
            expected_rejected=1,
        )
        self.assertTrue(same["passed"])

        different = evaluate_phase(
            name="different_identity",
            workers=2,
            results=[
                {"allowed": True, "error": None},
                {"allowed": True, "error": None},
            ],
            timed_out=False,
            exit_codes=[0, 0],
            expected_allowed=2,
            expected_rejected=0,
        )
        self.assertTrue(different["passed"])

    def test_phase_evaluation_rejects_false_green_fixture(self):
        report = evaluate_phase(
            name="same_identity",
            workers=2,
            results=[],
            timed_out=False,
            exit_codes=[0, 0],
            expected_allowed=1,
            expected_rejected=1,
        )
        self.assertFalse(report["passed"])
