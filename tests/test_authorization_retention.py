"""Retention for the authorization request record (the idempotency ledger).

Every successful verify writes one row carrying the full signed response
payload (~1.8KB measured), and the model deliberately blocks ordinary deletes.
Without a sanctioned exit the table grows without bound; with a careless one it
would let an old allow envelope be replayed.  These tests pin both halves: the
named purge works, and the guards stay shut behind it.
"""

import json
from datetime import timedelta

from django.core.management import CommandError, call_command
from django.test import TestCase
from django.utils import timezone

from authorization_platform.audit.models import AuditEvent
from authorization_platform.licensing.models import (
    AuthorizationNonce,
    AuthorizationRequestRecord,
)


def _record(request_id: str, *, age_days: int, action: str = "verify") -> AuthorizationRequestRecord:
    return AuthorizationRequestRecord.objects.create(
        request_id=request_id,
        action=action,
        idempotency_key=f"idem-{request_id}",
        request_hash="0" * 64,
        response_status=200,
        response_payload={"decision": "active"},
        created_at=timezone.now() - timedelta(days=age_days),
    )


def _nonce(name: str, *, age_days: int) -> AuthorizationNonce:
    from authorization_platform.catalog.models import ProfileStatus, Software, SoftwareProfile

    software, _ = Software.objects.get_or_create(
        software_id="nonce-fixture", defaults={"name": "随机值夹具"}
    )
    profile, _ = SoftwareProfile.objects.get_or_create(
        software=software,
        profile_id="stable",
        defaults={"client_id": "nonce-fixture-windows", "status": ProfileStatus.ACTIVE},
    )
    consumed = timezone.now() - timedelta(days=age_days)
    return AuthorizationNonce.objects.create(
        software=software,
        profile=profile,
        nonce_hash=name,
        action="verify",
        request_id=f"req-{name}",
        consumed_at=consumed,
        created_at=consumed,
    )


class RequestRecordPurgeTests(TestCase):
    def test_purge_keeps_recent_rows_and_removes_only_expired_ones(self):
        _record("old-1", age_days=40)
        _record("old-2", age_days=31)
        _record("fresh-1", age_days=0)
        cutoff = timezone.now() - timedelta(days=30)

        removed = AuthorizationRequestRecord.purge_older_than(cutoff=cutoff)

        self.assertEqual(removed, 2)
        remaining = set(AuthorizationRequestRecord.objects.values_list("request_id", flat=True))
        self.assertEqual(remaining, {"fresh-1"})

    def test_purge_is_batched_and_capped(self):
        for index in range(25):
            _record(f"old-{index:02d}", age_days=40)
        _record("fresh-1", age_days=0)
        cutoff = timezone.now() - timedelta(days=30)

        removed = AuthorizationRequestRecord.purge_older_than(
            cutoff=cutoff, batch_size=10, max_batches=2
        )

        self.assertEqual(removed, 20, "max_batches must cap a single run")
        self.assertEqual(
            AuthorizationRequestRecord.objects.filter(created_at__lt=cutoff).count(), 5
        )
        self.assertTrue(AuthorizationRequestRecord.objects.filter(request_id="fresh-1").exists())

    def test_purge_leaves_nonce_rows_untouched(self):
        _record("old-1", age_days=40)
        _nonce("11111111-1111-1111-1111-111111111111", age_days=40)
        before = AuthorizationNonce.objects.count()

        AuthorizationRequestRecord.purge_older_than(cutoff=timezone.now() - timedelta(days=30))

        self.assertEqual(AuthorizationNonce.objects.count(), before)

    def test_ordinary_deletes_are_still_refused(self):
        row = _record("old-1", age_days=40)
        with self.assertRaises(ValueError):
            row.delete()
        with self.assertRaises(ValueError):
            AuthorizationRequestRecord.objects.filter(request_id="old-1").delete()
        self.assertTrue(AuthorizationRequestRecord.objects.filter(request_id="old-1").exists())

    def test_nonce_deletes_are_still_refused(self):
        # Nonce is the only replay primitive left when device proof is switched
        # off, and clearing it would also stop the REPLAY_DETECTED audit line
        # from ever being written.  Retention must never touch it.
        nonce = _nonce("22222222-2222-2222-2222-222222222222", age_days=40)
        with self.assertRaises(ValueError):
            nonce.delete()
        with self.assertRaises(ValueError):
            AuthorizationNonce.objects.all().delete()


class PruneCommandTests(TestCase):
    def test_command_defaults_to_dry_run(self):
        _record("old-1", age_days=40)
        call_command("prune_authorization_records")

        self.assertTrue(AuthorizationRequestRecord.objects.filter(request_id="old-1").exists())

    def test_command_apply_deletes_expired_rows_and_records_the_run(self):
        _record("old-1", age_days=40)
        _record("fresh-1", age_days=1)
        stdout = io_stdout()

        call_command("prune_authorization_records", "--apply", stdout=stdout)

        summary = json.loads(stdout.getvalue().strip().splitlines()[-1])
        self.assertEqual(summary["mode"], "apply")
        self.assertEqual(summary["rows_deleted"], 1)
        self.assertEqual(summary["rows_eligible"], 1)
        self.assertEqual(summary["retention_days"], 30)
        self.assertEqual(
            list(AuthorizationRequestRecord.objects.values_list("request_id", flat=True)),
            ["fresh-1"],
        )
        self.assertTrue(
            AuditEvent.objects.filter(action="licensing.request_record_prune").exists()
        )

    def test_command_refuses_a_non_positive_retention(self):
        # Zero would mean "keep nothing", i.e. wipe the idempotency ledger.
        _record("old-1", age_days=40)
        for value in ("0", "-5"):
            with self.assertRaises(CommandError):
                call_command("prune_authorization_records", "--days", value, "--apply")
        self.assertTrue(AuthorizationRequestRecord.objects.filter(request_id="old-1").exists())


class RecoveryInventoryToleranceTests(TestCase):
    """A retention prune must not make disaster-recovery verification fail.

    The inventory fingerprints every table. Once the idempotency ledger has been
    pruned, a restored copy legitimately differs from the live source -- and if
    that counted as a mismatch, nobody would ever pass a recovery check again
    after the first prune, and the only conclusion left would be "the backup is
    broken".
    """

    def _inventory(self, *, records: int, cards: int = 7) -> dict:
        return {
            "schema_version": 3,
            "key_references": {"authorizations": 1},
            "tables": {
                "authorization_request_records": {
                    "count": records,
                    "fingerprint": f"fp-{records}",
                },
                "license_cards": {"count": cards, "fingerprint": f"fp-cards-{cards}"},
            },
        }

    def test_a_pruned_ledger_is_reported_but_does_not_fail_the_check(self):
        from authorization_platform.core.recovery_inventory import compare_recovery_inventories

        result = compare_recovery_inventories(
            self._inventory(records=100), self._inventory(records=60)
        )

        self.assertTrue(result["matches"], result)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["mismatches"], [])
        self.assertTrue(result["pruned_paths"])
        self.assertTrue(all("authorization_request_records" in item for item in result["pruned_paths"]))
        self.assertIn("保留期", result["reason"])

    def test_a_real_difference_still_fails(self):
        from authorization_platform.core.recovery_inventory import compare_recovery_inventories

        result = compare_recovery_inventories(
            self._inventory(records=100, cards=7), self._inventory(records=100, cards=6)
        )

        self.assertFalse(result["matches"])
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("license_cards" in item for item in result["mismatches"]))
        self.assertEqual(result["pruned_paths"], [])

    def test_identical_databases_still_pass_cleanly(self):
        from authorization_platform.core.recovery_inventory import compare_recovery_inventories

        result = compare_recovery_inventories(self._inventory(records=5), self._inventory(records=5))

        self.assertTrue(result["matches"])
        self.assertEqual(result["pruned_paths"], [])
        self.assertNotIn("保留期", result["reason"])


def io_stdout():
    from io import StringIO

    return StringIO()
