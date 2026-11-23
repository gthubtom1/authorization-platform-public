"""The backup health marker must not contradict the run records.

`mark_success` only writes a success marker when it can bind a pgBackRest proof
to the current run.  This deployment has no pgBackRest repository at all, so the
marker stayed at `failure` while every backup actually succeeded and the
database said so -- and the management API reported `critical`.  A permanently
red alarm teaches the owner to ignore alarms, which is the real hazard.

`backup_status_reconcile` aligns the marker with the database and is explicit
that this is *not* a passed proof.
"""

import io
import json
import tempfile
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from authorization_platform.backup_control.models import BackupRunRequest


class DumpOnlyHealthTests(TestCase):
    """A deployment without pgBackRest must not read as broken forever."""

    def _disk(self):
        from authorization_platform.core.backup_governance import DiskCapacity

        return DiskCapacity(total_bytes=100, free_bytes=50, free_percent=50.0, status="ok")

    def _status(self, **extra):
        document = {
            "last_result": "success",
            "last_success_at_utc": "2026-09-27T00:03:20Z",
        }
        document.update(extra)
        return document

    def test_dump_only_without_proof_is_a_warning_not_critical(self):
        from authorization_platform.core.backup_governance import backup_health

        result = backup_health(
            status_document=self._status(proof_mode="dump_only", last_success_proof=None),
            now=datetime(2026, 9, 27, 1, 30, tzinfo=dt_timezone.utc),
            rpo_minutes=780,
            disk=self._disk(),
        )
        self.assertNotEqual(result["status"], "critical", result)
        self.assertIn("backup_dump_only_proof_absent", result["reasons"])

    def test_a_broken_or_missing_proof_without_the_mode_flag_stays_critical(self):
        from authorization_platform.core.backup_governance import backup_health

        result = backup_health(
            status_document=self._status(last_success_proof=None),
            now=datetime(2026, 9, 27, 1, 30, tzinfo=dt_timezone.utc),
            rpo_minutes=780,
            disk=self._disk(),
        )
        self.assertEqual(result["status"], "critical", result)
        self.assertIn("backup_success_proof_missing_or_invalid", result["reasons"])

    def test_a_failed_run_is_always_critical(self):
        from authorization_platform.core.backup_governance import backup_health

        result = backup_health(
            status_document={"last_result": "failure", "last_success_at_utc": None},
            now=datetime(2026, 9, 27, 1, 30, tzinfo=dt_timezone.utc),
            rpo_minutes=780,
            disk=self._disk(),
        )
        self.assertEqual(result["status"], "critical", result)


class EffectiveRpoTests(TestCase):
    def test_rpo_follows_the_diff_cadence_not_the_scan_cadence(self):
        from authorization_platform.backup_control.services import _effective_rpo_minutes

        class Policy:
            diff_interval_hours = 6

        # 15 分钟是巡检节奏；全量一天一次、增量每 6 小时一次，按巡检节奏判过期
        # 会让每次成功备份几十分钟后就被标红。
        self.assertGreaterEqual(_effective_rpo_minutes(Policy()), 2 * 6 * 60 + 60)

    def test_an_explicitly_larger_rpo_is_respected(self):
        from authorization_platform.backup_control.services import _effective_rpo_minutes
        from django.test import override_settings

        class Policy:
            diff_interval_hours = 6

        with override_settings(BACKUP_RPO_MINUTES="3000"):
            self.assertEqual(_effective_rpo_minutes(Policy()), 3000)
class ReconcileBackupStatusTests(TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.marker = Path(self._tmp.name) / "backup-status.json"

    def _write_marker(self, document: dict) -> None:
        self.marker.write_text(json.dumps(document), encoding="utf-8")

    def _read_marker(self) -> dict:
        return json.loads(self.marker.read_text(encoding="utf-8"))

    def _reconcile(self) -> dict:
        out = io.StringIO()
        call_command("backup_status_reconcile", "--status-file", str(self.marker), stdout=out)
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def _run_record(self, status: str, *, age_minutes: int = 5):
        return BackupRunRequest.objects.create(
            backup_type="full",
            status=status,
            message="测试夹具",
            created_at=timezone.now() - timedelta(minutes=age_minutes),
        )

    def test_no_runs_leaves_the_marker_alone(self):
        result = self._reconcile()
        self.assertEqual(result["status"], "no_runs")
        self.assertFalse(result["changed"])
        self.assertFalse(self.marker.exists())

    def test_a_failed_latest_run_never_turns_the_marker_green(self):
        self._write_marker({"last_result": "failure", "last_failure_code": "backup_service_failed"})
        self._run_record("failed", age_minutes=1)
        result = self._reconcile()
        self.assertEqual(result["status"], "latest_run_not_successful")
        self.assertFalse(result["changed"])
        self.assertEqual(self._read_marker()["last_result"], "failure")

    def test_a_successful_run_flips_a_false_red_marker(self):
        self._write_marker(
            {"last_result": "failure", "last_failure_code": "backup_service_failed", "last_success_at_utc": None}
        )
        self._run_record("succeeded", age_minutes=2)
        result = self._reconcile()
        self.assertEqual(result["status"], "reconciled")
        self.assertTrue(result["changed"])
        document = self._read_marker()
        self.assertEqual(document["last_result"], "success")
        self.assertIsNotNone(document["last_success_at_utc"])
        self.assertIsNone(document["last_failure_code"])
        # It must not pretend a proof exists.
        self.assertIsNone(document["last_success_proof"])
        self.assertEqual(document["proof_mode"], "dump_only")
        self.assertEqual(document["reconciled_from"], "backup_run_request")

    def test_reconciling_twice_is_a_no_op(self):
        self._run_record("succeeded", age_minutes=2)
        first = self._reconcile()
        second = self._reconcile()
        self.assertTrue(first["changed"])
        self.assertEqual(second["status"], "already_current")
        self.assertFalse(second["changed"])

    def test_a_newer_recorded_success_is_never_rolled_back(self):
        # Guards against an out-of-order or replayed run record dragging the
        # marker back in time.
        self._run_record("succeeded", age_minutes=90)
        recorded = timezone.now().isoformat().replace("+00:00", "Z")
        self._write_marker({"last_result": "success", "last_success_at_utc": recorded})
        result = self._reconcile()
        self.assertFalse(result["changed"])
        self.assertEqual(self._read_marker()["last_success_at_utc"], recorded)
