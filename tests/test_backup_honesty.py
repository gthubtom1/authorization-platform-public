"""Backup honesty contracts.

The test station ran 29 encrypted dumps in a row and every one of them failed
its proof chain, yet the page said "backup completed", systemd recorded success
and the hourly maintenance log printed "failed=0".  Three separate mechanisms
made the failure invisible; these tests pin all three shut.
"""

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "deploy" / "backup" / "maintenance.sh"
RUNNER = ROOT / "deploy" / "backup" / "backup_runner.sh"
ALERT_BRIDGE = ROOT / "deploy" / "backup" / "backup_alert.sh"
INSTALL = ROOT / "deploy" / "install-site.sh"


def _git_bash() -> str:
    import shutil

    candidates = []
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    candidates.extend(
        [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise AssertionError("Git Bash is required to run the maintenance script")


def _bash_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)
    text = resolved.as_posix()
    if len(text) >= 2 and text[1] == ":":
        return f"/{text[0].lower()}{text[2:]}"
    return text


def _runner_source() -> str:
    return RUNNER.read_text(encoding="utf-8")


def _directive_lines(text: str) -> list[str]:
    """Comment lines cannot break a backup, so assertions ignore them."""
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


class MaintenanceHealthVerdictTests(unittest.TestCase):
    """The hourly health check has to be able to return a verdict at all."""

    def _run(self, tmp: Path, *, backup_log: str, status):
        import tempfile

        maintenance_log = tmp / "maintenance.log"
        backup_log_path = tmp / "backup.log"
        backup_log_path.write_text(backup_log, encoding="utf-8")
        status_path = tmp / "backup-status.json"
        if status is not None:
            status_path.write_text(json.dumps(status), encoding="utf-8")
        environment = dict(os.environ)
        environment.update(
            {
                # No such containers: the clearsessions call is expected to fail
                # and is logged, which must not abort the run.
                "AUTHORIZATION_PLATFORM_APP_CONTAINER": "ap-does-not-exist",
                "AUTHORIZATION_PLATFORM_DB_CONTAINER": "db-does-not-exist",
                "BACKUP_MAINTENANCE_LOG_FILE": _bash_path(maintenance_log),
                "BACKUP_LOG_FILE": _bash_path(backup_log_path),
                "BACKUP_STATUS_FILE": _bash_path(status_path),
            }
        )
        result = subprocess.run(
            [_git_bash(), _bash_path(MAINTENANCE)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=120,
        )
        written = maintenance_log.read_text(encoding="utf-8", errors="replace")
        return result, written

    def _healthy_status(self):
        return {
            "last_result": "success",
            "last_failure_code": None,
            "last_success_at_utc": "2026-09-26T18:30:35Z",
        }

    def test_healthy_state_exits_zero(self):
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            result, log = self._run(
                Path(raw),
                backup_log="[x] backup runner complete\n",
                status=self._healthy_status(),
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("result=success", log)
        self.assertIn("maintenance complete\n", log)

    def test_status_reporting_failure_exits_non_zero(self):
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            result, log = self._run(
                Path(raw),
                backup_log="[x] backup runner complete\n",
                status={
                    "last_result": "failure",
                    "last_failure_code": "backup_service_failed",
                    "last_success_at_utc": "2026-09-26T18:30:35Z",
                },
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CRITICAL backup status result=failure", log)

    def test_status_that_never_recorded_a_success_exits_non_zero(self):
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            result, log = self._run(
                Path(raw),
                backup_log="[x] backup runner complete\n",
                status={
                    "last_result": "success",
                    "last_failure_code": None,
                    "last_success_at_utc": None,
                },
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("has never recorded a success", log)

    def test_missing_status_file_exits_non_zero(self):
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            result, log = self._run(
                Path(raw), backup_log="[x] backup runner complete\n", status=None
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("result=absent", log)

    def test_real_failure_lines_are_counted(self):
        import tempfile

        backup_log = "\n".join(
            [
                "[x] full backup repo1 failed",
                "[x] full backup FAILED: dump failed",
                "[x] backup runner complete",
            ]
        )
        with tempfile.TemporaryDirectory() as raw:
            _, log = self._run(
                Path(raw), backup_log=backup_log, status=self._healthy_status()
            )
        self.assertIn("failed=2", log)
        self.assertIn("failure line(s)", log)

    def test_dump_only_proof_skip_is_not_counted_as_a_failure(self):
        # This is the other half of the contract: in a deployment without
        # pgBackRest the repository proof can never be satisfied, so treating it
        # as a failure would cry wolf every single run.  It must be logged
        # explicitly and must not trip the verdict.
        import tempfile

        backup_log = "\n".join(
            [
                "[x] pgBackRest proof skipped (dump-only mode: no pgBackRest repository in this deployment)",
                "[x] encrypted dump verified: decrypts to a pg_dump custom header",
                "[x] backup runner complete",
            ]
        )
        with tempfile.TemporaryDirectory() as raw:
            result, _ = self._run(
                Path(raw), backup_log=backup_log, status=self._healthy_status()
            )
        self.assertEqual(result.returncode, 0)

    def test_the_legacy_tautological_patterns_are_gone(self):
        source = MAINTENANCE.read_text(encoding="utf-8")
        # "backup failed" (lower case) never existed in the backup directory, so
        # the old counter could only ever return zero.
        self.assertNotIn('grep -cE "backup failed', source)
        self.assertIn("backup FAILED", source)
        self.assertIn('exit "$FAILED"', source)


class EncryptedDumpVerificationTests(unittest.TestCase):
    """The dump proof must accept a good dump and reject a bad one.

    Regression: the first version piped ``openssl ... | head -c 5 | grep``.  Under
    ``set -o pipefail`` that is *always* false -- head exits after five bytes,
    openssl takes SIGPIPE and exits 1, and a perfectly good dump was rejected.
    It shipped that way and failed every real backup on the test station until a
    scheduled run caught it.  This test runs the real block with a real openssl.
    """

    def _verification_block(self) -> str:
        source = _runner_source()
        start = source.index("PGDMP_MAGIC=")
        tail = 'rm -f "${DUMP_DIR}/${DUMP_NAME}.plain"'
        end = source.index(tail, start) + len(tail)
        return source[start:end]

    def _run_block(self, *, passphrase_ok: bool, plain_magic: bytes = b"PGDMP"):
        import stat
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            dump_dir = work / "dumps"
            dump_dir.mkdir()
            plain = dump_dir / "d.dump.enc.plain"
            encrypted = dump_dir / "d.dump.enc"
            plain.write_bytes(plain_magic + b"-rest-of-the-dump-bytes")
            real_pass = work / "pass-real.txt"
            real_pass.write_text("correct-passphrase\n", encoding="utf-8")
            used_pass = real_pass if passphrase_ok else work / "pass-wrong.txt"
            if not passphrase_ok:
                used_pass.write_text("wrong-passphrase\n", encoding="utf-8")
            log_file = work / "runner.log"

            # Native Windows openssl cannot read MSYS (/c/...) paths, while the
            # block itself uses the variables for both coreutils and openssl.
            # A drive-letter path is understood by both, so pass that form.
            def native(path: Path) -> str:
                return str(path).replace("\\", "/")

            quote = native
            setup = (
                "openssl enc -aes-256-cbc -salt -pbkdf2 "
                f"-in {quote(plain)} -out {quote(encrypted)} -pass file:{quote(real_pass)}\n"
            )
            script = (
                "set -uo pipefail\n"
                'log() { echo "$*" >> "$LOG"; }\n'
                f"DUMP_DIR={quote(dump_dir)}\n"
                "DUMP_NAME=d.dump.enc\n"
                f"GH_DUMP_PASS={quote(used_pass)}\n"
                f"LOG={quote(log_file)}\n"
                "DUMP_PROOF_FAILED=0\n"
                + setup
                + self._verification_block()
                + '\necho "proof_failed=$DUMP_PROOF_FAILED"\n'
            )
            result = subprocess.run(
                [_git_bash(), "-c", script], capture_output=True, text=True, timeout=120
            )
            self.assertIn("proof_failed=", result.stdout, result.stdout + result.stderr)
            failed = result.stdout.split("proof_failed=")[1].strip().splitlines()[0]
            written = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
            return failed, written, plain.exists()

    def test_a_good_dump_passes_and_its_plaintext_is_cleaned_up(self):
        failed, written, plaintext_left = self._run_block(passphrase_ok=True)
        self.assertEqual(failed, "0", written)
        self.assertIn("encrypted dump verified", written)
        self.assertFalse(plaintext_left, "the plaintext dump must not be left on disk")

    def test_a_wrong_passphrase_is_rejected(self):
        failed, written, _ = self._run_block(passphrase_ok=False)
        self.assertEqual(failed, "1", written)
        self.assertIn("does not decrypt", written)

    def test_output_that_is_not_a_pg_dump_is_rejected(self):
        failed, written, _ = self._run_block(passphrase_ok=True, plain_magic=b"NOPE!")
        self.assertEqual(failed, "1", written)
        self.assertIn("PGDMP header", written)

    def test_the_verification_never_depends_on_a_short_lived_pipe(self):
        # The exact shape that broke: openssl writing into a pipe that head closes.
        # Comments are excluded -- the regression write-up quotes the bad shape on
        # purpose, and a comment cannot break a backup.
        directives = "\n".join(_directive_lines(_runner_source()))
        self.assertNotIn("| head -c 5 | grep", directives)
        self.assertIn("-out /dev/null", directives)


class TelegramAlertBridgeTests(unittest.TestCase):
    """The alert bridge runs downstream of the backup, so it must never be able
    to fail one -- no token, no curl, a dead network or a retry storm all have to
    end in exit 0."""

    FAKE_CURL = """#!/usr/bin/env bash
set -uo pipefail
printf '%s\\n' "$*" >> "$FAKE_CURL_CALLS"
exit ${FAKE_CURL_RC:-0}
"""

    def _run_bridge(
        self,
        *,
        credentials: bool,
        curl_rc: int = 0,
        last_sent: int | None = None,
        payload: str = '{"event": "authorization_platform_backup_failure", "reason_code": "backup_service_failed"}',
    ):
        import stat
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            keys = work / "keys"
            keys.mkdir()
            if credentials:
                (keys / "telegram-bot-token.txt").write_text("123456:TEST-BOT-TOKEN\n", encoding="utf-8")
                (keys / "telegram-chat-id.txt").write_text("-1001234567890\n", encoding="utf-8")
            bin_dir = work / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text(self.FAKE_CURL, encoding="utf-8")
            curl.chmod(curl.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            calls = work / "curl-calls.txt"
            alert_log = work / "alert.log"
            state = work / "alert.state"
            if last_sent is not None:
                state.write_text(f"{last_sent}\n", encoding="utf-8")

            def posix(path: Path) -> str:
                text = path.resolve().as_posix()
                if len(text) >= 2 and text[1] == ":":
                    return f"/{text[0].lower()}{text[2:]}"
                return text

            environment = dict(os.environ)
            environment.update(
                {
                    "BACKUP_KEYS_DIR": posix(keys),
                    "BACKUP_ALERT_LOG": posix(alert_log),
                    "BACKUP_ALERT_STATE_FILE": posix(state),
                    "BACKUP_ALERT_MIN_INTERVAL_SECONDS": "900",
                    "FAKE_CURL_CALLS": posix(calls),
                    "FAKE_CURL_RC": str(curl_rc),
                }
            )
            launcher = f'PATH="{posix(bin_dir)}:$PATH"; exec bash "{posix(ALERT_BRIDGE)}"'
            result = subprocess.run(
                [_git_bash(), "-c", launcher],
                input=payload,
                capture_output=True,
                text=True,
                env=environment,
                timeout=120,
            )
            written = alert_log.read_text(encoding="utf-8", errors="replace") if alert_log.exists() else ""
            called = calls.read_text(encoding="utf-8", errors="replace") if calls.exists() else ""
            return result, written, called

    def test_a_configured_bridge_sends_the_failure_to_telegram(self):
        result, _, called = self._run_bridge(credentials=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("sendMessage", called)
        self.assertIn("chat_id=-1001234567890", called)
        self.assertIn("backup_service_failed", called)
        self.assertIn("--max-time", called)

    def test_missing_credentials_never_attempt_a_send(self):
        result, written, called = self._run_bridge(credentials=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(called, "")
        self.assertIn("telegram credentials missing", written)

    def test_a_failing_telegram_api_still_exits_zero(self):
        # curl --fail exits 22 on an API error; the bridge must swallow it so the
        # backup is never marked failed because a chat server was down.
        result, written, called = self._run_bridge(credentials=True, curl_rc=22)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("sendMessage", called)
        self.assertIn("telegram send failed (ignored)", written)

    def test_repeat_failures_inside_the_window_do_not_ping_again(self):
        import time

        result, written, called = self._run_bridge(
            credentials=True, last_sent=int(time.time())
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(called, "", "the retry loop must not turn into an alert storm")
        self.assertIn("suppressed", written)

    def test_the_bot_token_is_never_written_to_the_alert_log(self):
        result, written, _ = self._run_bridge(credentials=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("TEST-BOT-TOKEN", written)


class EncryptedDumpProofTests(unittest.TestCase):
    """The encrypted dump is the artifact of record; it must be proven usable."""

    def test_dump_is_decrypted_and_header_checked(self):
        source = _runner_source()
        self.assertIn("encrypted dump verified", source)
        self.assertIn("encrypted dump unusable", source)
        self.assertIn("PGDMP", source)

    def test_verification_happens_before_pruning(self):
        source = _runner_source()
        verified = source.index("encrypted dump verified")
        # Anchor on the call, not on the word: the explanation comment above the
        # verification mentions prune_dir too.
        pruned = source.index('prune_dir "$DUMP_DIR"')
        self.assertLess(
            verified,
            pruned,
            "a dump that cannot be decrypted must be caught before prune_dir "
            "rotates older, still-good backups out of the window",
        )

    def test_dump_failure_is_fatal_in_every_mode(self):
        source = _runner_source()
        self.assertIn("DUMP_PROOF_FAILED=0", source)
        self.assertIn("DUMP_PROOF_FAILED=1", source)
        # The old decision was `PROOF_FAILED && DB_STATE=enabled`, so a missing
        # pgBackRest repository silently turned every failure into exit 0.
        self.assertIn('if [ "$DUMP_PROOF_FAILED" -ne 0 ]; then', source)
        self.assertIn("backup runner complete (failed)", source)

    def test_missing_pgbackrest_is_stated_out_loud(self):
        source = _runner_source()
        self.assertIn("pgBackRest proof skipped", source)
        self.assertIn("dump-only mode", source)


class PolicySwitchIsNotSilentTests(unittest.TestCase):
    def test_installer_warns_when_it_turns_the_repository_switch_off(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn("policy-database-enabled-reset-by-installer", source)
        self.assertIn("被装机脚本关掉了", source)


if __name__ == "__main__":
    unittest.main()
