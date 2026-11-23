"""App guard behaviour.

The guard used to be a single `docker compose up -d app`, so a wedged worker
(process alive, every request 500 or timing out) was never noticed -- the
container restart policy only reacts to the process dying.  These tests drive
the real script with a stub docker on PATH so both halves of the contract are
pinned: it does restart a genuinely broken container, and it does NOT restart
during a migration window or on a cooldown loop.
"""

import os
import subprocess
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "deploy" / "backup" / "app_guard.sh"

FAKE_DOCKER = """#!/usr/bin/env bash
set -uo pipefail
printf 'docker %s\\n' "$*" >> "$FAKE_DOCKER_CALLS"
case "$*" in
  *" ps -q "*) echo "fake-container-id" ;;
  inspect*) echo "${FAKE_DOCKER_HEALTH:-healthy}" ;;
  exec*) echo "${FAKE_DOCKER_PAYLOAD:-{\\"status\\": \\"ok\\"}}" ;;
  *" restart "*) : > "$FAKE_DOCKER_RESTART_MARKER" ;;
esac
exit 0
"""


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
    raise AssertionError("Git Bash is required to drive the app guard")


def _bash_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)
    text = resolved.as_posix()
    if len(text) >= 2 and text[1] == ":":
        return f"/{text[0].lower()}{text[2:]}"
    return text


class AppGuardTests(unittest.TestCase):
    def _run_guard(self, tmp: Path, *, health: str, payload: str, last_restart: int | None = None):
        import stat
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            # A plain `docker` on PATH: going through docker.cmd only works on
            # some Windows shells and hides why a test fails.
            docker = bin_dir / "docker"
            docker.write_text(FAKE_DOCKER, encoding="utf-8")
            docker.chmod(docker.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            calls = work / "calls.txt"
            marker = work / "restarted"
            guard_log = work / "guard.log"
            state = work / "guard.state"
            if last_restart is not None:
                state.write_text(f"{last_restart}\n", encoding="utf-8")
            compose_file = work / "docker-compose.production.yml"
            compose_file.write_text("services: {}\n", encoding="utf-8")

            environment = dict(os.environ)
            environment.update(
                {
                    # Everything the script and the stub touch has to be an
                    # MSYS path: a Windows path would be taken literally by bash
                    # and create a file named "C:\..." in the working directory.
                    "FAKE_DOCKER_CALLS": _bash_path(calls),
                    "FAKE_DOCKER_HEALTH": health,
                    "FAKE_DOCKER_PAYLOAD": payload,
                    "FAKE_DOCKER_RESTART_MARKER": _bash_path(marker),
                    "APP_GUARD_COMPOSE_FILE": _bash_path(compose_file),
                    "APP_GUARD_ENV_FILE": "",
                    "APP_GUARD_PROJECT": "ap-test",
                    "APP_GUARD_SERVICE": "app",
                    "APP_GUARD_LOG": _bash_path(guard_log),
                    "APP_GUARD_STATE_FILE": _bash_path(state),
                    "APP_GUARD_RESTART_COOLDOWN_SECONDS": "600",
                }
            )
            # PATH is prepended inside bash so the entry is unambiguously POSIX.
            launcher = f'PATH="{_bash_path(bin_dir)}:$PATH"; exec bash "{_bash_path(GUARD)}"'
            result = subprocess.run(
                [_git_bash(), "-c", launcher],
                capture_output=True,
                text=True,
                env=environment,
                timeout=120,
            )
            written = guard_log.read_text(encoding="utf-8", errors="replace") if guard_log.exists() else ""
            return result, written, marker.exists()

    def test_healthy_container_is_left_alone(self):
        result, log, restarted = self._run_guard(
            Path("."), health="healthy", payload='{"status": "ok"}'
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(restarted)
        self.assertIn("health=healthy", log)

    def test_container_without_a_healthcheck_is_left_alone(self):
        result, log, restarted = self._run_guard(
            Path("."), health="none", payload='{"status": "ok"}'
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(restarted)
        self.assertIn("health=none", log)

    def test_pending_migrations_never_trigger_a_restart(self):
        # install-site.sh starts the app before it runs `manage.py migrate`, so
        # /healthz/ is 503 for a legitimate reason during every deploy.  A
        # restart here turns a deploy into a migration-failure loop.
        payload = '{"status": "error", "blockers": ["migrations_pending"]}'
        result, log, restarted = self._run_guard(Path("."), health="unhealthy", payload=payload)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(restarted)
        self.assertIn("not restarting", log)

    def test_unreadable_probe_verdict_does_not_trigger_a_restart(self):
        # Django rejects a loopback request unless the Host header is one of
        # ALLOWED_HOSTS, so the probe can come back 400 with no JSON at all.  A
        # blind restart there would flip a healthy container every 10 minutes.
        result, log, restarted = self._run_guard(
            Path("."), health="unhealthy", payload="<html>400 Bad Request</html>"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(restarted, log)
        self.assertIn("cannot read the probe verdict", log)

    def test_genuinely_unhealthy_container_is_restarted(self):
        payload = '{"status": "error", "blockers": ["cache_unavailable"]}'
        result, log, restarted = self._run_guard(Path("."), health="unhealthy", payload=payload)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(restarted, log)
        self.assertIn("restart issued", log)

    def test_repeated_failures_are_throttled_by_a_cooldown(self):
        payload = '{"status": "error", "blockers": ["cache_unavailable"]}'
        just_now = int(time.time())
        result, log, restarted = self._run_guard(
            Path("."), health="unhealthy", payload=payload, last_restart=just_now
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(restarted, log)
        self.assertIn("cooldown", log)

    def test_guard_refuses_to_run_without_a_project(self):
        result = subprocess.run(
            [_git_bash(), _bash_path(GUARD)],
            capture_output=True,
            text=True,
            env={**os.environ, "APP_GUARD_COMPOSE_FILE": "", "APP_GUARD_PROJECT": ""},
            timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APP_GUARD_PROJECT", result.stderr)


class AppGuardWiringTests(unittest.TestCase):
    def test_installer_runs_the_script_rather_than_a_bare_compose_up(self):
        source = (ROOT / "deploy" / "install-site.sh").read_text(encoding="utf-8")
        self.assertIn("deploy/backup/app_guard.sh", source)
        self.assertNotIn(
            "up -d app\nEOS",
            source,
            "the unit must delegate to app_guard.sh, otherwise the wedged-container "
            "repair never runs",
        )

    def test_app_service_declares_a_healthcheck(self):
        compose = (ROOT / "deploy" / "docker-compose.production.yml.example").read_text(
            encoding="utf-8"
        )
        app_block = compose.split("\n  app:", 1)[1]
        self.assertIn("healthcheck:", app_block)
        self.assertIn("/healthz/", app_block)
        self.assertIn("start_period", app_block)
        # Production forbids 127.0.0.1 in ALLOWED_HOSTS, so a bare loopback probe
        # comes back 400 and the container looks broken forever.
        self.assertIn("ALLOWED_HOSTS", app_block)
        self.assertIn("'Host': h", app_block)

    def test_guard_sends_the_same_host_header(self):
        guard = (ROOT / "deploy" / "backup" / "app_guard.sh").read_text(encoding="utf-8")
        self.assertIn("ALLOWED_HOSTS", guard)
        self.assertIn("'Host': host", guard)


if __name__ == "__main__":
    unittest.main()
