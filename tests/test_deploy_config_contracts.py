"""Deploy-time config contracts.

These files are installed verbatim onto the VPS, so a defect here is a
production defect that no Django test would ever notice.  Every check below
corresponds to a real failure that was observed on the test station.
"""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
INSTALL_SCRIPT = DEPLOY / "install-site.sh"
LOGROTATE_TEMPLATE = DEPLOY / "logrotate" / "authorization-platform.example"


def _has_carriage_return(path: Path) -> bool:
    return b"\r" in path.read_bytes()


def _directives_only(text: str) -> str:
    """Drop comment and blank lines so assertions look at real directives only."""
    return "\n".join(
        line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
    )


def git_bash() -> str:
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
    raise AssertionError("Git Bash is required to exercise the logrotate parse gate")


class DeployConfigLineEndingTests(unittest.TestCase):
    def test_logrotate_template_is_lf_only(self):
        # A CRLF copy shipped to the host made logrotate parse every directive as
        # a malformed keyword.  logrotate.service then failed every night while
        # install-site.sh still printed "logrotate: ok" because its verify only
        # grepped for a filename.
        self.assertTrue(LOGROTATE_TEMPLATE.is_file())
        self.assertFalse(
            _has_carriage_return(LOGROTATE_TEMPLATE),
            "deploy/logrotate/authorization-platform.example must be LF-only; "
            "a CRLF copy aborts the whole nightly log rotation run",
        )

    def test_gitattributes_pins_example_templates_to_lf(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("*.example text eol=lf", attributes)

    def test_shipped_deploy_templates_have_no_carriage_returns(self):
        offenders = [
            str(path.relative_to(ROOT)).replace("\\", "/")
            for path in sorted(DEPLOY.rglob("*.example"))
            if _has_carriage_return(path)
        ]
        self.assertEqual(offenders, [], f"CRLF in deploy templates: {offenders}")

    def test_shipped_shell_scripts_have_no_carriage_returns(self):
        offenders = [
            str(path.relative_to(ROOT)).replace("\\", "/")
            for path in sorted(DEPLOY.rglob("*.sh"))
            if _has_carriage_return(path)
        ]
        self.assertEqual(offenders, [], f"CRLF in deploy scripts: {offenders}")


class LogrotateInstallContractTests(unittest.TestCase):
    def setUp(self):
        self.source = INSTALL_SCRIPT.read_text(encoding="utf-8")

    def test_install_rejects_a_crlf_logrotate_template(self):
        self.assertIn("logrotate template must be LF-only", self.source)

    def test_install_parses_the_stanza_before_continuing(self):
        # "the file exists and mentions backup.log" is not evidence that logrotate
        # can read it; the installer has to hand it to the real binary.
        self.assertIn("logrotate --debug", self.source)

    def test_the_parse_gate_ignores_environment_warnings(self):
        # On Ubuntu /var/log is a world-writable sticky directory, so logrotate
        # returns non-zero for files under it even when the stanza is perfect.
        # Gating on the exit code blocked a correct install on 2026-09-26; the
        # gate must key on real parse errors only.
        self.assertIn("logrotate_stanza_parses", self.source)
        self.assertIn("lines must begin with", self.source)
        self.assertIn("found error in", self.source)
        # The template declares the rotation identity, which is what silences
        # the permission complaint in the first place.
        template = _directives_only(LOGROTATE_TEMPLATE.read_text(encoding="utf-8"))
        self.assertEqual(template.count("su root root"), 1)

    def test_verify_site_checks_parsing_not_just_presence(self):
        self.assertNotIn("grep -q 'backup.log' /etc/logrotate.d/authorization-platform", self.source)
        self.assertIn("MISSING_OR_UNPARSEABLE", self.source)

    def test_logrotate_template_owns_only_the_host_side_logs(self):
        # /etc/logrotate.d/nginx already owns /var/log/nginx/*.log. Declaring the
        # same files twice makes logrotate abort the whole nginx rotation config
        # with "duplicate log entry" -- which is exactly what happened on the test
        # station as soon as the CRLF bug was fixed and the stanza finally parsed.
        template = _directives_only(LOGROTATE_TEMPLATE.read_text(encoding="utf-8"))
        self.assertNotIn("/var/log/nginx", template)
        self.assertIn("/var/log/authorization-platform-maintenance.log", template)
        self.assertIn("/var/lib/authorization-platform-backup/backup.log", template)
        self.assertEqual(template.count("create 0640"), 1)
        self.assertIn("create 0640 root adm", template)

    def test_compose_is_refreshed_from_the_template_on_every_install(self):
        # The old `if [ ! -f ]` guard meant template changes never reached the
        # host: the app healthcheck was absent on the running container for a
        # whole deployment cycle.
        self.assertNotIn('if [ ! -f "$COMPOSE_FILE" ]; then', self.source)
        self.assertIn("refreshed from template", self.source)


class LogrotateParseGateBehaviourTests(unittest.TestCase):
    """The gate must fail on a real parse error and pass on an environment warning.

    ``logrotate --debug`` returns non-zero for both, so an exit-code gate blocks
    correct installs (Ubuntu's /var/log is a world-writable sticky directory) --
    that actually happened on the test station on 2026-09-26.  A real logrotate is
    not available on Windows, so the binary is stubbed and the function is lifted
    out of the installer the same way the backup governance tests do it.
    """

    STUB = "#!/usr/bin/env bash\nprintf '%s' \"$FAKE_LOGROTATE_STDOUT\"\nexit ${FAKE_LOGROTATE_RC:-0}\n"

    def _gate_source(self) -> str:
        source = INSTALL_SCRIPT.read_text(encoding="utf-8")
        start = source.index("logrotate_stanza_parses() {")
        end = source.index("\n}\n", start) + len("\n}\n")
        return source[start:end]

    def _run_gate(self, *, output: str, rc: int) -> int:
        import os
        import stat
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            stub = bin_dir / "logrotate"
            stub.write_text(self.STUB, encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            script = f'{self._gate_source()}\nlogrotate_stanza_parses /etc/logrotate.d/probe; echo "gate=$?"'
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": os.pathsep.join([str(bin_dir), environment.get("PATH", "")]),
                    "FAKE_LOGROTATE_STDOUT": output,
                    "FAKE_LOGROTATE_RC": str(rc),
                }
            )
            result = subprocess.run(
                [git_bash(), "-c", script], capture_output=True, text=True, env=environment, timeout=60
            )
            self.assertIn("gate=", result.stdout, result.stdout + result.stderr)
            return int(result.stdout.split("gate=")[1].split()[0])

    def test_a_clean_parse_passes_even_when_logrotate_exits_non_zero(self):
        # The Ubuntu permission warning: real complaint, not a syntax problem.
        output = (
            'error: skipping "/var/log/x.log" because parent directory has insecure permissions\n'
            "rotating pattern: /var/log/x.log after 1 days\n"
        )
        self.assertEqual(self._run_gate(output=output, rc=1), 0)

    def test_a_real_parse_error_fails(self):
        output = (
            "error: authorization-platform:2 lines must begin with a keyword or a filename\n"
            "error: found error in /etc/logrotate.d/authorization-platform\n"
        )
        self.assertEqual(self._run_gate(output=output, rc=1), 1)

    def test_a_crlf_parse_error_is_caught(self):
        output = 'error: authorization-platform:15 lines must begin with a keyword or a filename\n'
        self.assertEqual(self._run_gate(output=output, rc=0), 1)


if __name__ == "__main__":
    unittest.main()
