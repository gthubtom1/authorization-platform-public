import json
import os
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "postgresql-concurrency-acceptance.ps1"
PREFLIGHT = ROOT / "scripts" / "preflight-postgresql.ps1"
ARTIFACT_ROOT = ROOT / "output" / "postgresql-concurrency"
DATABASE_VARIABLES = (
    "DATABASE_ENGINE",
    "DATABASE_HOST",
    "DATABASE_PORT",
    "DATABASE_NAME",
    "DATABASE_USER",
    "DATABASE_PASSWORD",
)




_ENVIRONMENT_PASSTHROUGH = (
    "PATH",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PSModulePath",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "PYTHONHOME",
    "VIRTUAL_ENV",
)

def _minimal_environment(overrides: dict) -> dict:
    """Scrub process-level leftovers before spawning the runner.

    The runner script starts a grandchild PowerShell that re-reads
    DATABASE_*, Git and tool-discovery variables from its own
    environment.  Inheriting the full test-process environment let
    earlier Django tests change what that grandchild saw (settings
    module, proxy overrides, patched PATH entries), which made the
    outcome depend on which tests ran first in a full-suite run.
    Whitelist only what the tools need to start, and let each test
    declare the variables it actually cares about via ``overrides``.
    """
    environment = {
        name: os.environ[name]
        for name in _ENVIRONMENT_PASSTHROUGH
        if name in os.environ
    }
    environment.update(overrides)
    return environment


class PostgreSQLConcurrencyRunnerTests(unittest.TestCase):
    def _new_output_directory(self, prefix):
        ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
        return ARTIFACT_ROOT / f"{prefix}{uuid.uuid4().hex}"

    def _run_runner(
        self,
        environment,
        output_directory,
        approved_host="127.0.0.1",
        approved_port=5432,
    ):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell, "Windows PowerShell is required for the runner guard")
        proc = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(RUNNER),
                "-ConfirmIsolatedTarget",
                "-ApprovedHost",
                approved_host,
                "-ApprovedServerAddress",
                "127.0.0.1",
                "-ApprovedPort",
                str(approved_port),
                "-ApprovedDatabase",
                "isolated_acceptance",
                "-ApprovedUser",
                "test_role",
                "-OutputDirectory",
                str(output_directory),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=30,
        )
        return type("ProcessResult", (), {
            "returncode": proc.returncode,
            "stdout": self._decode_output(proc.stdout),
            "stderr": self._decode_output(proc.stderr),
        })()

    @staticmethod
    def _decode_output(raw_bytes: bytes) -> str:
        if not raw_bytes:
            return ""
        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw_bytes.decode("gbk")
            except UnicodeDecodeError:
                return raw_bytes.decode("utf-8", errors="replace")

    def _matching_environment(self, port=1):
        environment = _minimal_environment({})
        environment.update(
            {
                "DATABASE_ENGINE": "postgresql",
                "DATABASE_HOST": "127.0.0.1",
                "DATABASE_PORT": str(port),
                "DATABASE_NAME": "isolated_acceptance",
                "DATABASE_USER": "test_role",
                "DATABASE_PASSWORD": "sentinel-password-must-not-be-used",
            }
        )
        environment.pop("RUNNER_MAINTENANCE_DATABASE", None)
        return environment

    def test_missing_configuration_fails_before_connection_or_tests(self):
        environment = _minimal_environment({})
        for name in DATABASE_VARIABLES:
            environment.pop(name, None)
        environment.pop("RUNNER_MAINTENANCE_DATABASE", None)

        output_directory = self._new_output_directory("test-")
        try:
            completed = self._run_runner(environment, output_directory)

            self.assertNotEqual(completed.returncode, 0)
            combined_output = f"{completed.stdout}\n{completed.stderr}"
            self.assertIn("配置预检失败", combined_output)

            manifest = json.loads(
                (output_directory / "manifest.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(manifest["status"], "failed")
            self.assertTrue((output_directory / "preflight-config.stderr.txt").exists())
            self.assertFalse(
                (output_directory / "preflight-connection.stdout.txt").exists()
            )
            self.assertFalse((output_directory / "tests.stdout.txt").exists())
        finally:
            shutil.rmtree(output_directory, ignore_errors=True)

    def test_mismatched_configuration_fails_before_connection_or_tests(self):
        environment = _minimal_environment({})
        environment.update(
            {
                "DATABASE_ENGINE": "postgresql",
                "DATABASE_HOST": "not-approved-target.invalid",
                "DATABASE_PORT": "5432",
                "DATABASE_NAME": "isolated_acceptance",
                "DATABASE_USER": "test_role",
                "DATABASE_PASSWORD": "sentinel-password-must-not-be-used",
            }
        )
        environment.pop("RUNNER_MAINTENANCE_DATABASE", None)

        output_directory = self._new_output_directory("mismatch-")
        try:
            completed = self._run_runner(environment, output_directory, approved_host="127.0.0.1")

            self.assertNotEqual(completed.returncode, 0)
            combined_output = f"{completed.stdout}\n{completed.stderr}"
            self.assertIn("配置与批准的隔离目标不一致", combined_output)
            self.assertIn("未连接数据库", combined_output)

            manifest = json.loads(
                (output_directory / "manifest.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(manifest["status"], "failed")
            self.assertTrue((output_directory / "preflight-config.stdout.txt").exists())
            self.assertFalse((output_directory / "preflight-connection.stdout.txt").exists())
            self.assertFalse((output_directory / "preflight-connection.stderr.txt").exists())
            self.assertFalse((output_directory / "identity.stdout.txt").exists())
            self.assertFalse((output_directory / "tests.stdout.txt").exists())
            self.assertNotIn("sentinel-password-must-not-be-used", combined_output)
        finally:
            shutil.rmtree(output_directory, ignore_errors=True)

    def test_existing_output_directory_is_rejected_without_overwrite(self):
        environment = _minimal_environment({})
        for name in DATABASE_VARIABLES:
            environment.pop(name, None)
        environment.pop("RUNNER_MAINTENANCE_DATABASE", None)

        output_directory = self._new_output_directory("existing-")
        output_directory.mkdir(parents=True)
        sentinel = output_directory / "manifest.json"
        sentinel.write_text("sentinel", encoding="utf-8")
        try:
            completed = self._run_runner(environment, output_directory)

            self.assertNotEqual(completed.returncode, 0)
            combined_output = f"{completed.stdout}\n{completed.stderr}"
            self.assertIn("产物目录已经存在", combined_output)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "sentinel")
        finally:
            shutil.rmtree(output_directory, ignore_errors=True)

    def test_dirty_worktree_fails_before_database_connection_or_tests(self):
        environment = self._matching_environment(port=1)
        # The dirty state has to be injected.  Relying on the developer's real
        # worktree being dirty made this test green locally and red on any
        # clean checkout (CI, fresh clone, right after a commit): the runner's
        # Git guard (postgresql-concurrency-acceptance.ps1) lets a clean tree
        # through to the read-only connection preflight, which then always
        # writes preflight-connection.stdout.txt and fails the assertion below.
        # A stub git that reports a dirty worktree is the only way to prove the
        # guard fires *before* any database work, and it keeps the strict
        # assertions below honest instead of weakening them.
        fake_git_directory = Path(self._new_output_directory("fake-git-dirty-"))
        fake_git_directory.mkdir(parents=True)
        fake_git = fake_git_directory / "git.cmd"
        fake_git.write_text(
            "@echo off\r\n"
            'if /I "%~3"=="rev-parse" (echo 1111111111111111111111111111111111111111& exit /b 0)\r\n'
            'if /I "%~3"=="status" (echo  M tests\\test_postgresql_runner.py& exit /b 0)\r\n'
            'if /I "%~3"=="branch" (echo main& exit /b 0)\r\n'
            "exit /b 1\r\n",
            encoding="utf-8",
        )
        environment["PATH"] = os.pathsep.join(
            (str(fake_git_directory), environment.get("PATH", ""))
        )
        output_directory = self._new_output_directory("dirty-")
        try:
            completed = self._run_runner(
                environment,
                output_directory,
                approved_host="127.0.0.1",
                approved_port=1,
            )

            self.assertNotEqual(completed.returncode, 0)
            combined_output = f"{completed.stdout}\n{completed.stderr}"
            self.assertIn("工作区不是干净状态", combined_output)
            self.assertIn("未连接数据库", combined_output)
            manifest = json.loads(
                (output_directory / "manifest.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(manifest["worktree_status"], "dirty")
            self.assertFalse((output_directory / "preflight-connection.stdout.txt").exists())
            self.assertFalse((output_directory / "identity.stdout.txt").exists())
            self.assertFalse((output_directory / "tests.stdout.txt").exists())
        finally:
            shutil.rmtree(fake_git_directory, ignore_errors=True)
            shutil.rmtree(output_directory, ignore_errors=True)

    def test_clean_worktree_is_not_mistaken_for_a_dirty_one(self):
        """A clean tree must pass the Git guard and stop at the preflight.

        This is the mirror image of the test above.  It also uses a stub git so
        the outcome does not depend on whether the developer currently has
        uncommitted changes -- a test that flips with the local worktree is
        exactly the failure mode this file just had.
        """
        environment = self._matching_environment(port=1)
        fake_git_directory = Path(self._new_output_directory("fake-git-clean-"))
        fake_git_directory.mkdir(parents=True)
        fake_git = fake_git_directory / "git.cmd"
        fake_git.write_text(
            "@echo off\r\n"
            'if /I "%~3"=="rev-parse" (echo 1111111111111111111111111111111111111111& exit /b 0)\r\n'
            'if /I "%~3"=="status" exit /b 0\r\n'
            'if /I "%~3"=="branch" (echo main& exit /b 0)\r\n'
            "exit /b 1\r\n",
            encoding="utf-8",
        )
        environment["PATH"] = os.pathsep.join(
            (str(fake_git_directory), environment.get("PATH", ""))
        )
        output_directory = self._new_output_directory("clean-")
        try:
            completed = self._run_runner(
                environment,
                output_directory,
                approved_host="127.0.0.1",
                approved_port=1,
            )

            self.assertNotEqual(completed.returncode, 0)
            combined_output = f"{completed.stdout}\n{completed.stderr}"
            self.assertIn("只读连接预检失败", combined_output)
            self.assertNotIn("工作区不是干净状态", combined_output)
            manifest = json.loads(
                (output_directory / "manifest.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(manifest["worktree_status"], "clean")
            self.assertTrue((output_directory / "preflight-connection.stdout.txt").exists())
        finally:
            shutil.rmtree(fake_git_directory, ignore_errors=True)
            shutil.rmtree(output_directory, ignore_errors=True)

    def test_git_head_read_failure_fails_closed(self):
        environment = self._matching_environment(port=1)
        fake_git_directory = Path(self._new_output_directory("fake-git-"))
        fake_git_directory.mkdir(parents=True)
        fake_git = fake_git_directory / "git.cmd"
        fake_git.write_text("@echo off\r\nexit /b 1\r\n", encoding="utf-8")
        environment["PATH"] = os.pathsep.join(
            (str(fake_git_directory), environment.get("PATH", ""))
        )
        output_directory = self._new_output_directory("git-failure-")
        try:
            completed = self._run_runner(
                environment,
                output_directory,
                approved_host="127.0.0.1",
                approved_port=1,
            )

            self.assertNotEqual(completed.returncode, 0)
            combined_output = f"{completed.stdout}\n{completed.stderr}"
            self.assertIn("Git HEAD", combined_output)
            self.assertIn("未连接数据库", combined_output)
            manifest = json.loads(
                (output_directory / "manifest.json").read_text(encoding="utf-8-sig")
            )
            self.assertIsNone(manifest.get("commit"))
            self.assertFalse((output_directory / "preflight-connection.stdout.txt").exists())
            self.assertFalse((output_directory / "identity.stdout.txt").exists())
        finally:
            shutil.rmtree(fake_git_directory, ignore_errors=True)
            shutil.rmtree(output_directory, ignore_errors=True)

    def test_runner_process_and_database_safety_contract_is_executable(self):
        source = RUNNER.read_text(encoding="utf-8")

        self.assertIn("ProcessTreeStopped", source)
        self.assertIn("OutputDrainTimedOut", source)
        self.assertIn("identity_script", source)
        self.assertIn("-TimeoutSeconds $ProcessTimeoutSeconds", source)
        self.assertNotIn("$identityOutputItems = @(& $python -c $identityCode", source)
        self.assertIn("role_superuser", source)
        self.assertIn("role_createrole", source)
        self.assertIn("role_replication", source)
        self.assertIn("role_bypassrls", source)
        self.assertIn("host(inet_server_addr())", source)
        self.assertIn("$(Quote-ProcessArgument -Value $manage) test --settings", source)
        self.assertNotIn('DATABASES[\\"default\\"]', source)
        self.assertIn("final_commit", source)
        self.assertIn("final_worktree_status", source)

        self.assertIn("CREATE DATABASE", source)
        self.assertIn("DROP DATABASE", source)
        self.assertIn("WITH (FORCE)", source)
        self.assertIn("--keepdb", source)
        self.assertIn("test_database_exists_after_cleanup", source)

    def test_preflight_connection_uses_a_temp_python_script_without_leaking_password(self):
        powershell = shutil.which("powershell.exe")
        self.assertIsNotNone(powershell, "Windows PowerShell is required for the preflight guard")
        environment = _minimal_environment({})
        environment.update(
            {
                "DATABASE_ENGINE": "postgresql",
                "DATABASE_HOST": "127.0.0.1",
                "DATABASE_PORT": "1",
                "DATABASE_NAME": "preflight_probe",
                "DATABASE_USER": "preflight_probe",
                "DATABASE_PASSWORD": "sentinel-password-must-not-leak",
            }
        )
        proc = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(PREFLIGHT),
                "-CheckConnection",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=30,
        )
        completed = type("ProcessResult", (), {
            "returncode": proc.returncode,
            "stdout": self._decode_output(proc.stdout),
            "stderr": self._decode_output(proc.stderr),
        })()
        output = f"{completed.stdout}\n{completed.stderr}"
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("PostgreSQL connection failed; details are intentionally not printed.", output)
        self.assertNotIn("SyntaxError", output)
        self.assertNotIn("sentinel-password-must-not-leak", output)


if __name__ == "__main__":
    unittest.main()
