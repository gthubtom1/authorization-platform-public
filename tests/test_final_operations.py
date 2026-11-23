"""Round-one C1-C4 counterexamples; all files are disposable fixtures."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection, connections
from django.test import Client, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from authorization_platform.audit.models import AuditEvent
from authorization_platform.backup_control import views as backup_views
from authorization_platform.backup_control.models import BackupControlOperation, BackupPolicy
from authorization_platform.releases.models import Release, ReleaseOperation, ReleaseSignatureStatus
from tests import test_releases as release_tests


ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / "TEMP" / "operations-tests"
User = get_user_model()


def fixture_directory():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=SCRATCH)


def bash_path(path):
    value = Path(path).resolve().as_posix()
    return f"/{value[0].lower()}{value[2:]}" if len(value) > 1 and value[1] == ":" else value


class FinalDumpRunnerTests(SimpleTestCase):
    def _run(self, mode):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "Bash is required: add D:/Tools/Git/bin to PATH")
        with fixture_directory() as directory:
            root = Path(directory)
            work = root / "sync"
            downloads = root / "downloads"
            for path in (work / "dumps", work / ".git", downloads, root / "keys"):
                path.mkdir(parents=True)
            for path in (work / "dumps" / "previous.enc", downloads / "previous.enc"):
                path.write_bytes(b"previous valid encrypted fixture")
                os.utime(path, (1, 1))
            manifest = work / "recovery-manifest.json"
            manifest.write_bytes(b"previous valid manifest")
            for filename in ("manage.py", "collector.py", "generator.py", "graph.json", "pass.txt"):
                (root / filename).write_text("fixture-only", encoding="utf-8")
            (root / "keys" / "github-token.txt").write_text("fake-local-token", encoding="utf-8")
            # Copy the actual runner next to harmless optional-copy scripts.
            runner = root / "backup_runner.sh"
            runner.write_bytes((ROOT / "deploy/backup/backup_runner.sh").read_bytes())
            for name in ("telegram_backup_copy.sh", "github_collapse.sh"):
                (root / name).write_text('#!/bin/bash\necho optional-copy >> "$CALLS"\n', encoding="utf-8")
                (root / name).chmod(0o700)
            harness = root / "harness.sh"
            harness.write_text(r'''#!/bin/bash
set -eu
docker() {
  if [ "$1" = cp ]; then
    if [ "$MODE" = header ]; then printf 'BROKEN fake dump' > "$3";
    else printf 'PGDMP fake dump' > "$3"; fi
  fi
}
openssl() {
  if [ "${2:-}" = -d ] && [ "$MODE" = decrypt ]; then return 1; fi
  local arg
  local args=()
  for arg in "$@"; do
    if [[ "$arg" = file:/* ]] && command -v cygpath >/dev/null; then
      arg="file:$(cygpath -m "${arg#file:}")"
    fi
    args+=("$arg")
  done
  command openssl "${args[@]}"
}
git() {
  echo git >> "$CALLS"
  case "$*" in
    *'remote get-url origin') echo 'https://github.com/fixture/backup' ;;
    *'rev-parse --verify'*) return 1 ;;
  esac
}
fixture_python() {
  if [ "${2:-}" = backup_policy ]; then
    case "$3" in
      --github-retention) echo 1 ;;
      --cleanup-check|--github-check) echo enabled ;;
      --github-repo) echo fixture/backup ;;
      --database-check) echo disabled ;;
      *) return 1 ;;
    esac
  else
    echo proof >> "$CALLS"
    return 1
  fi
}
export -f docker openssl git fixture_python
bash "$RUNNER" --type=full --proof-file="$FIXTURE_ROOT/proof.json"
''', encoding="utf-8")
            env = {key: value for key, value in os.environ.items()
                   if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
            env.update({"PATH": "/mingw64/bin:/usr/bin:/bin" if os.name == "nt" else os.environ["PATH"],
                   "MODE": mode, "CALLS": bash_path(root / "calls"),
                   "RUNNER": bash_path(runner), "FIXTURE_ROOT": bash_path(root),
                   "BACKUP_ROOT": bash_path(root), "BACKUP_GITHUB_WORK_DIR": bash_path(work),
                   "BACKUP_DOWNLOAD_DIR": bash_path(downloads), "BACKUP_KEYS_DIR": bash_path(root / "keys"),
                   "BACKUP_DUMP_PASS_FILE": bash_path(root / "pass.txt"),
                   "AUTHORIZATION_PLATFORM_MANAGE": bash_path(root / "manage.py"),
                   "AUTHORIZATION_PLATFORM_DB_CONTAINER": "fixture-db", "PYTHON_BIN": "fixture_python",
                   "BACKUP_PROOF_GENERATOR": bash_path(root / "generator.py"),
                   "BACKUP_EVIDENCE_COLLECTOR": bash_path(root / "collector.py"),
                   "BACKUP_MIGRATION_GRAPH_FILE": bash_path(root / "graph.json"),
                   "BACKUP_CANDIDATE_COMMIT": "fixture-commit", "BACKUP_KEY_VERSIONS": "fixture-v1"})
            result = subprocess.run([bash, bash_path(harness)], env=env, cwd=ROOT,
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            calls = (root / "calls").read_text() if (root / "calls").exists() else ""
            log = (root / "backup.log").read_text(encoding="utf-8", errors="replace")
            if mode == "good":
                self.assertEqual(result.returncode, 0, result.stderr + log)
                self.assertIn("encrypted dump verified", log)
                self.assertIn("git", calls)
                self.assertEqual(len(list(downloads.glob("*.enc"))), 1)
                self.assertFalse((downloads / "previous.enc").exists())
            else:
                self.assertNotEqual(result.returncode, 0, result.stderr + log)
                self.assertIn("PGDMP header" if mode == "header" else "does not decrypt", log)
                self.assertEqual(manifest.read_bytes(), b"previous valid manifest")
                for folder in (work / "dumps", downloads):
                    self.assertEqual([p.name for p in folder.glob("*.enc")], ["previous.enc"])
                    self.assertEqual((folder / "previous.enc").read_bytes(), b"previous valid encrypted fixture")
                self.assertFalse(list(root.rglob("*.plain")))
                self.assertEqual(calls, "", "bad dump reached a copy, push or proof stage")

    def test_c1_bad_header_preserves_previous_artifacts_before_any_delivery(self):
        self._run("header")

    def test_c1_decrypt_failure_preserves_previous_artifacts_before_any_delivery(self):
        self._run("decrypt")

    def test_c1_verified_dump_still_delivers_and_rotates(self):
        self._run("good")


class FinalReleaseTests(TestCase):
    # Reuse the real signed-ZIP fixture and API helpers without inheriting its tests.
    def setUp(self):
        self.admin = User.objects.create_superuser(username="release-admin", password="Admin-password-123")
        self.client.force_login(self.admin)
        self.software = release_tests.create_software(
            actor=self.admin, software_id="release-tool", name="Release Tool", status="active")
        self.profile = release_tests.create_profile(
            actor=self.admin, software_id=self.software.pk, profile_id="stable", client_id="release-tool-windows",
            target="windows", arch="x64", channel="stable", status="active")
        self.temp = fixture_directory()
        self.storage_root = Path(self.temp.name) / "storage"
        self.release_root = self.storage_root / "releases"
        self.settings_override = override_settings(
            STORAGE_ROOT=self.storage_root, RELEASE_STORAGE_ROOT=self.release_root,
            RELEASE_REQUIRE_VERIFIED_SIGNATURE=False)
        self.settings_override.enable()

    tearDown = release_tests.ReleaseApiTests.tearDown
    _signed_package = release_tests.ReleaseApiTests._signed_package
    _package = release_tests.ReleaseApiTests._package
    _upload = release_tests.ReleaseApiTests._upload
    _rename = release_tests.ReleaseApiTests._rename
    _publish_external = release_tests.ReleaseApiTests._publish_external

    def _published_zip(self, *, signed=True):
        package, public_key = self._signed_package() if signed else (self._package(), "")
        with override_settings(RELEASE_REQUIRE_VERIFIED_SIGNATURE=signed, RELEASE_SIGNING_PUBLIC_KEY=public_key,
                               RELEASE_SIGNING_KEY_ID="signed-test-key" if signed else "test-key"):
            uploaded = self.client.post(reverse("releases:manage_collection"),
                                        {"software_id": "release-tool", "channel": "stable", "release_package": package},
                                        HTTP_IDEMPOTENCY_KEY="final-zip-upload")
            self.assertEqual(uploaded.status_code, 201, uploaded.content)
            release_id = uploaded.json()["item"]["release_id"]
            published = self.client.post(reverse("releases:publish", kwargs={"release_id": release_id}),
                                         data=json.dumps({"notes": "真实签名包发布反例"}), content_type="application/json",
                                         HTTP_IDEMPOTENCY_KEY="final-zip-publish")
            self.assertEqual(published.status_code, 200, published.content)
        return Release.objects.get(pk=release_id)

    def test_c2_verified_zip_cannot_change_signed_manifest_in_place(self):
        release = self._published_zip()
        before = Release.objects.values().get(pk=release.pk)
        response = self._rename(release.pk, version="1.2.4", key="final-zip-rename")
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["error"]["code"], "RELEASE_NOT_RENUMBERABLE")
        self.assertEqual(Release.objects.values().get(pk=release.pk), before)
        self.assertFalse(ReleaseOperation.objects.filter(action="update_version").exists())
        self.assertFalse(AuditEvent.objects.filter(action="release.version.update", outcome="success").exists())

    def test_c2_declared_zip_is_also_not_renumberable(self):
        release = self._published_zip(signed=False)
        response = self._rename(release.pk, version="1.2.4", key="final-declared-rename")
        self.assertEqual(response.status_code, 409, response.content)
        release.refresh_from_db()
        self.assertEqual(release.version, "1.2.3")

    def test_c2_external_release_keeps_renumber_replay_and_update_behavior(self):
        release_tests.ReleaseApiTests.test_update_version_in_place_makes_clients_see_the_update(self)

    def test_c3_anonymous_download_rejects_declared_before_opening_or_rate_budget(self):
        release = self._published_zip()
        url = reverse("releases:public_download", kwargs={"software_id": "release-tool", "profile_id": "stable",
                                                        "release_id": release.pk})
        Release.objects.filter(pk=release.pk).update(signature_status=ReleaseSignatureStatus.DECLARED)
        cache.clear()
        with override_settings(RELEASE_REQUIRE_VERIFIED_SIGNATURE=True, RELEASE_DOWNLOAD_REQUIRE_AUTH=False,
                               PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT=1):
            with patch("authorization_platform.releases.api_views.open_release_package") as opened:
                rejected = Client().get(url, REMOTE_ADDR="127.0.0.31")
            self.assertEqual(rejected.status_code, 404)
            self.assertEqual(rejected.json()["error"]["code"], "RELEASE_NOT_FOUND")
            opened.assert_not_called()
            Release.objects.filter(pk=release.pk).update(signature_status=ReleaseSignatureStatus.VERIFIED)
            allowed = Client().get(url, REMOTE_ADDR="127.0.0.31")
            self.assertEqual(allowed.status_code, 200, getattr(allowed, "content", b""))
            self.assertIn(b"client-release.v1.json", b"".join(allowed.streaming_content))
            self.assertEqual(Client().get(url, REMOTE_ADDR="127.0.0.31").status_code, 429)


@unittest.skipUnless(connection.vendor == "postgresql", "Requires isolated PostgreSQL row locks")
class FinalBackupDeleteConcurrencyTests(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser(username="operations-writer", password="Fixture-password-123")
        BackupPolicy.objects.create(key="default", github_retention_count=1)
        self.temp = fixture_directory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("first.enc", "second.enc", "reserve.enc"):
            (self.root / name).write_bytes(name.encode())

    def _post(self, name, key):
        client = Client()
        client.raise_request_exception = False
        client.force_login(User.objects.get(pk=self.admin.pk))
        response = client.post(reverse("backup_control:api_delete_download", args=[name]),
                               data=json.dumps({"confirmed": True}), content_type="application/json",
                               HTTP_IDEMPOTENCY_KEY=key)
        return response.status_code, response.json() if response.headers.get("Content-Type", "").startswith("application/json") else {}

    def _race(self, *, second_name, second_key="same-key", virtual=False):
        first_inside = threading.Event()
        competitor_attempted = threading.Event()
        first_finished = threading.Event()
        delete = backup_views.delete_encrypted_download
        lookup = backup_views.existing_operation
        effects = []

        def lookup_spy(**kwargs):
            result = lookup(**kwargs)
            if threading.current_thread().name.endswith("_1"):
                # Old code reaches an unprotected stale read. Correct code is
                # already waiting for SELECT FOR UPDATE and reads after commit.
                competitor_attempted.set()
                self.assertTrue(first_finished.wait(10))
            return result

        def delete_spy(**kwargs):
            if threading.current_thread().name.endswith("_0"):
                first_inside.set()
                self.assertTrue(competitor_attempted.wait(10))
            effects.append(kwargs["name"])
            if virtual:
                return {"deleted": kwargs["name"], "size": 1, "sha256_suffix": "fixture",
                        "remaining_count": 2, "retention_count": 1}
            return delete(**kwargs)

        def observe_lock(execute, sql, params, many, context):
            if "FOR UPDATE" in sql.upper() and "backup_control_backuppolicy" in sql:
                competitor_attempted.set()
            return execute(sql, params, many, context)

        def first():
            try:
                return self._post("first.enc", "same-key")
            finally:
                first_finished.set()
                connections.close_all()

        def second():
            try:
                self.assertTrue(first_inside.wait(10))
                with connection.execute_wrapper(observe_lock):
                    return self._post(second_name, second_key)
            finally:
                connections.close_all()

        with override_settings(BACKUP_DOWNLOAD_DIR=self.root), patch.object(backup_views, "existing_operation", lookup_spy), \
                patch.object(backup_views, "delete_encrypted_download", delete_spy):
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="operations_delete") as pool:
                a = pool.submit(first)
                b = pool.submit(second)
                results = a.result(timeout=20), b.result(timeout=20)
        return results, effects

    def test_c4_same_key_other_target_conflicts_before_virtual_file_effect(self):
        results, effects = self._race(second_name="second.enc", virtual=True)
        self.assertEqual(effects, ["first.enc"])
        self.assertEqual(results[0][0], 200, results)
        self.assertEqual(results[1][0], 409, results)

    def test_c4_same_key_other_target_preserves_second_real_file(self):
        results, effects = self._race(second_name="second.enc")
        self.assertTrue((self.root / "second.enc").exists())
        self.assertEqual(results[0][0], 200, results)
        self.assertEqual(results[1][0], 409, results)
        self.assertEqual(results[1][1]["error"]["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(effects, ["first.enc"])
        self.assertEqual(BackupControlOperation.objects.filter(action="download.delete").count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="backup.download.delete", outcome="success").count(), 1)

    def test_c4_same_key_same_target_replays_committed_result(self):
        results, effects = self._race(second_name="first.enc")
        self.assertEqual([result[0] for result in results], [200, 200], results)
        self.assertEqual(results[0][1], results[1][1])
        self.assertEqual(effects, ["first.enc"])

    def test_c4_different_keys_keep_the_last_backup_under_concurrency(self):
        (self.root / "reserve.enc").unlink()
        results, effects = self._race(second_name="second.enc", second_key="other-key")
        self.assertEqual(results[0][0], 200, results)
        self.assertEqual(results[1][0], 409, results)
        self.assertEqual(results[1][1]["error"]["code"], "BACKUP_RETENTION_FLOOR")
        self.assertTrue((self.root / "second.enc").exists())
