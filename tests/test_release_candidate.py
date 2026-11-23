from __future__ import annotations

import json
import base64
import io
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from scripts.application_rollback import RollbackError, activate_candidate, read_state, rollback_candidate
from scripts.capacity_probe import ProbeResult, evaluate_capacity, run_probe
from scripts.capacity_threshold_acceptance import run_thresholds
from scripts.migration_recovery import migration_recovery_plan
from scripts.release_candidate_acceptance import (
    ARCHIVE_PREVIEW_NAMES,
    FROZEN_PAGE_NAMES,
    _js_function_body,
    _management_action_pause_copy,
    _management_action_reset_copy,
    _management_action_block_copy,
    _management_action_unblock_copy,
    _static_preview_findings,
    _extra_preview_page_findings,
    main as release_candidate_main,
    safe_summary,
    validate_candidate_archive,
    validate_frozen_page_content,
    validate_frozen_pages,
    validate_nginx_config,
    validate_production_environment,
)
from authorization_platform.core.object_storage import S3ObjectStore, configured_object_store
from authorization_platform.releases.services import ReleaseOperationError, _ensure_local_storage_adapter, resolve_release_package_path
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
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "PYTHONHOME",
    "PYTHONPATH",
    "VIRTUAL_ENV",
)

def _minimal_environment(overrides: dict) -> dict:
    """Scrub process-level leftovers before spawning a subprocess.

    Production settings-module probes only need Python plus the
    project on PYTHONPATH.  Inheriting the full test-process
    environment let whichever Django test ran first leak its own
    DJANGO_SETTINGS_MODULE / DATABASE_* / proxy variables into the
    child, which made the assertion order-dependent in a full-suite
    run.  Whitelist only startup variables; everything the child
    must see must be declared in ``overrides``.
    """
    environment = {
        name: os.environ[name]
        for name in _ENVIRONMENT_PASSTHROUGH
        if name in os.environ
    }
    environment.update(overrides)
    return environment




def _empty_archive_preview_payload(name: str) -> bytes:
    if name == "404.html":
        return (
            b"<!doctype html><html><head>"
            b'<link rel="stylesheet" href="preview.css" />'
            b"</head><body>"
            b"<h1>Not Found</h1>"
            b'<p><a href="/downstream-login.html">downstream-login.html</a></p>'
            b"</body></html>"
        )
    if name.endswith(".html"):
        return b"<html><body></body></html>"
    return b""


def _current_preview_archive_entries() -> list[tuple[str, bytes, str]]:
    root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
    return [
        (f"candidate/docs/ui-preview/{name}", (root / name).read_bytes(), "file")
        for name in ARCHIVE_PREVIEW_NAMES
    ]


def _write_preview_archive(
    path: Path,
    archive_format: str,
    entries: list[tuple[str, bytes, str]],
) -> None:
    if archive_format == "tar":
        with tarfile.open(path, "w:gz") as archive:
            for name, payload, member_type in entries:
                info = tarfile.TarInfo(name)
                if member_type == "directory":
                    info.type = tarfile.DIRTYPE
                elif member_type == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "manage.html"
                else:
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
                    continue
                archive.addfile(info)
        return
    if archive_format == "zip":
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload, member_type in entries:
                if member_type == "directory":
                    archive.writestr(name.rstrip("/") + "/", b"")
                elif member_type == "symlink":
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, payload)
                else:
                    archive.writestr(name, payload)
        return
    raise ValueError(archive_format)


def production_env() -> dict[str, str]:
    values = {
        "APP_ENV": "production",
        "DJANGO_DEBUG": "false",
        "DJANGO_SECRET_KEY": "django-secret-unique-1234567890",
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
        "RELEASE_DOWNLOAD_REQUIRE_AUTH": "false",
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
    return values


class ReleaseCandidateChecksTests(SimpleTestCase):
    def test_complete_production_contract_does_not_expose_values(self):
        checks = validate_production_environment(production_env())
        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        summary = safe_summary(checks)
        encoded = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn("database-secret", encoded)
        self.assertNotIn("object-secret", encoded)

    def test_missing_or_reused_production_secret_is_rejected(self):
        values = production_env()
        values["QUOTA_CARD_HASH_KEY"] = values["DJANGO_SECRET_KEY"]
        checks = validate_production_environment(values)
        self.assertEqual(next(item.status for item in checks if item.name == "production_secrets_independent"), "failed")

    def test_production_cannot_disable_release_signature_enforcement(self):
        values = production_env()
        values["RELEASE_REQUIRE_VERIFIED_SIGNATURE"] = "false"
        checks = validate_production_environment(values)
        self.assertEqual(next(item.status for item in checks if item.name == "release_signature_enforced"), "failed")

    def test_production_rejects_card_gated_release_download(self):
        values = production_env()
        values["RELEASE_DOWNLOAD_REQUIRE_AUTH"] = "true"
        checks = validate_production_environment(values)
        self.assertEqual(next(item.status for item in checks if item.name == "release_download_anonymous"), "failed")

    def test_production_allows_omitting_release_download_auth(self):
        values = production_env()
        values.pop("RELEASE_DOWNLOAD_REQUIRE_AUTH", None)
        checks = validate_production_environment(values)
        self.assertEqual(next(item.status for item in checks if item.name == "release_download_anonymous"), "passed")

    def test_django_settings_import_rejects_production_download_auth_true(self):
        env = _minimal_environment({})
        env.update(
            {
                "APP_ENV": "production",
                "DJANGO_DEBUG": "false",
                "DJANGO_SECRET_KEY": "django-secret-unique-1234567890-pad-to-fifty-chars!!!!",
                "ALLOWED_HOSTS": "auth.example.com",
                "CSRF_TRUSTED_ORIGINS": "https://auth.example.com",
                "TRUSTED_PROXY_IPS": "10.0.0.0/8",
                "TRUST_PROXY_SSL_HEADER": "true",
                "INVITATION_ENCRYPTION_KEY": "invitation-key-unique-value-aaaaaaaa",
                "PASSWORD_OPERATION_HASH_KEY": "password-key-unique-value-bbbbbbbb",
                "ACCOUNT_OPERATION_HASH_KEY": "account-key-unique-value-cccccccccc",
                "RELEASE_DOWNLOAD_REQUIRE_AUTH": "true",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            }
        )
        env.pop("DJANGO_SETTINGS_MODULE", None)
        result = subprocess.run(
            [sys.executable, "-c", "import authorization_platform.settings"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("card-gated", result.stderr)

    def test_django_settings_import_rejects_production_signature_enforcement_false(self):
        env = _minimal_environment({})
        env.update(production_env())
        env["DJANGO_SECRET_KEY"] = "django-secret-unique-1234567890-pad-to-fifty-chars!!!!"
        env["RELEASE_REQUIRE_VERIFIED_SIGNATURE"] = "false"
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        env.pop("DJANGO_SETTINGS_MODULE", None)
        result = subprocess.run(
            [sys.executable, "-c", "import authorization_platform.settings"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RELEASE_REQUIRE_VERIFIED_SIGNATURE", result.stderr)

    def _import_production_settings(self, **overrides: str):
        env = _minimal_environment({})
        env.update(production_env())
        env["DJANGO_SECRET_KEY"] = "django-secret-unique-1234567890-pad-to-fifty-chars!!!!"
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        env.pop("DJANGO_SETTINGS_MODULE", None)
        env.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", "import authorization_platform.settings"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(Path(__file__).resolve().parents[1]),
        )

    def test_django_settings_import_accepts_complete_production_env(self):
        result = self._import_production_settings()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_django_settings_import_rejects_production_download_rate_limit_zero(self):
        result = self._import_production_settings(PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RuntimeError", result.stderr)
        self.assertIn("PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT", result.stderr)

    def test_django_settings_import_rejects_production_download_rate_limit_negative(self):
        result = self._import_production_settings(PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT="-1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RuntimeError", result.stderr)
        self.assertIn("PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT", result.stderr)

    def test_django_settings_import_rejects_production_download_ip_rate_limit_zero(self):
        result = self._import_production_settings(PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RuntimeError", result.stderr)
        self.assertIn("PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT", result.stderr)

    def test_django_settings_import_rejects_production_download_ip_rate_limit_negative(self):
        result = self._import_production_settings(PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT="-1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RuntimeError", result.stderr)
        self.assertIn("PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT", result.stderr)

    def test_django_settings_import_rejects_production_invitation_issue_rate_limit_zero(self):
        result = self._import_production_settings(INVITATION_ISSUE_RATE_LIMIT="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RuntimeError", result.stderr)
        self.assertIn("INVITATION_ISSUE_RATE_LIMIT", result.stderr)

    def test_django_settings_import_rejects_production_invitation_issue_rate_limit_negative(self):
        result = self._import_production_settings(INVITATION_ISSUE_RATE_LIMIT="-1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RuntimeError", result.stderr)
        self.assertIn("INVITATION_ISSUE_RATE_LIMIT", result.stderr)

    def test_production_rejects_invalid_release_public_key(self):
        values = production_env()
        values["RELEASE_SIGNING_PUBLIC_KEY"] = "public-key"
        checks = validate_production_environment(values)
        self.assertEqual(next(item.status for item in checks if item.name == "release_public_key"), "failed")

    def test_proxy_template_and_frozen_page_contract_are_present(self):
        root = Path(__file__).resolve().parents[1]
        pages = validate_frozen_pages(root / "docs" / "ui-preview")
        self.assertEqual([item.name for item in pages], [f"frozen_page_file:{page}" for page in FROZEN_PAGE_NAMES])
        self.assertTrue(all(item.status == "passed" for item in pages))
        content_checks = validate_frozen_page_content(root / "docs" / "ui-preview")
        self.assertEqual([item.status for item in content_checks], ["passed"])
        checks = validate_nginx_config(root / "deploy" / "nginx" / "authorization-platform.conf.example")
        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        iqd = validate_nginx_config(root / "部署与恢复" / "nginx" / "authorization-platform-retired.example.com.conf")
        self.assertTrue(all(item.status == "passed" for item in iqd), iqd)
        nginx = (root / "deploy" / "nginx" / "authorization-platform.conf.example").read_text(encoding="utf-8")
        self.assertIn("listen 443 ssl http2;", nginx)
        self.assertIn("location = /", nginx)
        self.assertIn("return 404;", nginx)
        self.assertNotIn("try_files /entry.html", nginx)
        self.assertNotIn("http2 on;", nginx)

    def test_frozen_preview_rejects_redeem_refresh_as_failure(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'redeemDialog?.querySelector(\'[data-success-screen="ledger"]\')?.addEventListener("click", async (event) => {',
                    "  try {",
                    '    const payload = await apiRequest("/downstream/credits/", {',
                    '      method: "POST",',
                    "      body: JSON.stringify({ card_code: input.value.trim() }),",
                    "    });",
                    "    await loadDownstreamCredits();",
                    '    redeemDialog.close("success");',
                    "  } catch (requestError) {",
                    '    if (error) error.textContent = apiErrorMessage(requestError, "额度卡兑换失败，请重试。");',
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("redeem-treats-ledger-refresh-as-redeem-failure" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'redeemDialog?.querySelector(\'[data-success-screen="ledger"]\')?.addEventListener("click", async (event) => {',
                    "  try {",
                    '    payload = await apiRequest("/downstream/credits/", { method: "POST", body: "{}" });',
                    "  } catch (requestError) {",
                    '    error.textContent = apiErrorMessage(requestError, "额度卡兑换失败，请重试。");',
                    "    return;",
                    "  }",
                    "  try {",
                    "    await loadDownstreamCredits();",
                    "  } catch (refreshError) {",
                    '    showToast("额度已兑换，账本列表请稍后重试。");',
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("redeem-treats-ledger-refresh-as-redeem-failure" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        self.assertFalse(
            any("redeem-treats-ledger-refresh-as-redeem-failure" in item for item in _static_preview_findings("preview.js", source))
        )

    def test_frozen_preview_rejects_software_code_hidden_in_advanced(self):
        hidden = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<dialog id="softwareDialog">',
                    '<details data-software-advanced><summary>高级标识与接入</summary>',
                    '<input id="softwareCode" required />',
                    "</details>",
                    "</dialog>",
                ]
            ),
        )
        self.assertTrue(any("software-code-hidden-in-advanced" in item for item in hidden))
        visible = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<dialog id="softwareDialog">',
                    '<label>软件标识<input id="softwareCode" required /></label>',
                    '<details data-software-advanced><summary>高级接入</summary>',
                    '<input id="softwareProfile" required />',
                    "</details>",
                    "</dialog>",
                ]
            ),
        )
        self.assertFalse(any("software-code-hidden-in-advanced" in item for item in visible))
        self.assertFalse(any("software-code-missing-from-dialog" in item for item in visible))
        missing = _static_preview_findings(
            "manage.html",
            '<dialog id="softwareDialog"><details data-software-advanced></details></dialog>',
        )
        self.assertTrue(any("software-code-missing-from-dialog" in item for item in missing))
        live = _static_preview_findings(
            "manage.html",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("software-code-hidden-in-advanced" in item for item in live))
        self.assertFalse(any("software-code-missing-from-dialog" in item for item in live))

    def test_frozen_preview_rejects_software_create_refresh_as_save_failure(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'softwareDialog?.querySelector("[data-software-save]")?.addEventListener("click", async (event) => {',
                    "  try {",
                    '    const payload = await apiRequest("/manage/catalog/", { method: "POST", body: "{}" });',
                    '    showSoftwareStage("result");',
                    "    await loadCatalog();",
                    '    showToast("软件、Profile、策略和首个套餐已保存到服务端目录。 ");',
                    "  } catch (requestError) {",
                    '    error.textContent = apiErrorMessage(requestError, "软件与套餐保存失败。");',
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("software-create-treats-catalog-refresh-as-save-failure" in item for item in coupled))
        self.assertTrue(any("software-create-refresh-missing-retry-copy" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'softwareDialog?.querySelector("[data-software-save]")?.addEventListener("click", async (event) => {',
                    "  try {",
                    '    payload = await apiRequest("/manage/catalog/", { method: "POST", body: "{}" });',
                    "  } catch (requestError) {",
                    '    error.textContent = apiErrorMessage(requestError, "软件与套餐保存失败。");',
                    "    return;",
                    "  }",
                    '  showSoftwareStage("result");',
                    "  try {",
                    "    await loadCatalog();",
                    "  } catch {",
                    '    showToast("软件已保存，目录列表请稍后重试。");',
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("software-create-treats-catalog-refresh-as-save-failure" in item for item in split))
        self.assertFalse(any("software-create-refresh-missing-retry-copy" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("software-create-treats-catalog-refresh-as-save-failure" in item for item in live))
        self.assertFalse(any("software-create-refresh-missing-retry-copy" in item for item in live))

    def test_frozen_preview_rejects_empty_plan_software_without_local_empty(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderPlanCatalog(items = catalogItems) {",
                    "  softwareEntries.forEach(([softwareKey, softwarePlans]) => {",
                    "    if (!softwarePlans.length) return;",
                    "  });",
                    "  if (!softwareEntries.length || !softwareEntries.some(([, values]) => values.length)) {",
                    '    empty.textContent = "当前没有可用套餐。";',
                    "  }",
                    "}",
                    "function applyPlanCatalogFilter(catalog, softwareId) {",
                    "  item.hidden = softwareId !== \"all\" && item.dataset.planSoftware !== softwareId;",
                    "}",
                    "function updateIssuePreview() {",
                    '    const selectedCost = Number.parseInt(plan.selectedOptions[0]?.dataset.cost || "0", 10);',
                    "    const canGenerate = validQuantity && total <= availableBalance;",
                    "    issueSubmit.disabled = !canGenerate;",
                    "}",
                ]
            ),
        )
        self.assertTrue(
            any("plan-catalog-hides-empty-software-without-local-empty" in item for item in coupled)
        )
        self.assertTrue(any("issue-preview-treats-missing-plan-cost-as-zero" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderPlanCatalog(items = catalogItems) {",
                    "  softwareEntries.forEach(([softwareKey, softwarePlans]) => {",
                    "    if (!softwarePlans.length) return;",
                    "  });",
                    "}",
                    "function applyPlanCatalogFilter(catalog, softwareId) {",
                    "  catalog.querySelector(\"[data-plan-catalog-empty]\")?.remove();",
                    '  empty.dataset.planCatalogEmpty = scoped ? selected : "all";',
                    '  empty.textContent = "当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。";',
                    "}",
                    "function updateIssuePreview() {",
                    "    if (!software?.value || !plan.value || !selectedOption) {",
                    '      issueError.textContent = "当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。";',
                    "      issueSubmit.disabled = true;",
                    "      return;",
                    "    }",
                    "    const selectedCost = Number.parseInt(selectedOption.dataset.cost, 10);",
                    "    const canGenerate = validQuantity && total <= availableBalance;",
                    "}",
                ]
            ),
        )
        self.assertFalse(
            any("plan-catalog-hides-empty-software-without-local-empty" in item for item in split)
        )
        self.assertFalse(any("issue-preview-treats-missing-plan-cost-as-zero" in item for item in split))
        self.assertFalse(any("plan-catalog-empty-tells-downstream-to-create-plan" in item for item in split))
        wrong_copy = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderPlanCatalog(items = catalogItems) {",
                    "  if (!softwarePlans.length) return;",
                    "}",
                    "function applyPlanCatalogFilter(catalog, softwareId) {",
                    '  empty.dataset.planCatalogEmpty = "scoped";',
                    '  empty.textContent = "先建套餐";',
                    "}",
                ]
            ),
        )
        self.assertTrue(
            any("plan-catalog-empty-tells-downstream-to-create-plan" in item for item in wrong_copy)
        )
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(
            any("plan-catalog-hides-empty-software-without-local-empty" in item for item in live)
        )
        self.assertFalse(any("issue-preview-treats-missing-plan-cost-as-zero" in item for item in live))
        self.assertFalse(any("plan-catalog-empty-tells-downstream-to-create-plan" in item for item in live))
        self.assertFalse(any("issue-empty-plan-tells-downstream-to-create-plan" in item for item in live))

    def test_frozen_preview_rejects_issue_gate_ignoring_ledger_balance(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyDownstreamLedgerBalance(account) {",
                    "  const balance = Number(account?.available_balance || 0).toLocaleString(\"zh-CN\");",
                    "  document.querySelectorAll(\"#downstreamAvailableBalance\").forEach((target) => {",
                    "    target.textContent = balance;",
                    "  });",
                    "}",
                    "function updateIssuePreview() {",
                    "    const availableBalance = Number.parseInt(issueDialog.dataset.availableBalance || \"0\", 10);",
                    "    const canGenerate = validQuantity && total <= availableBalance;",
                    "    if (licenseIssueApiAvailable && canGenerate) {",
                    "      queueLicensePreview();",
                    "    }",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("issue-gate-ignores-ledger-available-balance" in item for item in coupled))
        parsed = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function syncIssueAvailableBalance(raw) {",
                    "  issueDialog.dataset.availableBalance = document.getElementById(\"downstreamAvailableBalance\").textContent;",
                    "}",
                    "function applyDownstreamLedgerBalance(account) {",
                    "  syncIssueAvailableBalance(account.available_balance);",
                    "}",
                    "function updateIssuePreview() {",
                    "    const availableBalance = Number.parseInt(issueDialog.dataset.availableBalance || \"0\", 10);",
                    "    const canGenerate = validQuantity && total <= availableBalance;",
                    "    issueError.textContent = \"当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。\";",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("issue-gate-parses-locale-balance-text" in item for item in parsed))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function syncIssueAvailableBalance(raw) {",
                    "  const value = Number(raw);",
                    "  if (!Number.isFinite(value)) return;",
                    "  issueDialog.dataset.availableBalance = String(Math.trunc(value));",
                    "}",
                    "function applyDownstreamLedgerBalance(account) {",
                    "  const numeric = Number(account?.available_balance);",
                    "  const balance = (Number.isFinite(numeric) ? numeric : 0).toLocaleString(\"zh-CN\");",
                    "  document.querySelectorAll(\"#downstreamAvailableBalance\").forEach((target) => {",
                    "    target.textContent = balance;",
                    "  });",
                    "  syncIssueAvailableBalance(Number.isFinite(numeric) ? numeric : 0);",
                    "}",
                    "function updateIssuePreview() {",
                    "    if (!software?.value || !plan.value || !selectedOption) {",
                    "      issueError.textContent = \"当前软件暂时没有可发卡的套餐，请联系管理员或换一个软件。\";",
                    "      issueSubmit.disabled = true;",
                    "      return;",
                    "    }",
                    "    const availableBalance = Number.parseInt(issueDialog.dataset.availableBalance || \"0\", 10);",
                    "    const canGenerate = validQuantity && total <= availableBalance;",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("issue-gate-ignores-ledger-available-balance" in item for item in split))
        self.assertFalse(any("issue-gate-parses-locale-balance-text" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("issue-gate-ignores-ledger-available-balance" in item for item in live))
        self.assertFalse(any("issue-gate-parses-locale-balance-text" in item for item in live))

    def test_frozen_preview_rejects_release_withdraw_upload_and_filename_heuristics(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function bindDialogTriggers(root = document) {",
                    '  if (dialog === releaseDialog) showReleaseStage("upload", 0);',
                    "}",
                    'releaseNext?.addEventListener("click", async () => {',
                    "  const form = new FormData();",
                    '  form.append("software_id", software?.value || "");',
                    "});",
                    'document.querySelector("[data-withdraw-confirm]")?.addEventListener("click", async (event) => {',
                    "  event.currentTarget.disabled = true;",
                    "  try {",
                    '    await apiRequest("/manage/releases/x/withdraw/", { method: "POST" });',
                    '    dialog?.close("success");',
                    "  } catch (requestError) {",
                    "    event.currentTarget.disabled = false;",
                    "  }",
                    "});",
                    "function packageValidationError(file) {",
                    '  if (name.includes("hash-fail")) return "SHA-256 复算结果与 Manifest 不一致。";',
                    '  if (name.includes("manifest-mismatch")) return "Manifest 中的软件、Profile 或平台与所选范围不一致。";',
                    "  return \"\";",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("withdraw-confirm-stays-disabled-after-success" in item for item in coupled))
        self.assertTrue(any("release-dialog-open-does-not-copy-table-software" in item for item in coupled))
        self.assertTrue(any("release-upload-posts-dialog-software" in item for item in coupled))
        self.assertTrue(any("release-package-validates-by-filename" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function bindDialogTriggers(root = document) {",
                    "  if (dialog === releaseDialog) {",
                    "    syncReleaseUploadSoftwareFromTable();",
                    '    showReleaseStage("upload", 0);',
                    "  }",
                    "}",
                    'releaseNext?.addEventListener("click", async () => {',
                    "  const form = new FormData();",
                    '  form.append("software_id", releaseUploadSoftwareId());',
                    "});",
                    "function resetWithdrawConfirm() {",
                    "  confirm.disabled = false;",
                    "}",
                    'document.getElementById("withdrawReleaseDialog")?.addEventListener("close", () => {',
                    "  resetWithdrawConfirm();",
                    "});",
                    'document.querySelector("[data-withdraw-confirm]")?.addEventListener("click", async (event) => {',
                    "  event.currentTarget.disabled = true;",
                    "  try {",
                    '    await apiRequest("/manage/releases/x/withdraw/", { method: "POST" });',
                    '    dialog?.close("success");',
                    "  } catch (requestError) {",
                    "    if (error) error.textContent = \"版本撤回失败，请重试。\";",
                    "  } finally {",
                    "    resetWithdrawConfirm();",
                    "  }",
                    "});",
                    "function packageValidationError(file) {",
                    '  if (!name.endsWith(".zip")) return "文件类型不允许：只接受 ZIP 构建包。";',
                    "  return \"\";",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("withdraw-confirm-stays-disabled-after-success" in item for item in split))
        self.assertFalse(any("release-dialog-open-does-not-copy-table-software" in item for item in split))
        self.assertFalse(any("release-upload-posts-dialog-software" in item for item in split))
        self.assertFalse(any("release-package-validates-by-filename" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("withdraw-confirm-stays-disabled-after-success" in item for item in live))
        self.assertFalse(any("release-dialog-open-does-not-copy-table-software" in item for item in live))
        self.assertFalse(any("release-upload-posts-dialog-software" in item for item in live))
        self.assertFalse(any("release-package-validates-by-filename" in item for item in live))

    def test_frozen_preview_rejects_release_card_published_failure_as_empty(self):
        scaffolding = [
            "async function fetchAllCollectionPages(){}",
            "options.pageSize || 100",
            "options.maxPages || 20",
            "async function loadCatalog() { await fetchAllCollectionPages('/manage/catalog/'); }",
            "async function loadDownstreams() { await fetchAllCollectionPages('/manage/downstreams/'); }",
            "extraQuery: { status }",
            "async function loadPublishedReleases(softwareId) { if (!payload.pagination?.has_next) return []; }",
            "function fillReleaseSignatureStatus(item) {}",
            "async function loadReleasesForSoftware(softwareId, page = releasePage) { ++releaseListRequestGeneration; if (generation !== releaseListRequestGeneration) return; }",
            "function catalogSoftwareForRelease(softwareId) { return null; }",
            "function currentReclaimFilters(panel) { return { recordScope: 'licenses', status: 'unused' }; }",
            "function currentFilteredReclaimRows(panel) { return []; }",
        ]
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                scaffolding[:7]
                + [
                    "async function applyReleaseContext(softwareId) {",
                    '  if (softwareId === "all") { currentTarget.textContent = "请选择软件"; return; }',
                    "  let current = null;",
                    "  try { current = highestPublishedRelease(await loadPublishedReleases(softwareId)); }",
                    "  catch (_requestError) { current = null; }",
                    '  statusTarget.textContent = current ? "分发中" : "暂无发布";',
                    "}",
                ]
                + scaffolding[7:]
            ),
        )
        self.assertTrue(any("release-card-paints-published-failure-as-empty" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                scaffolding[:7]
                + [
                    "async function applyReleaseContext(softwareId) {",
                    '  if (softwareId === "all") { currentTarget.textContent = "请选择软件"; return; }',
                    "  try {",
                    "    const current = highestPublishedRelease(await loadPublishedReleases(softwareId));",
                    '    statusTarget.textContent = current ? "分发中" : "暂无发布";',
                    "  } catch (_requestError) {",
                    '    currentTarget.textContent = "暂时无法读取";',
                    '    statusTarget.textContent = "读取失败";',
                    "  }",
                    "}",
                ]
                + scaffolding[7:]
            ),
        )
        self.assertFalse(any("release-card-paints-published-failure-as-empty" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("release-card-paints-published-failure-as-empty" in item for item in live))

    def test_frozen_preview_rejects_release_card_stale_software(self):
        scaffolding = [
            "async function fetchAllCollectionPages(){}",
            "options.pageSize || 100",
            "options.maxPages || 20",
            "async function loadCatalog() { await fetchAllCollectionPages('/manage/catalog/'); }",
            "async function loadDownstreams() { await fetchAllCollectionPages('/manage/downstreams/'); }",
            "extraQuery: { status }",
            "async function loadPublishedReleases(softwareId) { if (!payload.pagination?.has_next) return []; }",
            "function fillReleaseSignatureStatus(item) {}",
            "async function loadReleasesForSoftware(softwareId, page = releasePage) { ++releaseListRequestGeneration; if (generation !== releaseListRequestGeneration) return; }",
            "function catalogSoftwareForRelease(softwareId) { return null; }",
            "function currentReclaimFilters(panel) { return { recordScope: 'licenses', status: 'unused' }; }",
            "function currentFilteredReclaimRows(panel) { return []; }",
        ]
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                scaffolding[:7]
                + [
                    "async function applyReleaseContext(softwareId) {",
                    '  if (softwareId === "all") { currentTarget.textContent = "请选择软件"; return; }',
                    "  try {",
                    "    const current = highestPublishedRelease(await loadPublishedReleases(softwareId));",
                    '    statusTarget.textContent = current ? "分发中" : "暂无发布";',
                    "  } catch (_requestError) {",
                    '    currentTarget.textContent = "暂时无法读取";',
                    '    statusTarget.textContent = "读取失败";',
                    "  }",
                    "}",
                ]
                + scaffolding[7:]
            ),
        )
        self.assertTrue(any("release-card-applies-stale-software" in item for item in coupled))
        self.assertTrue(any("release-card-missing-generation" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                scaffolding[:7]
                + [
                    "async function applyReleaseContext(softwareId) {",
                    "  const generation = ++releaseContextRequestGeneration;",
                    '  if (softwareId === "all") { currentTarget.textContent = "请选择软件"; return; }',
                    "  try {",
                    "    const current = highestPublishedRelease(await loadPublishedReleases(softwareId));",
                    "    if (generation !== releaseContextRequestGeneration) return;",
                    '    if ((releaseContext?.value || "all") !== softwareId) return;',
                    '    statusTarget.textContent = current ? "分发中" : "暂无发布";',
                    "  } catch (_requestError) {",
                    "    if (generation !== releaseContextRequestGeneration) return;",
                    '    currentTarget.textContent = "暂时无法读取";',
                    '    statusTarget.textContent = "读取失败";',
                    "  }",
                    "}",
                ]
                + scaffolding[7:]
            ),
        )
        self.assertFalse(any("release-card-applies-stale-software" in item for item in split))
        self.assertFalse(any("release-card-missing-generation" in item for item in split))
        self.assertFalse(any("release-card-paints-published-failure-as-empty" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("release-card-applies-stale-software" in item for item in live))
        self.assertFalse(any("release-card-missing-generation" in item for item in live))

    def test_frozen_preview_rejects_ux_copy_dialog_focus_and_empty_state_gaps(self):
        old_css = _static_preview_findings(
            "preview.css",
            "\n".join(
                [
                    ".page-heading p,",
                    ".screen .overline,",
                    ".section-copy,",
                    ".modal-copy {",
                    "  display: none;",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("heading-hides-contract-form-hint" in item for item in old_css))
        old_html = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<label class="form-label">',
                    "          >操作原因<textarea name=\"reason\"></textarea></label>",
                    "              >断网宽限（小时）<input /></label>",
                    "            ><label class=\"form-label\">卡种名称</label>",
                ]
            ),
        )
        self.assertTrue(any("reclaim-reason-label-has-stray-gt" in item for item in old_html))
        self.assertTrue(any("software-form-stray-gt-between-labels" in item for item in old_html))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function bindDialogChrome(dialog) {",
                    "  dialog.addEventListener('cancel', (event) => {});",
                    "}",
                    'const redeemDialog = document.getElementById("redeemDialog");',
                    "function activateScreen(name, options = {}) {",
                    '  const panel = document.querySelector(`[data-screen-panel="${name}"]`);',
                    "  return true;",
                    "}",
                    'document.querySelector("[data-release-check]")?.addEventListener("click", async (event) => {',
                    "  event.currentTarget.disabled = true;",
                    "  try {",
                    "    await recheckPublicReleaseRegistry(releaseContext?.value || '');",
                    "  } finally {",
                    "    event.currentTarget.disabled = false;",
                    "    event.currentTarget.textContent = '↻ 重新检查';",
                    "  }",
                    "});",
                    "function ensureTableState(table) {",
                    '  empty.textContent = "当前条件没有匹配的记录。";',
                    "}",
                    "function updateIssuePreview() {",
                    '  issueError.textContent = "请选择软件和套餐后再生成。";',
                    "}",
                    "function applyPlanCatalogFilter(catalog, softwareId) {",
                    '  empty.textContent = "当前没有可用套餐。";',
                    "}",
                    "async function fetchAllCollectionPages(){}",
                    "options.pageSize || 100",
                    "options.maxPages || 20",
                    "async function loadCatalog() { await fetchAllCollectionPages('/manage/catalog/'); }",
                    "async function loadDownstreams() { await fetchAllCollectionPages('/manage/downstreams/'); }",
                    "extraQuery: { status }",
                    "async function loadPublishedReleases(softwareId) { if (!payload.pagination?.has_next) return []; }",
                    "async function applyReleaseContext(softwareId) {",
                    '  if (softwareId === "all") { currentTarget.textContent = "请选择软件"; return; }',
                    "  const generation = ++releaseContextRequestGeneration;",
                    "  const contextIsCurrent = () => generation === releaseContextRequestGeneration && (releaseContext?.value || 'all') === (softwareId || 'all');",
                    "  try {",
                    "    const current = highestPublishedRelease(await loadPublishedReleases(softwareId));",
                    '    statusTarget.textContent = current ? "分发中" : "暂无发布";',
                    "  } catch (_requestError) {",
                    '    statusTarget.textContent = "读取失败";',
                    "  }",
                    "}",
                    "function fillReleaseSignatureStatus(item) {}",
                    "async function loadReleasesForSoftware(softwareId, page = releasePage) { ++releaseListRequestGeneration; if (generation !== releaseListRequestGeneration) return; }",
                    "function catalogSoftwareForRelease(softwareId) { return null; }",
                    "function currentReclaimFilters(panel) { return { recordScope: 'scope', status: 'unused' }; }",
                    "function currentFilteredReclaimRows(panel) { return []; }",
                ]
            ),
        )
        self.assertTrue(any("dialog-open-leaves-focus-on-close" in item for item in old_js))
        self.assertTrue(any("redeem-dialog-keeps-last-error" in item for item in old_js))
        self.assertTrue(any("activate-screen-leaves-open-dialogs" in item for item in old_js))
        self.assertTrue(any("release-check-missing-button-capture" in item for item in old_js))
        self.assertTrue(any("release-check-finally-uses-currenttarget" in item for item in old_js))
        self.assertTrue(any("table-empty-always-says-filter-mismatch" in item for item in old_js))
        self.assertTrue(any("issue-empty-software-asks-to-select" in item for item in old_js))
        self.assertTrue(any("plan-catalog-all-empty-omits-admin-open" in item for item in old_js))
        self.assertTrue(any("release-card-missing-update-copy" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in ("preview.css", "preview.js", "manage.html", "404.html"):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "heading-hides-contract-form-hint",
            "reclaim-reason-label-has-stray-gt",
            "software-form-stray-gt-between-labels",
            "dialog-open-leaves-focus-on-close",
            "redeem-dialog-keeps-last-error",
            "activate-screen-leaves-open-dialogs",
            "release-check-missing-button-capture",
            "release-check-finally-uses-currenttarget",
            "table-empty-always-says-filter-mismatch",
            "issue-empty-software-asks-to-select",
            "plan-catalog-all-empty-omits-admin-open",
            "release-card-missing-update-copy",
            "root-404-missing-preview-css",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live), live)

    def test_frozen_preview_rejects_stale_downstream_support_write(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadDownstreamSupport(softwareId) {",
                    "  const payload = await apiRequest(`/downstream/support/${softwareId}/`);",
                    '  document.querySelector("[data-support-purchase]").value = support.purchase_url;',
                    "}",
                    'document.querySelector("[data-support-save]")?.addEventListener("click", async (event) => {',
                    "  const select = document.querySelector(\"[data-support-context]\");",
                    "  const softwareId = select?.value || \"\";",
                    "  await apiRequest(`/downstream/support/${encodeURIComponent(softwareId)}/`, { method: \"POST\" });",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("support-load-applies-stale-software" in item for item in coupled))
        self.assertTrue(any("support-save-posts-live-select" in item for item in coupled))
        split = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadDownstreamSupport(softwareId) {",
                    "  const generation = ++supportLoadGeneration;",
                    "  const payload = await apiRequest(`/downstream/support/${softwareId}/`);",
                    "  if (generation !== supportLoadGeneration) return;",
                    '  document.querySelector("[data-support-purchase]").value = support.purchase_url;',
                    "  supportLoadedSoftwareId = softwareId;",
                    "}",
                    'document.querySelector("[data-support-save]")?.addEventListener("click", async (event) => {',
                    "  const selectedId = select?.value || \"\";",
                    "  if (supportLoadPending || supportLoadedSoftwareId !== selectedId) return;",
                    "  const softwareId = supportLoadedSoftwareId;",
                    "  await apiRequest(`/downstream/support/${encodeURIComponent(softwareId)}/`, { method: \"POST\" });",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("support-load-applies-stale-software" in item for item in split))
        self.assertFalse(any("support-save-posts-live-select" in item for item in split))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("support-load-applies-stale-software" in item for item in live))
        self.assertFalse(any("support-save-posts-live-select" in item for item in live))

    def test_frozen_preview_rejects_support_contact_merge_and_wechat_label(self):
        merged = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadDownstreamSupport(softwareId) {",
                    "  const generation = ++supportLoadGeneration;",
                    "  const payload = await apiRequest(`/downstream/support/${softwareId}/`);",
                    "  if (generation !== supportLoadGeneration) return;",
                    "  contact.value = support.wechat || support.qq || \"\";",
                    "  supportLoadedSoftwareId = softwareId;",
                    "}",
                    'document.querySelector("[data-support-save]")?.addEventListener("click", async (event) => {',
                    "  await apiRequest(`/downstream/support/${encodeURIComponent(softwareId)}/`, {",
                    "    body: JSON.stringify({ values: { purchase_url: purchase, wechat: contact, qq: \"\" } }),",
                    "  });",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("support-load-merges-contact-candidates" in item for item in merged))
        self.assertTrue(any("support-save-locks-contact-to-wechat" in item for item in merged))
        wechat_html = _static_preview_findings(
            "downstream.html",
            '<label class="form-label">微信号<input type="url" data-support-contact value="" /></label>',
        )
        self.assertTrue(any("support-contact-labeled-wechat-only" in item for item in wechat_html))
        self.assertTrue(any("support-contact-is-url-input" in item for item in wechat_html))
        self.assertTrue(any("support-contact-missing-free-text-label" in item for item in wechat_html))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        live_html = _static_preview_findings(
            "downstream.html",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "downstream.html").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("support-load-merges-contact-candidates" in item for item in live_js))
        self.assertFalse(any("support-save-locks-contact-to-wechat" in item for item in live_js))
        self.assertFalse(any("support-contact-labeled-wechat-only" in item for item in live_html))
        self.assertFalse(any("support-contact-is-url-input" in item for item in live_html))
        self.assertFalse(any("support-contact-missing-free-text-label" in item for item in live_html))

    def test_frozen_preview_rejects_exact_search_export_and_filter_drift(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelectorAll("[data-export]").forEach((button) => {',
                    "  button.addEventListener(\"click\", async () => {",
                    '    if (button.dataset.exportQuery === "quota-cards") {',
                    "      const params = new URLSearchParams(quotaCardFilterQuery(panel));",
                    '    } else if (button.dataset.exportQuery === "licenses") {',
                    "      const params = new URLSearchParams(licenseCardFilterQuery(panel));",
                    "    }",
                    "    await window.fetch(url);",
                    "  });",
                    "});",
                    "async function searchAdminCredential(input, options) {",
                    "  render(payload.item ? [payload.item] : []);",
                    "  showToast(successMessage);",
                    "}",
                    "function bindAdminCredentialSearch(selector, handler) {}",
                    "function applyCredentialFilters(group, options = {}) {",
                    "  loadLicenseCards(1);",
                    "  loadAdminCredits(1);",
                    "}",
                    "function currentReclaimFilters(panel) { return {}; }",
                    'filteredButton.dataset.reclaimFiltered = "";',
                    'filteredButton.addEventListener("click", async () => {',
                    "  const search = panel.querySelector(\"[data-sensitive-search]\");",
                    "  if (search?.value.trim()) {",
                    '    showToast("请先清空完整码精确搜索，再使用当前筛选全量回收。");',
                    "    return;",
                    "  }",
                    "  const dialog = document.getElementById(selectedButton.dataset.reclaimSelectionDialog);",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("license-export-ignores-exact-search" in item for item in coupled))
        self.assertTrue(any("quota-export-ignores-exact-search" in item for item in coupled))
        self.assertTrue(any("quota-search-keeps-pagination" in item for item in coupled))
        self.assertTrue(any("invitation-search-keeps-pagination" in item for item in coupled))
        self.assertTrue(any("credential-filter-reloads-during-exact-search" in item for item in coupled))
        self.assertTrue(any("filtered-reclaim-checks-input-only" in item for item in coupled))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        findings = _static_preview_findings("preview.js", source)
        self.assertFalse(any("license-export-ignores-exact-search" in item for item in findings))
        self.assertFalse(any("quota-export-ignores-exact-search" in item for item in findings))
        self.assertFalse(any("quota-search-keeps-pagination" in item for item in findings))
        self.assertFalse(any("invitation-search-keeps-pagination" in item for item in findings))
        self.assertFalse(any("credential-filter-reloads-during-exact-search" in item for item in findings))
        self.assertFalse(any("filtered-reclaim-checks-input-only" in item for item in findings))

    def test_frozen_preview_rejects_quota_revoke_partial_success(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-quota-revoke-confirm]")?.addEventListener("click", async (event) => {',
                    "  try {",
                    "    for (const publicId of ids) {",
                    "      await apiRequest(`/manage/credits/cards/${encodeURIComponent(publicId)}/revoke/`, {",
                    '        method: "POST",',
                    "        headers: { \"Idempotency-Key\": requestIdempotencyKey(`quota-revoke-${publicId}`) },",
                    "        body: JSON.stringify({ reason }),",
                    "      });",
                    "    }",
                    '    dialog.close("success");',
                    "    showToast(`已作废 ${ids.length} 枚未兑换额度码，不能再被兑换。`);",
                    "    await loadAdminCredits();",
                    "  } catch (requestError) {",
                    '    if (error) error.textContent = apiErrorMessage(requestError, "作废失败，未兑换码状态未全部改变。");',
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("quota-revoke-stops-on-first-failure" in item for item in coupled))
        self.assertTrue(any("quota-revoke-toasts-selection-count" in item for item in coupled))
        self.assertTrue(any("quota-revoke-hides-partial-results" in item for item in coupled))
        self.assertTrue(any("quota-revoke-treats-refresh-as-revoke-failure" in item for item in coupled))
        continued = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-quota-revoke-confirm]")?.addEventListener("click", async (event) => {',
                    "  const succeeded = [];",
                    "  const failed = [];",
                    "  for (const publicId of ids) {",
                    "    try {",
                    "      await apiRequest(`/manage/credits/cards/${encodeURIComponent(publicId)}/revoke/`, {",
                    '        method: "POST",',
                    "        body: JSON.stringify({ reason }),",
                    "      });",
                    "      succeeded.push(publicId);",
                    "    } catch (requestError) {",
                    "      failed.push(publicId);",
                    "    }",
                    "  }",
                    "  if (!failed.length) {",
                    "    showToast(`已作废 ${succeeded.length} 枚未兑换额度码，不能再被兑换。`);",
                    "  } else {",
                    "    showToast(`已作废 ${succeeded.length} 枚，${failed.length} 枚未成功。失败的码仍留在列表。`);",
                    "  }",
                    "  try {",
                    "    await loadAdminCredits();",
                    "  } catch (refreshError) {",
                    "    showToast(`已作废 ${succeeded.length} 枚未兑换额度码，列表请稍后刷新。`);",
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("quota-revoke-stops-on-first-failure" in item for item in continued))
        self.assertFalse(any("quota-revoke-toasts-selection-count" in item for item in continued))
        self.assertFalse(any("quota-revoke-hides-partial-results" in item for item in continued))
        self.assertFalse(any("quota-revoke-treats-refresh-as-revoke-failure" in item for item in continued))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("quota-revoke-stops-on-first-failure" in item for item in live))
        self.assertFalse(any("quota-revoke-toasts-selection-count" in item for item in live))
        self.assertFalse(any("quota-revoke-hides-partial-results" in item for item in live))
        self.assertFalse(any("quota-revoke-treats-refresh-as-revoke-failure" in item for item in live))

    def test_frozen_preview_rejects_ledger_dual_pagination_and_stale_page(self):
        html_bad = (
            '<section class="panel table-panel">'
            '<span data-admin-ledger-pagination></span>'
            "</section>"
        )
        self.assertTrue(
            any(
                "ledger-table-not-server-paginated" in item
                for item in _static_preview_findings("manage.html", html_bad)
            )
        )
        html_good = (
            '<section class="panel table-panel" data-server-paginated="true">'
            '<span data-admin-ledger-pagination></span>'
            "</section>"
        )
        self.assertFalse(
            any(
                "ledger-table-not-server-paginated" in item
                for item in _static_preview_findings("manage.html", html_good)
            )
        )
        downstream_bad = (
            '<section class="panel table-panel">'
            '<span data-downstream-ledger-pagination></span>'
            "</section>"
        )
        self.assertTrue(
            any(
                "ledger-table-not-server-paginated" in item
                for item in _static_preview_findings("downstream.html", downstream_bad)
            )
        )
        js_bad = "\n".join(
            [
                "function ensureTableState(table) {",
                '  panel.querySelector("[data-risk-server-pagination], [data-quota-card-server-pagination]");',
                "}",
                'redeemDialog?.querySelector(\'[data-success-screen="ledger"]\')?.addEventListener("click", async (event) => {',
                "  try {",
                '    payload = await apiRequest("/downstream/credits/", { method: "POST", body: "{}" });',
                "  } catch (requestError) {",
                "    return;",
                "  }",
                "  try {",
                "    await loadDownstreamCredits();",
                "  } catch (refreshError) {}",
                "});",
            ]
        )
        bad_findings = _static_preview_findings("preview.js", js_bad)
        self.assertTrue(any("ledger-missing-from-server-pagination-selectors" in item for item in bad_findings))
        self.assertTrue(any("redeem-keeps-current-ledger-page" in item for item in bad_findings))
        js_good = "\n".join(
            [
                "function ensureTableState(table) {",
                '  panel.querySelector("[data-admin-ledger-pagination], [data-downstream-ledger-pagination]");',
                "}",
                'redeemDialog?.querySelector(\'[data-success-screen="ledger"]\')?.addEventListener("click", async (event) => {',
                "  try {",
                '    payload = await apiRequest("/downstream/credits/", { method: "POST", body: "{}" });',
                "  } catch (requestError) {",
                "    return;",
                "  }",
                "  try {",
                "    await loadDownstreamCredits(1);",
                "  } catch (refreshError) {}",
                "});",
            ]
        )
        good_findings = _static_preview_findings("preview.js", js_good)
        self.assertFalse(any("ledger-missing-from-server-pagination-selectors" in item for item in good_findings))
        self.assertFalse(any("redeem-keeps-current-ledger-page" in item for item in good_findings))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("ledger-missing-from-server-pagination-selectors" in item for item in live))
        self.assertFalse(any("redeem-keeps-current-ledger-page" in item for item in live))
        manage = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(encoding="utf-8")
        downstream = (
            Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "downstream.html"
        ).read_text(encoding="utf-8")
        self.assertFalse(
            any("ledger-table-not-server-paginated" in item for item in _static_preview_findings("manage.html", manage))
        )
        self.assertFalse(
            any(
                "ledger-table-not-server-paginated" in item
                for item in _static_preview_findings("downstream.html", downstream)
            )
        )

    def test_frozen_preview_rejects_ledger_render_without_server_data_loaded(self):
        js_bad = "\n".join(
            [
                "function renderAdminCreditLedger(entries, accounts) {",
                '  const body = document.querySelector(\'[data-screen-panel="credits"] [data-work-panel="ledger"] tbody\');',
                "  body.replaceChildren();",
                "  window.__previewRefreshTables?.();",
                "}",
                "function renderDownstreamCreditLedger(entries) {",
                '  const body = document.querySelector(\'[data-screen-panel="ledger"] tbody\');',
                "  body.replaceChildren();",
                "  window.__previewRefreshTables?.();",
                "}",
            ]
        )
        bad_findings = _static_preview_findings("preview.js", js_bad)
        self.assertTrue(any("admin-ledger-render-missing-server-data-loaded" in item for item in bad_findings))
        self.assertTrue(
            any("downstream-ledger-render-missing-server-data-loaded" in item for item in bad_findings)
        )
        js_loaded_after_refresh = "\n".join(
            [
                "function renderAdminCreditLedger(entries, accounts) {",
                "  const panel = body.closest('.table-panel');",
                "  window.__previewRefreshTables?.();",
                '  panel.dataset.serverDataLoaded = "true";',
                "}",
            ]
        )
        after_findings = _static_preview_findings("preview.js", js_loaded_after_refresh)
        self.assertTrue(any("admin-ledger-render-missing-server-data-loaded" in item for item in after_findings))
        js_good = "\n".join(
            [
                "function renderAdminCreditLedger(entries, accounts) {",
                "  const panel = body.closest('.table-panel');",
                '  if (panel) panel.dataset.serverDataLoaded = "true";',
                "  window.__previewRefreshTables?.();",
                "}",
                "function renderDownstreamCreditLedger(entries) {",
                "  const panel = body.closest('.table-panel');",
                '  if (panel) panel.dataset.serverDataLoaded = "true";',
                "  window.__previewRefreshTables?.();",
                "}",
            ]
        )
        good_findings = _static_preview_findings("preview.js", js_good)
        self.assertFalse(any("admin-ledger-render-missing-server-data-loaded" in item for item in good_findings))
        self.assertFalse(
            any("downstream-ledger-render-missing-server-data-loaded" in item for item in good_findings)
        )
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("admin-ledger-render-missing-server-data-loaded" in item for item in live))
        self.assertFalse(any("downstream-ledger-render-missing-server-data-loaded" in item for item in live))

    def test_frozen_preview_rejects_revoked_quota_fifth_column_redeemable(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderQuotaCardRows(items, { serverSearch = false } = {}) {",
                    "  appendTextCell(",
                    "    row,",
                    "    item.redeemed_by",
                    "      ? `${item.redeemed_by} · ${formatApiDate(item.redeemed_at)}`",
                    '      : "任何活跃下游可兑换 · 永久有效",',
                    "  );",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("quota-revoked-fifth-column-says-redeemable" in item for item in coupled))
        guarded = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderQuotaCardRows(items, { serverSearch = false } = {}) {",
                    "  appendTextCell(",
                    "    row,",
                    "    item.redeemed_by",
                    "      ? `${item.redeemed_by} · ${formatApiDate(item.redeemed_at)}`",
                    '      : item.status === "issued"',
                    '        ? "任何活跃下游可兑换 · 永久有效"',
                    '        : "尚未兑换",',
                    "  );",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("quota-revoked-fifth-column-says-redeemable" in item for item in guarded))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("quota-revoked-fifth-column-says-redeemable" in item for item in live))

    def test_frozen_preview_rejects_fake_issue_notes_and_invitation_unused_used_time(self):
        notes = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<label class="form-label">生成数量<input id="inviteQuantity" type="number" /></label>',
                    '<label class="form-label">备注<input id="inviteNote" type="text" placeholder="可选备注" /></label>',
                    '<label class="form-label">备注<input id="quotaCardNote" type="text" placeholder="可选备注" /></label>',
                ]
            ),
        )
        self.assertTrue(any("invite-issue-fake-note-field" in item for item in notes))
        self.assertTrue(any("quota-issue-fake-note-field" in item for item in notes))
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderInvitationRows(items, { serverSearch = false } = {}) {",
                    '  row.dataset.codeExpires = item.status === "issued" ? "永久有效" : "已结束";',
                    '  appendTextCell(row, item.consumed_at ? formatApiDate(item.consumed_at) : item.expires_at ? formatApiDate(item.expires_at) : "永久有效", "mono");',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("invitation-unused-used-time-says-permanent" in item for item in coupled))
        guarded = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderInvitationRows(items, { serverSearch = false } = {}) {",
                    '  row.dataset.codeExpires = item.status === "issued" ? "永久有效" : "已结束";',
                    '  appendTextCell(row, item.consumed_at ? formatApiDate(item.consumed_at) : "尚未使用", "mono");',
                    "}",
                ]
            ),
        )
        self.assertFalse(any("invitation-unused-used-time-says-permanent" in item for item in guarded))
        self.assertFalse(any("quota-revoked-fifth-column-says-redeemable" in item for item in coupled))
        self.assertFalse(any("quota-revoked-fifth-column-says-redeemable" in item for item in guarded))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        self.assertFalse(any("invitation-unused-used-time-says-permanent" in item for item in live_js))
        self.assertFalse(any("invite-issue-fake-note-field" in item for item in live_manage))
        self.assertFalse(any("quota-issue-fake-note-field" in item for item in live_manage))
        self.assertFalse(any("quota-revoked-fifth-column-says-redeemable" in item for item in live_js))

    def test_frozen_preview_rejects_invitation_issue_new_key_on_retry(self):
        minted = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function installInvitationIssue(loadData) {",
                    "  button?.addEventListener('click', async () => {",
                    '    await apiRequest("/manage/invitations/", {',
                    '      method: "POST",',
                    '      headers: { "Idempotency-Key": requestIdempotencyKey("invitation-issue") },',
                    "    });",
                    "  });",
                    "}",
                    "function next() {}",
                ]
            ),
        )
        self.assertTrue(any("invitation-issue-mints-new-idempotency-key" in item for item in minted))
        self.assertTrue(any("invitation-issue-missing-pinned-idempotency-key" in item for item in minted))
        pinned = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function installInvitationIssue(loadData) {",
                    "  button?.addEventListener('click', async () => {",
                    '    await apiRequest("/manage/invitations/", {',
                    '      method: "POST",',
                    '      headers: { "Idempotency-Key": inviteDialog.dataset.inviteKey || (inviteDialog.dataset.inviteKey = requestIdempotencyKey("invitation-issue")) },',
                    "    });",
                    '    inviteDialog.dataset.inviteKey = "";',
                    "  });",
                    "}",
                    "function next() {}",
                ]
            ),
        )
        self.assertFalse(any("invitation-issue-mints-new-idempotency-key" in item for item in pinned))
        self.assertFalse(any("invitation-issue-missing-pinned-idempotency-key" in item for item in pinned))
        self.assertFalse(any("invitation-issue-keeps-key-after-success" in item for item in pinned))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("invitation-issue-mints-new-idempotency-key" in item for item in live))
        self.assertFalse(any("invitation-issue-missing-pinned-idempotency-key" in item for item in live))
        self.assertFalse(any("invitation-issue-keeps-key-after-success" in item for item in live))

    def test_frozen_preview_rejects_credit_adjust_new_key_on_retry(self):
        minted = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-credit-adjust-confirm]")?.addEventListener("click", async (event) => {',
                    '  await apiRequest("/manage/credits/adjust/", {',
                    '    method: "POST",',
                    '    headers: { "Idempotency-Key": requestIdempotencyKey("credit-adjust") },',
                    "  });",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("credit-adjust-mints-new-idempotency-key" in item for item in minted))
        self.assertTrue(any("credit-adjust-missing-pinned-idempotency-key" in item for item in minted))
        self.assertTrue(any("credit-adjust-retry-copy-omits-already-posted" in item for item in minted))
        pinned = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-credit-adjust-confirm]")?.addEventListener("click", async (event) => {',
                    '  await apiRequest("/manage/credits/adjust/", {',
                    "    method: \"POST\",",
                    '    headers: { "Idempotency-Key": dialog.dataset.adjustKey || (dialog.dataset.adjustKey = requestIdempotencyKey("credit-adjust")) },',
                    "  });",
                    '  dialog.dataset.adjustKey = "";',
                    '  if (!(requestError instanceof ApiRequestError && requestError.status)) {',
                    '    error.textContent = "可能已经入账，请先看额度流水确认，不要换数字再点。";',
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("credit-adjust-mints-new-idempotency-key" in item for item in pinned))
        self.assertFalse(any("credit-adjust-missing-pinned-idempotency-key" in item for item in pinned))
        self.assertFalse(any("credit-adjust-keeps-key-after-success" in item for item in pinned))
        self.assertFalse(any("credit-adjust-retry-copy-omits-already-posted" in item for item in pinned))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("credit-adjust-mints-new-idempotency-key" in item for item in live))
        self.assertFalse(any("credit-adjust-missing-pinned-idempotency-key" in item for item in live))
        self.assertFalse(any("credit-adjust-keeps-key-after-success" in item for item in live))
        self.assertFalse(any("credit-adjust-retry-copy-omits-already-posted" in item for item in live))

    def test_frozen_preview_rejects_dialog_enter_cancel(self):
        cancel = _static_preview_findings(
            "manage.html",
            '<form method="dialog"><button class="modal-close" value="cancel">x</button></form>',
        )
        self.assertTrue(any("dialog-cancel-is-default-submit" in item for item in cancel))
        editor = _static_preview_findings(
            "preview.js",
            'function openPlanEditor(button) { if (planManagerDialog?.open) planManagerDialog.close("edit"); }',
        )
        self.assertTrue(any("plan-editor-closes-manager" in item for item in editor))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        downstream = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        preview = (root / "preview.js").read_text(encoding="utf-8")
        self.assertFalse(any("dialog-cancel-is-default-submit" in item for item in manage + downstream))
        self.assertNotIn('planManagerDialog.close("edit")', preview)

    def test_frozen_preview_rejects_password_change_catch_claims_unchanged(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const changeButton = changeDialog?.querySelector("[data-password-change-submit]");',
                    'changeButton.addEventListener("click", async () => {',
                    '  const result = await apiRequest("/auth/password/change/", { method: "POST" });',
                    '  if (error) error.textContent = apiErrorMessage(requestError, "密码修改失败，账号状态未改变。 ");',
                    "});",
                ]
            ),
        )
        self.assertTrue(any("password-change-catch-claims-unchanged" in item for item in coupled))
        guarded = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const changeButton = changeDialog?.querySelector("[data-password-change-submit]");',
                    'changeButton.addEventListener("click", async () => {',
                    '  const result = await apiRequest("/auth/password/change/", { method: "POST" });',
                    '  if (error) error.textContent = apiErrorMessage(requestError, "请求没有完成，请稍后重试。");',
                    "});",
                ]
            ),
        )
        self.assertFalse(any("password-change-catch-claims-unchanged" in item for item in guarded))
        reset_only = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const resetButton = resetDialog?.querySelector("[data-password-reset-submit]");',
                    'resetButton.addEventListener("click", async () => {',
                    '  if (error) error.textContent = apiErrorMessage(requestError, "密码重置失败，账号状态未改变。");',
                    "});",
                ]
            ),
        )
        self.assertFalse(any("password-change-catch-claims-unchanged" in item for item in reset_only))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("password-change-catch-claims-unchanged" in item for item in live))

    def test_frozen_preview_rejects_register_logout_guard_misses_sibling_button(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function offerRegistrationLogout(form, session) {",
                    '  if (!form || form.querySelector("[data-register-session-action]")) return;',
                    "  const button = document.createElement(\"button\");",
                    "  form.after(button);",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("register-logout-guard-misses-sibling-button" in item for item in coupled))
        guarded = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function offerRegistrationLogout(form, session) {",
                    '  if (!form || form.parentElement?.querySelector("[data-register-session-action]")) return;',
                    "  const button = document.createElement(\"button\");",
                    "  form.after(button);",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("register-logout-guard-misses-sibling-button" in item for item in guarded))
        inside_form = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function offerRegistrationLogout(form, session) {",
                    '  if (!form || form.querySelector("[data-register-session-action]")) return;',
                    "  form.append(button);",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("register-logout-guard-misses-sibling-button" in item for item in inside_form))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("register-logout-guard-misses-sibling-button" in item for item in live))

    def test_frozen_preview_rejects_admin_audit_query_source_overwriting_subject_role(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function adminAuditQuery(page = adminAuditPage) {",
                    '  if (subject === "client") params.set("actor_role", "anonymous");',
                    '  if (source) params.set("actor_role", source);',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("admin-audit-query-source-overwrites-subject-role" in item for item in coupled))
        guarded = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function adminAuditQuery(page = adminAuditPage) {",
                    '  if (subject === "client") params.set("actor_role", "anonymous");',
                    '  if (source && !params.has("actor_role")) params.set("actor_role", source);',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("admin-audit-query-source-overwrites-subject-role" in item for item in guarded))
        empty_filters = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function adminAuditQuery(page = adminAuditPage) {",
                    '  const params = new URLSearchParams({ page: "1", page_size: "10" });',
                    "  return params.toString();",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("admin-audit-query-source-overwrites-subject-role" in item for item in empty_filters))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("admin-audit-query-source-overwrites-subject-role" in item for item in live))
        query_fn = _js_function_body(source, "function adminAuditQuery")
        self.assertIn('data-audit-filter="source"', query_fn)
        self.assertIn("uniqueRoles", query_fn)
        self.assertNotIn('params.has("actor_role")', query_fn)
        manage = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        self.assertIn('data-audit-filter="subject"', manage)
        self.assertIn('data-audit-filter="source"', manage)

    def test_frozen_preview_rejects_storage_cleanup_confirm_opens_without_scan_totals(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const storageExecuteButton = document.querySelector("[data-storage-cleanup]");',
                    'storageExecuteButton?.addEventListener("click", () => {',
                    "  storageCleanupDialog?.showModal();",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("storage-cleanup-confirm-opens-without-scan-totals" in item for item in coupled))
        filled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const storageExecuteButton = document.querySelector("[data-storage-cleanup]");',
                    'storageExecuteButton?.addEventListener("click", async () => {',
                    '  const payload = await apiRequest("/manage/storage/cleanup/");',
                    '  summary.textContent = `本次扫描 ${payload.candidate_count} 个，共 ${payload.candidate_bytes} 字节`;',
                    '  document.querySelector("[data-storage-cleanup-summary]");',
                    "  storageCleanupDialog?.showModal();",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("storage-cleanup-confirm-opens-without-scan-totals" in item for item in filled))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("storage-cleanup-confirm-opens-without-scan-totals" in item for item in live))
        manage = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("data-storage-cleanup-summary", manage)
        self.assertIn('data-storage-cleanup-confirm', manage)

    def test_frozen_preview_rejects_pause_copy_omitting_login_block(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const managementActionCopy = {",
                    '    pause: ["暂停下游账号", "暂停后不能发卡、兑换额度或新建授权。已有授权按软件策略继续验证。"],',
                    '    resume: ["恢复下游账号", "恢复后下游可再次登录并开展新业务。"],',
                    '    archive: ["归档对象", "归档后停止业务；只有归档对象才允许删除。"],',
                    "};",
                ]
            ),
        )
        self.assertTrue(any("pause-copy-omits-login-block" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const managementActionCopy = {",
                    '    pause: ["暂停下游账号", "暂停后不能登录、不能发卡、兑换额度或新建授权。已有授权按软件策略继续验证。"],',
                    '    resume: ["恢复下游账号", "恢复后下游可再次登录并开展新业务。"],',
                    "};",
                ]
            ),
        )
        self.assertFalse(any("pause-copy-omits-login-block" in item for item in new_js))
        plan_manager = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function preparePlanManagerDialog(button, requestedPage) {",
                    "  const statusCopy = {",
                    '    archived: ["已暂停", "status-warm"],',
                    "  };",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("pause-copy-omits-login-block" in item for item in plan_manager))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("pause-copy-omits-login-block" in item for item in live))
        pause_copy = _management_action_pause_copy(source)
        self.assertIn("不能登录", pause_copy)
        self.assertIn("不能发卡", pause_copy)
        self.assertIn("兑换", pause_copy)
        self.assertIn("继续验证", pause_copy)

    def test_frozen_preview_rejects_reset_copy_omitting_switch_and_delay(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const managementActionCopy = {",
                    '    reset: ["重置设备绑定", "只解除当前设备绑定，不重置到期时间、套餐快照或收入事实。"],',
                    "};",
                ]
            ),
        )
        self.assertTrue(any("reset-copy-omits-switch-and-delay" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const managementActionCopy = {",
                    '    reset: ["重置设备绑定", "只解除当前设备绑定，不受换机开关限制，不重置到期时间、套餐快照或收入事实。旧电脑可能还要过一会儿才停。"],',
                    "};",
                ]
            ),
        )
        self.assertFalse(any("reset-copy-omits-switch-and-delay" in item for item in new_js))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("reset-copy-omits-switch-and-delay" in item for item in live))
        self.assertFalse(any("admin-reset-button-omits-unbind-copy" in item for item in live))
        self.assertFalse(any("downstream-reset-button-omits-unbind-copy" in item for item in live))
        reset_copy = _management_action_reset_copy(source)
        self.assertIn("不受换机开关", reset_copy)
        self.assertIn("旧电脑可能还要过一会儿才停", reset_copy)
        self.assertIn("重置设备（只解绑，不受换机开关）", source)

    def test_frozen_preview_rejects_old_device_wide_block_copy_and_url(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const managementActionCopy = {",
                    '    block: ["封禁设备", "封禁整台设备：同一安装上的其他授权也会一起无法验证，不改变各授权到期时间。"],',
                    '    unblock: ["解除设备封禁", "解除封禁不复活历史绑定；客户仍需重新激活。"],',
                    "};",
                    "function renderAuthorizationRiskRows(items) {",
                    '  const riskLabel = device.risk_state === "blocked" ? "已封禁" : "正常";',
                    "  appendAuthorizationRiskAction(actions, device.risk_state === \"blocked\" ? \"解除封禁\" : \"封禁\", device.risk_state === \"blocked\" ? \"unblock\" : \"block\");",
                    "}",
                    "const route = `/manage/authorizations/devices/${encodeURIComponent(deviceId)}/${kind}/`;",
                    'if (kind === "unblock") { binding.textContent = "已解除封禁 · 需重新激活"; actions.textContent = "解除封禁后不自动恢复绑定"; }',
                ]
            ),
        )
        self.assertTrue(any("block-copy-still-freezes-whole-device" in item for item in old_js))
        self.assertTrue(any("block-copy-omits-this-card" in item for item in old_js))
        self.assertTrue(any("unblock-copy-still-requires-reactivate" in item for item in old_js))
        self.assertTrue(any("block-url-omits-authorization-id" in item for item in old_js))
        self.assertTrue(any("block-button-uses-device-risk-state" in item for item in old_js))
        self.assertTrue(any("block-button-omits-card-frozen" in item for item in old_js))
        self.assertTrue(any("unblock-preview-still-requires-reactivate" in item for item in old_js))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("block-copy-still-freezes-whole-device" in item for item in live))
        self.assertFalse(any("block-copy-omits-this-card" in item for item in live))
        self.assertFalse(any("unblock-copy-still-requires-reactivate" in item for item in live))
        self.assertFalse(any("block-url-omits-authorization-id" in item for item in live))
        self.assertFalse(any("block-button-uses-device-risk-state" in item for item in live))
        self.assertFalse(any("block-button-omits-card-frozen" in item for item in live))
        self.assertFalse(any("unblock-preview-still-requires-reactivate" in item for item in live))
        self.assertIn("这张卡", _management_action_block_copy(source))
        self.assertNotIn("封禁整台设备", _management_action_block_copy(source))
        self.assertIn("不必重新激活", _management_action_unblock_copy(source))
        self.assertIn("item.card_frozen", source)
        self.assertIn("/manage/authorizations/${encodeURIComponent(authorizationId)}/devices/${encodeURIComponent(deviceId)}/${kind}/", source)

    def test_frozen_preview_rejects_old_allow_customer_switch_label(self):
        old_html = _static_preview_findings(
            "manage.html",
            '<label><input id="policyAllowSwitch" type="checkbox" /> 允许客户换机</label>',
        )
        self.assertTrue(any("policy-switch-label-still-customer-switch" in item for item in old_html))
        self.assertTrue(any("policy-switch-label-not-full-slot-squeeze" in item for item in old_html))
        new_html = _static_preview_findings(
            "manage.html",
            '<label><input id="policyAllowSwitch" type="checkbox" /> 满员时允许新电脑挤掉旧电脑</label>',
        )
        self.assertFalse(any("policy-switch-label-still-customer-switch" in item for item in new_html))
        self.assertFalse(any("policy-switch-label-not-full-slot-squeeze" in item for item in new_html))
        manage = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("manage.html", manage)
        self.assertFalse(any("policy-switch-label" in item for item in live))
        self.assertIn("满员时允许新电脑挤掉旧电脑", manage)
        downstream = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "downstream.html").read_text(
            encoding="utf-8"
        )
        downstream_live = _static_preview_findings("downstream.html", downstream)
        self.assertFalse(any("downstream-reset-copy-omits-switch-and-delay" in item for item in downstream_live))
        self.assertIn("不受换机开关", downstream)
        self.assertIn("旧电脑可能还要过一会儿才停", downstream)

    def test_frozen_preview_rejects_catalog_scope_copy_omitting_unused_activate_block(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function ensureCatalogScopeDialog() {",
                    '  catalogScopeDialog.innerHTML = \'<form method="dialog"><p class="form-hint">只保存软件开放状态；开放后默认允许该软件当前全部可用套餐。</p><button type="button" data-catalog-scope-save>保存经营范围</button></form>\';',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("catalog-scope-copy-omits-unused-activate-block" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function ensureCatalogScopeDialog() {",
                    '  catalogScopeDialog.innerHTML = \'<form method="dialog"><p class="form-hint">关掉某软件后，该下游该软件未激活卡不能再开通；已开通验证不受影响；未激活仍可回收退额度。开放后默认允许该软件当前全部可用套餐。</p><button type="button" data-catalog-scope-save>保存经营范围</button></form>\';',
                    "}",
                ]
            ),
        )
        self.assertFalse(any("catalog-scope-copy-omits-unused-activate-block" in item for item in new_js))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("catalog-scope-copy-omits-unused-activate-block" in item for item in live))
        self.assertFalse(any("catalog-scope-copy-omits-cannot-issue" in item for item in live))
        self.assertIn("未激活卡不能再开通", source)
        self.assertIn("已开通验证不受影响", source)
        self.assertIn("回收退额度", source)
        self.assertIn("不能再发", source)

    def test_frozen_preview_rejects_catalog_scope_copy_omitting_cannot_issue(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function ensureCatalogScopeDialog() {",
                    '  catalogScopeDialog.innerHTML = \'<form method="dialog"><p class="form-hint">关掉某软件后，该下游该软件未激活卡不能再开通；已开通验证不受影响；未激活仍可回收退额度。开放后默认允许该软件当前全部可用套餐。</p><button type="button" data-catalog-scope-save>保存经营范围</button></form>\';',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("catalog-scope-copy-omits-cannot-issue" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function ensureCatalogScopeDialog() {",
                    '  catalogScopeDialog.innerHTML = \'<form method="dialog"><p class="form-hint">关掉某软件后，该下游该软件不能再发、未激活卡不能再开通；已开通验证不受影响；未激活仍可回收退额度。开放后默认允许该软件当前全部可用套餐。</p><button type="button" data-catalog-scope-save>保存经营范围</button></form>\';',
                    "}",
                ]
            ),
        )
        self.assertFalse(any("catalog-scope-copy-omits-cannot-issue" in item for item in new_js))

    def test_frozen_preview_rejects_catalog_scope_modal_that_clips_actions(self):
        old_css = _static_preview_findings(
            "preview.css",
            "\n".join(
                [
                    ".form-label input, .form-label select { width: 100%; min-height: 40px; }",
                    "dialog.modal { overflow: hidden; border-radius: 12px; }",
                ]
            ),
        )
        self.assertTrue(any("form-label-stretches-checkboxes" in item for item in old_css))
        self.assertTrue(any("modal-overflow-hidden-clips-actions" in item for item in old_css))
        self.assertTrue(any("catalog-scope-options-missing-scroll" in item for item in old_css))
        self.assertTrue(any("generated-code-list-missing-scroll" in item for item in old_css))
        self.assertTrue(any("modal-actions-not-sticky" in item for item in old_css))
        self.assertTrue(any("modal-missing-viewport-max-height" in item for item in old_css))
        old_js = _static_preview_findings(
            "preview.js",
            'label.className = "form-label checkbox-label";',
        )
        self.assertTrue(any("catalog-scope-uses-stretching-form-label" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_css = _static_preview_findings("preview.css", (root / "preview.css").read_text(encoding="utf-8"))
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "form-label-stretches-checkboxes",
            "modal-overflow-hidden-clips-actions",
            "catalog-scope-options-missing-scroll",
            "generated-code-list-missing-scroll",
            "modal-actions-not-sticky",
            "modal-missing-viewport-max-height",
            "catalog-scope-uses-stretching-form-label",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_css + live_js))
        css = (root / "preview.css").read_text(encoding="utf-8")
        self.assertIn('.form-label input[type="checkbox"]', css)
        self.assertIn("[data-catalog-scope-options]", css)
        self.assertIn('className = "checkbox-label"', (root / "preview.js").read_text(encoding="utf-8"))

    def test_frozen_preview_rejects_layout_class_growing_tables_and_stuck_preview(self):
        old_css = _static_preview_findings(
            "preview.css",
            "\n".join(
                [
                    ".table-scroll { overflow-x: auto; }",
                    "td { white-space: nowrap; }",
                    ".modal-actions { display: flex; }",
                    ".credential-detail-grid dd { overflow-wrap: anywhere; }",
                    ".impact-box b { display: block; }",
                ]
            ),
        )
        self.assertTrue(any("table-cells-grow-without-ellipsis" in item for item in old_css))
        self.assertTrue(any("table-action-column-not-sticky" in item for item in old_css))
        self.assertTrue(any("table-last-column-buttons-not-sticky" in item for item in old_css))
        self.assertTrue(any("detail-grid-grows-without-scroll" in item for item in old_css))
        self.assertTrue(any("impact-box-grows-without-scroll" in item for item in old_css))
        self.assertTrue(any("access-missing-short-viewport" in item for item in old_css))
        self.assertTrue(any("restore-confirm-not-sticky" in item for item in old_css))
        self.assertTrue(any("restore-confirm-not-capped" in item for item in old_css))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function appendTextCell(row, value, className = '') {",
                    "  const cell = document.createElement('td');",
                    "  cell.textContent = value;",
                    "  row.append(cell);",
                    "}",
                    'document.getElementById("reclaimBatch").textContent = rows.map((row) => row.dataset.codeSuffix).join("、");',
                    "issueSubmit.disabled = true;",
                    'issueSubmit.setAttribute("aria-disabled", "true");',
                    'if (issueError) issueError.textContent = apiErrorMessage(error, "成本预览失败，请稍后重试。 ");',
                    'document.createElement("dialog");',
                    'document.createElement("dialog");',
                    '[data-release-back]").addEventListener("click", () => showReleaseStage("upload", 0));',
                    'action.textContent = "12 秒后可重试"; action.disabled = true;',
                    "confirmBox.hidden = false; confirmBox.dataset.stagingId = payload.staging_id;",
                    "本次扫描失败，不能确认清理。 storageCleanupDialog?.showModal();",
                    "function renderDownstreamDeviceRows(items) { const actionCell = document.createElement('td'); actionCell.append(action); }",
                ]
            ),
        )
        self.assertTrue(any("issue-preview-error-leaves-submit-disabled" in item for item in old_js))
        self.assertTrue(any("extra-generated-dialog" in item for item in old_js))
        self.assertTrue(any("reclaim-batch-missing-joined-summary" in item for item in old_js))
        self.assertTrue(any("table-text-cell-missing-title-tooltip" in item for item in old_js))
        self.assertTrue(any("release-back-skips-reread-file" in item for item in old_js))
        self.assertTrue(any("error-429-retry-never-reenables" in item for item in old_js))
        self.assertTrue(any("restore-confirm-missing-scroll-into-view" in item for item in old_js))
        self.assertTrue(any("storage-cleanup-failure-still-opens-modal" in item for item in old_js))
        self.assertTrue(any("action-cells-missing-shared-wrap" in item for item in old_js))
        old_html = _static_preview_findings(
            "manage.html",
            "<dialog id='softwareDialog'></dialog><dialog id='policyDialog'></dialog>",
        )
        self.assertTrue(any("html-dialog-missing-modal-class" in item for item in old_html))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_css = _static_preview_findings("preview.css", (root / "preview.css").read_text(encoding="utf-8"))
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings(
            "downstream.html", (root / "downstream.html").read_text(encoding="utf-8")
        )
        banned = (
            "table-cells-grow-without-ellipsis",
            "table-action-column-not-sticky",
            "table-last-column-buttons-not-sticky",
            "detail-grid-grows-without-scroll",
            "impact-box-grows-without-scroll",
            "issue-preview-error-leaves-submit-disabled",
            "extra-generated-dialog",
            "reclaim-batch-missing-joined-summary",
            "table-text-cell-missing-title-tooltip",
            "html-dialog-missing-modal-class",
            "html-dialog-missing-modal-actions",
            "release-back-skips-reread-file",
            "error-429-retry-never-reenables",
            "restore-confirm-missing-scroll-into-view",
            "storage-cleanup-failure-still-opens-modal",
            "action-cells-missing-shared-wrap",
            "access-missing-short-viewport",
            "restore-confirm-not-sticky",
            "restore-confirm-not-capped",
        )
        self.assertFalse(
            any(any(token in item for token in banned) for item in live_css + live_js + live_manage + live_down)
        )
        css = (root / "preview.css").read_text(encoding="utf-8")
        self.assertIn("td:has(.table-actions)", css)
        self.assertIn("text-overflow: ellipsis", css)
        js = (root / "preview.js").read_text(encoding="utf-8")
        self.assertIn("function formatJoinedSummary", js)
        self.assertIn('issueSubmit.disabled = false;', js)

    def test_frozen_preview_rejects_disabled_license_status_filter(self):
        old_html = _static_preview_findings(
            "manage.html",
            '<select data-credential-filter="codeStatus"><option value="已禁用">已禁用</option></select>',
        )
        self.assertTrue(any("license-status-filter-keeps-disabled" in item for item in old_html))
        new_html = _static_preview_findings(
            "manage.html",
            '<select data-credential-filter="codeStatus"><option value="已撤销">已撤销</option></select>',
        )
        self.assertFalse(any("license-status-filter-keeps-disabled" in item for item in new_html))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const LICENSE_STATUS_FILTER_TO_API = {",
                    '  已禁用: "disabled",',
                    '  disabled: "disabled",',
                    "};",
                ]
            ),
        )
        self.assertTrue(any("license-status-filter-maps-disabled" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const LICENSE_STATUS_FILTER_TO_API = {",
                    '  已撤销: "revoked",',
                    "};",
                ]
            ),
        )
        self.assertFalse(any("license-status-filter-maps-disabled" in item for item in new_js))
        manage = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        downstream = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "downstream.html").read_text(
            encoding="utf-8"
        )
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        self.assertFalse(any("license-status-filter-keeps-disabled" in item for item in _static_preview_findings("manage.html", manage)))
        self.assertFalse(any("license-status-filter-keeps-disabled" in item for item in _static_preview_findings("downstream.html", downstream)))
        self.assertFalse(any("license-status-filter-maps-disabled" in item for item in _static_preview_findings("preview.js", source)))

    def test_frozen_preview_rejects_management_action_omitting_property_inventory(self):
        old_html = _static_preview_findings(
            "manage.html",
            '<dialog id="managementActionDialog"><div class="impact-box"><span>规则</span><b data-management-action-impact>—</b></div></dialog>',
        )
        self.assertTrue(any("management-action-omits-property-inventory" in item for item in old_html))
        new_html = _static_preview_findings(
            "manage.html",
            '<dialog id="managementActionDialog"><div class="impact-box"><span>财产清单</span><b data-management-action-inventory>—</b></div></dialog>',
        )
        self.assertFalse(any("management-action-omits-property-inventory" in item for item in new_html))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const managementActionCopy = { archive: ["归档对象", "归档后停止业务；只有归档对象才允许删除。"], delete: ["删除归档对象", "删除后保留最小脱敏墓碑与审计引用，不能恢复。"] };',
                    "function openManagementAction() {",
                    '  managementActionDialog.querySelector("[data-management-action-impact]");',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("archive-copy-omits-activated-still-works" in item for item in old_js))
        self.assertTrue(any("delete-copy-omits-activated-still-works" in item for item in old_js))
        self.assertTrue(any("management-action-omits-property-inventory" in item for item in old_js))
        self.assertTrue(any("management-action-inventory-omits-active-count" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'const managementActionCopy = { archive: ["归档对象", "归档后停止业务；已激活仍可用；只有归档对象才允许删除。"], delete: ["删除归档对象", "删除后保留最小脱敏墓碑与审计引用，不能恢复。已激活仍可用。"] };',
                    "function openManagementAction() {",
                    '  managementActionDialog.querySelector("[data-management-action-inventory]");',
                    '  inventory.textContent = `在役授权 ${activeCount} 张`;',
                    "}",
                ]
            ),
        )
        self.assertFalse(any("archive-copy-omits-activated-still-works" in item for item in new_js))
        self.assertFalse(any("delete-copy-omits-activated-still-works" in item for item in new_js))
        self.assertFalse(any("management-action-omits-property-inventory" in item for item in new_js))
        self.assertFalse(any("management-action-inventory-omits-active-count" in item for item in new_js))
        manage = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        self.assertFalse(any("management-action-omits-property-inventory" in item for item in _static_preview_findings("manage.html", manage)))
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("archive-copy-omits-activated-still-works" in item for item in live))
        self.assertFalse(any("delete-copy-omits-activated-still-works" in item for item in live))
        self.assertFalse(any("management-action-omits-property-inventory" in item for item in live))
        self.assertFalse(any("management-action-inventory-omits-active-count" in item for item in live))

    def test_frozen_preview_rejects_catalog_create_posting_switch_off(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "payload = await apiRequest('/manage/catalog/', {",
                    "  method: 'POST',",
                    "  body: JSON.stringify({",
                    "    allow_device_switch: false,",
                    "    device_switch_limit: 0,",
                    "  }),",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("catalog-create-posts-switch-off" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "payload = await apiRequest('/manage/catalog/', {",
                    "  method: 'POST',",
                    "  body: JSON.stringify({",
                    "    allow_device_switch: true,",
                    "    device_switch_limit: 5,",
                    "  }),",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("catalog-create-posts-switch-off" in item for item in new_js))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("catalog-create-posts-switch-off" in item for item in live))
        self.assertFalse(any("catalog-create-hardcodes-switch" in item for item in live))
        self.assertFalse(any("catalog-create-missing-switch-fields" in item for item in live))
        self.assertRegex(source, r"allow_device_switch:\s*Boolean\(softwareAllowSwitch")
        self.assertIn("softwareSwitchLimit", source)
        html = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        create_dialog = html.split('id="softwareDialog"', 1)[-1].split("</dialog>", 1)[0]
        self.assertIn("每日换机次数", create_dialog)
        self.assertIn("softwareAllowSwitch", create_dialog)
        self.assertIn("满员时允许新电脑挤掉旧电脑", create_dialog)
        self.assertNotIn('id="policySwitchLimit"', create_dialog)
        self.assertIn("每日换机次数", html)
        self.assertIn("已售跟着变", html)
        self.assertIn("已售不跟", html)
        self.assertRegex(create_dialog, r'id="softwareVerifyInterval"[^>]*value="1"')
        self.assertIn("像心跳", create_dialog)
        self.assertIn("不必为改间隔再发卡", create_dialog)
        self.assertNotIn("测挤机要新发卡", create_dialog)
        self.assertIn("|| 60", source)
        self.assertNotIn("|| 900", source)

    def test_frozen_preview_rejects_backup_screen_without_three_work_tabs(self):
        old_html = _static_preview_findings(
            "manage.html",
            """
<section class="screen" data-screen-panel="backup">
  <div class="page-heading">
    <div><h1>备份</h1></div>
    <div class="heading-actions">
      <button class="button button-secondary" type="button" data-backup-run="diff">立即增量备份</button>
      <button class="button button-primary" type="button" data-backup-run="full">立即全量备份</button>
    </div>
  </div>
  <section class="panel"><div class="panel-heading"><h2>时间和去向</h2></div><form data-backup-form></form></section>
  <section class="panel"><div class="panel-heading"><h2>导入备份</h2></div>
    <form data-backup-restore-form>
      <button class="button button-danger" type="button" data-backup-restore-apply>确认导入</button>
    </form>
  </section>
</section>
""",
        )
        self.assertTrue(any("backup-screen-not-record-download-tabs" in item for item in old_html))
        self.assertTrue(any("backup-page-heading-keeps-run-buttons" in item for item in old_html))
        self.assertTrue(any("backup-tabs-missing-record-download-labels" in item for item in old_html))
        self.assertTrue(any("backup-run-still-says-immediate" in item for item in old_html))
        self.assertTrue(any("backup-settings-missing-schedule-switch" in item for item in old_html))
        self.assertTrue(any("backup-settings-missing-full-time" in item for item in old_html))
        self.assertTrue(any("backup-settings-missing-diff-interval" in item for item in old_html))
        self.assertFalse(any("backup-restore-apply-not-type-button" in item for item in old_html))
        submit_apply = _static_preview_findings(
            "manage.html",
            """
<section class="screen" data-screen-panel="backup">
  <div class="page-heading"><div><h1>备份</h1></div></div>
  <form data-backup-form>
    <label><input name="enabled" type="checkbox" /> 备份总开关</label>
    <label><input name="github_enabled" type="checkbox" /> 同时拷到 GitHub</label>
    <span>上次备份结果</span>
    <button type="button" data-backup-probe>试连 GitHub</button>
    <button type="button" data-backup-run="full">现在备份</button>
  </form>
  <div class="work-view-shell" data-work-view-scope="backup-management">
    <div class="record-tabs page-tabs" role="tablist">
      <button type="button" role="tab" data-work-view="records" aria-selected="true">备份记录</button>
      <button type="button" role="tab" data-work-view="downloads" aria-selected="false">下载加密备份</button>
      <button type="button" role="tab" data-work-view="restore" aria-selected="false">导入备份</button>
    </div>
    <section data-work-panel="records">
      <p data-table-empty>还没有备份记录</p>
    </section>
    <section data-work-panel="downloads" hidden>
      <p>列表里是完整加密库</p>
      <p data-table-empty>还没有可下载的加密包</p>
    </section>
    <section data-work-panel="restore" hidden>
      <button class="button button-danger" type="submit" data-backup-restore-apply>确认导入</button>
    </section>
  </div>
</section>
""",
        )
        self.assertTrue(any("backup-restore-apply-not-type-button" in item for item in submit_apply))
        self.assertFalse(any("backup-screen-not-record-download-tabs" in item for item in submit_apply))
        self.assertFalse(any("backup-page-heading-keeps-run-buttons" in item for item in submit_apply))
        self.assertFalse(any("backup-settings-missing-full-run" in item for item in submit_apply))
        self.assertFalse(any("backup-tabs-missing-record-download-labels" in item for item in submit_apply))
        amber = _static_preview_findings(
            "manage.html",
            """
<section class="screen" data-screen-panel="backup">
  <div class="page-heading"><div><h1>备份</h1></div></div>
  <form data-backup-form>
    <label><input name="enabled" type="checkbox" /> 备份总开关</label>
    <label><input name="github_enabled" type="checkbox" /> 同时拷到 GitHub</label>
    <span>上次备份结果</span>
    <button type="button" data-backup-probe>试连 GitHub</button>
    <button type="button" data-backup-run="full">现在备份</button>
  </form>
  <div class="work-view-shell" data-work-view-scope="backup-management">
    <div class="record-tabs page-tabs" role="tablist">
      <button type="button" role="tab" data-work-view="records" aria-selected="true">备份记录</button>
      <button type="button" role="tab" data-work-view="downloads" aria-selected="false">下载加密备份</button>
      <button type="button" role="tab" data-work-view="restore" aria-selected="false">导入备份</button>
    </div>
    <section data-work-panel="records">
      <p data-table-empty>还没有备份记录</p>
    </section>
    <section data-work-panel="downloads" hidden>
      <p class="connection-note">列表里是完整加密库</p>
      <p data-table-empty>还没有可下载的加密包</p>
    </section>
    <section data-work-panel="restore" hidden>
      <p class="connection-note">口令不在网页上，在密钥包/服务器口令文件</p>
      <label>抄上面的北京时间，不要抄文件名</label>
      <p class="connection-note">将覆盖当前库，包括管理员</p>
      <button class="button button-danger" type="button" data-backup-restore-apply>确认导入</button>
    </section>
  </div>
</section>
""",
        )
        self.assertTrue(any("backup-downloads-keeps-amber-note" in item for item in amber))
        self.assertTrue(any("backup-restore-keeps-amber-note" in item for item in amber))
        new_html = _static_preview_findings(
            "manage.html",
            """
<section class="screen" data-screen-panel="backup">
  <div class="page-heading"><div><h1>备份</h1></div></div>
  <form data-backup-form>
    <label><input name="enabled" type="checkbox" /> 备份总开关</label>
    <label><input name="github_enabled" type="checkbox" /> 同时拷到 GitHub</label>
    <span>上次备份结果</span>
    <button type="button" data-backup-probe>试连 GitHub</button>
    <button type="button" data-backup-run="full">现在备份</button>
  </form>
  <div class="work-view-shell" data-work-view-scope="backup-management">
    <div class="record-tabs page-tabs" role="tablist">
      <button type="button" role="tab" data-work-view="records" aria-selected="true">备份记录</button>
      <button type="button" role="tab" data-work-view="downloads" aria-selected="false">下载加密备份</button>
      <button type="button" role="tab" data-work-view="restore" aria-selected="false">导入备份</button>
    </div>
    <section data-work-panel="records">
      <p data-table-empty>还没有备份记录</p>
    </section>
    <section data-work-panel="downloads" hidden>
      <p>列表里是完整加密库</p>
      <p data-table-empty>还没有可下载的加密包</p>
    </section>
    <section data-work-panel="restore" hidden>
      <p>口令不在网页上，在密钥包/服务器口令文件</p>
      <label>抄上面的北京时间，不要抄文件名</label>
      <p>将覆盖当前库，包括管理员</p>
      <button class="button button-danger" type="button" data-backup-restore-apply>确认导入</button>
    </section>
  </div>
</section>
""",
        )
        self.assertFalse(any("backup-screen-not-record-download-tabs" in item for item in new_html))
        self.assertFalse(any("backup-page-heading-keeps-run-buttons" in item for item in new_html))
        self.assertFalse(any("backup-settings-missing-full-run" in item for item in new_html))
        self.assertFalse(any("backup-restore-apply-not-type-button" in item for item in new_html))
        self.assertFalse(any("backup-tabs-missing-record-download-labels" in item for item in new_html))
        self.assertFalse(any("backup-run-still-says-immediate" in item for item in new_html))
        self.assertFalse(any("backup-settings-missing-queued-full" in item for item in new_html))
        self.assertFalse(any("backup-page-keeps-diff-run" in item for item in new_html))
        self.assertFalse(any("backup-page-keeps-netdisk-ui" in item for item in new_html))
        self.assertFalse(any("backup-last-result-still-says-program" in item for item in new_html))
        self.assertFalse(any("backup-runs-missing-empty-copy" in item for item in new_html))
        self.assertFalse(any("backup-downloads-missing-empty-copy" in item for item in new_html))
        self.assertFalse(any("backup-settings-missing-probe" in item for item in new_html))
        self.assertFalse(any("backup-restore-missing-overwrite-warning" in item for item in new_html))
        self.assertFalse(any("backup-restore-missing-copy-beijing-time" in item for item in new_html))
        self.assertFalse(any("backup-downloads-keeps-amber-note" in item for item in new_html))
        self.assertFalse(any("backup-restore-keeps-amber-note" in item for item in new_html))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("manage.html", source)
        self.assertFalse(any("backup-screen-not-record-download-tabs" in item for item in live))
        self.assertFalse(any("backup-page-heading-keeps-run-buttons" in item for item in live))
        self.assertFalse(any("backup-settings-missing-full-run" in item for item in live))
        self.assertFalse(any("backup-restore-apply-not-type-button" in item for item in live))
        self.assertFalse(any("backup-tabs-missing-record-download-labels" in item for item in live))
        self.assertFalse(any("backup-run-still-says-immediate" in item for item in live))
        self.assertFalse(any("backup-settings-missing-queued-full" in item for item in live))
        self.assertFalse(any("backup-page-keeps-diff-run" in item for item in live))
        self.assertFalse(any("backup-page-keeps-netdisk-ui" in item for item in live))
        self.assertFalse(any("backup-last-result-still-says-program" in item for item in live))
        self.assertFalse(any("backup-runs-missing-empty-copy" in item for item in live))
        self.assertFalse(any("backup-downloads-missing-empty-copy" in item for item in live))
        self.assertFalse(any("backup-tables-use-generic-empty" in item for item in live))
        self.assertFalse(any("backup-downloads-missing-full-dump-note" in item for item in live))
        self.assertFalse(any("backup-settings-missing-probe" in item for item in live))
        self.assertFalse(any("backup-restore-missing-overwrite-warning" in item for item in live))
        self.assertFalse(any("backup-restore-missing-copy-beijing-time" in item for item in live))
        self.assertFalse(any("backup-restore-missing-passphrase-location" in item for item in live))
        self.assertFalse(any("backup-downloads-keeps-amber-note" in item for item in live))
        self.assertFalse(any("backup-restore-keeps-amber-note" in item for item in live))
        self.assertFalse(any("backup-empty-site-still-three-item" in item for item in live))
        self.assertFalse(any("storage-cleanup-copy-says-expired-packages" in item for item in live))
        self.assertFalse(any("storage-cleanup-copy-omits-enc-exclusion" in item for item in live))
        self.assertFalse(any("storage-cleanup-dialog-says-expired-packages" in item for item in live))
        self.assertFalse(any("storage-cleanup-dialog-omits-enc-exclusion" in item for item in live))
        self.assertFalse(any("backup-download-delete-dialog-missing" in item for item in live))

    def test_frozen_preview_rejects_storage_cleanup_copy_and_download_delete_gaps(self):
        html_bad = """
<section class="screen" data-screen-panel="backup">
  <div class="page-heading"><h1>备份</h1></div>
  <section class="panel">
    <div class="panel-heading"><div><h2>存储清理</h2></div></div>
    <p>清理过期安装包、临时导出和日志残留。审计与额度流水不会删除。</p>
    <button type="button" data-storage-cleanup>清理可删文件</button>
  </section>
  <div class="work-view-shell">
    <button type="button" data-work-view="runs">运行与记录</button>
    <button type="button" data-work-view="schedule">时间和去向</button>
    <button type="button" data-work-view="restore">导入备份</button>
    <section data-work-panel="runs">
      <button type="button" data-backup-run="full">现在备份</button>
      <button type="button" data-backup-run="diff">排队增量备份</button>
      <h2>上次备份结果</h2>
      <p>还没有备份记录</p>
      <p>还没有可下载的加密包</p>
      <p>列表里是完整加密库，增量指机器侧。</p>
      <tbody data-backup-download-table></tbody>
    </section>
    <section data-work-panel="schedule"><button type="button" data-backup-probe>试连</button>关了就不做物理双仓</section>
    <section data-work-panel="restore">将覆盖当前库，包括管理员 抄上面的北京时间，不要抄文件名 口令不在网页上，在密钥包/服务器口令文件</section>
  </div>
</section>
<dialog id="storageCleanupDialog"><p>只删除过期安装包、临时导出和日志残留。</p></dialog>
"""
        bad_html = _static_preview_findings("manage.html", html_bad)
        self.assertTrue(any("storage-cleanup-copy-says-expired-packages" in item for item in bad_html))
        self.assertTrue(any("storage-cleanup-copy-omits-enc-exclusion" in item for item in bad_html))
        self.assertTrue(any("storage-cleanup-dialog-says-expired-packages" in item for item in bad_html))
        self.assertTrue(any("storage-cleanup-dialog-omits-enc-exclusion" in item for item in bad_html))
        self.assertTrue(any("backup-download-delete-dialog-missing" in item for item in bad_html))
        js_bad = "\n".join(
            [
                "function renderBackupDownloads(items) {",
                "  const action = appendActionCell(row, '下载');",
                "  action.dataset.backupDownload = item.name;",
                '  empty.textContent = "还没有可下载的加密包";',
                "}",
                "function installAdminBackup() {",
                "  apiRequest('/manage/backup/destinations/probe/');",
                "}",
                "function renderBackupRuns() { empty.textContent = '还没有备份记录'; }",
                'empty.textContent = "当前条件没有匹配的记录。";',
            ]
        )
        bad_js = _static_preview_findings("preview.js", js_bad)
        self.assertTrue(any("backup-downloads-missing-delete-action" in item for item in bad_js))
        self.assertTrue(any("backup-js-missing-download-delete-api" in item for item in bad_js))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("backup-downloads-missing-delete-action" in item for item in live_js))
        self.assertFalse(any("backup-js-missing-download-delete-api" in item for item in live_js))
        self.assertFalse(any("backup-js-delete-missing-confirmed" in item for item in live_js))

    def test_frozen_preview_rejects_withdraw_zip_copy_and_delete_package_gaps(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="releases"><h1>版本发布</h1><p>客户点更新后打开网盘地址</p></section>',
                    '<dialog id="withdrawReleaseDialog"><p class="form-hint">已安装的不会被卸掉。目录不再提供这个版本下载。</p><button data-withdraw-confirm>确认撤回</button></dialog>',
                ]
            ),
        )
        self.assertTrue(any("withdraw-missing-zip-kept-copy" in item for item in old_manage))
        self.assertTrue(any("release-package-delete-dialog-missing" in item for item in old_manage))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderReleaseRows(items) {",
                    '  if (item.status === "published") {',
                    '    action.dataset.dialog = "withdrawReleaseDialog";',
                    '    action.textContent = "撤回";',
                    "  } else {",
                    '    actionCell.textContent = "已保留历史记录";',
                    "  }",
                    "}",
                    'document.querySelector("[data-withdraw-confirm]")?.addEventListener("click", async (event) => {',
                    '  showToast("版本已撤回。已安装的不会被卸掉。公开目录会改指向 v1.0.0。审计记录已保留。");',
                    "});",
                ]
            ),
        )
        self.assertTrue(any("withdraw-toast-missing-zip-kept-copy" in item for item in old_js))
        self.assertTrue(any("withdrawn-row-missing-delete-package" in item for item in old_js))
        self.assertTrue(any("release-js-missing-delete-package-api" in item for item in old_js))
        published_delete = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderReleaseRows(items) {",
                    '  if (item.status === "published") {',
                    '    action.dataset.dialog = "deleteReleasePackageDialog";',
                    '    action.setAttribute("data-release-delete-package", "");',
                    "  } else if (item.status === \"withdrawn\" && item.package_available) {",
                    '    action.dataset.dialog = "deleteReleasePackageDialog";',
                    "  }",
                    "}",
                    'document.querySelector("[data-release-delete-package-confirm]")?.addEventListener("click", async (event) => {',
                    '  await apiRequest(`/manage/releases/${id}/delete-package/`, { method: "POST", body: JSON.stringify({ confirmed: true }) });',
                    "});",
                ]
            ),
        )
        self.assertTrue(any("published-row-has-delete-package" in item for item in published_delete))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "withdraw-missing-zip-kept-copy",
            "withdraw-toast-missing-zip-kept-copy",
            "release-package-delete-dialog-missing",
            "withdrawn-row-missing-delete-package",
            "published-row-has-delete-package",
            "release-js-missing-delete-package-api",
            "release-js-delete-package-missing-confirmed",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_manage + live_js))

    def test_frozen_preview_rejects_search_copy_and_software_id_filter_gaps(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="software"><label class="search-field"><span class="sr-only">搜索软件名称</span><input type="search" placeholder="搜索软件名称" /></label></section>',
                    '<label class="search-field"><span class="sr-only">输入完整卡密精确搜索</span><input type="search" data-sensitive-search placeholder="完整卡密" /></label>',
                ]
            ),
        )
        self.assertTrue(any("sensitive-search-missing-paste-full-code-copy" in item for item in old_manage))
        self.assertTrue(any("software-search-missing-id-copy" in item for item in old_manage))
        old_down = _static_preview_findings(
            "downstream.html",
            '<label class="search-field"><span class="sr-only">搜索设备、软件或授权 ID</span><input type="search" data-downstream-device-search placeholder="设备 / 软件 / 授权 ID" /></label>',
        )
        self.assertTrue(any(token in item for item in old_down for token in ("device-search-missing-no-card-copy", "device-search-missing-unified-copy")))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function searchLicenseCard(input) {",
                    '  showToast("请输入完整卡密精确搜索，不能按尾号查找。当前列表未改动。");',
                    "}",
                    "async function searchAdminCredential(input, options) {",
                    '  showToast("请输入完整码精确搜索，不能按尾号查找。当前列表未改动。");',
                    "}",
                    "function setDownstreamDevicePagination(pagination = {}) {",
                    '  summary.textContent = pagination.total ? "共 N 条" : "当前下游暂无已激活设备";',
                    "}",
                    "function applyTablePreview(context, options = {}) {",
                    '  row.dataset.queryMatch = String(!query || text.includes(query));',
                    "}",
                    "function renderAdminCatalogRows(items) {",
                    "  row.dataset.catalogSoftwareId = softwareItem.software_id;",
                    "}",
                    "function renderTableState(state, syncUrl) {",
                    "  showFixedPlaceholderRows(state, visibleRecords.length);",
                    "  catalogSearchHidesPlaceholders();",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("license-search-toast-missing-paste-and-reveal" in item for item in old_js))
        self.assertTrue(any("credential-search-toast-missing-paste-and-reveal" in item for item in old_js))
        self.assertTrue(any("device-empty-ignores-search-query" in item for item in old_js))
        self.assertTrue(any("software-filter-ignores-software-id" in item for item in old_js))
        self.assertTrue(any(token in item for item in old_js for token in ("software-search-keeps-placeholder-padding", "software-search-hides-placeholder-padding")))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "sensitive-search-missing-paste-full-code-copy",
            "software-search-missing-id-copy",
            "device-search-missing-no-card-copy",
            "license-search-toast-missing-paste-and-reveal",
            "credential-search-toast-missing-paste-and-reveal",
            "device-empty-ignores-search-query",
            "software-filter-ignores-software-id",
            "software-search-keeps-placeholder-padding",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_manage + live_down + live_js))

    def test_frozen_preview_rejects_wechat_wipe_login_hash_and_credential_query(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-support-save]")?.addEventListener("click", async (event) => {',
                    "  await apiRequest(`/downstream/support/${encodeURIComponent(softwareId)}/`, {",
                    '    body: JSON.stringify({ values: { purchase_url: purchase, qq: contact, wechat: "" } }),',
                    "  });",
                    "});",
                    "function activateScreen(name, options = {}) { return true; }",
                    "window.location.href = form.dataset.previewDestination;",
                    'window.location.href = "manage.html";',
                    'window.location.href = "downstream.html";',
                    "const requestedScreen = window.location.hash.slice(1);",
                    "const initialScreen = requestedScreen || defaultScreen;",
                    "if (!activateScreen(initialScreen, { smooth: false, focus: false })) {}",
                    "function clearTransientQuery() {",
                    "  updateQuery({ page: null, q: null, filter: null, criteria: null, view: null, code: null });",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("support-save-posts-empty-wechat" in item for item in old_js))
        self.assertTrue(any("login-jumps-without-workspace-hash" in item for item in old_js))
        self.assertTrue(any("session-bounce-missing-overview-hash" in item for item in old_js))
        self.assertTrue(any("session-bounce-missing-workspace-hash" in item for item in old_js))
        self.assertTrue(any("workbench-boot-missing-default-hash" in item for item in old_js))
        self.assertTrue(any("clear-transient-query-keeps-credential" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "support-save-posts-empty-wechat",
            "login-jumps-without-workspace-hash",
            "session-bounce-missing-overview-hash",
            "session-bounce-missing-workspace-hash",
            "workbench-boot-missing-default-hash",
            "clear-transient-query-keeps-credential",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_js))

    def test_frozen_preview_rejects_backup_dual_lamp_live_empty_and_run_download_gap(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyBackupDashboard(payload) {",
                    '  const resultCopy = { success: "上次：成功", failure: "上次：失败", missing: "尚无程序记录" };',
                    '  setBackupMetric("last-result", resultCopy[status.last_result]);',
                    "  healthNode.textContent =",
                    '    status.last_result === "missing" ? "尚未确认"',
                    '    : health === "ok" ? "上次证明正常"',
                    '    : health === "critical" ? "上次证明异常"',
                    '    : "尚未确认";',
                    "}",
                    "function renderServerTableState(state) {",
                    "  const matches = matchingRows(state);",
                    "  if (matches.length === 0) {",
                    "    state.placeholders.forEach((row) => {",
                    "      row.hidden = true;",
                    "    });",
                    "  } else {",
                    "    showFixedPlaceholderRows(state, matches.length);",
                    "  }",
                    "  state.empty.hidden = matches.length !== 0;",
                    "}",
                    "function renderBackupRuns(items) {",
                    '  if (empty) empty.textContent = "还没有备份记录";',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("backup-success-plus-critical-still-says-proof-error" in item for item in old_js))
        self.assertTrue(any("server-loaded-empty-hides-placeholder-padding" in item for item in old_js))
        self.assertTrue(any("backup-runs-empty-omits-download-source" in item for item in old_js))
        old_css = _static_preview_findings(
            "preview.css",
            "\n".join(
                [
                    ".table-placeholder-row td:first-child::before {",
                    '  content: "—";',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("placeholder-row-paints-dash" in item for item in old_css))
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<tbody data-backup-run-table></tbody>',
                    '<p class="table-empty" data-table-empty>还没有备份记录</p>',
                ]
            ),
        )
        self.assertTrue(any("backup-runs-html-empty-omits-download-source" in item for item in old_manage))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_css = _static_preview_findings("preview.css", (root / "preview.css").read_text(encoding="utf-8"))
        banned = (
            "backup-success-plus-critical-still-says-proof-error",
            "server-loaded-empty-hides-placeholder-padding",
            "placeholder-row-paints-dash",
            "backup-runs-empty-omits-download-source",
            "backup-runs-html-empty-omits-download-source",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_js + live_manage + live_css))

    def test_frozen_preview_rejects_rail_path_backup_cta_and_global_search_copy(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<div class="rail-entry"><span>管理端</span><code>/manage/</code></div>',
                    '<section class="screen" data-screen-panel="backup">',
                    '<button class="button button-danger" type="button" data-storage-cleanup>清理可删文件</button>',
                    '<button class="button button-primary" type="button" data-backup-run="full">排队全量备份</button>',
                    "</section>",
                    '<button class="icon-button" type="button" title="精确查找卡密" aria-label="精确查找卡密" data-global-search>⌕</button>',
                ]
            ),
        )
        self.assertTrue(any("manage-rail-shows-english-path" in item for item in old_manage))
        self.assertTrue(any("backup-cleanup-still-danger-cta" in item for item in old_manage))
        self.assertTrue(any("header-missing-standalone-card-search" in item for item in old_manage))
        old_down = _static_preview_findings(
            "downstream.html",
            '<div class="rail-entry"><span>下游端</span><code>/downstream/</code></div>',
        )
        self.assertTrue(any("downstream-rail-shows-english-path" in item for item in old_down))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelectorAll("[data-global-search]").forEach((button) => {',
                    '  showToast("全局搜索：输入完整授权卡密即可精确定位。");',
                    "});",
                ]
            ),
        )
        self.assertTrue(any("global-search-toast-says-global" in item for item in old_js))
        self.assertTrue(any("global-search-toast-says-global" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in ("manage.html", "downstream.html", "preview.js"):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "manage-rail-shows-english-path",
            "downstream-rail-shows-english-path",
            "backup-cleanup-still-danger-cta",
            "global-search-label-not-exact-card",
            "global-search-toast-says-global",
            "global-search-toast-missing-full-code-only",
            "header-missing-standalone-card-search",
            "js-missing-standalone-card-search",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))

    def test_frozen_preview_rejects_root_404_key_id_and_credit_adjust_gaps(self):
        missing_guide = _static_preview_findings("404.html", "<html><body>404 Not Found</body></html>")
        self.assertTrue(any("root-404-missing-downstream-login" in item for item in missing_guide))
        self.assertTrue(any("root-404-missing-preview-css" in item for item in missing_guide))
        leaked = _static_preview_findings(
            "404.html",
            "\n".join(
                [
                    "<p>这个地址没有页面。</p>",
                    '<p><a href="/manage-login.html">管理端</a></p>',
                    '<p><a href="/manage.html">工作台</a></p>',
                    '<p><a href="/entry.html">入口</a></p>',
                    '<p><a href="/downstream-login.html">下游</a></p>',
                ]
            ),
        )
        self.assertTrue(any("root-404-contains-manage-login-html" in item for item in leaked))
        self.assertTrue(any("root-404-contains-manage-html" in item for item in leaked))
        self.assertTrue(any("root-404-contains-entry-html" in item for item in leaked))
        old_client = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="client">',
                    '<p class="form-hint">验签公钥用来核对授权信封，不是卡密。</p>',
                    '<button type="button" data-copy-signing-key>复制当前验签公钥</button>',
                    "</section>",
                ]
            ),
        )
        self.assertTrue(any("client-missing-visible-signing-key-id" in item for item in old_client))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-copy-signing-key]")?.addEventListener("click", async (event) => {',
                    '  const payload = await apiRequest("/manage/authorization-signing-key/");',
                    '  const text = [`key_id=${payload.key_id || ""}`, payload.public_key || ""].join("\\n");',
                    "});",
                ]
            ),
        )
        self.assertTrue(any("signing-key-id-loader-missing-slot" in item for item in old_js))
        self.assertTrue(any("signing-key-id-never-loaded" in item for item in old_js))
        root = Path(__file__).resolve().parents[1]
        preview = root / "docs" / "ui-preview"
        live = []
        for filename in ("404.html", "manage.html", "preview.js"):
            live.extend(_static_preview_findings(filename, (preview / filename).read_text(encoding="utf-8")))
        banned = (
            "root-404-missing-downstream-login",
            "root-404-missing-preview-css",
            "root-404-contains-manage-login-html",
            "root-404-contains-manage-html",
            "root-404-contains-entry-html",
            "client-missing-visible-signing-key-id",
            "signing-key-id-loader-missing-slot",
            "signing-key-id-loader-not-writing-key-id",
            "signing-key-id-never-loaded",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))
        pages = validate_frozen_pages(preview)
        self.assertTrue(all(item.status == "passed" for item in pages), pages)
        self.assertTrue((preview / "404.html").is_file())
        nginx_files = (
            root / "deploy" / "nginx" / "authorization-platform.conf.example",
            root / "部署与恢复" / "nginx" / "authorization-platform-retired.example.com.conf",
        )
        for nginx_path in nginx_files:
            checks = validate_nginx_config(nginx_path)
            self.assertTrue(all(item.status == "passed" for item in checks), (nginx_path, checks))
        with tempfile.TemporaryDirectory() as directory:
            old_nginx = Path(directory) / "old.conf"
            old_nginx.write_text(
                nginx_files[0].read_text(encoding="utf-8").replace("        error_page 404 /404.html;\n", ""),
                encoding="utf-8",
            )
            old_checks = validate_nginx_config(old_nginx)
            self.assertEqual(next(item.status for item in old_checks if item.name == "root_path_custom_404"), "failed")
            self.assertEqual(next(item.status for item in old_checks if item.name == "root_path_404"), "passed")

    def test_frozen_preview_rejects_backup_queue_wording_and_probe(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function ensureTableState(table) {",
                    '  empty.textContent = "当前条件没有匹配的记录。";',
                    "}",
                    "function renderBackupRuns(items) {",
                    "  window.__previewRefreshTables?.();",
                    "}",
                    "function renderBackupDownloads(items) {",
                    "  window.__previewRefreshTables?.();",
                    "}",
                    "function installAdminBackup() {",
                    '  showToast("立即备份已排队。备份程序巡检到才会执行");',
                    '  const payload = await apiRequest("/manage/backup/runs/", { method: "POST" });',
                    '  panel.querySelector("[data-backup-probe]")?.addEventListener("click", async () => {',
                    '    await apiRequest("/manage/backup/runs/", { method: "POST" });',
                    "  });",
                    "}",
                    'note.textContent = "当前没有软件、下游和卡密，可以核对应导入的备份。";',
                ]
            ),
        )
        self.assertTrue(any("backup-js-still-says-immediate" in item for item in old_js))
        self.assertTrue(any("backup-js-empty-site-still-three-item" in item for item in old_js))
        self.assertTrue(any("backup-js-missing-destination-probe" in item for item in old_js))
        self.assertTrue(any("backup-js-probe-posts-backup-run" in item for item in old_js))
        self.assertTrue(any("backup-js-runs-missing-empty-copy" in item for item in old_js))
        self.assertTrue(any("backup-js-downloads-missing-empty-copy" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function ensureTableState(table) {",
                    '  empty.textContent = "当前条件没有匹配的记录。";',
                    "}",
                    "function renderBackupRuns(items) {",
                    '  if (empty) empty.textContent = "还没有备份记录";',
                    "}",
                    "function renderBackupDownloads(items) {",
                    '  if (empty) empty.textContent = "还没有可下载的加密包";',
                    "}",
                    "function installAdminBackup() {",
                    '  showToast("排队备份已入队。");',
                    '  panel.querySelector("[data-backup-probe]")?.addEventListener("click", async () => {',
                    '    await apiRequest("/manage/backup/destinations/probe/", { method: "POST", body: "{}" });',
                    "  });",
                    "}",
                    'note.textContent = "当前没有业务数据，可以核对应导入的备份。";',
                ]
            ),
        )
        self.assertFalse(any("backup-js-still-says-immediate" in item for item in new_js))
        self.assertFalse(any("backup-js-empty-site-still-three-item" in item for item in new_js))
        self.assertFalse(any("backup-js-missing-destination-probe" in item for item in new_js))
        self.assertFalse(any("backup-js-probe-posts-backup-run" in item for item in new_js))
        self.assertFalse(any("backup-js-runs-missing-empty-copy" in item for item in new_js))
        self.assertFalse(any("backup-js-downloads-missing-empty-copy" in item for item in new_js))
        self.assertFalse(any("backup-js-global-empty-copy-missing" in item for item in new_js))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
            encoding="utf-8"
        )
        live = _static_preview_findings("preview.js", source)
        self.assertFalse(any("backup-js-still-says-immediate" in item for item in live))
        self.assertFalse(any("backup-js-empty-site-still-three-item" in item for item in live))
        self.assertFalse(any("backup-js-missing-destination-probe" in item for item in live))
        self.assertFalse(any("backup-js-probe-posts-backup-run" in item for item in live))
        self.assertFalse(any("backup-js-runs-missing-empty-copy" in item for item in live))
        self.assertFalse(any("backup-js-downloads-missing-empty-copy" in item for item in live))
        self.assertFalse(any("backup-js-global-empty-copy-missing" in item for item in live))
        self.assertFalse(any("backup-script-keeps-netdisk-ui" in item for item in live))

    def test_frozen_preview_requires_backup_schedule_controls_and_serialization(self):
        old_html = _static_preview_findings(
            "manage.html",
            """
<section class="screen" data-screen-panel="backup">
  <form data-backup-form>
    <label><input name="enabled" type="checkbox" /> 备份总开关</label>
  </form>
  <div class="work-view-shell">
    <section data-work-panel="records"></section>
    <section data-work-panel="downloads"></section>
    <section data-work-panel="restore"></section>
  </div>
</section>
""",
        )
        self.assertTrue(any("backup-settings-missing-schedule-switch" in item for item in old_html))
        self.assertTrue(any("backup-settings-missing-full-time" in item for item in old_html))
        self.assertTrue(any("backup-settings-missing-diff-interval" in item for item in old_html))

        old_js = _static_preview_findings(
            "preview.js",
            """
function collectBackupPolicy() {
  const payload = { schedule_enabled: false };
  return payload;
}
""",
            strict=True,
        )
        self.assertTrue(any("backup-js-schedule-hardcoded-off" in item for item in old_js))
        self.assertTrue(any("backup-js-missing-schedule-switch" in item for item in old_js))
        self.assertTrue(any("backup-js-missing-full-time" in item for item in old_js))
        self.assertTrue(any("backup-js-missing-diff-interval" in item for item in old_js))
        for finding in (
            "backup-js-apply-policy-missing",
            "backup-js-dashboard-missing",
            "backup-js-load-dashboard-missing",
            "backup-js-install-missing",
        ):
            self.assertTrue(any(finding in item for item in old_js))

        good_js = _static_preview_findings(
            "preview.js",
            """
function collectBackupPolicy() {
  const payload = {
    schedule_enabled: Boolean(form.elements.schedule_enabled?.checked),
    full_time: String(form.elements.full_time?.value || "").trim(),
    diff_interval_hours: String(form.elements.diff_interval_hours?.value || "").trim(),
  };
  return payload;
}
""",
        )
        self.assertFalse(any("backup-js-schedule-hardcoded-off" in item for item in good_js))
        self.assertFalse(any("backup-js-missing-schedule-switch" in item for item in good_js))
        self.assertFalse(any("backup-js-missing-full-time" in item for item in good_js))
        self.assertFalse(any("backup-js-missing-diff-interval" in item for item in good_js))
        constant_schedule = _static_preview_findings(
            "preview.js",
            """
function collectBackupPolicy() {
  return {
    schedule_enabled: form.elements.schedule_enabled ? false : false,
    full_time: String(form.elements.full_time?.value || "").trim(),
    diff_interval_hours: String(form.elements.diff_interval_hours?.value || "").trim(),
  };
}
""",
            strict=True,
        )
        self.assertTrue(any("backup-js-schedule-switch-not-read" in item for item in constant_schedule))
        decoy_save_listener = _static_preview_findings(
            "preview.js",
            """
function installAdminBackup() {
  apiRequest("/manage/backup/", { method: "POST", body: JSON.stringify(collectBackupPolicy()) });
  panel.querySelector("[data-other-form]")?.addEventListener("submit", async (event) => {
    await apiRequest("/manage/backup/", { method: "POST", body: JSON.stringify(collectBackupPolicy()) });
    applyBackupDashboard(payload);
  });
}
""",
            strict=True,
        )
        self.assertTrue(any("backup-js-save-listener-missing" in item for item in decoy_save_listener))
        pseudo_function = _static_preview_findings(
            "preview.js",
            """
/* function collectBackupPolicy() {
  form.elements.schedule_enabled;
  form.elements.full_time;
  form.elements.diff_interval_hours;
} */
function removedCollectBackupPolicy() { return { schedule_enabled: false }; }
""",
            strict=True,
        )
        self.assertTrue(any("backup-js-collect-policy-missing" in item for item in pseudo_function))

        root = Path(__file__).resolve().parents[1]
        html = (root / "docs" / "ui-preview" / "manage.html").read_text(encoding="utf-8")
        self.assertIn('name="schedule_enabled"', html)
        self.assertIn('name="full_time"', html)
        self.assertIn('name="diff_interval_hours"', html)
        hidden_schedule = html.replace(
            'class="backup-schedule-settings" data-backup-schedule-fields',
            'class="backup-schedule-settings" data-backup-schedule-fields hidden',
            1,
        )
        hidden_findings = _static_preview_findings("manage.html", hidden_schedule)
        self.assertTrue(any("backup-settings-schedule-switch-hidden" in item for item in hidden_findings))
        wrong_schedule_type = html.replace(
            'name="schedule_enabled" type="checkbox"',
            'name="schedule_enabled" type="text"',
            1,
        )
        wrong_type_findings = _static_preview_findings("manage.html", wrong_schedule_type)
        self.assertTrue(any("backup-settings-schedule-switch-not-checkbox" in item for item in wrong_type_findings))
        missing_range = re.sub(
            r'(name="diff_interval_hours"[\s\S]{0,200}?min=")1("[\s\S]{0,80}?max=")24',
            r'\g<1>0\g<2>48',
            html,
            count=1,
        )
        range_findings = _static_preview_findings("manage.html", missing_range)
        self.assertTrue(any("backup-settings-diff-interval-missing-range" in item for item in range_findings))
        controls_outside_form = _static_preview_findings(
            "manage.html",
            """
<section class="screen" data-screen-panel="backup">
  <form data-backup-form>
    <input name="enabled" type="checkbox" />
  </form>
  <input name="schedule_enabled" type="checkbox" />
  <input name="full_time" type="time" min="00:00" max="23:59" required />
  <input name="diff_interval_hours" type="number" min="1" max="24" step="1" required />
  <div class="work-view-shell">
    <section data-work-panel="records"></section>
    <section data-work-panel="downloads"></section>
    <section data-work-panel="restore"></section>
  </div>
</section>
""",
        )
        for finding in (
            "backup-settings-missing-schedule-switch",
            "backup-settings-missing-full-time",
            "backup-settings-missing-diff-interval",
        ):
            self.assertTrue(any(finding in item for item in controls_outside_form))
        disabled_inputs = _static_preview_findings(
            "manage.html",
            html.replace('name="full_time"', 'name="full_time" disabled', 1).replace(
                'name="diff_interval_hours"', 'name="diff_interval_hours" disabled', 1
            ),
        )
        self.assertTrue(any("backup-settings-full-time-disabled" in item for item in disabled_inputs))
        self.assertTrue(any("backup-settings-diff-interval-disabled" in item for item in disabled_inputs))
        aria_hidden_inputs = _static_preview_findings(
            "manage.html",
            html.replace(
                'class="backup-schedule-settings" data-backup-schedule-fields',
                'class="backup-schedule-settings" data-backup-schedule-fields aria-hidden="true"',
                1,
            ),
        )
        self.assertTrue(any("backup-settings-schedule-switch-hidden" in item for item in aria_hidden_inputs))
        self.assertTrue(any("backup-settings-full-time-hidden" in item for item in aria_hidden_inputs))
        self.assertTrue(any("backup-settings-diff-interval-hidden" in item for item in aria_hidden_inputs))
        hidden_css = _static_preview_findings(
            "preview.css",
            '[data-screen-panel="backup"] .backup-schedule-settings { display: none; }',
        )
        self.assertTrue(any("backup-schedule-fields-hidden-by-css" in item for item in hidden_css))
        source = (root / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        collect = source.split("function collectBackupPolicy()", 1)[1].split("function renderBackupRuns", 1)[0]
        self.assertNotIn("schedule_enabled: false", collect)
        self.assertIn("form.elements.schedule_enabled", collect)
        self.assertIn("form.elements.full_time", collect)
        self.assertIn("form.elements.diff_interval_hours", collect)
        live_html = _static_preview_findings("manage.html", html, strict=True)
        live_js = _static_preview_findings("preview.js", source, strict=True)
        for finding in (
            "backup-settings-missing-schedule-switch",
            "backup-settings-missing-full-time",
            "backup-settings-missing-diff-interval",
        ):
            self.assertFalse(any(finding in item for item in live_html))
        for finding in (
            "backup-js-schedule-hardcoded-off",
            "backup-js-missing-schedule-switch",
            "backup-js-missing-full-time",
            "backup-js-missing-diff-interval",
            "backup-js-collect-policy-missing",
            "backup-js-apply-policy-missing",
            "backup-js-dashboard-missing",
            "backup-js-load-dashboard-missing",
            "backup-js-install-missing",
            "backup-js-dashboard-skips-policy-apply",
            "backup-js-load-dashboard-unwired",
            "backup-js-save-missing-api",
            "backup-js-save-missing-post",
            "backup-js-save-missing-policy-payload",
            "backup-js-save-skips-response-apply",
            "backup-js-save-listener-missing",
            "backup-js-save-does-not-require-loaded-policy",
            "backup-js-load-does-not-fail-closed",
            "backup-js-policy-load-state-missing",
            "backup-js-policy-load-state-incomplete",
            "backup-js-retention-not-from-policy",
            "backup-js-dashboard-retention-not-from-policy",
            "backup-js-retention-hardcoded-three",
            "backup-js-collects-retention-without-control",
            "backup-js-schedule-switch-not-read",
            "backup-js-full-time-not-read",
            "backup-js-diff-interval-not-read",
            "backup-script-keeps-netdisk-ui",
        ):
            self.assertFalse(any(finding in item for item in live_js))

    def test_frozen_preview_rejects_restore_file_staging_decoupling(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function installAdminBackup() {",
                    '  const restoreForm = panel.querySelector("[data-backup-restore-form]");',
                    '  restoreForm?.addEventListener("submit", async (event) => {',
                    '    const payload = await apiRequest("/manage/backup/restore/inspect/", { method: "POST", body });',
                    "    confirmBox.dataset.stagingId = payload?.staging_id || \"\";",
                    "  });",
                    '  panel.querySelector("[data-backup-restore-apply]")?.addEventListener("click", async (event) => {',
                    "    button.disabled = true;",
                    "    try {",
                    '      await apiRequest("/manage/backup/restore/", { method: "POST", body: JSON.stringify({ staging_id: stagingId }) });',
                    "    } catch (error) {",
                    '      showToast("fail");',
                    "    } finally {",
                    "      button.disabled = false;",
                    "    }",
                    "  });",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("restore-file-change-keeps-staging" in item for item in old_js))
        self.assertTrue(any("restore-inspect-applies-stale-file-staging" in item for item in old_js))
        self.assertTrue(any("restore-apply-reenables-after-success" in item for item in old_js))
        new_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function installAdminBackup() {",
                    '  const restoreForm = panel.querySelector("[data-backup-restore-form]");',
                    '  restoreForm?.elements.backup_file?.addEventListener("change", () => {',
                    "    resetBackupRestoreConfirm(panel);",
                    "  });",
                    '  restoreForm?.addEventListener("submit", async (event) => {',
                    "    const submittedToken = backupRestoreFileToken(file);",
                    '    const payload = await apiRequest("/manage/backup/restore/inspect/", { method: "POST", body });',
                    "    if (backupRestoreFileToken(currentFile) !== submittedToken) {",
                    "      resetBackupRestoreConfirm(panel);",
                    "      return;",
                    "    }",
                    "    confirmBox.dataset.stagingId = payload?.staging_id || \"\";",
                    "  });",
                    '  panel.querySelector("[data-backup-restore-apply]")?.addEventListener("click", async (event) => {',
                    "    button.disabled = true;",
                    "    try {",
                    '      await apiRequest("/manage/backup/restore/", { method: "POST", body: JSON.stringify({ staging_id: stagingId }) });',
                    "    } catch (error) {",
                    "      button.disabled = false;",
                    "    }",
                    "  });",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("restore-file-change-keeps-staging" in item for item in new_js))
        self.assertFalse(any("restore-inspect-applies-stale-file-staging" in item for item in new_js))
        self.assertFalse(any("restore-apply-reenables-after-success" in item for item in new_js))
        withdraw = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'panel.querySelector("[data-withdraw-confirm]")?.addEventListener("click", async (event) => {',
                    "  try {",
                    '    await apiRequest("/manage/releases/withdraw/");',
                    "  } finally {",
                    "    button.disabled = false;",
                    "  }",
                    "});",
                ]
            ),
        )
        self.assertFalse(any("restore-file-change-keeps-staging" in item for item in withdraw))
        self.assertFalse(any("restore-inspect-applies-stale-file-staging" in item for item in withdraw))
        self.assertFalse(any("restore-apply-reenables-after-success" in item for item in withdraw))
        live = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("restore-file-change-keeps-staging" in item for item in live))
        self.assertFalse(any("restore-inspect-applies-stale-file-staging" in item for item in live))
        self.assertFalse(any("restore-apply-reenables-after-success" in item for item in live))

    def test_frozen_preview_rejects_unwired_credits_month_net_consumed(self):
        unwired = _static_preview_findings(
            "manage.html",
            '<div class="balance-meta"><span>本月净消耗 <b>—</b></span><span>活跃账户 —</span></div>',
        )
        self.assertTrue(any("credits-unwired-month-net-consumed" in item for item in unwired))
        self.assertTrue(any("credits-unwired-active-accounts" in item for item in unwired))
        live = _static_preview_findings(
            "manage.html",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(encoding="utf-8"),
        )
        self.assertFalse(any("credits-unwired-month-net-consumed" in item for item in live))
        self.assertFalse(any("credits-unwired-active-accounts" in item for item in live))
        downstream = _static_preview_findings(
            "downstream.html",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "downstream.html").read_text(encoding="utf-8"),
        )
        self.assertFalse(any("credits-unwired-month-net-consumed" in item for item in downstream))
        self.assertIn("今日消耗", (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "downstream.html").read_text(encoding="utf-8"))

    def test_frozen_preview_rejects_credits_balance_summing_all_accounts(self):
        summed = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadAdminCredits(page = quotaCardsPage) {",
                    "  const payload = await apiRequest('/manage/credits/');",
                    "  const totalBalance = (payload.accounts || []).reduce((total, account) => total + Number(account.available_balance || 0), 0);",
                    "}",
                    "function applyDownstreamLedgerBalance(account) {}",
                ]
            ),
        )
        self.assertTrue(any("credits-balance-sums-all-accounts" in item for item in summed))
        self.assertTrue(any("credits-balance-missing-operating-total" in item for item in summed))
        guarded = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadAdminCredits(page = quotaCardsPage) {",
                    "  const payload = await apiRequest('/manage/credits/');",
                    "  const totalBalance = Number(payload.operating_available_balance);",
                    "}",
                    "function applyDownstreamLedgerBalance(account) {}",
                ]
            ),
        )
        self.assertFalse(any("credits-balance-sums-all-accounts" in item for item in guarded))
        self.assertFalse(any("credits-balance-missing-operating-total" in item for item in guarded))
        live = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8"),
        )
        self.assertFalse(any("credits-balance-sums-all-accounts" in item for item in live))
        self.assertFalse(any("credits-balance-missing-operating-total" in item for item in live))

    def test_frozen_preview_rejects_analytics_seven_day_chart_and_window_export(self):
        sliced = _static_preview_findings(
            "preview.js",
            "const items = Array.isArray(payload.trend) ? payload.trend.slice(-7) : [];",
        )
        self.assertTrue(any("analytics-trend-sliced-to-seven" in item for item in sliced))
        seven_cols = _static_preview_findings(
            "preview.css",
            ".bar-chart { display: grid; grid-template-columns: repeat(7, minmax(34px, 1fr)); }",
        )
        self.assertTrue(any("analytics-chart-locked-to-seven-columns" in item for item in seven_cols))
        seven_aria = _static_preview_findings(
            "manage.html",
            '<div class="bar-chart" aria-label="近七天激活量柱状图"></div>',
        )
        self.assertTrue(any("analytics-chart-aria-locked-to-seven-days" in item for item in seven_aria))
        beside = _static_preview_findings(
            "manage.html",
            '<span class="table-result">软件维度明细</span><button data-export-query="analytics">↓ 导出当前范围</button>',
        )
        self.assertTrue(any("analytics-export-pretends-current-window" in item for item in beside))
        self.assertTrue(any("analytics-export-beside-window-breakdown" in item for item in beside))
        unlabeled = _static_preview_findings(
            "manage.html",
            '<div class="revenue-grid" aria-label="激活收入"><article><span>今日收入</span><strong>—</strong></article></div>',
        )
        self.assertTrue(any("revenue-grid-missing-quota-unit" in item for item in unlabeled))
        self.assertTrue(any("revenue-grid-missing-activation-rule" in item for item in unlabeled))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_css = _static_preview_findings("preview.css", (root / "preview.css").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        self.assertFalse(any("analytics-trend-sliced-to-seven" in item for item in live_js))
        self.assertFalse(any("analytics-chart-locked-to-seven-columns" in item for item in live_css))
        self.assertFalse(any("analytics-chart-aria-locked-to-seven-days" in item for item in live_manage))
        self.assertFalse(any("analytics-export-pretends-current-window" in item for item in live_manage))
        self.assertFalse(any("analytics-export-beside-window-breakdown" in item for item in live_manage))
        self.assertFalse(any("revenue-grid-missing-quota-unit" in item for item in live_manage + live_down))
        self.assertFalse(any("revenue-grid-missing-activation-rule" in item for item in live_manage + live_down))
        self.assertFalse(any("revenue-rule-omits-activation" in item for item in live_manage + live_down))

    def test_frozen_preview_rejects_empty_analytics_hiding_snapshot_and_fake_refresh(self):
        hidden = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyAnalyticsPayload(payload) {",
                    "  const hasData = Boolean(payload?.has_data);",
                    "  analyticsContent.hidden = !hasData;",
                    "  if (hasData) {",
                    "    const target = analyticsScreen.querySelector(`[data-analytics-metric=\"${name}\"]`);",
                    "  }",
                    "}",
                    "function applyDownstreamMetricsPayload(payload) {",
                    "  const hasData = Boolean(payload?.has_data);",
                    "  const signals = downstreamWorkspace.querySelector(\".downstream-signals\");",
                    "  if (signals) signals.hidden = !hasData;",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("analytics-hides-content-when-empty-window" in item for item in hidden))
        self.assertTrue(any("analytics-skips-snapshot-metrics-when-empty-window" in item for item in hidden))
        self.assertTrue(any("downstream-hides-signals-when-empty-window" in item for item in hidden))
        fake_toast = _static_preview_findings(
            "manage.html",
            '<button type="button" data-toast="需要处理列表已刷新。">↻</button>',
        )
        self.assertTrue(any("overview-attention-refresh-is-fake-toast" in item for item in fake_toast))
        empty_copy = _static_preview_findings(
            "manage.html",
            "<h2>当前范围没有运营数据</h2>",
        )
        self.assertTrue(any("analytics-empty-copy-says-no-operations" in item for item in empty_copy))
        down_copy = _static_preview_findings(
            "downstream.html",
            "<h2>当前范围没有经营数据</h2>",
        )
        self.assertTrue(any("downstream-empty-copy-says-no-operations" in item for item in down_copy))
        kept = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyAnalyticsPayload(payload) {",
                    "  const hasData = Boolean(payload?.has_data);",
                    "  analyticsContent.hidden = false;",
                    "  analyticsEmpty.hidden = hasData;",
                    "  windowChart.hidden = !hasData;",
                    "  windowTable.hidden = !hasData;",
                    "}",
                    "function applyDownstreamMetricsPayload(payload) {",
                    "  const hasData = Boolean(payload?.has_data);",
                    "  if (empty) empty.hidden = hasData;",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("analytics-hides-content-when-empty-window" in item for item in kept))
        self.assertFalse(any("analytics-skips-snapshot-metrics-when-empty-window" in item for item in kept))
        self.assertFalse(any("downstream-hides-signals-when-empty-window" in item for item in kept))
        self.assertFalse(any("analytics-empty-leaves-window-chart" in item for item in kept))
        self.assertFalse(any("analytics-empty-leaves-window-table" in item for item in kept))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        self.assertFalse(any("analytics-hides-content-when-empty-window" in item for item in live_js))
        self.assertFalse(any("analytics-skips-snapshot-metrics-when-empty-window" in item for item in live_js))
        self.assertFalse(any("downstream-hides-signals-when-empty-window" in item for item in live_js))
        self.assertFalse(any("overview-attention-refresh-is-fake-toast" in item for item in live_manage))
        self.assertFalse(any("analytics-empty-copy-says-no-operations" in item for item in live_manage))
        self.assertFalse(any("downstream-empty-copy-says-no-operations" in item for item in live_down))

    def test_frozen_preview_rejects_missing_header_workspace_refresh(self):
        missing = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<div class="header-actions">',
                    '<button class="text-button" type="button">账户安全</button>',
                    '<button class="text-button" type="button">退出</button>',
                    "</div>",
                ]
            ),
        )
        self.assertTrue(any("header-missing-workspace-refresh" in item for item in missing))
        after_logout = _static_preview_findings(
            "downstream.html",
            "\n".join(
                [
                    '<div class="header-actions">',
                    '<button class="text-button" type="button">退出</button>',
                    '<button class="text-button" type="button" data-workspace-refresh>刷新</button>',
                    "</div>",
                ]
            ),
        )
        self.assertTrue(any("header-refresh-not-before-logout" in item for item in after_logout))
        fake = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<div class="header-actions">',
                    '<button class="text-button" type="button" data-workspace-refresh data-toast="列表已刷新。">刷新</button>',
                    '<button class="text-button" type="button">退出</button>',
                    "</div>",
                ]
            ),
        )
        self.assertTrue(any("header-refresh-is-fake-toast" in item for item in fake))
        toast_only = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function refreshVisibleWorkspace(options = {}) {",
                    '  showToast("列表已刷新。");',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("header-refresh-skips-license-cards" in item for item in toast_only))
        kept_html = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<div class="header-actions">',
                    '<button class="text-button" type="button" data-workspace-refresh>刷新</button>',
                    '<button class="text-button" type="button">退出</button>',
                    "</div>",
                ]
            ),
        )
        self.assertFalse(any("header-missing-workspace-refresh" in item for item in kept_html))
        self.assertFalse(any("header-refresh-not-before-logout" in item for item in kept_html))
        self.assertFalse(any("header-refresh-is-fake-toast" in item for item in kept_html))
        kept_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function refreshScreenData(screen) {",
                    "  await loadLicenseCards();",
                    "  await loadAdminBackup();",
                    "  await loadOverviewSnapshot();",
                    "  await loadDownstreamCredits();",
                    "}",
                    "async function refreshVisibleWorkspace(options = {}) {",
                    "  if (isStandaloneStaticPreview && !window.__b1ApiActive) return;",
                    "  await refreshScreenData(currentVisibleScreen);",
                    "}",
                    "function installWorkspaceRefresh() {}",
                    "function installLogout(session) {",
                    '  if (!button.textContent.includes("退出")) return;',
                    "}",
                    "async function loadLicenseCards() {}",
                ]
            ),
        )
        self.assertFalse(any("header-refresh-handler-missing" in item for item in kept_js))
        self.assertFalse(any("header-refresh-skips-license-cards" in item for item in kept_js))
        self.assertFalse(any("header-refresh-skips-backup" in item for item in kept_js))
        self.assertFalse(any("logout-binder-not-scoped-to-exit" in item for item in kept_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        self.assertFalse(any("header-missing-workspace-refresh" in item for item in live_manage))
        self.assertFalse(any("header-refresh-not-before-logout" in item for item in live_manage))
        self.assertFalse(any("header-refresh-is-fake-toast" in item for item in live_manage))
        self.assertFalse(any("header-missing-workspace-refresh" in item for item in live_down))
        self.assertFalse(any("header-refresh-not-before-logout" in item for item in live_down))
        self.assertFalse(any("header-refresh-handler-missing" in item for item in live_js))
        self.assertFalse(any("header-refresh-skips-license-cards" in item for item in live_js))
        self.assertFalse(any("header-refresh-skips-backup" in item for item in live_js))
        self.assertFalse(any("header-refresh-skips-overview" in item for item in live_js))
        self.assertFalse(any("header-refresh-skips-downstream-credits" in item for item in live_js))
        self.assertFalse(any("logout-binder-not-scoped-to-exit" in item for item in live_js))
        self.assertFalse(any("header-refresh-missing-audit" in item for item in live_js))
        self.assertFalse(any("header-refresh-missing-activity" in item for item in live_js))

    def test_frozen_preview_rejects_analytics_window_layout_jumping(self):
        stacked = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="analytics">',
                    '<div data-analytics-content>',
                    '<tbody data-analytics-breakdown></tbody>',
                    "</div>",
                    '<section data-analytics-empty></section>',
                    "</section>",
                ]
            ),
        )
        self.assertTrue(any("analytics-window-blocks-unmarked" in item for item in stacked))
        self.assertTrue(any("analytics-empty-cta-below-window-table" in item for item in stacked))
        leaves = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyAnalyticsPayload(payload) {",
                    "  const hasData = Boolean(payload?.has_data);",
                    "  analyticsContent.hidden = false;",
                    "  analyticsEmpty.hidden = hasData;",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("analytics-empty-leaves-window-chart" in item for item in leaves))
        self.assertTrue(any("analytics-empty-leaves-window-table" in item for item in leaves))
        growing = _static_preview_findings(
            "preview.css",
            ".bar-chart { grid-auto-columns: minmax(22px, 1fr); } .bar-chart div { grid-template-rows: 150px auto auto; }",
        )
        self.assertTrue(any("analytics-chart-squeezes-thirty-day-bars" in item for item in growing))
        self.assertTrue(any("analytics-chart-label-rows-grow-with-window" in item for item in growing))
        kept_html = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="analytics">',
                    '<section data-analytics-empty></section>',
                    '<div data-analytics-window-chart></div>',
                    '<section data-analytics-window-table>',
                    '<tbody data-analytics-breakdown></tbody>',
                    "</section>",
                    "</section>",
                ]
            ),
        )
        kept_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyAnalyticsPayload(payload) {",
                    "  const hasData = Boolean(payload?.has_data);",
                    "  analyticsContent.hidden = false;",
                    "  analyticsEmpty.hidden = hasData;",
                    "  windowChart.hidden = !hasData;",
                    "  windowTable.hidden = !hasData;",
                    "}",
                ]
            ),
        )
        kept_css = _static_preview_findings(
            "preview.css",
            ".bar-chart { grid-auto-columns: minmax(36px, 1fr); height: 215px; } .bar-chart div { grid-template-rows: 150px 14px 14px; }",
        )
        self.assertFalse(any("analytics-window-blocks-unmarked" in item for item in kept_html))
        self.assertFalse(any("analytics-empty-cta-below-window-table" in item for item in kept_html))
        self.assertFalse(any("analytics-empty-leaves-window-chart" in item for item in kept_js))
        self.assertFalse(any("analytics-empty-leaves-window-table" in item for item in kept_js))
        self.assertFalse(any("analytics-chart-squeezes-thirty-day-bars" in item for item in kept_css))
        self.assertFalse(any("analytics-chart-label-rows-grow-with-window" in item for item in kept_css))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_css = _static_preview_findings("preview.css", (root / "preview.css").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        self.assertFalse(any("analytics-empty-leaves-window-chart" in item for item in live_js))
        self.assertFalse(any("analytics-empty-leaves-window-table" in item for item in live_js))
        self.assertFalse(any("analytics-chart-squeezes-thirty-day-bars" in item for item in live_css))
        self.assertFalse(any("analytics-chart-label-rows-grow-with-window" in item for item in live_css))
        self.assertFalse(any("analytics-window-blocks-unmarked" in item for item in live_manage))
        self.assertFalse(any("analytics-empty-cta-below-window-table" in item for item in live_manage))

    def test_frozen_preview_rejects_recent_cards_looking_like_full_inventory(self):
        coupled = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadLicenseCards(page = licenseCardsPage) {",
                    "  const payload = await apiRequest('/downstream/licenses/cards/');",
                    "  renderLicenseCardRows(payload.items || []);",
                    "  renderDownstreamRecentCards(payload.items || []);",
                    "}",
                    "function renderDownstreamRecentCards(items) {",
                    "  empty.textContent = \"当前还没有授权卡密。\";",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("recent-cards-bound-to-license-list-page" in item for item in coupled))
        self.assertTrue(any("recent-cards-empty-says-no-inventory" in item for item in coupled))
        unlabeled = _static_preview_findings(
            "downstream.html",
            '<div class="panel-heading"><h2>最近卡密</h2></div><div data-downstream-recent-cards><p>当前还没有授权卡密。</p></div>',
        )
        self.assertTrue(any("recent-cards-heading-unlabeled-limit" in item for item in unlabeled))
        self.assertTrue(any("recent-cards-empty-says-no-inventory" in item for item in unlabeled))
        kept = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadLicenseCards(page = licenseCardsPage) {",
                    "  const payload = await apiRequest('/downstream/licenses/cards/');",
                    "  renderLicenseCardRows(payload.items || []);",
                    "}",
                    "function renderDownstreamRecentCards(items, pagination) {",
                    "  empty.textContent = \"这里只显示最近 3 张。完整库存在「全部卡密」。\";",
                    "}",
                    "async function loadDownstreamRecentCards() {",
                    "  const payload = await apiRequest('/downstream/licenses/cards/?page=1&page_size=3');",
                    "  renderDownstreamRecentCards(payload.items || [], payload.pagination || {});",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("recent-cards-bound-to-license-list-page" in item for item in kept))
        self.assertFalse(any("recent-cards-empty-says-no-inventory" in item for item in kept))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        self.assertFalse(any("recent-cards-bound-to-license-list-page" in item for item in live_js))
        self.assertFalse(any("recent-cards-empty-says-no-inventory" in item for item in live_js + live_down))
        self.assertFalse(any("recent-cards-heading-unlabeled-limit" in item for item in live_down))

    def test_frozen_preview_rejects_license_main_table_without_status(self):
        missing_filter = _static_preview_findings(
            "downstream.html",
            """
<div data-record-view-scope="downstream-licenses">
  <section class="panel table-panel" data-record-panel="items">
    <span data-record-scope-summary data-record-scope-default="当前下游未激活卡 · 默认脱敏">当前下游未激活卡 · 默认脱敏</span>
    <div class="credential-filter-bar" data-credential-filters>
      <label>软件<select data-credential-filter="codeSoftware"></select></label>
    </div>
    <table><thead><tr><th>授权卡密</th><th>软件 / 套餐</th></tr></thead></table>
  </section>
</div>
""",
        )
        self.assertTrue(any("license-main-table-missing-status-filter" in item for item in missing_filter))
        self.assertTrue(any("license-main-table-missing-status-column" in item for item in missing_filter))
        self.assertTrue(any("downstream-license-summary-claims-unused-by-default" in item for item in missing_filter))
        invitation_only = _static_preview_findings(
            "manage.html",
            """
<div data-record-view-scope="invitations">
  <label>状态<select data-credential-filter="codeStatus"></select></label>
  <table><thead><tr><th>邀请码</th><th>状态</th></tr></thead></table>
</div>
<section data-screen-panel="licenses">
<div data-record-view-scope="management-licenses">
  <section class="panel table-panel" data-record-panel="items">
    <div class="credential-filter-bar" data-credential-filters>
      <label>软件<select data-credential-filter="codeSoftware"></select></label>
    </div>
    <table><thead><tr><th>授权卡密</th></tr></thead></table>
  </section>
</div>
</section>
""",
        )
        self.assertTrue(any("license-main-table-missing-status-filter" in item for item in invitation_only))
        self.assertTrue(any("license-main-table-missing-status-column" in item for item in invitation_only))
        no_chip = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                    "  appendTextCell(row, item.masked_code);",
                    "  row.dataset.codeStatus = status[0];",
                    "}",
                    "function addGeneratedLicenseRecords(items) {",
                    "  appendTextCell(row, item.masked_code);",
                    "}",
                    "function licenseCardFilterQuery(panel) {",
                    "  query.status = select.value;",
                    "}",
                    "async function loadInvitations(page = invitationPage) {",
                    "  const statusLabel = document.querySelector('[data-credential-filter=\"codeStatus\"]')?.value || \"\";",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("license-main-rows-missing-status-chip" in item for item in no_chip))
        self.assertTrue(any("license-generated-rows-missing-status-chip" in item for item in no_chip))
        self.assertTrue(any("license-status-filter-missing-unused-mapping" in item for item in no_chip))
        self.assertTrue(any("invitation-status-filter-unscoped" in item for item in no_chip))
        kept = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const LICENSE_STATUS_FILTER_TO_API = { 未激活: \"unused\" };",
                    "function licenseCardFilterQuery(panel) {",
                    "  const status = licenseApiStatusFromFilter(value);",
                    "  if (status) query.status = status;",
                    "}",
                    "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                    "  appendStatusCell(row, status[0], status[1]);",
                    "}",
                    "function addGeneratedLicenseRecords(items) {",
                    "  appendStatusCell(row, item.status_label || \"未激活\", \"status-green\");",
                    "}",
                    "async function loadInvitations(page = invitationPage) {",
                    "  const statusLabel = document.querySelector('[data-record-view-scope=\"invitations\"] [data-credential-filter=\"codeStatus\"]')?.value || \"\";",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("license-main-rows-missing-status-chip" in item for item in kept))
        self.assertFalse(any("license-generated-rows-missing-status-chip" in item for item in kept))
        self.assertFalse(any("license-status-filter-missing-unused-mapping" in item for item in kept))
        self.assertFalse(any("invitation-status-filter-unscoped" in item for item in kept))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        self.assertFalse(any("license-main-rows-missing-status-chip" in item for item in live_js))
        self.assertFalse(any("license-generated-rows-missing-status-chip" in item for item in live_js))
        self.assertFalse(any("license-status-filter-missing-unused-mapping" in item for item in live_js))
        self.assertFalse(any("invitation-status-filter-unscoped" in item for item in live_js))
        self.assertFalse(any("license-main-table-missing-status-filter" in item for item in live_manage + live_down))
        self.assertFalse(any("license-main-table-missing-status-column" in item for item in live_manage + live_down))
        self.assertFalse(any("downstream-license-summary-claims-unused-by-default" in item for item in live_down))
        self.assertFalse(any("downstream-reclaimable-missing-status-target" in item for item in live_down))

    def test_frozen_preview_rejects_license_chip_ignoring_wall_clock_and_raw_iso_rule(self):
        js_bad = "\n".join(
            [
                "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                "  const status = licenseStatusCopy[item.status] || [item.status_label, \"status-gray\"];",
                "  row.dataset.cardStatus = item.status || \"\";",
                "  appendStatusCell(row, status[0], status[1]);",
                "  appendTextCell(row, item.activation_rule || \"激活后计时\");",
                "}",
                "function addGeneratedLicenseRecords(items) {",
                "  appendStatusCell(row, item.status_label || \"未激活\", \"status-green\");",
                "  appendTextCell(row, item.activation_rule || \"激活后计时\");",
                "}",
                "function renderDownstreamRecentCards(items) {",
                "  const status = licenseStatusCopy[item.status] || [item.status_label, \"status-gray\"];",
                "}",
                "function licenseActivationRuleLabel(item) {",
                "  return formatApiDate(item.activation_rule);",
                "}",
            ]
        )
        bad = _static_preview_findings("preview.js", js_bad)
        self.assertTrue(any("license-chip-missing-wall-clock-helper" in item for item in bad))
        self.assertTrue(any("license-main-chip-ignores-wall-clock" in item for item in bad))
        self.assertTrue(any("license-main-rule-uses-raw-iso" in item for item in bad))
        self.assertTrue(any("license-generated-chip-ignores-wall-clock" in item for item in bad))
        self.assertTrue(any("license-generated-rule-uses-raw-iso" in item for item in bad))
        self.assertTrue(any("recent-cards-chip-ignores-wall-clock" in item for item in bad))
        self.assertTrue(any("license-formats-activation-rule-string" in item for item in bad))
        js_good = "\n".join(
            [
                "function licenseCardDisplayStatus(item) {",
                "  const inventory = item.status || \"\";",
                "  if (inventory === \"activated\" && licenseCardWallClockExpired(item)) return licenseStatusCopy.expired;",
                "  return licenseStatusCopy[inventory];",
                "}",
                "function licenseActivationRuleLabel(item) {",
                "  if (item.expires_at) return `${formatApiDate(item.expires_at)} 到期`;",
                "  return item.activation_rule || \"激活后计时\";",
                "}",
                "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                "  const status = licenseCardDisplayStatus(item);",
                "  row.dataset.cardStatus = item.status || \"\";",
                "  appendStatusCell(row, status[0], status[1]);",
                "  appendTextCell(row, licenseActivationRuleLabel(item));",
                "}",
                "function addGeneratedLicenseRecords(items) {",
                "  const status = licenseCardDisplayStatus(item);",
                "  appendStatusCell(row, status[0], status[1]);",
                "  appendTextCell(row, licenseActivationRuleLabel(item));",
                "}",
                "function renderDownstreamRecentCards(items) {",
                "  const status = licenseCardDisplayStatus(item);",
                "}",
            ]
        )
        good = _static_preview_findings("preview.js", js_good)
        self.assertFalse(any("license-chip-missing-wall-clock-helper" in item for item in good))
        self.assertFalse(any("license-main-chip-ignores-wall-clock" in item for item in good))
        self.assertFalse(any("license-main-rule-uses-raw-iso" in item for item in good))
        self.assertFalse(any("license-generated-chip-ignores-wall-clock" in item for item in good))
        self.assertFalse(any("license-generated-rule-uses-raw-iso" in item for item in good))
        self.assertFalse(any("recent-cards-chip-ignores-wall-clock" in item for item in good))
        self.assertFalse(any("license-formats-activation-rule-string" in item for item in good))
        self.assertFalse(any("license-rows-lost-inventory-card-status" in item for item in good))
        live = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("license-chip-missing-wall-clock-helper" in item for item in live))
        self.assertFalse(any("license-main-chip-ignores-wall-clock" in item for item in live))
        self.assertFalse(any("license-main-rule-uses-raw-iso" in item for item in live))
        self.assertFalse(any("license-generated-chip-ignores-wall-clock" in item for item in live))
        self.assertFalse(any("license-generated-rule-uses-raw-iso" in item for item in live))
        self.assertFalse(any("recent-cards-chip-ignores-wall-clock" in item for item in live))
        self.assertFalse(any("license-formats-activation-rule-string" in item for item in live))
        self.assertFalse(any("license-rows-lost-inventory-card-status" in item for item in live))

    def test_frozen_preview_rejects_license_archive_ignoring_past_expiry_activated(self):
        status_only = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const lifecycleScopes = {",
                    '  "management-licenses": {',
                    '    prefix: "/manage/licenses/cards",',
                    '    archiveStatuses: ["expired", "revoked", "reclaimed"],',
                    "  },",
                    '  "quota-cards": { archiveStatuses: ["redeemed", "revoked"] },',
                    "};",
                    "const collectLifecycle = (button, action) => {",
                    "  const candidateFilter =",
                    '    action === "archive"',
                    "      ? (status) => config.archiveStatuses.includes(status)",
                    '      : (status) => status === "archived";',
                    "  boxes.filter((box) => candidateFilter(box.dataset.cardStatus));",
                    "};",
                    "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                    "  row.dataset.cardStatus = item.status;",
                    "  appendStatusCell(row, status[0], status[1]);",
                    "}",
                ]
            ),
        )
        self.assertTrue(
            any("license-archive-ignores-wall-clock-activated" in item for item in status_only)
        )
        self.assertTrue(
            any("license-rows-missing-expires-at-for-archive" in item for item in status_only)
        )
        all_activated = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function licenseCardMayArchive(box, config) {",
                    "  return config.archiveStatuses.includes(box.dataset.cardStatus);",
                    "}",
                    "const lifecycleScopes = {",
                    '  "management-licenses": {',
                    '    prefix: "/manage/licenses/cards",',
                    '    archiveStatuses: ["expired", "revoked", "reclaimed", "activated"],',
                    "  },",
                    '  "quota-cards": { archiveStatuses: ["redeemed"] },',
                    "};",
                    "const collectLifecycle = (button, action) => {",
                    '  boxes.filter((box) => (action === "archive" ? licenseCardMayArchive(box, config) : false));',
                    "};",
                    "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                    "  row.dataset.expiresAt = item.expires_at || \"\";",
                    "  appendStatusCell(row, status[0], status[1]);",
                    "}",
                ]
            ),
        )
        self.assertTrue(
            any("license-archive-unconditionally-includes-activated" in item for item in all_activated)
        )
        self.assertFalse(
            any("license-archive-ignores-wall-clock-activated" in item for item in all_activated)
        )
        no_expiry_check = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function licenseCardMayArchive(box, config) {",
                    '  return box.dataset.cardStatus === "activated";',
                    "}",
                    "const lifecycleScopes = {",
                    '  "management-licenses": {',
                    '    prefix: "/manage/licenses/cards",',
                    '    archiveStatuses: ["expired", "revoked", "reclaimed"],',
                    "  },",
                    '  "quota-cards": { archiveStatuses: ["redeemed"] },',
                    "};",
                    "const collectLifecycle = (button, action) => {",
                    '  boxes.filter((box) => (action === "archive" ? licenseCardMayArchive(box, config) : false));',
                    "};",
                    "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                    "  row.dataset.expiresAt = item.expires_at || \"\";",
                    "  appendStatusCell(row, status[0], status[1]);",
                    "}",
                ]
            ),
        )
        self.assertTrue(
            any("license-archive-activated-without-expiry-check" in item for item in no_expiry_check)
        )
        kept = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function licenseCardExpiryHasPassed(box) {",
                    "  return Date.parse(box.dataset.expiresAt) <= Date.now();",
                    "}",
                    "function licenseCardMayArchive(box, config) {",
                    "  if (config.archiveStatuses.includes(box.dataset.cardStatus)) return true;",
                    '  return box.dataset.cardStatus === "activated" && licenseCardExpiryHasPassed(box);',
                    "}",
                    "const lifecycleScopes = {",
                    '  "management-licenses": {',
                    '    prefix: "/manage/licenses/cards",',
                    '    archiveStatuses: ["expired", "revoked", "reclaimed"],',
                    "  },",
                    '  "quota-cards": { archiveStatuses: ["redeemed"] },',
                    "};",
                    "const collectLifecycle = (button, action) => {",
                    '  boxes.filter((box) => (action === "archive" ? licenseCardMayArchive(box, config) : false));',
                    "};",
                    "function renderLicenseCardRows(items, { serverSearch = false } = {}) {",
                    "  row.dataset.expiresAt = item.expires_at || \"\";",
                    "  appendStatusCell(row, status[0], status[1]);",
                    "}",
                ]
            ),
        )
        self.assertFalse(
            any("license-archive-ignores-wall-clock-activated" in item for item in kept)
        )
        self.assertFalse(
            any("license-archive-unconditionally-includes-activated" in item for item in kept)
        )
        self.assertFalse(
            any("license-archive-activated-without-expiry-check" in item for item in kept)
        )
        self.assertFalse(any("license-rows-missing-expires-at-for-archive" in item for item in kept))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("license-archive-ignores-wall-clock-activated" in item for item in live_js))
        self.assertFalse(
            any("license-archive-unconditionally-includes-activated" in item for item in live_js)
        )
        self.assertFalse(any("license-archive-activated-without-expiry-check" in item for item in live_js))
        self.assertFalse(any("license-rows-missing-expires-at-for-archive" in item for item in live_js))

    def test_frozen_preview_rejects_authorization_risk_filter_and_pending_page_count(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function authorizationRiskStatus(item) {",
                    '  if (item.status === "revoked") return ["已撤销", "status-red"];',
                    '  if (item.status === "expired") return ["已过期", "status-gray"];',
                    '  if (item.device_binding_state === "blocked") return ["正常 / 已封禁", "status-red"];',
                    '  return ["正常 / 已绑定", "status-green"];',
                    "}",
                    "function renderAuthorizationRiskRows(items, pagination = {}) {",
                    '  const deviceState = device.device_id ? (device.binding_state === "active" ? "已绑定" : "等待激活") : "等待激活";',
                    '  summary.textContent = `待处理 ${rows.flatMap((item) => item.devices || []).filter((device) => device.risk_state === "blocked").length}`;',
                    "}",
                    "async function loadAuthorizationRisk(page = 1) {",
                    "  const payload = await apiRequest('/manage/authorizations/');",
                    "  renderAuthorizationRiskRows(payload.items || [], payload.pagination || {});",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("authorization-risk-status-ignores-instance-blocked" in item for item in old_js))
        self.assertTrue(any("authorization-risk-status-splices-device-onto-normal" in item for item in old_js))
        self.assertTrue(any("authorization-risk-pending-counts-current-page" in item for item in old_js))
        self.assertTrue(any("authorization-risk-device-column-non-active-as-waiting" in item for item in old_js))
        self.assertTrue(any("authorization-risk-pending-skips-server-total" in item for item in old_js))
        old_html = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="risk">',
                    '<select data-risk-filter="status"><option value="">全部授权</option><option value="active">正常</option></select>',
                    '<select data-risk-filter="device_state"><option value="unbound">等待激活</option></select>',
                    "</section>",
                    '<section class="screen" data-screen-panel="client"></section>',
                ]
            ),
        )
        self.assertTrue(any("authorization-risk-status-filter-missing-blocked" in item for item in old_html))
        self.assertTrue(any("authorization-risk-unbound-labeled-waiting" in item for item in old_html))
        kept_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function authorizationRiskStatus(item) {",
                    '  if (item.status === "blocked") return ["已阻断", "status-red"];',
                    '  if (item.status === "revoked") return ["已撤销", "status-red"];',
                    '  return ["正常", "status-green"];',
                    "}",
                    "function renderAuthorizationRiskRows(items, pagination = {}, pendingCount = 0) {",
                    "  const deviceState = authorizationRiskDeviceState(device);",
                    "  summary.textContent = `待处理 ${pendingCount}`;",
                    "}",
                    "async function loadAuthorizationRisk(page = 1) {",
                    '  pendingQuery.set("risk_state", "blocked");',
                    "  pendingTotal = Number(pendingPayload.pagination?.total) || 0;",
                    "  renderAuthorizationRiskRows(payload.items || [], payload.pagination || {}, pendingTotal);",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("authorization-risk-status-ignores-instance-blocked" in item for item in kept_js))
        self.assertFalse(any("authorization-risk-status-splices-device-onto-normal" in item for item in kept_js))
        self.assertFalse(any("authorization-risk-pending-counts-current-page" in item for item in kept_js))
        self.assertFalse(any("authorization-risk-device-column-non-active-as-waiting" in item for item in kept_js))
        self.assertFalse(any("authorization-risk-pending-skips-server-total" in item for item in kept_js))
        kept_html = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="risk">',
                    '<select data-risk-filter="status"><option value="">全部授权</option><option value="blocked">已阻断</option></select>',
                    '<select data-risk-filter="device_state"><option value="unbound">已解绑</option></select>',
                    "</section>",
                    '<section class="screen" data-screen-panel="client"></section>',
                ]
            ),
        )
        self.assertFalse(any("authorization-risk-status-filter-missing-blocked" in item for item in kept_html))
        self.assertFalse(any("authorization-risk-unbound-labeled-waiting" in item for item in kept_html))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        live_manage = _static_preview_findings(
            "manage.html",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "manage.html").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("authorization-risk-status-ignores-instance-blocked" in item for item in live_js))
        self.assertFalse(any("authorization-risk-status-splices-device-onto-normal" in item for item in live_js))
        self.assertFalse(any("authorization-risk-pending-counts-current-page" in item for item in live_js))
        self.assertFalse(any("authorization-risk-device-column-non-active-as-waiting" in item for item in live_js))
        self.assertFalse(any("authorization-risk-pending-skips-server-total" in item for item in live_js))
        self.assertFalse(any("authorization-risk-status-filter-missing-blocked" in item for item in live_manage))
        self.assertFalse(any("authorization-risk-unbound-labeled-waiting" in item for item in live_manage))

    def test_frozen_preview_rejects_blocked_device_reset_as_unbound(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function confirmReset() {",
                    "  await apiRequest('/downstream/authorizations/x/devices/y/reset/', { method: 'POST' });",
                    "  showToast(`设备已重置，到期时间仍为 ${expiry}。`);",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("downstream-reset-toast-missing" in item for item in old_js))
        self.assertTrue(any("downstream-reset-confirm-ignores-reset-toast" in item for item in old_js))
        old_toast = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function downstreamDeviceResetToast(payload, expiry) {",
                    "  return `设备已重置，到期时间仍为 ${expiry}。`;",
                    "}",
                    "showToast(downstreamDeviceResetToast(payload, expiry));",
                ]
            ),
        )
        self.assertTrue(any("downstream-reset-toast-ignores-blocked-state" in item for item in old_toast))
        self.assertTrue(any("downstream-reset-toast-missing-blocked-copy" in item for item in old_toast))
        self.assertTrue(any("downstream-reset-toast-always-reset" in item for item in old_toast))
        kept_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function downstreamDeviceResetToast(payload, expiry) {",
                    '  if (payload?.device?.binding_state === "blocked") {',
                    "    return `设备仍已阻断，没有可解绑的有效绑定。到期时间仍为 ${expiry}。`;",
                    "  }",
                    "  return `设备已重置，到期时间仍为 ${expiry}。`;",
                    "}",
                    "showToast(downstreamDeviceResetToast(payload, expiry));",
                ]
            ),
        )
        self.assertFalse(any("downstream-reset-toast-missing" in item for item in kept_js))
        self.assertFalse(any("downstream-reset-toast-ignores-blocked-state" in item for item in kept_js))
        self.assertFalse(any("downstream-reset-toast-missing-blocked-copy" in item for item in kept_js))
        self.assertFalse(any("downstream-reset-toast-says-unbound" in item for item in kept_js))
        self.assertFalse(any("downstream-reset-toast-always-reset" in item for item in kept_js))
        self.assertFalse(any("downstream-reset-confirm-ignores-reset-toast" in item for item in kept_js))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("downstream-reset-toast-missing" in item for item in live_js))
        self.assertFalse(any("downstream-reset-toast-ignores-blocked-state" in item for item in live_js))
        self.assertFalse(any("downstream-reset-toast-missing-blocked-copy" in item for item in live_js))
        self.assertFalse(any("downstream-reset-toast-says-unbound" in item for item in live_js))
        self.assertFalse(any("downstream-reset-toast-always-reset" in item for item in live_js))
        self.assertFalse(any("downstream-reset-confirm-ignores-reset-toast" in item for item in live_js))

    def test_frozen_preview_rejects_plan_manager_archived_as_paused(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function preparePlanManagerDialog(button, requestedPage) {",
                    "  const statusCopy = {",
                    '    active: ["可用", "status-green"],',
                    '    draft: ["草稿", "status-gray"],',
                    '    archived: ["已暂停", "status-warm"],',
                    "  };",
                    "  visiblePlans.forEach((planItem) => {",
                    '    const [statusLabel, statusClass] = statusCopy[planItem.status] || ["可用", "status-green"];',
                    "    appendStatusCell(row, statusLabel, statusClass);",
                    "  });",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("plan-manager-archived-labeled-paused" in item for item in old_js))
        self.assertTrue(any("plan-manager-status-ignores-test-only" in item for item in old_js))
        self.assertTrue(any("plan-manager-status-missing-archived-copy" in item for item in old_js))
        self.assertTrue(any("plan-manager-status-missing-test-only-copy" in item for item in old_js))
        kept_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function preparePlanManagerDialog(button, requestedPage) {",
                    "  visiblePlans.forEach((planItem) => {",
                    "    const testOnly = Boolean(planItem.test_only || planItem.testOnly);",
                    '    let statusLabel = "可用";',
                    '    let statusClass = "status-green";',
                    '    if (planItem.status === "archived") {',
                    '      statusLabel = "已归档";',
                    '      statusClass = "status-gray";',
                    '    } else if (planItem.status === "draft") {',
                    '      statusLabel = "草稿";',
                    '      statusClass = "status-gray";',
                    "    } else if (testOnly) {",
                    '      statusLabel = "仅测试";',
                    '      statusClass = "status-warm";',
                    "    }",
                    "    appendStatusCell(row, statusLabel, statusClass);",
                    "  });",
                    "}",
                    "function appendPlanSummary(planCell, softwarePlans) {",
                    "  softwarePlans.slice(0, 4).forEach((item) => {",
                    "    const chip = document.createElement('span');",
                    "    chip.textContent = item.name;",
                    "  });",
                    "}",
                ]
            ),
        )
        self.assertFalse(any("plan-manager-archived-labeled-paused" in item for item in kept_js))
        self.assertFalse(any("plan-manager-status-ignores-test-only" in item for item in kept_js))
        self.assertFalse(any("plan-manager-status-missing-archived-copy" in item for item in kept_js))
        self.assertFalse(any("plan-manager-status-missing-test-only-copy" in item for item in kept_js))
        self.assertFalse(any("plan-chip-injects-lifecycle-copy" in item for item in kept_js))
        self.assertFalse(any("plan-chip-not-name-only" in item for item in kept_js))
        chip_injected = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function preparePlanManagerDialog(button, requestedPage) {",
                    "    const testOnly = Boolean(planItem.test_only);",
                    '    statusLabel = "已归档";',
                    '    statusLabel = "仅测试";',
                    "}",
                    "function appendPlanSummary(planCell, softwarePlans) {",
                    "  chip.textContent = item.name + '仅测试';",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("plan-chip-injects-lifecycle-copy" in item for item in chip_injected))
        self.assertTrue(any("plan-chip-not-name-only" in item for item in chip_injected))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("plan-manager-archived-labeled-paused" in item for item in live_js))
        self.assertFalse(any("plan-manager-status-ignores-test-only" in item for item in live_js))
        self.assertFalse(any("plan-manager-status-missing-archived-copy" in item for item in live_js))
        self.assertFalse(any("plan-manager-status-missing-test-only-copy" in item for item in live_js))
        self.assertFalse(any("plan-chip-injects-lifecycle-copy" in item for item in live_js))
        self.assertFalse(any("plan-chip-not-name-only" in item for item in live_js))

    def test_frozen_preview_rejects_archived_plan_without_delete(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function preparePlanManagerDialog(button, requestedPage) {",
                    '    let statusLabel = "已归档";',
                    '    statusLabel = "仅测试";',
                    '    lifecycleButton.textContent = planItem.status === "archived" ? "恢复" : "归档";',
                    "}",
                    "function openPlanLifecycle(planItem, softwareItem) {",
                    '    title.textContent = "归档套餐";',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("plan-manager-archived-missing-delete" in item for item in old_js))
        self.assertTrue(any("plan-lifecycle-delete-omits-invalidate-copy" in item for item in old_js))
        self.assertTrue(any("plan-lifecycle-delete-endpoint-missing" in item for item in old_js))
        live_js = _static_preview_findings(
            "preview.js",
            (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(any("plan-manager-archived-missing-delete" in item for item in live_js))
        self.assertFalse(any("plan-lifecycle-delete-omits-invalidate-copy" in item for item in live_js))
        self.assertFalse(any("plan-lifecycle-delete-endpoint-missing" in item for item in live_js))

    def test_frozen_preview_rejects_loaded_claim_entry_link_and_static_count(self):
        loaded = _static_preview_findings("manage.html", '<div data-server-data-loaded="true"></div>')
        self.assertTrue(any("frozen-server-data-loaded" in item for item in loaded))
        entry = _static_preview_findings("manage.html", '<a href="entry.html">hidden</a>')
        self.assertTrue(any("live-entry-html" in item for item in entry))
        counts = _static_preview_findings("manage.html", '<button type="button" data-count="12">运行中</button>')
        self.assertTrue(any("frozen-static-count" in item for item in counts))
        self.assertFalse(
            any("live-entry-html" in item for item in _static_preview_findings("entry.html", '<a href="entry.html">hidden</a>'))
        )

    def test_frozen_preview_rejects_remaining_fix_batch_regressions(self):
        overlay = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function bindDialogChrome(dialog) {",
                    "  dialog.addEventListener('click', (event) => {",
                    "    if (event.target === dialog) dialog.close('cancel');",
                    "  });",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("dialog-light-dismiss-on-overlay" in item for item in overlay))
        filters = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyCredentialFilters(group, options = {}) {",
                    "  loadLicenseCards(1).catch((error) => showToast(apiErrorMessage(error, '卡密筛选失败，请重试。')));",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("credential-filter-failure-does-not-restore" in item for item in filters))
        plans = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function syncLicenseCredentialFilters() {",
                    "  const planSelects = document.querySelectorAll('[data-credential-filter=\"codePlan\"]');",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("quota-codeplan-filter-shares-license-plans" in item for item in plans))
        analytics = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderOverviewCards(payload) {}",
                    "function applyAnalyticsPayload(payload) {",
                    "  renderOverviewCards(payload);",
                    "  updateRevenueGrids(payload.revenue);",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("analytics-payload-writes-overview" in item for item in analytics))
        self.assertTrue(any("overview-missing-unfiltered-snapshot-loader" in item for item in analytics))
        devices = _static_preview_findings(
            "preview.js",
            "function setDownstreamDevicePagination(pagination = {}) { panel.querySelector('[data-device-count]').textContent = `共 ${pagination.total} 份授权`; }",
        )
        self.assertTrue(any("downstream-device-summary-says-authorization-count" in item for item in devices))
        backup = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyBackupDashboard(payload) {",
                    "  const health = status.health?.status || 'unknown';",
                    "  healthNode.textContent = health === 'ok' ? '上次证明正常' : '上次证明异常';",
                    "  setBackupMetric('last-result', waiting ? '排队等待执行' : resultCopy[status.last_result]);",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("backup-missing-marker-labeled-proof-error" in item for item in backup))
        self.assertTrue(any("backup-queue-overwrites-last-result" in item for item in backup))
        self.assertTrue(any("backup-queue-metric-missing" in item for item in backup))
        access = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function bootstrapB1Runtime() {",
                    "  const isAccessPage = document.body.classList.contains('access-preview');",
                    "  await loadPublicQuotaPurchaseLink();",
                    "  const session = await apiRequest('/session/');",
                    "  if (isAccessPage) return;",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("access-page-logged-in-stays-on-form" in item for item in access))
        self.assertTrue(any("purchase-link-failure-clears-as-unconfigured" in item for item in access))
        html = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section data-screen-panel="software"><div class="table-toolbar"></div></section>',
                    '<section data-record-view-scope="quota-cards"></section>',
                    '<section data-record-view-scope="invitations"></section>',
                    '<section data-screen-panel="credits"></section>',
                    '<section data-screen-panel="backup"></section>',
                    '<option value="blocked">待复核</option>',
                ]
            ),
        )
        self.assertTrue(any("quota-amount-filter-missing" in item for item in html))
        self.assertTrue(any("software-table-missing-name-search" in item for item in html))
        self.assertTrue(any("invitation-revoke-dialog-missing" in item for item in html))
        self.assertTrue(any("recover-deleted-dialog-missing" in item for item in html))
        self.assertTrue(any("backup-queue-metric-missing" in item for item in html))
        self.assertTrue(any("risk-blocked-labeled-pending-review" in item for item in html))
        audit = _static_preview_findings(
            "preview.js",
            "function adminAuditQuery(page = 1) { return 'page=1'; }",
        )
        self.assertTrue(any("admin-audit-export-uses-live-unapplied-query" in item for item in audit))
        client_config = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadClientProfileConfig(softwareId) {",
                    '  document.querySelector("[data-client-title]").textContent = softwareId;',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("client-config-load-applies-stale-software" in item for item in client_config))
        issue_plan = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function normalizeCatalogPlan(softwareId, item) {",
                    "  return { test_only: item.test_only, label: item.name };",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("issue-plan-option-missing-test-only-label" in item for item in issue_plan))
        quota_fifth = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderQuotaCardRows(items, { serverSearch = false } = {}) {",
                    '  const fifth = item.status === "issued" ? "可兑换" : "已消费";',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("quota-issued-fifth-column-says-redeemable" in item for item in quota_fifth))
        invite_json = _static_preview_findings(
            "preview.js",
            'await apiRequest("/manage/invitations/", { method: "GET" });',
        )
        self.assertTrue(any("invitation-revoke-json-missing" in item for item in invite_json))
        recover_json = _static_preview_findings(
            "preview.js",
            'const dialog = document.getElementById("creditRecoverDeletedDialog");',
        )
        self.assertTrue(any("recover-deleted-json-missing" in item for item in recover_json))
        issue_preview = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "issueSubmit?.addEventListener('click', async () => {",
                    "  try { await apiRequest('/manage/licenses/'); }",
                    "  finally { updateIssuePreview(); }",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("issue-failure-refreshes-expired-preview" in item for item in issue_preview))
        login = _static_preview_findings("manage-login.html", "<form data-preview-destination='manage.html'></form>")
        self.assertTrue(any("access-page-missing-toast" in item for item in login))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        live_html = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_login = _static_preview_findings(
            "manage-login.html",
            (root / "manage-login.html").read_text(encoding="utf-8"),
        )
        banned = (
            "dialog-light-dismiss-on-overlay",
            "credential-filter-failure-does-not-restore",
            "quota-codeplan-filter-shares-license-plans",
            "analytics-payload-writes-overview",
            "overview-missing-unfiltered-snapshot-loader",
            "downstream-device-summary-says-authorization-count",
            "backup-missing-marker-labeled-proof-error",
            "backup-queue-overwrites-last-result",
            "backup-queue-metric-missing",
            "access-page-logged-in-stays-on-form",
            "purchase-link-failure-clears-as-unconfigured",
            "quota-amount-filter-missing",
            "software-table-missing-name-search",
            "invitation-revoke-dialog-missing",
            "invitation-revoke-json-missing",
            "recover-deleted-dialog-missing",
            "recover-deleted-json-missing",
            "admin-audit-export-uses-live-unapplied-query",
            "client-config-load-applies-stale-software",
            "client-config-catch-ignores-generation",
            "issue-plan-option-missing-test-only-label",
            "quota-issued-fifth-column-says-redeemable",
            "issue-failure-refreshes-expired-preview",
            "risk-blocked-labeled-pending-review",
            "access-page-missing-toast",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_js))
        self.assertFalse(any(any(token in item for token in banned) for item in live_html))
        self.assertFalse(any(any(token in item for token in banned) for item in live_login))

    def test_frozen_preview_rejects_round6_client_config_reclaim_and_issue_ttl(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section data-quota-purchase-settings><h2>额度卡购买链接</h2></section>',
                    '<h1>全平台授权卡密</h1>',
                    '<dialog id="clientConfigDialog">',
                    '<input name="support_email" /><input name="purchase_url" />',
                    "<legend>可见模块</legend></dialog>",
                    '<dialog id="issueDialog"><h2>代下游生成授权卡密</h2></dialog>',
                    '<dialog id="revokeDialog"></dialog>',
                    '<dialog id="adminReclaimDialog"><h2>管理员代下游回收</h2></dialog>',
                ]
            ),
        )
        self.assertTrue(any("client-config-dialog-keeps-fake-fields" in item for item in old_manage))
        self.assertTrue(any("quota-purchase-heading-not-downstream-site" in item for item in old_manage))
        self.assertTrue(any("manage-keeps-proxy-issue-dialog" in item for item in old_manage))
        self.assertTrue(any("manage-keeps-dead-revoke-dialog" in item for item in old_manage))
        self.assertTrue(any("licenses-heading-missing-issue-on-downstream" in item for item in old_manage))
        self.assertTrue(any("admin-reclaim-missing-void-copy" in item for item in old_manage))
        old_down = _static_preview_findings(
            "downstream.html",
            "\n".join(
                [
                    '<label>购买额度卡网站<input data-support-purchase /></label>',
                    '<dialog id="reclaimDialog"><b id="reclaimCount">0 张</b></dialog>',
                    '<dialog id="issueDialog"><div class="rule-note">首次激活后按套餐计时</div></dialog>',
                    '<dialog id="credentialDetailDialog"><dd data-detail-expires>激活后按套餐计算</dd></dialog>',
                    '<button class="text-button" type="button">续期</button>',
                ]
            ),
        )
        self.assertTrue(any("downstream-support-label-not-customer-facing" in item for item in old_down))
        self.assertTrue(any("downstream-reclaim-missing-void-copy" in item for item in old_down))
        self.assertTrue(any("downstream-reclaim-missing-reason" in item for item in old_down))
        self.assertTrue(any("issue-rules-missing-new-card-copy" in item for item in old_down))
        self.assertTrue(any("card-expiry-missing-new-card-copy" in item for item in old_down))
        self.assertTrue(any("downstream-renew-entry" in item for item in old_down))
        old_renew_dialog = _static_preview_findings(
            "manage.html",
            '<dialog id="renewAuthorizationDialog"><p>把已激活的授权往后推。</p></dialog>',
        )
        self.assertTrue(any("renew-dialog-missing-active-only-copy" in item for item in old_renew_dialog))
        self.assertTrue(any("renew-dialog-missing-no-ledger-copy" in item for item in old_renew_dialog))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function applyClientConfig(payload) {",
                    '  set("[data-client-support]", cfg.qq || cfg.purchase_url || "未配置");',
                    "}",
                    "await apiRequest(`/manage/software/${softwareId}/profiles/${encodeURIComponent(profileId)}/configuration/`, {",
                    '  body: JSON.stringify({ values: { purchase_url: purchase, qq: email } })',
                    "});",
                    "document.querySelectorAll('[data-reclaim-confirm]').forEach((button) => {",
                    '  const body = selection === "filtered"',
                    '    ? { selection: "filtered", filters: dialog.__reclaimFilters || {} }',
                    "    : { card_ids: cardIds };",
                    '  activateScreen("ledger", { history: "push" });',
                    "});",
                    "function licensePreviewMatchesCurrent() {",
                    "  return Boolean(activeLicensePreview && activeLicensePreview.software_id === software?.value);",
                    "}",
                    "issueDialog?.addEventListener('close', () => {",
                    '  issueDialog.dataset.generatedCodes = "[]";',
                    "});",
                    'issueError.textContent = apiErrorMessage(error, "授权卡密生成失败，额度和数据没有改变。 ");',
                    "function renderPlanCatalog(items = catalogItems) {",
                    '  action.dataset.dialog = "issueDialog";',
                    '  if (document.body.classList.contains("role-admin")) {',
                    '    action.textContent = "管理端不可发卡";',
                    "  }",
                    "}",
                    'button.textContent = "续期";',
                    'await apiRequest("/licenses/cards/extend/", { method: "POST" });',                ]
            ),
        )
        self.assertTrue(any("client-config-summary-paints-profile-support" in item for item in old_js))
        self.assertTrue(any("client-config-post-sends-customer-support" in item for item in old_js))
        self.assertTrue(any("reclaim-confirm-live-requeries-filters" in item for item in old_js))
        self.assertTrue(any("reclaim-success-jumps-to-ledger" in item for item in old_js))
        self.assertTrue(any("license-preview-match-ignores-expiry" in item for item in old_js))
        self.assertTrue(any("issue-close-clears-codes-without-copy-prompt" in item for item in old_js))
        self.assertTrue(any("issue-unknown-outcome-omits-maybe-issued" in item for item in old_js))
        self.assertTrue(any("admin-cannot-issue-still-opens-issue-dialog" in item for item in old_js))
        self.assertTrue(any("renew-through-license-card-route" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_down = _static_preview_findings("downstream.html", (root / "downstream.html").read_text(encoding="utf-8"))
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "client-config-dialog-keeps-fake-fields",
            "quota-purchase-heading-not-downstream-site",
            "manage-keeps-proxy-issue-dialog",
            "manage-keeps-dead-revoke-dialog",
            "licenses-heading-missing-issue-on-downstream",
            "admin-reclaim-missing-void-copy",
            "downstream-support-label-not-customer-facing",
            "downstream-reclaim-missing-void-copy",
            "downstream-reclaim-missing-reason",
            "issue-rules-missing-new-card-copy",
            "card-expiry-missing-new-card-copy",
            "client-config-summary-paints-profile-support",
            "client-config-post-sends-customer-support",
            "reclaim-confirm-live-requeries-filters",
            "reclaim-success-jumps-to-ledger",
            "license-preview-match-ignores-expiry",
            "issue-close-clears-codes-without-copy-prompt",
            "issue-unknown-outcome-omits-maybe-issued",
            "admin-cannot-issue-still-opens-issue-dialog",
            "renew-through-license-card-route",
            "downstream-renew-entry",
            "renew-dialog-missing-active-only-copy",
            "renew-dialog-missing-no-ledger-copy",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_manage + live_down + live_js))

    def test_frozen_preview_rejects_round7_create_switch_unlist_and_official_zero(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<dialog id="softwareDialog">',
                    '<label>默认设备数<input id="softwareMaxDevices" /></label>',
                    '<label>单卡额度成本<input id="softwarePlanCost" type="number" min="0" /></label>',
                    "</dialog>",
                    '<dialog id="policyDialog">',
                    '<p class="form-hint">保存会生成新的策略版本；换机规则对已激活卡下次握手生效；有效期/套餐仍锁快照。</p>',
                    "</dialog>",
                ]
            ),
        )
        self.assertTrue(any("catalog-create-missing-switch-fields" in item for item in old_manage))
        self.assertTrue(any("create-plan-cost-allows-zero" in item for item in old_manage))
        self.assertTrue(any("policy-dialog-missing-sold-follow-copy" in item for item in old_manage))
        self.assertTrue(any("manage-missing-unlist-dialog" in item for item in old_manage))
        old_unlist = _static_preview_findings(
            "manage.html",
            '<dialog id="softwareUnlistDialog"><h2>下架</h2><p>只改状态</p></dialog>',
        )
        self.assertTrue(any("unlist-dialog-missing-stop-new-issue-copy" in item for item in old_unlist))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'document.querySelector("[data-software-save]")?.addEventListener("click", async (event) => {',
                    "  await apiRequest('/manage/catalog/', {",
                    "    body: JSON.stringify({ allow_device_switch: true, device_switch_limit: 5 }),",
                    "  });",
                    "});",
                    "function renderCatalogRows() {",
                    '  policyButton.textContent = "授权参数";',
                    '  managePlansButton.textContent = "套餐管理";',
                    "}",
                    'document.querySelector("[data-policy-save]")?.addEventListener("click", async () => {',
                    '  showToast("授权参数已保存，并生成新的策略版本。换机规则对已激活卡下次握手生效；有效期/套餐仍锁快照。");',
                    "});",
                    'document.querySelector("[data-plan-save]")?.addEventListener("click", async (event) => {',
                    "  const requestBody = { quota_cost: Number(planQuotaCost.value), test_only: planStatus.value === 'test' };",
                    "});",
                ]
            ),
        )
        self.assertTrue(any("catalog-create-hardcodes-switch" in item for item in old_js))
        self.assertTrue(any("catalog-create-hardcodes-switch-limit" in item for item in old_js))
        self.assertTrue(any("software-row-missing-unlist" in item for item in old_js))
        self.assertTrue(any("policy-save-toast-missing-sold-follow" in item for item in old_js))
        self.assertTrue(any("plan-save-allows-official-zero" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live_manage = _static_preview_findings("manage.html", (root / "manage.html").read_text(encoding="utf-8"))
        live_js = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "catalog-create-missing-switch-fields",
            "create-plan-cost-allows-zero",
            "policy-dialog-missing-sold-follow-copy",
            "manage-missing-unlist-dialog",
            "unlist-dialog-missing-stop-new-issue-copy",
            "catalog-create-hardcodes-switch",
            "catalog-create-hardcodes-switch-limit",
            "software-row-missing-unlist",
            "software-unlist-missing-status-post",
            "software-unlist-toast-missing-stop-new-issue-copy",
            "policy-save-toast-missing-sold-follow",
            "plan-save-allows-official-zero",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live_manage + live_js))

    def test_frozen_preview_rejects_round8_sidebar_revoke_withdraw_login_and_search(self):
        old_css = _static_preview_findings(
            "preview.css",
            ".side-nav .nav-secondary { display: none; }",
        )
        self.assertTrue(any("nav-secondary-still-hidden" in item for item in old_css))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function activateScreen(name, options = {}) {",
                    "  const activeNavigation = routeLink?.dataset.navParent || name;",
                    "  const active = link.dataset.screen === activeNavigation;",
                    "}",
                    'document.querySelectorAll("[data-screen-target]").forEach((button) => {',
                    "  button.addEventListener(\"click\", () => activateScreen(button.dataset.screenTarget));",
                    "});",
                    "function renderOverviewCards(payload) {",
                    "  const target = document.querySelector(`[data-overview-metric=\"${name}\"]`);",
                    "}",
                    "function applyDownstreamMetricsPayload(payload) {",
                    "  const target = downstreamWorkspace.querySelector(`[data-downstream-metric=\"${name}\"]`);",
                    "}",
                    "const managementActionCopy = {",
                    '  revoke: ["撤销授权", "撤销会使授权和当前设备绑定失效，下一次验证生效。"],',
                    "};",
                    "function renderAuthorizationRiskRows(items) {",
                    "  row.dataset.deviceLicense = item.masked_code;",
                    "}",
                    'showToast(`版本已撤回。客户端将回退到 v${fallbackVersion}。审计记录已保留。`);',
                    'document.querySelector("[data-withdraw-confirm]");',
                    "releaseDialog?.addEventListener(\"close\", () => {",
                    "  releaseFileState = null;",
                    "});",
                    'const next = releaseDialog?.querySelector("[data-release-next]");',
                    'filteredButton.dataset.reclaimFiltered = "";',
                    "selectedButton.insertAdjacentElement(\"afterend\", filteredButton);",
                ]
            ),
        )
        self.assertTrue(any("sidebar-highlights-parent-not-current" in item for item in old_js))
        self.assertTrue(any("screen-target-not-delegated" in item for item in old_js))
        self.assertTrue(any("overview-attention-stays-hardcoded-empty" in item for item in old_js))
        self.assertTrue(any("overview-signal-label-stays-pending" in item for item in old_js))
        self.assertTrue(any("downstream-signal-label-stays-pending" in item for item in old_js))
        self.assertTrue(any("revoke-copy-missing-card-interval" in item for item in old_js))
        self.assertTrue(any("revoke-row-missing-verify-interval" in item for item in old_js))
        self.assertTrue(any("withdraw-toast-implies-uninstall" in item for item in old_js))
        self.assertTrue(any("withdraw-missing-installed-kept-copy" in item for item in old_js))
        self.assertTrue(any("release-close-does-not-discard-draft" in item for item in old_js))
        self.assertTrue(any("reclaim-filtered-inserted-in-filter-bar" in item for item in old_js))
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<button class="icon-button" type="button" title="搜索" aria-label="搜索" data-global-search>⌕</button>',
                    '<div class="rail-bottom"><p>服务端时间<br /><strong>—</strong></p></div>',
                    '<section class="screen" data-screen-panel="audit"><button data-storage-cleanup>清理</button></section>',
                    '<section class="screen" data-screen-panel="backup"><h1>备份</h1></section>',
                    '<section class="screen" data-screen-panel="releases"><h1>版本发布</h1></section>',
                    '<section class="screen" data-screen-panel="client"><h1>客户端运营</h1></section>',
                    '<dialog id="withdrawReleaseDialog"><button data-withdraw-confirm>确认撤回</button></dialog>',
                ]
            ),
        )
        self.assertTrue(any("header-missing-standalone-card-search" in item for item in old_manage))
        self.assertTrue(any("manage-rail-label-server-time" in item for item in old_manage))
        self.assertTrue(any("storage-cleanup-still-on-audit" in item for item in old_manage))
        self.assertTrue(any("storage-cleanup-missing-from-backup" in item for item in old_manage))
        self.assertTrue(any("releases-missing-external-update-copy" in item for item in old_manage))
        self.assertTrue(any("manage-missing-signing-key-copy" in item for item in old_manage))
        self.assertTrue(any("withdraw-missing-installed-kept-copy" in item for item in old_manage))
        old_down = _static_preview_findings(
            "downstream.html",
            '<input data-downstream-device-search placeholder="卡密 / 设备 / 软件 / 授权 ID" /><a data-quota-purchase-link>购买额度卡</a>',
        )
        self.assertTrue(any(token in item for item in old_down for token in ("device-search-placeholder-claims-card-code", "device-search-missing-unified-copy")))
        self.assertTrue(any("quota-purchase-missing-manual-redeem-note" in item for item in old_down))
        old_login = _static_preview_findings(
            "downstream-login.html",
            '<a data-quota-purchase-link href="#">购买额度卡</a>',
        )
        self.assertTrue(any("quota-purchase-missing-manual-redeem-note" in item for item in old_login))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in ("preview.css", "preview.js", "manage.html", "downstream.html", "downstream-login.html", "downstream-register.html"):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "nav-secondary-still-hidden",
            "sidebar-highlights-parent-not-current",
            "screen-target-not-delegated",
            "overview-attention-stays-hardcoded-empty",
            "overview-signal-label-stays-pending",
            "downstream-signal-label-stays-pending",
            "revoke-copy-missing-card-interval",
            "revoke-row-missing-verify-interval",
            "withdraw-toast-implies-uninstall",
            "withdraw-missing-installed-kept-copy",
            "release-close-does-not-discard-draft",
            "reclaim-filtered-inserted-in-filter-bar",
            "global-search-label-not-exact-card",
            "manage-rail-label-server-time",
            "storage-cleanup-still-on-audit",
            "storage-cleanup-missing-from-backup",
            "releases-missing-external-update-copy",
            "manage-missing-signing-key-copy",
            "device-search-placeholder-claims-card-code",
            "device-search-teaches-license-hmac",
            "quota-purchase-missing-manual-redeem-note",
            "signing-key-copy-missing-api",
            "header-missing-standalone-card-search",
            "js-missing-standalone-card-search",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))

    def test_frozen_preview_rejects_round9_register_success_and_fingerprint_contract(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "const isRegister = Boolean(form.elements.invitation_code);",
                    "window.location.href = response.redirect || form.dataset.previewDestination;",
                    "if (submit) submit.disabled = false;",
                ]
            ),
        )
        self.assertTrue(any("register-missing-inflight-guard" in item for item in old_js))
        self.assertTrue(any("register-success-jumps-without-copy" in item for item in old_js))
        self.assertTrue(any("register-success-still-finally-enable" in item for item in old_js))
        old_register = _static_preview_findings(
            "downstream-register.html",
            '<input name="password" type="password" required minlength="10" /><button>注册并进入工作台</button>',
        )
        self.assertTrue(any("register-password-rules-incomplete" in item for item in old_register))
        self.assertTrue(any("register-button-enters-workspace" in item for item in old_register))
        old_login = _static_preview_findings(
            "downstream-login.html",
            '<body class="preview-index access-preview"><h2>登录渠道工作台</h2></body>',
        )
        self.assertTrue(any("login-missing-register-success" in item for item in old_login))
        root = Path(__file__).resolve().parents[1]
        preview = root / "docs" / "ui-preview"
        live = []
        for filename in ("preview.js", "downstream-register.html", "downstream-login.html"):
            live.extend(_static_preview_findings(filename, (preview / filename).read_text(encoding="utf-8")))
        banned = (
            "register-missing-inflight-guard",
            "register-success-jumps-without-copy",
            "register-success-still-finally-enable",
            "register-password-rules-incomplete",
            "register-button-enters-workspace",
            "login-missing-register-success",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))
        django_register = (
            root / "src" / "authorization_platform" / "accounts" / "templates" / "accounts" / "register.html"
        ).read_text(encoding="utf-8")
        self.assertIn("注册并前往登录", django_register)
        self.assertNotIn("进入工作台", django_register)
        self.assertIn("field.help_text", django_register)
        form_src = (root / "src" / "authorization_platform" / "accounts" / "forms.py").read_text(encoding="utf-8")
        self.assertIn("至少 10 位", form_src)
        self.assertIn("不能全是数字", form_src)
        self.assertIn("常见密码", form_src)
        docs = root / "docs"
        for rel in ("API-CONTRACT.md", "DOMAIN-RULES.md", "CLIENT-INTEGRATION-HANDOFF.md"):
            text = (docs / rel).read_text(encoding="utf-8")
            self.assertIn("稳定主板/硬件指纹", text)
            self.assertIn("重装不得换值", text)
        api = (docs / "API-CONTRACT.md").read_text(encoding="utf-8")
        self.assertNotIn("| 客户端安装标识；必须被设备证明绑定", api)
        self.assertIn("都不是授权事实", api)
        security = (docs / "SECURITY-BASELINE.md").read_text(encoding="utf-8")
        self.assertIn("不能单独作为身份凭证", security)

    def test_acceptance_scripts_do_not_claim_production_proof_on_sqlite_signature_off(self):
        root = Path(__file__).resolve().parents[1]
        platform = (root / "scripts" / "platform-8123-acceptance.ps1").read_text(encoding="utf-8")
        frozen = (root / "scripts" / "frozen-8123-acceptance.ps1").read_text(encoding="utf-8")
        tests = (root / "scripts" / "test.ps1").read_text(encoding="utf-8")
        self.assertIn("not production verified-signature proof", platform)
        self.assertIn("RELEASE_REQUIRE_VERIFIED_SIGNATURE", platform)
        self.assertIn("not pagination drain proof", frozen)
        self.assertIn("not PostgreSQL concurrency", tests)

    def test_frozen_preview_requires_collection_page_drain(self):
        skipped = _static_preview_findings("preview.js", "async function loadCatalog() { await apiRequest('/manage/catalog/'); }")
        self.assertTrue(any("missing-fetch-all-collection-pages" in item for item in skipped))
        self.assertTrue(any("load-catalog-skips-pagination" in item for item in skipped))
        hollow_card = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function fetchAllCollectionPages(){}",
                    "options.pageSize || 100",
                    "options.maxPages || 20",
                    "async function loadCatalog() { await fetchAllCollectionPages('/manage/catalog/'); }",
                    "async function loadDownstreams() { await fetchAllCollectionPages('/manage/downstreams/'); }",
                    "extraQuery: { status }",
                    "async function loadPublishedReleases(softwareId) { return []; }",
                    "async function applyReleaseContext(softwareId) { return softwareId; }",
                    "function fillReleaseSignatureStatus(item) {}",
                    "async function loadReleasesForSoftware(softwareId, page = releasePage) { await apiRequest('/manage/releases/'); }",
                    "function catalogSoftwareForRelease(softwareId) { return null; }",
                    "function currentReclaimFilters(panel) { return { status: 'unused' }; }",
                    "function currentFilteredReclaimRows(panel) { return []; }",
                ]
            ),
        )
        self.assertTrue(any("release-context-skips-published-query" in item for item in hollow_card))
        self.assertTrue(any("published-release-loader-skips-pagination" in item for item in hollow_card))
        self.assertTrue(any("release-list-missing-generation" in item for item in hollow_card))
        self.assertTrue(any("reclaim-filters-missing-record-scope" in item for item in hollow_card))
        source = (Path(__file__).resolve().parents[1] / "docs" / "ui-preview" / "preview.js").read_text(encoding="utf-8")
        self.assertFalse(_static_preview_findings("preview.js", source))

    def test_candidate_archive_rejects_static_frontend_fixture_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "candidate.tar.gz"
            entries = _current_preview_archive_entries()
            name, payload, member_type = entries[1]
            entries[1] = (name, payload + b"\n<p>LIC-STALE-0001</p>\n", member_type)
            _write_preview_archive(archive_path, "tar", entries)
            checks = validate_candidate_archive(archive_path)
            self.assertEqual([item.status for item in checks], ["failed"])
            self.assertEqual(checks[0].name, "candidate_archive_no_static_fixtures")

    def test_candidate_archive_accepts_current_frozen_preview_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "candidate.tar.gz"
            root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name in ARCHIVE_PREVIEW_NAMES:
                    payload = (root / name).read_bytes()
                    info = tarfile.TarInfo(f"candidate/docs/ui-preview/{name}")
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            checks = validate_candidate_archive(archive_path)
            self.assertEqual([item.status for item in checks], ["passed"])

    def test_candidate_archive_reuses_backup_preview_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "candidate.tar.gz"
            root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name in ARCHIVE_PREVIEW_NAMES:
                    payload = (root / name).read_bytes()
                    if name == "manage.html":
                        payload = payload.replace(
                            b'name="schedule_enabled"',
                            b'name="removed_schedule_enabled"',
                            1,
                        )
                    elif name == "preview.js":
                        payload = payload.replace(
                            b"function collectBackupPolicy()",
                            b"function removedCollectBackupPolicy()",
                            1,
                        )
                    info = tarfile.TarInfo(f"candidate/docs/ui-preview/{name}")
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            checks = validate_candidate_archive(archive_path)
            self.assertEqual([item.status for item in checks], ["failed"])

    def test_candidate_tar_and_zip_reject_extra_and_duplicate_preview_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for archive_format, suffix in (("tar", ".tar.gz"), ("zip", ".zip")):
                with self.subTest(archive_format=archive_format, member="extra"):
                    archive_path = root / f"extra{suffix}"
                    entries = _current_preview_archive_entries()
                    entries.append(
                        (
                            "candidate/docs/ui-preview/old.html",
                            b"<p>LIC-EXTRA-0001</p>",
                            "file",
                        )
                    )
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])
                with self.subTest(archive_format=archive_format, member="duplicate"):
                    archive_path = root / f"duplicate{suffix}"
                    entries = [
                        (
                            "candidate/docs/ui-preview/manage.html",
                            b"<p>LIC-DUPLICATE-0001</p>",
                            "file",
                        ),
                        *_current_preview_archive_entries(),
                    ]
                    _write_preview_archive(archive_path, archive_format, entries)
                    checks = validate_candidate_archive(archive_path)
                    self.assertEqual([item.status for item in checks], ["failed"])
                    self.assertIn("结构不安全", checks[0].reason)

    def test_candidate_tar_and_zip_reject_non_regular_and_directory_preview_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for archive_format, suffix in (("tar", ".tar.gz"), ("zip", ".zip")):
                with self.subTest(archive_format=archive_format, member="symlink"):
                    archive_path = root / f"symlink{suffix}"
                    entries = [
                        item
                        for item in _current_preview_archive_entries()
                        if item[0].endswith("/manage.html")
                    ]
                    entries[0] = (entries[0][0], b"", "symlink")
                    entries = [
                        *[
                            item
                            for item in _current_preview_archive_entries()
                            if not item[0].endswith("/manage.html")
                        ],
                        *entries,
                    ]
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])
                with self.subTest(archive_format=archive_format, member="directory"):
                    archive_path = root / f"directory{suffix}"
                    entries = [
                        item
                        for item in _current_preview_archive_entries()
                        if not item[0].endswith("/manage.html")
                    ]
                    entries.append(("candidate/docs/ui-preview/manage.html", b"", "directory"))
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])

    def test_candidate_tar_and_zip_reject_encoded_static_marker_and_hidden_schedule_css(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for archive_format, suffix in (("tar", ".tar.gz"), ("zip", ".zip")):
                with self.subTest(archive_format=archive_format, case="html entity"):
                    archive_path = root / f"entity{suffix}"
                    entries = _current_preview_archive_entries()
                    name, payload, member_type = entries[1]
                    entries[1] = (name, payload + b"\n<p>LIC&#45;ENTITY-0001</p>\n", member_type)
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])
                with self.subTest(archive_format=archive_format, case="css hidden"):
                    archive_path = root / f"css-hidden{suffix}"
                    entries = _current_preview_archive_entries()
                    index = next(i for i, item in enumerate(entries) if item[0].endswith("/preview.css"))
                    name, payload, member_type = entries[index]
                    entries[index] = (
                        name,
                        payload + b'\n[data-screen-panel="backup"] .backup-schedule-settings { display: none; }\n',
                        member_type,
                    )
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])

    def test_candidate_tar_and_zip_reject_real_schedule_collector_removal_and_constant_false(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for archive_format, suffix in (("tar", ".tar.gz"), ("zip", ".zip")):
                with self.subTest(archive_format=archive_format, case="comment pseudo function"):
                    archive_path = root / f"comment{suffix}"
                    entries = _current_preview_archive_entries()
                    index = next(i for i, item in enumerate(entries) if item[0].endswith("/preview.js"))
                    name, payload, member_type = entries[index]
                    payload = payload.replace(
                        b"function collectBackupPolicy()",
                        b"function removedCollectBackupPolicy()",
                        1,
                    )
                    payload = b"/* function collectBackupPolicy() { form.elements.schedule_enabled; } */\n" + payload
                    entries[index] = (name, payload, member_type)
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])
                with self.subTest(archive_format=archive_format, case="constant false"):
                    archive_path = root / f"constant-false{suffix}"
                    entries = _current_preview_archive_entries()
                    index = next(i for i, item in enumerate(entries) if item[0].endswith("/preview.js"))
                    name, payload, member_type = entries[index]
                    payload = payload.replace(
                        b"schedule_enabled: Boolean(form.elements.schedule_enabled?.checked)",
                        b"schedule_enabled: form.elements.schedule_enabled ? false : false",
                        1,
                    )
                    entries[index] = (name, payload, member_type)
                    _write_preview_archive(archive_path, archive_format, entries)
                    self.assertEqual([item.status for item in validate_candidate_archive(archive_path)], ["failed"])

    def test_release_candidate_cli_requires_explicit_archive_or_source_only(self):
        with self.assertRaises(SystemExit) as raised:
            release_candidate_main(["--root", str(Path(__file__).resolve().parents[1])])
        self.assertEqual(raised.exception.code, 2)

    def test_candidate_archive_rejects_missing_frozen_page(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "candidate.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name in ARCHIVE_PREVIEW_NAMES[:-1]:
                    payload = b"<html><body></body></html>" if name.endswith(".html") else b""
                    info = tarfile.TarInfo(f"candidate/docs/ui-preview/{name}")
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            checks = validate_candidate_archive(archive_path)
            self.assertEqual([item.status for item in checks], ["failed"])

    def test_candidate_zip_archive_accepts_current_frozen_preview_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "candidate.zip"
            root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name in ARCHIVE_PREVIEW_NAMES:
                    payload = (root / name).read_bytes()
                    archive.writestr(f"candidate/docs/ui-preview/{name}", payload)
            checks = validate_candidate_archive(archive_path)
            self.assertEqual([item.status for item in checks], ["passed"])

    def test_frozen_content_rejects_unlisted_business_row(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ARCHIVE_PREVIEW_NAMES:
                payload = "<html><body></body></html>" if name.endswith(".html") else ""
                (root / name).write_text(payload, encoding="utf-8")
            (root / "manage.html").write_text(
                "<html><body><table><tbody><tr><td>Unlisted Product</td></tr></tbody></table></body></html>",
                encoding="utf-8",
            )
            checks = validate_frozen_page_content(root)
            self.assertEqual([item.status for item in checks], ["failed"])

    def test_docker_candidate_isolated_from_legacy_and_uses_scoped_object_store_user(self):
        root = Path(__file__).resolve().parents[1]
        compose = (root / "deploy" / "docker-compose.production.yml.example").read_text(encoding="utf-8")
        compose_env = (root / "deploy" / "compose.env.example").read_text(encoding="utf-8")
        policy = json.loads((root / "deploy" / "object-store-policy.json").read_text(encoding="utf-8"))
        dockerfile = (root / "deploy" / "Dockerfile").read_text(encoding="utf-8")
        requirements = (root / "requirements.lock").read_text(encoding="utf-8")
        self.assertIn("authorization-platform-candidate-db", compose)
        self.assertIn("object-store-init", compose)
        self.assertIn("command:\n      - >-", compose)
        self.assertIn("condition: service_completed_successfully", compose)
        self.assertIn("127.0.0.1:${APP_HOST_PORT:-8000}:8000", compose)
        self.assertIn("server --certs-dir /certs", compose)
        self.assertIn("OBJECT_STORAGE_CA_CERT: /app/object-store-ca.crt", compose)
        self.assertIn("https://object-store:9000", compose)
        self.assertNotIn("deploy-db-1", compose)
        self.assertIn('"s3:GetObject"', json.dumps(policy))
        self.assertNotIn('"s3:*"', json.dumps(policy))
        self.assertIn("python:3.12-slim-bookworm", dockerfile)
        self.assertIn("postgresql-client-17", dockerfile)
        self.assertNotIn("postgresql-client \\", dockerfile)
        restore_doc = (root / "部署与恢复" / "03-新VPS怎么装怎么导备份.md").read_text(encoding="utf-8")
        self.assertIn("postgresql-client-17", restore_doc)
        self.assertIn("pg_restore --version", restore_doc)
        self.assertIn("gunicorn==26.1.0", requirements)
        self.assertRegex(compose_env, re.compile(r"^POSTGRES_IMAGE_REF=.*@sha256:[0-9a-f]{64}$", re.MULTILINE))
        self.assertRegex(compose_env, re.compile(r"^MINIO_IMAGE_REF=.*@sha256:[0-9a-f]{64}$", re.MULTILINE))
        self.assertRegex(compose_env, re.compile(r"^MINIO_MC_IMAGE_REF=.*@sha256:[0-9a-f]{64}$", re.MULTILINE))
        self.assertRegex(compose_env, re.compile(r"^PYTHON_IMAGE_REF=.*@sha256:[0-9a-f]{64}$", re.MULTILINE))

    def test_isolated_runner_uses_real_shared_rate_limit_probe(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "isolated-postgresql-backup-restore-acceptance.ps1").read_text(encoding="utf-8")
        self.assertIn("shared_rate_limit_probe.py", source)
        self.assertIn("shared-worker-rate-limit.json", source)
        self.assertIn("seed_recovery_fixture", source)
        self.assertIn("recovery_inventory", source)
        self.assertIn("ExpectedBackupSha256", source)
        self.assertNotIn("shared_worker_probe.py", source)

    def test_backup_restore_candidate_is_fail_closed_and_binds_source_inventory_artifact(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "postgresql-backup-restore.ps1").read_text(encoding="utf-8")
        runner = (root / "scripts" / "isolated-postgresql-backup-restore-acceptance.ps1").read_text(encoding="utf-8")
        self.assertIn("restore 模式必须提供 ExpectedBackupSha256", source)
        self.assertIn("restore_cleanup_status", source)
        self.assertIn("failure_stage", source)
        self.assertIn('status = "failed"', source)
        self.assertIn("$sourceInventoryArtifact", runner)
        self.assertIn("--compare $sourceInventoryArtifact", runner)
        self.assertNotIn("--allow-same-database", runner)
        collector = (root / "scripts" / "backup_evidence_collector.py").read_text(encoding="utf-8")
        self.assertIn('"--compare", compare_path', collector)
        self.assertNotIn('"--allow-same-database"', collector)
        self.assertNotIn("'--allow-same-database'", collector)
        self.assertIn("BACKUP_OBJECT_STORAGE_LIST", collector)
        self.assertIn("object-manifest-not-object-storage", collector)
        self.assertIn("recovery-ciphertext-not-verified", collector)
        self.assertNotIn("find /var/lib/postgresql/data", collector)
        services = (root / "src" / "authorization_platform" / "backup_control" / "services.py").read_text(encoding="utf-8")
        self.assertIn("--single-transaction", services)
        secrets = (root / "deploy" / "backup" / "secrets_runner.sh").read_text(encoding="utf-8")
        self.assertIn("production.env missing", secrets)
        self.assertIn("github token missing or empty", secrets)
        self.assertNotIn("authorization-platform-candidate-380c59a", secrets)
        self.assertNotIn(r"D:\vps-password", secrets)
        code_runner = (root / "deploy" / "backup" / "code_runner.sh").read_text(encoding="utf-8")
        self.assertIn("app source missing", code_runner)
        self.assertNotIn("authorization-platform-candidate-380c59a", code_runner)
        backup_runner = (root / "deploy" / "backup" / "backup_runner.sh").read_text(encoding="utf-8")
        self.assertIn('"$PYTHON_BIN" "$BACKUP_PROOF_GENERATOR"', backup_runner)
        self.assertIn('"$PYTHON_BIN" "$BACKUP_EVIDENCE_COLLECTOR"', backup_runner)
        self.assertNotIn('if [ -x "$BACKUP_PROOF_GENERATOR" ]', backup_runner)
        self.assertNotIn('if [ -x "$BACKUP_EVIDENCE_COLLECTOR" ]', backup_runner)
        self.assertIn("github dump pass missing or empty", backup_runner)
        self.assertIn("BACKUP_DUMP_PASS_FILE", backup_runner)
        self.assertIn("DATABASE_NAME", backup_runner)
        self.assertIn("DATABASE_USER", backup_runner)
        self.assertIn("BACKUP_STANZA", backup_runner)
        self.assertIn('if [ -L "$GH_DUMP_PASS" ] || [ ! -f "$GH_DUMP_PASS" ] || [ ! -s "$GH_DUMP_PASS" ]; then', backup_runner)
        self.assertLess(backup_runner.find('if [ -L "$GH_DUMP_PASS" ]'), backup_runner.find("openssl enc"))
        self.assertIn('"source": "${DB_CONTAINER}"', backup_runner)
        self.assertNotIn("authorization-platform-candidate-380c59a", backup_runner)
        self.assertIn("部署与恢复/灾备钥匙包", backup_runner)
        self.assertNotIn(r"D:\vps-password", backup_runner)

    @override_settings(
        OBJECT_STORAGE_PROVIDER="s3-compatible",
        OBJECT_STORAGE_ENDPOINT="http://objects.internal:9000",
        OBJECT_STORAGE_BUCKET="authorization-platform",
        OBJECT_STORAGE_REGION="internal-1",
        OBJECT_STORAGE_ACCESS_KEY_ID="access-id",
        OBJECT_STORAGE_SECRET_ACCESS_KEY="object-secret",
    )
    def test_remote_provider_never_falls_back_to_local_release_or_cleanup(self):
        self.assertIsNone(resolve_release_package_path("releases/example.zip"))
        with self.assertRaises(ReleaseOperationError):
            _ensure_local_storage_adapter()
        self.assertIsInstance(configured_object_store(), S3ObjectStore)

    def test_frozen_preview_rejects_dingdang_round2_entry_layout_and_sandbox(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<link rel="stylesheet" href="preview.css?v=layout-11" />',
                    '<script src="preview.js?v=layout-6"></script>',
                ]
            ),
        )
        self.assertTrue(any("preview-cache-stamp-split" in item for item in old_manage))
        old_login = _static_preview_findings("manage-login.html", '<form data-preview-destination="manage.html" novalidate>')
        self.assertTrue(any("login-form-missing-post-method" in item for item in old_login))
        old_css = _static_preview_findings(
            "preview.css",
            "\n".join(
                [
                    ".credential-filter-bar { flex-wrap: nowrap; }",
                    ".credential-filter-bar { flex-wrap: wrap; padding: 10px; }",
                    ".modal-actions { position: sticky; bottom: 0; }",
                ]
            ),
        )
        self.assertTrue(any("credential-filter-bar-wraps" in item for item in old_css))
        self.assertTrue(any("issue-result-sticky-covers-codes" in item for item in old_css))
        old_down = _static_preview_findings(
            "downstream.html",
            '<aside class="client-mockup-window"><div class="client-mockup-app-title">AutoPilot</div></aside>',
        )
        self.assertTrue(any("support-keeps-client-mockup-sandbox" in item for item in old_down))
        with tempfile.TemporaryDirectory() as directory:
            extra = Path(directory) / "auto_login_downstream.html"
            extra.write_text("<html></html>", encoding="utf-8")
            extra_findings = _extra_preview_page_findings(Path(directory))
        self.assertTrue(any("capture-bridge-page" in item for item in extra_findings))
        self.assertTrue(any("extra-frozen-html" in item for item in extra_findings))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in (
            "preview.css",
            "preview.js",
            "manage.html",
            "manage-login.html",
            "downstream.html",
            "downstream-login.html",
            "downstream-register.html",
        ):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "preview-cache-stamp-split",
            "login-form-missing-post-method",
            "credential-filter-bar-wraps",
            "issue-result-sticky-covers-codes",
            "support-keeps-client-mockup-sandbox",
            "AutoPilot",
            "XXXX-XXXX-XXXX-XXXX-XXXX",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))
        self.assertFalse(_extra_preview_page_findings(root))

    def test_frozen_preview_rejects_dingdang_round3_credits_backup_and_restore(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function clearCreditRuntimeData() {",
                    '  applyQuotaPurchaseLink("", { fallback: false });',
                    "}",
                    "function applyBackupDashboard(payload) {",
                    '  healthNode.textContent = staleOnly ? "上次验收已过期" : "上次证明异常";',
                    "}",
                    'panel.querySelector("[data-backup-restore-inspect]");',
                    "if (applyButton) applyButton.disabled = false;",
                ]
            ),
        )
        self.assertTrue(any("credit-get-failure-clears-purchase-link" in item for item in old_js))
        self.assertTrue(any("backup-disabled-stale-still-says-expired" in item for item in old_js))
        self.assertTrue(any("restore-enables-apply-before-copied-time" in item for item in old_js))
        old_manage = _static_preview_findings(
            "manage.html",
            '<button class="button button-danger" type="button" data-backup-restore-apply>确认导入</button>',
        )
        self.assertTrue(any("restore-apply-not-disabled-by-default" in item for item in old_manage))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in ("preview.js", "manage.html"):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "credit-get-failure-clears-purchase-link",
            "backup-disabled-stale-still-says-expired",
            "restore-enables-apply-before-copied-time",
            "restore-apply-not-disabled-by-default",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))

    def test_frozen_preview_rejects_dingdang_round4_release_and_client_config(self):
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    'releaseDialog?.querySelector("[data-release-confirm]")?.addEventListener("click", async (event) => {',
                    "  event.currentTarget.disabled = true;",
                    "  await apiRequest('/manage/releases/1/publish/');",
                    "  event.currentTarget.disabled = false;",
                    "});",
                    "async function loadReleasesForSoftware(softwareId, page = 1) {",
                    "  try { await apiRequest('/manage/releases/'); }",
                    "  catch (requestError) {",
                    "    showRuntimeReadError('[data-screen-panel=\"releases\"]', '版本列表暂时无法读取。');",
                    "    throw requestError;",
                    "  }",
                    "}",
                    "function catalogSoftwareForRelease(softwareId) { return null; }",
                    'clientContextEl?.addEventListener("change", (event) => {',
                    "  if (event.target.value) loadClientProfileConfig(event.target.value);",
                    "});",
                    "function applyClientConfig(payload) {",
                    "  if (!payload) {",
                    '    publish.textContent = "待读取";',
                    "    return;",
                    "  }",
                    '  publish.textContent = "待读取";',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("release-confirm-currenttarget-reset-lost" in item for item in old_js))
        self.assertTrue(any("release-list-failure-skips-context" in item for item in old_js))
        self.assertTrue(any("client-context-change-keeps-previous-announcement" in item for item in old_js))
        self.assertTrue(any("client-config-payload-still-pending-badge" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = _static_preview_findings("preview.js", (root / "preview.js").read_text(encoding="utf-8"))
        banned = (
            "release-confirm-currenttarget-reset-lost",
            "release-list-failure-skips-context",
            "client-context-change-keeps-previous-announcement",
            "client-config-payload-still-pending-badge",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))

    def test_frozen_preview_rejects_dingdang_round5_audit_overview_and_hide(self):
        old_manage = _static_preview_findings(
            "manage.html",
            "\n".join(
                [
                    '<section class="screen" data-screen-panel="overview">',
                    '<article class="signal signal-credits"><span>额度净消耗</span><span class="signal-label">全平台合计</span>',
                    '<strong data-overview-metric="credits">—</strong></article>',
                    "</section>",
                ]
            ),
        )
        self.assertTrue(any("overview-credits-missing-30d-window" in item for item in old_manage))
        old_js = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "function renderOverviewCards(payload) {",
                    '  overview.querySelector(".signal-credits .signal-label").textContent = "全平台合计";',
                    "}",
                    "if (revealed) {",
                    "  full.textContent = maskCredential(credentialDialog.dataset.fullCode || 'CODE');",
                    '  showToast("完整码已重新隐藏。");',
                    "  return;",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("overview-credits-js-drops-30d-window" in item for item in old_js))
        self.assertTrue(any("credential-hide-keeps-dom-plaintext" in item for item in old_js))
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in ("preview.js", "manage.html"):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "overview-credits-missing-30d-window",
            "overview-credits-js-drops-30d-window",
            "credential-hide-keeps-dom-plaintext",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))

    def test_frozen_preview_rejects_dingdang_round6_gates_and_device_search(self):
        stale_catch = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadClientProfileConfig(softwareId) {",
                    "  const generation = ++clientConfigLoadGeneration;",
                    "  try { await apiRequest('/manage/software/x'); }",
                    "  catch (requestError) { applyClientConfig(null); }",
                    "}",
                ]
            ),
        )
        self.assertTrue(any("client-config-catch-ignores-generation" in item for item in stale_catch))
        hmac_devices = _static_preview_findings(
            "preview.js",
            "\n".join(
                [
                    "async function loadDownstreamDevices(page = 1) {",
                    '  const query = rawSearch ? await resolveTableSearchQuery(rawSearch, "license") : "";',
                    "}",
                ]
            ),
        )
        self.assertTrue(any("device-search-js-still-hmacs-license" in item for item in hmac_devices))
        old_down = _static_preview_findings(
            "downstream.html",
            '<input data-downstream-device-search placeholder="软件、套餐、设备码，或粘完整卡密" />',
        )
        self.assertTrue(any("device-search-teaches-license-hmac" in item for item in old_down))
        missing_header = _static_preview_findings("manage.html", "<header class='app-header'></header>")
        self.assertTrue(any("header-missing-standalone-card-search" in item for item in missing_header))
        missing_js = _static_preview_findings("preview.js", "function installLogout(session) {}")
        self.assertTrue(any("js-missing-standalone-card-search" in item for item in missing_js))
        empty_payload = _empty_archive_preview_payload("manage.html")
        self.assertNotIn(b"data-page-label", empty_payload)
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        live = []
        for filename in ("preview.js", "manage.html", "downstream.html"):
            live.extend(_static_preview_findings(filename, (root / filename).read_text(encoding="utf-8")))
        banned = (
            "client-config-catch-ignores-generation",
            "device-search-js-still-hmacs-license",
            "device-search-teaches-license-hmac",
            "header-missing-standalone-card-search",
            "js-missing-standalone-card-search",
        )
        self.assertFalse(any(any(token in item for token in banned) for item in live))
    def test_activation_requires_health_and_rollback_restores_previous_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            first = Path(directory) / "candidate-one"
            second = Path(directory) / "candidate-two"
            first.mkdir()
            second.mkdir()
            (first / "app.txt").write_text("one", encoding="utf-8")
            (second / "app.txt").write_text("two", encoding="utf-8")
            with self.assertRaises(RollbackError):
                activate_candidate(root, first, "v1", health_verified=False)
            activate_candidate(root, first, "v1", health_verified=True)
            activate_candidate(root, second, "v2", health_verified=True)
            self.assertEqual(read_state(root)["active"]["version"], "v2")
            restored = rollback_candidate(root)
            self.assertEqual(restored["active"]["version"], "v1")

    def test_rollback_rejects_tampered_previous_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            first = Path(directory) / "candidate-one"
            second = Path(directory) / "candidate-two"
            first.mkdir()
            second.mkdir()
            (first / "app.txt").write_text("one", encoding="utf-8")
            (second / "app.txt").write_text("two", encoding="utf-8")
            activate_candidate(root, first, "v1", health_verified=True)
            activate_candidate(root, second, "v2", health_verified=True)
            (first / "app.txt").write_text("tampered", encoding="utf-8")
            with self.assertRaises(RollbackError):
                rollback_candidate(root)


class CapacityProbeTests(SimpleTestCase):
    def test_probe_reports_latency_statuses_and_429_without_network(self):
        results = [
            ProbeResult(status_code=200, elapsed_ms=10.0, error=None),
            ProbeResult(status_code=200, elapsed_ms=20.0, error=None),
            ProbeResult(status_code=429, elapsed_ms=30.0, error=None),
        ]
        with patch("scripts.capacity_probe._request", side_effect=results):
            report = run_probe("http://127.0.0.1/healthz/", requests=3, concurrency=2)
        self.assertEqual(report["requests"], 3)
        self.assertEqual(report["http_429"], 1)
        self.assertEqual(report["transport_errors"], 0)
        self.assertIsNotNone(report["latency_ms"]["p95"])

    def test_capacity_evaluation_rejects_unexpected_status_and_slo_breach(self):
        report = {
            "requests": 3,
            "status_counts": {"200": 2, "429": 1},
            "http_429": 1,
            "transport_errors": 0,
            "latency_ms": {"p95": 1200.0},
        }
        acceptance = evaluate_capacity(report)
        self.assertFalse(acceptance["accepted"])
        self.assertEqual(acceptance["failure_reasons"], ["http_429", "unexpected_status", "p95_latency"])

    def test_capacity_thresholds_bind_registry_identity_and_run_all_targets(self):
        root = Path(__file__).resolve().parents[1]
        thresholds = json.loads((root / "deploy" / "capacity-thresholds.json").read_text(encoding="utf-8"))
        registry = next(item for item in thresholds["targets"] if item["name"] == "skinforge_release_registry")
        self.assertIn("client_id=skinforge-windows", registry["path"])
        self.assertIn("target=windows", registry["path"])
        self.assertIn("arch=x86_64", registry["path"])
        self.assertIn("channel=stable", registry["path"])

        reports = [
            {"requests": 2, "status_counts": {"200": 2}, "http_429": 0, "transport_errors": 0, "latency_ms": {"p95": 10.0}},
            {"requests": 2, "status_counts": {"200": 2}, "http_429": 0, "transport_errors": 0, "latency_ms": {"p95": 20.0}},
            {"requests": 2, "status_counts": {"200": 2}, "http_429": 0, "transport_errors": 0, "latency_ms": {"p95": 30.0}},
        ]
        with patch("scripts.capacity_threshold_acceptance.run_probe", side_effect=reports):
            result = run_thresholds("https://candidate.example", root / "deploy" / "capacity-thresholds.json", requests_override=2, concurrency_override=1)
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["targets"]), 3)
        self.assertTrue(result["targets"][2]["url"].endswith("channel=stable"))


class MigrationRecoveryTests(SimpleTestCase):
    def test_unstarted_migration_can_return_to_previous_application(self):
        plan = migration_recovery_plan(migration_started=False, backup_verified=False, schema_compatible=False)
        self.assertEqual(plan["action"], "rollback_application_checkpoint")

    def test_partial_migration_without_backup_stops(self):
        plan = migration_recovery_plan(migration_started=True, backup_verified=False, schema_compatible=False)
        self.assertEqual(plan["action"], "stop_and_escalate")

    def test_incompatible_partial_migration_requires_isolated_restore(self):
        plan = migration_recovery_plan(migration_started=True, backup_verified=True, schema_compatible=False)
        self.assertEqual(plan["action"], "restore_isolated_then_forward_fix")
