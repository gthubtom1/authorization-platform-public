"""Read-only release-candidate checks for the central authorization platform.

This module intentionally validates contracts instead of connecting to a
production service.  It can be imported by tests and run locally to produce a
safe JSON summary.  Secret values are never returned, logged, or hashed.
"""

from __future__ import annotations

import argparse
import base64
from functools import lru_cache
import hashlib
from html.parser import HTMLParser
from html import unescape
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authorization_platform.core.backup_governance import validate_backup_environment  # noqa: E402


FROZEN_PAGE_NAMES = (
    "entry.html",
    "manage.html",
    "manage-login.html",
    "downstream.html",
    "downstream-login.html",
    "downstream-register.html",
    "404.html",
)

PRODUCTION_SECRET_NAMES = (

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


def _valid_ed25519_public_key(value: str) -> bool:
    if not value:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if len(raw) != 32:
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError, base64.binascii.Error):
        return False
    return True


STATIC_PREVIEW_MARKERS = (
    "LIC-",
    "INV-",
    "QUOTA-",
    "Alpha Desktop",
    "Beta Studio",
    "Gamma Tools",
    "渠道 A",
    "渠道 B",
    "渠道北区",
    "support@example",
    "portal.example",
    "shop.example",
    "new-software",
    "profile-new-",
    "data-static-code-key",
    "data-fixture",
    "data-demo",
    "AutoPilot",
    "XXXX-XXXX-XXXX-XXXX-XXXX",
)

ARCHIVE_PREVIEW_NAMES = (*FROZEN_PAGE_NAMES, "preview.js", "preview.css")
ARCHIVE_BUSINESS_ATTRIBUTES = (
    "data-public-id",
    "data-generated",
    "data-static-code-key",
    "data-downstream-row",
    "data-device-row",
    "data-release-id",
    "data-catalog-software-id",
)
LIVE_PREVIEW_NAMES = {
    "manage.html",
    "manage-login.html",
    "downstream.html",
    "downstream-login.html",
    "downstream-register.html",
    "preview.js",
}
ARCHIVE_METRIC_PATTERN = re.compile(
    r"<[^>]*data-(?:overview-metric|revenue-metric|analytics-metric|downstream-metric)=[^>]*>\s*([^<]*)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    reason: str


def _check(name: str, passed: bool, reason: str) -> Check:
    return Check(name=name, status="passed" if passed else "failed", reason=reason)


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def validate_production_environment(env: Mapping[str, str] | None = None) -> list[Check]:
    """Validate fail-closed production configuration without exposing values."""

    values = _env(env)
    checks: list[Check] = []
    checks.append(_check("environment", values.get("APP_ENV", "").strip().lower() == "production", "APP_ENV 必须为 production。"))
    checks.append(_check("debug", values.get("DJANGO_DEBUG", "").strip().lower() in {"0", "false", "no", "off"}, "DJANGO_DEBUG 必须显式关闭。"))
    hosts = [item.strip() for item in values.get("ALLOWED_HOSTS", "").split(",") if item.strip()]
    checks.append(_check("allowed_hosts", bool(hosts) and "*" not in hosts and not any(item in {"localhost", "127.0.0.1"} for item in hosts), "ALLOWED_HOSTS 必须是显式生产域名。"))
    origins = [item.strip().lower() for item in values.get("CSRF_TRUSTED_ORIGINS", "").split(",") if item.strip()]
    checks.append(_check("csrf_origins", bool(origins) and all(item.startswith("https://") for item in origins), "CSRF_TRUSTED_ORIGINS 必须全部使用 HTTPS。"))
    proxy_ips = [item.strip() for item in values.get("TRUSTED_PROXY_IPS", "").split(",") if item.strip()]
    checks.append(_check("trusted_proxy", bool(proxy_ips) and values.get("TRUST_PROXY_SSL_HEADER", "").strip().lower() in {"1", "true", "yes", "on"}, "必须显式配置可信代理网段和 HTTPS forwarded 头。"))
    checks.append(_check("redirect", values.get("SECURE_SSL_REDIRECT", "").strip().lower() in {"1", "true", "yes", "on"}, "SECURE_SSL_REDIRECT 必须开启。"))
    try:
        hsts = int(values.get("SECURE_HSTS_SECONDS", "0"))
    except ValueError:
        hsts = 0
    checks.append(_check("hsts", hsts >= 31_536_000 and values.get("SECURE_HSTS_INCLUDE_SUBDOMAINS", "").strip().lower() in {"1", "true", "yes", "on"}, "HSTS 必须至少一年并覆盖子域。"))
    checks.append(_check("database", values.get("DATABASE_ENGINE", "").strip().lower() == "postgresql", "生产数据库必须是 PostgreSQL。"))
    required_database = ("DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_HOST", "DATABASE_PORT")
    missing_database = [name for name in required_database if not values.get(name)]
    checks.append(_check("database_settings", not missing_database, "数据库连接参数必须完整。" if not missing_database else "缺少数据库连接参数。"))
    backend = values.get("DJANGO_CACHE_BACKEND", "").strip()
    checks.append(_check("shared_cache", bool(backend) and "locmem" not in backend.lower(), "生产不得使用 LocMemCache，必须使用共享后端。"))
    try:
        workers = int(values.get("AUTHORIZATION_PLATFORM_WORKERS", "0"))
    except ValueError:
        workers = 0
    checks.append(_check("worker_count", workers >= 2, "生产至少需要两个应用 Worker。"))

    secret_values = {name: values.get(name, "") for name in PRODUCTION_SECRET_NAMES}
    missing_secrets = [name for name, value in secret_values.items() if not value]
    checks.append(_check("production_secrets_present", not missing_secrets, "生产密钥合同完整。" if not missing_secrets else "缺少生产密钥配置。"))
    unique_values = [value for value in secret_values.values() if value]
    independent = bool(values.get("DJANGO_SECRET_KEY")) and all(value != values.get("DJANGO_SECRET_KEY") for value in unique_values) and len(unique_values) == len(set(unique_values))
    checks.append(_check("production_secrets_independent", independent, "生产密钥必须彼此独立且不能复用 Django SECRET_KEY。"))
    checks.append(_check("signing_key_id", bool(values.get("AUTHORIZATION_SIGNING_KEY_ID")) and values.get("AUTHORIZATION_SIGNING_KEY_ID") != "platform-dev-v1", "授权签名 key id 必须指向托管生产版本。"))
    checks.append(_check("release_signature_enforced", values.get("RELEASE_REQUIRE_VERIFIED_SIGNATURE", "").strip().lower() in {"1", "true", "yes", "on"}, "生产版本发布不得关闭 verified 签名强制。"))
    checks.append(_check("release_download_anonymous", values.get("RELEASE_DOWNLOAD_REQUIRE_AUTH", "").strip().lower() not in {"1", "true", "yes", "on"}, "生产本站安装包谁都能下，不得再强制卡密下载。"))
    release_key_id = values.get("RELEASE_SIGNING_KEY_ID", "").strip()
    checks.append(_check("release_signing_key_id", bool(release_key_id) and release_key_id != "release-dev-v1", "生产版本发布必须绑定托管签名 Key ID。"))
    checks.append(_check("release_public_key", _valid_ed25519_public_key(values.get("RELEASE_SIGNING_PUBLIC_KEY", "")), "生产版本发布必须配置有效的 Ed25519 公钥。"))

    provider = values.get("OBJECT_STORAGE_PROVIDER", "").strip().lower()
    object_fields = ("OBJECT_STORAGE_ENDPOINT", "OBJECT_STORAGE_BUCKET", "OBJECT_STORAGE_REGION", "OBJECT_STORAGE_ACCESS_KEY_ID", "OBJECT_STORAGE_SECRET_ACCESS_KEY")
    object_ready = provider in {"s3", "s3-compatible"} and all(values.get(name) for name in object_fields)
    checks.append(_check("object_storage", object_ready, "生产必须使用已配置的 S3 兼容对象存储。"))
    checks.append(_check("object_storage_https", values.get("OBJECT_STORAGE_ENDPOINT", "").strip().lower().startswith("https://"), "生产对象存储 endpoint 必须使用 HTTPS。"))
    checks.extend(validate_backup_environment(values))
    return checks


def validate_nginx_config(path: Path) -> list[Check]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [_check("reverse_proxy_config", False, f"无法读取反向代理配置：{exc.__class__.__name__}。")]
    root_location = re.search(r"location\s*=\s*/\s*\{(?P<body>.*?)\n\s*\}", text, re.DOTALL)
    root_body = root_location.group("body") if root_location else ""
    root_path_404 = (
        bool(re.search(r"\breturn\s+404\s*;", root_body))
        and not bool(re.search(r"try_files\s+/entry\.html", root_body))
        and not bool(re.search(r"try_files\s+/404\.html", root_body))
    )
    root_path_custom_404 = bool(re.search(r"error_page\s+404\s+/404\.html\s*;", root_body))
    custom_404_page_location = bool(re.search(r"location\s*=\s*/404\.html\s*\{", text))
    checks = [
        _check("root_path_404", root_path_404, "域名根路径必须直接返回 404，不得分流到 entry.html。"),
        _check("root_path_custom_404", root_path_custom_404, "根路径 404 必须改写为自定义页，不得只回库存 HTML。"),
        _check("custom_404_page_location", custom_404_page_location, "必须能按 /404.html 取出自定义页。"),
        _check("tls_listener", "listen 443 ssl" in text, "必须存在 HTTPS 监听。"),
        _check("tls_versions", "ssl_protocols TLSv1.2 TLSv1.3" in text, "只允许 TLS 1.2/1.3。"),
        _check("hsts_header", "Strict-Transport-Security" in text, "必须返回 HSTS。"),
        _check("http_redirect", "return 301 https://$host$request_uri" in text, "HTTP 必须重定向到 HTTPS。"),
        _check("trusted_proto_forward", "proxy_set_header X-Forwarded-Proto $scheme" in text, "必须转发代理协议。"),
        _check("trusted_for_forward", "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for" in text, "必须转发客户端地址链。"),
        _check("internal_upstream", (
            "proxy_pass http://127.0.0.1:8000" in text
            or "proxy_pass http://127.0.0.1:18002" in text
        ), "Django 只能作为内部回环上游（127.0.0.1，非默认 8000 端口可防默认入侵面）。"),
        _check("no_8143", "8143" not in text, "不得创建 8143 页面入口。"),
        _check("no_runserver", "runserver" not in text.lower(), "生产代理配置不能把 runserver 当作应用进程。"),
    ]
    for page in FROZEN_PAGE_NAMES:
        checks.append(_check(f"frozen_page:{page}", page in text, f"必须保留冻结页面 {page}。"))
    return checks


def validate_frozen_pages(root: Path) -> list[Check]:
    return [_check(f"frozen_page_file:{page}", (root / page).is_file(), f"缺少冻结页面 {page}。") for page in FROZEN_PAGE_NAMES]


def _js_brace_body(source: str, open_at: int) -> str:
    masked = _js_mask_non_code(source, mask_strings=True)
    if open_at < 0 or open_at >= len(source) or masked[open_at] != "{":
        return ""
    depth = 0
    index = open_at
    while index < len(source):
        character = masked[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[open_at + 1 : index]
        index += 1
    return ""


@lru_cache(maxsize=16)
def _js_mask_non_code(source: str, *, mask_strings: bool) -> str:
    """Mask comments and, optionally, quoted literals without changing offsets."""
    masked = list(source)
    state = "code"
    quote = ""
    index = 0

    def blank(position: int) -> None:
        if source[position] not in "\r\n":
            masked[position] = " "

    while index < len(source):
        character = source[index]
        if state == "line_comment":
            if character in "\r\n":
                state = "code"
            else:
                blank(index)
            index += 1
            continue
        if state == "block_comment":
            if character == "*" and index + 1 < len(source) and source[index + 1] == "/":
                blank(index)
                blank(index + 1)
                index += 2
                state = "code"
            else:
                blank(index)
                index += 1
            continue
        if state == "string":
            if character == "\\":
                if mask_strings:
                    blank(index)
                index += 1
                if index < len(source):
                    if mask_strings:
                        blank(index)
                    index += 1
                continue
            if character == quote:
                if mask_strings:
                    blank(index)
                index += 1
                state = "code"
                quote = ""
                continue
            if mask_strings:
                blank(index)
            index += 1
            continue
        if character == "/" and index + 1 < len(source):
            next_character = source[index + 1]
            if next_character == "/":
                blank(index)
                blank(index + 1)
                index += 2
                state = "line_comment"
                continue
            if next_character == "*":
                blank(index)
                blank(index + 1)
                index += 2
                state = "block_comment"
                continue
        if character in {'"', "'", "`"}:
            quote = character
            if mask_strings:
                blank(index)
            index += 1
            state = "string"
            continue
        index += 1
    return "".join(masked)


def _strip_js_comments(source: str) -> str:
    return _js_mask_non_code(source, mask_strings=False)


def _js_try_bodies(source: str) -> list[str]:
    masked = _js_mask_non_code(source, mask_strings=True)
    bodies: list[str] = []
    search_from = 0
    while True:
        match = re.search(r"\btry\s*\{", masked[search_from:])
        if not match:
            break
        brace = search_from + match.end() - 1
        bodies.append(_js_brace_body(source, brace))
        search_from = brace + 1
    return bodies


def _js_function_body(source: str, marker: str) -> str:
    start = _js_mask_non_code(source, mask_strings=True).find(marker)
    if start < 0:
        return ""
    brace = source.find("{", start)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _js_function_body_skip_signature(source: str, marker: str) -> str:
    masked = _js_mask_non_code(source, mask_strings=True)
    start = masked.find(marker)
    if start < 0:
        return ""
    paren = masked.find("(", start)
    if paren < 0 or paren > start + 120:
        return _js_function_body(source, marker)
    depth = 0
    index = paren
    while index < len(source):
        character = masked[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                brace = masked.find("{", index)
                return _js_brace_body(source, brace) if brace >= 0 else ""
        index += 1
    return ""


def _js_event_listener_body(source: str, selector: str, event_name: str) -> str:
    cleaned = _strip_js_comments(source)
    pattern = re.compile(
        rf"\bquerySelector\(\s*[\"']{re.escape(selector)}[\"']\s*\)\s*\??\.\s*"
        rf"addEventListener\(\s*[\"']{re.escape(event_name)}[\"']\s*,"
    )
    match = pattern.search(cleaned)
    if not match:
        return ""
    brace = cleaned.find("{", match.end())
    return _js_brace_body(cleaned, brace) if brace >= 0 else ""


def _ensure_table_state_body(source: str) -> str:
    return _js_function_body(source, "function ensureTableState")


def _ledger_table_panel_is_server_paginated(source: str, attr: str) -> bool:
    pos = source.find(attr)
    if pos < 0:
        return False
    opening = source.rfind("<section", 0, pos)
    while opening >= 0:
        tag_end = source.find(">", opening)
        if tag_end < 0:
            return False
        tag = source[opening : tag_end + 1]
        if "table-panel" in tag:
            return 'data-server-paginated="true"' in tag
        opening = source.rfind("<section", 0, opening)
    return False


def _ledger_render_marks_server_data_loaded(body: str) -> bool:
    if not body:
        return False
    loaded_at = -1
    for token in (
        'dataset.serverDataLoaded = "true"',
        "dataset.serverDataLoaded = 'true'",
        'serverDataLoaded = "true"',
        "serverDataLoaded = 'true'",
    ):
        pos = body.find(token)
        if pos >= 0:
            loaded_at = pos if loaded_at < 0 else min(loaded_at, pos)
    refresh_at = body.find("__previewRefreshTables")
    return (
        loaded_at >= 0
        and refresh_at >= 0
        and loaded_at < refresh_at
        and ".table-panel" in body
    )


def _redeem_click_handler_body(source: str) -> str:
    marker = "querySelector('[data-success-screen=\"ledger\"]')"
    start = source.find(marker)
    if start < 0:
        return ""
    listener = source.find('addEventListener("click"', start)
    if listener < 0:
        return ""
    arrow = source.find("=>", listener)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace)


def _software_save_handler_body(source: str) -> str:
    marker = 'querySelector("[data-software-save]")'
    start = source.find(marker)
    if start < 0:
        return ""
    listener = source.find('addEventListener("click"', start)
    if listener < 0:
        return ""
    arrow = source.find("=>", listener)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _password_change_handler_body(source: str) -> str:
    marker = 'querySelector("[data-password-change-submit]")'
    start = source.find(marker)
    if start < 0:
        return ""
    listener = source.find('addEventListener("click"', start)
    if listener < 0:
        return ""
    arrow = source.find("=>", listener)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _withdraw_confirm_handler_body(source: str) -> str:
    marker = 'querySelector("[data-withdraw-confirm]")'
    start = source.find(marker)
    if start < 0:
        return ""
    listener = source.find('addEventListener("click"', start)
    if listener < 0:
        return ""
    arrow = source.find("=>", listener)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _release_next_handler_body(source: str) -> str:
    marker = 'releaseNext?.addEventListener("click"'
    start = source.find(marker)
    if start < 0:
        return ""
    arrow = source.find("=>", start)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _support_save_handler_body(source: str) -> str:
    marker = 'querySelector("[data-support-save]")'
    start = source.find(marker)
    if start < 0:
        return ""
    listener = source.find('addEventListener("click"', start)
    if listener < 0:
        return ""
    arrow = source.find("=>", listener)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _management_action_pause_copy(source: str) -> str:
    start = source.find("const managementActionCopy")
    if start < 0:
        return ""
    brace = source.find("{", start)
    body = _js_brace_body(source, brace) if brace >= 0 else ""
    match = re.search(r'pause:\s*\[\s*"[^"]*"\s*,\s*"([^"]*)"\s*\]', body)
    return match.group(1) if match else ""


def _management_action_reset_copy(source: str) -> str:
    start = source.find("const managementActionCopy")
    if start < 0:
        return ""
    brace = source.find("{", start)
    body = _js_brace_body(source, brace) if brace >= 0 else ""
    match = re.search(r'reset:\s*\[\s*"[^"]*"\s*,\s*"([^"]*)"\s*\]', body)
    return match.group(1) if match else ""


def _management_action_block_copy(source: str) -> str:
    start = source.find("const managementActionCopy")
    if start < 0:
        return ""
    brace = source.find("{", start)
    body = _js_brace_body(source, brace) if brace >= 0 else ""
    match = re.search(r'block:\s*\[\s*"[^"]*"\s*,\s*"([^"]*)"\s*\]', body)
    return match.group(1) if match else ""


def _management_action_unblock_copy(source: str) -> str:
    start = source.find("const managementActionCopy")
    if start < 0:
        return ""
    brace = source.find("{", start)
    body = _js_brace_body(source, brace) if brace >= 0 else ""
    match = re.search(r'unblock:\s*\[\s*"[^"]*"\s*,\s*"([^"]*)"\s*\]', body)
    return match.group(1) if match else ""


def _management_action_archive_copy(source: str) -> str:
    start = source.find("const managementActionCopy")
    if start < 0:
        return ""
    brace = source.find("{", start)
    body = _js_brace_body(source, brace) if brace >= 0 else ""
    match = re.search(r'archive:\s*\[\s*"[^"]*"\s*,\s*"([^"]*)"\s*\]', body)
    return match.group(1) if match else ""


def _management_action_delete_copy(source: str) -> str:
    start = source.find("const managementActionCopy")
    if start < 0:
        return ""
    brace = source.find("{", start)
    body = _js_brace_body(source, brace) if brace >= 0 else ""
    match = re.search(r'delete:\s*\[\s*"[^"]*"\s*,\s*"([^"]*)"\s*\]', body)
    return match.group(1) if match else ""


def _storage_cleanup_open_handler_body(source: str) -> str:
    marker = 'storageExecuteButton?.addEventListener("click"'
    start = source.find(marker)
    if start < 0:
        return ""
    arrow = source.find("=>", start)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace) if brace >= 0 else ""


def _js_event_listener_body(source: str, marker: str, event: str) -> str:
    start = source.find(marker)
    if start < 0:
        return ""
    needle = f'addEventListener("{event}"'
    alt = f"addEventListener('{event}'"
    search_from = start
    end_limit = min(len(source), start + 8000)
    while search_from < end_limit:
        listener = source.find(needle, search_from, end_limit)
        if listener < 0:
            listener = source.find(alt, search_from, end_limit)
        if listener < 0:
            return ""
        arrow = source.find("=>", listener)
        if 0 <= arrow - listener <= 120:
            brace = source.find("{", arrow)
            if 0 <= brace - arrow <= 40:
                return _js_brace_body(source, brace)
        search_from = listener + 1
    return ""


def _js_finally_bodies(source: str) -> list[str]:
    bodies: list[str] = []
    search_from = 0
    while True:
        match = re.search(r"\bfinally\s*\{", source[search_from:])
        if not match:
            break
        brace = search_from + match.end() - 1
        bodies.append(_js_brace_body(source, brace))
        search_from = brace + 1
    return bodies


def _quota_revoke_confirm_handler_body(source: str) -> str:
    marker = "[data-quota-revoke-confirm]"
    start = source.find(marker)
    if start < 0:
        return ""
    listener = source.find('addEventListener("click"', start)
    if listener < 0:
        return ""
    arrow = source.find("=>", listener)
    if arrow < 0:
        return ""
    brace = source.find("{", arrow)
    return _js_brace_body(source, brace)


def _invitation_rows_body(source: str) -> str:
    return _js_function_body_skip_signature(source, "function renderInvitationRows")


def _quota_card_rows_body(source: str) -> str:
    marker = "function renderQuotaCardRows"
    start = source.find(marker)
    if start < 0:
        return ""
    token = "= {}) {"
    pos = source.find(token, start)
    if pos >= 0:
        return _js_brace_body(source, pos + len(token) - 1)
    header_end = source.find(") {", start)
    if header_end < 0:
        return ""
    return _js_brace_body(source, header_end + 2)


def _license_card_rows_body(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        return ""
    token = "= {}) {"
    pos = source.find(token, start)
    if pos >= 0 and pos < start + 160:
        return _js_brace_body(source, pos + len(token) - 1)
    return _js_function_body(source, marker)


def _license_scope_block(source: str, scope: str) -> str:
    marker = f'data-record-view-scope="{scope}"'
    start = source.find(marker)
    if start < 0:
        return ""
    next_scope = source.find("data-record-view-scope=", start + len(marker))
    next_screen = source.find('data-screen-panel="', start + len(marker))
    ends = [index for index in (next_scope, next_screen) if index > start]
    end = min(ends) if ends else len(source)
    return source[start:end]


def _screen_panel_block(source: str, panel: str) -> str:
    marker = f'data-screen-panel="{panel}"'
    start = source.find(marker)
    if start < 0:
        return ""
    next_screen = source.find('data-screen-panel="', start + len(marker))
    end = next_screen if next_screen > start else len(source)
    return source[start:end]


def _risk_screen_block(source: str) -> str:
    start = source.find('data-screen-panel="risk"')
    if start < 0:
        return ""
    next_screen = source.find('data-screen-panel="', start + len('data-screen-panel="risk"'))
    end = next_screen if next_screen > start else len(source)
    return source[start:end]


def _extract_open_tag_block(source: str, start: int) -> str:
    match = re.match(r"<([a-zA-Z0-9:-]+)([^>]*)>", source[start:])
    if not match:
        return source[start:]
    tag = match.group(1)
    if match.group(2).rstrip().endswith("/"):
        return match.group(0)
    pos = start + match.end()
    depth = 1
    for token in re.finditer(rf"<{tag}\b[^>]*>|</{tag}\s*>", source[pos:], re.IGNORECASE):
        raw = token.group(0)
        if raw.lower().startswith("</"):
            depth -= 1
            if depth == 0:
                return source[start : pos + token.end()]
        elif not raw.rstrip().endswith("/>"):
            depth += 1
    return source[start:]


def _backup_screen_block(source: str) -> str:
    match = re.search(
        r'<section\b[^>]*\bdata-screen-panel=["\']backup["\'][^>]*>',
        source,
        re.IGNORECASE,
    )
    if not match:
        return ""
    return _extract_open_tag_block(source, match.start())


class _BackupControlParser(HTMLParser):
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.controls: list[tuple[dict[str, str | None], bool]] = []
        self._hidden_depth = 0
        self._backup_form_depth = 0
        self._stack: list[tuple[str, bool, bool]] = []

    @staticmethod
    def _is_hidden(attrs: dict[str, str | None]) -> bool:
        classes = set((attrs.get("class") or "").split())
        style = re.sub(r"\s+", "", (attrs.get("style") or "").lower())
        return (
            "hidden" in attrs
            or "hidden" in classes
            or bool(re.search(r"(?:display:none|visibility:hidden)", style))
            or (attrs.get("aria-hidden") or "").lower() == "true"
        )

    def _record_start(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = dict(attrs)
        hidden = self._hidden_depth > 0 or self._is_hidden(normalized)
        if tag == "input" and self._backup_form_depth > 0 and normalized.get("name"):
            self.controls.append((normalized, hidden))
        is_backup_form = tag == "form" and "data-backup-form" in normalized
        if tag not in self._VOID_TAGS:
            self._stack.append((tag, hidden, is_backup_form))
            if hidden:
                self._hidden_depth += 1
            if is_backup_form:
                self._backup_form_depth += 1

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record_start(tag.lower(), attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record_start(tag.lower(), attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] != tag:
                continue
            for _, hidden, is_backup_form in self._stack[index:]:
                if hidden:
                    self._hidden_depth -= 1
                if is_backup_form:
                    self._backup_form_depth = max(0, self._backup_form_depth - 1)
            del self._stack[index:]
            return


def _backup_form_controls(source: str) -> dict[str, tuple[dict[str, str | None], bool]]:
    parser = _BackupControlParser()
    try:
        parser.feed(source)
        parser.close()
    except (AssertionError, ValueError):
        return {}
    controls: dict[str, tuple[dict[str, str | None], bool]] = {}
    for attrs, hidden in parser.controls:
        name = attrs.get("name")
        if name and name not in controls:
            controls[name] = (attrs, hidden)
    return controls


def _backup_work_panel_block(block: str, panel: str) -> str:
    marker = f'data-work-panel="{panel}"'
    start = block.find(marker)
    if start < 0:
        return ""
    next_panel = block.find("data-work-panel=", start + len(marker))
    end = next_panel if next_panel > start else len(block)
    return block[start:end]


def _backup_tab_labels(block: str) -> list[str]:
    labels: list[str] = []
    for match in re.finditer(
        r"<button\b([^>]*)>([\s\S]*?)</button\s*>",
        block,
        re.IGNORECASE,
    ):
        attrs, inner = match.group(1), match.group(2)
        if "data-work-view=" not in attrs:
            continue
        if 'role="tab"' not in attrs and "role='tab'" not in attrs:
            continue
        text = re.sub(r"<[^>]+>", "", inner)
        labels.append(re.sub(r"\s+", "", text))
    return labels


def _backup_restore_apply_type(block: str) -> str | None:
    match = re.search(r"<button\b[^>]*\bdata-backup-restore-apply\b[^>]*>", block, re.IGNORECASE)
    if not match:
        return None
    type_match = re.search(r'\btype=["\']([^"\']+)["\']', match.group(0), re.IGNORECASE)
    return type_match.group(1).lower() if type_match else ""


def _backup_page_heading_block(block: str) -> str:
    marker = 'class="page-heading"'
    hit = block.find(marker)
    if hit < 0:
        return ""
    open_div = block.rfind("<div", 0, hit)
    if open_div < 0:
        return ""
    i = open_div
    depth = 0
    while i < len(block):
        next_open = block.find("<div", i)
        next_close = block.find("</div>", i)
        if next_close < 0:
            return block[open_div:]
        if next_open >= 0 and next_open < next_close:
            depth += 1
            i = next_open + 4
            continue
        depth -= 1
        i = next_close + 6
        if depth == 0:
            return block[open_div:i]
    return block[open_div:]


def _append_backup_screen_findings(name: str, source: str, findings: list[str]) -> None:
    backup = _backup_screen_block(source)
    if not backup:
        return
    panels = re.findall(r'data-work-panel="([^"]+)"', backup)
    if panels != ["records", "downloads", "restore"]:
        findings.append(f"{name}:backup-screen-not-record-download-tabs")
    if "data-backup-run" in _backup_page_heading_block(backup):
        findings.append(f"{name}:backup-page-heading-keeps-run-buttons")
    shell_start = backup.find("work-view-shell")
    settings = backup[:shell_start] if shell_start > 0 else backup
    records = _backup_work_panel_block(backup, "records")
    downloads = _backup_work_panel_block(backup, "downloads")
    restore = _backup_work_panel_block(backup, "restore")
    if 'data-backup-form' not in settings:
        findings.append(f"{name}:backup-settings-missing-form")
    if "备份总开关" not in settings:
        findings.append(f"{name}:backup-settings-missing-master-switch")
    if "同时拷到 GitHub" not in settings:
        findings.append(f"{name}:backup-settings-missing-github-switch")
    controls = _backup_form_controls(settings)
    schedule_control = controls.get("schedule_enabled")
    full_time_control = controls.get("full_time")
    diff_interval_control = controls.get("diff_interval_hours")
    if schedule_control is None:
        findings.append(f"{name}:backup-settings-missing-schedule-switch")
    elif schedule_control[1]:
        findings.append(f"{name}:backup-settings-schedule-switch-hidden")
    elif (schedule_control[0].get("type") or "").lower() != "checkbox":
        findings.append(f"{name}:backup-settings-schedule-switch-not-checkbox")
    elif "disabled" in schedule_control[0]:
        findings.append(f"{name}:backup-settings-schedule-switch-disabled")
    if full_time_control is None:
        findings.append(f"{name}:backup-settings-missing-full-time")
    elif full_time_control[1]:
        findings.append(f"{name}:backup-settings-full-time-hidden")
    else:
        attrs = full_time_control[0]
        if (attrs.get("type") or "").lower() != "time":
            findings.append(f"{name}:backup-settings-full-time-not-time-input")
        if attrs.get("min") != "00:00" or attrs.get("max") != "23:59":
            findings.append(f"{name}:backup-settings-full-time-missing-range")
        if "required" not in attrs:
            findings.append(f"{name}:backup-settings-full-time-not-required")
        if "disabled" in attrs or (attrs.get("aria-disabled") or "").lower() == "true":
            findings.append(f"{name}:backup-settings-full-time-disabled")
    if diff_interval_control is None:
        findings.append(f"{name}:backup-settings-missing-diff-interval")
    elif diff_interval_control[1]:
        findings.append(f"{name}:backup-settings-diff-interval-hidden")
    else:
        attrs = diff_interval_control[0]
        if (attrs.get("type") or "").lower() != "number":
            findings.append(f"{name}:backup-settings-diff-interval-not-number-input")
        if attrs.get("min") != "1" or attrs.get("max") != "24" or attrs.get("step") != "1":
            findings.append(f"{name}:backup-settings-diff-interval-missing-range")
        if "required" not in attrs:
            findings.append(f"{name}:backup-settings-diff-interval-not-required")
        if "disabled" in attrs or (attrs.get("aria-disabled") or "").lower() == "true":
            findings.append(f"{name}:backup-settings-diff-interval-disabled")
    if 'data-backup-run="full"' not in settings:
        findings.append(f"{name}:backup-settings-missing-full-run")
    if "现在备份" not in settings:
        findings.append(f"{name}:backup-settings-missing-queued-full")
    if "data-backup-probe" not in settings:
        findings.append(f"{name}:backup-settings-missing-probe")
    if "上次备份结果" not in settings:
        findings.append(f"{name}:backup-settings-missing-last-result-copy")
    if _backup_restore_apply_type(backup) != "button":
        findings.append(f"{name}:backup-restore-apply-not-type-button")
    if _backup_tab_labels(backup) != ["备份记录", "下载加密备份", "导入备份"]:
        findings.append(f"{name}:backup-tabs-missing-record-download-labels")
    if "立即全量备份" in backup or "立即增量备份" in backup:
        findings.append(f"{name}:backup-run-still-says-immediate")
    if "排队增量备份" in backup:
        findings.append(f"{name}:backup-page-keeps-diff-run")
    if "坚果云" in backup or "Cloudflare R2" in backup or "网盘类型" in backup:
        findings.append(f"{name}:backup-page-keeps-netdisk-ui")
    if "上次程序" in backup:
        findings.append(f"{name}:backup-last-result-still-says-program")
    if "还没有备份记录" not in records:
        findings.append(f"{name}:backup-runs-missing-empty-copy")
    if "还没有可下载的加密包" not in downloads:
        findings.append(f"{name}:backup-downloads-missing-empty-copy")
    if "当前条件没有匹配的记录。" in records:
        findings.append(f"{name}:backup-tables-use-generic-empty")
    if "列表里是完整加密库" not in downloads:
        findings.append(f"{name}:backup-downloads-missing-full-dump-note")
    if "将覆盖当前库，包括管理员" not in restore:
        findings.append(f"{name}:backup-restore-missing-overwrite-warning")
    if "抄上面的北京时间，不要抄文件名" not in restore:
        findings.append(f"{name}:backup-restore-missing-copy-beijing-time")
    if "口令不在网页上，在密钥包/服务器口令文件" not in restore:
        findings.append(f"{name}:backup-restore-missing-passphrase-location")
    if re.search(r'class="[^"]*connection-note', downloads):
        findings.append(f"{name}:backup-downloads-keeps-amber-note")
    if re.search(r'class="[^"]*connection-note', restore):
        findings.append(f"{name}:backup-restore-keeps-amber-note")
    if "没有软件、下游和卡密" in backup or "只有软件、下游和卡密" in backup:
        findings.append(f"{name}:backup-empty-site-still-three-item")
    cleanup_copy = ""
    panel_match = re.search(r"<h2>\s*存储清理\s*</h2>[\s\S]{0,800}?</section>", backup)
    if panel_match:
        cleanup_copy += panel_match.group(0)
    if "过期安装包" in cleanup_copy:
        findings.append(f"{name}:storage-cleanup-copy-says-expired-packages")
    if cleanup_copy and (".enc" not in cleanup_copy or "不含" not in cleanup_copy):
        findings.append(f"{name}:storage-cleanup-copy-omits-enc-exclusion")
    dialog = re.search(r'id=["\']storageCleanupDialog["\'][\s\S]*?</dialog>', source)
    if dialog:
        dialog_copy = dialog.group(0)
        if "过期安装包" in dialog_copy:
            findings.append(f"{name}:storage-cleanup-dialog-says-expired-packages")
        if ".enc" not in dialog_copy or "不含" not in dialog_copy:
            findings.append(f"{name}:storage-cleanup-dialog-omits-enc-exclusion")
    if 'id="backupDownloadDeleteDialog"' not in source and "data-backup-download-table" in source:
        findings.append(f"{name}:backup-download-delete-dialog-missing")


def _append_backup_preview_js_findings(
    name: str,
    source: str,
    findings: list[str],
    *,
    strict: bool = False,
) -> None:
    if name != "preview.js":
        return
    if "s3_r2" in source or "webdav_jianguoyun" in source or "netdisk_preset" in source:
        findings.append(f"{name}:backup-script-keeps-netdisk-ui")
    if "立即备份已排队" in source or "立即备份先排队" in source or "立即备份没有受理" in source:
        findings.append(f"{name}:backup-js-still-says-immediate")
    if "当前没有软件、下游和卡密" in source:
        findings.append(f"{name}:backup-js-empty-site-still-three-item")
    collect = _js_function_body(source, "function collectBackupPolicy")
    if strict and not collect:
        findings.append(f"{name}:backup-js-collect-policy-missing")
    if collect:
        collect_code = _js_mask_non_code(collect, mask_strings=True)
        if re.search(r"schedule_enabled\s*:\s*false", collect):
            findings.append(f"{name}:backup-js-schedule-hardcoded-off")
        if "form.elements.schedule_enabled" not in collect:
            findings.append(f"{name}:backup-js-missing-schedule-switch")
        elif strict and not re.search(
            r"schedule_enabled\s*:\s*(?:Boolean\s*\(\s*|!!\s*)"
            r"form\.elements\.schedule_enabled\s*(?:\?\.)?checked",
            collect_code,
        ):
            findings.append(f"{name}:backup-js-schedule-switch-not-read")
        if "form.elements.full_time" not in collect:
            findings.append(f"{name}:backup-js-missing-full-time")
        elif strict and not re.search(
            r"full_time\s*:\s*String\s*\(\s*form\.elements\.full_time\s*(?:\?\.)?value",
            collect_code,
        ):
            findings.append(f"{name}:backup-js-full-time-not-read")
        if "form.elements.diff_interval_hours" not in collect:
            findings.append(f"{name}:backup-js-missing-diff-interval")
        elif strict and not re.search(
            r"diff_interval_hours\s*:\s*String\s*\(\s*form\.elements\.diff_interval_hours\s*(?:\?\.)?value",
            collect_code,
        ):
            findings.append(f"{name}:backup-js-diff-interval-not-read")
        if re.search(r"github_retention_count\s*:\s*", collect):
            findings.append(f"{name}:backup-js-collects-retention-without-control")
    if strict:
        apply_policy = _js_function_body(source, "function applyBackupPolicy")
        if not apply_policy:
            findings.append(f"{name}:backup-js-apply-policy-missing")
        else:
            apply_code = _strip_js_comments(apply_policy)
            if 'assignCheck("schedule_enabled"' not in apply_code:
                findings.append(f"{name}:backup-js-apply-missing-schedule-switch")
            if 'assignValue("full_time"' not in apply_code:
                findings.append(f"{name}:backup-js-apply-missing-full-time")
            if 'assignValue("diff_interval_hours"' not in apply_code:
                findings.append(f"{name}:backup-js-apply-missing-diff-interval")
            if "policy.github_retention_count" not in apply_code:
                findings.append(f"{name}:backup-js-retention-not-from-policy")
            if re.search(r"__backupDownloadRetention\s*=\s*3", apply_code):
                findings.append(f"{name}:backup-js-retention-hardcoded-three")
        dashboard = _js_function_body(source, "function applyBackupDashboard")
        if not dashboard:
            findings.append(f"{name}:backup-js-dashboard-missing")
        else:
            dashboard_code = _strip_js_comments(dashboard)
            if "applyBackupPolicy(policy)" not in dashboard_code:
                findings.append(f"{name}:backup-js-dashboard-skips-policy-apply")
            if "policy.github_retention_count" not in dashboard_code:
                findings.append(f"{name}:backup-js-dashboard-retention-not-from-policy")
            if "policy.github_retention_count ?? 3" in dashboard_code:
                findings.append(f"{name}:backup-js-retention-hardcoded-three")
        load = _js_function_body(source, "async function loadAdminBackup")
        if not load:
            findings.append(f"{name}:backup-js-load-dashboard-missing")
        else:
            load_code = _strip_js_comments(load)
            if (
                not re.search(
                    r"apiRequest\(\s*[\"']/manage/backup/[\"']\s*,\s*\{[\s\S]{0,160}?"
                    r"method\s*:\s*[\"']GET[\"']",
                    load_code,
                )
                or "applyBackupDashboard(payload)" not in load_code
            ):
                findings.append(f"{name}:backup-js-load-dashboard-unwired")
            if not re.search(r"setBackupPolicyLoadState\(\s*false\s*\)", load_code) or not re.search(
                r"setBackupPolicyLoadState\(\s*true\s*\)", load_code
            ):
                findings.append(f"{name}:backup-js-load-does-not-fail-closed")
        load_state = _js_function_body(source, "function setBackupPolicyLoadState")
        if not load_state:
            findings.append(f"{name}:backup-js-policy-load-state-missing")
        else:
            load_state_code = _strip_js_comments(load_state)
            if "backupPolicyLoaded" not in load_state_code or "button.disabled = !backupPolicyLoaded" not in load_state_code:
                findings.append(f"{name}:backup-js-policy-load-state-incomplete")
    install = _js_function_body(source, "function installAdminBackup")
    if strict and not install:
        findings.append(f"{name}:backup-js-install-missing")
    if install:
        install_code = _strip_js_comments(install)
        if "/manage/backup/destinations/probe/" not in install_code:
            findings.append(f"{name}:backup-js-missing-destination-probe")
        if re.search(r"data-backup-probe[\s\S]{0,800}/manage/backup/runs/", install_code):
            findings.append(f"{name}:backup-js-probe-posts-backup-run")
        if strict:
            submit = _js_event_listener_body(install, "[data-backup-form]", "submit")
            if not submit:
                findings.append(f"{name}:backup-js-save-listener-missing")
            submit_code = _strip_js_comments(submit)
            if not re.search(r"apiRequest\(\s*[\"']/manage/backup/[\"']\s*,", submit_code):
                findings.append(f"{name}:backup-js-save-missing-api")
            if not re.search(r'method\s*:\s*["\']POST["\']', submit_code):
                findings.append(f"{name}:backup-js-save-missing-post")
            if "JSON.stringify(collectBackupPolicy())" not in submit_code:
                findings.append(f"{name}:backup-js-save-missing-policy-payload")
            if "applyBackupDashboard(payload)" not in submit_code:
                findings.append(f"{name}:backup-js-save-skips-response-apply")
            if "if (!backupPolicyLoaded)" not in submit_code:
                findings.append(f"{name}:backup-js-save-does-not-require-loaded-policy")
    render_runs = _js_function_body(source, "function renderBackupRuns")
    if render_runs and "还没有备份记录" not in render_runs:
        findings.append(f"{name}:backup-js-runs-missing-empty-copy")
    render_downloads = _js_function_body(source, "function renderBackupDownloads")
    if render_downloads and "还没有可下载的加密包" not in render_downloads:
        findings.append(f"{name}:backup-js-downloads-missing-empty-copy")
    if render_downloads and "data-backup-download-delete" not in render_downloads:
        findings.append(f"{name}:backup-downloads-missing-delete-action")
    if "function installAdminBackup" in source and "/delete/" not in source:
        findings.append(f"{name}:backup-js-missing-download-delete-api")
    if "function installAdminBackup" in source and '"confirmed": true' not in source and "confirmed: true" not in source:
        findings.append(f"{name}:backup-js-delete-missing-confirmed")
    if "已扫描" in source and "storage/cleanup" in source and "不含下载表" not in source and "不含" not in source:
        findings.append(f"{name}:storage-cleanup-toast-omits-enc-exclusion")
    if "function ensureTableState" in source and "当前条件没有匹配的记录。" not in source:
        findings.append(f"{name}:backup-js-global-empty-copy-missing")


def _append_backup_preview_css_findings(name: str, source: str, findings: list[str]) -> None:
    if name != "preview.css":
        return
    for match in re.finditer(r"(?P<selectors>[^{}]+)\{(?P<body>[^{}]*)\}", source):
        selectors = match.group("selectors")
        body = match.group("body")
        if ".backup-schedule-settings" not in selectors:
            continue
        if re.search(r"\bdisplay\s*:\s*none\b|\bvisibility\s*:\s*hidden\b", body, re.IGNORECASE):
            findings.append(f"{name}:backup-schedule-fields-hidden-by-css")
            break


def _append_round6_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "manage.html":
        client_dialog = re.search(r'id=["\']clientConfigDialog["\'][\s\S]*?</dialog>', source)
        if client_dialog:
            block = client_dialog.group(0)
            if 'name="purchase_url"' in block or 'name="support_email"' in block or "可见模块" in block:
                findings.append(f"{name}:client-config-dialog-keeps-fake-fields")
        if "data-quota-purchase-settings" in source:
            if "额度卡购买链接" in source or "给下游买额度" not in source:
                findings.append(f"{name}:quota-purchase-heading-not-downstream-site")
        if "代下游生成授权卡密" in source:
            findings.append(f"{name}:manage-keeps-proxy-issue-dialog")
        if re.search(r'id=["\']revokeDialog["\']', source):
            findings.append(f"{name}:manage-keeps-dead-revoke-dialog")
        if "全平台授权卡密" in source and "发卡在下游工作台" not in source:
            findings.append(f"{name}:licenses-heading-missing-issue-on-downstream")
        admin_reclaim = re.search(r'id=["\']adminReclaimDialog["\'][\s\S]*?</dialog>', source)
        if admin_reclaim and "回收后客户手里的码立即作废" not in admin_reclaim.group(0):
            findings.append(f"{name}:admin-reclaim-missing-void-copy")
    if name == "downstream.html":
        if "data-support-purchase" in source:
            if "购买额度卡网站" in source or "给你客户看" not in source:
                findings.append(f"{name}:downstream-support-label-not-customer-facing")
        reclaim = re.search(r'id=["\']reclaimDialog["\'][\s\S]*?</dialog>', source)
        if reclaim:
            block = reclaim.group(0)
            if "回收后客户手里的码立即作废" not in block:
                findings.append(f"{name}:downstream-reclaim-missing-void-copy")
            if 'name="reason"' not in block:
                findings.append(f"{name}:downstream-reclaim-missing-reason")
        issue = re.search(r'id=["\']issueDialog["\'][\s\S]*?</dialog>', source)
        if issue and "新卡密" not in issue.group(0):
            findings.append(f"{name}:issue-rules-missing-new-card-copy")
        detail = re.search(r'id=["\']credentialDetailDialog["\'][\s\S]*?</dialog>', source)
        if detail and "新卡密" not in detail.group(0):
            findings.append(f"{name}:card-expiry-missing-new-card-copy")
    if name == "downstream.html" and re.search(r">续期<|>延期<", source):
        # 下游只能看到“续期由平台做”的说明，不得出现自己给自己加时间的入口。
        findings.append(f"{name}:downstream-renew-entry")
    if name in {"manage.html", "downstream.html", "preview.js"}:
        if re.search(r"/licenses/[^\"'\s]*/(?:extend|renew)/", source):
            findings.append(f"{name}:renew-through-license-card-route")
    if name == "manage.html":
        renew_dialog = re.search(r'id=["\']renewAuthorizationDialog["\'][\s\S]*?</dialog>', source)
        if renew_dialog:
            block = renew_dialog.group(0)
            if "已激活且未过期" not in block:
                findings.append(f"{name}:renew-dialog-missing-active-only-copy")
            if "额度流水" not in block:
                findings.append(f"{name}:renew-dialog-missing-no-ledger-copy")
    if name != "preview.js":
        return
    apply_config = _js_function_body(source, "function applyClientConfig")
    if apply_config and "data-client-support" in apply_config and (
        "cfg.qq" in apply_config or "cfg.purchase_url" in apply_config
    ):
        findings.append(f"{name}:client-config-summary-paints-profile-support")
    config_idx = source.find("/profiles/${encodeURIComponent(profileId)}/configuration/")
    if config_idx >= 0:
        chunk = source[config_idx : config_idx + 900]
        if "purchase_url" in chunk or re.search(r"\bqq:", chunk):
            findings.append(f"{name}:client-config-post-sends-customer-support")
    if re.search(r'selection:\s*"filtered"', source):
        findings.append(f"{name}:reclaim-confirm-live-requeries-filters")
    reclaim_idx = source.find("[data-reclaim-confirm]")
    if reclaim_idx >= 0:
        chunk = source[reclaim_idx : reclaim_idx + 2200]
        if 'activateScreen("ledger"' in chunk:
            findings.append(f"{name}:reclaim-success-jumps-to-ledger")
    match_preview = _js_function_body(source, "function licensePreviewMatchesCurrent")
    if match_preview and "expiresAt" not in match_preview:
        findings.append(f"{name}:license-preview-match-ignores-expiry")
    if 'issueDialog.dataset.generatedCodes = "[]"' in source and "请先复制" not in source:
        findings.append(f"{name}:issue-close-clears-codes-without-copy-prompt")
    if "额度和数据没有改变" in source and "可能已经发出" not in source:
        findings.append(f"{name}:issue-unknown-outcome-omits-maybe-issued")
    render_plans = _js_function_body(source, "function renderPlanCatalog")
    if render_plans:
        dialog_idx = render_plans.find('dataset.dialog = "issueDialog"')
        if dialog_idx < 0:
            dialog_idx = render_plans.find("dataset.dialog = 'issueDialog'")
        admin_idx = render_plans.find("role-admin")
        if dialog_idx >= 0 and (admin_idx < 0 or dialog_idx < admin_idx):
            findings.append(f"{name}:admin-cannot-issue-still-opens-issue-dialog")


def _dialog_block(source: str, dialog_id: str) -> str:
    match = re.search(rf'id=["\']{re.escape(dialog_id)}["\'][\s\S]*?</dialog>', source)
    return match.group(0) if match else ""


def _append_round7_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "manage.html":
        create_dialog = _dialog_block(source, "softwareDialog")
        if create_dialog:
            if "每日换机次数" not in create_dialog or "softwareAllowSwitch" not in create_dialog:
                findings.append(f"{name}:catalog-create-missing-switch-fields")
            if "满员时允许新电脑挤掉旧电脑" not in create_dialog:
                findings.append(f"{name}:catalog-create-missing-switch-fields")
            if re.search(r'id=["\']softwarePlanCost["\'][^>]*min=["\']0["\']', create_dialog):
                findings.append(f"{name}:create-plan-cost-allows-zero")
        policy_dialog = _dialog_block(source, "policyDialog")
        if policy_dialog and ("已售跟着变" not in policy_dialog or "已售不跟" not in policy_dialog):
            findings.append(f"{name}:policy-dialog-missing-sold-follow-copy")
        unlist_dialog = _dialog_block(source, "softwareUnlistDialog")
        has_software_ui = 'id="softwareDialog"' in source or 'data-screen-panel="software"' in source
        if has_software_ui and not unlist_dialog:
            findings.append(f"{name}:manage-missing-unlist-dialog")
        elif unlist_dialog and (
            "停新发" not in unlist_dialog or "未激活不能开通" not in unlist_dialog or "已激活用到过期" not in unlist_dialog
        ):
            findings.append(f"{name}:unlist-dialog-missing-stop-new-issue-copy")
    if name != "preview.js":
        return
    save_body = _js_event_listener_body(source, "[data-software-save]", "click")
    if save_body and "/manage/catalog/" in save_body:
        if "softwareAllowSwitch" not in save_body or ".checked" not in save_body:
            findings.append(f"{name}:catalog-create-hardcodes-switch")
        if "softwareSwitchLimit" not in save_body:
            findings.append(f"{name}:catalog-create-hardcodes-switch-limit")
    if ("套餐管理" in source or 'dataset.dialog = "planManagerDialog"' in source) and (
        'textContent = "下架"' not in source and "textContent = '下架'" not in source
    ):
        findings.append(f"{name}:software-row-missing-unlist")
    unlist_confirm = _js_event_listener_body(source, "[data-software-unlist-confirm]", "click")
    if unlist_confirm:
        if "/manage/catalog/software/" not in unlist_confirm or "/status/" not in unlist_confirm:
            findings.append(f"{name}:software-unlist-missing-status-post")
        if "停新发" not in unlist_confirm or "未激活不能开通" not in unlist_confirm or "已激活用到过期" not in unlist_confirm:
            findings.append(f"{name}:software-unlist-toast-missing-stop-new-issue-copy")
    elif "softwareUnlistDialog" in source:
        findings.append(f"{name}:software-unlist-missing-status-post")
    if "授权参数已保存" in source and ("已售跟着变" not in source or "已售不跟" not in source):
        findings.append(f"{name}:policy-save-toast-missing-sold-follow")
    has_plan_save = "[data-plan-save]" in source
    missing_official_test_guard = (
        'planStatus.value !== "test"' not in source and "planStatus.value !== 'test'" not in source
    )
    missing_official_cost_guard = "Number(planQuotaCost.value) < 1" not in source
    if has_plan_save and (missing_official_test_guard or missing_official_cost_guard):
        findings.append(f"{name}:plan-save-allows-official-zero")


def _screen_block(source: str, name: str) -> str:
    marker = f'data-screen-panel="{name}"'
    hit = source.find(marker)
    if hit < 0:
        return ""
    start = source.rfind("<section", 0, hit)
    if start < 0:
        start = hit
    rest = source[hit + len(marker) :]
    nxt = re.search(r'<section[^>]*data-screen-panel="', rest)
    end = hit + len(marker) + nxt.start() if nxt else len(source)
    return source[start:end]


def _dialog_block(source: str, dialog_id: str) -> str:
    marker = f'id="{dialog_id}"'
    hit = source.find(marker)
    if hit < 0:
        marker = f"id='{dialog_id}'"
        hit = source.find(marker)
    if hit < 0:
        return ""
    start = source.rfind("<dialog", 0, hit)
    if start < 0:
        start = hit
    end = source.find("</dialog>", hit)
    if end < 0:
        return source[start:]
    return source[start : end + len("</dialog>")]


def _append_round8_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "preview.css" and re.search(r"\.side-nav\s+\.nav-secondary\s*\{[^}]*display\s*:\s*none", source, re.I):
        findings.append(f"{name}:nav-secondary-still-hidden")
    if name == "manage.html":
        has_search_button = "data-global-search" in source
        has_search_label = bool(re.search(r">\s*只找完整卡密\s*<", source))
        if not has_search_button or not has_search_label:
            findings.append(f"{name}:header-missing-standalone-card-search")
        if re.search(r'class="rail-entry"[\s\S]*?<code>/manage/</code>', source):
            findings.append(f"{name}:manage-rail-shows-english-path")
        backup = _screen_block(source, "backup") if 'data-screen-panel="backup"' in source else ""
        if backup and re.search(
            r"<button[^>]*button-danger[^>]*data-storage-cleanup(?:\s|>)|<button[^>]*data-storage-cleanup(?:\s|>)[^>]*button-danger",
            backup,
        ):
            findings.append(f"{name}:backup-cleanup-still-danger-cta")
        if "rail-bottom" in source and "服务端时间" in source:
            findings.append(f"{name}:manage-rail-label-server-time")
        if 'data-screen-panel="audit"' in source:
            audit = _screen_block(source, "audit")
            backup = _screen_block(source, "backup")
            if "data-storage-cleanup" in audit:
                findings.append(f"{name}:storage-cleanup-still-on-audit")
            if "data-storage-cleanup" not in backup:
                findings.append(f"{name}:storage-cleanup-missing-from-backup")
        if 'data-screen-panel="releases"' in source and "客户点更新后打开网盘地址" not in _screen_block(source, "releases"):
            findings.append(f"{name}:releases-missing-external-update-copy")
        if 'data-screen-panel="client"' in source and ("data-copy-signing-key" not in source or "不是卡密" not in source):
            findings.append(f"{name}:manage-missing-signing-key-copy")
        if 'id="withdrawReleaseDialog"' in source and "已安装的不会被卸掉" not in source:
            findings.append(f"{name}:withdraw-missing-installed-kept-copy")
        withdraw_dialog = _dialog_block(source, "withdrawReleaseDialog")
        if withdraw_dialog and ("ZIP" not in withdraw_dialog or "仍留" not in withdraw_dialog):
            findings.append(f"{name}:withdraw-missing-zip-kept-copy")
        if 'data-screen-panel="releases"' in source and 'id="deleteReleasePackageDialog"' not in source:
            findings.append(f"{name}:release-package-delete-dialog-missing")
    if name == "downstream.html" and re.search(r'class="rail-entry"[\s\S]*?<code>/downstream/</code>', source):
        findings.append(f"{name}:downstream-rail-shows-english-path")
    if name in {"manage.html", "downstream.html"}:
        nav = re.search(r'<nav class="side-nav"[\s\S]*?</nav>', source)
        if nav:
            last_primary = None
            for attrs in re.findall(r"<a\b([^>]*)>", nav.group(0)):
                screen = re.search(r'data-screen="([^"]+)"', attrs)
                parent = re.search(r'data-nav-parent="([^"]+)"', attrs)
                class_match = re.search(r'class="([^"]*)"', attrs)
                classes = class_match.group(1) if class_match else ""
                is_secondary = "nav-secondary" in classes.split()
                if not screen:
                    continue
                if is_secondary:
                    if not parent or parent.group(1) != last_primary:
                        findings.append(f"{name}:nav-secondary-not-under-parent")
                        break
                else:
                    last_primary = screen.group(1)
    if name.endswith(".html") and "data-quota-purchase-link" in source and "付款不会自动到账" not in source:
        findings.append(f"{name}:quota-purchase-missing-manual-redeem-note")
    if name != "preview.js":
        return
    activate = _js_function_body_skip_signature(source, "function activateScreen")
    if activate and ("activeNavigation" in activate or "dataset.navParent || name" in activate):
        findings.append(f"{name}:sidebar-highlights-parent-not-current")
    if 'querySelectorAll("[data-screen-target]")' in source and 'closest("[data-screen-target]")' not in source:
        findings.append(f"{name}:screen-target-not-delegated")
    overview = _js_function_body(source, "function renderOverviewCards")
    if overview:
        if "attention-list" not in overview and "renderAttentionList" not in overview:
            findings.append(f"{name}:overview-attention-stays-hardcoded-empty")
        if ".signal-label" not in overview:
            findings.append(f"{name}:overview-signal-label-stays-pending")
    down = _js_function_body(source, "function applyDownstreamMetricsPayload")
    if down and ".signal-label" not in down:
        findings.append(f"{name}:downstream-signal-label-stays-pending")
    if 'revoke: ["撤销授权"' in source and "大约还能开" not in source:
        findings.append(f"{name}:revoke-copy-missing-card-interval")
    if "function renderAuthorizationRiskRows" in source and "verifyIntervalSeconds" not in source:
        findings.append(f"{name}:revoke-row-missing-verify-interval")
    if "客户端将回退" in source:
        findings.append(f"{name}:withdraw-toast-implies-uninstall")
    if "[data-withdraw-confirm]" in source and "已安装的不会被卸掉" not in source:
        findings.append(f"{name}:withdraw-missing-installed-kept-copy")
    withdraw_confirm = _js_event_listener_body(source, 'querySelector("[data-withdraw-confirm]")', "click")
    if withdraw_confirm:
        if "ZIP" not in withdraw_confirm or "仍留" not in withdraw_confirm:
            findings.append(f"{name}:withdraw-toast-missing-zip-kept-copy")
    elif "版本已撤回" in source and ("ZIP 仍留" not in source and "仍留在磁盘" not in source):
        findings.append(f"{name}:withdraw-toast-missing-zip-kept-copy")
    render_release_rows = _js_function_body(source, "function renderReleaseRows")
    if render_release_rows:
        if "package_available" not in render_release_rows or "deleteReleasePackageDialog" not in render_release_rows:
            findings.append(f"{name}:withdrawn-row-missing-delete-package")
        published_at = render_release_rows.find('item.status === "published"')
        if published_at >= 0:
            published_brace = render_release_rows.find("{", published_at)
            published_body = _js_brace_body(render_release_rows, published_brace) if published_brace >= 0 else ""
            if "deleteReleasePackageDialog" in published_body or "data-release-delete-package" in published_body:
                findings.append(f"{name}:published-row-has-delete-package")
        confirm = _js_event_listener_body(source, 'querySelector("[data-release-delete-package-confirm]")', "click")
        if not confirm or "/delete-package/" not in confirm:
            findings.append(f"{name}:release-js-missing-delete-package-api")
        elif "confirmed: true" not in confirm and "confirmed:true" not in confirm:
            findings.append(f"{name}:release-js-delete-package-missing-confirmed")
    close_body = _js_event_listener_body(source, "releaseDialog?.addEventListener", "close")
    if "releaseDialog" in source and "[data-release-next]" in source and "/discard/" not in (close_body or ""):
        findings.append(f"{name}:release-close-does-not-discard-draft")
    if "editReleaseUrlDialog" in source:
        if name.endswith(".html") and "data-edit-url-channel" not in source:
            findings.append(f"{name}:edit-url-dialog-missing-channel")
        if name.endswith(".html") and "data-release-result-heading" not in source:
            findings.append(f"{name}:release-result-missing-heading-hook")
        if name == "preview.js":
            if "data-edit-url-channel" not in source:
                findings.append(f"{name}:edit-url-js-missing-channel")
            if "已覆盖旧链接" not in source:
                findings.append(f"{name}:release-result-missing-replaced-copy")
            edit_url_enter = _js_event_listener_body(source, 'getElementById("releaseEditUrl")', "keydown")
            if not edit_url_enter or "Enter" not in edit_url_enter:
                findings.append(f"{name}:edit-url-missing-enter-save")
    if "dataset.reclaimFiltered" in source and (
        'selectedButton.insertAdjacentElement("afterend"' in source or 'bar.insertAdjacentElement("afterend"' not in source
    ):
        findings.append(f"{name}:reclaim-filtered-inserted-in-filter-bar")
    if "[data-copy-signing-key]" in source and "/manage/authorization-signing-key/" not in source:
        findings.append(f"{name}:signing-key-copy-missing-api")
    if name == "preview.js":
        has_search_binder = (
            'querySelectorAll("[data-global-search]")' in source
            or 'querySelector("[data-global-search]")' in source
        )
        if not has_search_binder:
            findings.append(f"{name}:js-missing-standalone-card-search")
        elif "全局搜索" in source:
            findings.append(f"{name}:global-search-toast-says-global")


def _append_dingdang_round2_findings(name: str, source: str, findings: list[str]) -> None:
    if name.endswith(".html"):
        css = re.search(r"preview\.css\?v=([^\"']+)", source)
        js = re.search(r"preview\.js\?v=([^\"']+)", source)
        if css and js and css.group(1) != js.group(1):
            findings.append(f"{name}:preview-cache-stamp-split")
    if name in {"manage-login.html", "downstream-login.html", "downstream-register.html"}:
        if not re.search(r"<form\b[^>]*\bmethod=['\"]post['\"]", source, re.I):
            findings.append(f"{name}:login-form-missing-post-method")
    if name == "preview.css":
        blocks = list(re.finditer(r"\.credential-filter-bar\s*\{([^}]*)\}", source))
        if blocks and re.search(r"flex-wrap\s*:\s*wrap", blocks[-1].group(1)):
            findings.append(f"{name}:credential-filter-bar-wraps")
        if not re.search(
            r"\.credential-delivery\s*\+\s*\.modal-actions\s*\{[^}]*position\s*:\s*static",
            source,
        ):
            findings.append(f"{name}:issue-result-sticky-covers-codes")
    if name == "downstream.html":
        if "client-mockup" in source or "data-mockup-" in source:
            findings.append(f"{name}:support-keeps-client-mockup-sandbox")


def _append_dingdang_round3_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "preview.js":
        clear_credit = _js_function_body(source, "function clearCreditRuntimeData")
        if clear_credit and "applyQuotaPurchaseLink" in clear_credit and "keepOnEmpty: true" not in clear_credit:
            findings.append(f"{name}:credit-get-failure-clears-purchase-link")
        apply_backup = _js_function_body(source, "function applyBackupDashboard")
        if apply_backup and "上次验收已过期" in apply_backup and "计划已关" not in apply_backup:
            findings.append(f"{name}:backup-disabled-stale-still-says-expired")
        inspect_idx = source.find("[data-backup-restore-inspect]")
        if inspect_idx >= 0:
            chunk = source[inspect_idx : inspect_idx + 4200]
            if "applyButton.disabled = false" in chunk and "dataset.backupTime" not in chunk:
                findings.append(f"{name}:restore-enables-apply-before-copied-time")
    if name == "manage.html" and "data-backup-restore-apply" in source:
        if not re.search(
            r"<button[^>]*data-backup-restore-apply[^>]*\bdisabled\b|<button[^>]*\bdisabled\b[^>]*data-backup-restore-apply",
            source,
        ):
            findings.append(f"{name}:restore-apply-not-disabled-by-default")


def _append_dingdang_round4_findings(name: str, source: str, findings: list[str]) -> None:
    if name != "preview.js":
        return
    confirm_idx = source.find("[data-release-confirm]")
    if confirm_idx >= 0:
        chunk = source[confirm_idx : confirm_idx + 2800]
        if "event.currentTarget.disabled = false" in chunk and "const button = event.currentTarget" not in chunk:
            findings.append(f"{name}:release-confirm-currenttarget-reset-lost")
    load_releases = _js_function_body(source, "async function loadReleasesForSoftware")
    if load_releases:
        marker = "catch (requestError)" if "catch (requestError)" in load_releases else "catch(requestError)"
        request_catch = load_releases[load_releases.find(marker) :] if marker in load_releases else ""
        if request_catch and "showRuntimeReadError" in request_catch and "applyReleaseContext" not in request_catch:
            findings.append(f"{name}:release-list-failure-skips-context")
    change_idx = source.find('clientContextEl?.addEventListener("change"')
    if change_idx >= 0:
        chunk = source[change_idx : change_idx + 900]
        if "applyClientConfig(null)" not in chunk or "dataset.configSoftware" not in chunk:
            findings.append(f"{name}:client-context-change-keeps-previous-announcement")
    apply_client = _js_function_body(source, "function applyClientConfig")
    if apply_client and "if (!payload)" in apply_client:
        payload_branch = apply_client.split("if (!payload)", 1)[-1]
        payload_branch = payload_branch.split("return", 1)[-1] if "return" in payload_branch else payload_branch
        if 'publish.textContent = "待读取"' in payload_branch:
            findings.append(f"{name}:client-config-payload-still-pending-badge")


def _append_dingdang_round5_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "manage.html" and 'data-overview-metric="credits"' in source:
        overview = _screen_block(source, "overview") if 'data-screen-panel="overview"' in source else source
        if "近 30 天" not in overview:
            findings.append(f"{name}:overview-credits-missing-30d-window")
    if name != "preview.js":
        return
    render_overview = _js_function_body(source, "function renderOverviewCards")
    if render_overview and "全平台合计" in render_overview and "近 30 天" not in render_overview:
        findings.append(f"{name}:overview-credits-js-drops-30d-window")
    hide_idx = source.find("完整码已重新隐藏")
    if hide_idx >= 0:
        chunk = source[max(0, hide_idx - 900) : hide_idx]
        if 'dataset.fullCode = ""' not in chunk and "dataset.fullCode = ''" not in chunk:
            findings.append(f"{name}:credential-hide-keeps-dom-plaintext")


def _append_dingdang_round6_findings(name: str, source: str, findings: list[str]) -> None:
    if name != "preview.js":
        return
    load_devices = _js_function_body(source, "async function loadDownstreamDevices")
    if load_devices and "resolveTableSearchQuery" in load_devices and '"license"' in load_devices:
        findings.append(f"{name}:device-search-js-still-hmacs-license")


def _extra_preview_page_findings(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*.html")):
        relative = path.relative_to(root).as_posix()
        if re.search(r"auto_login|bridge_", path.name, re.I):
            findings.append(f"{relative}:capture-bridge-page")
        if relative not in FROZEN_PAGE_NAMES:
            findings.append(f"{relative}:extra-frozen-html")
    return findings


def _append_measured_round5_findings(name: str, source: str, findings: list[str]) -> None:
    if name.endswith(".html") and "data-sensitive-search" in source:
        for match in re.finditer(r"<label class=\"search-field\"[\s\S]*?</label>", source):
            block = match.group(0)
            if "data-sensitive-search" not in block:
                continue
            if "粘客户" not in block:
                findings.append(f"{name}:sensitive-search-missing-paste-full-code-copy")
                break
    if name == "downstream.html" and "data-downstream-device-search" in source:
        device_tag = next(
            (match.group(0) for match in re.finditer(r"<input\b[^>]*>", source) if "data-downstream-device-search" in match.group(0)),
            "",
        )
        if "不搜卡密" not in device_tag:
            findings.append(f"{name}:device-search-missing-unified-copy")
        if "完整卡密" in device_tag or "粘完整卡密" in device_tag:
            findings.append(f"{name}:device-search-teaches-license-hmac")
    if name == "manage.html" and 'data-screen-panel="software"' in source:
        software = _screen_block(source, "software")
        if software and "软件名称或软件标识" not in software:
            findings.append(f"{name}:software-search-missing-id-copy")
    if name != "preview.js":
        return
    license_search = _js_function_body_skip_signature(source, "async function searchLicenseCard")
    if not license_search:
        license_search = _js_function_body(source, "async function searchLicenseCard")
    if license_search and ("粘客户" not in license_search or "显示完整码" not in license_search):
        findings.append(f"{name}:license-search-toast-missing-paste-and-reveal")
    admin_search = _js_function_body_skip_signature(source, "async function searchAdminCredential")
    if not admin_search:
        admin_search = _js_function_body(source, "async function searchAdminCredential")
    if admin_search and ("粘客户" not in admin_search or "显示完整码" not in admin_search):
        findings.append(f"{name}:credential-search-toast-missing-paste-and-reveal")
    device_summary = _js_function_body_skip_signature(source, "function setDownstreamDevicePagination")
    if not device_summary:
        device_summary = _js_function_body(source, "function setDownstreamDevicePagination")
    if device_summary and "暂无已激活设备" in device_summary and "没有匹配的设备" not in device_summary:
        findings.append(f"{name}:device-empty-ignores-search-query")
    apply_preview = _js_function_body_skip_signature(source, "function applyTablePreview")
    if not apply_preview:
        apply_preview = _js_function_body(source, "function applyTablePreview")
    render_catalog = _js_function_body(source, "function renderAdminCatalogRows")
    if render_catalog:
        writes_search = "searchValue" in render_catalog and "software_id" in render_catalog
        reads_id = "catalogSoftwareId" in (apply_preview or "")
        if not writes_search and not reads_id:
            findings.append(f"{name}:software-filter-ignores-software-id")
    render_table = _js_function_body(source, "function renderTableState")
    if render_table and "catalogSearchHidesPlaceholders" in render_table:
        findings.append(f"{name}:software-search-hides-placeholder-padding")


def _append_measured_round7_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "manage.html":
        if "data-backup-run-table" in source and "还没有备份记录" in source and "同一张表" not in source:
            findings.append(f"{name}:backup-runs-html-empty-omits-download-source")
    if name == "preview.css" and re.search(
        r"\.table-placeholder-row td:first-child::before[\s\S]{0,120}content:\s*[\"']—[\"']",
        source,
    ):
        findings.append(f"{name}:placeholder-row-paints-dash")
    if name != "preview.js":
        return
    apply_backup = _js_function_body(source, "function applyBackupDashboard")
    if (
        apply_backup
        and "上次：成功" in apply_backup
        and "上次证明异常" in apply_backup
        and "程序记录成功，证明未齐" not in apply_backup
    ):
        findings.append(f"{name}:backup-success-plus-critical-still-says-proof-error")
    server_state = _js_function_body(source, "function renderServerTableState")
    if server_state and re.search(
        r"matches\.length\s*===\s*0[\s\S]{0,220}placeholders[\s\S]{0,80}hidden\s*=\s*true",
        server_state,
    ):
        findings.append(f"{name}:server-loaded-empty-hides-placeholder-padding")
    render_runs = _js_function_body(source, "function renderBackupRuns")
    if render_runs and "还没有备份记录" in render_runs and "同一张表" not in render_runs:
        findings.append(f"{name}:backup-runs-empty-omits-download-source")


def _append_measured_round9_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "404.html":
        if "preview.css" not in source:
            findings.append(f"{name}:root-404-missing-preview-css")
        if "preview-index" not in source:
            findings.append(f"{name}:root-404-missing-preview-index")
        if "downstream-login.html" not in source:
            findings.append(f"{name}:root-404-missing-downstream-login")
        if "manage-login.html" in source:
            findings.append(f"{name}:root-404-contains-manage-login-html")
        if "manage.html" in source.replace("manage-login.html", ""):
            findings.append(f"{name}:root-404-contains-manage-html")
        if "entry.html" in source:
            findings.append(f"{name}:root-404-contains-entry-html")
    if name.endswith(".html") and 'data-screen-panel="client"' in source:
        client = _screen_block(source, "client")
        if "data-signing-key-id" not in client:
            findings.append(f"{name}:client-missing-visible-signing-key-id")
    if name != "preview.js":
        return
    if "/manage/authorization-signing-key/" not in source and "[data-copy-signing-key]" not in source:
        return
    loader = _js_function_body(source, "async function loadSigningKeyId")
    if "[data-signing-key-id]" not in loader:
        findings.append(f"{name}:signing-key-id-loader-missing-slot")
    elif "payload.key_id" not in loader or "textContent" not in loader:
        findings.append(f"{name}:signing-key-id-loader-not-writing-key-id")
    if "loadSigningKeyId();" not in source:
        findings.append(f"{name}:signing-key-id-never-loaded")


def _append_round9_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "downstream-register.html":
        if 'name="password"' in source and ("不能全是数字" not in source or "常见密码" not in source):
            findings.append(f"{name}:register-password-rules-incomplete")
        if "进入工作台" in source:
            findings.append(f"{name}:register-button-enters-workspace")
    if name == "downstream-login.html" and "access-preview" in source:
        if "data-register-success" not in source or "账号已创建" not in source:
            findings.append(f"{name}:login-missing-register-success")
    if name != "preview.js":
        return
    if "form.elements.invitation_code" not in source:
        return
    if "registerInFlight" not in source or "registerSucceeded" not in source:
        findings.append(f"{name}:register-missing-inflight-guard")
    if "registered=" not in source:
        findings.append(f"{name}:register-success-jumps-without-copy")
    if "registerSucceeded" not in source:
        findings.append(f"{name}:register-success-still-finally-enable")


def _append_ux_copy_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "preview.css":
        heading_hide = re.search(
            r"\.page-heading p[\s,][\s\S]{0,160}display:\s*none",
            source,
        )
        hint_show = re.search(
            r"\.page-heading p\.form-hint\s*\{[^}]*display:\s*block",
            source,
        )
        if heading_hide and not hint_show:
            findings.append(f"{name}:heading-hides-contract-form-hint")
    if name == "manage.html":
        if re.search(r'form-label">\s*>操作原因', source):
            findings.append(f"{name}:reclaim-reason-label-has-stray-gt")
        if re.search(r"</label>\s*>\s*<label", source):
            findings.append(f"{name}:software-form-stray-gt-between-labels")
    if name != "preview.js":
        return
    chrome = _js_function_body(source, "function bindDialogChrome")
    if chrome and "nativeShowModal" not in chrome and "showModalAndFocus" not in chrome:
        findings.append(f"{name}:dialog-open-leaves-focus-on-close")
    if 'getElementById("redeemDialog")' in source:
        focus = _js_function_body(source, "function focusOpenDialog")
        if not focus or "quota_code" not in focus or "data-form-error" not in focus:
            findings.append(f"{name}:redeem-dialog-keeps-last-error")
    activate = _js_function_body_skip_signature(source, "function activateScreen")
    if activate and "data-screen-panel" in activate and "dialog[open]" not in activate:
        findings.append(f"{name}:activate-screen-leaves-open-dialogs")
    check_body = _js_event_listener_body(source, "[data-release-check]", "click")
    if check_body and "recheckPublicReleaseRegistry" in check_body:
        await_at = check_body.find("await ")
        setup = check_body[:await_at] if await_at >= 0 else ""
        if "const button = event.currentTarget" not in setup:
            findings.append(f"{name}:release-check-missing-button-capture")
        for finally_body in _js_finally_bodies(check_body):
            if "event.currentTarget" in finally_body:
                findings.append(f"{name}:release-check-finally-uses-currenttarget")
    ensure = _js_function_body(source, "function ensureTableState")
    if ensure and 'empty.textContent = "当前条件没有匹配的记录。"' in ensure and "tableHasActiveFilter" not in source:
        findings.append(f"{name}:table-empty-always-says-filter-mismatch")
    preview_fn = _js_function_body(source, "function updateIssuePreview")
    if preview_fn and "请选择软件和套餐后再生成。" in preview_fn and "还没有可经营软件" not in preview_fn:
        findings.append(f"{name}:issue-empty-software-asks-to-select")
    filter_fn = _js_function_body(source, "function applyPlanCatalogFilter")
    if filter_fn and "当前没有可用套餐。" in filter_fn and "还没有可经营软件" not in filter_fn:
        findings.append(f"{name}:plan-catalog-all-empty-omits-admin-open")


def _record_view_block(source: str, scope: str) -> str:
    marker = f'data-record-view-scope="{scope}"'
    hit = source.find(marker)
    if hit < 0:
        return ""
    start = source.rfind("<div", 0, hit)
    if start < 0:
        start = hit
    rest = source[hit + len(marker) :]
    nxt = re.search(r'data-(?:record-view-scope|screen-panel)="', rest)
    end = hit + len(marker) + nxt.start() if nxt else len(source)
    return source[start:end]


def _toolbar_search_fields(block: str) -> list[str]:
    toolbar = re.search(r'<div class="table-toolbar">([\s\S]*?)</div>', block)
    if not toolbar:
        return []
    return re.findall(r"<label class=\"search-field\"[\s\S]*?</label>", toolbar.group(1))


def _append_table_readability_findings(name: str, source: str, findings: list[str]) -> None:
    if name == "preview.css":
        if not re.search(r"th,\s*td\s*\{[^}]*border-right:\s*1px\s+solid", source):
            findings.append(f"{name}:table-missing-vertical-column-lines")
        if not re.search(r"th:last-child,\s*td:last-child\s*\{[^}]*border-right:\s*none", source):
            findings.append(f"{name}:table-last-column-keeps-right-border")
    if name.endswith(".html"):
        if name in {"manage.html", "downstream.html"}:
            if "data-license-fuzzy-search" in source:
                findings.append(f"{name}:license-table-keeps-separate-fuzzy-box")
            scope = "management-licenses" if name == "manage.html" else "downstream-licenses"
            licenses = _record_view_block(source, scope)
            if not licenses:
                findings.append(f"{name}:license-table-missing-unified-search")
            else:
                fields = _toolbar_search_fields(licenses)
                if len(fields) != 1:
                    findings.append(f"{name}:license-table-not-single-search")
                joined = "\n".join(fields)
                if "软件" not in joined or "完整卡密" not in joined:
                    findings.append(f"{name}:license-table-search-missing-unified-copy")
        if name == "manage.html":
            invitations = _record_view_block(source, "invitations")
            if invitations:
                fields = _toolbar_search_fields(invitations)
                if len(fields) != 1:
                    findings.append(f"{name}:invitation-table-not-single-search")
                joined = "\n".join(fields)
                if "注册账号" not in joined or "完整邀请码" not in joined:
                    findings.append(f"{name}:invitation-table-search-missing-unified-copy")
            quota = _record_view_block(source, "quota-cards")
            if quota:
                fields = _toolbar_search_fields(quota)
                if len(fields) != 1:
                    findings.append(f"{name}:quota-table-not-single-search")
                joined = "\n".join(fields)
                if "兑换下游" not in joined or "完整兑换码" not in joined:
                    findings.append(f"{name}:quota-table-search-missing-unified-copy")
        if 'data-audit-search' in source and re.search(
            r"<input[^>]*data-audit-search[^>]*data-sensitive-search",
            source,
        ):
            findings.append(f"{name}:audit-search-marked-sensitive")
        if name == "manage.html":
            if "data-audit-search" not in source:
                findings.append(f"{name}:audit-table-missing-fuzzy-search")
            risk = _screen_block(source, "risk") if 'data-screen-panel="risk"' in source else source
            if "完整卡密" not in risk:
                findings.append(f"{name}:risk-search-missing-unified-copy")
            if re.search(r"全部下游账户流水</span>\s*>\s*<button", source):
                findings.append(f"{name}:ledger-toolbar-has-stray-gt")
        if name == "downstream.html" and "data-activity-search" not in source:
            findings.append(f"{name}:activity-table-missing-fuzzy-search")
    if name != "preview.js":
        return
    if "data-license-fuzzy-search" in source:
        findings.append(f"{name}:license-search-still-reads-separate-fuzzy-box")
    if "looksLikePrefixedCredential" not in source or "nonSecretTableQuery" not in source or "resolveTableSearchQuery" not in source:
        findings.append(f"{name}:table-search-missing-full-code-heuristic")
    audit_rows = _js_function_body(source, "function renderAdminAuditRows")
    if audit_rows and "formatApiDate(item.occurred_at)" not in audit_rows:
        findings.append(f"{name}:audit-table-paints-raw-iso-time")
    activity_rows = _js_function_body(source, "function renderDownstreamActivityRows")
    if activity_rows and "formatApiDate(item.occurred_at)" not in activity_rows:
        findings.append(f"{name}:activity-table-paints-raw-iso-time")
    risk_status = _js_function_body(source, "function authorizationRiskStatus")
    if risk_status and "licenseCardWallClockExpired" not in risk_status:
        findings.append(f"{name}:risk-status-ignores-wall-clock-expiry")
    expiry_label = _js_function_body(source, "function riskExpiryLabel")
    if expiry_label and "days <= 0" not in expiry_label:
        findings.append(f"{name}:risk-expiry-label-treats-past-as-soon")
    activate = _js_function_body_skip_signature(source, "function activateScreen") or _js_function_body(
        source, "function activateScreen"
    )
    if activate and "clearTransientQuery" not in activate:
        findings.append(f"{name}:screen-switch-keeps-transient-query")
    restore = _js_function_body(source, "function restoreListState")
    if restore and 'params.get("page")' in restore:
        findings.append(f"{name}:restore-list-state-applies-leftover-page")


def _header_actions_block(source: str) -> str:
    match = re.search(r'<div class="header-actions">([\s\S]*?)</div>', source)
    return match.group(1) if match else ""


def _append_header_refresh_findings(name: str, source: str, findings: list[str]) -> None:
    if name in {"manage.html", "downstream.html"} and 'class="header-actions"' in source:
        block = _header_actions_block(source)
        if "data-workspace-refresh" not in block:
            findings.append(f"{name}:header-missing-workspace-refresh")
        else:
            refresh_at = block.find("data-workspace-refresh")
            logout_at = block.find("退出")
            if logout_at < 0 or refresh_at > logout_at:
                findings.append(f"{name}:header-refresh-not-before-logout")
            button = re.search(
                r"<button\b[^>]*data-workspace-refresh[\s\S]*?</button",
                block,
            )
            markup = button.group(0) if button else ""
            if "data-toast" in markup:
                findings.append(f"{name}:header-refresh-is-fake-toast")
            if not re.search(r">\s*刷新\s*<", markup):
                findings.append(f"{name}:header-refresh-wrong-label")
    if name != "preview.js":
        return
    if "async function loadLicenseCards" in source:
        if "async function refreshVisibleWorkspace" not in source:
            findings.append(f"{name}:header-refresh-handler-missing")
        if "function installWorkspaceRefresh" not in source:
            findings.append(f"{name}:header-refresh-binder-missing")
    if "async function refreshVisibleWorkspace" not in source:
        return
    visible = _js_function_body(source, "async function refreshVisibleWorkspace")
    screen = _js_function_body(source, "async function refreshScreenData")
    combined = f"{visible}\n{screen}"
    if "loadLicenseCards" not in combined:
        findings.append(f"{name}:header-refresh-skips-license-cards")
    if "loadAdminBackup" not in combined:
        findings.append(f"{name}:header-refresh-skips-backup")
    if "loadOverviewSnapshot" not in combined:
        findings.append(f"{name}:header-refresh-skips-overview")
    if "loadDownstreamCredits" not in combined:
        findings.append(f"{name}:header-refresh-skips-downstream-credits")
    if "isStandaloneStaticPreview" not in visible:
        findings.append(f"{name}:header-refresh-static-preview-unhandled")
    logout = _js_function_body(source, "function installLogout")
    if logout and 'includes("退出")' not in logout:
        findings.append(f"{name}:logout-binder-not-scoped-to-exit")
    if "async function loadAdminAudit" in source and 'registerWorkspaceReloader("audit"' not in source:
        findings.append(f"{name}:header-refresh-missing-audit")
    if "async function loadDownstreamActivity" in source and 'registerWorkspaceReloader("activity"' not in source:
        findings.append(f"{name}:header-refresh-missing-activity")


def _static_preview_findings(name: str, source: str, *, strict: bool = False) -> list[str]:
    findings: list[str] = []
    _append_header_refresh_findings(name, source, findings)
    _append_round8_findings(name, source, findings)
    _append_round9_findings(name, source, findings)
    _append_measured_round5_findings(name, source, findings)
    _append_measured_round7_findings(name, source, findings)
    _append_measured_round9_findings(name, source, findings)
    _append_dingdang_round2_findings(name, source, findings)
    _append_dingdang_round3_findings(name, source, findings)
    _append_dingdang_round4_findings(name, source, findings)
    _append_dingdang_round5_findings(name, source, findings)
    _append_dingdang_round6_findings(name, source, findings)
    _append_ux_copy_findings(name, source, findings)
    _append_table_readability_findings(name, source, findings)
    _append_backup_preview_css_findings(name, source, findings)
    html_source = name.lower().endswith(".html")
    scan_source = unescape(source) if html_source else source
    for line_number, line in enumerate(scan_source.splitlines(), start=1):
        for marker in STATIC_PREVIEW_MARKERS:
            if marker in line:
                findings.append(f"{name}:{line_number}:{marker}")
        if re.search(r"\b(?:LIC|INV|QUOTA)-", line):
            findings.append(f"{name}:{line_number}:credential-prefix")
        if html_source and any(attribute in line for attribute in ARCHIVE_BUSINESS_ATTRIBUTES):
            findings.append(f"{name}:{line_number}:business-row-attribute")
        if name in LIVE_PREVIEW_NAMES and "entry.html" in line:
            findings.append(f"{name}:{line_number}:live-entry-html")
    if html_source and re.search(r"<tbody\b(?:(?!</?tbody\b).)*?<tr\b", source, re.IGNORECASE | re.DOTALL):
        findings.append(f"{name}:business-table-row")
    if html_source and re.search(r'class=["\'][^"\']*\b(?:package-row|batch-row)[^"\']*["\']', source, re.IGNORECASE):
        findings.append(f"{name}:business-item-class")
    if html_source and "data-server-data-loaded" in source:
        findings.append(f"{name}:frozen-server-data-loaded")
    if html_source and re.search(r"\bdata-count=", source, re.IGNORECASE):
        findings.append(f"{name}:frozen-static-count")
    if name == "manage.html" and re.search(r'id=["\']inviteNote["\']', source):
        findings.append(f"{name}:invite-issue-fake-note-field")
    if name == "manage.html" and re.search(r'id=["\']quotaCardNote["\']', source):
        findings.append(f"{name}:quota-issue-fake-note-field")
    if name == "manage.html" and "本月净消耗" in source:
        findings.append(f"{name}:credits-unwired-month-net-consumed")
    if name == "manage.html" and "活跃账户" in source:
        findings.append(f"{name}:credits-unwired-active-accounts")
    if name == "preview.js" and "payload.trend.slice(-7)" in source:
        findings.append(f"{name}:analytics-trend-sliced-to-seven")
    if name == "preview.css":
        chart_rule = re.search(r"\.bar-chart\s*\{[^}]*\}", source)
        if chart_rule and "repeat(7" in chart_rule.group(0):
            findings.append(f"{name}:analytics-chart-locked-to-seven-columns")
        if chart_rule and "minmax(22px, 1fr)" in chart_rule.group(0):
            findings.append(f"{name}:analytics-chart-squeezes-thirty-day-bars")
        bar_div = re.search(r"\.bar-chart div\s*\{[^}]*\}", source)
        if bar_div and re.search(r"grid-template-rows:\s*150px\s+auto\s+auto", bar_div.group(0)):
            findings.append(f"{name}:analytics-chart-label-rows-grow-with-window")
    if name == "manage.html" and "近七天激活量柱状图" in source:
        findings.append(f"{name}:analytics-chart-aria-locked-to-seven-days")
    if name == "manage.html" and "导出当前范围" in source:
        findings.append(f"{name}:analytics-export-pretends-current-window")
    if name == "manage.html" and re.search(
        r"软件维度明细[\s\S]{0,500}data-export-query=\"analytics\"",
        source,
    ):
        findings.append(f"{name}:analytics-export-beside-window-breakdown")
    if name in {"manage.html", "downstream.html"}:
        grid = re.search(r'<div class="revenue-grid"[^>]*>[\s\S]*?</div>', source)
        if grid and re.search(r"<span>今日收入</span>", grid.group(0)):
            findings.append(f"{name}:revenue-grid-missing-quota-unit")
        if grid and "data-revenue-rule" not in source:
            findings.append(f"{name}:revenue-grid-missing-activation-rule")
        if "data-revenue-rule" in source and "已激活" not in source:
            findings.append(f"{name}:revenue-rule-omits-activation")
    if name == "preview.js":
        apply_analytics = _js_function_body(source, "function applyAnalyticsPayload")
        if "analyticsContent.hidden = !hasData" in apply_analytics:
            findings.append(f"{name}:analytics-hides-content-when-empty-window")
        if re.search(r"if \(hasData\) \{[\s\S]*data-analytics-metric", apply_analytics):
            findings.append(f"{name}:analytics-skips-snapshot-metrics-when-empty-window")
        if apply_analytics:
            if "windowChart.hidden = !hasData" not in apply_analytics:
                findings.append(f"{name}:analytics-empty-leaves-window-chart")
            if "windowTable.hidden = !hasData" not in apply_analytics:
                findings.append(f"{name}:analytics-empty-leaves-window-table")
        apply_down = _js_function_body(source, "function applyDownstreamMetricsPayload")
        if "signals.hidden = !hasData" in apply_down:
            findings.append(f"{name}:downstream-hides-signals-when-empty-window")
    if name == "manage.html" and 'data-toast="需要处理列表已刷新。"' in source:
        findings.append(f"{name}:overview-attention-refresh-is-fake-toast")
    if name == "manage.html" and 'data-screen-panel="analytics"' in source:
        if "data-analytics-window-chart" not in source or "data-analytics-window-table" not in source:
            findings.append(f"{name}:analytics-window-blocks-unmarked")
        empty_at = source.find("data-analytics-empty")
        table_at = source.find("data-analytics-window-table")
        breakdown_at = source.find("data-analytics-breakdown")
        if empty_at >= 0 and (
            (table_at >= 0 and empty_at > table_at)
            or (breakdown_at >= 0 and empty_at > breakdown_at)
        ):
            findings.append(f"{name}:analytics-empty-cta-below-window-table")
    if name == "manage.html" and "当前范围没有运营数据" in source:
        findings.append(f"{name}:analytics-empty-copy-says-no-operations")
    if name == "downstream.html" and "当前范围没有经营数据" in source:
        findings.append(f"{name}:downstream-empty-copy-says-no-operations")
    if name == "downstream.html" and "data-downstream-recent-cards" in source:
        if re.search(r"<h2>\s*最近卡密\s*</h2>", source):
            findings.append(f"{name}:recent-cards-heading-unlabeled-limit")
        if "当前还没有授权卡密" in source:
            findings.append(f"{name}:recent-cards-empty-says-no-inventory")
    if name == "preview.js":
        load_cards = _js_function_body(source, "async function loadLicenseCards")
        if "renderDownstreamRecentCards(payload.items" in load_cards:
            findings.append(f"{name}:recent-cards-bound-to-license-list-page")
        recent_fn = _js_function_body(source, "function renderDownstreamRecentCards")
        if "当前还没有授权卡密" in recent_fn:
            findings.append(f"{name}:recent-cards-empty-says-no-inventory")
        render_cards = _license_card_rows_body(source, "function renderLicenseCardRows")
        if render_cards and "appendStatusCell" not in render_cards:
            findings.append(f"{name}:license-main-rows-missing-status-chip")
        generated_cards = _license_card_rows_body(source, "function addGeneratedLicenseRecords")
        if generated_cards and "appendStatusCell" not in generated_cards:
            findings.append(f"{name}:license-generated-rows-missing-status-chip")
        display_fn = _js_function_body(source, "function licenseCardDisplayStatus")
        if "function renderLicenseCardRows" in source:
            if not display_fn:
                findings.append(f"{name}:license-chip-missing-wall-clock-helper")
            elif 'inventory === "activated"' not in display_fn and 'status === "activated"' not in display_fn:
                findings.append(f"{name}:license-chip-helper-ignores-activated")
            elif "expires_at" not in display_fn and "licenseCardWallClockExpired" not in display_fn:
                findings.append(f"{name}:license-chip-helper-ignores-expires-at")
        rule_fn = _js_function_body(source, "function licenseActivationRuleLabel")
        if "function renderLicenseCardRows" in source:
            if not rule_fn:
                findings.append(f"{name}:license-activation-rule-helper-missing")
            elif "formatApiDate(item.activation_rule)" in rule_fn:
                findings.append(f"{name}:license-formats-activation-rule-string")
            elif "formatApiDate(item.expires_at)" not in rule_fn:
                findings.append(f"{name}:license-activation-rule-skips-expires-at")
        if render_cards:
            if "licenseCardDisplayStatus" not in render_cards:
                findings.append(f"{name}:license-main-chip-ignores-wall-clock")
            if "licenseActivationRuleLabel" not in render_cards:
                findings.append(f"{name}:license-main-rule-uses-raw-iso")
            if "dataset.cardStatus = item.status" not in render_cards:
                findings.append(f"{name}:license-rows-lost-inventory-card-status")
        if generated_cards:
            if "licenseCardDisplayStatus" not in generated_cards:
                findings.append(f"{name}:license-generated-chip-ignores-wall-clock")
            if "licenseActivationRuleLabel" not in generated_cards:
                findings.append(f"{name}:license-generated-rule-uses-raw-iso")
        if recent_fn and "licenseStatusCopy[item.status]" in recent_fn:
            findings.append(f"{name}:recent-cards-chip-ignores-wall-clock")
        query_fn = _js_function_body(source, "function licenseCardFilterQuery")
        if query_fn and (
            "licenseApiStatusFromFilter" not in query_fn
            or not re.search(r"未激活:\s*[\"']unused[\"']", source)
        ):
            findings.append(f"{name}:license-status-filter-missing-unused-mapping")
        load_invitations = _js_function_body(source, "async function loadInvitations")
        if load_invitations and "codeStatus" in load_invitations and 'data-record-view-scope="invitations"' not in load_invitations:
            findings.append(f"{name}:invitation-status-filter-unscoped")
    if name in {"manage.html", "downstream.html"}:
        scope = "management-licenses" if name == "manage.html" else "downstream-licenses"
        block = _license_scope_block(source, scope)
        if block:
            if 'data-credential-filter="codeStatus"' not in block:
                findings.append(f"{name}:license-main-table-missing-status-filter")
            if not re.search(r"<th>\s*状态\s*</th>", block):
                findings.append(f"{name}:license-main-table-missing-status-column")
    if name == "downstream.html":
        block = _license_scope_block(source, "downstream-licenses")
        if re.search(r"当前下游未激活卡", block or source):
            default_summary = re.search(
                r'data-record-scope-default="([^"]*)"',
                block or "",
            )
            if default_summary and "未激活" in default_summary.group(1):
                findings.append(f"{name}:downstream-license-summary-claims-unused-by-default")
            elif not block and "当前下游未激活卡" in source:
                findings.append(f"{name}:downstream-license-summary-claims-unused-by-default")
        if ("待回收" in source or "data-target-credential" in source) and 'data-target-credential-status="未激活"' not in source:
            findings.append(f"{name}:downstream-reclaimable-missing-status-target")
        if re.search(r"微信号\s*<input[^>]*data-support-contact", source):
            findings.append(f"{name}:support-contact-labeled-wechat-only")
        contact_input = re.search(r"<input\b[^>]*data-support-contact[^>]*>", source)
        if contact_input and re.search(r'type=["\']url["\']', contact_input.group(0)):
            findings.append(f"{name}:support-contact-is-url-input")
        if 'data-support-contact' in source and "联系方式" not in source:
            findings.append(f"{name}:support-contact-missing-free-text-label")
    if name == "preview.js":
        collect = _js_function_body(source, "const collectLifecycle")
        if collect:
            archive_sees_wall_clock = (
                "licenseCardMayArchive" in collect
                or ("activated" in collect and ("expiresAt" in collect or "expires_at" in collect))
            )
            if not archive_sees_wall_clock:
                findings.append(f"{name}:license-archive-ignores-wall-clock-activated")
        scopes = _js_function_body(source, "const lifecycleScopes")
        mgmt_start = scopes.find('"management-licenses"')
        quota_start = scopes.find('"quota-cards"', mgmt_start + 1 if mgmt_start >= 0 else 0)
        mgmt_entry = (
            scopes[mgmt_start:quota_start]
            if mgmt_start >= 0 and quota_start > mgmt_start
            else ""
        )
        if mgmt_entry and re.search(
            r"archiveStatuses:\s*\[[^\]]*[\"']activated[\"']",
            mgmt_entry,
        ):
            findings.append(f"{name}:license-archive-unconditionally-includes-activated")
        may_archive = _js_function_body(source, "function licenseCardMayArchive")
        if may_archive and "activated" in may_archive:
            if (
                "licenseCardExpiryHasPassed" not in may_archive
                and "expiresAt" not in may_archive
                and "expires_at" not in may_archive
            ):
                findings.append(f"{name}:license-archive-activated-without-expiry-check")
        render_cards = _license_card_rows_body(source, "function renderLicenseCardRows")
        if render_cards and (
            "dataset.expiresAt" not in render_cards or "item.expires_at" not in render_cards
        ):
            findings.append(f"{name}:license-rows-missing-expires-at-for-archive")
        status_fn = _js_function_body(source, "function authorizationRiskStatus")
        if status_fn:
            if not re.search(r'item\.status\s*===\s*["\']blocked["\']', status_fn):
                findings.append(f"{name}:authorization-risk-status-ignores-instance-blocked")
            if "正常 /" in status_fn:
                findings.append(f"{name}:authorization-risk-status-splices-device-onto-normal")
        render_risk = _js_function_body_skip_signature(source, "function renderAuthorizationRiskRows")
        if render_risk:
            if "flatMap" in render_risk and "待处理" in render_risk:
                findings.append(f"{name}:authorization-risk-pending-counts-current-page")
            if re.search(
                r'binding_state\s*===\s*["\']active["\']\s*\?\s*["\']已绑定["\']\s*:\s*["\']等待激活["\']',
                render_risk,
            ):
                findings.append(f"{name}:authorization-risk-device-column-non-active-as-waiting")
            if "risk_pending" in render_risk:
                findings.append(f"{name}:authorization-risk-pending-uses-analytics")
        load_risk = _js_function_body(source, "async function loadAuthorizationRisk")
        if load_risk:
            if "risk_pending" in load_risk:
                findings.append(f"{name}:authorization-risk-pending-uses-analytics")
            if not re.search(r'set\(\s*["\']risk_state["\']\s*,\s*["\']blocked["\']\s*\)', load_risk):
                findings.append(f"{name}:authorization-risk-pending-skips-server-total")
        toast_fn = _js_function_body(source, "function downstreamDeviceResetToast")
        has_device_reset = (
            "downstreamDeviceResetToast" in source
            or "data-device-reset" in source
            or ("/devices/" in source and "/reset/" in source)
        )
        if has_device_reset:
            if not toast_fn:
                findings.append(f"{name}:downstream-reset-toast-missing")
            else:
                if not re.search(r'binding_state\s*===?\s*["\']blocked["\']', toast_fn):
                    findings.append(f"{name}:downstream-reset-toast-ignores-blocked-state")
                if "已阻断" not in toast_fn:
                    findings.append(f"{name}:downstream-reset-toast-missing-blocked-copy")
                if "已解绑" in toast_fn:
                    findings.append(f"{name}:downstream-reset-toast-says-unbound")
                if "设备已重置" in toast_fn and "blocked" not in toast_fn:
                    findings.append(f"{name}:downstream-reset-toast-always-reset")
            if "showToast(downstreamDeviceResetToast(" not in source:
                findings.append(f"{name}:downstream-reset-confirm-ignores-reset-toast")
        plan_manager = _js_function_body(source, "function preparePlanManagerDialog")
        if plan_manager:
            if "已暂停" in plan_manager:
                findings.append(f"{name}:plan-manager-archived-labeled-paused")
            if "test_only" not in plan_manager and "testOnly" not in plan_manager:
                findings.append(f"{name}:plan-manager-status-ignores-test-only")
            if "已归档" not in plan_manager:
                findings.append(f"{name}:plan-manager-status-missing-archived-copy")
            if "仅测试" not in plan_manager:
                findings.append(f"{name}:plan-manager-status-missing-test-only-copy")
            if "删除" not in plan_manager:
                findings.append(f"{name}:plan-manager-archived-missing-delete")
        lifecycle = _js_function_body(source, "function openPlanLifecycle")
        if lifecycle:
            if "作废" not in lifecycle and "失效" not in lifecycle:
                findings.append(f"{name}:plan-lifecycle-delete-omits-invalidate-copy")
        if "function preparePlanManagerDialog" in source and "/delete/" not in source:
            findings.append(f"{name}:plan-lifecycle-delete-endpoint-missing")
        plan_chips = _js_function_body(source, "function appendPlanSummary")
        if plan_chips:
            if "已归档" in plan_chips or "仅测试" in plan_chips:
                findings.append(f"{name}:plan-chip-injects-lifecycle-copy")
            if not re.search(r"chip\.textContent\s*=\s*item\.name\s*;", plan_chips):
                findings.append(f"{name}:plan-chip-not-name-only")
    if name == "manage.html":
        advanced = re.search(
            r"<details\b[^>]*data-software-advanced[\s\S]*?</details>",
            source,
            re.IGNORECASE,
        )
        if advanced and re.search(r'id=["\']softwareCode["\']', advanced.group(0)):
            findings.append(f"{name}:software-code-hidden-in-advanced")
        dialog = re.search(r'id=["\']softwareDialog["\'][\s\S]*?</dialog>', source)
        if dialog and not re.search(r'id=["\']softwareCode["\']', dialog.group(0)):
            findings.append(f"{name}:software-code-missing-from-dialog")
        risk_html = _risk_screen_block(source)
        status_select = re.search(r'data-risk-filter="status">([\s\S]*?)</select>', risk_html)
        if status_select and not re.search(r'value="blocked"', status_select.group(1)):
            findings.append(f"{name}:authorization-risk-status-filter-missing-blocked")
        device_select = re.search(r'data-risk-filter="device_state">([\s\S]*?)</select>', risk_html)
        if device_select:
            if "等待激活" in device_select.group(1):
                findings.append(f"{name}:authorization-risk-unbound-labeled-waiting")
        _append_backup_screen_findings(name, source, findings)
        _append_round6_findings(name, source, findings)
        _append_round7_findings(name, source, findings)
    if name == "preview.js":
        _append_backup_preview_js_findings(name, source, findings, strict=strict)
        _append_round6_findings(name, source, findings)
        _append_round7_findings(name, source, findings)
    if name == "downstream.html":
        _append_round6_findings(name, source, findings)
    if name == "manage.html" and "data-admin-ledger-pagination" in source:
        if not _ledger_table_panel_is_server_paginated(source, "data-admin-ledger-pagination"):
            findings.append(f"{name}:ledger-table-not-server-paginated")
    if name == "downstream.html" and "data-downstream-ledger-pagination" in source:
        if not _ledger_table_panel_is_server_paginated(source, "data-downstream-ledger-pagination"):
            findings.append(f"{name}:ledger-table-not-server-paginated")
    if name == "preview.js":
        admin_ledger = _js_function_body(source, "function renderAdminCreditLedger")
        if admin_ledger and not _ledger_render_marks_server_data_loaded(admin_ledger):
            findings.append(f"{name}:admin-ledger-render-missing-server-data-loaded")
        downstream_ledger = _js_function_body(source, "function renderDownstreamCreditLedger")
        if downstream_ledger and not _ledger_render_marks_server_data_loaded(downstream_ledger):
            findings.append(f"{name}:downstream-ledger-render-missing-server-data-loaded")
    if html_source:
        for match in re.finditer(r"<button\b[^>]*>", source):
            tag = match.group(0)
            if 'value="cancel"' in tag and 'type="button"' not in tag:
                findings.append(f"{name}:dialog-cancel-is-default-submit")
                break
    if name == "preview.js" and "function openPlanEditor" in source:
        if 'planManagerDialog.close("edit")' in source:
            findings.append(f"{name}:plan-editor-closes-manager")
    if 'id="policyAllowSwitch"' in source:
        if "满员时允许新电脑挤掉旧电脑" not in source:
            findings.append(f"{name}:policy-switch-label-not-full-slot-squeeze")
        if re.search(r'id="policyAllowSwitch"[^>]*>\s*允许客户换机', source):
            findings.append(f"{name}:policy-switch-label-still-customer-switch")
    if 'id="resetDeviceDialog"' in source:
        if "不受换机开关" not in source or "旧电脑可能还要过一会儿才停" not in source:
            findings.append(f"{name}:downstream-reset-copy-omits-switch-and-delay")
    if 'data-credential-filter="codeStatus"' in source and 'value="已禁用"' in source:
        findings.append(f"{name}:license-status-filter-keeps-disabled")
    if 'id="managementActionDialog"' in source and "data-management-action-inventory" not in source:
        findings.append(f"{name}:management-action-omits-property-inventory")
    if name == "preview.js":
        redeem_handler = _redeem_click_handler_body(source)
        for try_body in _js_try_bodies(redeem_handler):
            posted = 'apiRequest("/downstream/credits/"' in try_body and re.search(
                r'method:\s*"POST"', try_body
            )
            if posted and "loadDownstreamCredits(" in try_body:
                findings.append(f"{name}:redeem-treats-ledger-refresh-as-redeem-failure")
                break
        software_save = _software_save_handler_body(source)
        for try_body in _js_try_bodies(software_save):
            posted = 'apiRequest("/manage/catalog/"' in try_body and re.search(
                r'method:\s*"POST"', try_body
            )
            if posted and "loadCatalog(" in try_body:
                findings.append(f"{name}:software-create-treats-catalog-refresh-as-save-failure")
                break
        if software_save and "loadCatalog(" in software_save and "请稍后重试" not in software_save:
            findings.append(f"{name}:software-create-refresh-missing-retry-copy")
        change_handler = _password_change_handler_body(source)
        if (
            change_handler
            and "/auth/password/change/" in change_handler
            and "账号状态未改变" in change_handler
        ):
            findings.append(f"{name}:password-change-catch-claims-unchanged")
        logout_fn = _js_function_body(source, "function offerRegistrationLogout")
        if (
            logout_fn
            and 'form.querySelector("[data-register-session-action]")' in logout_fn
            and "form.after(" in logout_fn
        ):
            findings.append(f"{name}:register-logout-guard-misses-sibling-button")
        audit_query_fn = _js_function_body(source, "function adminAuditQuery")
        if audit_query_fn:
            subject_sets_role = 'params.set("actor_role", "anonymous")' in audit_query_fn
            source_overwrites_role = bool(
                re.search(
                    r'if\s*\(\s*source\s*\)\s*params\.set\(\s*["\']actor_role["\']\s*,\s*source\s*\)',
                    audit_query_fn,
                )
            )
            drops_source = (
                'params.has("actor_role")' in audit_query_fn
                and 'params.set("actor_role", source)' in audit_query_fn
            )
            if (subject_sets_role and source_overwrites_role) or drops_source:
                findings.append(f"{name}:admin-audit-query-source-overwrites-subject-role")
        cleanup_open = _storage_cleanup_open_handler_body(source)
        if cleanup_open and "showModal(" in cleanup_open:
            writes_count = "candidate_count" in cleanup_open
            writes_bytes = "candidate_bytes" in cleanup_open
            writes_summary = "data-storage-cleanup-summary" in cleanup_open
            if not (writes_count and writes_bytes and writes_summary):
                findings.append(f"{name}:storage-cleanup-confirm-opens-without-scan-totals")
            if writes_count and "truncated" not in cleanup_open:
                findings.append(f"{name}:storage-cleanup-omits-truncated-window")
        pause_copy = _management_action_pause_copy(source)
        if pause_copy:
            missing_login = "不能登录" not in pause_copy
            keeps_issue = "不能发卡" in pause_copy
            keeps_redeem = "兑换" in pause_copy
            if missing_login and keeps_issue and keeps_redeem:
                findings.append(f"{name}:pause-copy-omits-login-block")
        reset_copy = _management_action_reset_copy(source)
        if reset_copy:
            if "不受换机开关" not in reset_copy or "旧电脑可能还要过一会儿才停" not in reset_copy:
                findings.append(f"{name}:reset-copy-omits-switch-and-delay")
        block_copy = _management_action_block_copy(source)
        if block_copy:
            if "封禁整台设备" in block_copy or "其他授权也会一起无法验证" in block_copy:
                findings.append(f"{name}:block-copy-still-freezes-whole-device")
            if "这张卡" not in block_copy:
                findings.append(f"{name}:block-copy-omits-this-card")
        unblock_copy = _management_action_unblock_copy(source)
        if unblock_copy:
            if "不复活历史绑定" in unblock_copy or "仍需重新激活" in unblock_copy:
                findings.append(f"{name}:unblock-copy-still-requires-reactivate")
        archive_copy = _management_action_archive_copy(source)
        if archive_copy and "已激活仍可用" not in archive_copy:
            findings.append(f"{name}:archive-copy-omits-activated-still-works")
        delete_copy = _management_action_delete_copy(source)
        if delete_copy and "已激活仍可用" not in delete_copy:
            findings.append(f"{name}:delete-copy-omits-activated-still-works")
        if "function openManagementAction" in source:
            if "data-management-action-inventory" not in source:
                findings.append(f"{name}:management-action-omits-property-inventory")
            if "在役授权" not in source:
                findings.append(f"{name}:management-action-inventory-omits-active-count")
        filter_map_start = source.find("const LICENSE_STATUS_FILTER_TO_API")
        if filter_map_start >= 0:
            filter_brace = source.find("{", filter_map_start)
            filter_map = _js_brace_body(source, filter_brace) if filter_brace >= 0 else ""
            if "已禁用" in filter_map or "disabled" in filter_map:
                findings.append(f"{name}:license-status-filter-maps-disabled")
        if "/manage/authorizations/devices/${encodeURIComponent(deviceId)}/" in source:
            findings.append(f"{name}:block-url-omits-authorization-id")
        if 'device.risk_state === "blocked" ? "解除封禁"' in source or "device.risk_state === 'blocked' ? \"解除封禁\"" in source:
            findings.append(f"{name}:block-button-uses-device-risk-state")
        if "function renderAuthorizationRiskRows" in source and "item.card_frozen" not in source:
            findings.append(f"{name}:block-button-omits-card-frozen")
        if "需重新激活" in source or "不自动恢复绑定" in source:
            findings.append(f"{name}:unblock-preview-still-requires-reactivate")
        if 'data-reset-device' in source and 'textContent = "重置设备"' in source:
            findings.append(f"{name}:downstream-reset-button-omits-unbind-copy")
        if re.search(r'appendAuthorizationRiskAction\(\s*actions,\s*"重置设备"\s*,\s*"reset"', source):
            findings.append(f"{name}:admin-reset-button-omits-unbind-copy")
        if "data-catalog-scope-save" in source:
            missing_unused = "未激活卡不能再开通" not in source
            missing_verify = "已开通验证不受影响" not in source
            missing_reclaim = "回收退额度" not in source
            if missing_unused or missing_verify or missing_reclaim:
                findings.append(f"{name}:catalog-scope-copy-omits-unused-activate-block")
            if "不能再发" not in source:
                findings.append(f"{name}:catalog-scope-copy-omits-cannot-issue")
        if re.search(r"allow_device_switch:\s*false", source) and re.search(r"device_switch_limit:\s*0", source):
            findings.append(f"{name}:catalog-create-posts-switch-off")
        inspect_body = _js_event_listener_body(source, "[data-backup-restore-form]", "submit")
        apply_body = _js_event_listener_body(source, "[data-backup-restore-apply]", "click")
        file_change = _js_event_listener_body(source, "elements.backup_file", "change")
        if not file_change:
            file_change = _js_event_listener_body(source, '[name="backup_file"]', "change")
        if inspect_body and "dataset.stagingId" in inspect_body:
            resets_on_change = bool(
                file_change
                and (
                    "resetBackupRestoreConfirm" in file_change
                    or 'dataset.stagingId = ""' in file_change
                    or "dataset.stagingId = ''" in file_change
                )
            )
            if not resets_on_change:
                findings.append(f"{name}:restore-file-change-keeps-staging")
            guards_stale = (
                "lastModified" in inspect_body
                or "restoreInspectGeneration" in inspect_body
                or "backupRestoreFileToken" in inspect_body
            )
            if "await" in inspect_body and not guards_stale:
                findings.append(f"{name}:restore-inspect-applies-stale-file-staging")
        if apply_body and "/manage/backup/restore/" in apply_body:
            for finally_body in _js_finally_bodies(apply_body):
                if not re.search(r"disabled\s*=\s*false", finally_body):
                    continue
                if not re.search(r"if\s*\(\s*!", finally_body):
                    findings.append(f"{name}:restore-apply-reenables-after-success")
                    break
        catalog_fn = _js_function_body(source, "function renderPlanCatalog")
        filter_fn = _js_function_body(source, "function applyPlanCatalogFilter")
        if catalog_fn:
            skips_empty = bool(re.search(r"if\s*\(\s*!softwarePlans\.length\s*\)\s*return", catalog_fn))
            has_local_empty = bool(
                filter_fn
                and "data-plan-catalog-empty" in filter_fn
                and "请联系管理员" in filter_fn
            )
            if skips_empty and not has_local_empty:
                findings.append(f"{name}:plan-catalog-hides-empty-software-without-local-empty")
            if filter_fn and "先建套餐" in filter_fn:
                findings.append(f"{name}:plan-catalog-empty-tells-downstream-to-create-plan")
        preview_fn = _js_function_body(source, "function updateIssuePreview")
        if preview_fn:
            treats_missing_as_zero = bool(re.search(r"dataset\.cost\s*\|\|\s*[\"']0[\"']", preview_fn))
            if treats_missing_as_zero or ("canGenerate" in preview_fn and "请联系管理员" not in preview_fn):
                findings.append(f"{name}:issue-preview-treats-missing-plan-cost-as-zero")
            if "先建套餐" in preview_fn:
                findings.append(f"{name}:issue-empty-plan-tells-downstream-to-create-plan")
            apply_balance = _js_function_body(source, "function applyDownstreamLedgerBalance")
            sync_balance = _js_function_body(source, "function syncIssueAvailableBalance")
            if "canGenerate" in preview_fn and "dataset.availableBalance" in preview_fn:
                apply_writes = bool(
                    apply_balance
                    and "available_balance" in apply_balance
                    and (
                        "dataset.availableBalance" in apply_balance
                        or "syncIssueAvailableBalance" in apply_balance
                    )
                )
                if not apply_writes:
                    findings.append(f"{name}:issue-gate-ignores-ledger-available-balance")
            if sync_balance and re.search(r"textContent|innerText", sync_balance):
                findings.append(f"{name}:issue-gate-parses-locale-balance-text")
            if apply_balance and re.search(
                r"dataset\.availableBalance\s*=\s*[^\n]*(?:textContent|innerText)",
                apply_balance,
            ):
                findings.append(f"{name}:issue-gate-parses-locale-balance-text")
        withdraw = _withdraw_confirm_handler_body(source)
        if withdraw:
            disables = "disabled = true" in withdraw or "disabled=true" in withdraw
            restores = "finally" in withdraw and (
                "resetWithdrawConfirm" in withdraw or "disabled = false" in withdraw
            )
            close_resets = bool(
                re.search(
                    r"withdrawReleaseDialog[\s\S]{0,400}(?:resetWithdrawConfirm|disabled\s*=\s*false)",
                    source,
                )
            )
            if disables and not restores and not close_resets:
                findings.append(f"{name}:withdraw-confirm-stays-disabled-after-success")
        bind_triggers = _js_function_body(source, "function bindDialogTriggers")
        if bind_triggers and re.search(
            r"dialog === releaseDialog\)\s*showReleaseStage\(\"upload\"",
            bind_triggers,
        ):
            findings.append(f"{name}:release-dialog-open-does-not-copy-table-software")
        elif bind_triggers and "releaseDialog" in bind_triggers and "syncReleaseUploadSoftwareFromTable" not in bind_triggers:
            findings.append(f"{name}:release-dialog-open-does-not-copy-table-software")
        upload = _release_next_handler_body(source)
        if upload and 'form.append("software_id"' in upload:
            if "releaseUploadSoftwareId" not in upload and "data-release-context" not in upload:
                findings.append(f"{name}:release-upload-posts-dialog-software")
        package_fn = _js_function_body(source, "function packageValidationError")
        if package_fn and any(
            token in package_fn
            for token in ("hash-fail", "manifest-mismatch", "signature-fail", "no-manifest")
        ):
            findings.append(f"{name}:release-package-validates-by-filename")
        support_load = _js_function_body(source, "async function loadDownstreamSupport")
        if support_load and "data-support-purchase" in support_load:
            if "supportLoadGeneration" not in support_load and "generation !==" not in support_load:
                findings.append(f"{name}:support-load-applies-stale-software")
        support_save = _support_save_handler_body(source)
        if support_save and "/downstream/support/" in support_save:
            uses_live = bool(re.search(r"select\?\.value|select\.value", support_save))
            if uses_live and "supportLoadedSoftwareId" not in support_save:
                findings.append(f"{name}:support-save-posts-live-select")
            if re.search(r"wechat:\s*contact", support_save) and not re.search(
                r"qq:\s*contact",
                support_save,
            ):
                findings.append(f"{name}:support-save-locks-contact-to-wechat")
            if re.search(r'wechat:\s*""', support_save):
                findings.append(f"{name}:support-save-posts-empty-wechat")
        if support_load and re.search(
            r"support\.(?:wechat|qq)\s*\|\|\s*support\.(?:wechat|qq)",
            support_load,
        ):
            findings.append(f"{name}:support-load-merges-contact-candidates")
        if re.search(
            r"location\.href\s*=\s*(?:response\.redirect\s*\|\|\s*)?form\.dataset\.previewDestination\b",
            source,
        ):
            findings.append(f"{name}:login-jumps-without-workspace-hash")
        if re.search(r'location\.href\s*=\s*"manage.html"', source):
            findings.append(f"{name}:session-bounce-missing-overview-hash")
        if re.search(r'location\.href\s*=\s*"downstream.html"', source):
            findings.append(f"{name}:session-bounce-missing-workspace-hash")
        if (
            "function activateScreen" in source
            and "const requestedScreen = window.location.hash.slice(1)" in source
        ):
            if "access-preview" not in source or not re.search(
                r"replaceState[\s\S]{0,220}#\$\{defaultScreen\}",
                source,
            ):
                findings.append(f"{name}:workbench-boot-missing-default-hash")
        clear_transient = _js_function_body(source, "function clearTransientQuery")
        if clear_transient and "credential" not in clear_transient:
            findings.append(f"{name}:clear-transient-query-keeps-credential")
        if redeem_handler and "loadDownstreamCredits(" in redeem_handler:
            if not re.search(r"loadDownstreamCredits\(\s*1\s*\)", redeem_handler):
                findings.append(f"{name}:redeem-keeps-current-ledger-page")
        ensure_body = _ensure_table_state_body(source)
        if ensure_body and (
            "data-admin-ledger-pagination" not in ensure_body
            or "data-downstream-ledger-pagination" not in ensure_body
        ):
            findings.append(f"{name}:ledger-missing-from-server-pagination-selectors")
        load_admin = re.search(
            r"async function loadAdminCredits\([\s\S]*?\n\s*function applyDownstreamLedgerBalance",
            source,
        )
        load_admin_body = load_admin.group(0) if load_admin else ""
        if load_admin_body:
            if re.search(
                r"\(payload\.accounts \|\| \[\]\)\.reduce\(\(total, account\) => total \+ Number\(account\.available_balance",
                load_admin_body,
            ):
                findings.append(f"{name}:credits-balance-sums-all-accounts")
            if "operating_available_balance" not in load_admin_body:
                findings.append(f"{name}:credits-balance-missing-operating-total")
        quota_rows = _quota_card_rows_body(source)
        if quota_rows and re.search(
            r'item\.redeemed_by\s*\?[\s\S]*?:\s*"任何活跃下游可兑换',
            quota_rows,
        ):
            findings.append(f"{name}:quota-revoked-fifth-column-says-redeemable")
        invite_rows = _invitation_rows_body(source)
        if invite_rows and re.search(
            r"appendTextCell\(\s*row,\s*item\.consumed_at\s*\?[^;\n]*(?:永久有效|item\.expires_at)",
            invite_rows,
        ):
            findings.append(f"{name}:invitation-unused-used-time-says-permanent")
        revoke_handler = _quota_revoke_confirm_handler_body(source)
        if revoke_handler:
            if re.search(
                r"for \(const publicId of ids\) \{\s*await apiRequest\(",
                revoke_handler,
            ):
                findings.append(f"{name}:quota-revoke-stops-on-first-failure")
            if re.search(r"showToast\(`已作废 \$\{ids\.length\}", revoke_handler):
                findings.append(f"{name}:quota-revoke-toasts-selection-count")
            if "作废失败，未兑换码状态未全部改变" in revoke_handler:
                findings.append(f"{name}:quota-revoke-hides-partial-results")
            for try_body in _js_try_bodies(revoke_handler):
                posted = "/revoke/" in try_body and re.search(r'method:\s*"POST"', try_body)
                if posted and "loadAdminCredits(" in try_body:
                    findings.append(f"{name}:quota-revoke-treats-refresh-as-revoke-failure")
                    break
        export_handler = re.search(
            r'querySelectorAll\("\[data-export\]"\)\.forEach\(\(button\) => \{([\s\S]*?)\n  \}\);',
            source,
        )
        export_body = export_handler.group(1) if export_handler else ""
        if 'dataset.exportQuery === "licenses"' in source and "hasCredentialSearchOverlay" not in export_body:
            findings.append(f"{name}:license-export-ignores-exact-search")
        if 'dataset.exportQuery === "quota-cards"' in source and "hasCredentialSearchOverlay" not in export_body:
            findings.append(f"{name}:quota-export-ignores-exact-search")
        admin_body = _js_function_body_skip_signature(source, "async function searchAdminCredential") or _js_function_body(
            source, "async function searchAdminCredential"
        )
        if "async function searchAdminCredential" in source:
            if "setQuotaCardServerPagination(null)" not in admin_body:
                findings.append(f"{name}:quota-search-keeps-pagination")
            if "setInvitationServerPagination(null)" not in admin_body:
                findings.append(f"{name}:invitation-search-keeps-pagination")
        apply_filters = re.search(
            r"function applyCredentialFilters\(group, options = \{\}\) \{([\s\S]*?)\n(?:  )?function ",
            source,
        )
        apply_body = apply_filters.group(1) if apply_filters else ""
        if "loadLicenseCards(1)" in apply_body and "hasCredentialSearchOverlay" not in apply_body:
            findings.append(f"{name}:credential-filter-reloads-during-exact-search")
        reclaim_click = re.search(
            r'dataset\.reclaimFiltered = ""[\s\S]*?addEventListener\("click", async \(\) => \{([\s\S]*?)const dialog = document\.getElementById',
            source,
        )
        reclaim_body = reclaim_click.group(1) if reclaim_click else ""
        if "dataset.reclaimFiltered" in source and reclaim_body and "hasCredentialSearchOverlay" not in reclaim_body:
            findings.append(f"{name}:filtered-reclaim-checks-input-only")
        if "function installInvitationIssue" in source:
            invite_issue = re.search(
                r"function installInvitationIssue\([\s\S]*?\n  function ",
                source,
            )
            invite_body = invite_issue.group(0) if invite_issue else source
            if re.search(
                r'"Idempotency-Key":\s*requestIdempotencyKey\("invitation-issue"\)',
                invite_body,
            ):
                findings.append(f"{name}:invitation-issue-mints-new-idempotency-key")
            if "dataset.inviteKey" not in invite_body:
                findings.append(f"{name}:invitation-issue-missing-pinned-idempotency-key")
            elif 'dataset.inviteKey = ""' not in invite_body and "dataset.inviteKey = ''" not in invite_body:
                findings.append(f"{name}:invitation-issue-keeps-key-after-success")
        if "data-credit-adjust-confirm" in source:
            if re.search(
                r'"Idempotency-Key":\s*requestIdempotencyKey\("credit-adjust"\)',
                source,
            ):
                findings.append(f"{name}:credit-adjust-mints-new-idempotency-key")
            if "dataset.adjustKey" not in source:
                findings.append(f"{name}:credit-adjust-missing-pinned-idempotency-key")
            elif 'dataset.adjustKey = ""' not in source and "dataset.adjustKey = ''" not in source:
                findings.append(f"{name}:credit-adjust-keeps-key-after-success")
            if "可能已经入账" not in source:
                findings.append(f"{name}:credit-adjust-retry-copy-omits-already-posted")
    if name == "preview.js" and (
        "loadCatalog" in source or "/manage/catalog/" in source or "fetchAllCollectionPages" in source
    ):
        if "async function fetchAllCollectionPages" not in source:
            findings.append(f"{name}:missing-fetch-all-collection-pages")
        if "options.pageSize || 100" not in source:
            findings.append(f"{name}:collection-page-size-not-100")
        if "options.maxPages || 20" not in source:
            findings.append(f"{name}:collection-max-pages-not-20")
        if not re.search(r"async function loadCatalog\(\)[\s\S]*?fetchAllCollectionPages\(", source):
            findings.append(f"{name}:load-catalog-skips-pagination")
        if not re.search(r"async function loadDownstreams\(\)[\s\S]*?fetchAllCollectionPages\(", source):
            findings.append(f"{name}:load-downstreams-skips-pagination")
        if "extraQuery: { status }" not in source:
            findings.append(f"{name}:downstream-status-query-missing")
        if "function fillCreditAdjustDialog" in source:
            match = re.search(r"function fillCreditAdjustDialog\(\) \{([\s\S]*?)\n  function ", source)
            body = match.group(1) if match else ""
            if "downstreamProfiles" in body:
                findings.append(f"{name}:credit-adjust-reuses-downstream-table")
            if "quotaAccountsCache" not in body:
                findings.append(f"{name}:credit-adjust-missing-accounts-cache")
            if "item.downstream_public_id" not in body:
                findings.append(f"{name}:credit-adjust-missing-downstream-public-id")
        if "async function applyReleaseContext(items)" in source:
            findings.append(f"{name}:release-context-uses-current-page")
        if "async function applyReleaseContext(softwareId)" in source:
            match = re.search(
                r"async function applyReleaseContext\(softwareId\) \{([\s\S]*?)\n\s*function fillReleaseSignatureStatus",
                source,
            )
            body = match.group(1) if match else ""
            if "await loadPublishedReleases(softwareId)" not in body:
                findings.append(f"{name}:release-context-skips-published-query")
            if "softwareId === \"all\"" not in body or "请选择软件" not in body:
                findings.append(f"{name}:release-context-uses-all-as-current-page")
            if re.search(
                r"catch[\s\S]{0,240}current\s*=\s*null[\s\S]{0,480}暂无发布",
                body,
            ):
                findings.append(f"{name}:release-card-paints-published-failure-as-empty")
            if "++releaseContextRequestGeneration" not in body:
                findings.append(f"{name}:release-card-missing-generation")
            if "generation !== releaseContextRequestGeneration" not in body and "generation === releaseContextRequestGeneration" not in body:
                findings.append(f"{name}:release-card-applies-stale-software")
            if "releaseContext?.value" not in body:
                findings.append(f"{name}:release-card-applies-stale-software")
            if "paintReleaseUpdateCopy" not in body and "[data-update-copy]" not in body:
                findings.append(f"{name}:release-card-missing-update-copy")
            helper = _js_function_body(source, "function paintReleaseUpdateCopy")
            if "paintReleaseUpdateCopy" in source and helper and "[data-update-copy]" not in helper:
                findings.append(f"{name}:release-card-missing-update-copy")
            published = re.search(
                r"async function loadPublishedReleases\(softwareId[^)]*\) \{([\s\S]*?)\n  async function applyReleaseContext",
                source,
            )
            published_body = published.group(1) if published else ""
            if "has_next" not in published_body:
                findings.append(f"{name}:published-release-loader-skips-pagination")
        if "async function loadReleasesForSoftware" in source:
            listed = re.search(
                r"async function loadReleasesForSoftware\([\s\S]*?\) \{([\s\S]*?)\n  function catalogSoftwareForRelease",
                source,
            )
            listed_body = listed.group(1) if listed else ""
            if "++releaseListRequestGeneration" not in listed_body:
                findings.append(f"{name}:release-list-missing-generation")
            if "generation !== releaseListRequestGeneration" not in listed_body:
                findings.append(f"{name}:release-list-applies-stale-response")
        if "function currentReclaimFilters" in source:
            reclaim = re.search(
                r"function currentReclaimFilters\(panel\) \{([\s\S]*?)\n  function currentFilteredReclaimRows",
                source,
            )
            reclaim_body = reclaim.group(1) if reclaim else ""
            if 'recordScope: "scope"' not in reclaim_body:
                findings.append(f"{name}:reclaim-filters-missing-record-scope")
    if name == "preview.js":
        chrome = _js_function_body(source, "function bindDialogChrome")
        if chrome and "event.target === dialog" in chrome:
            findings.append(f"{name}:dialog-light-dismiss-on-overlay")
        apply_filters = _js_function_body_skip_signature(source, "function applyCredentialFilters")
        if apply_filters and "loadLicenseCards(1)" in apply_filters and "restoreCredentialFilters" not in apply_filters:
            findings.append(f"{name}:credential-filter-failure-does-not-restore")
        sync_plans = _js_function_body(source, "function syncLicenseCredentialFilters")
        if sync_plans and re.search(
            r'querySelectorAll\(\s*[\'"]\[data-credential-filter="codePlan"\][\'"]\s*\)',
            sync_plans,
        ):
            findings.append(f"{name}:quota-codeplan-filter-shares-license-plans")
        apply_analytics = _js_function_body(source, "function applyAnalyticsPayload")
        if apply_analytics and ("renderOverviewCards(" in apply_analytics or "updateRevenueGrids(" in apply_analytics):
            findings.append(f"{name}:analytics-payload-writes-overview")
        if "async function loadOverviewSnapshot" not in source and "function renderOverviewCards" in source:
            findings.append(f"{name}:overview-missing-unfiltered-snapshot-loader")
        if re.search(r"共 \$\{pagination\.total\} 份授权", source):
            findings.append(f"{name}:downstream-device-summary-says-authorization-count")
        apply_backup = _js_function_body(source, "function applyBackupDashboard")
        if apply_backup and "上次证明异常" in apply_backup and 'last_result === "missing"' not in apply_backup:
            findings.append(f"{name}:backup-missing-marker-labeled-proof-error")
        last_result_call = re.search(r'setBackupMetric\(\s*["\']last-result["\']', apply_backup or "")
        if last_result_call:
            rest = apply_backup[last_result_call.end() :]
            next_call = re.search(r"setBackupMetric\(", rest)
            chunk = rest[: next_call.start()] if next_call else rest
            if "排队等待执行" in chunk:
                findings.append(f"{name}:backup-queue-overwrites-last-result")
        if "function applyBackupDashboard" in source and not re.search(
            r'setBackupMetric\(\s*["\']queue["\']', source
        ):
            findings.append(f"{name}:backup-queue-metric-missing")
        bootstrap = _js_function_body(source, "async function bootstrapB1Runtime")
        if bootstrap and "isAccessPage" in bootstrap and 'workspaceLandingUrl("manage.html")' not in bootstrap and 'window.location.href = "manage.html"' not in bootstrap:
            findings.append(f"{name}:access-page-logged-in-stays-on-form")
        if bootstrap and "isAccessPage" in bootstrap and "data-session-switch-hint" not in bootstrap:
            findings.append(f"{name}:access-login-still-bounces-authenticated")
        if bootstrap and "loadPublicQuotaPurchaseLink" in bootstrap and "keepOnEmpty: true" not in bootstrap:
            findings.append(f"{name}:purchase-link-failure-clears-as-unconfigured")
        if "function adminAuditQuery" in source and "appliedAdminAuditQuery" not in source:
            findings.append(f"{name}:admin-audit-export-uses-live-unapplied-query")
        if "issueSubmit?.addEventListener" in source and (
            "let issuePosted = false" not in source or "if (issuePosted) updateIssuePreview()" not in source
        ):
            findings.append(f"{name}:issue-failure-refreshes-expired-preview")
        if "/manage/invitations/" in source and not re.search(
            r"/manage/invitations/\$\{[^}]+\}/revoke/",
            source,
        ):
            findings.append(f"{name}:invitation-revoke-json-missing")
        if "creditRecoverDeletedDialog" in source and "/manage/credits/recover-deleted/" not in source:
            findings.append(f"{name}:recover-deleted-json-missing")
        load_client = _js_function_body(source, "async function loadClientProfileConfig")
        if load_client and "clientConfigLoadGeneration" not in load_client:
            findings.append(f"{name}:client-config-load-applies-stale-software")
        if load_client:
            catch_idx = load_client.rfind("catch")
            catch_body = load_client[catch_idx:] if catch_idx >= 0 else ""
            if "applyClientConfig(null)" in catch_body and "generation !== clientConfigLoadGeneration" not in catch_body:
                findings.append(f"{name}:client-config-catch-ignores-generation")
        normalize_plan = _js_function_body(source, "function normalizeCatalogPlan")
        if normalize_plan and "test_only" in normalize_plan and "仅测试" not in normalize_plan:
            findings.append(f"{name}:issue-plan-option-missing-test-only-label")
        quota_rows = _quota_card_rows_body(source)
        if quota_rows and re.search(r'item\.status\s*===\s*["\']issued["\']\s*\?[\s\S]{0,80}可兑换', quota_rows):
            findings.append(f"{name}:quota-issued-fifth-column-says-redeemable")
    if name == "manage.html":
        software_panel = _screen_panel_block(source, "software")
        if software_panel and "search-field" not in software_panel:
            findings.append(f"{name}:software-table-missing-name-search")
        if 'data-record-view-scope="quota-cards"' in source and 'data-credential-filter="codeAmount"' not in source:
            findings.append(f"{name}:quota-amount-filter-missing")
        if 'data-record-view-scope="invitations"' in source and 'id="invitationRevokeDialog"' not in source:
            findings.append(f"{name}:invitation-revoke-dialog-missing")
        if 'data-screen-panel="credits"' in source and 'id="creditRecoverDeletedDialog"' not in source:
            findings.append(f"{name}:recover-deleted-dialog-missing")
        if 'data-screen-panel="backup"' in source and 'data-backup-metric="queue"' not in source:
            findings.append(f"{name}:backup-queue-metric-missing")
        if re.search(r'value="blocked">\s*待复核', source):
            findings.append(f"{name}:risk-blocked-labeled-pending-review")
        invitation_search_ok = (
            'placeholder="完整邀请码"' in source
            or "粘客户发来的完整邀请码" in source
        )
        if not invitation_search_ok and "邀请码" in source and "尾号" in source:
            findings.append(f"{name}:invitation-search-mentions-suffix")
    if name in {"manage-login.html", "downstream-login.html"}:
        if "data-session-switch-hint" not in source:
            findings.append(f"{name}:login-missing-session-switch-hint")
    if name in {"manage-login.html", "downstream-login.html", "downstream-register.html"}:
        if (
            "access-preview" in source
            or "data-preview-destination" in source
            or "data-login-form" in source
        ) and 'class="toast"' not in source:
            findings.append(f"{name}:access-page-missing-toast")
    if name == "preview.css":
        if re.search(r"dialog\.modal\s*\{[^}]*overflow:\s*hidden", source):
            findings.append(f"{name}:modal-overflow-hidden-clips-actions")
        if '.form-label input[type="checkbox"]' not in source and "input:not([type=\"checkbox\"])" not in source:
            findings.append(f"{name}:form-label-stretches-checkboxes")
        scope_box = re.search(r"\[data-catalog-scope-options\]\s*\{[^}]*\}", source)
        if not scope_box or "max-height" not in scope_box.group(0) or "overflow: auto" not in scope_box.group(0):
            findings.append(f"{name}:catalog-scope-options-missing-scroll")
        code_list = re.search(r"\.credential-code-list\s*\{[^}]*\}", source)
        if not code_list or "max-height" not in code_list.group(0) or "overflow: auto" not in code_list.group(0):
            findings.append(f"{name}:generated-code-list-missing-scroll")
        actions = re.search(r"\.modal-actions\s*\{[^}]*\}", source)
        if not actions or "position: sticky" not in actions.group(0):
            findings.append(f"{name}:modal-actions-not-sticky")
        modal_box = re.search(r"(?<![-\w])\.modal\s*\{[^}]*\}", source)
        if not modal_box or "max-height" not in modal_box.group(0) or "100vh" not in modal_box.group(0):
            findings.append(f"{name}:modal-missing-viewport-max-height")
        scroll_td = re.search(r"\.table-scroll td\s*\{[^}]*\}", source)
        if (
            not scroll_td
            or "max-width" not in scroll_td.group(0)
            or "text-overflow: ellipsis" not in scroll_td.group(0)
        ):
            findings.append(f"{name}:table-cells-grow-without-ellipsis")
        action_col = re.search(r"td:has\(\.table-actions\)\s*\{[^}]*\}", source)
        if not action_col or "position: sticky" not in action_col.group(0):
            findings.append(f"{name}:table-action-column-not-sticky")
        if "td:last-child button" not in source:
            findings.append(f"{name}:table-last-column-buttons-not-sticky")
        detail_dd = re.search(r"\.credential-detail-grid dd\s*\{[^}]*\}", source)
        if not detail_dd or "max-height" not in detail_dd.group(0) or "overflow: auto" not in detail_dd.group(0):
            findings.append(f"{name}:detail-grid-grows-without-scroll")
        impact_b = re.search(r"\.impact-box b\s*\{[^}]*\}", source)
        if not impact_b or "max-height" not in impact_b.group(0):
            findings.append(f"{name}:impact-box-grows-without-scroll")
        if not re.search(r"@media\s*\(max-height:\s*720px\)\s*\{[\s\S]*?\.access-shell", source):
            findings.append(f"{name}:access-missing-short-viewport")
        if not re.search(
            r"\[data-backup-restore-confirm\]:not\(\[hidden\]\)\s*\{[^}]*position:\s*sticky",
            source,
        ):
            findings.append(f"{name}:restore-confirm-not-sticky")
        if not re.search(
            r"\[data-backup-restore-confirm\]:not\(\[hidden\]\)\s*\{[^}]*max-height:[^}]*overflow:\s*auto",
            source,
        ):
            findings.append(f"{name}:restore-confirm-not-capped")
    if name == "preview.js" and 'className = "form-label checkbox-label"' in source:
        findings.append(f"{name}:catalog-scope-uses-stretching-form-label")
    if name == "preview.js":
        if re.search(
            r"issueSubmit\.disabled = true;\s*issueSubmit\.setAttribute\(\"aria-disabled\", \"true\"\);\s*if \(issueError\) issueError\.textContent = apiErrorMessage\(error, \"成本预览失败",
            source,
        ):
            findings.append(f"{name}:issue-preview-error-leaves-submit-disabled")
        if 'createElement("dialog")' in source and source.count('createElement("dialog")') > 1:
            findings.append(f"{name}:extra-generated-dialog")
        if 'getElementById("reclaimBatch")' in source and "function formatJoinedSummary" not in source:
            findings.append(f"{name}:reclaim-batch-missing-joined-summary")
        text_cell = _js_function_body(source, "function appendTextCell")
        if text_cell and "cell.title" not in text_cell:
            findings.append(f"{name}:table-text-cell-missing-title-tooltip")
        if re.search(
            r'\[data-release-back\][\s\S]{0,280}showReleaseStage\("upload", 0\)',
            source,
        ) and not re.search(
            r'\[data-release-back\][\s\S]{0,400}readReleaseFile\(\)',
            source,
        ):
            findings.append(f"{name}:release-back-skips-reread-file")
        retry_pos = source.find("12 秒后可重试")
        if retry_pos >= 0:
            window = source[retry_pos : retry_pos + 700]
            if "setTimeout" not in window or "disabled = false" not in window:
                findings.append(f"{name}:error-429-retry-never-reenables")
        confirm_pos = source.find("confirmBox.hidden = false")
        if confirm_pos >= 0:
            window = source[confirm_pos : confirm_pos + 450]
            if "scrollIntoView" not in window:
                findings.append(f"{name}:restore-confirm-missing-scroll-into-view")
        if re.search(
            r"本次扫描失败[\s\S]{0,280}storageCleanupDialog\?\.showModal",
            source,
        ):
            findings.append(f"{name}:storage-cleanup-failure-still-opens-modal")
        if "function renderDownstreamDeviceRows" in source and "function wrapTableActions" not in source:
            findings.append(f"{name}:action-cells-missing-shared-wrap")
    if name in {"manage.html", "downstream.html"}:
        dialog_tags = re.findall(r"<dialog\b([^>]*)>", source, re.I | re.S)
        if len(dialog_tags) >= 2:
            if any("modal" not in attrs for attrs in dialog_tags):
                findings.append(f"{name}:html-dialog-missing-modal-class")
            if "modal-actions" not in source:
                findings.append(f"{name}:html-dialog-missing-modal-actions")
    if html_source:
        for match in ARCHIVE_METRIC_PATTERN.finditer(source):
            if match.group(1).strip() not in {"", "—"}:
                findings.append(f"{name}:static-metric")
    return findings


def validate_frozen_page_content(root: Path) -> list[Check]:
    findings: list[str] = []
    missing = [name for name in ARCHIVE_PREVIEW_NAMES if not (root / name).is_file()]
    findings.extend(f"missing:{name}" for name in missing)
    findings.extend(_extra_preview_page_findings(root))
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".html", ".js", ".css"}:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(path.name)
            continue
        findings.extend(_static_preview_findings(path.name, source, strict=True))
    return [
        _check(
            "frozen_ui_no_static_fixtures",
            not findings,
            "冻结前端文件齐全且不含静态业务样本。" if not findings else "冻结前端缺文件或仍包含静态业务样本。",
        )
    ]


class _UnsafeCandidateArchive(ValueError):
    """A candidate archive contains ambiguous or non-regular preview members."""


def _archive_preview_sources(path: Path) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}

    def logical_name(name: str) -> str | None:
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or ".." in normalized.split("/"):
            raise _UnsafeCandidateArchive
        parts = normalized.strip("/").split("/")
        for index in range(len(parts) - 1):
            if parts[index : index + 2] == ["docs", "ui-preview"]:
                relative = "/".join(parts[index + 2 :])
                return relative or None
        return None

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir() or member.filename.replace("\\", "/").endswith("/"):
                    continue
                relative = logical_name(member.filename)
                if relative is None:
                    continue
                if relative not in ARCHIVE_PREVIEW_NAMES:
                    raise _UnsafeCandidateArchive
                mode = (member.external_attr >> 16) & 0xFFFF
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                    raise _UnsafeCandidateArchive
                if relative in sources:
                    raise _UnsafeCandidateArchive
                sources[relative] = archive.read(member)
        return sources

    with tarfile.open(path, mode="r:*") as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            relative = logical_name(member.name)
            if relative is None:
                continue
            if relative not in ARCHIVE_PREVIEW_NAMES or not member.isfile():
                raise _UnsafeCandidateArchive
            if relative in sources:
                raise _UnsafeCandidateArchive
            source_file = archive.extractfile(member)
            if source_file is not None:
                sources[relative] = source_file.read()
    return sources


def _archive_sample_findings(name: str, source: str) -> list[str]:
    findings: list[str] = []
    scan_source = unescape(source) if name.lower().endswith(".html") else source
    for line_number, line in enumerate(scan_source.splitlines(), start=1):
        for marker in STATIC_PREVIEW_MARKERS:
            if marker in line:
                findings.append(f"{name}:{line_number}:{marker}")
        if re.search(r"\b(?:LIC|INV|QUOTA)-", line):
            findings.append(f"{name}:{line_number}:credential-prefix")
        if name.lower().endswith(".html") and any(attribute in line for attribute in ARCHIVE_BUSINESS_ATTRIBUTES):
            findings.append(f"{name}:{line_number}:business-row-attribute")
    return findings


def validate_candidate_archive(path: Path) -> list[Check]:
    findings: list[str] = []
    try:
        sources = _archive_preview_sources(path)
        findings.extend(f"missing:{name}" for name in ARCHIVE_PREVIEW_NAMES if name not in sources)
        for name, raw in sources.items():
            try:
                source = raw.decode("utf-8")
                findings.extend(_archive_sample_findings(name, source))
                findings.extend(_static_preview_findings(name, source, strict=True))
            except UnicodeDecodeError:
                findings.append(f"{name}:invalid-utf8")
    except (OSError, tarfile.TarError, zipfile.BadZipFile, UnicodeDecodeError, KeyError, RuntimeError) as exc:
        return [_check("candidate_archive_no_static_fixtures", False, f"候选归档无法扫描：{exc.__class__.__name__}。")]
    except _UnsafeCandidateArchive:
        return [_check("candidate_archive_no_static_fixtures", False, "候选归档结构不安全，未接受重复、额外或非普通文件。")]
    return [
        _check(
            "candidate_archive_no_static_fixtures",
            not findings,
            "候选归档冻结页面齐全且不含静态业务样本。" if not findings else "候选归档缺少冻结文件或仍包含静态业务样本。",
        )
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_migration_checks(root: Path, python_executable: str | None = None) -> list[Check]:
    python = python_executable or sys.executable
    manage = root / "manage.py"
    checks: list[Check] = []
    commands = (
        ("migration_files", (python, str(manage), "makemigrations", "--check", "--dry-run")),
        ("migration_plan", (python, str(manage), "migrate", "--plan")),
        ("migration_applied", (python, str(manage), "migrate", "--check")),
    )
    for name, command in commands:
        try:
            completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(_check(name, False, f"迁移检查未完成：{exc.__class__.__name__}。"))
            continue
        checks.append(_check(name, completed.returncode == 0, "迁移命令通过。" if completed.returncode == 0 else "迁移命令未通过。"))
    return checks


def safe_summary(checks: Sequence[Check]) -> dict[str, object]:
    failed = [item.name for item in checks if item.status != "passed"]
    return {
        "schema_version": 1,
        "status": "passed" if not failed else "blocked",
        "failed_checks": failed,
        "checks": [asdict(item) for item in checks],
        "secret_values_exposed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run local read-only release candidate checks.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--nginx-config", type=Path)
    parser.add_argument("--run-migrations", action="store_true")
    parser.add_argument("--candidate-archive", type=Path, help="候选 tar/zip 归档路径；扫描其中的冻结前端内容。")
    parser.add_argument("--source-only", action="store_true", help="只检查当前源码树；候选出口必须改用 --candidate-archive。")
    args = parser.parse_args(argv)

    if bool(args.candidate_archive) == args.source_only:
        parser.error("必须二选一：候选出口提供 --candidate-archive，源码诊断显式提供 --source-only。")

    root = args.root.resolve()
    checks = [*validate_production_environment()]
    checks.extend(validate_frozen_pages(root / "docs" / "ui-preview"))
    checks.extend(validate_frozen_page_content(root / "docs" / "ui-preview"))
    if args.candidate_archive:
        checks.extend(validate_candidate_archive(args.candidate_archive.resolve()))
    if args.nginx_config:
        checks.extend(validate_nginx_config(args.nginx_config.resolve()))
    if args.run_migrations:
        checks.extend(run_migration_checks(root))
    print(json.dumps(safe_summary(checks), ensure_ascii=False, indent=2))
    return 0 if all(item.status == "passed" for item in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
