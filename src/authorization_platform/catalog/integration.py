"""Administrator-only, public-material handoff for a single saved profile."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings

from authorization_platform.licensing.authorization import (
    AUTHORIZATION_ALGORITHM,
    AUTHORIZATION_CANONICALIZATION,
    authorization_signing_public_key,
)

from .models import Software, SoftwareProfile
from .services import CatalogOperationError

SCHEMA = "software-bind.v2"
GUIDE_VERSION = "2026-11-16"
PROTOCOL_FILES = (
    "authorization.v1.schema.json",
    "authorization-a-core.v1.schema.json",
    "device-proof.v1.json",
)


def _platform_origin(request) -> str:
    origin = settings.AUTHORIZATION_PUBLIC_BASE_URL or request.build_absolute_uri("/").rstrip("/")
    try:
        parsed = urlsplit(origin)
        parsed.port
    except ValueError as exc:
        raise CatalogOperationError("PLATFORM_URL_UNAVAILABLE", "平台公开地址配置不正确。") from exc
    local_http = (
        settings.APP_ENV == "local"
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if (parsed.scheme != "https" and not local_http) or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise CatalogOperationError("PLATFORM_URL_UNAVAILABLE", "请配置正确的 HTTPS 平台公开地址。")
    return origin.rstrip("/")


def build_integration_config(request, software_id: str) -> dict:
    try:
        software = Software.objects.get(pk=software_id)
    except Software.DoesNotExist as exc:
        raise CatalogOperationError("SOFTWARE_NOT_FOUND", "软件不存在。") from exc
    if software.status not in {"active", "testing"}:
        raise CatalogOperationError("SOFTWARE_UNAVAILABLE", "该软件尚未启用或已经下架，不能导出接入配置。")
    profiles = software.profiles.all()
    selected = request.GET.get("profile_id", "").strip()
    if not selected and profiles.count() != 1:
        raise CatalogOperationError("PROFILE_REQUIRED", "请选择要导出的接入配置。")
    try:
        profile = profiles.get(profile_id=selected) if selected else profiles.get()
    except SoftwareProfile.DoesNotExist as exc:
        raise CatalogOperationError("PROFILE_NOT_FOUND", "该软件没有这个接入配置。") from exc
    if profile.status not in {"active", "testing"}:
        raise CatalogOperationError("PROFILE_UNAVAILABLE", "该接入配置未启用或已经归档。")
    if not profile.policy_versions.filter(status="active").exists():
        raise CatalogOperationError("PROFILE_NOT_READY", "请先为这个软件设置生效的授权规则。")
    origin = _platform_origin(request)
    root = Path(settings.BASE_DIR)
    try:
        guide = (root / "接入说明" / "09-给软件项目AI的接入指令.md").read_text(encoding="utf-8")
        contracts = {name: json.loads((root / "protocol" / name).read_text(encoding="utf-8")) for name in PROTOCOL_FILES}
        api_contract = (root / "docs" / "API-CONTRACT.md").read_text(encoding="utf-8")
        ticket_section = api_contract.split("### 一次性启动票据\n", 1)[1]
        ticket_contract = "### 一次性启动票据\n" + re.split(r"\n#{1,3} ", ticket_section, maxsplit=1)[0]
        if not guide.strip():
            raise ValueError("empty integration guide")
    except (OSError, ValueError, IndexError) as exc:
        raise CatalogOperationError("INTEGRATION_GUIDE_UNAVAILABLE", "接入资料不完整，请联系平台维护者。") from exc
    public_key = authorization_signing_public_key()
    return {
        "schema": SCHEMA,
        "guide_version": GUIDE_VERSION,
        "platform": {
            "base_url": origin,
            "contract_version": profile.contract_version,
            "authorization_public_key_id": settings.AUTHORIZATION_SIGNING_KEY_ID,
            "authorization_public_key": public_key,
            "algorithm": AUTHORIZATION_ALGORITHM,
            "encoding": "base64url-no-padding",
            "canonicalization": AUTHORIZATION_CANONICALIZATION,
        },
        "software": {
            "name": software.name,
            "software_id": software.software_id,
            "profile_id": profile.profile_id,
            "client_id": profile.client_id,
            "target": profile.target,
            "arch": profile.arch,
            "channel": profile.channel,
            "minimum_client_version": profile.minimum_client_version,
            "capabilities": [
                {"key": item.capability_key, "type": item.value_type, "default": item.default_value}
                for item in profile.capabilities.filter(status="active", is_public=True).order_by("capability_key")
            ],
        },
        "authorization_a": {
            "copy_from_master": True,
            "local_contract_version": "authorization-a-core.v1",
            "local_bind_policy": "127.0.0.1-only",
        },
        "core": {"talks_to_platform": False, "talks_to_local_a_only": True},
        "api": {
            "activate": "/api/v1/public/licenses/activate",
            "verify": "/api/v1/public/licenses/verify",
            "deactivate": "/api/v1/public/licenses/deactivate",
            "launch_ticket": "/api/v1/public/licenses/launch-ticket",
            "consume_launch_ticket": "/api/v1/public/licenses/launch-ticket/consume",
            "releases": f"/api/v1/public/software/{software.software_id}/profiles/{profile.profile_id}/releases/",
        },
        "contracts": contracts,
        "launch_ticket_contract": ticket_contract,
        "response_contracts": {
            "activate_verify_deactivate": "contracts.authorization.v1.schema.json",
            "launch_ticket_and_consume": "launch_ticket_contract; do not apply the authorization.v1 response schema to issued/consumed responses",
        },
        "ai_handoff": guide,
    }
