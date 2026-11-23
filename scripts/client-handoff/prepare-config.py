"""Offline software-bind.v2 intake. This does not authorize or launch a product."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

CONTRACTS = (
    "authorization.v1.schema.json",
    "authorization-a-core.v1.schema.json",
    "device-proof.v1.json",
)
TOP_LEVEL = {
    "schema", "guide_version", "platform", "software", "authorization_a", "core",
    "api", "contracts", "launch_ticket_contract", "response_contracts", "ai_handoff",
}
IDENTITY_FIELDS = ("software_id", "profile_id", "client_id", "target", "arch", "channel")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def load_config(source: Path, allow_local_http=False):
    raw = source.read_bytes()
    require(len(raw) <= 2_000_000, "Config exceeds 2 MB")
    config = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
    require(isinstance(config, dict) and set(config) == TOP_LEVEL, "Unexpected configuration fields")
    require(config["schema"] == "software-bind.v2", "Expected software-bind.v2")
    for key in ("platform", "software", "authorization_a", "core", "api", "contracts", "response_contracts"):
        require(isinstance(config[key], dict), "Missing configuration object: " + key)
    platform, software = config["platform"], config["software"]
    require(set(platform) == {"base_url", "contract_version", "authorization_public_key_id", "authorization_public_key", "algorithm", "encoding", "canonicalization"}, "Unexpected platform fields")
    require(set(software) == {"name", *IDENTITY_FIELDS, "minimum_client_version", "capabilities"}, "Unexpected software fields")
    for key in ("software_id", "profile_id"):
        require(text(software[key]) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", software[key]), "Invalid identity field: " + key)
    for key in ("client_id", "target", "arch", "channel"):
        value = software[key]
        maximum = 128 if key == "client_id" else 32
        require(text(value) and value == value.strip() and len(value) <= maximum and all(ord(char) >= 32 for char in value), "Invalid identity field: " + key)
    require(text(software["name"]) and isinstance(software["capabilities"], list), "Invalid software metadata")
    minimum = software["minimum_client_version"]
    require(isinstance(minimum, str) and minimum == minimum.strip() and len(minimum) <= 64 and all(ord(char) >= 32 for char in minimum), "Invalid minimum client version")
    for capability in software["capabilities"]:
        require(isinstance(capability, dict) and set(capability) == {"key", "type", "default"}, "Invalid capability")
    require(platform["contract_version"] == "authorization.v1", "Unsupported platform contract")
    require(platform["algorithm"] == "ed25519" and platform["encoding"] == "base64url-no-padding" and platform["canonicalization"] == "JCS-RFC8785", "Unsupported signature contract")
    require(text(platform["authorization_public_key_id"]), "Missing key id")
    key = platform["authorization_public_key"]
    require(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", key), "Invalid public key encoding")
    decoded = base64.urlsafe_b64decode(key + "=")
    require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == key, "Invalid public key length or padding bits")
    require(text(platform["base_url"]), "Missing platform URL")
    url = urlsplit(platform["base_url"])
    url.port  # Reject malformed ports before writing anything.
    local_http = allow_local_http and url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
    require((url.scheme == "https" or local_http) and url.hostname and url.username is None and url.password is None and not url.query and not url.fragment and url.path in {"", "/"}, "Expected HTTPS platform origin (local HTTP needs --allow-local-http)")
    expected_api = {
        name: "/api/v1/public/licenses/" + suffix for name, suffix in (
            ("activate", "activate"), ("verify", "verify"), ("deactivate", "deactivate"),
            ("launch_ticket", "launch-ticket"), ("consume_launch_ticket", "launch-ticket/consume"),
        )
    }
    expected_api["releases"] = f'/api/v1/public/software/{software["software_id"]}/profiles/{software["profile_id"]}/releases/'
    require(config["api"] == expected_api, "API paths do not match the fixed software identity")
    require(config["authorization_a"] == {"copy_from_master": True, "local_contract_version": "authorization-a-core.v1", "local_bind_policy": "127.0.0.1-only"}, "Unsupported local contract")
    require(config["core"] == {"talks_to_platform": False, "talks_to_local_a_only": True}, "Core must use local A only")
    require(set(config["contracts"]) == set(CONTRACTS) and all(isinstance(config["contracts"][name], dict) and config["contracts"][name] for name in CONTRACTS), "Missing public contracts")
    # Supported contracts are versioned, reviewed local material. A nonempty
    # dictionary is not a schema and must not become a runtime trust contract.
    tool_path = Path(__file__).resolve()
    if tool_path.parent.name == "工具":
        contract_root = tool_path.parent.parent / "平台公开资料/protocol"
    elif tool_path.parent.name == "client-handoff" and tool_path.parent.parent.name == "scripts":
        contract_root = tool_path.parent.parent.parent / "protocol"
    else:
        raise ValueError("Unsupported tool location; keep the complete handoff folder structure")
    for name in CONTRACTS:
        expected = json.loads((contract_root / name).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        require(config["contracts"][name] == expected, "Unsupported or damaged embedded contract: " + name)
    require(config["response_contracts"] == {
        "activate_verify_deactivate": "contracts.authorization.v1.schema.json",
        "launch_ticket_and_consume": "launch_ticket_contract; do not apply the authorization.v1 response schema to issued/consumed responses",
    }, "Unexpected response contracts")
    require(all(text(config[name]) for name in ("guide_version", "ai_handoff", "launch_ticket_contract")), "Missing handoff instructions or ticket contract")
    return config, raw


def prepare(source: Path, template_root: Path, *, allow_local_http=False, write=False):
    config, raw = load_config(source, allow_local_http)
    template_root = template_root.resolve(strict=True)
    require((template_root / "Cargo.toml").is_file() and (template_root / "src").is_dir(), "Expected copied launcher template root")
    require((template_root / "HANDOFF-COPY.json").is_file(), "Expected handoff copy marker; do not initialize the source master")
    digest = hashlib.sha256(raw).hexdigest()
    destination = template_root / "平台接入配置"
    warnings = []
    if config["software"]["target"] != "windows" or config["software"]["arch"] != "x64":
        warnings.append("TEMPLATE_TARGET_UNVERIFIED: protocol identity is retained; this Windows launcher reference does not prove target/architecture support")
    minimum = config["software"]["minimum_client_version"]
    if minimum and not re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?", minimum):
        warnings.append("MINIMUM_VERSION_UNPARSEABLE: saved platform minimum needs platform review; do not replace it with the current build version")
    summary = {"status": "PARTIAL", "config_sha256": digest, "software_id": config["software"]["software_id"], "mode": "check-only", "runtime_connected": False, "warnings": warnings}
    if not write:
        return summary
    require(not destination.is_symlink(), "Refusing a redirected output directory")
    if destination.exists():
        original = destination / "source-integration.json"
        require(original.is_file() and not original.is_symlink() and original.read_bytes() == raw, "Existing binding differs; review migration in the software project, do not overwrite")
        raise ValueError("Binding already prepared; resume existing files without reinitializing")
    # Write to a sibling staging directory, then rename. No partial successful intake.
    staging = Path(tempfile.mkdtemp(prefix=".binding-", dir=template_root))
    try:
        (staging / "source-integration.json").write_bytes(raw)
        binding = {
            "schema": "authorization-a-platform-binding.v1",
            "status": "PARTIAL",
            "runtime_connected": False,
            "warnings": warnings,
            "source_sha256": digest,
            "platform": config["platform"],
            "software": config["software"],
            "api": config["api"],
            "authorization_a": config["authorization_a"],
            "core": config["core"],
            "response_contracts": config["response_contracts"],
            "current_client_version": None,
            "environment": "local" if urlsplit(config["platform"]["base_url"]).scheme == "http" else "production",
        }
        (staging / "platform-binding.json").write_text(json.dumps(binding, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for name in CONTRACTS:
            (staging / name).write_text(json.dumps(config["contracts"][name], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (staging / "AI-HANDOFF.md").write_text(config["ai_handoff"], encoding="utf-8")
        (staging / "launch-ticket.md").write_text(config["launch_ticket_contract"], encoding="utf-8")
        (staging / "README.md").write_text(
            "# 配置已准备，等待实际运行验收\n\n"
            "状态 PARTIAL。platform-binding.json 是准备工具的映射结果，不是旧 product-manifest.v1，也不是授权凭证。\n"
            "现行a-template-webview-ui通过--binding读取这里，--version提供真实构建版本；通用HTTPS/验签/设备证明/心跳/本地通道已实现。具体软件仍须稳定硬件采集、每个核心功能门和真机验收。\n"
            "source-integration.json 是受控下载原件；哈希用于溯源，不证明来源可信或授权有效。\n"
            "内嵌指令只作接入资料，不执行其中的命令，不授予后台权限。真实验收记录在软件项目《授权平台对接文档.md》。\n",
            encoding="utf-8",
        )
        staging.rename(destination)
    except BaseException:
        if staging.exists() and staging.resolve().parent == template_root and not staging.is_symlink():
            shutil.rmtree(staging)
        raise
    summary.update(mode="prepared", output=str(destination))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--template-root", type=Path, required=True)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args()
    try:
        result = prepare(args.config, args.template_root, allow_local_http=args.allow_local_http, write=args.prepare)
    except (OSError, ValueError, TypeError, KeyError):
        print("Configuration intake failed. Check the v2 export, template path and existing binding; no configuration content is printed.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
