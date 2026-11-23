"""Product-neutral online authorization service.

This module is the central platform side of the frozen topology:

    authorization platform -> authorization A -> core EXE

The platform is the only authority for a license card, authorization instance,
device binding, expiry and revocation state.  The public response is signed for
Authorization A.  A must validate it and issue its own local envelope; this
module never contains a product name or a core-specific route.

The response value set is deliberately restricted to I-JSON-compatible
strings, booleans, nulls, arrays, objects and safe integers.  The small JCS
encoder below is therefore a contract encoder, not a general-purpose JSON
serializer.  Values outside that set fail closed instead of being signed with
an ambiguous representation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.configuration import current_config_version, effective_configuration_for_authorization
from authorization_platform.catalog.models import (
    CapabilityStatus,
    DownstreamSoftware,
    DownstreamSoftwareStatus,
    PlanSnapshot,
    PolicyStatus,
    PolicyVersion,
    ProfileStatus,
    SoftwareProfile,
    SoftwareStatus,
)
from authorization_platform.core.time import Clock, SystemClock, as_utc, to_beijing

from .models import (
    AuthorizationNonce,
    AuthorizationRequestRecord,
    AuthorizationState,
    Device,
    DeviceBinding,
    DeviceBindingState,
    DeviceKey,
    DeviceRiskState,
    LaunchTicket,
    LicenseCard,
    LicenseCardStatus,
    LicenseInstance,
)
from .services import license_card_hash


AUTHORIZATION_SCHEMA_VERSION = "authorization.v1"
AUTHORIZATION_CONTRACT_VERSION = "authorization.v1"
AUTHORIZATION_TIME_ZONE = "Asia/Shanghai"
AUTHORIZATION_ALGORITHM = "ed25519"
AUTHORIZATION_CANONICALIZATION = "JCS-RFC8785"
GENERIC_ADAPTER_KEY = "generic-online-v1"
DEVICE_PROOF_DOMAIN = "authorization-platform.device-proof.v1"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
AUTHORIZATION_RESPONSE_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "software_id",
        "profile_id",
        "client_id",
        "contract_version",
        "target",
        "arch",
        "channel",
        "authorization_id",
        "authorization_revision",
        "device_scope",
        "decision",
        "state_code",
        "issued_at",
        "expires_at",
        "server_time",
        "cache_until",
        "next_verify_at",
        "grace_until",
        "config_version",
        "support",
        "announcement",
        "modules",
        "integrity",
    }
)
AUTHORIZATION_RESPONSE_REQUEST_ONLY_FIELDS = frozenset(
    {"device_public_key", "device_proof", "client_version", "nonce", "installation_id"}
)
AUTHORIZATION_RESPONSE_OPTIONAL_FIELDS = frozenset(
    {
        "status",
        "policy_version",
        "adapter_key",
        "adapter_version",
        "capabilities",
        "entitlements",
        "purchase",
        "qr",
        "update",
        "binding_state",
        "error",
        "extensions",
    }
)
AUTHORIZATION_REQUEST_COMMON_FIELDS = frozenset(
    {
        "request_id",
        "idempotency_key",
        "software_id",
        "profile_id",
        "client_id",
        "contract_version",
        "target",
        "arch",
        "channel",
        "installation_id",
        "device_public_key",
        "device_proof",
        "client_version",
        "nonce",
        "known_authorization_revision",
        "known_config_version",
        "config_version",
    }
)
AUTHORIZATION_DEVICE_SCOPE_FIELDS = frozenset({"scope", "device_id", "installation_id"})
AUTHORIZATION_DECISIONS = frozenset({"active", "grace", "expired", "revoked", "blocked", "not_modified", "unbound"})
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+){0,3})(?:[-+][0-9A-Za-z.-]+)?$")


class AuthorizationOperationError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.http_status = http_status


@dataclass(frozen=True)
class AuthorizationResult:
    payload: dict[str, Any]
    status_code: int = 200
    repeated: bool = False


def canonicalize_jcs(value: Any) -> bytes:
    """Encode the supported authorization value set using JCS ordering rules."""

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > MAX_SAFE_INTEGER:
                raise ValueError("integer is outside the authorization JCS safe range")
            return str(item)
        if isinstance(item, float):
            raise ValueError("floating point values are not permitted in authorization responses")
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("JCS object keys must be strings")
            # RFC 8785 orders object keys by UTF-16 code units, not by Unicode
            # code points.  Python's str comparison sorts by code point, which
            # differs once a key contains an astral character, so a strict JCS
            # verifier on the client would reject an otherwise valid response.
            return "{" + ",".join(
                f"{encode(key)}:{encode(item[key])}"
                for key in sorted(item, key=lambda name: name.encode("utf-16-be"))
            ) + "}"
        raise ValueError(f"unsupported JCS value type: {type(item).__name__}")

    try:
        return encode(value).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError) as exc:
        raise ValueError("authorization response cannot be canonically encoded") from exc


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise AuthorizationOperationError("INVALID_REQUEST", f"{label}格式不正确。")
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise AuthorizationOperationError("INVALID_REQUEST", f"{label}格式不正确。") from exc


def _signing_private_key() -> Ed25519PrivateKey:
    configured = getattr(settings, "AUTHORIZATION_SIGNING_PRIVATE_KEY", "")
    if configured:
        raw = _base64url_decode(configured, label="授权签名私钥")
        if len(raw) != 32:
            raise AuthorizationOperationError("SIGNING_KEY_UNAVAILABLE", "授权签名密钥配置不正确。", http_status=503)
        try:
            return Ed25519PrivateKey.from_private_bytes(raw)
        except ValueError as exc:
            raise AuthorizationOperationError("SIGNING_KEY_UNAVAILABLE", "授权签名密钥配置不正确。", http_status=503) from exc
    if getattr(settings, "APP_ENV", "local") != "local":
        # Only local development may derive a signing key from SECRET_KEY.  A
        # test or production platform without an explicit key would otherwise
        # sign with a publicly derivable seed, letting anyone forge responses.
        raise AuthorizationOperationError("SIGNING_KEY_UNAVAILABLE", "授权签名服务暂不可用。", retryable=True, http_status=503)
    # Local-only deterministic fallback keeps tests reproducible.  Settings
    # already refuse to start outside local development without a real key.
    seed = hashlib.sha256(
        (f"{settings.SECRET_KEY}|authorization-platform.dev.ed25519").encode("utf-8")
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def authorization_signing_public_key() -> str:
    public = _signing_private_key().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return _base64url_encode(public)


def _signing_key_id() -> str:
    return getattr(settings, "AUTHORIZATION_SIGNING_KEY_ID", "platform-dev-v1")


def sign_authorization_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Sign a complete authorization.v1 response without the signature field."""

    response = dict(payload)
    response["integrity"] = {
        "algorithm": AUTHORIZATION_ALGORITHM,
        "key_id": _signing_key_id(),
        "canonicalization": AUTHORIZATION_CANONICALIZATION,
    }
    try:
        signature = _signing_private_key().sign(canonicalize_jcs(response))
    except AuthorizationOperationError:
        raise
    except (ValueError, TypeError) as exc:
        raise AuthorizationOperationError("SIGNATURE_UNAVAILABLE", "授权响应完整性处理失败。", http_status=503) from exc
    response["integrity"]["signature"] = _base64url_encode(signature)
    validate_authorization_response_shape(response)
    return response


def verify_authorization_response(
    payload: Mapping[str, Any],
    trusted_keys: Mapping[str, Ed25519PublicKey | str | bytes],
) -> None:
    """Strict verification helper used by contract tests and future A clients."""

    if not isinstance(payload, Mapping):
        raise AuthorizationOperationError("RESPONSE_SCHEMA_INVALID", "授权响应必须是对象。", http_status=502)
    integrity = payload.get("integrity")
    if not isinstance(integrity, dict):
        raise AuthorizationOperationError("SIGNATURE_INVALID", "授权响应缺少完整性字段。")
    if integrity.get("algorithm") != AUTHORIZATION_ALGORITHM:
        raise AuthorizationOperationError("ALGORITHM_UNSUPPORTED", "授权响应算法不受支持。")
    if integrity.get("canonicalization") != AUTHORIZATION_CANONICALIZATION:
        raise AuthorizationOperationError("CANONICALIZATION_UNSUPPORTED", "授权响应规范化方式不受支持。")
    validate_authorization_response_shape(payload)
    key_id = integrity.get("key_id")
    if not isinstance(key_id, str) or key_id not in trusted_keys:
        raise AuthorizationOperationError("KEY_UNKNOWN", "授权响应签名密钥未知。")
    try:
        signature = _base64url_decode(integrity.get("signature", ""), label="授权响应签名")
    except AuthorizationOperationError as exc:
        raise AuthorizationOperationError("SIGNATURE_INVALID", "授权响应签名格式无效。") from exc
    signable = dict(payload)
    signable_integrity = dict(integrity)
    signable_integrity.pop("signature", None)
    signable["integrity"] = signable_integrity
    try:
        public_key = trusted_keys[key_id]
        if not isinstance(public_key, Ed25519PublicKey):
            if isinstance(public_key, bytes) and len(public_key) == 32:
                raw_public_key = public_key
            else:
                raw = public_key.encode("ascii") if isinstance(public_key, str) else public_key
                raw_public_key = _base64url_decode(raw.decode("ascii"), label="授权公钥")
            public_key = Ed25519PublicKey.from_public_bytes(raw_public_key)
        public_key.verify(signature, canonicalize_jcs(signable))
    except (InvalidSignature, ValueError, TypeError, UnicodeError) as exc:
        raise AuthorizationOperationError("SIGNATURE_INVALID", "授权响应签名无效。") from exc


def _response_schema_error(message: str) -> None:
    raise AuthorizationOperationError("RESPONSE_SCHEMA_INVALID", message, http_status=502)


def validate_device_scope(value: Any) -> None:
    """Validate the product-neutral, server-confirmed device scope claim."""

    if not isinstance(value, Mapping):
        _response_schema_error("device_scope 必须是对象。")
    if set(value) != AUTHORIZATION_DEVICE_SCOPE_FIELDS:
        _response_schema_error("device_scope 字段集合不正确。")
    if value.get("scope") != "current_device":
        _response_schema_error("device_scope.scope 不受支持。")
    for field, max_length in (("device_id", 64), ("installation_id", 128)):
        item = value.get(field)
        if item is None:
            continue
        if not isinstance(item, str) or not item or len(item) > max_length:
            _response_schema_error(f"device_scope.{field} 格式不正确。")


def _validate_response_string(payload: Mapping[str, Any], field: str, max_length: int) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value or len(value) > max_length:
        _response_schema_error(f"授权响应字段 {field} 格式不正确。")


def _validate_response_object(payload: Mapping[str, Any], field: str, *, allow_null: bool = False) -> None:
    value = payload.get(field)
    if allow_null and value is None:
        return
    if not isinstance(value, Mapping):
        _response_schema_error(f"授权响应字段 {field} 必须是对象。")


def _validate_nullable_response_string(value: Any, field: str, max_length: int) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value or len(value) > max_length:
        _response_schema_error(f"授权响应字段 {field} 格式不正确。")


def _validate_configuration_response(payload: Mapping[str, Any]) -> None:
    support = payload.get("support")
    if support is not None:
        if not isinstance(support, Mapping) or set(support) != {"purchase_url", "qq", "wechat"}:
            _response_schema_error("授权响应字段 support 结构不正确。")
        _validate_nullable_response_string(support.get("purchase_url"), "support.purchase_url", 2048)
        _validate_nullable_response_string(support.get("qq"), "support.qq", 64)
        _validate_nullable_response_string(support.get("wechat"), "support.wechat", 64)
        if all(support.get(field) is None for field in ("purchase_url", "qq", "wechat")):
            _response_schema_error("空支持信息必须使用 null。")

    announcement = payload.get("announcement")
    if announcement is not None:
        if not isinstance(announcement, Mapping) or set(announcement) != {"title", "body"}:
            _response_schema_error("授权响应字段 announcement 结构不正确。")
        _validate_nullable_response_string(announcement.get("title"), "announcement.title", 120)
        _validate_nullable_response_string(announcement.get("body"), "announcement.body", 2000)
        if announcement.get("title") is None and announcement.get("body") is None:
            _response_schema_error("空公告必须使用 null。")

    modules = payload.get("modules")
    if not isinstance(modules, Mapping) or set(modules) != {"contact", "notice", "purchase", "qr", "update"}:
        _response_schema_error("授权响应字段 modules 结构不正确。")
    for field in ("contact", "notice", "purchase", "qr", "update"):
        _validate_response_object(modules, field, allow_null=True)
    if modules["contact"] != support or modules["notice"] != announcement:
        _response_schema_error("授权响应 modules 未与 support/announcement 对齐。")


def _validate_response_epoch(payload: Mapping[str, Any], field: str) -> None:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**63) <= value <= 2**63 - 1:
        _response_schema_error(f"授权响应字段 {field} 必须是 64 位整数秒。")


def validate_authorization_response_shape(payload: Mapping[str, Any]) -> None:
    """Fail closed on a signed response that does not match authorization.v1."""

    if not isinstance(payload, Mapping):
        _response_schema_error("授权响应必须是对象。")
    missing = AUTHORIZATION_RESPONSE_REQUIRED_FIELDS.difference(payload)
    if missing:
        _response_schema_error(f"授权响应缺少字段：{','.join(sorted(missing))}。")
    leaked = AUTHORIZATION_RESPONSE_REQUEST_ONLY_FIELDS.intersection(payload)
    if leaked:
        _response_schema_error(f"请求字段不能进入授权响应：{','.join(sorted(leaked))}。")
    unknown = set(payload).difference(AUTHORIZATION_RESPONSE_REQUIRED_FIELDS, AUTHORIZATION_RESPONSE_OPTIONAL_FIELDS)
    if unknown:
        _response_schema_error(f"授权响应包含未声明顶层字段：{','.join(sorted(unknown))}。")
    if payload.get("schema_version") != AUTHORIZATION_SCHEMA_VERSION:
        _response_schema_error("授权响应 schema_version 不受支持。")
    _validate_response_string(payload, "request_id", 128)
    _validate_response_string(payload, "software_id", 64)
    _validate_response_string(payload, "profile_id", 64)
    _validate_response_string(payload, "client_id", 128)
    if payload.get("contract_version") != AUTHORIZATION_CONTRACT_VERSION:
        _response_schema_error("授权响应 contract_version 不受支持。")
    for field in ("target", "arch", "channel"):
        _validate_response_string(payload, field, 32)
    _validate_response_string(payload, "authorization_id", 64)
    revision = payload.get("authorization_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        _response_schema_error("授权响应 authorization_revision 格式不正确。")
    scope = payload.get("device_scope")
    validate_device_scope(scope)
    if (scope["device_id"] is None) != (scope["installation_id"] is None):
        _response_schema_error("device_scope 的设备 ID 和安装标识必须同时为空或同时存在。")
    decision = payload.get("decision")
    if decision not in AUTHORIZATION_DECISIONS:
        _response_schema_error("授权响应 decision 不受支持。")
    if decision in {"active", "grace", "not_modified"} and (
        scope["device_id"] is None or scope["installation_id"] is None
    ):
        _response_schema_error("有效授权响应必须包含已确认的设备范围。")
    _validate_response_string(payload, "state_code", 32)
    for field in ("issued_at", "expires_at", "server_time", "cache_until", "next_verify_at", "grace_until"):
        _validate_response_epoch(payload, field)
    issued_at = payload["issued_at"]
    expires_at = payload["expires_at"]
    server_time = payload["server_time"]
    if issued_at > server_time:
        _response_schema_error("授权响应 issued_at 不能晚于 server_time。")
    if payload["cache_until"] != payload["next_verify_at"]:
        _response_schema_error("授权响应 cache_until 必须与 next_verify_at 一致。")
    if payload["cache_until"] > expires_at:
        _response_schema_error("授权响应缓存窗口不能越过 expires_at。")
    if decision in {"active", "grace", "not_modified"} and server_time >= expires_at:
        _response_schema_error("有效授权响应不能在 expires_at 时刻或之后放行。")
    if decision == "expired" and server_time < expires_at:
        _response_schema_error("过期授权响应必须位于 expires_at 时刻或之后。")
    _validate_response_string(payload, "config_version", 64)
    for field in ("status", "policy_version", "adapter_key", "adapter_version", "binding_state"):
        if field in payload:
            _validate_response_string(payload, field, 64 if field != "binding_state" else 32)
    for field in ("capabilities", "entitlements", "error", "extensions"):
        if field in payload:
            _validate_response_object(payload, field)
    for field in ("purchase", "qr", "update"):
        if field in payload:
            _validate_response_object(payload, field, allow_null=True)
    _validate_configuration_response(payload)
    integrity = payload.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != {"algorithm", "key_id", "canonicalization", "signature"}:
        _response_schema_error("授权响应 integrity 字段集合不正确。")
    if integrity.get("algorithm") != AUTHORIZATION_ALGORITHM:
        _response_schema_error("授权响应 integrity.algorithm 不受支持。")
    if integrity.get("canonicalization") != AUTHORIZATION_CANONICALIZATION:
        _response_schema_error("授权响应 integrity.canonicalization 不受支持。")
    key_id = integrity.get("key_id")
    signature = integrity.get("signature")
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        _response_schema_error("授权响应 integrity.key_id 格式不正确。")
    if not isinstance(signature, str) or not signature:
        _response_schema_error("授权响应 integrity.signature 格式不正确。")


def _text(value: Any, name: str, *, max_length: int = 128, required: bool = True) -> str:
    if not isinstance(value, str):
        if required:
            raise AuthorizationOperationError("MISSING_REQUIRED_FIELD", f"缺少 {name}。")
        return ""
    value = value.strip()
    if required and not value:
        raise AuthorizationOperationError("MISSING_REQUIRED_FIELD", f"缺少 {name}。")
    if len(value) > max_length:
        raise AuthorizationOperationError("INVALID_REQUEST", f"{name}长度超出限制。")
    if not _is_encodable(value):
        # JSON allows lone surrogate escapes; encoding them later would raise
        # UnicodeEncodeError and surface as an unhandled 500 on a public route.
        raise AuthorizationOperationError("INVALID_REQUEST", f"{name}包含无效字符。")
    return value


def _is_encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _normalize_request(
    action: str,
    request: Mapping[str, Any],
    *,
    request_id: str | None,
    idempotency_key: str | None,
) -> tuple[dict[str, Any], str, str]:
    if not isinstance(request, Mapping):
        raise AuthorizationOperationError("INVALID_REQUEST", "请求必须是 JSON 对象。")
    data = dict(request)
    allowed_fields = AUTHORIZATION_REQUEST_COMMON_FIELDS | {
        "license_key" if action == "activate" else "authorization_id"
    }
    if action == "ticket-consume":
        allowed_fields = allowed_fields | {"ticket_id"}
    unknown = set(data).difference(allowed_fields)
    if unknown:
        raise AuthorizationOperationError(
            "INVALID_REQUEST",
            f"请求包含未声明字段：{','.join(sorted(unknown))}。",
        )
    body_request_id = data.get("request_id")
    resolved_request_id = _text(request_id or body_request_id, "request_id")
    if body_request_id and str(body_request_id).strip() != resolved_request_id:
        raise AuthorizationOperationError("INVALID_REQUEST", "请求头与请求体的 request_id 不一致。")
    resolved_idempotency = _text(idempotency_key or data.get("idempotency_key") or resolved_request_id, "idempotency_key")
    if data.get("idempotency_key") and str(data["idempotency_key"]).strip() != resolved_idempotency:
        raise AuthorizationOperationError("INVALID_REQUEST", "幂等键不一致。")

    normalized: dict[str, Any] = {
        "action": action,
        "request_id": resolved_request_id,
        "idempotency_key": resolved_idempotency,
    }
    for field in ("software_id", "profile_id", "client_id", "contract_version", "target", "arch", "channel"):
        normalized[field] = _text(data.get(field), field, max_length=128)
    normalized["client_version"] = _text(data.get("client_version"), "client_version", max_length=64)
    normalized["nonce"] = _text(data.get("nonce"), "nonce", max_length=128)
    if len(normalized["nonce"]) < 8:
        raise AuthorizationOperationError("INVALID_REQUEST", "nonce 长度不足。")

    if action == "activate":
        normalized["license_key"] = _text(data.get("license_key"), "license_key", max_length=256)
    else:
        normalized["authorization_id"] = _text(data.get("authorization_id"), "authorization_id", max_length=64)
    normalized["installation_id"] = _text(data.get("installation_id"), "installation_id", max_length=128)
    normalized["device_public_key"] = _text(data.get("device_public_key"), "device_public_key", max_length=256)
    normalized["device_proof"] = _text(data.get("device_proof"), "device_proof", max_length=256, required=False)
    for field in ("known_config_version", "config_version"):
        if data.get(field) is not None:
            normalized[field] = _text(data.get(field), field, max_length=64)
    if data.get("known_authorization_revision") is not None:
        value = data["known_authorization_revision"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise AuthorizationOperationError("INVALID_REQUEST", "authorization_revision 格式不正确。")
        normalized["known_authorization_revision"] = value
    if action == "ticket-consume":
        normalized["ticket_id"] = _text(data.get("ticket_id"), "ticket_id", max_length=64)
    return normalized, resolved_request_id, resolved_idempotency


def _request_fingerprint(data: Mapping[str, Any]) -> str:
    safe = dict(data)
    if "license_key" in safe:
        safe["license_key_hash"] = license_card_hash(str(safe.pop("license_key")))
    for field in ("device_proof",):
        if safe.get(field):
            safe[field] = hashlib.sha256(str(safe[field]).encode("utf-8")).hexdigest()
    return hashlib.sha256(canonicalize_jcs(safe)).hexdigest()


def _nonce_hash(nonce: str) -> str:
    key = getattr(settings, "AUTHORIZATION_NONCE_HASH_KEY", settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def _installation_hash(profile: SoftwareProfile, installation_id: str) -> str:
    key = getattr(settings, "AUTHORIZATION_DEVICE_HASH_KEY", settings.SECRET_KEY).encode("utf-8")
    value = f"{profile.software_id}|{profile.profile_id}|{installation_id}".encode("utf-8")
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def device_proof_message(data: Mapping[str, Any]) -> bytes:
    fields = {
        "domain": DEVICE_PROOF_DOMAIN,
        "action": data.get("action", ""),
        "request_id": data.get("request_id", ""),
        "authorization_id": data.get("authorization_id", ""),
        "software_id": data.get("software_id", ""),
        "profile_id": data.get("profile_id", ""),
        "client_id": data.get("client_id", ""),
        "contract_version": data.get("contract_version", ""),
        "target": data.get("target", ""),
        "arch": data.get("arch", ""),
        "channel": data.get("channel", ""),
        "installation_id": data.get("installation_id", ""),
        "device_public_key": data.get("device_public_key", ""),
        "nonce": data.get("nonce", ""),
    }
    return canonicalize_jcs(fields)


def _device_key_info(data: Mapping[str, Any]) -> tuple[bytes, str, str]:
    try:
        raw = _base64url_decode(data["device_public_key"], label="device_public_key")
    except AuthorizationOperationError as exc:
        raise AuthorizationOperationError("DEVICE_KEY_INVALID", "设备公钥格式不正确。", http_status=403) from exc
    if len(raw) != 32:
        raise AuthorizationOperationError("DEVICE_KEY_INVALID", "设备公钥必须是 32 字节 Ed25519 公钥。")
    encoded = _base64url_encode(raw)
    key_id = f"device-ed25519-{hashlib.sha256(raw).hexdigest()[:32]}"
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise AuthorizationOperationError("DEVICE_KEY_INVALID", "设备公钥无效。") from exc
    return raw, key_id, encoded


def _verify_device_proof(data: Mapping[str, Any], *, proof_required: bool) -> tuple[bytes, str, str]:
    raw, key_id, encoded = _device_key_info(data)
    proof = data.get("device_proof", "")
    if not proof:
        if proof_required:
            raise AuthorizationOperationError("DEVICE_PROOF_REQUIRED", "当前策略要求设备证明。", http_status=403)
        return raw, key_id, encoded
    try:
        signature = _base64url_decode(proof, label="device_proof")
    except AuthorizationOperationError as exc:
        raise AuthorizationOperationError("DEVICE_PROOF_INVALID", "设备证明格式不正确。", http_status=403) from exc
    if len(signature) != 64:
        raise AuthorizationOperationError("DEVICE_PROOF_INVALID", "设备证明签名长度不正确。", http_status=403)
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, device_proof_message(data))
    except (InvalidSignature, ValueError) as exc:
        raise AuthorizationOperationError("DEVICE_PROOF_INVALID", "设备证明无效。", http_status=403) from exc
    return raw, key_id, encoded


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.fullmatch(value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _validate_profile(data: Mapping[str, Any]) -> SoftwareProfile:
    try:
        profile = SoftwareProfile.objects.select_related("software").get(
            software_id=data["software_id"],
            profile_id=data["profile_id"],
        )
    except SoftwareProfile.DoesNotExist as exc:
        raise AuthorizationOperationError("PROFILE_MISMATCH", "软件与 Profile 身份不匹配。", http_status=403) from exc
    software = profile.software
    if software.status not in {SoftwareStatus.TESTING, SoftwareStatus.ACTIVE, SoftwareStatus.ARCHIVED} or profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
        raise AuthorizationOperationError("PROFILE_NOT_ACTIVE", "当前 Profile 暂不可用于授权。", http_status=403)
    if profile.contract_version != AUTHORIZATION_CONTRACT_VERSION or data["contract_version"] != AUTHORIZATION_CONTRACT_VERSION:
        raise AuthorizationOperationError("CONTRACT_VERSION_UNSUPPORTED", "授权合同版本不受支持。")
    mismatches = [
        field for field in ("client_id", "target", "arch", "channel")
        if data[field] != getattr(profile, field)
    ]
    if mismatches:
        raise AuthorizationOperationError(
            "PROFILE_MISMATCH",
            f"客户端身份与登记 Profile 不匹配：{','.join(mismatches)}。",
            http_status=403,
        )
    if profile.adapter_key != GENERIC_ADAPTER_KEY:
        raise AuthorizationOperationError("ADAPTER_UNSUPPORTED", "当前 Profile 的授权适配器不受支持。", http_status=503)
    if profile.minimum_client_version:
        minimum = _version_tuple(profile.minimum_client_version)
        current = _version_tuple(data["client_version"])
        if minimum is None or current is None:
            raise AuthorizationOperationError("VERSION_BLOCKED", "客户端版本格式不受支持。", http_status=403)
        if current < minimum:
            raise AuthorizationOperationError("VERSION_BLOCKED", "客户端版本过低，请更新后重试。", http_status=403)
    return profile


def _load_card_policy(card: LicenseCard, profile: SoftwareProfile) -> tuple[PlanSnapshot, Any]:
    try:
        snapshot = PlanSnapshot.objects.select_related("software", "profile", "policy_version").get(
            snapshot_id=card.plan_snapshot_id
        )
    except PlanSnapshot.DoesNotExist as exc:
        raise AuthorizationOperationError("POLICY_VERSION_UNSUPPORTED", "授权套餐策略快照不可用。", http_status=503) from exc
    mismatches = []
    if card.software_id != profile.software_id:
        mismatches.append("card.software_id")
    if card.profile_id != profile.pk:
        mismatches.append("card.profile_id")
    if snapshot.software_id != profile.software_id:
        mismatches.append("snapshot.software_id")
    if snapshot.profile_id != profile.pk:
        mismatches.append("snapshot.profile_id")
    if snapshot.policy_version.profile_id != profile.pk:
        mismatches.append("policy.profile_id")
    if mismatches:
        raise AuthorizationOperationError(
            "PROFILE_MISMATCH",
            f"授权卡密与 Profile 归属不匹配：{','.join(mismatches)}。",
            http_status=403,
        )
    return snapshot, snapshot.policy_version


def _lock_card_by_license_key(license_key: str) -> LicenseCard:
    try:
        return LicenseCard.objects.select_for_update().get(card_hash=license_card_hash(license_key))
    except LicenseCard.DoesNotExist as exc:
        raise AuthorizationOperationError("LICENSE_NOT_FOUND", "授权卡密不存在或不可用。", http_status=403) from exc


def _lock_instance_for_card(card: LicenseCard) -> LicenseInstance | None:
    try:
        return LicenseInstance.objects.select_for_update().select_related(
            "software", "profile", "plan_snapshot", "policy_version"
        ).get(license_card_id=card.public_id)
    except LicenseInstance.DoesNotExist:
        return None


def _lock_card_for_instance(authorization_id: str) -> tuple[LicenseCard, LicenseInstance]:
    try:
        parsed_id = uuid.UUID(str(authorization_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AuthorizationOperationError("INVALID_REQUEST", "authorization_id 格式不正确。", http_status=400) from exc
    try:
        reference = LicenseInstance.objects.only("license_card_id").get(authorization_id=parsed_id)
    except LicenseInstance.DoesNotExist as exc:
        raise AuthorizationOperationError("AUTHORIZATION_NOT_FOUND", "授权实例不存在。", http_status=403) from exc
    card = LicenseCard.objects.select_for_update().get(public_id=reference.license_card_id)
    instance = LicenseInstance.objects.select_for_update().select_related(
        "software", "profile", "plan_snapshot", "policy_version"
    ).get(authorization_id=authorization_id)
    return card, instance


def _ensure_downstream_active(card: LicenseCard) -> None:
    if not card.current_downstream_public_id:
        raise AuthorizationOperationError("DOWNSTREAM_NOT_ACTIVE", "授权卡密归属下游当前不可用。", http_status=403)
    try:
        downstream = DownstreamProfile.objects.select_related("user").get(public_id=card.current_downstream_public_id)
    except DownstreamProfile.DoesNotExist as exc:
        raise AuthorizationOperationError("DOWNSTREAM_NOT_ACTIVE", "授权卡密归属下游当前不可用。", http_status=403) from exc
    if downstream.status != DownstreamStatus.ACTIVE or not downstream.user.is_active:
        raise AuthorizationOperationError("DOWNSTREAM_NOT_ACTIVE", "授权卡密归属下游当前不可用。", http_status=403)


def _ensure_catalog_access_for_unused_activate(card: LicenseCard) -> None:
    if card.software_id and getattr(card.software, "status", None) == SoftwareStatus.ARCHIVED:
        raise AuthorizationOperationError("LICENSE_NOT_ACTIVE", "授权卡密当前不能开通。", http_status=403)
    if not card.current_downstream_id:
        raise AuthorizationOperationError("LICENSE_NOT_ACTIVE", "授权卡密当前不能开通。", http_status=403)
    has_active_access = (
        DownstreamSoftware.objects.select_for_update()
        .filter(
            downstream_id=card.current_downstream_id,
            software_id=card.software_id,
            status=DownstreamSoftwareStatus.ACTIVE,
        )
        .exists()
    )
    if not has_active_access:
        raise AuthorizationOperationError("LICENSE_NOT_ACTIVE", "授权卡密当前不能开通。", http_status=403)


def _ensure_device(
    profile: SoftwareProfile,
    installation_id: str,
    *,
    ip_address: str | None,
    now: datetime,
) -> Device:
    installation_hash = _installation_hash(profile, installation_id)
    device = Device.objects.select_for_update().filter(
        software_id=profile.software_id,
        profile_id=profile.pk,
        installation_hash=installation_hash,
    ).first()
    if device is None:
        try:
            device = Device.objects.create(
                software=profile.software,
                profile=profile,
                installation_hash=installation_hash,
                installation_id=installation_id,
                first_seen_at=now,
                last_seen_at=now,
                last_ip=ip_address,
            )
        except IntegrityError as exc:
            raise AuthorizationOperationError("DEVICE_CONFLICT", "设备注册发生冲突，请重试。", retryable=True, http_status=409) from exc
    elif device.risk_state == DeviceRiskState.BLOCKED:
        raise AuthorizationOperationError("RISK_BLOCKED", "当前设备已被阻断。", http_status=403)
    else:
        device.last_seen_at = now
        device.last_ip = ip_address or device.last_ip
        update_fields = ["last_seen_at", "last_ip"]
        # Older rows only had the derived hash.  Backfill the client-facing
        # value on the first trusted activation that sees the same device.
        if not device.installation_id:
            device.installation_id = installation_id
            update_fields.append("installation_id")
        device.save(update_fields=update_fields, _allow_mutation=True)
    return device


def _ensure_device_key(device: Device, *, key_id: str, encoded_public_key: str, now: datetime) -> DeviceKey:
    existing = DeviceKey.objects.select_for_update().filter(key_id=key_id).first()
    if existing:
        if existing.device_id != device.public_id:
            raise AuthorizationOperationError("DEVICE_KEY_REUSED", "设备公钥不能跨设备复用。", http_status=403)
        if existing.public_key != encoded_public_key or not existing.is_active:
            raise AuthorizationOperationError("DEVICE_KEY_MISMATCH", "设备公钥与登记记录不匹配。", http_status=403)
        return existing
    try:
        return DeviceKey.objects.create(
            key_id=key_id,
            device=device,
            algorithm=AUTHORIZATION_ALGORITHM,
            public_key=encoded_public_key,
            created_at=now,
        )
    except IntegrityError as exc:
        raise AuthorizationOperationError("DEVICE_KEY_REUSED", "设备公钥不能跨设备复用。", http_status=403) from exc


def _existing_device_key(device: Device, *, key_id: str, encoded_public_key: str) -> DeviceKey:
    try:
        key = DeviceKey.objects.select_for_update().get(key_id=key_id, device=device)
    except DeviceKey.DoesNotExist as exc:
        raise AuthorizationOperationError("DEVICE_KEY_MISMATCH", "设备公钥与登记记录不匹配。", http_status=403) from exc
    if key.public_key != encoded_public_key or not key.is_active:
        raise AuthorizationOperationError("DEVICE_KEY_MISMATCH", "设备公钥与登记记录不匹配。", http_status=403)
    return key


def _consume_nonce(*, profile: SoftwareProfile, device: Device, data: Mapping[str, Any], now: datetime) -> None:
    try:
        with transaction.atomic():
            AuthorizationNonce.objects.create(
                software=profile.software,
                profile=profile,
                device=device,
                nonce_hash=_nonce_hash(data["nonce"]),
                action=data["action"],
                request_id=data["request_id"],
                consumed_at=now,
                created_at=now,
            )
    except IntegrityError as exc:
        raise AuthorizationOperationError("REPLAY_DETECTED", "请求随机值已经使用。", http_status=409) from exc


def _server_now(clock: Clock | None) -> datetime:
    current = as_utc((clock or SystemClock()).now()).replace(microsecond=0)
    return current


def _epoch(value: datetime) -> int:
    return int(as_utc(value).timestamp())


def _binding_for_device(instance: LicenseInstance, device: Device, *, active_only: bool = False) -> DeviceBinding | None:
    query = DeviceBinding.objects.select_for_update().filter(authorization=instance, device=device)
    if active_only:
        query = query.filter(state=DeviceBindingState.ACTIVE)
    return query.in_history_order().first()


def _assert_device_key_matches_binding(binding: DeviceBinding | None, device_key: DeviceKey) -> None:
    if binding is not None and binding.device_key_id != device_key.key_id:
        raise AuthorizationOperationError("DEVICE_KEY_MISMATCH", "设备公钥与当前授权绑定不匹配。", http_status=403)


def _active_bindings(instance: LicenseInstance) -> list[DeviceBinding]:
    return list(
        DeviceBinding.objects.select_for_update().filter(
            authorization=instance,
            state=DeviceBindingState.ACTIVE,
        ).in_history_order().reverse()
    )


def _beijing_calendar_day(now: datetime):
    return to_beijing(now).date()


def _current_device_switch_policy(profile: SoftwareProfile) -> tuple[bool, int]:
    current = (
        PolicyVersion.objects.filter(profile=profile, status=PolicyStatus.ACTIVE)
        .order_by("-effective_at", "-created_at")
        .first()
    )
    if current is None:
        return False, 0
    return bool(current.allow_device_switch), int(current.device_switch_limit)


def current_verify_interval_seconds(profile: SoftwareProfile, *, fallback: int = 0) -> int:
    current = (
        PolicyVersion.objects.filter(profile=profile, status=PolicyStatus.ACTIVE)
        .order_by("-effective_at", "-created_at")
        .first()
    )
    if current is None:
        return max(0, int(fallback or 0))
    return max(0, int(current.verify_interval_seconds))


def _trusted_time_high_water_mark(
    instance: LicenseInstance,
    binding: DeviceBinding | None,
) -> datetime:
    trusted_times = [instance.issued_at]
    if instance.last_server_time:
        trusted_times.append(instance.last_server_time)
    if binding and binding.last_server_time:
        trusted_times.append(binding.last_server_time)
    return max(trusted_times)


def _mark_blocked_for_time_rollback(
    instance: LicenseInstance,
    *,
    binding: DeviceBinding | None,
    now: datetime,
) -> None:
    instance.state = AuthorizationState.BLOCKED
    instance.authorization_revision += 1
    instance.state_reason = TIME_ROLLBACK_BLOCKED_REASON
    instance.revoked_at = None
    # Keep the previous high-water mark; it is the evidence of the rollback.
    instance.save(update_fields=("state", "authorization_revision", "state_reason", "updated_at"), _allow_mutation=True)
    bindings = _active_bindings(instance)
    blocked_at = _trusted_time_high_water_mark(instance, binding)
    for item in bindings:
        item.state = DeviceBindingState.BLOCKED
        item.reason = TIME_ROLLBACK_BINDING_REASON
        item.unbound_at = blocked_at
        item.save(update_fields=("state", "reason", "unbound_at"), _allow_mutation=True)


# 服务端时钟微漂移容差：防 NTP 校准误封正常付费客户
TIME_ROLLBACK_TOLERANCE_SECONDS = 15
# 回拨阻断的稳定标记。回拨会把实例和绑定一起打成 BLOCKED，因此不能用
# 「实例 BLOCKED + 仍有 ACTIVE 绑定」的冻卡定义去识别它；管理员解冻必须
# 能认出这一类阻断，否则客户只能靠撤销废卡才能恢复。
TIME_ROLLBACK_BLOCKED_REASON = "服务端时间回退，等待管理员处理"
TIME_ROLLBACK_BINDING_REASON = "服务端时间回退"


def is_time_rollback_blocked(instance) -> bool:
    """True when this instance was blocked by server clock rollback detection.

    The marker lives in `state_reason`, which terminal transitions may rewrite,
    so the check is substring-based rather than equality-based: a rewritten
    reason keeps the marker as a prefix instead of silently dropping it and
    stranding the customer with revoke-only recovery.
    """

    return (
        instance.state == AuthorizationState.BLOCKED
        and TIME_ROLLBACK_BLOCKED_REASON in (instance.state_reason or "")
    )


def _active_bindings_high_water(instance: LicenseInstance) -> datetime | None:
    values = DeviceBinding.objects.filter(
        authorization=instance, state=DeviceBindingState.ACTIVE
    ).exclude(last_server_time__isnull=True).values_list("last_server_time", flat=True)
    candidates = [value for value in list(values) if value]
    return max(candidates) if candidates else None


def _time_rollback_detected(instance: LicenseInstance, binding: DeviceBinding | None, now: datetime) -> bool:
    last_values = [value for value in (instance.last_server_time, instance.issued_at, binding.last_server_time if binding else None) if value]
    if not last_values:
        return False
    # 只有当时间倒退超过容差时，才判定为真正的回滚攻击
    high_water = max(last_values)
    return now < high_water - timedelta(seconds=TIME_ROLLBACK_TOLERANCE_SECONDS)


def _sync_terminal_state(instance: LicenseInstance, card: LicenseCard, now: datetime) -> None:
    target_state: str | None = None
    reason = ""
    if card.status == LicenseCardStatus.REVOKED:
        target_state, reason = AuthorizationState.REVOKED, "授权卡密已撤销"
    elif card.status == LicenseCardStatus.DISABLED:
        target_state, reason = AuthorizationState.BLOCKED, "授权卡密已禁用"
    elif card.status == LicenseCardStatus.EXPIRED or (
        instance.state in {AuthorizationState.ACTIVE, AuthorizationState.GRACE} and now >= instance.expires_at
    ):
        target_state, reason = AuthorizationState.EXPIRED, "授权已到期"
    if not target_state or instance.state == target_state:
        return
    instance.state = target_state
    instance.authorization_revision += 1
    # Never let a terminal transition erase a rollback marker: doing so would
    # remove the only evidence that lets an administrator recover the seats.
    if is_time_rollback_blocked(instance) and target_state == AuthorizationState.BLOCKED:
        instance.state_reason = f"{TIME_ROLLBACK_BLOCKED_REASON}；{reason}"
    else:
        instance.state_reason = reason
    instance.last_server_time = max(filter(None, (instance.last_server_time, now)), default=now)
    instance.save(update_fields=("state", "authorization_revision", "state_reason", "last_server_time", "updated_at"), _allow_mutation=True)
    for binding in DeviceBinding.objects.select_for_update().filter(authorization=instance, state=DeviceBindingState.ACTIVE):
        binding.state = DeviceBindingState.BLOCKED if target_state in {AuthorizationState.REVOKED, AuthorizationState.BLOCKED} else DeviceBindingState.EXPIRED
        binding.unbound_at = now
        binding.reason = reason
        binding.save(update_fields=("state", "unbound_at", "reason"), _allow_mutation=True)
    if target_state == AuthorizationState.EXPIRED and card.status == LicenseCardStatus.ACTIVATED:
        card.status = LicenseCardStatus.EXPIRED
        card.expires_at = instance.expires_at
        card.status_reason = reason
        card.save(update_fields=("status", "expires_at", "status_reason"), _allow_mutation=True)


def _store_request_result(
    *,
    action: str,
    request_id: str,
    idempotency_key: str,
    request_hash: str,
    payload: dict[str, Any],
    status_code: int,
) -> AuthorizationResult:
    try:
        with transaction.atomic():
            record = AuthorizationRequestRecord.objects.create(
                request_id=request_id,
                action=action,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_status=status_code,
                response_payload=payload,
            )
    except IntegrityError:
        record = AuthorizationRequestRecord.objects.filter(action=action, idempotency_key=idempotency_key).first()
        if record is None:
            record = AuthorizationRequestRecord.objects.filter(request_id=request_id).first()
        if record is None or record.request_hash != request_hash:
            raise AuthorizationOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同请求。", http_status=409)
        return AuthorizationResult(record.response_payload, record.response_status, repeated=True)
    return AuthorizationResult(record.response_payload, record.response_status, repeated=False)


def _idempotent_allow_is_stale(
    payload: Mapping[str, Any],
    *,
    card: LicenseCard | None,
    instance: LicenseInstance | None,
    now: datetime,
    device_key_id: str | None = None,
) -> bool:
    """Never replay an allow response after its server-side facts changed."""

    if payload.get("decision") not in {"active", "grace", "not_modified"}:
        return False
    if instance is None:
        return True
    # Deactivate returns a state_code=unbound result for the same idempotent
    # action. It is already non-authorizing and must remain replayable.
    if payload.get("state_code") == "unbound":
        return False
    if payload.get("state_code") not in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
        return True
    try:
        recorded_revision = int(payload.get("authorization_revision"))
    except (TypeError, ValueError):
        return True
    if recorded_revision != instance.authorization_revision:
        return True
    if payload.get("config_version") != current_config_version(instance):
        return True
    if instance.state not in {AuthorizationState.ACTIVE, AuthorizationState.GRACE} or now >= instance.expires_at:
        return True
    if card and card.status not in {LicenseCardStatus.ACTIVATED}:
        return True
    device_scope = payload.get("device_scope")
    device_id = device_scope.get("device_id") if isinstance(device_scope, Mapping) else None
    if not device_id or instance is None or not device_key_id:
        return True
    device = Device.objects.filter(public_id=device_id).only("risk_state").first()
    if device is None or device.risk_state == DeviceRiskState.BLOCKED:
        return True
    binding = DeviceBinding.objects.select_for_update().filter(
        authorization=instance,
        device_id=device_id,
        state=DeviceBindingState.ACTIVE,
    ).only("device_key_id").first()
    if binding is None or binding.device_key_id != device_key_id:
        return True
    return False


def _existing_request_result(
    *,
    action: str,
    request_id: str,
    idempotency_key: str,
    request_hash: str,
    card: LicenseCard | None = None,
    instance: LicenseInstance | None = None,
    now: datetime | None = None,
    device_key_id: str | None = None,
) -> AuthorizationResult | None:
    record = AuthorizationRequestRecord.objects.select_for_update().filter(action=action, idempotency_key=idempotency_key).first()
    if record is None:
        record = AuthorizationRequestRecord.objects.select_for_update().filter(request_id=request_id).first()
    if record is None:
        return None
    if record.request_hash != request_hash:
        raise AuthorizationOperationError("IDEMPOTENCY_CONFLICT", "同一个幂等键不能对应不同请求。", http_status=409)
    if now is not None and _idempotent_allow_is_stale(
        record.response_payload,
        card=card,
        instance=instance,
        now=now,
        device_key_id=device_key_id,
    ):
        raise AuthorizationOperationError(
            "IDEMPOTENCY_CONFLICT",
            "原幂等结果已因授权状态变化失效，请使用新的请求标识重试。",
            http_status=409,
        )
    return AuthorizationResult(record.response_payload, record.response_status, repeated=True)


def _build_response(
    instance: LicenseInstance,
    *,
    binding: DeviceBinding | None,
    data: Mapping[str, Any],
    now: datetime,
    decision: str | None = None,
    state_code: str | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
    confirmed_installation_id: str | None = None,
) -> tuple[dict[str, Any], int]:
    policy = instance.policy_version
    verify_interval_seconds = current_verify_interval_seconds(
        instance.profile,
        fallback=policy.verify_interval_seconds,
    )
    response_now = now
    if error_code == "TIME_ROLLBACK_DETECTED":
        # The wall clock that triggered rollback detection is untrusted. Use
        # the persisted high-water mark for the signed diagnostic envelope so
        # the temporal invariant issued_at <= server_time remains true.
        response_now = _trusted_time_high_water_mark(instance, binding)
    else:
        # 服务端 NTP 微调在容差内不阻断，但返回给客户端的时间仍保持单调不退后
        response_now = max(now, _trusted_time_high_water_mark(instance, binding))
    state = state_code or instance.state
    response_decision = decision or state
    if state in {AuthorizationState.ACTIVE, AuthorizationState.GRACE}:
        verify_after = min(
            instance.expires_at,
            response_now + timedelta(seconds=max(0, verify_interval_seconds)),
        )
        cache_until = verify_after
        grace_until = instance.expires_at + timedelta(seconds=policy.offline_grace_seconds)
        status_code = 200
    elif state == "unbound":
        verify_after = min(response_now, instance.expires_at)
        cache_until = verify_after
        grace_until = response_now
        status_code = 200
    else:
        verify_after = min(response_now, instance.expires_at)
        cache_until = verify_after
        grace_until = response_now
        status_code = 403
    device = binding.device if binding and confirmed_installation_id is not None else None
    if device and _installation_hash(instance.profile, confirmed_installation_id) != device.installation_hash:
        raise AuthorizationOperationError("DEVICE_SCOPE_MISMATCH", "已确认设备范围与授权绑定不匹配。", http_status=502)
    public_capability_keys = set(
        instance.profile.capabilities.filter(
            status=CapabilityStatus.ACTIVE,
            is_public=True,
        ).values_list("capability_key", flat=True)
    )
    configuration = effective_configuration_for_authorization(instance)
    response: dict[str, Any] = {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "request_id": data["request_id"],
        "software_id": instance.software.software_id,
        "profile_id": instance.profile.profile_id,
        "client_id": instance.client_id,
        "contract_version": instance.contract_version,
        "target": instance.target,
        "arch": instance.arch,
        "channel": instance.channel,
        "authorization_id": str(instance.authorization_id),
        "authorization_revision": int(instance.authorization_revision),
        "device_scope": {
            "scope": "current_device",
            "device_id": str(device.public_id) if device else None,
            "installation_id": confirmed_installation_id if device else None,
        },
        "decision": response_decision,
        "state_code": state,
        "status": state,
        "issued_at": _epoch(instance.issued_at),
        "expires_at": _epoch(instance.expires_at),
        "server_time": _epoch(response_now),
        "cache_until": _epoch(cache_until),
        "next_verify_at": _epoch(verify_after),
        "grace_until": _epoch(grace_until),
        "config_version": configuration["config_version"],
        "policy_version": policy.version,
        "adapter_key": instance.profile.adapter_key,
        "adapter_version": instance.profile.adapter_version,
        "capabilities": {
            key: value
            for key, value in (instance.plan_snapshot.capability_values or {}).items()
            if key in public_capability_keys
        },
        "entitlements": {
            "plan_name": instance.plan_snapshot.name,
            "test_only": bool(instance.plan_snapshot.test_only),
            "duration_seconds": int(instance.plan_snapshot.duration_seconds),
        },
        "support": configuration["support"],
        "announcement": configuration["announcement"],
        "purchase": configuration["purchase"],
        "qr": configuration["qr"],
        "update": configuration["update"],
        "modules": configuration["modules"],
    }
    if state == "unbound":
        response["binding_state"] = DeviceBindingState.UNBOUND
    if error_code:
        response["error"] = {
            "code": error_code,
            "message": error_message or error_code,
            "request_id": data["request_id"],
            "retryable": False,
        }
    return sign_authorization_response(response), status_code


def _request_audit_metadata(request: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        return {}
    metadata: dict[str, Any] = {}
    for field, max_length in (("software_id", 64), ("profile_id", 64), ("authorization_id", 64)):
        value = request.get(field)
        if isinstance(value, str) and value.strip():
            metadata[field] = value.strip()[:max_length]
    downstream_public_id = request.get("downstream_public_id")
    if isinstance(downstream_public_id, str) and downstream_public_id.strip():
        metadata["downstream_public_id"] = downstream_public_id.strip()[:64]
    installation_id = request.get("installation_id")
    if isinstance(installation_id, str) and installation_id.strip():
        metadata["installation_id"] = installation_id.strip()[:128]
    license_key = request.get("license_key")
    if isinstance(license_key, str) and license_key.strip():
        # Keep only the existing keyed digest so a failed activation can be
        # matched to its downstream without persisting a plaintext card.
        metadata["card_digest"] = license_card_hash(license_key.strip())
    return metadata


def _audit_failure(
    action: str,
    error: AuthorizationOperationError,
    *,
    request_id: str | None,
    ip_address: str | None,
    request_metadata: Mapping[str, Any] | None = None,
) -> None:
    try:
        metadata: dict[str, Any] = {"retryable": error.retryable}
        if request_metadata:
            metadata.update({key: value for key, value in request_metadata.items() if value not in (None, "")})
        record_event(
            actor=None,
            action=f"authorization.{action}",
            outcome=AuditOutcome.FAILURE,
            request_id=_audit_request_id(request_id),
            ip_address=ip_address,
            reason_code=error.code,
            metadata=metadata,
        )
    except Exception:
        # An audit failure must not turn a stable client error into a secret leak
        # or a different authorization result in this local slice.
        return


def _audit_request_id(value: str | None) -> str | None:
    """Keep client-controlled request IDs out of the authorization audit text."""

    if not value:
        return None
    return f"auth-{hashlib.sha256(str(value).encode('utf-8')).hexdigest()}"


def _validate_and_prepare(action: str, request: Mapping[str, Any], *, request_id: str | None, idempotency_key: str | None) -> tuple[dict[str, Any], str, str, str]:
    data, resolved_request_id, resolved_idempotency = _normalize_request(
        action,
        request,
        request_id=request_id,
        idempotency_key=idempotency_key,
    )
    try:
        request_hash = _request_fingerprint(data)
    except ValueError as exc:
        raise AuthorizationOperationError("INVALID_REQUEST", "请求内容无法规范化。") from exc
    return data, resolved_request_id, resolved_idempotency, request_hash


def activate_license(
    *,
    request: Mapping[str, Any],
    request_id: str | None = None,
    idempotency_key: str | None = None,
    clock: Clock | None = None,
    ip_address: str | None = None,
) -> AuthorizationResult:
    try:
        data, resolved_request_id, resolved_idempotency, request_hash = _validate_and_prepare(
            "activate", request, request_id=request_id, idempotency_key=idempotency_key
        )
        with transaction.atomic():
            profile = _validate_profile(data)
            card = _lock_card_by_license_key(data["license_key"])
            snapshot, policy = _load_card_policy(card, profile)
            instance = _lock_instance_for_card(card)
            now = _server_now(clock)
            _, request_key_id, _ = _device_key_info(data)
            existing = _existing_request_result(
                action="activate",
                request_id=resolved_request_id,
                idempotency_key=resolved_idempotency,
                request_hash=request_hash,
                card=card,
                instance=instance,
                now=now,
                device_key_id=request_key_id,
            )
            if existing:
                return existing
            if card.status == LicenseCardStatus.RECLAIMED:
                raise AuthorizationOperationError("LICENSE_NOT_ACTIVE", "授权卡密已经回收。", http_status=403)
            if card.status == LicenseCardStatus.REVOKED:
                if instance:
                    _sync_terminal_state(instance, card, now)
                    binding = DeviceBinding.objects.filter(authorization=instance).in_history_order().first()
                    payload, status = _build_response(instance, binding=binding, data=data, now=now, error_code="LICENSE_REVOKED", error_message="授权卡密已撤销。")
                    return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
                raise AuthorizationOperationError("LICENSE_REVOKED", "授权卡密已撤销。", http_status=403)
            if card.status == LicenseCardStatus.DISABLED:
                if instance:
                    _sync_terminal_state(instance, card, now)
                    binding = DeviceBinding.objects.filter(authorization=instance).in_history_order().first()
                    payload, status = _build_response(instance, binding=binding, data=data, now=now, error_code="LICENSE_BLOCKED", error_message="授权卡密已禁用。")
                    return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
                raise AuthorizationOperationError("LICENSE_BLOCKED", "授权卡密已禁用。", http_status=403)
            if card.status in {LicenseCardStatus.ARCHIVED, LicenseCardStatus.DELETED_TOMBSTONE}:
                raise AuthorizationOperationError(
                    "LICENSE_NOT_ACTIVE",
                    "授权卡密已归档或已删除，不能激活。",
                    http_status=403,
                )
            if card.status == LicenseCardStatus.EXPIRED and instance is None:
                raise AuthorizationOperationError("LICENSE_EXPIRED", "授权卡密已过期。", http_status=403)
            if card.status == LicenseCardStatus.UNUSED:
                _ensure_downstream_active(card)
                _ensure_catalog_access_for_unused_activate(card)
            elif instance is None:
                raise AuthorizationOperationError("AUTHORIZATION_STATE_INCONSISTENT", "授权记录不完整，已阻止本次操作。", http_status=503)

            if instance:
                _sync_terminal_state(instance, card, now)
                if instance.state in {AuthorizationState.EXPIRED, AuthorizationState.REVOKED, AuthorizationState.BLOCKED}:
                    error_code = {
                        AuthorizationState.EXPIRED: "LICENSE_EXPIRED",
                        AuthorizationState.REVOKED: "LICENSE_REVOKED",
                        AuthorizationState.BLOCKED: "LICENSE_BLOCKED",
                    }[instance.state]
                    binding = DeviceBinding.objects.filter(authorization=instance).in_history_order().first()
                    payload, status = _build_response(instance, binding=binding, data=data, now=now, error_code=error_code, error_message="当前授权不可用。")
                    return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
                if _time_rollback_detected(instance, None, now):
                    # Untrusted proof failures must not persist a customer block,
                    # even when the server clock really has rolled back.
                    _verify_device_proof(data, proof_required=policy.device_proof_required)
                    _mark_blocked_for_time_rollback(instance, binding=None, now=now)
                    payload, status = _build_response(instance, binding=None, data=data, now=now, error_code="TIME_ROLLBACK_DETECTED", error_message="服务端可信时间发生回退，授权已阻断。")
                    return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
                existing_device = Device.objects.filter(
                    software_id=profile.software_id,
                    profile_id=profile.pk,
                    installation_hash=_installation_hash(profile, data["installation_id"]),
                ).first()
                if existing_device is None or not DeviceBinding.objects.filter(
                    authorization=instance,
                    device=existing_device,
                    state=DeviceBindingState.ACTIVE,
                ).exists():
                    _ensure_downstream_active(card)

            _, key_id, encoded_key = _verify_device_proof(data, proof_required=policy.device_proof_required)
            device = _ensure_device(profile, data["installation_id"], ip_address=ip_address, now=now)
            device_key = _ensure_device_key(device, key_id=key_id, encoded_public_key=encoded_key, now=now)
            active_binding = _binding_for_device(instance, device, active_only=True) if instance else None
            previous_binding = (active_binding or _binding_for_device(instance, device)) if instance else None
            # A legacy same-time multi-key history has no recoverable last key.
            # Free recovery requires every possible last key to match, until a
            # successful new event establishes a persisted order.
            previous_candidates = []
            if active_binding:
                previous_candidates = [active_binding]
            elif instance:
                previous_candidates = list(
                    DeviceBinding.objects.filter(authorization=instance, device=device).latest_candidates()
                )
            previous_key_ids = {item.device_key_id for item in previous_candidates}
            key_rotation_charged = False
            if previous_binding and previous_key_ids != {device_key.pk}:
                # 同一物理设备持合法卡密与有效证明重新激活：自愈轮换设备公钥，消除重装死锁
                # 复核结论：轮换计入当日换机额度（不看allow开关，保证重装可用），防止持卡冒用installation_id无限乒乓劫持
                _, rotate_limit = _current_device_switch_policy(profile)
                rotate_today = _beijing_calendar_day(now)
                rotate_used = instance.device_switch_count if instance.device_switch_day == rotate_today else 0
                if rotate_limit > 0 and rotate_used >= rotate_limit:
                    raise AuthorizationOperationError(
                        "DEVICE_SWITCH_LIMIT_REACHED",
                        "当日换机次数已用尽。",
                        http_status=403,
                    )
                instance.device_switch_count = rotate_used + 1
                instance.device_switch_day = rotate_today
                key_rotation_charged = True
                old_key_id = previous_binding.device_key_id if len(previous_key_ids) == 1 else ""
                if active_binding:
                    rotate_effective = max(filter(None, (instance.last_server_time, active_binding.last_server_time, now)), default=now)
                    active_binding.device_key = device_key
                    active_binding.bound_at = rotate_effective
                    active_binding.save(update_fields=("device_key", "bound_at"), _allow_mutation=True, _advance_order=True)
                    instance.authorization_revision += 1
                record_event(
                    actor=None,
                    action="device.key_rotate",
                    outcome=AuditOutcome.SUCCESS,
                    request_id=resolved_request_id,
                    ip_address=ip_address,
                    object_type="DeviceBinding",
                    object_public_id=previous_binding.binding_id,
                    metadata={
                        "authorization_id": str(instance.authorization_id),
                        "device_id": str(device.public_id),
                        "installation_id": data["installation_id"],
                        "old_key_id": old_key_id,
                        "new_key_id": key_id,
                        "legacy_key_order_ambiguous": len(previous_key_ids) > 1,
                        "new_revision": instance.authorization_revision + (0 if active_binding else 1),
                    },
                )
            else:
                _assert_device_key_matches_binding(active_binding, device_key)
            _consume_nonce(profile=profile, device=device, data=data, now=now)

            first_activation = instance is None
            if instance is None:
                expires_at = now + timedelta(seconds=snapshot.duration_seconds)
                instance = LicenseInstance.objects.create(
                    license_card=card,
                    software=profile.software,
                    profile=profile,
                    plan_snapshot=snapshot,
                    policy_version=policy,
                    current_downstream_public_id=card.current_downstream_public_id,
                    client_id=profile.client_id,
                    contract_version=profile.contract_version,
                    target=profile.target,
                    arch=profile.arch,
                    channel=profile.channel,
                    client_version=data["client_version"],
                    state=AuthorizationState.ACTIVE,
                    authorization_revision=1,
                    config_version=profile.config_version,
                    issued_at=now,
                    activated_at=now,
                    expires_at=expires_at,
                    last_verified_at=now,
                    last_server_time=now,
                )
                binding = DeviceBinding.objects.create(
                    authorization=instance,
                    device=device,
                    device_key=device_key,
                    state=DeviceBindingState.ACTIVE,
                    bound_at=now,
                    last_server_time=now,
                )
                card.status = LicenseCardStatus.ACTIVATED
                card.activated_at = now
                card.expires_at = expires_at
                card.status_reason = "首次在线激活"
                card.save(update_fields=("status", "activated_at", "expires_at", "status_reason"), _allow_mutation=True)
            else:
                binding = active_binding
                if binding:
                    if _time_rollback_detected(instance, binding=binding, now=now):
                        _mark_blocked_for_time_rollback(instance, binding=binding, now=now)
                        payload, status = _build_response(instance, binding=binding, data=data, now=now, error_code="TIME_ROLLBACK_DETECTED", error_message="服务端可信时间发生回退，授权已阻断。", confirmed_installation_id=data["installation_id"])
                        return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
                    effective_server_time = max(filter(None, (instance.last_server_time, binding.last_server_time, now)), default=now)
                    binding.last_server_time = effective_server_time
                    binding.save(update_fields=("last_server_time",), _allow_mutation=True)
                    instance.last_verified_at = now
                    instance.last_server_time = effective_server_time
                    instance.client_version = data["client_version"]
                    instance.save(update_fields=("last_verified_at", "last_server_time", "client_version", "authorization_revision", "device_switch_count", "device_switch_day", "updated_at"), _allow_mutation=True)
                else:
                    active_bindings = _active_bindings(instance)
                    bindings_high_water = _active_bindings_high_water(instance)
                    if bindings_high_water and now < bindings_high_water - timedelta(seconds=TIME_ROLLBACK_TOLERANCE_SECONDS):
                        _mark_blocked_for_time_rollback(instance, binding=None, now=now)
                        payload, status = _build_response(instance, binding=None, data=data, now=now, error_code="TIME_ROLLBACK_DETECTED", error_message="服务端可信时间发生回退，授权已阻断。", confirmed_installation_id=data["installation_id"])
                        return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
                    history_device_ids = set(
                        DeviceBinding.objects.filter(authorization=instance).values_list("device_id", flat=True)
                    )
                    last_candidates = list(
                        DeviceBinding.objects.filter(authorization=instance)
                        .latest_candidates()
                    )
                    is_switching_device = False
                    if len(active_bindings) >= policy.max_devices:
                        is_switching_device = True
                    elif device.pk not in history_device_ids and len(history_device_ids) >= policy.max_devices:
                        is_switching_device = True
                    elif (
                        device.pk in history_device_ids
                        and any(item.device_id != device.pk for item in last_candidates)
                    ):
                        is_switching_device = True

                    if is_switching_device:
                        allow_switch, daily_limit = _current_device_switch_policy(profile)
                        if not allow_switch:
                            raise AuthorizationOperationError(
                                "DEVICE_LIMIT_REACHED",
                                "当前不允许新电脑挤掉旧电脑。请先在原电脑退出，或联系代理重置设备。",
                                http_status=403,
                            )
                        today = _beijing_calendar_day(now)
                        used = instance.device_switch_count if instance.device_switch_day == today else 0
                        if not key_rotation_charged and used >= daily_limit:
                            raise AuthorizationOperationError(
                                "DEVICE_SWITCH_LIMIT_REACHED",
                                "当日换机次数已用尽。",
                                http_status=403,
                            )
                        if len(active_bindings) >= policy.max_devices:
                            old_binding = active_bindings[0]
                            old_binding.state = DeviceBindingState.UNBOUND
                            old_binding.unbound_at = now
                            old_binding.reason = "设备切换"
                            old_binding.switch_count += 1
                            old_binding.save(update_fields=("state", "unbound_at", "reason", "switch_count"), _allow_mutation=True)
                            # 挤机是「谁把谁踢了」这件事唯一的正向事件。这里以前只改绑定
                            # 状态、不写任何审计，于是客户说「我被踢了」时，平台侧只剩被踢
                            # 设备下次 verify 报出的 DEVICE_NOT_BOUND ——看不出是谁、什么
                            # 时候、用哪台机顶的。写下来，管理员才能自己查清楚，而不是靠猜。
                            record_event(
                                actor=None,
                                action="device.kicked",
                                outcome=AuditOutcome.SUCCESS,
                                request_id=_audit_request_id(resolved_request_id),
                                ip_address=ip_address,
                                object_type="DeviceBinding",
                                object_public_id=old_binding.binding_id,
                                metadata={
                                    "authorization_id": str(instance.authorization_id),
                                    "software_id": card.software_id,
                                    "downstream_public_id": str(card.current_downstream_public_id),
                                    "kicked_device_id": str(old_binding.device.public_id),
                                    "kicked_installation_id": old_binding.device.installation_id or "",
                                    "kicked_device_key_id": old_binding.device_key_id,
                                    "incoming_device_id": str(device.public_id),
                                    "incoming_installation_id": data["installation_id"],
                                    "active_bindings_before": len(active_bindings),
                                    "max_devices": policy.max_devices,
                                    "reason": "设备切换",
                                },
                            )
                        instance.device_switch_count = used if key_rotation_charged else used + 1
                        instance.device_switch_day = today
                    effective_server_time = max(filter(None, (instance.last_server_time, _active_bindings_high_water(instance), now)), default=now)
                    binding = DeviceBinding.objects.create(
                        authorization=instance,
                        device=device,
                        device_key=device_key,
                        state=DeviceBindingState.ACTIVE,
                        switch_count=instance.device_switch_count,
                        bound_at=effective_server_time,
                        last_server_time=effective_server_time,
                    )
                    instance.authorization_revision += 1
                    instance.last_verified_at = now
                    instance.last_server_time = effective_server_time
                    instance.client_version = data["client_version"]
                    instance.save(
                        update_fields=(
                            "authorization_revision",
                            "last_verified_at",
                            "last_server_time",
                            "client_version",
                            "device_switch_count",
                            "device_switch_day",
                            "updated_at",
                        ),
                        _allow_mutation=True,
                    )

            decision = "not_modified" if data.get("known_authorization_revision") == instance.authorization_revision and data.get("known_config_version", data.get("config_version")) == current_config_version(instance) else None
            payload, status = _build_response(instance, binding=binding, data=data, now=now, decision=decision, confirmed_installation_id=data["installation_id"])
            record_event(
                actor=None,
                action="authorization.activate",
                outcome=AuditOutcome.SUCCESS,
                request_id=_audit_request_id(resolved_request_id),
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "repeated": False,
                    "authorization_revision": instance.authorization_revision,
                    "device_id": str(device.public_id),
                    "installation_id": data["installation_id"],
                    "software_id": card.software_id,
                    "downstream_public_id": str(card.current_downstream_public_id),
                },
            )
            if first_activation:
                from authorization_platform.backup_control.services import schedule_change_backup

                schedule_change_backup()
            return _store_request_result(action="activate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
    except AuthorizationOperationError as exc:
        _audit_failure(
            "activate",
            exc,
            request_id=request_id,
            ip_address=ip_address,
            request_metadata=_request_audit_metadata(request),
        )
        raise


def verify_license(
    *,
    request: Mapping[str, Any],
    request_id: str | None = None,
    idempotency_key: str | None = None,
    clock: Clock | None = None,
    ip_address: str | None = None,
) -> AuthorizationResult:
    try:
        data, resolved_request_id, resolved_idempotency, request_hash = _validate_and_prepare(
            "verify", request, request_id=request_id, idempotency_key=idempotency_key
        )
        with transaction.atomic():
            profile = _validate_profile(data)
            card, instance = _lock_card_for_instance(data["authorization_id"])
            now = _server_now(clock)
            _, request_key_id, _ = _device_key_info(data)
            existing = _existing_request_result(
                action="verify",
                request_id=resolved_request_id,
                idempotency_key=resolved_idempotency,
                request_hash=request_hash,
                card=card,
                instance=instance,
                now=now,
                device_key_id=request_key_id,
            )
            if existing:
                return existing
            if instance.profile_id != profile.pk or instance.software_id != profile.software_id:
                raise AuthorizationOperationError("PROFILE_MISMATCH", "授权实例与客户端身份不匹配。", http_status=403)
            policy = instance.policy_version
            raw_key, key_id, encoded_key = _verify_device_proof(data, proof_required=policy.device_proof_required)
            device = Device.objects.select_for_update().filter(
                software_id=profile.software_id,
                profile_id=profile.pk,
                installation_hash=_installation_hash(profile, data["installation_id"]),
            ).first()
            if device is None:
                raise AuthorizationOperationError("DEVICE_NOT_BOUND", "当前设备没有授权绑定。", http_status=403)
            if not device.installation_id:
                device.installation_id = data["installation_id"]
                device.save(update_fields=("installation_id",), _allow_mutation=True)
            if device.risk_state == DeviceRiskState.BLOCKED:
                raise AuthorizationOperationError("RISK_BLOCKED", "当前设备已被阻断。", http_status=403)
            device_key = _existing_device_key(device, key_id=key_id, encoded_public_key=encoded_key)
            binding = _binding_for_device(instance, device, active_only=True)
            _assert_device_key_matches_binding(binding, device_key)
            latest_binding = binding or _binding_for_device(instance, device)
            if _time_rollback_detected(instance, latest_binding, now):
                _mark_blocked_for_time_rollback(instance, binding=latest_binding, now=now)
                payload, status = _build_response(instance, binding=latest_binding, data=data, now=now, error_code="TIME_ROLLBACK_DETECTED", error_message="服务端可信时间发生回退，授权已阻断。", confirmed_installation_id=data["installation_id"])
                _consume_nonce(profile=profile, device=device, data=data, now=now)
                return _store_request_result(action="verify", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
            if binding is None and instance.state == AuthorizationState.ACTIVE:
                raise AuthorizationOperationError("DEVICE_NOT_BOUND", "当前设备没有有效授权绑定。", http_status=403)
            _consume_nonce(profile=profile, device=device, data=data, now=now)
            _sync_terminal_state(instance, card, now)
            if instance.state == AuthorizationState.ACTIVE:
                effective_server_time = max(filter(None, (instance.last_server_time, binding.last_server_time if binding else None, now)), default=now)
                if binding:
                    binding.last_server_time = effective_server_time
                    binding.save(update_fields=("last_server_time",), _allow_mutation=True)
                device.last_seen_at = now
                device.last_ip = ip_address or device.last_ip
                device.save(update_fields=("last_seen_at", "last_ip"), _allow_mutation=True)
                instance.last_verified_at = now
                instance.last_server_time = effective_server_time
                instance.client_version = data["client_version"]
                instance.save(update_fields=("last_verified_at", "last_server_time", "client_version", "updated_at"), _allow_mutation=True)
            error_code = None
            error_message = None
            if instance.state == AuthorizationState.EXPIRED:
                error_code, error_message = "LICENSE_EXPIRED", "授权已过期。"
            elif instance.state == AuthorizationState.REVOKED:
                error_code, error_message = "LICENSE_REVOKED", "授权已撤销。"
            elif instance.state == AuthorizationState.BLOCKED:
                error_code, error_message = "LICENSE_BLOCKED", "授权已阻断。"
            decision = None
            if instance.state == AuthorizationState.ACTIVE and data.get("known_authorization_revision") == instance.authorization_revision and data.get("known_config_version", data.get("config_version")) == current_config_version(instance):
                decision = "not_modified"
            payload, status = _build_response(instance, binding=latest_binding, data=data, now=now, decision=decision, error_code=error_code, error_message=error_message, confirmed_installation_id=data["installation_id"])
            record_event(
                actor=None,
                action="authorization.verify",
                outcome=AuditOutcome.SUCCESS,
                request_id=_audit_request_id(resolved_request_id),
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "decision": payload["decision"],
                    "authorization_revision": instance.authorization_revision,
                    "device_id": str(device.public_id),
                    "installation_id": data["installation_id"],
                    "software_id": instance.software_id,
                    "downstream_public_id": str(instance.current_downstream_public_id),
                },
            )
            return _store_request_result(action="verify", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
    except AuthorizationOperationError as exc:
        _audit_failure(
            "verify",
            exc,
            request_id=request_id,
            ip_address=ip_address,
            request_metadata=_request_audit_metadata(request),
        )
        raise


def deactivate_license(
    *,
    request: Mapping[str, Any],
    request_id: str | None = None,
    idempotency_key: str | None = None,
    clock: Clock | None = None,
    ip_address: str | None = None,
) -> AuthorizationResult:
    try:
        data, resolved_request_id, resolved_idempotency, request_hash = _validate_and_prepare(
            "deactivate", request, request_id=request_id, idempotency_key=idempotency_key
        )
        with transaction.atomic():
            profile = _validate_profile(data)
            card, instance = _lock_card_for_instance(data["authorization_id"])
            now = _server_now(clock)
            _, request_key_id, _ = _device_key_info(data)
            existing = _existing_request_result(
                action="deactivate",
                request_id=resolved_request_id,
                idempotency_key=resolved_idempotency,
                request_hash=request_hash,
                card=card,
                instance=instance,
                now=now,
                device_key_id=request_key_id,
            )
            if existing:
                return existing
            if instance.profile_id != profile.pk or instance.software_id != profile.software_id:
                raise AuthorizationOperationError("PROFILE_MISMATCH", "授权实例与客户端身份不匹配。", http_status=403)
            policy = instance.policy_version
            _, key_id, encoded_key = _verify_device_proof(data, proof_required=policy.device_proof_required)
            device = Device.objects.select_for_update().filter(
                software_id=profile.software_id,
                profile_id=profile.pk,
                installation_hash=_installation_hash(profile, data["installation_id"]),
            ).first()
            if device is None:
                raise AuthorizationOperationError("DEVICE_NOT_BOUND", "当前设备没有授权绑定。", http_status=403)
            device_key = _existing_device_key(device, key_id=key_id, encoded_public_key=encoded_key)
            binding = _binding_for_device(instance, device, active_only=True)
            if binding is None:
                raise AuthorizationOperationError("DEVICE_NOT_BOUND", "当前设备没有有效授权绑定。", http_status=403)
            _assert_device_key_matches_binding(binding, device_key)
            _sync_terminal_state(instance, card, now)
            if instance.state == AuthorizationState.EXPIRED:
                _consume_nonce(profile=profile, device=device, data=data, now=now)
                payload, status = _build_response(
                    instance,
                    binding=binding,
                    data=data,
                    now=now,
                    error_code="LICENSE_EXPIRED",
                    error_message="授权已过期。",
                    confirmed_installation_id=data["installation_id"],
                )
                return _store_request_result(
                    action="deactivate",
                    request_id=resolved_request_id,
                    idempotency_key=resolved_idempotency,
                    request_hash=request_hash,
                    payload=payload,
                    status_code=status,
                )
            if instance.state in {AuthorizationState.REVOKED, AuthorizationState.BLOCKED}:
                _consume_nonce(profile=profile, device=device, data=data, now=now)
                error_code, error_message = (
                    ("LICENSE_REVOKED", "授权已撤销。")
                    if instance.state == AuthorizationState.REVOKED
                    else ("LICENSE_BLOCKED", "授权已阻断。")
                )
                payload, status = _build_response(
                    instance,
                    binding=binding,
                    data=data,
                    now=now,
                    error_code=error_code,
                    error_message=error_message,
                    confirmed_installation_id=data["installation_id"],
                )
                return _store_request_result(
                    action="deactivate",
                    request_id=resolved_request_id,
                    idempotency_key=resolved_idempotency,
                    request_hash=request_hash,
                    payload=payload,
                    status_code=status,
                )
            if _time_rollback_detected(instance, binding, now):
                _mark_blocked_for_time_rollback(instance, binding=binding, now=now)
                _consume_nonce(profile=profile, device=device, data=data, now=now)
                payload, status = _build_response(instance, binding=binding, data=data, now=now, error_code="TIME_ROLLBACK_DETECTED", error_message="服务端可信时间发生回退，授权已阻断。", confirmed_installation_id=data["installation_id"])
                return _store_request_result(action="deactivate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
            _consume_nonce(profile=profile, device=device, data=data, now=now)
            binding.state = DeviceBindingState.UNBOUND
            binding.unbound_at = now
            binding.reason = "客户端主动解绑"
            binding.save(update_fields=("state", "unbound_at", "reason"), _allow_mutation=True)
            effective_server_time = max(filter(None, (instance.last_server_time, now)), default=now)
            instance.authorization_revision += 1
            instance.last_verified_at = now
            instance.last_server_time = effective_server_time
            instance.save(update_fields=("authorization_revision", "last_verified_at", "last_server_time", "updated_at"), _allow_mutation=True)
            payload, status = _build_response(instance, binding=binding, data=data, now=now, state_code="unbound", decision="unbound", confirmed_installation_id=data["installation_id"])
            record_event(
                actor=None,
                action="authorization.deactivate",
                outcome=AuditOutcome.SUCCESS,
                request_id=_audit_request_id(resolved_request_id),
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "device_id": str(device.public_id),
                    "installation_id": data["installation_id"],
                    "authorization_revision": instance.authorization_revision,
                    "software_id": instance.software_id,
                    "downstream_public_id": str(instance.current_downstream_public_id),
                },
            )
            return _store_request_result(action="deactivate", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=status)
    except AuthorizationOperationError as exc:
        _audit_failure(
            "deactivate",
            exc,
            request_id=request_id,
            ip_address=ip_address,
            request_metadata=_request_audit_metadata(request),
        )
        raise


LAUNCH_TICKET_SCHEMA_VERSION = "authorization.v1"
LAUNCH_TICKET_CONTRACT_VERSION = "authorization.v1"
LAUNCH_TICKET_DEFAULT_TTL_SECONDS = 180
LAUNCH_TICKET_ORIGIN = "authorization-platform"


def _launch_ticket_audience(software_id: str) -> str:
    """派生票据受众。规则固定为 ``{software_id}-core``，不按软件名分支。

    例如 ``cs2-pro-vision`` 派生出 ``cs2-pro-vision-core``，与客户端钉死的
    值一致；新软件自动得到自己的受众，无需改平台代码。
    """

    return f"{software_id}-core"


def sign_launch_ticket(payload: Mapping[str, Any]) -> dict[str, Any]:
    """签一张启动票据响应。签名口径与中央授权响应一致。

    覆盖范围 = 整个响应体去掉 ``integrity.signature`` 这一个字段，其余字段
    （包括 ``integrity`` 内的 ``algorithm`` / ``key_id`` /
    ``canonicalization`` / ``origin`` / ``audience``）全部参与 JCS 规范化。
    注意：不要把整个 ``integrity`` 对象删掉再签，那是另一种字节流，
    客户端按本口径验签会失败。
    """

    ticket = dict(payload)
    integrity = ticket.get("integrity")
    if not isinstance(integrity, dict):
        raise AuthorizationOperationError("INVALID_REQUEST", "票据缺少完整性字段。")
    for field in ("algorithm", "key_id", "canonicalization", "origin", "audience"):
        if field not in integrity:
            raise AuthorizationOperationError("INVALID_REQUEST", f"票据完整性缺少 {field}。")
    if (
        integrity.get("algorithm") != AUTHORIZATION_ALGORITHM
        or integrity.get("canonicalization") != AUTHORIZATION_CANONICALIZATION
    ):
        raise AuthorizationOperationError("INVALID_REQUEST", "票据完整性算法不受支持。")
    signable = dict(ticket)
    signable_integrity = dict(integrity)
    signable_integrity.pop("signature", None)
    signable["integrity"] = signable_integrity
    try:
        signature = _signing_private_key().sign(canonicalize_jcs(signable))
    except AuthorizationOperationError:
        raise
    except (ValueError, TypeError) as exc:
        raise AuthorizationOperationError("SIGNATURE_UNAVAILABLE", "票据签名失败。", http_status=503) from exc
    ticket["integrity"] = dict(signable_integrity)
    ticket["integrity"]["signature"] = _base64url_encode(signature)
    return ticket


def _ticket_epoch(value: datetime) -> int:
    return int(_epoch(as_utc(value).replace(microsecond=0)))


def _build_ticket_payload(
    *,
    instance: LicenseInstance,
    device: Device,
    ticket: LaunchTicket,
    data: Mapping[str, Any],
    now: datetime,
    server_time: int,
) -> dict[str, Any]:
    audience = _launch_ticket_audience(instance.software_id)
    issued_at = _ticket_epoch(ticket.issued_at)
    expires_at = _ticket_epoch(ticket.expires_at)
    return sign_launch_ticket(
        {
            "schema_version": LAUNCH_TICKET_SCHEMA_VERSION,
            "contract_version": LAUNCH_TICKET_CONTRACT_VERSION,
            "request_id": data["request_id"],
            "software_id": instance.software_id,
            "profile_id": instance.profile.profile_id,
            "client_id": data["client_id"],
            "target": data["target"],
            "arch": data["arch"],
            "channel": data["channel"],
            "authorization_id": str(instance.authorization_id),
            "authorization_revision": instance.authorization_revision,
            "decision": "issued",
            "server_time": server_time,
            "ticket": {
                "ticket_id": str(ticket.ticket_id),
                "software_id": instance.software_id,
                "profile_id": instance.profile.profile_id,
                "client_id": data["client_id"],
                "installation_id": device.installation_id or data["installation_id"],
                "issued_at": issued_at,
                "not_before": issued_at,
                "expires_at": expires_at,
                "audience": audience,
            },
            "integrity": {
                "algorithm": AUTHORIZATION_ALGORITHM,
                "key_id": _signing_key_id(),
                "canonicalization": AUTHORIZATION_CANONICALIZATION,
                "origin": LAUNCH_TICKET_ORIGIN,
                "audience": audience,
            },
        }
    )



def _launch_context(*, profile, card, instance, data, now):
    """Validate live authorization facts before *any* ticket allow/replay.

    Caller holds card/instance locks; device and binding follow the existing
    licensing lock order. Replays validate proof but never consume nonce twice.
    """
    if instance.profile_id != profile.pk or instance.software_id != profile.software_id:
        raise AuthorizationOperationError("PROFILE_MISMATCH", "授权实例与客户端身份不匹配。", http_status=403)
    policy = instance.policy_version
    current = PolicyVersion.objects.filter(profile=profile, status=PolicyStatus.ACTIVE).order_by("-effective_at", "-created_at").first()
    ticket_policy = current or policy
    if not ticket_policy.launch_ticket_enabled:
        raise AuthorizationOperationError("LAUNCH_TICKET_DISABLED", "当前策略未开启启动票据。", http_status=403)
    _, key_id, encoded_key = _verify_device_proof(data, proof_required=policy.device_proof_required)
    device = Device.objects.select_for_update().filter(
        software_id=profile.software_id, profile_id=profile.pk,
        installation_hash=_installation_hash(profile, data["installation_id"]),
    ).first()
    if device is None:
        raise AuthorizationOperationError("DEVICE_NOT_BOUND", "当前设备没有授权绑定。", http_status=403)
    if device.risk_state == DeviceRiskState.BLOCKED:
        raise AuthorizationOperationError("RISK_BLOCKED", "当前设备已被阻断。", http_status=403)
    device_key = _existing_device_key(device, key_id=key_id, encoded_public_key=encoded_key)
    binding = _binding_for_device(instance, device, active_only=True)
    _assert_device_key_matches_binding(binding, device_key)
    if _time_rollback_detected(instance, binding or _binding_for_device(instance, device), now):
        raise AuthorizationOperationError("TIME_ROLLBACK_DETECTED", "服务端可信时间发生回退，拒绝票据操作。", http_status=403)
    now = max(now, _trusted_time_high_water_mark(instance, binding))
    _sync_terminal_state(instance, card, now)
    for state, code, message in (
        (AuthorizationState.EXPIRED, "LICENSE_EXPIRED", "授权已过期。"),
        (AuthorizationState.REVOKED, "LICENSE_REVOKED", "授权已撤销。"),
        (AuthorizationState.BLOCKED, "LICENSE_BLOCKED", "授权已阻断。"),
    ):
        if instance.state == state:
            raise AuthorizationOperationError(code, message, http_status=403)
    if card.status != LicenseCardStatus.ACTIVATED or instance.state not in (AuthorizationState.ACTIVE, AuthorizationState.GRACE):
        raise AuthorizationOperationError("LICENSE_NOT_ACTIVE", "授权当前不可用。", http_status=403)
    if binding is None:
        raise AuthorizationOperationError("DEVICE_NOT_BOUND", "当前设备没有有效授权绑定。", http_status=403)
    if not device.installation_id:
        device.installation_id = data["installation_id"]
        device.save(update_fields=("installation_id",), _allow_mutation=True)
    # Caller holds the instance and binding locks. These writes commit only
    # with a successful ticket action, including the public API's rate gate.
    instance.last_server_time = now
    instance.save(update_fields=("last_server_time", "updated_at"), _allow_mutation=True)
    binding.last_server_time = now
    binding.save(update_fields=("last_server_time",), _allow_mutation=True)
    return device, ticket_policy, key_id, now

def issue_launch_ticket(
    *,
    request: Mapping[str, Any],
    request_id: str | None = None,
    idempotency_key: str | None = None,
    clock: Clock | None = None,
    ip_address: str | None = None,
) -> AuthorizationResult:
    """签发一次性启动票据。仅当授权处于 active/grace 且当前设备绑定有效时签发。

    复用 verify 的判定顺序：profile 归属 → 设备证明 → 设备绑定 → 风险 →
    时钟回退 → 终端状态。任何硬失败直接抛错，调用方不得用限流覆盖。
    """

    try:
        data, resolved_request_id, resolved_idempotency, request_hash = _validate_and_prepare(
            "launch-ticket", request, request_id=request_id, idempotency_key=idempotency_key
        )
        with transaction.atomic():
            profile = _validate_profile(data)
            card, instance = _lock_card_for_instance(data["authorization_id"])
            now = _server_now(clock)
            device, ticket_policy, request_key_id, now = _launch_context(
                profile=profile, card=card, instance=instance, data=data, now=now,
            )
            existing = _existing_request_result(
                action="launch-ticket", request_id=resolved_request_id,
                idempotency_key=resolved_idempotency, request_hash=request_hash,
                card=card, instance=instance, now=now, device_key_id=request_key_id,
            )
            if existing:
                original = existing.payload
                ticket = LaunchTicket.objects.select_for_update().filter(
                    ticket_id=original.get("ticket", {}).get("ticket_id"), instance=instance, device=device,
                ).first()
                if ticket is None or original.get("authorization_revision") != instance.authorization_revision:
                    raise AuthorizationOperationError("IDEMPOTENCY_CONFLICT", "原票据授权事实已改变，请重新验证授权。", http_status=409)
                if as_utc(ticket.expires_at) <= now:
                    raise AuthorizationOperationError("TICKET_EXPIRED", "原票据已过期，请发起新的签发请求。", http_status=410)
                if now < as_utc(ticket.issued_at):
                    raise AuthorizationOperationError("TICKET_NOT_YET_VALID", "原票据尚未生效。", http_status=403)
                if ticket.consumed_at is not None:
                    raise AuthorizationOperationError("TICKET_ALREADY_CONSUMED", "原票据已核销。", http_status=409)
                return existing
            _consume_nonce(profile=profile, device=device, data=data, now=now)
            ttl = ticket_policy.launch_ticket_ttl_seconds or LAUNCH_TICKET_DEFAULT_TTL_SECONDS
            ticket = LaunchTicket.objects.create(
                instance=instance,
                device=device,
                software_id=instance.software_id,
                audience=_launch_ticket_audience(instance.software_id),
                issued_at=now,
                expires_at=min(instance.expires_at, now + timedelta(seconds=int(ttl))),
                request_id=resolved_request_id,
            )
            server_time = _ticket_epoch(now)
            payload = _build_ticket_payload(
                instance=instance, device=device, ticket=ticket,
                data=data, now=now, server_time=server_time,
            )
            record_event(
                actor=None,
                action="authorization.launch_ticket",
                outcome=AuditOutcome.SUCCESS,
                request_id=_audit_request_id(resolved_request_id),
                ip_address=ip_address,
                object_type="LicenseInstance",
                object_public_id=instance.authorization_id,
                metadata={
                    "decision": "issued",
                    "ticket_id": str(ticket.ticket_id),
                    "authorization_revision": instance.authorization_revision,
                    "device_id": str(device.public_id),
                    "installation_id": data["installation_id"],
                    "software_id": instance.software_id,
                    "downstream_public_id": str(instance.current_downstream_public_id),
                },
            )
            return _store_request_result(action="launch-ticket", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=200)
    except AuthorizationOperationError as exc:
        _audit_failure(
            "launch-ticket",
            exc,
            request_id=request_id,
            ip_address=ip_address,
            request_metadata=_request_audit_metadata(request),
        )
        raise


def consume_launch_ticket(
    *,
    request: Mapping[str, Any],
    request_id: str | None = None,
    idempotency_key: str | None = None,
    clock: Clock | None = None,
    ip_address: str | None = None,
) -> AuthorizationResult:
    """核销启动票据。同一张票只能核销一次，过期票拒绝。

    核销证明与签发证明同形（Ed25519，domain 相同），但 action 固定为
    ``ticket-consume``：签发时的证明不能重放到核销，反之亦然。nonce 每次
    调用都必须换新（一次性），与现有 verify/activate 口径一致。
    """

    try:
        data, resolved_request_id, resolved_idempotency, request_hash = _validate_and_prepare(
            "ticket-consume", request, request_id=request_id, idempotency_key=idempotency_key
        )
        try:
            ticket_uuid = uuid.UUID(str(data.get("ticket_id") or "").strip())
        except (ValueError, AttributeError, TypeError):
            raise AuthorizationOperationError("INVALID_REQUEST", "ticket_id 格式不正确。") from None
        with transaction.atomic():
            profile = _validate_profile(data)
            card, instance = _lock_card_for_instance(data["authorization_id"])
            now = _server_now(clock)
            try:
                ticket = LaunchTicket.objects.select_for_update().get(ticket_id=ticket_uuid)
            except LaunchTicket.DoesNotExist:
                raise AuthorizationOperationError("TICKET_NOT_FOUND", "票据不存在。", http_status=404) from None
            if str(ticket.instance_id) != str(instance.authorization_id):
                raise AuthorizationOperationError("TICKET_NOT_FOUND", "票据不存在。", http_status=404)
            device, _, request_key_id, now = _launch_context(
                profile=profile, card=card, instance=instance, data=data, now=now,
            )
            if device.pk != ticket.device_id:
                raise AuthorizationOperationError("DEVICE_SCOPE_MISMATCH", "核销设备与签发设备不一致。", http_status=403)
            if as_utc(ticket.expires_at) <= now:
                raise AuthorizationOperationError("TICKET_EXPIRED", "票据已过期。", http_status=410)
            if now < as_utc(ticket.issued_at):
                raise AuthorizationOperationError("TICKET_NOT_YET_VALID", "票据尚未生效。", http_status=403)
            existing = _existing_request_result(
                action="ticket-consume",
                request_id=resolved_request_id,
                idempotency_key=resolved_idempotency,
                request_hash=request_hash,
                card=card,
                instance=instance,
                now=now,
                device_key_id=request_key_id,
            )
            if existing:
                return existing
            if ticket.consumed_at is not None:
                raise AuthorizationOperationError("TICKET_ALREADY_CONSUMED", "票据已经核销过。", http_status=409)
            _consume_nonce(profile=profile, device=device, data=data, now=now)
            ticket.consumed_at = now
            ticket.save(update_fields=("consumed_at",))
            payload = {
                "schema_version": LAUNCH_TICKET_SCHEMA_VERSION,
                "contract_version": LAUNCH_TICKET_CONTRACT_VERSION,
                "request_id": resolved_request_id,
                "software_id": instance.software_id,
                "profile_id": instance.profile.profile_id,
                "authorization_id": str(instance.authorization_id),
                "decision": "consumed",
                "server_time": _ticket_epoch(now),
                "ticket_id": str(ticket.ticket_id),
            }
            record_event(
                actor=None,
                action="authorization.launch_ticket_consume",
                outcome=AuditOutcome.SUCCESS,
                request_id=_audit_request_id(resolved_request_id),
                ip_address=ip_address,
                object_type="LaunchTicket",
                object_public_id=ticket.ticket_id,
                metadata={
                    "decision": "consumed",
                    "device_id": str(device.public_id),
                    "software_id": instance.software_id,
                },
            )
            return _store_request_result(action="ticket-consume", request_id=resolved_request_id, idempotency_key=resolved_idempotency, request_hash=request_hash, payload=payload, status_code=200)
    except AuthorizationOperationError as exc:
        _audit_failure(
            "ticket-consume",
            exc,
            request_id=request_id,
            ip_address=ip_address,
            request_metadata=_request_audit_metadata(request),
        )
        raise
