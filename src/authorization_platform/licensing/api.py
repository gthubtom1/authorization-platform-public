from __future__ import annotations

import ipaddress
import json

from django.conf import settings
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.accounts.rate_limit import blocked as blocked_rate

from .authorization import (
    AuthorizationOperationError,
    activate_license,
    consume_launch_ticket,
    deactivate_license,
    issue_launch_ticket,
    verify_license,
)

# Public authorization payloads are small typed envelopes.  Capping the body
# before json.loads keeps an unauthenticated caller from making the server
# parse an arbitrarily large document (DATA_UPLOAD_MAX_MEMORY_SIZE is 100MB).
MAX_PUBLIC_LICENSE_BODY_BYTES = 32 * 1024
MAX_PUBLIC_LICENSE_BODY_DEPTH = 8
# A 32KB body can hold thousands of opening brackets, which drives json.loads
# into its own recursion limit and raises RecursionError.  Scanning the raw
# bytes first rejects that before the parser runs.
MAX_PUBLIC_LICENSE_RAW_DEPTH = 16


def _payload_depth(value, depth: int = 0) -> int:
    if depth > MAX_PUBLIC_LICENSE_BODY_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((_payload_depth(item, depth + 1) for item in value.values()), default=depth)
    if isinstance(value, list):
        return max((_payload_depth(item, depth + 1) for item in value), default=depth)
    return depth


def _raw_nesting_depth(body: bytes) -> int:
    """Maximum bracket nesting in the raw body, ignoring string literals.

    Runs before ``json.loads`` so deeply nested input is rejected instead of
    tripping the parser's recursion limit and escaping as a 500.  String-aware
    so a legitimate field value containing brackets is not miscounted.
    """

    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for byte in body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # double quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # { or [
            depth += 1
            deepest = max(deepest, depth)
        elif byte in (0x7D, 0x5D):  # } or ]
            depth = max(0, depth - 1)
    return deepest


def _json_payload(request):
    declared = request.META.get("CONTENT_LENGTH")
    try:
        declared_length = int(declared) if declared else 0
    except (TypeError, ValueError):
        declared_length = 0
    if declared_length > MAX_PUBLIC_LICENSE_BODY_BYTES:
        raise AuthorizationOperationError("INVALID_REQUEST", "请求内容过大。")
    body = request.body
    if len(body) > MAX_PUBLIC_LICENSE_BODY_BYTES:
        raise AuthorizationOperationError("INVALID_REQUEST", "请求内容过大。")
    if _raw_nesting_depth(body) > MAX_PUBLIC_LICENSE_RAW_DEPTH:
        raise AuthorizationOperationError("INVALID_REQUEST", "请求嵌套层级过深。")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        # RecursionError is a parser-level failure on deeply nested input; it
        # must not escape as an unhandled 500.
        raise AuthorizationOperationError("INVALID_REQUEST", "请求必须是合法 JSON。")
    if not isinstance(value, dict):
        raise AuthorizationOperationError("INVALID_REQUEST", "请求必须是 JSON 对象。")
    if _payload_depth(value) > MAX_PUBLIC_LICENSE_BODY_DEPTH:
        raise AuthorizationOperationError("INVALID_REQUEST", "请求嵌套层级过深。")
    return value


def _request_id(request, payload: dict) -> str | None:
    header = request.headers.get("X-Request-Id") or request.headers.get("X-Request-ID")
    body = payload.get("request_id")
    if header and body and str(header).strip() != str(body).strip():
        raise AuthorizationOperationError("INVALID_REQUEST", "请求头与请求体的 request_id 不一致。")
    return str(header or body).strip() if (header or body) else None


def _idempotency_key(request, payload: dict) -> str | None:
    header = request.headers.get("Idempotency-Key")
    body = payload.get("idempotency_key")
    if header and body and str(header).strip() != str(body).strip():
        raise AuthorizationOperationError("INVALID_REQUEST", "请求头与请求体的幂等键不一致。")
    return str(header or body).strip() if (header or body) else None


def _client_ip(request) -> str | None:
    value = request.META.get("REMOTE_ADDR")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


# verify 硬失败必须原样返回，不能被 IP 限流盖成 RATE_LIMITED。
# RATE_LIMITED 只用于：这台绑定仍有效，只是问太勤。
_VERIFY_HARD_FAILURE_CODES = frozenset(
    {
        "DEVICE_NOT_BOUND",
        "LICENSE_REVOKED",
        "LICENSE_BLOCKED",
        "LICENSE_EXPIRED",
        "DEVICE_KEY_INVALID",
        "DEVICE_KEY_MISMATCH",
        "RISK_BLOCKED",
        "TIME_ROLLBACK_DETECTED",
        "LICENSE_NOT_ACTIVE",
        "AUTHORIZATION_NOT_FOUND",
    }
)
_VERIFY_STILL_BOUND_DECISIONS = frozenset({"active", "grace", "not_modified"})

# Rejected verify attempts are counted separately so operators can alert on
# abuse, but this counter NEVER changes the response.  The frozen client
# contract (docs/API-CONTRACT.md「验证」一节) requires that a hard failure —
# being kicked, unbound, revoked, blocked or expired — is returned as-is even
# when the caller has already tripped a rate limit; turning those into 429 would
# make the launcher treat a real kick as retryable and leave the customer's
# software open.  The contract-sanctioned ceiling for a still-bound client is
# PUBLIC_LICENSE_RATE_LIMIT below, and malformed input is rejected cheaply
# before any database work by the size/depth caps above.
FAILED_VERIFY_OBSERVATION_LIMIT = 600
FAILED_VERIFY_WINDOW_SECONDS = 300

# launch-ticket 沿用 verify 的“先判定再限流”：硬失败原样返回，429 只替换
# 本会成功的签发。观测计数同样只记数、不改返回。
_LAUNCH_TICKET_HARD_FAILURE_CODES = frozenset(
    {
        "DEVICE_NOT_BOUND",
        "LICENSE_REVOKED",
        "LICENSE_BLOCKED",
        "LICENSE_EXPIRED",
        "LICENSE_NOT_ACTIVE",
        "DEVICE_KEY_INVALID",
        "DEVICE_KEY_MISMATCH",
        "DEVICE_SCOPE_MISMATCH",
        "DEVICE_PROOF_REQUIRED",
        "DEVICE_PROOF_INVALID",
        "RISK_BLOCKED",
        "TIME_ROLLBACK_DETECTED",
        "LAUNCH_TICKET_DISABLED",
        "TICKET_NOT_FOUND",
        "TICKET_ALREADY_CONSUMED",
        "TICKET_EXPIRED",
        "AUTHORIZATION_NOT_FOUND",
        "PROFILE_MISMATCH",
    }
)
LAUNCH_TICKET_FAILED_OBSERVATION_LIMIT = 600
LAUNCH_TICKET_FAILED_WINDOW_SECONDS = 300


def _error_response(error: AuthorizationOperationError, *, request_id: str | None) -> JsonResponse:
    response = JsonResponse(
        {
            "error": {
                "code": error.code,
                "message": error.message,
                "request_id": request_id or "",
                "retryable": error.retryable,
            }
        },
        status=error.http_status,
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


def _rate_limited_response(*, request_id: str | None, window_seconds: int | None = None) -> JsonResponse:
    """Build the 429 body. `window_seconds` must be the window actually hit."""

    response = _error_response(
        AuthorizationOperationError("RATE_LIMITED", "授权请求过于频繁，请稍后重试。", retryable=True, http_status=429),
        request_id=request_id,
    )
    response["Retry-After"] = str(
        settings.AUTH_RATE_LIMIT_WINDOW_SECONDS if window_seconds is None else window_seconds
    )
    return response


def _consume_public_license_rate(action: str, client_ip: str) -> bool:
    return allow_rate(
        f"public-license-{action}",
        client_ip,
        limit=settings.PUBLIC_LICENSE_RATE_LIMIT,
    )


def _consume_failed_verify_rate(client_ip: str) -> bool:
    """Count one rejected verify attempt for observation/alerting only.

    The return value is deliberately ignored by the caller: the frozen client
    contract forbids a hard failure from being replaced by 429.
    """

    return allow_rate(
        "public-license-verify-failed",
        client_ip,
        limit=FAILED_VERIFY_OBSERVATION_LIMIT,
        timeout=FAILED_VERIFY_WINDOW_SECONDS,
    )


def _failed_verify_budget_exhausted(client_ip: str) -> bool:
    """Report whether the observation counter is saturated (never gates)."""

    return blocked_rate(
        "public-license-verify-failed",
        client_ip,
        limit=FAILED_VERIFY_OBSERVATION_LIMIT,
    )


def _verify_result_is_hard_failure(result) -> bool:
    if result.status_code >= 400:
        return True
    error = result.payload.get("error") if isinstance(result.payload, dict) else None
    if isinstance(error, dict) and error.get("code") in _VERIFY_HARD_FAILURE_CODES:
        return True
    return False


def _verify_result_is_still_bound(result) -> bool:
    if _verify_result_is_hard_failure(result):
        return False
    return result.payload.get("decision") in _VERIFY_STILL_BOUND_DECISIONS


@csrf_exempt
def public_license_action(request, action: str):
    client_ip = _client_ip(request) or "unknown"
    if action != "verify" and not _consume_public_license_rate(action, client_ip):
        return _rate_limited_response(
            request_id=request.headers.get("X-Request-Id") or request.headers.get("X-Request-ID") or "",
        )
    if request.method != "POST":
        request_id = request.headers.get("X-Request-Id") or request.headers.get("X-Request-ID") or ""
        response = _error_response(
            AuthorizationOperationError("METHOD_NOT_ALLOWED", "该授权接口只接受 POST。", http_status=405),
            request_id=request_id,
        )
        response["Allow"] = "POST"
        return response
    request_id = None
    try:
        payload = _json_payload(request)
        request_id = _request_id(request, payload)
        idempotency_key = _idempotency_key(request, payload)
        common = {
            "request": payload,
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "ip_address": _client_ip(request),
        }
        if action == "activate":
            result = activate_license(**common)
        elif action == "verify":
            result = verify_license(**common)
            rate_ok = _consume_public_license_rate(action, client_ip)
            if _verify_result_is_hard_failure(result) or not _verify_result_is_still_bound(result):
                # 挤机 / 解绑 / 撤销 / 阻断 / 到期：限流不得盖住硬结果。
                # 这类失败只记进观测计数（供告警），绝不改返回码——合同
                # 明确要求「已被挤掉或解绑后，即使该 IP 已经触发限流，
                # 仍必须返回 DEVICE_NOT_BOUND/撤销/阻断，不能 429」。
                _consume_failed_verify_rate(client_ip)
                response = JsonResponse(result.payload, status=result.status_code)
                response["Cache-Control"] = "no-store"
                response["Pragma"] = "no-cache"
                return response
            if not rate_ok:
                return _rate_limited_response(request_id=request_id)
        elif action == "deactivate":
            result = deactivate_license(**common)
        else:
            raise AuthorizationOperationError("INVALID_REQUEST", "授权动作不受支持。")
        response = JsonResponse(result.payload, status=result.status_code)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response
    except AuthorizationOperationError as exc:
        if action == "verify":
            _consume_public_license_rate(action, client_ip)
            _consume_failed_verify_rate(client_ip)
        return _error_response(exc, request_id=request_id)


def _consume_failed_ticket_rate(client_ip: str) -> bool:
    return allow_rate(
        "public-license-launch-ticket-failed",
        client_ip,
        limit=LAUNCH_TICKET_FAILED_OBSERVATION_LIMIT,
        timeout=LAUNCH_TICKET_FAILED_WINDOW_SECONDS,
    )


def _ticket_error_is_hard_failure(error: AuthorizationOperationError) -> bool:
    return error.code in _LAUNCH_TICKET_HARD_FAILURE_CODES


@csrf_exempt
def launch_ticket_api(request):
    """签发一次性启动票据。硬失败原样返回，429 只替换本会成功的签发。"""

    return _public_ticket_action(request, "launch-ticket")


@csrf_exempt
def launch_ticket_consume_api(request):
    """核销启动票据。同样先判定再限流。"""

    return _public_ticket_action(request, "ticket-consume")


def _public_ticket_action(request, action: str):
    client_ip = _client_ip(request) or "unknown"
    if request.method != "POST":
        request_id = request.headers.get("X-Request-Id") or request.headers.get("X-Request-ID") or ""
        response = _error_response(
            AuthorizationOperationError("METHOD_NOT_ALLOWED", "该授权接口只接受 POST。", http_status=405),
            request_id=request_id,
        )
        response["Allow"] = "POST"
        return response
    request_id = None
    rate_bucket = action
    try:
        payload = _json_payload(request)
        request_id = _request_id(request, payload)
        idempotency_key = _idempotency_key(request, payload)
        common = {
            "request": payload,
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "ip_address": _client_ip(request),
        }
        if action == "launch-ticket":
            service = issue_launch_ticket
            rate_bucket = "launch-ticket"
        elif action == "ticket-consume":
            service = consume_launch_ticket
            rate_bucket = "ticket-consume"
        else:
            raise AuthorizationOperationError("INVALID_REQUEST", "授权动作不受支持。")
        try:
            # 先判定再限流，但不能先落库再 429：外层原子块保证，被限流挡下的
            # 成功结果随整个事务回滚（票据行、nonce、幂等台账一个不留），客户端
            # 换新 nonce 重试即新票；硬失败走 except 原样返回，永远不被 429 覆盖。
            with transaction.atomic():
                result = service(**common)
                rate_ok = _consume_public_license_rate(rate_bucket, client_ip)
                if not rate_ok:
                    transaction.set_rollback(True)
                    result = None
        except AuthorizationOperationError as exc:
            # The service's failure audit was inside our transaction and has
            # rolled back. Record it once after the outermost ticket rollback.
            from .authorization import _audit_failure, _request_audit_metadata

            _audit_failure(action, exc, request_id=request_id, ip_address=_client_ip(request),
                           request_metadata=_request_audit_metadata(payload))
            _consume_public_license_rate(rate_bucket, client_ip)
            _consume_failed_ticket_rate(client_ip)
            return _error_response(exc, request_id=request_id)
        if result is None:
            return _rate_limited_response(request_id=request_id)
        response = JsonResponse(result.payload, status=result.status_code)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response
    except AuthorizationOperationError as exc:
        _consume_public_license_rate(rate_bucket, client_ip)
        _consume_failed_ticket_rate(client_ip)
        return _error_response(exc, request_id=request_id)


@csrf_exempt
def activate_api(request):
    return public_license_action(request, "activate")


@csrf_exempt
def verify_api(request):
    return public_license_action(request, "verify")


@csrf_exempt
def deactivate_api(request):
    return public_license_action(request, "deactivate")
