from __future__ import annotations

import json

from django.http import HttpRequest, JsonResponse

from authorization_platform.accounts.api_views import _admin_required, _api_methods, _error, _read_json, _request_id, _success

from .services import StorageCleanupError, execute_cleanup, inspect_cleanup


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


@_admin_required
@_api_methods("GET", "POST")
def api_manage_storage_cleanup(request: HttpRequest, _identity) -> JsonResponse:
    if request.method == "GET":
        return _success(inspect_cleanup())
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    if payload is None:
        payload = {}
    try:
        result = execute_cleanup(
            actor=request.user,
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_body=request.body or json.dumps(payload, sort_keys=True).encode("utf-8"),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except StorageCleanupError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    result["request_id"] = _request_id(request)
    return _success(result)
