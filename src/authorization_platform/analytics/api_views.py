from __future__ import annotations

import csv as csv_module
import io

from django.http import HttpRequest, HttpResponse, JsonResponse

from authorization_platform.accounts.api_views import _api_methods, _error, _ip_address, _request_id, _role_for_request, _success
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .services import AnalyticsQueryError, build_summary


def _summary_payload(request: HttpRequest, *, expected_role: str):
    role, identity = _role_for_request(request)
    if role == "anonymous":
        return None, _error(request, "UNAUTHORIZED", "请先登录后查看统计。", status=401)
    if role != expected_role:
        return None, _error(request, "FORBIDDEN", "当前账号没有访问此统计范围的权限。", status=403)
    try:
        payload = build_summary(
            actor=request.user,
            role=role,
            software_id=request.GET.get("software_id", "all"),
            downstream_id=request.GET.get("downstream_id", "all"),
            window=request.GET.get("window", "7d"),
        )
    except AnalyticsQueryError as exc:
        return None, _error(request, exc.code, exc.message, status=exc.status)
    return payload, None


def _summary(request: HttpRequest, *, expected_role: str) -> JsonResponse:
    payload, error = _summary_payload(request, expected_role=expected_role)
    if error is not None:
        return error
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_api_methods("GET")
def api_manage_analytics_export(request: HttpRequest) -> HttpResponse:
    payload, error = _summary_payload(request, expected_role="platform_admin")
    if error is not None:
        return error
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(["指标", "数值", "范围说明"])
    revenue = payload.get("revenue") or {}
    window = payload.get("window") or "7d"
    timezone_name = payload.get("timezone") or "Asia/Shanghai"
    date_range = payload.get("range") or {}
    scope = f"{window} · {date_range.get('from', '')} ~ {date_range.get('to', '')} · {timezone_name}"
    for key, label in [
        ("today", "今日收入(额度)"),
        ("month", "本月收入(额度)"),
        ("total", "累计收入(额度)"),
    ]:
        writer.writerow([label, revenue.get(key, 0), scope])
    record_event(
        actor=request.user if getattr(request.user, "is_authenticated", False) else None,
        action="analytics.export",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        metadata={"window": window, "software_id": request.GET.get("software_id", "all"), "downstream_id": request.GET.get("downstream_id", "all")},
    )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="analytics-summary.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    return response


@_api_methods("GET")
def api_manage_analytics_summary(request: HttpRequest) -> JsonResponse:
    return _summary(request, expected_role="platform_admin")


@_api_methods("GET")
def api_downstream_analytics_summary(request: HttpRequest) -> JsonResponse:
    return _summary(request, expected_role="downstream")
