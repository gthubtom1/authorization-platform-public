from __future__ import annotations

from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse, JsonResponse

from authorization_platform.accounts.api_views import (
    _admin_required,
    _api_methods,
    _error,
    _request_id,
    _success,
)
from authorization_platform.licensing.api_views import _downstream_required
from authorization_platform.audit.queries import (
    AUDIT_EXPORT_LIMIT,
    AUDIT_MAX_PAGE_SIZE,
    AUDIT_PAGE_SIZE,
    audit_events_for_user,
    paginate_audit_events,
    present_event,
)
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.core.csv_utils import csv_safe_row

AUDIT_API_PAGE_SIZE = AUDIT_PAGE_SIZE
VALID_ACTOR_ROLES = {"platform_admin", "downstream", "anonymous", "unknown"}
VALID_OUTCOMES = {"success", "failure"}


def _query_page_size(request: HttpRequest) -> int:
    raw = (request.GET.get("page_size") or str(AUDIT_PAGE_SIZE)).strip()
    try:
        return min(max(int(raw), 1), AUDIT_MAX_PAGE_SIZE)
    except (TypeError, ValueError):
        return AUDIT_PAGE_SIZE


class AuditFilterError(ValueError):
    pass


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        from datetime import date

        return date.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise AuditFilterError("日期筛选格式不正确。") from exc


def _audit_filters(request: HttpRequest) -> dict:
    filters: dict = {}
    from_date = _parse_date(request.GET.get("from_date"))
    if from_date:
        filters["from_date"] = from_date
    to_date = _parse_date(request.GET.get("to_date"))
    if to_date:
        filters["to_date"] = to_date
    if from_date and to_date and from_date > to_date:
        raise AuditFilterError("起始日期不能晚于结束日期。")
    action = (request.GET.get("action") or "").strip()
    if action:
        if len(action) > 64:
            raise AuditFilterError("动作筛选不能超过 64 个字符。")
        filters["action"] = action
    outcome = (request.GET.get("outcome") or "").strip()
    if outcome:
        if outcome not in VALID_OUTCOMES:
            raise AuditFilterError("结果筛选不正确。")
        filters["outcome"] = outcome
    actor_role = (request.GET.get("actor_role") or "").strip()
    if actor_role:
        if actor_role not in VALID_ACTOR_ROLES:
            raise AuditFilterError("操作者角色筛选不正确。")
        filters["actor_role"] = actor_role
    actor = (request.GET.get("actor") or "").strip()
    if actor:
        if actor != "me" or not request.user.is_authenticated:
            raise AuditFilterError("操作者筛选不正确。")
        filters["actor_id"] = request.user.pk
    downstream_id = (request.GET.get("downstream_public_id") or "").strip()
    if downstream_id:
        import uuid as uuid_module

        try:
            filters["downstream_public_id"] = uuid_module.UUID(downstream_id)
        except (ValueError, TypeError) as exc:
            raise AuditFilterError("下游筛选标识不正确。") from exc
    software_id = (request.GET.get("software_id") or "").strip()
    if software_id:
        if len(software_id) > 64:
            raise AuditFilterError("软件筛选不能超过 64 个字符。")
        filters["software_id"] = software_id
    query = (request.GET.get("q") or "").strip()
    if query:
        if len(query) > 128:
            raise AuditFilterError("搜索内容不能超过 128 个字符。")
        filters["q"] = query
    return filters


def _row_payload(row, *, downstream: bool = False) -> dict:
    return {
        "occurred_at": row.occurred_at.isoformat(),
        "actor_label": row.actor_label,
        "actor_role": row.actor_role_label,
        "action": row.action,
        "outcome": row.outcome_label,
        "object_type": row.object_type,
        "object_public_id": row.object_public_id,
        "object_label": row.object_label,
        "object_summary": row.object_summary,
        "request_id": row.request_id,
        "ip_address": row.ip_address,
        "reason_code": row.reason_code,
        "metadata": [
            {"label": item.label, "value": item.value} for item in row.metadata_items
        ],
    }


def _audit_filter_error(request: HttpRequest, error: AuditFilterError) -> JsonResponse:
    record_event(
        actor=request.user if request.user.is_authenticated else None,
        action="audit.export" if request.path.endswith("/export/") else "audit.query",
        outcome=AuditOutcome.FAILURE,
        request_id=_request_id(request),
        ip_address=request.META.get("REMOTE_ADDR") or None,
        reason_code="INVALID_FILTER",
        metadata={"path": request.path[:128]},
    )
    return _error(request, "INVALID_FILTER", str(error), status=400)


def _render_page(request: HttpRequest, events, *, downstream: bool = False) -> JsonResponse:
    page_number = (request.GET.get("page") or "1").strip()
    page_size = _query_page_size(request)
    page_obj = paginate_audit_events(events, page_number, page_size)
    public_id = request.user.downstream_profile.public_id if downstream else None
    rows = [
        _row_payload(present_event(event, downstream=downstream, downstream_public_id=public_id), downstream=downstream)
        for event in page_obj.object_list
    ]
    return _success(
        {
            "items": rows,
            "count": page_obj.paginator.count,
            "page": page_obj.number,
            "page_size": page_obj.paginator.per_page,
            "total_pages": page_obj.paginator.num_pages,
            "has_previous": page_obj.has_previous(),
            "has_next": page_obj.has_next(),
        }
    )


@_api_methods("GET")
@_admin_required
def api_manage_audit(request: HttpRequest, identity) -> JsonResponse:
    try:
        filters = _audit_filters(request)
    except AuditFilterError as exc:
        return _audit_filter_error(request, exc)
    events = audit_events_for_user(user=request.user, filters=filters)
    return _render_page(request, events)


@_api_methods("GET")
@_admin_required
def api_manage_audit_export(request: HttpRequest, identity):
    try:
        filters = _audit_filters(request)
    except AuditFilterError as exc:
        return _audit_filter_error(request, exc)
    events = audit_events_for_user(user=request.user, filters=filters)
    return _audit_csv_response(request, events, downstream=False)


def _audit_csv_response(request: HttpRequest, events, *, downstream: bool):
    import csv as csv_module
    import io

    if isinstance(events, QuerySet):
        total = events.count()
        event_list = list(events[:AUDIT_EXPORT_LIMIT])
    else:
        event_list = list(events)
        total = len(event_list)
        event_list = event_list[:AUDIT_EXPORT_LIMIT]
    truncated = total > AUDIT_EXPORT_LIMIT
    public_id = request.user.downstream_profile.public_id if downstream else None
    rows = [present_event(event, downstream=downstream, downstream_public_id=public_id) for event in event_list]
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(csv_safe_row(["时间", "操作者", "角色", "动作", "结果", "对象", "对象类型", "对象 ID", "对象摘要", "请求摘要", "IP", "原因", "字段摘要"]))
    for row in rows:
        writer.writerow(
            csv_safe_row([
                row.occurred_at.isoformat(),
                row.actor_label,
                row.actor_role_label,
                row.action,
                row.outcome_label,
                row.object_label,
                row.object_type,
                row.object_public_id,
                row.object_summary,
                row.request_id,
                row.ip_address,
                row.reason_code,
                "; ".join(f"{item.label}={item.value}" for item in row.metadata_items),
            ])
        )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="audit-events.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    if truncated:
        response["X-Export-Truncated"] = "1"
        response["X-Export-Total"] = str(total)
    record_event(
        actor=request.user if request.user.is_authenticated else None,
        action="audit.export",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=request.META.get("REMOTE_ADDR") or None,
        metadata={"row_count": len(rows), "total": total, "truncated": truncated, "downstream": downstream},
    )
    return response


@_api_methods("GET")
@_downstream_required
def api_downstream_audit(request: HttpRequest, identity) -> JsonResponse:
    scope = (request.GET.get("scope") or "all").strip()
    try:
        filters = _audit_filters(request)
    except AuditFilterError as exc:
        return _audit_filter_error(request, exc)
    events = audit_events_for_user(user=request.user, filters=filters)
    if scope == "mine":
        events = events.filter(actor_id=request.user.pk)
    elif scope == "client":
        events = events.filter(actor_id__isnull=True)
    elif scope != "all":
        return _audit_filter_error(request, AuditFilterError("scope 必须是 all/mine/client。"))
    return _render_page(request, events, downstream=True)


@_api_methods("GET")
@_downstream_required
def api_downstream_audit_export(request: HttpRequest, identity) -> HttpResponse:
    scope = (request.GET.get("scope") or "all").strip()
    try:
        filters = _audit_filters(request)
    except AuditFilterError as exc:
        return _audit_filter_error(request, exc)
    events = audit_events_for_user(user=request.user, filters=filters)
    if scope == "mine":
        events = events.filter(actor_id=request.user.pk)
    elif scope == "client":
        events = events.filter(actor_id__isnull=True)
    elif scope != "all":
        return _audit_filter_error(request, AuditFilterError("scope 必须是 all/mine/client。"))
    return _audit_csv_response(request, events, downstream=True)
