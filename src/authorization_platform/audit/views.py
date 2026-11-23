from __future__ import annotations

import csv
import hashlib
import io

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from authorization_platform.accounts.decorators import active_downstream_required, platform_admin_required
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .forms import AuditFilterForm
from .queries import AUDIT_EXPORT_LIMIT, audit_events_for_user, paginate_audit_events, present_event


def _query_context(request: HttpRequest):
    form = AuditFilterForm(request.GET or None)
    filters = form.cleaned_data if form.is_valid() else None
    events = audit_events_for_user(user=request.user, filters=filters or {}) if filters is not None else []
    return form, events


@never_cache
@require_GET
@platform_admin_required
def admin_audit_log(request: HttpRequest) -> HttpResponse:
    form, events = _query_context(request)
    page_obj = paginate_audit_events(events, request.GET.get("page"))
    rows = [present_event(event) for event in page_obj.object_list]
    return render(
        request,
        "audit/events.html",
        {
            "form": form,
            "page_obj": page_obj,
            "rows": rows,
            "scope_label": "全部平台审计",
            "export_url_name": "audit:admin_export",
            "is_admin": True,
        },
    )


@never_cache
@require_GET
@active_downstream_required
def downstream_audit_log(request: HttpRequest) -> HttpResponse:
    form, events = _query_context(request)
    page_obj = paginate_audit_events(events, request.GET.get("page"))
    rows = [present_event(event, downstream=True, downstream_public_id=request.user.downstream_profile.public_id) for event in page_obj.object_list]
    return render(
        request,
        "audit/events.html",
        {
            "form": form,
            "page_obj": page_obj,
            "rows": rows,
            "scope_label": "当前下游范围",
            "is_admin": False,
        },
    )


@never_cache
@require_GET
@platform_admin_required
def admin_audit_export(request: HttpRequest) -> HttpResponse:
    form, events = _query_context(request)
    if not form.is_valid():
        record_event(
            actor=request.user,
            action="audit.export",
            outcome=AuditOutcome.FAILURE,
            request_id="audit-export-invalid-filter",
            ip_address=request.META.get("REMOTE_ADDR") or None,
            reason_code="INVALID_FILTER",
        )
        return HttpResponse("筛选条件无效。", status=400, content_type="text/plain; charset=utf-8")
    rows = [present_event(event) for event in events[:AUDIT_EXPORT_LIMIT]]
    record_event(
        actor=request.user,
        action="audit.export",
        outcome=AuditOutcome.SUCCESS,
        request_id="audit-export-" + hashlib.sha256(request.get_full_path().encode("utf-8")).hexdigest()[:16],
        ip_address=request.META.get("REMOTE_ADDR") or None,
        metadata={"row_count": len(rows), "limited": len(rows) >= AUDIT_EXPORT_LIMIT},
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["时间", "操作者", "角色", "动作", "结果", "对象", "对象类型", "对象 ID", "对象摘要", "请求摘要", "IP", "原因", "字段摘要"])
    for row in rows:
        writer.writerow(
            [_csv_safe(value) for value in [
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
            ]]
        )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="audit-events.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    return response


def _csv_safe(value) -> str:
    text = str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
