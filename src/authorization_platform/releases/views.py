from __future__ import annotations

import secrets

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpRequest
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from authorization_platform.accounts.decorators import platform_admin_required
from authorization_platform.core.legacy_html import close_legacy_html

from .models import Release, ReleaseStatus
from .services import ReleaseOperationError, create_release_draft, publish_release, withdraw_release


@platform_admin_required
@require_http_methods(["GET", "POST"])
@close_legacy_html
def manage_releases(request: HttpRequest):
    if request.method == "POST":
        action = request.POST.get("action", "upload")
        key = request.POST.get("idempotency_key") or secrets.token_urlsafe(18)
        try:
            if action == "upload":
                package = request.FILES.get("release_package")
                if package is None:
                    raise ReleaseOperationError("PACKAGE_REQUIRED", "请选择客户端 ZIP 构建包。")
                result = create_release_draft(actor=request.user, uploaded_file=package, software_id=request.POST.get("software_id", ""), profile_id=request.POST.get("profile_id") or None, channel=request.POST.get("channel", ""), notes=request.POST.get("notes", ""), idempotency_key=key, request_id=f"web-{key}", ip_address=request.META.get("REMOTE_ADDR"))
                messages.success(request, f"版本 {result['item']['version']} 已上传为草稿。")
            elif action == "publish":
                publish_release(actor=request.user, release_id=request.POST.get("release_id"), notes=request.POST.get("notes", ""), idempotency_key=key, request_id=f"web-{key}", ip_address=request.META.get("REMOTE_ADDR"))
                messages.success(request, "版本已发布。")
            elif action == "withdraw":
                withdraw_release(actor=request.user, release_id=request.POST.get("release_id"), reason=request.POST.get("reason", ""), idempotency_key=key, request_id=f"web-{key}", ip_address=request.META.get("REMOTE_ADDR"))
                messages.success(request, "版本已撤回。")
            else:
                messages.error(request, "不支持的版本操作。")
        except (ReleaseOperationError, ValueError) as exc:
            messages.error(request, getattr(exc, "message", "版本操作失败，请检查后重试。"))
        return redirect("releases:manage_page")

    queryset = Release.objects.select_related("software", "profile").all()
    software_id = request.GET.get("software_id", "").strip()
    status = request.GET.get("status", "").strip()
    if software_id:
        queryset = queryset.filter(software_id=software_id)
    if status in {choice for choice, _label in ReleaseStatus.choices}:
        queryset = queryset.filter(status=status)
    try:
        page_number = max(1, int(request.GET.get("page", "1")))
    except ValueError:
        page_number = 1
    page = Paginator(queryset.order_by("-created_at", "-release_id"), 20).get_page(page_number)
    return render(request, "releases/manage.html", {"page": page, "software_id": software_id, "status": status, "statuses": ReleaseStatus.choices})
