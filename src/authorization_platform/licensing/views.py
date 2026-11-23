from __future__ import annotations

import csv
import hashlib
import io
import uuid

from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseGone
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from authorization_platform.accounts.decorators import active_downstream_required, platform_admin_required
from authorization_platform.core.legacy_html import close_legacy_html, legacy_html_closed_response
from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.accounts.services import get_downstream_profile
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.configuration import current_config_version, effective_configuration_for_authorization

from .admin import (
    list_authorizations_for_admin,
    list_devices_for_admin,
    list_risk_signals_for_admin,
    redact_request_id,
)
from .forms import AuthorizationAdminActionForm, AuthorizationConfigurationOverrideForm, LicenseBatchConfirmForm, LicenseBatchPreviewForm
from .models import LicenseInstance
from .services import (
    LicenseOperationError,
    export_license_batch,
    generate_license_batch,
    issued_cards_for_batch,
    list_license_batches,
    preview_license_batch,
    reclaim_license_card,
    reveal_license_card,
    set_authorization_configuration_override,
)
from authorization_platform.credits.services import get_quota_account


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied.encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _add_error(form, exc: LicenseOperationError) -> None:
    form.add_error(None, exc.message)


@never_cache
@require_http_methods(["GET", "POST"])
@active_downstream_required
@close_legacy_html
def batch_list(request: HttpRequest) -> HttpResponse:
    if settings.DISABLE_LEGACY_BATCH_VIEWS:
        return HttpResponseGone("旧批次入口已停用，请使用当前单卡管理页面。")
    preview = None
    confirm_form = None
    action = request.POST.get("action", "") if request.method == "POST" else ""
    preview_form = LicenseBatchPreviewForm(request.POST if action == "preview" else None, user=request.user)

    if request.method == "POST" and action == "preview" and preview_form.is_valid():
        cleaned = preview_form.cleaned_data
        try:
            preview = preview_license_batch(
                actor=request.user,
                software_id=cleaned["software"].software_id,
                plan_id=cleaned["plan"].pk,
                quantity=cleaned["quantity"],
            )
        except LicenseOperationError as exc:
            _add_error(preview_form, exc)
        else:
            confirm_form = LicenseBatchConfirmForm(
                initial={
                    "software_id": preview.software_id,
                    "plan_snapshot_id": preview.snapshot_id,
                    "quantity": preview.quantity,
                    "idempotency_key": uuid.uuid4().hex,
                    "preview_token": preview.preview_token,
                }
            )

    if request.method == "POST" and action == "confirm":
        confirm_form = LicenseBatchConfirmForm(request.POST)
        if confirm_form.is_valid():
            try:
                result = generate_license_batch(
                    actor=request.user,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                    **confirm_form.cleaned_data,
                )
            except LicenseOperationError as exc:
                _add_error(confirm_form, exc)
            else:
                request.session["new_license_card_batch"] = str(result.batch.batch_id)
                if result.repeated:
                    messages.info(request, "这次确认已处理过，系统返回原批次，没有重复扣除额度。")
                else:
                    messages.success(request, f"已生成 {len(result.cards)} 张授权卡密，额度扣除与批次已同时完成。")
                return redirect("licensing:batch_list")

    new_cards = None
    if request.method == "GET":
        batch_id = request.session.pop("new_license_card_batch", None)
        if batch_id:
            try:
                new_cards = issued_cards_for_batch(actor=request.user, batch_public_id=batch_id)
            except LicenseOperationError as exc:
                messages.error(request, exc.message)

    return render(
        request,
        "licensing/batch_list.html",
        {
            "profile": get_downstream_profile(request.user),
            "account": get_quota_account(get_downstream_profile(request.user)),
            "preview_form": preview_form,
            "confirm_form": confirm_form,
            "preview": preview,
            "new_cards": new_cards,
            "batches": list(list_license_batches(actor=request.user)),
        },
    )


@never_cache
@require_POST
@active_downstream_required
@close_legacy_html
def card_reveal(request: HttpRequest, public_id) -> HttpResponse:
    profile = get_downstream_profile(request.user)
    rate_identity = f"{_ip_address(request) or 'unknown'}:{profile.public_id}"
    if not allow_rate("license-card-reveal", rate_identity, limit=settings.LICENSE_CARD_REVEAL_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="license_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "license-card-reveal"},
        )
        messages.error(request, "查看授权卡密过于频繁，请稍后再试。")
        return redirect("licensing:batch_list")
    try:
        card, plaintext = reveal_license_card(
            actor=request.user,
            card_public_id=public_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except LicenseOperationError as exc:
        messages.error(request, exc.message)
        return redirect("licensing:batch_list")
    response = render(request, "licensing/card_reveal.html", {"card": card, "plaintext": plaintext})
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    return response


@never_cache
@require_POST
@active_downstream_required
@close_legacy_html
def card_reclaim(request: HttpRequest, public_id) -> HttpResponse:
    profile = get_downstream_profile(request.user)
    rate_identity = f"{_ip_address(request) or 'unknown'}:{profile.public_id}"
    if not allow_rate("license-card-reclaim", rate_identity, limit=settings.LICENSE_CARD_RECLAIM_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="license_card.reclaim",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "license-card-reclaim"},
        )
        messages.error(request, "回收授权卡密过于频繁，请稍后再试。")
        return redirect("licensing:batch_list")
    try:
        result = reclaim_license_card(
            actor=request.user,
            card_public_id=public_id,
            idempotency_key=request.POST.get("idempotency_key"),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except LicenseOperationError as exc:
        messages.error(request, exc.message)
    else:
        if result.repeated:
            messages.info(request, "这张授权卡密已经回收过，本次没有重复返还额度。")
        else:
            messages.success(request, f"授权卡密已回收，原始成本 {result.card.quota_cost} 已返还额度账户。")
    return redirect("licensing:batch_list")


@never_cache
@require_POST
@active_downstream_required
@close_legacy_html
def batch_export(request: HttpRequest, batch_id) -> HttpResponse:
    if settings.DISABLE_LEGACY_BATCH_VIEWS:
        return HttpResponseGone("旧批次导出已停用，请使用当前单卡导出接口。")
    profile = get_downstream_profile(request.user)
    rate_identity = f"{_ip_address(request) or 'unknown'}:{profile.public_id}"
    if not allow_rate("license-card-export", rate_identity, limit=settings.LICENSE_CARD_EXPORT_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="license_batch.export",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "license-card-export"},
        )
        messages.error(request, "导出授权卡密摘要过于频繁，请稍后再试。")
        return redirect("licensing:batch_list")
    try:
        batch, cards = export_license_batch(
            actor=request.user,
            batch_public_id=batch_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except LicenseOperationError as exc:
        messages.error(request, exc.message)
        return redirect("licensing:batch_list")

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("batch_id", "card_id", "software_id", "profile_id", "plan_snapshot_id", "quota_cost", "status", "issued_at"))
    for card in cards:
        writer.writerow(
            (
                str(batch.batch_id),
                str(card.public_id),
                card.software_id,
                card.profile.profile_id,
                str(card.plan_snapshot_id),
                card.quota_cost,
                card.status,
                card.issued_at.isoformat(),
            )
        )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="license-batch-{batch.batch_id}.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    return response


@never_cache
@platform_admin_required
@close_legacy_html
def authorization_admin_dashboard(request: HttpRequest) -> HttpResponse:
    risk_signals = [
        {
            "occurred_at": signal.occurred_at,
            "action": signal.action,
            "reason_code": signal.reason_code,
            "request_id": redact_request_id(signal.request_id),
        }
        for signal in list_risk_signals_for_admin(actor=request.user)
    ]
    return render(
        request,
        "licensing/authorization_admin.html",
        {
            "authorizations": list(list_authorizations_for_admin(actor=request.user)),
            "devices": list(list_devices_for_admin(actor=request.user)),
            "risk_signals": risk_signals,
            "action_form": AuthorizationAdminActionForm(),
        },
    )


@never_cache
@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def admin_authorization_configuration(request: HttpRequest, authorization_id) -> HttpResponse:
    instance = get_object_or_404(
        LicenseInstance.objects.select_related("software", "profile", "license_card"),
        authorization_id=authorization_id,
    )
    initial = instance.configuration_override if request.method == "GET" and instance.configuration_override else None
    form = AuthorizationConfigurationOverrideForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        try:
            instance = set_authorization_configuration_override(
                actor=request.user,
                authorization_id=authorization_id,
                values=form.cleaned_configuration,
                clear=form.cleaned_data["clear_override"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except LicenseOperationError as exc:
            _add_error(form, exc)
        else:
            messages.success(request, "客户授权配置已更新，授权 A 下次验证时会按新版本刷新。")
            return redirect("licensing:authorization_admin")
    effective = effective_configuration_for_authorization(instance)
    return render(
        request,
        "catalog/configuration_form.html",
        {
            "heading": "配置客户授权覆盖",
            "eyebrow": "AUTHORIZATION CONFIGURATION",
            "intro": f"授权 {instance.authorization_id} · {instance.software.name} / {instance.profile.profile_id}。填写内容会替换该授权的支持信息和公告；清除后回退到下游/Profile默认。当前版本 {current_config_version(instance)}。",
            "form": form,
            "cancel_href": reverse("licensing:authorization_admin"),
            "effective_configuration": effective,
        },
    )


@require_POST
@platform_admin_required
@close_legacy_html
def admin_revoke_authorization(request: HttpRequest, authorization_id) -> HttpResponse:
    return legacy_html_closed_response()


@require_POST
@platform_admin_required
@close_legacy_html
def admin_block_device(request: HttpRequest, device_id) -> HttpResponse:
    return legacy_html_closed_response()


@require_POST
@platform_admin_required
@close_legacy_html
def admin_unblock_device(request: HttpRequest, device_id) -> HttpResponse:
    return legacy_html_closed_response()
