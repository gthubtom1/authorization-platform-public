from __future__ import annotations

import hashlib
import uuid

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from authorization_platform.accounts.decorators import active_downstream_required, platform_admin_required
from authorization_platform.core.legacy_html import close_legacy_html
from authorization_platform.accounts.services import get_downstream_profile
from authorization_platform.core.time import normalize_duration

from .configuration import ConfigurationOperationError, configuration_from_object, update_downstream_configuration, update_profile_configuration
from .forms import CapabilityForm, DownstreamAccessForm, DownstreamConfigurationForm, PlanForm, PolicyVersionForm, ProfileConfigurationForm, ProfileForm, SoftwareForm, SoftwareStatusForm
from .models import CapabilityDefinition, DownstreamSoftware, Plan, PolicyVersion, Software, SoftwareProfile
from .services import (
    CatalogOperationError,
    accessible_plans_for,
    create_capability_definition,
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    list_accessible_software,
    list_software_accesses,
    set_downstream_software_access,
    update_software_status,
)


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied[:128].encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _catalog_error(form, exc: CatalogOperationError) -> None:
    form.add_error(None, exc.message)


@platform_admin_required
def software_list(request: HttpRequest) -> HttpResponse:
    softwares = Software.objects.prefetch_related("profiles", "plans").all()
    return render(request, "catalog/software_list.html", {"softwares": softwares})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def software_create(request: HttpRequest) -> HttpResponse:
    form = SoftwareForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            software = create_software(
                actor=request.user,
                software_id=form.cleaned_data["software_id"],
                name=form.cleaned_data["name"],
                description=form.cleaned_data["description"],
                status=form.cleaned_data["status"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except CatalogOperationError as exc:
            _catalog_error(form, exc)
        else:
            messages.success(request, f"软件 {software.name} 已登记。下一步创建 Profile。")
            return redirect("catalog:software_detail", software_id=software.software_id)
    return render(request, "catalog/form.html", {"form": form, "eyebrow": "SOFTWARE REGISTRY", "heading": "登记软件", "intro": "先创建隔离根，再为它登记自己的 Profile、策略、能力和套餐。", "submit_label": "保存软件", "cancel_href": reverse("catalog:software_list")})


@platform_admin_required
def software_detail(request: HttpRequest, software_id: str) -> HttpResponse:
    software = get_object_or_404(Software, pk=software_id)
    profiles = software.profiles.prefetch_related("policy_versions", "capabilities").all()
    plans = software.plans.select_related("profile").prefetch_related("snapshots").all()
    accesses = list_software_accesses(software)
    status_form = SoftwareStatusForm(initial={"status": software.status})
    return render(
        request,
        "catalog/software_detail.html",
        {"software": software, "profiles": profiles, "plans": plans, "accesses": accesses, "access_form": DownstreamAccessForm(software=software), "status_form": status_form},
    )


@require_http_methods(["POST"])
@platform_admin_required
@close_legacy_html
def software_status_update(request: HttpRequest, software_id: str) -> HttpResponse:
    software = get_object_or_404(Software, pk=software_id)
    form = SoftwareStatusForm(request.POST)
    if form.is_valid():
        try:
            update_software_status(
                actor=request.user,
                software_id=software.software_id,
                status=form.cleaned_data["status"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except CatalogOperationError as exc:
            messages.error(request, exc.message)
        else:
            messages.success(request, "软件状态已更新。归档软件不会自动恢复下游经营范围。")
    else:
        messages.error(request, "软件状态不正确。")
    return redirect("catalog:software_detail", software_id=software.software_id)


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def profile_create(request: HttpRequest, software_id: str) -> HttpResponse:
    software = get_object_or_404(Software, pk=software_id)
    form = ProfileForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            profile = create_profile(
                actor=request.user,
                software_id=software.software_id,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                **form.cleaned_data,
            )
        except CatalogOperationError as exc:
            _catalog_error(form, exc)
        else:
            messages.success(request, f"Profile {profile.profile_id} 已创建。接下来可以创建策略和能力。")
            return redirect("catalog:software_detail", software_id=software.software_id)
    return render(request, "catalog/form.html", {"form": form, "eyebrow": "PROFILE REGISTRY", "heading": f"为 {software.name} 创建 Profile", "intro": "Profile 是软件、客户端、平台和授权合同的隔离边界。", "submit_label": "保存 Profile", "cancel_href": reverse("catalog:software_detail", kwargs={"software_id": software.software_id})})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def policy_create(request: HttpRequest, software_id: str, profile_id: str) -> HttpResponse:
    profile = get_object_or_404(SoftwareProfile, software_id=software_id, profile_id=profile_id)
    form = PolicyVersionForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            policy = create_policy_version(
                actor=request.user,
                software_id=software_id,
                profile_id=profile_id,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                **form.cleaned_data,
            )
        except CatalogOperationError as exc:
            _catalog_error(form, exc)
        else:
            messages.success(request, f"策略 {policy.version} 已创建。")
            return redirect("catalog:software_detail", software_id=software_id)
    return render(request, "catalog/form.html", {"form": form, "eyebrow": "POLICY VERSION", "heading": f"为 {profile} 创建策略", "intro": "策略版本创建后作为不可变授权规则，旧快照不会被静默改写。", "submit_label": "保存策略", "cancel_href": reverse("catalog:software_detail", kwargs={"software_id": software_id})})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def capability_create(request: HttpRequest, software_id: str, profile_id: str) -> HttpResponse:
    profile = get_object_or_404(SoftwareProfile, software_id=software_id, profile_id=profile_id)
    form = CapabilityForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            capability = create_capability_definition(
                actor=request.user,
                software_id=software_id,
                profile_id=profile_id,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                **form.cleaned_data,
            )
        except CatalogOperationError as exc:
            _catalog_error(form, exc)
        else:
            messages.success(request, f"能力 {capability.capability_key} 已登记。")
            return redirect("catalog:software_detail", software_id=software_id)
    return render(request, "catalog/form.html", {"form": form, "eyebrow": "CAPABILITY DEFINITION", "heading": f"为 {profile} 登记能力", "intro": "只允许声明式、可校验的类型化能力，不存放任意脚本。", "submit_label": "保存能力", "cancel_href": reverse("catalog:software_detail", kwargs={"software_id": software_id})})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def plan_create(request: HttpRequest, software_id: str) -> HttpResponse:
    software = get_object_or_404(Software, pk=software_id)
    form = PlanForm(request.POST or None, software=software)
    if request.method == "POST" and form.is_valid():
        cleaned = form.cleaned_data
        try:
            duration_seconds = normalize_duration(cleaned["duration_value"], cleaned["duration_unit"])
            plan, snapshot = create_plan(
                actor=request.user,
                software_id=software.software_id,
                profile_id=cleaned["profile"].profile_id,
                policy_version=cleaned["policy_version"].version,
                name=cleaned["name"],
                duration_seconds=duration_seconds,
                quota_cost=cleaned["quota_cost"],
                test_only=cleaned["test_only"],
                capability_values=cleaned["capability_values"],
                status=cleaned["status"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except (CatalogOperationError, ValueError) as exc:
            if isinstance(exc, CatalogOperationError):
                _catalog_error(form, exc)
            else:
                form.add_error("duration_value", "有效期单位或数值不正确。")
        else:
            messages.success(request, f"套餐 {plan.name} 已创建，同时生成不可变快照 v{snapshot.snapshot_version}。")
            return redirect("catalog:software_detail", software_id=software.software_id)
    return render(request, "catalog/form.html", {"form": form, "eyebrow": "PLAN REGISTRY", "heading": f"为 {software.name} 创建套餐", "intro": "套餐保存为易懂的单位，服务端统一换算为整数秒，并立即留下不可变快照。", "submit_label": "保存套餐", "cancel_href": reverse("catalog:software_detail", kwargs={"software_id": software.software_id})})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def software_access(request: HttpRequest, software_id: str) -> HttpResponse:
    software = get_object_or_404(Software, pk=software_id)
    form = DownstreamAccessForm(request.POST or None, software=software)
    if request.method == "POST" and form.is_valid():
        cleaned = form.cleaned_data
        try:
            set_downstream_software_access(
                actor=request.user,
                downstream_public_id=cleaned["downstream"].public_id,
                software_id=software.software_id,
                enabled=cleaned["enabled"],
                all_plans_allowed=cleaned["all_plans_allowed"],
                allowed_plan_ids=[plan.pk for plan in cleaned["allowed_plans"]],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except CatalogOperationError as exc:
            _catalog_error(form, exc)
        else:
            messages.success(request, "下游经营范围已更新。")
            return redirect("catalog:software_detail", software_id=software.software_id)
    return render(request, "catalog/software_access.html", {"software": software, "form": form, "accesses": list_software_accesses(software)})


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def profile_configuration(request: HttpRequest, software_id: str, profile_id: str) -> HttpResponse:
    profile = get_object_or_404(SoftwareProfile, software_id=software_id, profile_id=profile_id)
    form = ProfileConfigurationForm(request.POST or None, initial=configuration_from_object(profile) if request.method == "GET" else None)
    if request.method == "POST" and form.is_valid():
        try:
            profile = update_profile_configuration(
                actor=request.user,
                profile=profile,
                values=form.cleaned_configuration,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except ConfigurationOperationError as exc:
            form.add_error(None, exc.message)
        else:
            messages.success(request, f"Profile {profile.profile_id} 的默认配置已更新。")
            return redirect("catalog:software_detail", software_id=software_id)
    return render(
        request,
        "catalog/configuration_form.html",
        {
            "heading": f"配置 {profile} 的默认信息",
            "eyebrow": "PROFILE CONFIGURATION",
            "intro": "这是软件 Profile 默认值；授权实例和下游覆盖会按真实归属继续解析。",
            "form": form,
            "cancel_href": reverse("catalog:software_detail", kwargs={"software_id": software_id}),
        },
    )


@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def admin_downstream_configuration(request: HttpRequest, software_id: str, downstream_public_id) -> HttpResponse:
    software = get_object_or_404(Software, pk=software_id)
    access = get_object_or_404(
        DownstreamSoftware.objects.select_related("downstream__user"),
        software=software,
        downstream__public_id=downstream_public_id,
    )
    form = DownstreamConfigurationForm(request.POST or None, initial=configuration_from_object(access) if request.method == "GET" else None)
    if request.method == "POST" and form.is_valid():
        try:
            update_downstream_configuration(
                actor=request.user,
                downstream_public_id=downstream_public_id,
                software_id=software.software_id,
                values=form.cleaned_configuration,
                clear=form.cleaned_data["clear_configuration"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except ConfigurationOperationError as exc:
            form.add_error(None, exc.message)
        else:
            messages.success(request, "下游-软件默认配置已更新。")
            return redirect("catalog:software_access", software_id=software.software_id)
    return render(
        request,
        "catalog/configuration_form.html",
        {
            "heading": f"配置 {access.downstream.user.username} 的 {software.name} 信息",
            "eyebrow": "DOWNSTREAM CONFIGURATION",
            "intro": "此配置只对该下游发行的当前软件授权生效；其他下游不会继承。",
            "form": form,
            "cancel_href": reverse("catalog:software_access", kwargs={"software_id": software.software_id}),
        },
    )


@require_http_methods(["GET", "POST"])
@active_downstream_required
@close_legacy_html
def downstream_configuration(request: HttpRequest, software_id: str) -> HttpResponse:
    profile = get_downstream_profile(request.user)
    access = get_object_or_404(
        DownstreamSoftware.objects.select_related("software", "downstream"),
        software_id=software_id,
        downstream=profile,
        status="active",
    )
    form = DownstreamConfigurationForm(request.POST or None, initial=configuration_from_object(access) if request.method == "GET" else None)
    if request.method == "POST" and form.is_valid():
        try:
            update_downstream_configuration(
                actor=request.user,
                downstream_public_id=profile.public_id,
                software_id=software_id,
                values=form.cleaned_configuration,
                clear=form.cleaned_data["clear_configuration"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except ConfigurationOperationError as exc:
            form.add_error(None, exc.message)
        else:
            messages.success(request, "软件支持信息已更新。")
            return redirect("catalog:downstream_software")
    return render(
        request,
        "catalog/configuration_form.html",
        {
            "heading": f"配置 {access.software.name} 的客户支持信息",
            "eyebrow": "DOWNSTREAM SUPPORT",
            "intro": "这些信息会随你发行的授权卡归属传递给授权 A；不填写的字段不会显示。",
            "form": form,
            "cancel_href": reverse("catalog:downstream_software"),
        },
    )


@active_downstream_required
def downstream_software(request: HttpRequest) -> HttpResponse:
    rows = [{"software": software, "plans": accessible_plans_for(request.user, software.software_id)} for software in list_accessible_software(request.user)]
    return render(request, "catalog/downstream_software.html", {"rows": rows})
