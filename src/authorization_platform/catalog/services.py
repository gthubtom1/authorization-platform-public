from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from django.db import IntegrityError, transaction
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus
from authorization_platform.accounts.services import get_downstream_profile, require_platform_admin
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .models import (
    CapabilityDefinition,
    CapabilityStatus,
    CapabilityValueType,
    DownstreamSoftware,
    DownstreamSoftwareStatus,
    Plan,
    PlanSnapshot,
    PlanStatus,
    PolicyStatus,
    PolicyVersion,
    ProfileStatus,
    Software,
    SoftwareProfile,
    SoftwareStatus,
    DEFAULT_VERIFY_INTERVAL_SECONDS,
)


IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
WRITABLE_PLAN_STATUSES = {PlanStatus.DRAFT, PlanStatus.ACTIVE, PlanStatus.ARCHIVED}


@dataclass(frozen=True)
class PlanDeleteResult:
    plan: Plan
    changed: bool
    unused_invalidated: int = 0
    activated_revoked: int = 0
    already_invalid: int = 0
    quota_refunded: int = 0


class CatalogOperationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _identifier(value: str, *, label: str, max_length: int = 64) -> str:
    if not isinstance(value, str):
        raise CatalogOperationError("INVALID_IDENTIFIER", f"{label}格式不正确。")
    normalized = value.strip().casefold()
    if len(normalized) > max_length or not IDENTIFIER_RE.fullmatch(normalized):
        raise CatalogOperationError("INVALID_IDENTIFIER", f"{label}只能使用小写字母、数字、点、下划线或短横线。")
    return normalized


def _required_text(value: str, *, label: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise CatalogOperationError("INVALID_INPUT", f"{label}格式不正确。")
    normalized = value.strip()
    if not normalized or len(normalized) > max_length:
        raise CatalogOperationError("INVALID_INPUT", f"请填写有效的{label}。")
    return normalized


def _positive_int(value, *, label: str, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CatalogOperationError("INVALID_NUMBER", f"{label}必须是整数。")
    number = value
    if number < 0 or (number == 0 and not allow_zero):
        raise CatalogOperationError("INVALID_NUMBER", f"{label}必须是{'大于等于 0' if allow_zero else '大于 0'}的整数。")
    return number


def _quota_cost_for_plan(value, *, test_only: bool) -> int:
    quota_cost = _positive_int(value, label="额度成本", allow_zero=True)
    if not test_only and quota_cost < 1:
        raise CatalogOperationError("INVALID_QUOTA_COST", "正式套餐额度成本至少为 1，测试套餐才可以填 0。")
    return quota_cost


def _json_value(value, *, label: str):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise CatalogOperationError("INVALID_JSON", f"{label}必须是有效的 JSON 值。") from exc
    return value


def _get_software(software_id: str) -> Software:
    try:
        return Software.objects.get(pk=software_id)
    except Software.DoesNotExist as exc:
        raise CatalogOperationError("SOFTWARE_NOT_FOUND", "软件不存在或已不可用。") from exc


def _get_profile(software_id: str, profile_id: str) -> SoftwareProfile:
    software = _get_software(software_id)
    try:
        return SoftwareProfile.objects.select_related("software").get(software=software, profile_id=profile_id)
    except SoftwareProfile.DoesNotExist as exc:
        raise CatalogOperationError("PROFILE_NOT_FOUND", "软件 Profile 不存在或已不可用。") from exc


def _ensure_software_writable(software: Software) -> None:
    if software.status == SoftwareStatus.ARCHIVED:
        raise CatalogOperationError("SOFTWARE_ARCHIVED", "已归档的软件不能继续配置。")


def _ensure_profile_writable(profile: SoftwareProfile) -> None:
    _ensure_software_writable(profile.software)
    if profile.status == ProfileStatus.ARCHIVED:
        raise CatalogOperationError("PROFILE_ARCHIVED", "已归档的 Profile 不能继续配置。")


def create_software(*, actor, software_id: str, name: str, description: str = "", status: str = SoftwareStatus.DRAFT, request_id: str | None = None, ip_address: str | None = None) -> Software:
    require_platform_admin(actor)
    software_id = _identifier(software_id, label="软件 ID")
    name = _required_text(name, label="软件名称", max_length=120)
    if status not in SoftwareStatus.values:
        raise CatalogOperationError("INVALID_STATUS", "软件状态不正确。")
    if Software.objects.filter(pk=software_id).exists():
        raise CatalogOperationError("SOFTWARE_EXISTS", "软件 ID 已存在，请换一个。")
    with transaction.atomic():
        try:
            software = Software.objects.create(software_id=software_id, name=name, description=(description or "").strip(), status=status)
        except IntegrityError as exc:
            raise CatalogOperationError("SOFTWARE_EXISTS", "软件 ID 已存在，请换一个。") from exc
        record_event(
            actor=actor,
            action="software.create",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Software",
            object_public_id=software.software_id,
            metadata={"status": software.status},
        )
    return software


def update_software_status(*, actor, software_id: str, status: str, reason: str = "", request_id: str | None = None, ip_address: str | None = None) -> Software:
    require_platform_admin(actor)
    if status not in SoftwareStatus.values:
        raise CatalogOperationError("INVALID_STATUS", "软件状态不正确。")
    with transaction.atomic():
        try:
            software = Software.objects.select_for_update().get(pk=software_id)
        except Software.DoesNotExist as exc:
            raise CatalogOperationError("SOFTWARE_NOT_FOUND", "软件不存在或已不可用。") from exc
        before = software.status
        software.status = status
        software.save(update_fields=("status", "updated_at"))
        if status == SoftwareStatus.ARCHIVED:
            DownstreamSoftware.objects.filter(software=software, status=DownstreamSoftwareStatus.ACTIVE).update(
                status=DownstreamSoftwareStatus.CLOSED,
                closed_at=timezone.now(),
                updated_at=timezone.now(),
            )
        record_event(
            actor=actor,
            action="software.status.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Software",
            object_public_id=software.software_id,
            metadata={"status": software.status, "before_status": before, "after_status": software.status, "reason": reason},
        )
    return software


def create_profile(*, actor, software_id: str, profile_id: str, client_id: str, contract_version: str = "authorization.v1", target: str = "windows", arch: str = "x64", channel: str = "stable", adapter_key: str = "generic-online-v1", adapter_version: str = "1", minimum_client_version: str = "", status: str = ProfileStatus.DRAFT, request_id: str | None = None, ip_address: str | None = None) -> SoftwareProfile:
    require_platform_admin(actor)
    software = _get_software(software_id)
    _ensure_software_writable(software)
    profile_id = _identifier(profile_id, label="Profile ID")
    client_id = _required_text(client_id, label="客户端 ID", max_length=128)
    contract_version = _required_text(contract_version, label="合同版本", max_length=64)
    target = _required_text(target, label="目标平台", max_length=32)
    arch = _required_text(arch, label="架构", max_length=32)
    channel = _required_text(channel, label="通道", max_length=32)
    adapter_key = _required_text(adapter_key, label="适配器标识", max_length=64)
    adapter_version = _required_text(adapter_version, label="适配器版本", max_length=32)
    if status not in ProfileStatus.values:
        raise CatalogOperationError("INVALID_STATUS", "Profile 状态不正确。")
    if SoftwareProfile.objects.filter(software=software, profile_id=profile_id).exists():
        raise CatalogOperationError("PROFILE_EXISTS", "这个软件下的 Profile ID 已存在。")
    with transaction.atomic():
        try:
            profile = SoftwareProfile.objects.create(
                software=software,
                profile_id=profile_id,
                client_id=client_id,
                contract_version=contract_version,
                target=target,
                arch=arch,
                channel=channel,
                adapter_key=adapter_key,
                adapter_version=adapter_version,
                minimum_client_version=(minimum_client_version or "").strip(),
                status=status,
            )
        except IntegrityError as exc:
            raise CatalogOperationError("PROFILE_EXISTS", "这个软件下的 Profile ID 已存在。") from exc
        record_event(
            actor=actor,
            action="software_profile.create",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="SoftwareProfile",
            object_public_id=f"{software.software_id}/{profile.profile_id}",
            metadata={"adapter_key": profile.adapter_key, "contract_version": profile.contract_version},
        )
    return profile


def create_policy_version(*, actor, software_id: str, profile_id: str, version: str, max_devices: int = 1, allow_device_switch: bool = False, device_switch_limit: int = 0, device_proof_required: bool = True, verify_interval_seconds: int = DEFAULT_VERIFY_INTERVAL_SECONDS, offline_grace_seconds: int = 0, effective_at: datetime | None = None, status: str = PolicyStatus.DRAFT, request_id: str | None = None, ip_address: str | None = None) -> PolicyVersion:
    require_platform_admin(actor)
    profile = _get_profile(software_id, profile_id)
    _ensure_profile_writable(profile)
    version = _identifier(version, label="策略版本")
    max_devices = _positive_int(max_devices, label="最大设备数")
    device_switch_limit = _positive_int(device_switch_limit, label="换机次数", allow_zero=True)
    verify_interval_seconds = _positive_int(verify_interval_seconds, label="验证间隔", allow_zero=True)
    offline_grace_seconds = _positive_int(offline_grace_seconds, label="断网宽限期", allow_zero=True)
    if allow_device_switch and device_switch_limit < 1:
        raise CatalogOperationError("INVALID_POLICY", "允许换机时，换机次数必须至少为 1。")
    if not allow_device_switch and device_switch_limit != 0:
        raise CatalogOperationError("INVALID_POLICY", "不允许换机时，换机次数必须为 0。")
    if status not in PolicyStatus.values:
        raise CatalogOperationError("INVALID_STATUS", "策略状态不正确。")
    if PolicyVersion.objects.filter(profile=profile, version=version).exists():
        raise CatalogOperationError("POLICY_EXISTS", "这个 Profile 下的策略版本已存在。")
    with transaction.atomic():
        try:
            policy = PolicyVersion.objects.create(
                profile=profile,
                version=version,
                status=status,
                max_devices=max_devices,
                allow_device_switch=allow_device_switch,
                device_switch_limit=device_switch_limit,
                device_proof_required=device_proof_required,
                verify_interval_seconds=verify_interval_seconds,
                offline_grace_seconds=offline_grace_seconds,
                effective_at=effective_at or timezone.now(),
                created_by=actor,
            )
        except IntegrityError as exc:
            raise CatalogOperationError("POLICY_EXISTS", "这个 Profile 下的策略版本已存在。") from exc
        record_event(
            actor=actor,
            action="policy_version.create",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="PolicyVersion",
            object_public_id=f"{profile}/{policy.version}",
            metadata={"status": policy.status, "max_devices": policy.max_devices},
        )
    return policy


def _validate_capability_value(value_type: str, value, *, minimum_value: int | None = None, maximum_value: int | None = None, label: str = "能力值") -> None:
    if value_type == CapabilityValueType.BOOLEAN:
        valid = isinstance(value, bool)
    elif value_type == CapabilityValueType.INTEGER:
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif value_type == CapabilityValueType.STRING:
        valid = isinstance(value, str) and len(value) <= 255
    else:
        raise CatalogOperationError("INVALID_CAPABILITY_TYPE", "能力类型不支持。")
    if not valid:
        raise CatalogOperationError("INVALID_CAPABILITY_VALUE", f"{label}类型与能力定义不匹配。")
    if value_type == CapabilityValueType.INTEGER:
        if minimum_value is not None and value < minimum_value:
            raise CatalogOperationError("CAPABILITY_OUT_OF_RANGE", f"{label}低于允许的最小值。")
        if maximum_value is not None and value > maximum_value:
            raise CatalogOperationError("CAPABILITY_OUT_OF_RANGE", f"{label}超过允许的最大值。")


def revise_policy_version(
    *,
    actor,
    software_id: str,
    profile_id: str,
    max_devices: int,
    allow_device_switch: bool,
    device_switch_limit: int,
    device_proof_required: bool,
    verify_interval_seconds: int,
    offline_grace_seconds: int,
    request_id: str | None = None,
    ip_address: str | None = None,
    launch_ticket_enabled: bool | None = None,
    launch_ticket_ttl_seconds: int | None = None,
) -> PolicyVersion:
    require_platform_admin(actor)
    max_devices = _positive_int(max_devices, label="最大设备数")
    device_switch_limit = _positive_int(device_switch_limit, label="换机次数", allow_zero=True)
    verify_interval_seconds = _positive_int(verify_interval_seconds, label="验证间隔", allow_zero=False)
    offline_grace_seconds = _positive_int(offline_grace_seconds, label="断网宽限期", allow_zero=True)
    if not isinstance(allow_device_switch, bool) or not isinstance(device_proof_required, bool):
        raise CatalogOperationError("INVALID_POLICY", "授权参数格式不正确。")
    if allow_device_switch and device_switch_limit < 1:
        raise CatalogOperationError("INVALID_POLICY", "允许换机时，换机次数必须至少为 1。")
    if not allow_device_switch and device_switch_limit != 0:
        raise CatalogOperationError("INVALID_POLICY", "不允许换机时，换机次数必须为 0。")
    with transaction.atomic():
        profile = (
            SoftwareProfile.objects.select_for_update()
            .select_related("software")
            .get(software_id=software_id, profile_id=profile_id)
        )
        _ensure_profile_writable(profile)
        current_policies = list(
            PolicyVersion.objects.select_for_update()
            .filter(profile=profile, status=PolicyStatus.ACTIVE)
            .order_by("-effective_at", "-created_at")
        )
        version_number = 1
        while PolicyVersion.objects.filter(profile=profile, version=f"policy-{version_number}").exists():
            version_number += 1
        for current in current_policies:
            current.status = PolicyStatus.ARCHIVED
            current.save(update_fields=("status",), _allow_mutation=True)
        inherit = current_policies[0] if current_policies else None
        if launch_ticket_enabled is None:
            launch_ticket_enabled = inherit.launch_ticket_enabled if inherit else True
        if launch_ticket_ttl_seconds is None:
            launch_ticket_ttl_seconds = inherit.launch_ticket_ttl_seconds if inherit else 180
        if not isinstance(launch_ticket_enabled, bool):
            raise CatalogOperationError("INVALID_POLICY", "启动票据开关格式不正确。")
        launch_ticket_ttl_seconds = _positive_int(launch_ticket_ttl_seconds, label="启动票据有效期", allow_zero=False)
        if launch_ticket_ttl_seconds < 30 or launch_ticket_ttl_seconds > 3600:
            raise CatalogOperationError("INVALID_POLICY", "启动票据有效期必须在 30 至 3600 秒之间。")
        policy = PolicyVersion.objects.create(
            profile=profile,
            version=f"policy-{version_number}",
            status=PolicyStatus.ACTIVE,
            max_devices=max_devices,
            allow_device_switch=allow_device_switch,
            device_switch_limit=device_switch_limit,
            device_proof_required=device_proof_required,
            verify_interval_seconds=verify_interval_seconds,
            offline_grace_seconds=offline_grace_seconds,
            launch_ticket_enabled=launch_ticket_enabled,
            launch_ticket_ttl_seconds=launch_ticket_ttl_seconds,
            effective_at=timezone.now(),
            created_by=actor,
        )
        archived_ids = {item.pk for item in current_policies}
        if archived_ids:
            for plan in Plan.objects.select_for_update().filter(profile=profile).order_by("pk"):
                latest = plan.snapshots.order_by("-snapshot_version").first()
                if latest is None or latest.policy_version_id not in archived_ids:
                    continue
                _create_plan_snapshot(
                    plan=plan,
                    policy=policy,
                    actor=actor,
                    snapshot_version=latest.snapshot_version + 1,
                )
        record_event(
            actor=actor,
            action="policy_version.revise",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="PolicyVersion",
            object_public_id=f"{profile.software_id}/{profile.profile_id}/{policy.version}",
            metadata={
                "previous_versions": [item.version for item in current_policies],
                "version": policy.version,
                "max_devices": policy.max_devices,
                "allow_device_switch": policy.allow_device_switch,
                "device_switch_limit": policy.device_switch_limit,
                "device_proof_required": policy.device_proof_required,
                "verify_interval_seconds": policy.verify_interval_seconds,
                "offline_grace_seconds": policy.offline_grace_seconds,
            },
        )
    return policy


def backfill_default_daily_device_switch(
    *,
    actor,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> list[PolicyVersion]:
    """Revise current ACTIVE false/0 switch policies to true/5.

    Issued cards keep their snapshots; the next activate hot-reads the new pair.
    """
    require_platform_admin(actor)
    revised: list[PolicyVersion] = []
    profile_pks = (
        PolicyVersion.objects.filter(
            status=PolicyStatus.ACTIVE,
            allow_device_switch=False,
            device_switch_limit=0,
        )
        .values_list("profile_id", flat=True)
        .distinct()
    )
    for profile_pk in profile_pks:
        current = (
            PolicyVersion.objects.select_related("profile", "profile__software")
            .filter(profile_id=profile_pk, status=PolicyStatus.ACTIVE)
            .order_by("-effective_at", "-created_at")
            .first()
        )
        if current is None:
            continue
        if current.allow_device_switch is not False or current.device_switch_limit != 0:
            continue
        profile = current.profile
        if profile.software.status == SoftwareStatus.ARCHIVED or profile.status == ProfileStatus.ARCHIVED:
            continue
        revised.append(
            revise_policy_version(
                actor=actor,
                software_id=profile.software_id,
                profile_id=profile.profile_id,
                max_devices=current.max_devices,
                allow_device_switch=True,
                device_switch_limit=5,
                device_proof_required=current.device_proof_required,
                verify_interval_seconds=current.verify_interval_seconds,
                offline_grace_seconds=current.offline_grace_seconds,
                request_id=request_id,
                ip_address=ip_address,
            )
        )
    return revised


def create_capability_definition(*, actor, software_id: str, profile_id: str, capability_key: str, value_type: str, default_value, minimum_value: int | None = None, maximum_value: int | None = None, is_public: bool = True, status: str = CapabilityStatus.ACTIVE, request_id: str | None = None, ip_address: str | None = None) -> CapabilityDefinition:
    require_platform_admin(actor)
    profile = _get_profile(software_id, profile_id)
    _ensure_profile_writable(profile)
    if not isinstance(capability_key, str) or not CAPABILITY_RE.fullmatch(capability_key.strip().casefold()) or "." not in capability_key:
        raise CatalogOperationError("INVALID_CAPABILITY_KEY", "能力键必须使用小写命名空间，例如 feature.export。")
    capability_key = capability_key.strip().casefold()
    if value_type not in CapabilityValueType.values:
        raise CatalogOperationError("INVALID_CAPABILITY_TYPE", "能力类型不支持。")
    default_value = _json_value(default_value, label="默认能力值")
    if minimum_value not in (None, ""):
        minimum_value = _positive_int(minimum_value, label="最小值", allow_zero=True)
    else:
        minimum_value = None
    if maximum_value not in (None, ""):
        maximum_value = _positive_int(maximum_value, label="最大值", allow_zero=True)
    else:
        maximum_value = None
    if minimum_value is not None and maximum_value is not None and minimum_value > maximum_value:
        raise CatalogOperationError("INVALID_CAPABILITY_RANGE", "最小值不能大于最大值。")
    _validate_capability_value(value_type, default_value, minimum_value=minimum_value, maximum_value=maximum_value, label="默认能力值")
    if status not in CapabilityStatus.values:
        raise CatalogOperationError("INVALID_STATUS", "能力状态不正确。")
    if CapabilityDefinition.objects.filter(profile=profile, capability_key=capability_key).exists():
        raise CatalogOperationError("CAPABILITY_EXISTS", "这个 Profile 下的能力键已存在。")
    with transaction.atomic():
        try:
            definition = CapabilityDefinition.objects.create(
                profile=profile,
                capability_key=capability_key,
                value_type=value_type,
                default_value=default_value,
                minimum_value=minimum_value,
                maximum_value=maximum_value,
                is_public=is_public,
                status=status,
            )
        except IntegrityError as exc:
            raise CatalogOperationError("CAPABILITY_EXISTS", "这个 Profile 下的能力键已存在。") from exc
        record_event(
            actor=actor,
            action="capability_definition.create",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="CapabilityDefinition",
            object_public_id=f"{profile}/{definition.capability_key}",
            metadata={"value_type": definition.value_type, "is_public": definition.is_public},
        )
    return definition


def _capability_values_for_profile(profile: SoftwareProfile, values) -> dict:
    values = _json_value(values or {}, label="套餐能力值")
    if not isinstance(values, dict):
        raise CatalogOperationError("INVALID_CAPABILITY_VALUES", "套餐能力值必须是 JSON 对象。")
    definitions = {
        item.capability_key: item
        for item in profile.capabilities.filter(status=CapabilityStatus.ACTIVE)
    }
    resolved = {key: definition.default_value for key, definition in definitions.items()}
    for key, value in values.items():
        if key not in definitions:
            raise CatalogOperationError("CAPABILITY_NOT_REGISTERED", f"能力键 {key} 尚未登记或已归档。")
        definition = definitions[key]
        _validate_capability_value(
            definition.value_type,
            value,
            minimum_value=definition.minimum_value,
            maximum_value=definition.maximum_value,
            label=f"能力 {key}",
        )
        resolved[key] = value
    return resolved


def _get_policy_for_plan(profile: SoftwareProfile, policy_version: str) -> PolicyVersion:
    try:
        policy = PolicyVersion.objects.get(profile=profile, version=policy_version)
    except PolicyVersion.DoesNotExist as exc:
        raise CatalogOperationError("POLICY_NOT_FOUND", "套餐引用的策略版本不存在。") from exc
    if policy.status == PolicyStatus.ARCHIVED:
        raise CatalogOperationError("POLICY_ARCHIVED", "已归档的策略版本不能用于新套餐。")
    return policy


def _create_plan_snapshot(*, plan: Plan, policy: PolicyVersion, actor, snapshot_version: int) -> PlanSnapshot:
    return PlanSnapshot.objects.create(
        plan=plan,
        software=plan.software,
        profile=plan.profile,
        policy_version=policy,
        snapshot_version=snapshot_version,
        name=plan.name,
        duration_seconds=plan.duration_seconds,
        quota_cost=plan.quota_cost,
        test_only=plan.test_only,
        capability_values=plan.capability_values,
        created_by=actor,
    )


def create_plan(*, actor, software_id: str, profile_id: str, policy_version: str, name: str, duration_seconds: int, quota_cost: int = 0, test_only: bool = False, capability_values=None, status: str = PlanStatus.DRAFT, effective_at: datetime | None = None, request_id: str | None = None, ip_address: str | None = None) -> tuple[Plan, PlanSnapshot]:
    require_platform_admin(actor)
    profile = _get_profile(software_id, profile_id)
    _ensure_profile_writable(profile)
    if status not in WRITABLE_PLAN_STATUSES:
        raise CatalogOperationError("INVALID_STATUS", "套餐状态不正确。")
    name = _required_text(name, label="套餐名称", max_length=120)
    duration_seconds = _positive_int(duration_seconds, label="有效期秒数")
    quota_cost = _quota_cost_for_plan(quota_cost, test_only=bool(test_only))
    policy = _get_policy_for_plan(profile, policy_version)
    if status == PlanStatus.ACTIVE and profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
        raise CatalogOperationError("PROFILE_NOT_ACTIVE", "只有测试中或正常的 Profile 才能发布可用套餐。")
    if status == PlanStatus.ACTIVE and policy.status != PolicyStatus.ACTIVE:
        raise CatalogOperationError("POLICY_NOT_ACTIVE", "可用套餐必须绑定生效中的策略版本。")
    resolved_values = _capability_values_for_profile(profile, capability_values)
    with transaction.atomic():
        plan = Plan.objects.create(
            software=profile.software,
            profile=profile,
            name=name,
            duration_seconds=duration_seconds,
            quota_cost=quota_cost,
            test_only=bool(test_only),
            status=status,
            effective_at=effective_at or timezone.now(),
            capability_values=resolved_values,
            created_by=actor,
        )
        snapshot = _create_plan_snapshot(plan=plan, policy=policy, actor=actor, snapshot_version=1)
        record_event(
            actor=actor,
            action="plan.create",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Plan",
            object_public_id=plan.pk,
            metadata={"snapshot_id": str(snapshot.snapshot_id), "duration_seconds": duration_seconds, "test_only": bool(test_only)},
        )
    return plan, snapshot


def create_software_bundle(*, actor, software_id: str, name: str, description: str, software_status: str, profile_id: str, client_id: str, contract_version: str, target: str, arch: str, channel: str, adapter_key: str, adapter_version: str, minimum_client_version: str, profile_status: str, policy_version: str, policy_status: str, max_devices: int, allow_device_switch: bool, device_switch_limit: int, device_proof_required: bool, verify_interval_seconds: int, offline_grace_seconds: int, plan_name: str, duration_seconds: int, quota_cost: int, test_only: bool, capability_values: dict, plan_status: str, include_plan: bool = True, request_id: str | None = None, ip_address: str | None = None) -> tuple[Software, SoftwareProfile, PolicyVersion, Plan | None, PlanSnapshot | None]:
    require_platform_admin(actor)
    with transaction.atomic():
        software = create_software(
            actor=actor,
            software_id=software_id,
            name=name,
            description=description,
            status=software_status,
            request_id=request_id,
            ip_address=ip_address,
        )
        profile = create_profile(
            actor=actor,
            software_id=software.software_id,
            profile_id=profile_id,
            client_id=client_id,
            contract_version=contract_version,
            target=target,
            arch=arch,
            channel=channel,
            adapter_key=adapter_key,
            adapter_version=adapter_version,
            minimum_client_version=minimum_client_version,
            status=profile_status,
            request_id=request_id,
            ip_address=ip_address,
        )
        policy = create_policy_version(
            actor=actor,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            version=policy_version,
            max_devices=max_devices,
            allow_device_switch=allow_device_switch,
            device_switch_limit=device_switch_limit,
            device_proof_required=device_proof_required,
            verify_interval_seconds=verify_interval_seconds,
            offline_grace_seconds=offline_grace_seconds,
            status=policy_status,
            request_id=request_id,
            ip_address=ip_address,
        )
        if not include_plan:
            return software, profile, policy, None, None
        plan, snapshot = create_plan(
            actor=actor,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name=plan_name,
            duration_seconds=duration_seconds,
            quota_cost=quota_cost,
            test_only=test_only,
            capability_values=capability_values,
            status=plan_status,
            request_id=request_id,
            ip_address=ip_address,
        )
    return software, profile, policy, plan, snapshot


def revise_plan(*, actor, plan_id: int, policy_version: str, name: str, duration_seconds: int, quota_cost: int = 0, test_only: bool = False, capability_values=None, status: str | None = None, request_id: str | None = None, ip_address: str | None = None) -> tuple[Plan, PlanSnapshot]:
    require_platform_admin(actor)
    with transaction.atomic():
        try:
            plan = Plan.objects.select_for_update().select_related("software", "profile").get(pk=plan_id)
        except Plan.DoesNotExist as exc:
            raise CatalogOperationError("PLAN_NOT_FOUND", "套餐不存在。") from exc
        _ensure_profile_writable(plan.profile)
        name = _required_text(name, label="套餐名称", max_length=120)
        duration_seconds = _positive_int(duration_seconds, label="有效期秒数")
        quota_cost = _quota_cost_for_plan(quota_cost, test_only=bool(test_only))
        policy = _get_policy_for_plan(plan.profile, policy_version)
        resolved_values = _capability_values_for_profile(plan.profile, capability_values)
        if plan.status == PlanStatus.DELETED:
            raise CatalogOperationError("PLAN_DELETED", "套餐已删除，不能再修改。")
        if status is not None and status not in WRITABLE_PLAN_STATUSES:
            raise CatalogOperationError("INVALID_STATUS", "套餐状态不正确。")
        target_status = status or plan.status
        if status is not None and status != plan.status:
            raise CatalogOperationError("PLAN_STATUS_USE_STATUS_API", "套餐归档或恢复请使用状态操作入口。")
        if target_status == PlanStatus.ACTIVE and plan.profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
            raise CatalogOperationError("PROFILE_NOT_ACTIVE", "只有测试中或正常的 Profile 才能发布可用套餐。")
        if target_status == PlanStatus.ACTIVE and policy.status != PolicyStatus.ACTIVE:
            raise CatalogOperationError("POLICY_NOT_ACTIVE", "可用套餐必须绑定生效中的策略版本。")
        plan.name = name
        plan.duration_seconds = duration_seconds
        plan.quota_cost = quota_cost
        plan.test_only = bool(test_only)
        plan.status = target_status
        plan.capability_values = resolved_values
        plan.save(update_fields=("name", "duration_seconds", "quota_cost", "test_only", "status", "capability_values", "updated_at"))
        previous_version = plan.snapshots.order_by("-snapshot_version").values_list("snapshot_version", flat=True).first() or 0
        snapshot = _create_plan_snapshot(plan=plan, policy=policy, actor=actor, snapshot_version=previous_version + 1)
        record_event(
            actor=actor,
            action="plan.revise",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Plan",
            object_public_id=plan.pk,
            metadata={"snapshot_id": str(snapshot.snapshot_id), "snapshot_version": snapshot.snapshot_version},
        )
    return plan, snapshot


def set_plan_status(*, actor, plan_id: int, status: str, reason: str, request_id: str | None = None, ip_address: str | None = None) -> tuple[Plan, bool]:
    """Archive or restore a plan without creating a duplicate snapshot."""

    require_platform_admin(actor)
    if status not in {PlanStatus.ACTIVE, PlanStatus.ARCHIVED}:
        raise CatalogOperationError("INVALID_STATUS", "套餐只能归档或恢复为可用。")
    normalized_reason = _required_text(reason, label="操作原因", max_length=255)
    if len(normalized_reason) < 4:
        raise CatalogOperationError("INVALID_REASON", "操作原因必须是 4 至 255 个字符。")

    with transaction.atomic():
        try:
            plan = (
                Plan.objects.select_for_update()
                .select_related("software", "profile")
                .prefetch_related("snapshots__policy_version")
                .get(pk=plan_id)
            )
        except Plan.DoesNotExist as exc:
            raise CatalogOperationError("PLAN_NOT_FOUND", "套餐不存在。") from exc

        previous_status = plan.status
        if previous_status == PlanStatus.DELETED:
            raise CatalogOperationError("PLAN_DELETED", "套餐已删除，不能再恢复。")
        if previous_status == status:
            return plan, False

        if status == PlanStatus.ACTIVE:
            _ensure_profile_writable(plan.profile)
            if plan.profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
                raise CatalogOperationError("PROFILE_NOT_ACTIVE", "只有测试中或正常的 Profile 才能恢复套餐。")
            snapshot = plan.latest_snapshot
            if snapshot is None:
                raise CatalogOperationError("PLAN_SNAPSHOT_NOT_FOUND", "套餐缺少历史快照，不能恢复。")
            if snapshot.policy_version.status != PolicyStatus.ACTIVE:
                raise CatalogOperationError("POLICY_NOT_ACTIVE", "套餐绑定的当前策略未生效，不能恢复。")

        plan.status = status
        plan.save(update_fields=("status", "updated_at"))
        record_event(
            actor=actor,
            action="plan.status.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Plan",
            object_public_id=plan.pk,
            metadata={
                "from_status": previous_status,
                "to_status": status,
                "reason": normalized_reason,
            },
        )
    return plan, True


def delete_plan(
    *,
    actor,
    plan_id: int,
    reason: str,
    request_id: str | None = None,
    ip_address: str | None = None,
    now=None,
) -> PlanDeleteResult:
    """Hide an archived plan and invalidate every remaining card it issued."""

    require_platform_admin(actor)
    normalized_reason = _required_text(reason, label="操作原因", max_length=255)
    if len(normalized_reason) < 4:
        raise CatalogOperationError("INVALID_REASON", "操作原因必须是 4 至 255 个字符。")

    from authorization_platform.licensing.services import (
        LicenseOperationError,
        invalidate_cards_for_plan_delete,
    )
    from authorization_platform.licensing.authorization import AuthorizationOperationError

    with transaction.atomic():
        try:
            plan = (
                Plan.objects.select_for_update()
                .select_related("software", "profile")
                .prefetch_related("snapshots__policy_version")
                .get(pk=plan_id)
            )
        except Plan.DoesNotExist as exc:
            raise CatalogOperationError("PLAN_NOT_FOUND", "套餐不存在。") from exc

        if plan.status == PlanStatus.DELETED:
            return PlanDeleteResult(plan=plan, changed=False)
        if plan.status != PlanStatus.ARCHIVED:
            raise CatalogOperationError("PLAN_NOT_ARCHIVED", "只有已归档套餐可以删除。请先归档。")

        try:
            invalidation = invalidate_cards_for_plan_delete(
                actor=actor,
                plan_id=plan.pk,
                reason=normalized_reason,
                request_id=request_id,
                ip_address=ip_address,
                now=now,
            )
        except LicenseOperationError as exc:
            raise CatalogOperationError(exc.code, exc.message) from exc
        except AuthorizationOperationError as exc:
            raise CatalogOperationError(exc.code, exc.message) from exc

        plan.status = PlanStatus.DELETED
        plan.save(update_fields=("status", "updated_at"))
        record_event(
            actor=actor,
            action="plan.delete",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Plan",
            object_public_id=plan.pk,
            metadata={
                "reason": normalized_reason,
                "from_status": PlanStatus.ARCHIVED,
                "to_status": PlanStatus.DELETED,
                "unused_invalidated": invalidation.unused_invalidated,
                "activated_revoked": invalidation.activated_revoked,
                "already_invalid": invalidation.already_invalid,
                "quota_refunded": invalidation.quota_refunded,
            },
        )
    return PlanDeleteResult(
        plan=plan,
        changed=True,
        unused_invalidated=invalidation.unused_invalidated,
        activated_revoked=invalidation.activated_revoked,
        already_invalid=invalidation.already_invalid,
        quota_refunded=invalidation.quota_refunded,
    )


def set_downstream_software_access(*, actor, downstream_public_id, software_id: str, enabled: bool, all_plans_allowed: bool = True, allowed_plan_ids: Iterable[int] | None = None, request_id: str | None = None, ip_address: str | None = None) -> DownstreamSoftware:
    require_platform_admin(actor)
    software = _get_software(software_id)
    if software.status not in {SoftwareStatus.TESTING, SoftwareStatus.ACTIVE}:
        raise CatalogOperationError("SOFTWARE_NOT_OPENABLE", "只有测试中或正常的软件可以开放给下游。")
    try:
        downstream = DownstreamProfile.objects.get(public_id=downstream_public_id)
    except DownstreamProfile.DoesNotExist as exc:
        raise CatalogOperationError("DOWNSTREAM_NOT_FOUND", "下游账号不存在。") from exc
    if downstream.status != DownstreamStatus.ACTIVE or not downstream.user.is_active:
        raise CatalogOperationError("DOWNSTREAM_NOT_ACTIVE", "只有正常下游账号可以开放经营范围。")
    raw_plan_ids = list(allowed_plan_ids or [])
    plans = list(Plan.objects.filter(id__in=raw_plan_ids, software=software, status=PlanStatus.ACTIVE))
    if enabled and not all_plans_allowed and not plans:
        raise CatalogOperationError("PLAN_SCOPE_REQUIRED", "限制套餐范围时，至少选择一个可用套餐。")
    if enabled and len(plans) != len(set(raw_plan_ids)) and not all_plans_allowed:
        raise CatalogOperationError("PLAN_SCOPE_INVALID", "选择的套餐不属于当前软件或已经不可用。")
    with transaction.atomic():
        access, _ = DownstreamSoftware.objects.select_for_update().get_or_create(
            downstream=downstream,
            software=software,
            defaults={"status": DownstreamSoftwareStatus.ACTIVE if enabled else DownstreamSoftwareStatus.CLOSED},
        )
        access.status = DownstreamSoftwareStatus.ACTIVE if enabled else DownstreamSoftwareStatus.CLOSED
        access.all_plans_allowed = bool(all_plans_allowed)
        access.closed_at = None if enabled else timezone.now()
        if enabled and not access.opened_at:
            access.opened_at = timezone.now()
        access.save(update_fields=("status", "all_plans_allowed", "closed_at", "opened_at", "updated_at"))
        if all_plans_allowed or not enabled:
            access.allowed_plans.clear()
        else:
            access.allowed_plans.set(plans)
        record_event(
            actor=actor,
            action="downstream.software_access.set",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamSoftware",
            object_public_id=f"{downstream.public_id}:{software.software_id}",
            metadata={"enabled": bool(enabled), "all_plans_allowed": bool(all_plans_allowed), "plan_count": len(plans)},
        )
    return access


def list_accessible_software(user):
    profile = get_downstream_profile(user)
    if not profile or profile.status != DownstreamStatus.ACTIVE:
        return Software.objects.none()
    return Software.objects.filter(
        status__in=(SoftwareStatus.TESTING, SoftwareStatus.ACTIVE),
        downstream_accesses__downstream=profile,
        downstream_accesses__status=DownstreamSoftwareStatus.ACTIVE,
    ).distinct().order_by("name", "software_id")


def accessible_plans_for(user, software_id: str):
    profile = get_downstream_profile(user)
    if not profile or profile.status != DownstreamStatus.ACTIVE:
        return Plan.objects.none()
    access = DownstreamSoftware.objects.filter(
        downstream=profile,
        software_id=software_id,
        status=DownstreamSoftwareStatus.ACTIVE,
    ).first()
    if not access:
        return Plan.objects.none()
    queryset = Plan.objects.filter(
        software_id=software_id,
        status=PlanStatus.ACTIVE,
        profile__status__in=(ProfileStatus.TESTING, ProfileStatus.ACTIVE),
        effective_at__lte=timezone.now(),
    )
    if access.software.status == SoftwareStatus.TESTING:
        queryset = queryset.filter(test_only=True)
    if not access.all_plans_allowed:
        queryset = queryset.filter(downstream_accesses=access)
    return queryset.select_related("profile").order_by("name", "id")


def list_software_accesses(software: Software):
    return DownstreamSoftware.objects.filter(software=software).select_related("downstream__user").prefetch_related("allowed_plans").order_by("downstream__user__username")
