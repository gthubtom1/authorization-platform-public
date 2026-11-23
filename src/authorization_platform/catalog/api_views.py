from __future__ import annotations

import hashlib
import json
import uuid
from functools import wraps
from typing import Callable

from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse

from authorization_platform.accounts.api_views import (
    _admin_required,
    _api_methods,
    _error,
    _read_json,
    _request_id,
    _success,
    _role_for_request,
)
from authorization_platform.core.csv_utils import csv_safe_row
from authorization_platform.core.time import normalize_duration
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.licensing.authorization import AuthorizationOperationError

from .models import (
    CapabilityDefinition,
    ConfigurationOperation,
    DownstreamSoftware,
    DownstreamSoftwareOperation,
    Plan,
    PlanCreateOperation,
    PlanLifecycleOperation,
    PlanRevisionOperation,
    PolicyRevisionOperation,
    PolicyStatus,
    PlanSnapshot,
    PlanStatus,
    PolicyVersion,
    Software,
    SoftwareProfile,
    SoftwareStatus,
    DEFAULT_VERIFY_INTERVAL_SECONDS,
)
from .configuration import (
    ConfigurationOperationError,
    configuration_from_object,
    update_downstream_configuration,
    update_profile_configuration,
)
from .services import (
    CatalogOperationError,
    accessible_plans_for,
    create_plan,
    create_software_bundle,
    delete_plan,
    list_accessible_software,
    list_software_accesses,
    revise_policy_version,
    revise_plan,
    set_downstream_software_access,
    set_plan_status,
    update_software_status,
)


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _downstream_required(view):
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        role, identity = _role_for_request(request)
        if role == "anonymous":
            return _error(request, "UNAUTHORIZED", "请先登录下游端。", status=401)
        if role != "downstream":
            return _error(request, "FORBIDDEN", "当前账号没有访问下游目录的权限。", status=403)
        return view(request, identity, *args, **kwargs)

    return wrapped


def _required_string(payload: dict, key: str, *, label: str, max_length: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise CatalogOperationError("INVALID_INPUT", f"请填写有效的{label}。")
    return value.strip()


def _optional_string(payload: dict, key: str, *, max_length: int, default: str = "") -> str:
    value = payload.get(key, default)
    if not isinstance(value, str) or len(value.strip()) > max_length:
        raise CatalogOperationError("INVALID_INPUT", f"{key}格式不正确。")
    return value.strip()


def _integer(payload: dict, key: str, *, label: str, minimum: int | None = None, default=None) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise CatalogOperationError("INVALID_NUMBER", f"{label}必须是整数。")
    if minimum is not None and value < minimum:
        raise CatalogOperationError("INVALID_NUMBER", f"{label}不符合范围要求。")
    return value


def _boolean(payload: dict, key: str, *, label: str, default=None) -> bool:
    value = payload.get(key, default)
    if not isinstance(value, bool):
        raise CatalogOperationError("INVALID_INPUT", f"{label}必须是布尔值。")
    return value


def _object(payload: dict, key: str, *, label: str, default=None) -> dict:
    value = payload.get(key, default if default is not None else {})
    if not isinstance(value, dict):
        raise CatalogOperationError("INVALID_JSON", f"{label}必须是 JSON 对象。")
    return value


def _duration_seconds(payload: dict) -> int:
    value = _integer(payload, "duration_value", label="有效期数值", minimum=1)
    unit = payload.get("duration_unit")
    if not isinstance(unit, str) or unit not in {"minute", "hour", "day"}:
        raise CatalogOperationError("INVALID_DURATION", "有效期单位不正确。")
    try:
        return normalize_duration(value, unit)
    except ValueError as exc:
        raise CatalogOperationError("INVALID_DURATION", "有效期不正确。") from exc


def _status(payload: dict, key: str, *, allowed: set[str], default: str) -> str:
    value = payload.get(key, default)
    if not isinstance(value, str) or value not in allowed:
        raise CatalogOperationError("INVALID_STATUS", f"{key}状态不正确。")
    return value


def _snapshot_payload(snapshot: PlanSnapshot | None) -> dict | None:
    if snapshot is None:
        return None
    return {
        "snapshot_id": str(snapshot.snapshot_id),
        "snapshot_version": snapshot.snapshot_version,
        "policy_version": snapshot.policy_version.version,
        "policy": {
            "max_devices": snapshot.policy_version.max_devices,
            "allow_device_switch": snapshot.policy_version.allow_device_switch,
            "device_switch_limit": snapshot.policy_version.device_switch_limit,
            "device_proof_required": snapshot.policy_version.device_proof_required,
        },
        "duration_seconds": snapshot.duration_seconds,
        "quota_cost": snapshot.quota_cost,
        "test_only": snapshot.test_only,
        "capability_values": snapshot.capability_values,
        "created_at": snapshot.created_at.isoformat(),
    }


def _plan_payload(plan: Plan) -> dict:
    snapshot = plan.latest_snapshot
    return {
        "id": plan.pk,
        "software_id": plan.software_id,
        "profile_id": plan.profile.profile_id,
        "name": plan.name,
        "duration_seconds": plan.duration_seconds,
        "quota_cost": plan.quota_cost,
        "test_only": plan.test_only,
        "status": plan.status,
        "effective_at": plan.effective_at.isoformat(),
        "capability_values": plan.capability_values,
        "latest_snapshot": _snapshot_payload(snapshot),
    }


def _policy_payload(policy: PolicyVersion) -> dict:
    return {
        "version": policy.version,
        "status": policy.status,
        "max_devices": policy.max_devices,
        "allow_device_switch": policy.allow_device_switch,
        "device_switch_limit": policy.device_switch_limit,
        "device_proof_required": policy.device_proof_required,
        "verify_interval_seconds": policy.verify_interval_seconds,
        "offline_grace_seconds": policy.offline_grace_seconds,
        "launch_ticket_enabled": policy.launch_ticket_enabled,
        "launch_ticket_ttl_seconds": policy.launch_ticket_ttl_seconds,
        "effective_at": policy.effective_at.isoformat(),
    }


def _capability_payload(capability: CapabilityDefinition) -> dict:
    return {
        "capability_key": capability.capability_key,
        "value_type": capability.value_type,
        "default_value": capability.default_value,
        "minimum_value": capability.minimum_value,
        "maximum_value": capability.maximum_value,
        "is_public": capability.is_public,
        "status": capability.status,
    }


def _profile_payload(profile: SoftwareProfile) -> dict:
    return {
        "profile_id": profile.profile_id,
        "client_id": profile.client_id,
        "contract_version": profile.contract_version,
        "target": profile.target,
        "arch": profile.arch,
        "channel": profile.channel,
        "adapter_key": profile.adapter_key,
        "adapter_version": profile.adapter_version,
        "minimum_client_version": profile.minimum_client_version,
        "config_version": profile.config_version,
        "status": profile.status,
        "policies": [_policy_payload(item) for item in profile.policy_versions.all()],
        "capabilities": [_capability_payload(item) for item in profile.capabilities.all()],
    }


def _access_payload(access: DownstreamSoftware) -> dict:
    return {
        "downstream_public_id": str(access.downstream.public_id),
        "username": access.downstream.user.username,
        "status": access.status,
        "all_plans_allowed": access.all_plans_allowed,
        "allowed_plan_ids": list(access.allowed_plans.values_list("id", flat=True)),
        "opened_at": access.opened_at.isoformat() if access.opened_at else None,
        "closed_at": access.closed_at.isoformat() if access.closed_at else None,
    }


def _software_payload(software: Software) -> dict:
    profiles = list(software.profiles.all())
    plans = [item for item in software.plans.all() if item.status != PlanStatus.DELETED]
    accesses = list(list_software_accesses(software))
    return {
        "software_id": software.software_id,
        "name": software.name,
        "description": software.description,
        "status": software.status,
        "client_connection": "not_connected",
        "profiles": [_profile_payload(item) for item in profiles],
        "plans": [_plan_payload(item) for item in plans],
        "accesses": [_access_payload(item) for item in accesses],
    }


def _catalog_payload(*, page_number: int = 1, page_size: int = 20) -> dict:
    softwares = Software.objects.prefetch_related(
        "profiles__policy_versions",
        "profiles__capabilities",
        "plans__profile",
        "plans__snapshots__policy_version",
        "downstream_accesses__downstream__user",
        "downstream_accesses__allowed_plans",
    ).order_by("name", "software_id")
    paginator = Paginator(softwares, min(max(page_size, 1), 100))
    page = paginator.get_page(max(page_number, 1))
    return {
        "items": [_software_payload(software) for software in page.object_list],
        "pagination": {
            "page": page.number,
            "page_size": paginator.per_page,
            "total": paginator.count,
            "total_pages": paginator.num_pages,
            "has_previous": page.has_previous(),
            "has_next": page.has_next(),
        },
    }


def _downstream_catalog_payload(user) -> dict:
    items = []
    for software in list_accessible_software(user):
        items.append(
            {
                "software_id": software.software_id,
                "name": software.name,
                "plans": [_plan_payload(plan) for plan in accessible_plans_for(user, software.software_id)],
            }
        )
    return {"items": items}


def _idempotency_key(request: HttpRequest) -> str:
    value = request.headers.get("Idempotency-Key", "").strip()
    if not value or len(value) > 128:
        raise CatalogOperationError("INVALID_REQUEST", "缺少有效的重复提交标识。")
    return value


def _run_configuration_idempotent(request: HttpRequest, target: str, callback: Callable[[], dict]) -> JsonResponse:
    try:
        key = _idempotency_key(request)
        digest = hashlib.sha256(request.body).hexdigest()
        with transaction.atomic():
            # A stable row exists before the first request. This also serializes
            # first-use keys across workers, with the mutation and result atomic.
            get_user_model().objects.select_for_update().get(pk=request.user.pk)
            existing = ConfigurationOperation.objects.filter(actor=request.user, idempotency_key=key).first()
            if existing:
                if existing.target != target or existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload))
            payload = callback()
            ConfigurationOperation.objects.create(
                actor=request.user, target=target, idempotency_key=key,
                request_hash=digest, response_payload=payload,
            )
            return _success(payload)
    except (CatalogOperationError, ConfigurationOperationError) as exc:
        return _error(request, exc.code, exc.message, status=400)


def _run_idempotent(request: HttpRequest, actor, namespace: str, callback: Callable[[], dict]) -> JsonResponse:
    try:
        key = _idempotency_key(request)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    digest = hashlib.sha256(request.body).hexdigest()
    cache_key = "authorization-catalog-api:" + hashlib.sha256(f"{namespace}:{actor.pk}:{key}".encode("utf-8")).hexdigest()
    cached = cache.get(cache_key)
    if cached:
        if cached["digest"] != digest:
            return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
        return _success(cached["payload"], status=cached["status"])
    lock_key = cache_key + ":lock"
    if not cache.add(lock_key, True, timeout=60):
        return _error(request, "RETRY_LATER", "请求正在处理中，请稍后重试。", status=409, retryable=True)
    try:
        payload = callback()
        status = int(payload.pop("_status", 200))
        cache.set(cache_key, {"digest": digest, "payload": payload, "status": status}, timeout=3600)
        return _success(payload, status=status)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    except (TypeError, ValueError, KeyError):
        return _error(request, "INVALID_REQUEST", "请求参数不正确。", status=400)
    finally:
        cache.delete(lock_key)


def _run_plan_create_idempotent(request: HttpRequest, actor, namespace: str, callback: Callable[[], dict]) -> JsonResponse:
    try:
        key = _idempotency_key(request)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    digest = hashlib.sha256(request.body).hexdigest()
    try:
        with transaction.atomic():
            existing = (
                PlanCreateOperation.objects.select_for_update()
                .filter(actor=actor, namespace=namespace, idempotency_key=key)
                .first()
            )
            if existing:
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            try:
                with transaction.atomic():
                    operation = PlanCreateOperation.objects.create(
                        actor=actor,
                        namespace=namespace,
                        idempotency_key=key,
                        request_hash=digest,
                    )
            except IntegrityError:
                existing = (
                    PlanCreateOperation.objects.select_for_update()
                    .filter(actor=actor, namespace=namespace, idempotency_key=key)
                    .first()
                )
                if existing is None:
                    raise CatalogOperationError("RETRY_LATER", "请求正在处理中，请稍后重试。")
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            payload = callback()
            plan = payload.pop("_plan", None)
            status = int(payload.pop("_status", 201))
            operation.plan = plan
            operation.response_status = status
            operation.response_payload = payload
            operation.save(update_fields=("plan", "response_status", "response_payload"), _allow_mutation=True)
            return _success(payload, status=status)
    except CatalogOperationError as exc:
        status = 409 if exc.code in {"IDEMPOTENCY_CONFLICT", "RETRY_LATER"} else 400
        return _error(request, exc.code, exc.message, status=status, retryable=exc.code == "RETRY_LATER")
    except (TypeError, ValueError, KeyError):
        return _error(request, "INVALID_REQUEST", "请求参数不正确。", status=400)


def _run_plan_revision_idempotent(request: HttpRequest, actor, plan_id: int, callback: Callable[[], dict]) -> JsonResponse:
    try:
        key = _idempotency_key(request)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    digest = hashlib.sha256(f"plan-revise:{plan_id}:".encode("utf-8") + request.body).hexdigest()
    try:
        with transaction.atomic():
            existing = (
                PlanRevisionOperation.objects.select_for_update()
                .filter(actor=actor, action="revise", idempotency_key=key)
                .first()
            )
            if existing:
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            try:
                with transaction.atomic():
                    operation = PlanRevisionOperation.objects.create(
                        actor=actor,
                        plan_id=plan_id,
                        action="revise",
                        idempotency_key=key,
                        request_hash=digest,
                    )
            except IntegrityError:
                existing = (
                    PlanRevisionOperation.objects.select_for_update()
                    .filter(actor=actor, action="revise", idempotency_key=key)
                    .first()
                )
                if existing is None:
                    raise CatalogOperationError("RETRY_LATER", "请求正在处理中，请稍后重试。")
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            payload = callback()
            status = int(payload.pop("_status", 200))
            operation.response_status = status
            operation.response_payload = payload
            operation.save(update_fields=("response_status", "response_payload"), _allow_mutation=True)
            return _success(payload, status=status)
    except CatalogOperationError as exc:
        status = 409 if exc.code in {"IDEMPOTENCY_CONFLICT", "RETRY_LATER"} else 400
        return _error(request, exc.code, exc.message, status=status, retryable=exc.code == "RETRY_LATER")
    except (TypeError, ValueError, KeyError):
        return _error(request, "INVALID_REQUEST", "请求参数不正确。", status=400)


def _run_policy_revision_idempotent(request: HttpRequest, actor, profile: SoftwareProfile, callback: Callable[[], dict]) -> JsonResponse:
    try:
        key = _idempotency_key(request)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    digest = hashlib.sha256(f"policy-revise:{profile.software_id}:{profile.profile_id}:".encode("utf-8") + request.body).hexdigest()
    try:
        with transaction.atomic():
            existing = (
                PolicyRevisionOperation.objects.select_for_update()
                .filter(actor=actor, profile=profile, idempotency_key=key)
                .first()
            )
            if existing:
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)
            try:
                with transaction.atomic():
                    operation = PolicyRevisionOperation.objects.create(
                        actor=actor,
                        profile=profile,
                        idempotency_key=key,
                        request_hash=digest,
                    )
            except IntegrityError:
                existing = (
                    PolicyRevisionOperation.objects.select_for_update()
                    .filter(actor=actor, profile=profile, idempotency_key=key)
                    .first()
                )
                if existing is None:
                    raise CatalogOperationError("RETRY_LATER", "请求正在处理中，请稍后重试。")
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)
            payload = callback()
            policy = payload.pop("_policy", None)
            status = int(payload.pop("_status", 200))
            operation.policy = policy
            operation.response_status = status
            operation.response_payload = payload
            operation.save(update_fields=("policy", "response_status", "response_payload"), _allow_mutation=True)
            return _success(payload, status=status)
    except CatalogOperationError as exc:
        status = 409 if exc.code in {"IDEMPOTENCY_CONFLICT", "RETRY_LATER", "POLICY_NOT_FOUND"} else 400
        return _error(request, exc.code, exc.message, status=status, retryable=exc.code == "RETRY_LATER")
    except (TypeError, ValueError, KeyError):
        return _error(request, "INVALID_REQUEST", "请求参数不正确。", status=400)


def _run_plan_lifecycle_idempotent(
    request: HttpRequest, actor, plan_id: int, action: str, callback: Callable[[], dict]
) -> JsonResponse:
    try:
        key = _idempotency_key(request)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    digest_prefix = f"plan:{plan_id}:" if action == "status" else f"plan:{plan_id}:{action}:"
    digest = hashlib.sha256(digest_prefix.encode("utf-8") + request.body).hexdigest()
    try:
        with transaction.atomic():
            existing = (
                PlanLifecycleOperation.objects.select_for_update()
                .filter(actor=actor, action=action, idempotency_key=key)
                .first()
            )
            if existing:
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            try:
                with transaction.atomic():
                    operation = PlanLifecycleOperation.objects.create(
                        actor=actor,
                        plan_id=plan_id,
                        action=action,
                        idempotency_key=key,
                        request_hash=digest,
                    )
            except IntegrityError:
                existing = (
                    PlanLifecycleOperation.objects.select_for_update()
                    .filter(actor=actor, action=action, idempotency_key=key)
                    .first()
                )
                if existing is None:
                    raise CatalogOperationError("RETRY_LATER", "请求正在处理中，请稍后重试。")
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            payload = callback()
            status = int(payload.pop("_status", 200))
            operation.response_status = status
            operation.response_payload = payload
            operation.save(update_fields=("response_status", "response_payload"), _allow_mutation=True)
            return _success(payload, status=status)
    except CatalogOperationError as exc:
        status = 409 if exc.code in {"IDEMPOTENCY_CONFLICT", "RETRY_LATER"} else 400
        return _error(request, exc.code, exc.message, status=status, retryable=exc.code == "RETRY_LATER")
    except (TypeError, ValueError, KeyError):
        return _error(request, "INVALID_REQUEST", "请求参数不正确。", status=400)


def _run_catalog_access_idempotent(
    request: HttpRequest,
    actor,
    downstream_public_id: uuid.UUID,
    software_id: str,
    callback: Callable[[], dict],
) -> JsonResponse:
    try:
        key = _idempotency_key(request)
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)
    digest = hashlib.sha256(
        f"access:{downstream_public_id}:{software_id}:".encode("utf-8") + request.body
    ).hexdigest()
    try:
        with transaction.atomic():
            existing = (
                DownstreamSoftwareOperation.objects.select_for_update()
                .filter(actor=actor, action="set", idempotency_key=key)
                .first()
            )
            if existing:
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            try:
                with transaction.atomic():
                    operation = DownstreamSoftwareOperation.objects.create(
                        actor=actor,
                        downstream_public_id=downstream_public_id,
                        software_id=software_id,
                        action="set",
                        idempotency_key=key,
                        request_hash=digest,
                    )
            except IntegrityError:
                existing = (
                    DownstreamSoftwareOperation.objects.select_for_update()
                    .filter(actor=actor, action="set", idempotency_key=key)
                    .first()
                )
                if existing is None:
                    raise CatalogOperationError("RETRY_LATER", "请求正在处理中，请稍后重试。")
                if existing.request_hash != digest:
                    return _error(request, "IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
                return _success(dict(existing.response_payload), status=existing.response_status)

            payload = callback()
            status = int(payload.pop("_status", 200))
            operation.response_status = status
            operation.response_payload = payload
            operation.save(update_fields=("response_status", "response_payload"), _allow_mutation=True)
            return _success(payload, status=status)
    except CatalogOperationError as exc:
        status = 409 if exc.code in {"IDEMPOTENCY_CONFLICT", "RETRY_LATER"} else 400
        return _error(request, exc.code, exc.message, status=status, retryable=exc.code == "RETRY_LATER")
    except (TypeError, ValueError, KeyError):
        return _error(request, "INVALID_REQUEST", "请求参数不正确。", status=400)


def _bundle_payload(payload: dict, request: HttpRequest, actor) -> dict:
    software_id = _optional_string(payload, "software_id", max_length=64, default=f"sw-{uuid.uuid4().hex}").casefold()
    name = _required_string(payload, "name", label="软件名称", max_length=120)
    description = _optional_string(payload, "description", max_length=2000)
    target = _optional_string(payload, "target", max_length=32, default="windows")
    profile_id = _optional_string(payload, "profile_id", max_length=64, default="stable").casefold()
    client_id = _optional_string(payload, "client_id", max_length=128, default=f"{software_id}-{target}")
    contract_version = _optional_string(payload, "contract_version", max_length=64, default="authorization.v1")
    arch = _optional_string(payload, "arch", max_length=32, default="x64")
    channel = _optional_string(payload, "channel", max_length=32, default="stable")
    adapter_key = _optional_string(payload, "adapter_key", max_length=64, default="generic-online-v1")
    adapter_version = _optional_string(payload, "adapter_version", max_length=32, default="1")
    minimum_client_version = _optional_string(payload, "minimum_client_version", max_length=64)
    policy_version = _optional_string(payload, "policy_version", max_length=64, default="policy-1").casefold()
    policy_status = _status(payload, "policy_status", allowed={"draft", "active", "archived"}, default="active")
    profile_status = _status(payload, "profile_status", allowed={"draft", "testing", "active", "archived"}, default="active")
    software_status = _status(payload, "software_status", allowed={"draft", "testing", "active", "archived"}, default="active")
    plan_status = _status(payload, "plan_status", allowed={"draft", "active", "archived"}, default="active")
    max_devices = _integer(payload, "max_devices", label="最大设备数", minimum=1, default=1)
    allow_device_switch = _boolean(payload, "allow_device_switch", label="是否允许换机", default=True)
    device_switch_limit = _integer(payload, "device_switch_limit", label="换机次数", minimum=0, default=5)
    device_proof_required = _boolean(payload, "device_proof_required", label="是否要求设备证明", default=True)
    verify_interval_seconds = _integer(payload, "verify_interval_seconds", label="验证间隔", minimum=0, default=DEFAULT_VERIFY_INTERVAL_SECONDS)
    offline_grace_seconds = _integer(payload, "offline_grace_seconds", label="断网宽限期", minimum=0, default=0)
    if "verify_interval_minutes" in payload:
        verify_interval_seconds = _integer(payload, "verify_interval_minutes", label="验证间隔", minimum=0) * 60
    if "offline_grace_hours" in payload:
        offline_grace_seconds = _integer(payload, "offline_grace_hours", label="断网宽限期", minimum=0) * 3600
    plan_fields = {"plan_name", "duration_seconds", "duration_value", "duration_unit", "quota_cost", "test_only", "capability_values", "plan_status"}
    has_plan_fields = bool(plan_fields.intersection(payload))
    include_plan = _boolean(payload, "create_plan", label="同时添加套餐", default=has_plan_fields)
    if not include_plan and has_plan_fields:
        raise CatalogOperationError("INVALID_REQUEST", "未选择添加套餐时不能提交套餐字段。")
    plan_name = _required_string(payload, "plan_name", label="套餐名称", max_length=120) if include_plan else ""
    duration_seconds = _duration_seconds(payload) if include_plan else 0
    quota_cost = _integer(payload, "quota_cost", label="额度成本", minimum=0, default=0) if include_plan else 0
    test_only = _boolean(payload, "test_only", label="测试套餐标记", default=False) if include_plan else False
    capability_values = _object(payload, "capability_values", label="套餐能力值") if include_plan else {}
    software, profile, policy, plan, snapshot = create_software_bundle(
        actor=actor,
        software_id=software_id,
        name=name,
        description=description,
        software_status=software_status,
        profile_id=profile_id,
        client_id=client_id,
        contract_version=contract_version,
        target=target,
        arch=arch,
        channel=channel,
        adapter_key=adapter_key,
        adapter_version=adapter_version,
        minimum_client_version=minimum_client_version,
        profile_status=profile_status,
        policy_version=policy_version,
        policy_status=policy_status,
        max_devices=max_devices,
        allow_device_switch=allow_device_switch,
        device_switch_limit=device_switch_limit,
        device_proof_required=device_proof_required,
        verify_interval_seconds=verify_interval_seconds,
        offline_grace_seconds=offline_grace_seconds,
        plan_name=plan_name,
        duration_seconds=duration_seconds,
        quota_cost=quota_cost,
        test_only=test_only,
        capability_values=capability_values,
        plan_status=plan_status,
        include_plan=include_plan,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
    )
    return {
        "software": _software_payload(software),
        "profile": _profile_payload(profile),
        "policy": _policy_payload(policy),
        "plan": _plan_payload(plan) if plan else None,
        "snapshot": _snapshot_payload(snapshot),
        "request_id": _request_id(request),
        "_status": 201,
        "_plan": plan,
    }


@_admin_required
@_api_methods("GET", "POST")
def api_catalog_collection(request: HttpRequest, _identity) -> JsonResponse:
    if request.method == "GET":
        try:
            page = max(1, int(request.GET.get("page", "1")))
            page_size = min(100, max(1, int(request.GET.get("page_size", "20"))))
        except (TypeError, ValueError):
            page, page_size = 1, 20
        return _success(_catalog_payload(page_number=page, page_size=page_size))
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    return _run_plan_create_idempotent(request, request.user, "software-create", lambda: _bundle_payload(payload, request, request.user))


@_admin_required
@_api_methods("GET")
def api_software_integration_config(request: HttpRequest, _identity, software_id: str) -> HttpResponse:
    from .integration import build_integration_config

    try:
        payload = build_integration_config(request, software_id)
    except AuthorizationOperationError as exc:
        return _error(request, "SIGNING_KEY_UNAVAILABLE", "平台验签公钥暂不可用，请联系维护者。", status=503, retryable=True)
    except CatalogOperationError as exc:
        status = 404 if exc.code in {"SOFTWARE_NOT_FOUND", "PROFILE_NOT_FOUND"} else 400
        if exc.code in {"PLATFORM_URL_UNAVAILABLE", "INTEGRATION_GUIDE_UNAVAILABLE", "PROFILE_NOT_READY"}:
            status = 503
        return _error(request, exc.code, exc.message, status=status)
    record_event(
        actor=request.user, action="software.integration_config.export", outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request), ip_address=_ip_address(request),
        object_type="Software", object_public_id=software_id,
        metadata={"profile_id": payload["software"]["profile_id"], "schema": payload["schema"], "key_id": payload["platform"]["authorization_public_key_id"]},
    )
    response = HttpResponse(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", content_type="application/json; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{software_id}-{payload["software"]["profile_id"]}-integration.json"'
    response["Cache-Control"] = "no-store, private"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@_admin_required
@_api_methods("POST")
def api_catalog_software_status(request: HttpRequest, _identity, software_id: str) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    normalized_software_id = str(software_id or "").strip().casefold()
    if not Software.objects.filter(pk=normalized_software_id).exists():
        return _error(request, "SOFTWARE_NOT_FOUND", "软件不存在。", status=404)

    def operation() -> dict:
        status = _status(payload, "status", allowed={SoftwareStatus.ARCHIVED, SoftwareStatus.ACTIVE}, default="archived")
        reason = _required_string(payload, "reason", label="操作原因", max_length=255)
        if len(reason) < 4:
            raise CatalogOperationError("INVALID_REASON", "操作原因必须是 4 至 255 个字符。")
        current = Software.objects.select_for_update().get(pk=normalized_software_id)
        if status == SoftwareStatus.ACTIVE and current.status not in {SoftwareStatus.ARCHIVED, SoftwareStatus.ACTIVE}:
            raise CatalogOperationError("INVALID_STATUS", "只有已下架的软件可以重新上架。")
        software = update_software_status(
            actor=request.user,
            software_id=normalized_software_id,
            status=status,
            reason=reason,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        return {
            "_status": 200,
            "software": _software_payload(software),
            "request_id": _request_id(request),
        }

    return _run_plan_create_idempotent(request, request.user, f"software-status:{normalized_software_id}", operation)


@_admin_required
@_api_methods("POST")
def api_catalog_policy_revise(request: HttpRequest, _identity, software_id: str, profile_id: str) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    try:
        profile = SoftwareProfile.objects.select_related("software").get(
            software_id=software_id,
            profile_id=profile_id,
        )
    except SoftwareProfile.DoesNotExist:
        return _error(request, "PROFILE_NOT_FOUND", "软件 Profile 不存在。", status=404)

    def operation() -> dict:
        current = profile.policy_versions.filter(status=PolicyStatus.ACTIVE).order_by("-effective_at", "-created_at").first()
        if current is None:
            raise CatalogOperationError("POLICY_NOT_FOUND", "当前 Profile 没有生效中的授权策略。")
        policy = revise_policy_version(
            actor=request.user,
            software_id=software_id,
            profile_id=profile_id,
            max_devices=_integer(payload, "max_devices", label="最大设备数", minimum=1, default=current.max_devices),
            allow_device_switch=_boolean(payload, "allow_device_switch", label="是否允许换机", default=current.allow_device_switch),
            device_switch_limit=_integer(payload, "device_switch_limit", label="换机次数", minimum=0, default=current.device_switch_limit),
            device_proof_required=_boolean(payload, "device_proof_required", label="是否要求设备证明", default=current.device_proof_required),
            verify_interval_seconds=_integer(payload, "verify_interval_seconds", label="验证间隔", minimum=1, default=current.verify_interval_seconds),
            offline_grace_seconds=_integer(payload, "offline_grace_seconds", label="断网宽限期", minimum=0, default=current.offline_grace_seconds),
            launch_ticket_enabled=_boolean(payload, "launch_ticket_enabled", label="启动票据开关", default=current.launch_ticket_enabled) if "launch_ticket_enabled" in payload else None,
            launch_ticket_ttl_seconds=_integer(payload, "launch_ticket_ttl_seconds", label="启动票据有效期", minimum=30, default=current.launch_ticket_ttl_seconds) if "launch_ticket_ttl_seconds" in payload else None,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        return {
            "policy": _policy_payload(policy),
            "profile_id": profile_id,
            "software_id": software_id,
            "request_id": _request_id(request),
            "_policy": policy,
        }

    return _run_policy_revision_idempotent(request, request.user, profile, operation)


@_admin_required
@_api_methods("POST")
def api_catalog_plan_create(request: HttpRequest, _identity) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error

    def operation() -> dict:
        software_id = _required_string(payload, "software_id", label="软件 ID", max_length=64).casefold()
        profile_id = _required_string(payload, "profile_id", label="Profile ID", max_length=64).casefold()
        policy_version = _required_string(payload, "policy_version", label="策略版本", max_length=64).casefold()
        name = _required_string(payload, "name", label="套餐名称", max_length=120)
        duration_seconds = _duration_seconds(payload)
        quota_cost = _integer(payload, "quota_cost", label="额度成本", minimum=0, default=0)
        test_only = _boolean(payload, "test_only", label="测试套餐标记", default=False)
        status = _status(payload, "status", allowed={"draft", "active", "archived"}, default="active")
        capability_values = _object(payload, "capability_values", label="套餐能力值")
        plan, snapshot = create_plan(
            actor=request.user,
            software_id=software_id,
            profile_id=profile_id,
            policy_version=policy_version,
            name=name,
            duration_seconds=duration_seconds,
            quota_cost=quota_cost,
            test_only=test_only,
            capability_values=capability_values,
            status=status,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        return {
            "plan": _plan_payload(plan),
            "snapshot": _snapshot_payload(snapshot),
            "request_id": _request_id(request),
            "_plan": plan,
            "_status": 201,
        }

    return _run_plan_create_idempotent(request, request.user, "plan-create", operation)


@_admin_required
@_api_methods("POST")
def api_catalog_plan_revise(request: HttpRequest, _identity, plan_id: str) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    try:
        numeric_plan_id = int(plan_id)
    except (TypeError, ValueError):
        return _error(request, "INVALID_REQUEST", "套餐标识不正确。", status=400)
    if not Plan.objects.filter(pk=numeric_plan_id).exists():
        return _error(request, "PLAN_NOT_FOUND", "套餐不存在。", status=400)

    def operation() -> dict:
        name = _required_string(payload, "name", label="套餐名称", max_length=120)
        duration_seconds = _duration_seconds(payload)
        quota_cost = _integer(payload, "quota_cost", label="额度成本", minimum=0, default=0)
        test_only = _boolean(payload, "test_only", label="测试套餐标记", default=False)
        capability_values = _object(payload, "capability_values", label="套餐能力值")
        try:
            current = Plan.objects.select_related("profile").get(pk=numeric_plan_id)
        except Plan.DoesNotExist as exc:
            raise CatalogOperationError("PLAN_NOT_FOUND", "套餐不存在。") from exc
        requested_status = payload.get("status")
        if requested_status is not None and requested_status not in PlanStatus.values:
            raise CatalogOperationError("INVALID_STATUS", "套餐状态不正确。")
        if requested_status is not None and requested_status != current.status:
            raise CatalogOperationError("PLAN_STATUS_USE_STATUS_API", "套餐归档或恢复请使用状态操作入口。")
        policy_version = payload.get("policy_version")
        if not isinstance(policy_version, str) or not policy_version.strip():
            latest = current.latest_snapshot
            policy_version = latest.policy_version.version if latest else ""
        plan, snapshot = revise_plan(
            actor=request.user,
            plan_id=numeric_plan_id,
            policy_version=policy_version,
            name=name,
            duration_seconds=duration_seconds,
            quota_cost=quota_cost,
            test_only=test_only,
            capability_values=capability_values,
            status=current.status,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        return {"plan": _plan_payload(plan), "snapshot": _snapshot_payload(snapshot), "request_id": _request_id(request)}

    return _run_plan_revision_idempotent(request, request.user, numeric_plan_id, operation)


@_admin_required
@_api_methods("POST")
def api_catalog_plan_status(request: HttpRequest, _identity, plan_id: str) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    try:
        numeric_plan_id = int(plan_id)
    except (TypeError, ValueError):
        return _error(request, "INVALID_REQUEST", "套餐标识不正确。", status=400)
    if not Plan.objects.filter(pk=numeric_plan_id).exists():
        return _error(request, "PLAN_NOT_FOUND", "套餐不存在。", status=404)

    def operation() -> dict:
        status = _status(payload, "status", allowed={PlanStatus.ACTIVE, PlanStatus.ARCHIVED}, default="archived")
        reason = _required_string(payload, "reason", label="操作原因", max_length=255)
        if len(reason) < 4:
            raise CatalogOperationError("INVALID_REASON", "操作原因必须是 4 至 255 个字符。")
        plan, changed = set_plan_status(
            actor=request.user,
            plan_id=numeric_plan_id,
            status=status,
            reason=reason,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        return {
            "plan": _plan_payload(plan),
            "changed": changed,
            "request_id": _request_id(request),
        }

    return _run_plan_lifecycle_idempotent(request, request.user, numeric_plan_id, "status", operation)


@_admin_required
@_api_methods("POST")
def api_catalog_plan_delete(request: HttpRequest, _identity, plan_id: str) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    try:
        numeric_plan_id = int(plan_id)
    except (TypeError, ValueError):
        return _error(request, "INVALID_REQUEST", "套餐标识不正确。", status=400)
    if not Plan.objects.filter(pk=numeric_plan_id).exists():
        return _error(request, "PLAN_NOT_FOUND", "套餐不存在。", status=404)

    def operation() -> dict:
        reason = _required_string(payload, "reason", label="操作原因", max_length=255)
        if len(reason) < 4:
            raise CatalogOperationError("INVALID_REASON", "操作原因必须是 4 至 255 个字符。")
        result = delete_plan(
            actor=request.user,
            plan_id=numeric_plan_id,
            reason=reason,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        return {
            "plan": _plan_payload(result.plan),
            "changed": result.changed,
            "invalidated": {
                "unused": result.unused_invalidated,
                "activated": result.activated_revoked,
                "already_invalid": result.already_invalid,
                "quota_refunded": result.quota_refunded,
            },
            "request_id": _request_id(request),
        }

    return _run_plan_lifecycle_idempotent(request, request.user, numeric_plan_id, "delete", operation)


@_admin_required
@_api_methods("POST")
def api_catalog_access(request: HttpRequest, _identity, downstream_public_id: str) -> JsonResponse:
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error
    try:
        public_id = uuid.UUID(str(downstream_public_id))
    except (ValueError, AttributeError, TypeError):
        return _error(request, "INVALID_REQUEST", "下游标识不正确。", status=400)

    try:
        software_id = _required_string(payload, "software_id", label="软件 ID", max_length=64).casefold()
    except CatalogOperationError as exc:
        return _error(request, exc.code, exc.message, status=400)

    def operation() -> dict:
        enabled = _boolean(payload, "enabled", label="开放状态")
        all_plans_allowed = _boolean(payload, "all_plans_allowed", label="套餐范围")
        raw_plan_ids = payload.get("allowed_plan_ids", [])
        if not isinstance(raw_plan_ids, list) or any(isinstance(item, bool) or not isinstance(item, int) for item in raw_plan_ids):
            raise CatalogOperationError("INVALID_REQUEST", "套餐范围必须是整数 ID 列表。")
        access = set_downstream_software_access(
            actor=request.user,
            downstream_public_id=public_id,
            software_id=software_id,
            enabled=enabled,
            all_plans_allowed=all_plans_allowed,
            allowed_plan_ids=raw_plan_ids,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
        access = DownstreamSoftware.objects.select_related("downstream__user").prefetch_related("allowed_plans").get(pk=access.pk)
        return {"access": _access_payload(access), "request_id": _request_id(request)}

    return _run_catalog_access_idempotent(request, request.user, public_id, software_id, operation)


@_downstream_required
@_api_methods("GET")
def api_downstream_catalog(request: HttpRequest, _identity) -> JsonResponse:
    return _success(_downstream_catalog_payload(request.user))


@_downstream_required
@_api_methods("GET", "POST")
def api_downstream_support(request: HttpRequest, identity, software_id: str) -> JsonResponse:
    """Read or update the current downstream's support override for one software."""
    profile = identity
    access = DownstreamSoftware.objects.select_related("software").filter(
        downstream=profile,
        software_id=software_id,
    ).first()
    if access is None:
        return _error(request, "ACCESS_NOT_FOUND", "当前下游还没有这个软件的经营范围。", status=404)

    if request.method == "GET":
        config = _downstream_support_payload(access)
        return _success({"software_id": software_id, "support": config})

    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error

    def execute():
        clear = bool(payload.get("clear"))
        values = None if clear else payload.get("values")
        if isinstance(values, dict):
            allowed = {"purchase_url", "qq", "wechat"}
            values = {key: values.get(key) for key in allowed if key in values}
            if any(not isinstance(value, str) for value in values.values()):
                raise CatalogOperationError("INVALID_REQUEST", "渠道字段必须是文本。")
        updated = update_downstream_configuration(
            actor=request.user,
            downstream_public_id=profile.public_id,
            software_id=software_id,
            values=values,
            clear=clear,
            request_id=_request_id(request),
            ip_address=request.META.get("REMOTE_ADDR") or None,
        )
        config = _downstream_support_payload(updated)
        return {"software_id": software_id, "support": config}

    return _run_configuration_idempotent(request, f"downstream:{profile.public_id}/{software_id}", execute)


def _downstream_support_payload(access: DownstreamSoftware) -> dict:
    return {
        "purchase_url": access.support_purchase_url or "",
        "qq": access.support_qq or "",
        "wechat": access.support_wechat or "",
        "config_version": access.config_version,
        "configuration_enabled": access.configuration_enabled,
    }

@_admin_required
@_api_methods("GET", "POST")
def api_manage_profile_configuration(
    request: HttpRequest, identity, software_id: str, profile_id: str
) -> JsonResponse:
    """Read or update one software Profile's default client configuration."""
    profile = SoftwareProfile.objects.filter(
        software_id=software_id, profile_id=profile_id
    ).first()
    if profile is None:
        return _error(request, "PROFILE_NOT_FOUND", "Profile 不存在。", status=404)
    if request.method == "GET":
        config = configuration_from_object(profile)
        return _success(
            {
                "software_id": software_id,
                "profile_id": profile_id,
                "configuration": config,
                "config_version": profile.config_version,
                "status": profile.status,
            }
        )
    payload, parse_error = _read_json(request)
    if parse_error:
        return parse_error

    def execute():
        clear = bool(payload.get("clear"))
        values = None if clear else payload.get("values")
        if not isinstance(values, dict):
            raise CatalogOperationError("INVALID_REQUEST", "values 必须是对象。")
        updated = update_profile_configuration(
            actor=request.user,
            profile=profile,
            values=values,
            request_id=_request_id(request),
            ip_address=request.META.get("REMOTE_ADDR") or None,
        )
        return {
            "software_id": software_id,
            "profile_id": profile_id,
            "configuration": configuration_from_object(updated),
            "config_version": updated.config_version,
            "status": updated.status,
        }

    return _run_configuration_idempotent(request, f"profile:{software_id}/{profile_id}", execute)

@_api_methods("GET")
@_admin_required
def api_manage_catalog_export(request: HttpRequest, identity) -> HttpResponse:
    import csv as csv_module
    import io

    from .models import Software

    softwares = Software.objects.prefetch_related("profiles", "plans__profile").order_by("name", "software_id")
    total = softwares.count()
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(csv_safe_row(["软件ID", "软件名称", "状态", "Profile数", "套餐数"]))
    for software in softwares[:1000]:
        writer.writerow(
            csv_safe_row([
                software.software_id,
                software.name,
                software.get_status_display(),
                len(list(software.profiles.all())),
                sum(plan.status != PlanStatus.DELETED for plan in software.plans.all()),
            ])
        )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="catalog.csv"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    if total > 1000:
        response["X-Export-Truncated"] = "1"
        response["X-Export-Total"] = str(total)
    return response
