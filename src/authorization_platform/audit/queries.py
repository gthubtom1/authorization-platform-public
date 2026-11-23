from __future__ import annotations

import hashlib
from copy import copy
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db.models import CharField, Q, QuerySet, TextField
from django.db.models.functions import Cast
from django.db.models.fields.json import KeyTextTransform
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamTombstone
from authorization_platform.accounts.roles import is_platform_admin_user

from .models import AuditEvent, AuditOutcome


AUDIT_PAGE_SIZE = 50
AUDIT_MAX_PAGE_SIZE = 100
AUDIT_EXPORT_LIMIT = 1000

AUDIT_ACTION_LABELS = {
    "auth.login": "登录",
    "auth.logout": "退出",
    "admin.access": "访问管理端",
    "downstream.register": "下游注册",
    "downstream.archive": "归档下游",
    "authorization.signing_key.export": "导出验签公钥",
    "software.integration_config.export": "下载软件接入配置",
    "authorization.activate": "激活授权",
    "authorization.verify": "验证授权",
    "device.kicked": "挤掉旧设备",
    "authorization.export": "导出授权摘要",
    "license.activate": "激活授权",
    "license.verify": "验证授权",
    "license_card.search": "精确查找卡密",
    "license_card.reveal": "查看完整卡密",
    "license_card.reclaim": "回收未激活卡",
    "license_card.reclaim_preview": "预览回收",
    "license_card.export": "导出卡密摘要",
    "license_card.issue": "生成授权卡",
    "license_batch.issue": "生成授权卡",
    "license_batch.preview": "预览发卡",
    "license_batch.export": "导出卡密批次",
    "device.reset": "重置设备绑定",
    "quota_card.reveal": "查看完整兑换码",
    "quota_card.issue": "生成额度兑换码",
    "quota_card.redeem": "兑换额度",
    "quota_card.revoke": "作废额度码",
    "quota.settings.update": "保存购卡链接",
    "quota.manual_credit": "调整下游额度",
    "quota.admin_recovery": "扣回已删除下游余额",
    "quota.debit": "扣额度",
    "release.upload": "上传版本",
    "release.publish": "发布版本",
    "release.publish_link": "发布网盘更新",
    "release.update_link": "修改网盘地址",
    "release.withdraw": "撤回版本",
    "release.discard": "丢弃草稿",
    "release.package.delete": "删除安装包",
    "storage.cleanup": "清理可删文件",
    "audit.query": "查看审计",
    "audit.export": "导出审计",
    "backup.download.delete": "删除加密备份",
}


def _audit_query_action_codes(query: str) -> list[str]:
    text = str(query or "").strip()
    if not text:
        return []
    folded = text.casefold()
    return [
        action
        for action, label in AUDIT_ACTION_LABELS.items()
        if text in label or folded in action.casefold()
    ]


@dataclass(frozen=True)
class AuditMetadataItem:
    label: str
    value: str


@dataclass(frozen=True)
class AuditEventRow:
    event_id: str
    occurred_at: datetime
    actor_label: str
    actor_role_label: str
    action: str
    outcome_label: str
    object_type: str
    object_public_id: str
    object_label: str
    object_summary: str
    request_id: str
    ip_address: str
    reason_code: str
    metadata_items: tuple[AuditMetadataItem, ...]


VISIBLE_METADATA = {
    "action": "动作",
    "admin_action_denied": "管理员动作被拒",
    "all_plans_allowed": "允许全部套餐",
    "amount": "额度",
    "authorization_revision": "授权版本",
    "balance_after": "变更后余额",
    "balance_before": "变更前余额",
    "card_count": "卡密数量",
    "card_digest": "卡密摘要",
    "config_version": "配置版本",
    "decision": "决定",
    "device_id": "平台设备 UUID",
    "direction": "方向",
    "duration_seconds": "有效秒数",
    "enabled": "已启用",
    "from_status": "原状态",
    "includes_plaintext": "包含明文",
    "installation_id": "客户端设备码",
    "ledger_entry_id": "额度流水 ID",
    "operation_type": "额度动作",
    "plan_count": "套餐数量",
    "profile_id": "Profile",
    "quantity": "数量",
    "quota_cost": "额度成本",
    "quota_ledger_entry_id": "额度流水 ID",
    "rate_scope": "限速范围",
    "reason_length": "原因长度",
    "repeated": "重复请求",
    "retryable": "可重试",
    "snapshot_id": "快照 ID",
    "snapshot_version": "快照版本",
    "software_id": "软件 ID",
    "source_type": "来源类型",
    "state": "状态",
    "status": "状态",
    "test_only": "测试套餐",
    "to_status": "新状态",
    "username_digest": "用户名摘要",
    "authorization_id": "授权实例 ID",
    "downstream_public_id": "下游公开 ID",
    "target_downstream_public_id": "目标下游公开 ID",
    "current_downstream_public_id": "当前下游公开 ID",
    "original_downstream_public_id": "原下游公开 ID",
}


def _local_day_start(value) -> datetime:
    local_zone = timezone.get_current_timezone()
    return timezone.make_aware(datetime.combine(value, time.min), local_zone)


def _filtered_queryset(filters: dict[str, Any]) -> QuerySet:
    queryset = AuditEvent.objects.select_related("actor").all()
    if filters.get("from_date"):
        queryset = queryset.filter(occurred_at__gte=_local_day_start(filters["from_date"]))
    if filters.get("to_date"):
        queryset = queryset.filter(occurred_at__lt=_local_day_start(filters["to_date"] + timedelta(days=1)))
    if filters.get("action"):
        queryset = queryset.filter(action=filters["action"])
    if filters.get("outcome"):
        queryset = queryset.filter(outcome=filters["outcome"])
    if filters.get("actor_role"):
        queryset = queryset.filter(actor_role=filters["actor_role"])
    if filters.get("actor_id"):
        queryset = queryset.filter(actor_id=filters["actor_id"])
    if filters.get("downstream_public_id"):
        value = str(filters["downstream_public_id"])
        owned = (
            Q(metadata__downstream_public_id=value)
            | Q(metadata__current_downstream_public_id=value)
            | Q(metadata__original_downstream_public_id=value)
            | Q(metadata__target_downstream_public_id=value)
            | Q(object_type="DownstreamProfile", object_public_id=value)
        )
        from authorization_platform.licensing.models import LicenseInstance

        owned |= Q(
            object_type="LicenseInstance",
            object_public_id__in=_subquery_ids(
                LicenseInstance.objects.filter(current_downstream_public_id=value),
                "authorization_id",
            ),
        )
        queryset = queryset.filter(owned)
    if filters.get("software_id"):
        queryset = queryset.filter(metadata__software_id=str(filters["software_id"]))
    if filters.get("object_type"):
        queryset = queryset.filter(object_type=filters["object_type"])
    if filters.get("object_public_id"):
        queryset = queryset.filter(object_public_id=filters["object_public_id"])
    query = str(filters.get("q") or "").strip()
    if query:
        query_filter = (
            Q(action__icontains=query)
            | Q(object_type__icontains=query)
            | Q(object_public_id__icontains=query)
            | Q(actor__username__icontains=query)
            | Q(reason_code__icontains=query)
            | Q(metadata__installation_id__icontains=query)
            | Q(metadata__downstream_public_id__icontains=query)
            | Q(metadata__current_downstream_public_id__icontains=query)
            | Q(metadata__original_downstream_public_id__icontains=query)
            | Q(metadata__target_downstream_public_id__icontains=query)
        )
        from authorization_platform.licensing.models import Device

        device_ids = [
            str(value)
            for value in Device.objects.filter(
                Q(installation_id__icontains=query) | Q(device_code__icontains=query)
            ).values_list("public_id", flat=True)
        ]
        if device_ids:
            query_filter |= Q(metadata__device_id__in=device_ids)
            query_filter |= Q(object_type="Device", object_public_id__in=device_ids)
        action_codes = _audit_query_action_codes(query)
        if action_codes:
            query_filter |= Q(action__in=action_codes)
        queryset = queryset.filter(query_filter)
    return queryset


def _stringify_ids(queryset, field: str) -> list[str]:
    return [str(value) for value in queryset.values_list(field, flat=True) if value is not None]


def _subquery_ids(queryset, field: str):
    from django.db import connection

    if connection.vendor == "sqlite":
        return [str(value) for value in queryset.values_list(field, flat=True) if value is not None]
    return queryset.annotate(_casted_id=Cast(field, CharField(max_length=64))).values("_casted_id")


def _downstream_visible_queryset(queryset: QuerySet, profile: DownstreamProfile) -> QuerySet:
    """SQL-side ownership: actor, metadata keys, and object IDs belonging to this downstream."""

    from authorization_platform.credits.models import QuotaAccount, QuotaCard, QuotaCardBatch, QuotaLedgerEntry
    from authorization_platform.licensing.models import DeviceBinding, LicenseCard, LicenseCardBatch, LicenseInstance

    profile_id = str(profile.public_id)
    owned = Q(actor_id=profile.user_id)
    owned |= Q(metadata__downstream_public_id=profile_id)
    owned |= Q(metadata__target_downstream_public_id=profile_id)
    owned |= Q(metadata__current_downstream_public_id=profile_id)
    owned |= Q(metadata__original_downstream_public_id=profile_id)
    owned |= Q(object_type="DownstreamProfile", object_public_id=profile_id)
    owned |= Q(object_type="DownstreamSoftware", object_public_id__startswith=f"{profile_id}:")

    owned |= Q(
        object_type="QuotaAccount",
        object_public_id__in=_subquery_ids(
            QuotaAccount.objects.filter(downstream_public_id=profile.public_id),
            "public_id",
        ),
    )
    owned |= Q(
        object_type="QuotaLedgerEntry",
        object_public_id__in=_subquery_ids(
            QuotaLedgerEntry.objects.filter(downstream_public_id=profile.public_id),
            "public_id",
        ),
    )
    owned |= Q(
        object_type="QuotaCardBatch",
        object_public_id__in=_subquery_ids(
            QuotaCardBatch.objects.filter(target_downstream_public_id=profile.public_id),
            "public_id",
        ),
    )
    owned |= Q(
        object_type="QuotaCard",
        object_public_id__in=_subquery_ids(
            QuotaCard.objects.filter(
                Q(target_downstream_public_id=profile.public_id) | Q(redeemed_by_public_id=profile.public_id)
            ),
            "public_id",
        ),
    )
    owned |= Q(
        object_type="LicenseCardBatch",
        object_public_id__in=_subquery_ids(
            LicenseCardBatch.objects.filter(
                Q(current_downstream_public_id=profile.public_id) | Q(original_downstream_public_id=profile.public_id)
            ),
            "batch_id",
        ),
    )
    owned |= Q(
        object_type="LicenseCard",
        object_public_id__in=_subquery_ids(
            LicenseCard.objects.filter(
                Q(current_downstream_public_id=profile.public_id) | Q(original_downstream_public_id=profile.public_id)
            ),
            "public_id",
        ),
    )
    owned |= Q(
        object_type="LicenseInstance",
        object_public_id__in=_subquery_ids(
            LicenseInstance.objects.filter(current_downstream_public_id=profile.public_id),
            "authorization_id",
        ),
    )
    owned |= Q(
        object_type="Device",
        object_public_id__in=_subquery_ids(
            DeviceBinding.objects.filter(authorization__current_downstream_public_id=profile.public_id),
            "device_id",
        ),
    )
    owned |= Q(
        object_type="DeviceKey",
        object_public_id__in=_subquery_ids(
            DeviceBinding.objects.filter(authorization__current_downstream_public_id=profile.public_id),
            "device_key_id",
        ),
    )

    events = queryset.filter(owned)
    # Historical use of a physical device grants visibility of device-wide
    # events, not events for another reseller's authorization on that device.
    own_authorizations = _subquery_ids(
        LicenseInstance.objects.filter(current_downstream_public_id=profile.public_id),
        "authorization_id",
    )
    # Cast the extraction to a plain text expression. KeyTextTransform still
    # inherits JSON's IN lookup, which reparses bare UUID parameters as JSON on
    # SQLite; the comparison here is between authorization ID strings.
    return events.annotate(
        _event_authorization_id=Cast(KeyTextTransform("authorization_id", "metadata"), TextField())
    ).filter(
        ~Q(object_type__in=["Device", "DeviceKey"])
        | ~Q(metadata__has_key="authorization_id")
        | Q(metadata__authorization_id="")
        | Q(metadata__authorization_id__isnull=True)
        | Q(_event_authorization_id__in=own_authorizations)
    )


def audit_events_for_user(*, user, filters: dict[str, Any]) -> QuerySet:
    queryset = _filtered_queryset(filters)
    if is_platform_admin_user(user):
        return queryset
    profile = DownstreamProfile.objects.filter(user=user).only("public_id", "user_id").first()
    if not profile:
        return AuditEvent.objects.none()
    return _downstream_visible_queryset(queryset, profile)


def paginate_audit_events(
    events: QuerySet | list[AuditEvent],
    page_number: str | int | None,
    page_size: int | None = None,
):
    size = page_size or AUDIT_PAGE_SIZE
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = AUDIT_PAGE_SIZE
    size = min(max(size, 1), AUDIT_MAX_PAGE_SIZE)
    return Paginator(events, size).get_page(page_number or 1)


def _safe_value(value: Any) -> str:
    if isinstance(value, bool):
        return "是" if value else "否"
    if value is None:
        return "空"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value[:128]
    return "已记录"


def _metadata_items(metadata: Any) -> tuple[AuditMetadataItem, ...]:
    if not isinstance(metadata, dict):
        return ()
    items = []
    for key, label in VISIBLE_METADATA.items():
        if key in metadata:
            items.append(AuditMetadataItem(label=label, value=_safe_value(metadata[key])))
    return tuple(items)


def _redact_request_id(value: str) -> str:
    if not value:
        return "未提供"
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _object_summary(event: AuditEvent) -> str:
    object_id = event.object_public_id
    if not event.object_type or not object_id:
        return "无对象引用"
    metadata = event.metadata if isinstance(event.metadata, dict) else {}
    parts = [str(event.object_type)]
    for key in (
        "software_id",
        "profile_id",
        "from_status",
        "to_status",
        "state",
        "status",
        "operation_type",
        "amount",
        "quota_cost",
        "quantity",
    ):
        value = metadata.get(key)
        if value in (None, ""):
            continue
        if key == "amount":
            parts.append(f"{value} 额度")
        elif key == "quota_cost":
            parts.append(f"成本 {value}")
        elif key == "quantity":
            parts.append(f"{value} 张")
        else:
            parts.append(str(value))
    return " · ".join(parts)


def _event_metadata(event: AuditEvent) -> dict[str, Any]:
    return event.metadata if isinstance(event.metadata, dict) else {}


def _event_installation_id(event: AuditEvent) -> str:
    metadata = _event_metadata(event)
    value = metadata.get("installation_id")
    if isinstance(value, str) and value.strip():
        from authorization_platform.licensing.device_codes import compact_device_code

        return (compact_device_code(value) or value.strip())[:128]
    device_id = metadata.get("device_id")
    if not device_id:
        return ""
    from authorization_platform.licensing.device_codes import compact_device_code
    from authorization_platform.licensing.models import Device

    try:
        device = Device.objects.filter(public_id=device_id).first()
    except (TypeError, ValueError, ValidationError):
        return ""
    if device is None:
        return ""
    return (
        str(device.device_code or compact_device_code(device.installation_id) or "").strip()[:128]
    )


def _event_downstream_public_id(event: AuditEvent) -> str:
    metadata = _event_metadata(event)
    # The recorded authorization is authoritative for a shared physical device.
    # Never attribute its historical events to the latest device binding.
    if metadata.get("authorization_id"):
        from authorization_platform.licensing.models import LicenseInstance

        try:
            value = LicenseInstance.objects.filter(authorization_id=str(metadata["authorization_id"])).values_list(
                "current_downstream_public_id", flat=True
            ).first()
            return str(value) if value else ""
        except (TypeError, ValueError, ValidationError):
            return ""
    for key in (
        "downstream_public_id",
        "current_downstream_public_id",
        "original_downstream_public_id",
        "target_downstream_public_id",
    ):
        value = metadata.get(key)
        if value:
            return str(value)
    if event.object_type == "DownstreamProfile" and event.object_public_id:
        return str(event.object_public_id)

    from authorization_platform.licensing.models import LicenseCard, LicenseCardBatch, LicenseInstance

    try:
        if event.object_type == "LicenseInstance" and event.object_public_id:
            value = LicenseInstance.objects.filter(authorization_id=event.object_public_id).values_list(
                "current_downstream_public_id", flat=True
            ).first()
            if value:
                return str(value)
        if event.object_type == "LicenseCard" and event.object_public_id:
            value = LicenseCard.objects.filter(public_id=event.object_public_id).values_list(
                "current_downstream_public_id", flat=True
            ).first()
            if value:
                return str(value)
        if event.object_type == "LicenseCardBatch" and event.object_public_id:
            value = LicenseCardBatch.objects.filter(batch_id=event.object_public_id).values_list(
                "current_downstream_public_id", flat=True
            ).first()
            if value:
                return str(value)
        if event.action == "authorization.activate" and metadata.get("card_digest"):
            value = LicenseCard.objects.filter(card_hash=str(metadata["card_digest"])).values_list(
                "current_downstream_public_id", flat=True
            ).first()
            if value:
                return str(value)
    except (TypeError, ValueError, ValidationError):
        return ""
    return ""


def _event_downstream_label(event: AuditEvent) -> str:
    downstream_public_id = _event_downstream_public_id(event)
    if not downstream_public_id:
        return ""
    try:
        DownstreamProfile._meta.get_field("public_id").get_prep_value(downstream_public_id)
        username = DownstreamProfile.objects.filter(public_id=downstream_public_id).values_list("user__username", flat=True).first()
    except (TypeError, ValueError, ValidationError):
        return ""
    if username:
        return str(username)
    if DownstreamTombstone.objects.filter(public_id=downstream_public_id).exists():
        return "已归档下游"
    return ""


def _downstream_projection(event: AuditEvent, public_id) -> AuditEvent:
    """Project shared rows for the current viewer without rewriting audit facts."""
    from authorization_platform.licensing.models import LicenseInstance

    projected = copy(event)
    metadata = dict(_event_metadata(event))
    own_id = str(public_id)
    for key in ("downstream_public_id", "current_downstream_public_id", "original_downstream_public_id", "target_downstream_public_id"):
        if key in metadata and str(metadata[key]) != own_id:
            metadata.pop(key)
    authorization_id = metadata.get("authorization_id")
    if authorization_id:
        try:
            own = LicenseInstance.objects.filter(authorization_id=str(authorization_id), current_downstream_public_id=public_id).exists()
        except (TypeError, ValueError, ValidationError):
            own = False
        if not own:
            metadata.pop("authorization_id", None)
    if event.object_type in {"Device", "DeviceKey"}:
        # A generic device event has no single downstream owner.
        for key in ("downstream_public_id", "current_downstream_public_id", "original_downstream_public_id", "target_downstream_public_id"):
            metadata.pop(key, None)
    projected.metadata = metadata
    return projected


def present_event(event: AuditEvent, *, downstream: bool = False, downstream_public_id=None) -> AuditEventRow:
    if downstream and downstream_public_id is not None:
        event = _downstream_projection(event, downstream_public_id)
    installation_id = _event_installation_id(event)
    client_event = event.actor_id is None and event.action.startswith("authorization.")
    actor_label = "平台操作"
    if event.actor_id and event.actor:
        actor_label = "当前下游" if downstream else event.actor.get_username()
    elif client_event:
        actor_label = installation_id or "客户端请求"
    outcome_label = dict(AuditOutcome.choices).get(event.outcome, event.outcome)
    actor_role = "client_device" if client_event else event.actor_role
    object_summary = _object_summary(event)
    if client_event and object_summary == "无对象引用":
        object_summary = "客户端授权请求"
    object_label = _event_downstream_label(event)
    if downstream and downstream_public_id is not None and _event_downstream_public_id(event) != str(downstream_public_id):
        object_label = ""
    if not object_label:
        object_label = "未匹配下游" if client_event else object_summary
    return AuditEventRow(
        event_id=str(event.public_id),
        occurred_at=timezone.localtime(event.occurred_at),
        actor_label=actor_label,
        actor_role_label={"platform_admin": "平台管理员", "downstream": "下游", "anonymous": "匿名", "client_device": "客户端设备", "unknown": "未知"}.get(
            actor_role, actor_role
        ),
        action=event.action,
        outcome_label=outcome_label,
        object_type=event.object_type or "—",
        object_public_id=event.object_public_id or "—",
        object_label=object_label,
        object_summary=object_summary,
        request_id=_redact_request_id(event.request_id),
        ip_address=event.ip_address or "未记录",
        reason_code=event.reason_code or "—",
        metadata_items=_metadata_items(event.metadata),
    )
