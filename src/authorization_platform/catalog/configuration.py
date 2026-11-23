from __future__ import annotations

import uuid
from collections.abc import Mapping
from urllib.parse import urlsplit

from django.db import transaction

from authorization_platform.accounts.models import DownstreamStatus
from authorization_platform.accounts.services import get_downstream_profile, is_platform_admin, require_platform_admin
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .models import DownstreamSoftware, DownstreamSoftwareStatus, SoftwareProfile


CONFIGURATION_KEYS = frozenset(
    {
        "purchase_url",
        "qq",
        "wechat",
        "announcement_enabled",
        "announcement_title",
        "announcement_body",
    }
)

EMPTY_CONFIGURATION = {
    "purchase_url": "",
    "qq": "",
    "wechat": "",
    "announcement_enabled": False,
    "announcement_title": "",
    "announcement_body": "",
}


class ConfigurationOperationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def new_config_version() -> str:
    return f"cfg-{uuid.uuid4().hex[:24]}"


def _text(value, *, label: str, max_length: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigurationOperationError("INVALID_CONFIGURATION", f"{label}格式不正确。")
    value = value.strip()
    if len(value) > max_length or any(ord(char) < 32 and char not in "\t\n" for char in value):
        raise ConfigurationOperationError("INVALID_CONFIGURATION", f"{label}格式不正确。")
    return value


def _url(value) -> str:
    value = _text(value, label="购买链接", max_length=2048)
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ConfigurationOperationError("INVALID_CONFIGURATION_URL", "购买链接格式不正确。") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ConfigurationOperationError("INVALID_CONFIGURATION_URL", "购买链接只能使用不带账号密码的 HTTP 或 HTTPS 地址。")
    return value


def normalize_configuration(
    values: Mapping | None = None,
    *,
    purchase_url: str = "",
    qq: str = "",
    wechat: str = "",
    announcement_enabled: bool = False,
    announcement_title: str = "",
    announcement_body: str = "",
) -> dict:
    if values is not None:
        if not isinstance(values, Mapping) or set(values) - CONFIGURATION_KEYS:
            raise ConfigurationOperationError("INVALID_CONFIGURATION", "配置只允许已登记的类型化字段。")
        purchase_url = values.get("purchase_url", "")
        qq = values.get("qq", "")
        wechat = values.get("wechat", "")
        announcement_enabled = values.get("announcement_enabled", False)
        announcement_title = values.get("announcement_title", "")
        announcement_body = values.get("announcement_body", "")
    if not isinstance(announcement_enabled, bool):
        raise ConfigurationOperationError("INVALID_CONFIGURATION", "公告开关格式不正确。")
    normalized = {
        "purchase_url": _url(purchase_url),
        "qq": _text(qq, label="QQ", max_length=64),
        "wechat": _text(wechat, label="微信", max_length=64),
        "announcement_enabled": announcement_enabled,
        "announcement_title": _text(announcement_title, label="公告标题", max_length=120),
        "announcement_body": _text(announcement_body, label="公告内容", max_length=2000),
    }
    if normalized["announcement_enabled"] and not (
        normalized["announcement_title"] or normalized["announcement_body"]
    ):
        raise ConfigurationOperationError("INVALID_CONFIGURATION", "启用公告时请填写标题或内容。")
    return normalized


def configuration_from_object(obj) -> dict:
    return {
        "purchase_url": obj.support_purchase_url,
        "qq": obj.support_qq,
        "wechat": obj.support_wechat,
        "announcement_enabled": bool(obj.announcement_enabled),
        "announcement_title": obj.announcement_title,
        "announcement_body": obj.announcement_body,
    }


def _bump_profile_config_version(profile: SoftwareProfile) -> str:
    profile.config_version = new_config_version()
    profile.save(update_fields=("config_version", "updated_at"))
    return profile.config_version


def _configuration_response(values: Mapping) -> dict:
    support = {
        "purchase_url": values["purchase_url"] or None,
        "qq": values["qq"] or None,
        "wechat": values["wechat"] or None,
    }
    support_value = support if any(value is not None for value in support.values()) else None
    announcement = None
    if values["announcement_enabled"] and (
        values["announcement_title"] or values["announcement_body"]
    ):
        announcement = {
            "title": values["announcement_title"] or None,
            "body": values["announcement_body"] or None,
        }
    return {
        "support": support_value,
        "announcement": announcement,
        "purchase": None,
        "qr": None,
        "update": None,
        "modules": {
            "contact": support_value,
            "notice": announcement,
            "purchase": None,
            "qr": None,
            "update": None,
        },
    }


def _base_configuration_for_authorization(instance) -> tuple[dict, str]:
    profile = instance.profile
    values = configuration_from_object(profile)
    # 客户端渠道通知只跟发卡下游在下游页填的购买 URL / 联系方式；
    # Profile 里的同名字段不得顶上去。没填就是空。
    values["purchase_url"] = ""
    values["qq"] = ""
    values["wechat"] = ""
    config_version = profile.config_version
    access = DownstreamSoftware.objects.filter(
        downstream__public_id=instance.current_downstream_public_id,
        software_id=instance.software_id,
    ).first()
    if access and access.configuration_enabled:
        values = configuration_from_object(access)
        config_version = access.config_version
    return values, config_version


def effective_configuration_for_authorization(instance) -> dict:
    values, config_version = _base_configuration_for_authorization(instance)
    override = instance.configuration_override or {}
    if override:
        values.update(normalize_configuration(override))
        config_version = instance.config_version
    return {
        "config_version": config_version,
        **_configuration_response(values),
    }


def current_config_version(instance) -> str:
    if instance.configuration_override:
        return instance.config_version
    _, config_version = _base_configuration_for_authorization(instance)
    return config_version


def update_profile_configuration(*, actor, profile: SoftwareProfile, values: Mapping, request_id: str | None = None, ip_address: str | None = None) -> SoftwareProfile:
    require_platform_admin(actor)
    if not isinstance(values, Mapping) or set(values) - CONFIGURATION_KEYS:
        raise ConfigurationOperationError("INVALID_CONFIGURATION", "配置只允许已登记的类型化字段。")
    with transaction.atomic():
        locked = SoftwareProfile.objects.select_for_update().get(pk=profile.pk)
        merged = configuration_from_object(locked)
        for key in CONFIGURATION_KEYS:
            if key in values:
                merged[key] = values[key]
        normalized = normalize_configuration(merged)
        _bump_profile_config_version(locked)
        for field, value in normalized.items():
            setattr(locked, f"support_{field}" if field in {"purchase_url", "qq", "wechat"} else field, value)
        locked.save(
            update_fields=(
                "support_purchase_url",
                "support_qq",
                "support_wechat",
                "announcement_enabled",
                "announcement_title",
                "announcement_body",
                "updated_at",
            )
        )
        record_event(
            actor=actor,
            action="profile.configuration.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="SoftwareProfile",
            object_public_id=f"{locked.software_id}/{locked.profile_id}",
            metadata={"config_version": locked.config_version},
        )
    return locked


def _actor_can_update_access(actor, access: DownstreamSoftware) -> None:
    if is_platform_admin(actor):
        return
    profile = get_downstream_profile(actor)
    if (
        not profile
        or profile.status != DownstreamStatus.ACTIVE
        or not actor.is_active
        or profile.public_id != access.downstream.public_id
    ):
        raise ConfigurationOperationError("FORBIDDEN", "只能配置当前下游自己的软件信息。")
    if access.status != DownstreamSoftwareStatus.ACTIVE:
        raise ConfigurationOperationError("ACCESS_CLOSED", "该软件经营范围已关闭，不能继续修改配置。")


def update_downstream_configuration(*, actor, downstream_public_id, software_id: str, values: Mapping | None = None, clear: bool = False, request_id: str | None = None, ip_address: str | None = None) -> DownstreamSoftware:
    try:
        access = DownstreamSoftware.objects.select_related("downstream__user", "software").get(
            downstream__public_id=downstream_public_id,
            software_id=software_id,
        )
    except DownstreamSoftware.DoesNotExist as exc:
        raise ConfigurationOperationError("ACCESS_NOT_FOUND", "当前下游还没有这个软件的经营范围。") from exc
    _actor_can_update_access(actor, access)
    with transaction.atomic():
        access = DownstreamSoftware.objects.select_for_update().select_related("software").get(pk=access.pk)
        _actor_can_update_access(actor, access)
        if clear:
            normalized = dict(EMPTY_CONFIGURATION)
        else:
            incoming = values or {}
            if not isinstance(incoming, Mapping) or set(incoming) - CONFIGURATION_KEYS:
                raise ConfigurationOperationError("INVALID_CONFIGURATION", "配置只允许已登记的类型化字段。")
            merged = configuration_from_object(access)
            for key in CONFIGURATION_KEYS:
                if key in incoming:
                    merged[key] = incoming[key]
            normalized = normalize_configuration(merged)
        access.configuration_enabled = not clear
        access.config_version = new_config_version()
        for field, value in normalized.items():
            setattr(access, f"support_{field}" if field in {"purchase_url", "qq", "wechat"} else field, value)
        access.save(
            update_fields=(
                "configuration_enabled",
                "config_version",
                "support_purchase_url",
                "support_qq",
                "support_wechat",
                "announcement_enabled",
                "announcement_title",
                "announcement_body",
                "updated_at",
            )
        )
        record_event(
            actor=actor,
            action="downstream.configuration.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="DownstreamSoftware",
            object_public_id=f"{access.downstream.public_id}:{access.software.software_id}",
            metadata={"enabled": not clear, "config_version": access.config_version},
        )
    return access
