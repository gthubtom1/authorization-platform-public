from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

from django.db.models import Case, F, IntegerField, Q, QuerySet, Sum, Value, When
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamTombstone
from authorization_platform.accounts.services import get_downstream_profile
from authorization_platform.catalog.models import Software
from authorization_platform.credits.models import QuotaAccount, QuotaLedgerDirection, QuotaLedgerEntry, QuotaLedgerOperation
from authorization_platform.licensing.models import AuthorizationState, Device, LicenseCard, LicenseCardBatch, LicenseCardStatus, LicenseInstance
from authorization_platform.audit.models import AuditEvent, AuditOutcome


LOCAL_TIMEZONE = ZoneInfo("Asia/Shanghai")


class AnalyticsQueryError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _local_midnight(value: date) -> datetime:
    return timezone.make_aware(datetime.combine(value, time.min), LOCAL_TIMEZONE)


def _range_for_window(window: str) -> tuple[datetime, datetime, date, date]:
    window = (window or "7d").strip().lower()
    today = timezone.localdate(timezone=LOCAL_TIMEZONE)
    if window == "7d":
        start = today - timedelta(days=6)
        end = today + timedelta(days=1)
    elif window == "30d":
        start = today - timedelta(days=29)
        end = today + timedelta(days=1)
    elif window == "empty":
        start = today + timedelta(days=3650)
        end = start + timedelta(days=1)
    else:
        raise AnalyticsQueryError("INVALID_WINDOW", "统计时间范围不正确。")
    return _local_midnight(start), _local_midnight(end), start, end


def _parse_uuid(value: str, label: str):
    import uuid

    try:
        return uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise AnalyticsQueryError("INVALID_FILTER", f"{label}筛选条件不正确。") from exc


def _software_filter(*, actor, role: str, value: str | None) -> tuple[Software | None, list[Software]]:
    if role == "downstream":
        profile = get_downstream_profile(actor)
        if not profile:
            raise AnalyticsQueryError("FORBIDDEN", "当前下游账号不存在。", status=403)
        allowed = list(
            Software.objects.filter(
                downstream_accesses__downstream=profile,
                downstream_accesses__status="active",
                status__in=("active", "testing"),
            ).distinct().order_by("name", "software_id")
        )
    else:
        allowed = list(Software.objects.all().order_by("name", "software_id"))
    if not value or value == "all":
        return None, allowed
    software = next((item for item in allowed if item.software_id == value), None)
    if software is None:
        raise AnalyticsQueryError("SOFTWARE_NOT_ALLOWED", "当前账号不能查看该软件统计。", status=403 if role == "downstream" else 404)
    return software, allowed


DELETED_DOWNSTREAM_ID = "deleted"


@dataclass(frozen=True)
class DownstreamScope:
    """Which downstream rows a statistic covers.

    ``None`` means "no downstream filter".  A deleted downstream still owns the
    cards it issued: deleting the profile only nulls the foreign key, while the
    bare ``*_public_id`` column survives on the card row.  Dropping those rows
    from the breakdown made the management total silently larger than the sum of
    the listed downstreams, so they get their own bucket instead.
    """

    profile: DownstreamProfile | None = None
    deleted_public_ids: tuple = ()

    @property
    def public_ids(self) -> list | None:
        if self.profile is not None:
            return [self.profile.public_id]
        if self.deleted_public_ids:
            return list(self.deleted_public_ids)
        return None


def _downstream_filter(*, actor, role: str, value: str | None) -> tuple[DownstreamScope, list[dict[str, str]]]:
    if role == "downstream":
        profile = get_downstream_profile(actor)
        if not profile:
            raise AnalyticsQueryError("FORBIDDEN", "当前下游账号不存在。", status=403)
        return DownstreamScope(profile=profile), [{"id": str(profile.public_id), "name": profile.user.username}]
    allowed = list(DownstreamProfile.objects.select_related("user").order_by("user__username"))
    options = [{"id": str(item.public_id), "name": item.user.username} for item in allowed]
    deleted_ids = tuple(DownstreamTombstone.objects.order_by("-deleted_at").values_list("public_id", flat=True))
    if value == DELETED_DOWNSTREAM_ID:
        if not deleted_ids:
            raise AnalyticsQueryError("DOWNSTREAM_NOT_FOUND", "没有已删除的下游。", status=404)
        return DownstreamScope(deleted_public_ids=deleted_ids), options
    if not value or value == "all":
        if deleted_ids:
            options.append(
                {"id": DELETED_DOWNSTREAM_ID, "name": f"已删除下游（{len(deleted_ids)} 个）"}
            )
        return DownstreamScope(), options
    public_id = _parse_uuid(value, "下游")
    profile = next((item for item in allowed if item.public_id == public_id), None)
    if profile is None:
        raise AnalyticsQueryError("DOWNSTREAM_NOT_FOUND", "下游不存在。", status=404)
    return DownstreamScope(profile=profile), options


def _apply_card_scope(queryset: QuerySet, *, software: Software | None, downstream: DownstreamScope | None):
    if software is not None:
        queryset = queryset.filter(software=software)
    public_ids = downstream.public_ids if downstream is not None else None
    if public_ids is not None:
        queryset = queryset.filter(original_downstream_public_id__in=public_ids)
    return queryset


def _apply_instance_scope(queryset: QuerySet, *, software: Software | None, downstream: DownstreamScope | None):
    if software is not None:
        queryset = queryset.filter(software=software)
    public_ids = downstream.public_ids if downstream is not None else None
    if public_ids is not None:
        queryset = queryset.filter(current_downstream_public_id__in=public_ids)
    return queryset


def _apply_device_scope(queryset: QuerySet, *, software: Software | None, downstream: DownstreamScope | None):
    if software is not None:
        queryset = queryset.filter(software=software)
    public_ids = downstream.public_ids if downstream is not None else None
    if public_ids is not None:
        queryset = queryset.filter(authorization_bindings__authorization__current_downstream_public_id__in=public_ids)
    return queryset.distinct()


def _apply_ledger_scope(queryset: QuerySet, *, software: Software | None, downstream: DownstreamScope | None):
    public_ids = downstream.public_ids if downstream is not None else None
    if public_ids is not None:
        queryset = queryset.filter(downstream_public_id__in=public_ids)
    production_shape = Q(
        operation_type=QuotaLedgerOperation.LICENSE_CARD_ISSUE,
        source_type="LicenseCardBatch",
    ) | Q(
        operation_type=QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
        source_type="LicenseCard",
    )
    if software is None:
        return queryset.filter(production_shape)
    issue_ids = [str(value) for value in LicenseCardBatch.objects.filter(software=software).values_list("batch_id", flat=True)]
    reclaim_ids = [str(value) for value in LicenseCard.objects.filter(software=software).values_list("public_id", flat=True)]
    if not issue_ids and not reclaim_ids:
        return queryset.none()
    return queryset.filter(
        Q(
            operation_type=QuotaLedgerOperation.LICENSE_CARD_ISSUE,
            source_type="LicenseCardBatch",
            source_public_id__in=issue_ids,
        )
        | Q(
            operation_type=QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
            source_type="LicenseCard",
            source_public_id__in=reclaim_ids,
        )
    )


def _sum_card_revenue(*, software: Software | None, downstream: DownstreamScope | None, start: datetime | None = None, end: datetime | None = None) -> int:
    cards = LicenseCard.objects.filter(activated_at__isnull=False)
    cards = _apply_card_scope(cards, software=software, downstream=downstream)
    if start is not None:
        cards = cards.filter(activated_at__gte=start)
    if end is not None:
        cards = cards.filter(activated_at__lt=end)
    return int(cards.aggregate(total=Sum("quota_cost"))["total"] or 0)


def _date_key(value: datetime) -> date:
    return timezone.localtime(value, LOCAL_TIMEZONE).date()


def build_summary(*, actor, role: str, software_id: str | None, downstream_id: str | None, window: str) -> dict[str, Any]:
    start, end, start_date, end_date = _range_for_window(window)
    software, software_options = _software_filter(actor=actor, role=role, value=software_id)
    downstream, downstream_options = _downstream_filter(actor=actor, role=role, value=downstream_id)
    # The scope returned above already carries the caller's own profile for a
    # downstream role; re-deriving it here used to overwrite the scope with a
    # bare DownstreamProfile and silently drop the deleted-downstream bucket.

    cards_in_range = _apply_card_scope(
        LicenseCard.objects.filter(activated_at__isnull=False, activated_at__gte=start, activated_at__lt=end),
        software=software,
        downstream=downstream,
    )
    all_cards_in_range = _apply_card_scope(
        LicenseCard.objects.filter(issued_at__gte=start, issued_at__lt=end),
        software=software,
        downstream=downstream,
    )
    instances = _apply_instance_scope(
        LicenseInstance.objects.filter(state__in=(AuthorizationState.ACTIVE, AuthorizationState.GRACE), expires_at__gt=timezone.now()),
        software=software,
        downstream=downstream,
    )
    audits = AuditEvent.objects.filter(action="authorization.activate", occurred_at__gte=start, occurred_at__lt=end)
    if software is not None:
        audits = audits.filter(metadata__software_id=software.software_id)
    public_ids = downstream.public_ids if downstream is not None else None
    if public_ids is not None:
        audits = audits.filter(metadata__downstream_public_id__in=[str(value) for value in public_ids])
    ledger = _apply_ledger_scope(
        QuotaLedgerEntry.objects.filter(occurred_at__gte=start, occurred_at__lt=end, operation_type__in=(QuotaLedgerOperation.LICENSE_CARD_ISSUE, QuotaLedgerOperation.LICENSE_CARD_RECLAIM)),
        software=software,
        downstream=downstream,
    )
    devices = _apply_device_scope(Device.objects.filter(risk_state="blocked", last_seen_at__lt=end), software=software, downstream=downstream)
    frozen_cards = _apply_instance_scope(
        LicenseInstance.objects.filter(state=AuthorizationState.BLOCKED),
        software=software,
        downstream=downstream,
    )

    success_count = audits.filter(outcome=AuditOutcome.SUCCESS).count()
    failure_count = audits.filter(outcome=AuditOutcome.FAILURE).count()
    attempts = success_count + failure_count
    activation_success_rate = round(success_count * 100 / attempts, 1) if attempts else None
    totals = ledger.aggregate(
        debit=Sum(Case(When(direction=QuotaLedgerDirection.DEBIT, then=F("amount")), default=Value(0), output_field=IntegerField())),
        credit=Sum(Case(When(direction=QuotaLedgerDirection.CREDIT, then=F("amount")), default=Value(0), output_field=IntegerField())),
    )
    quota_net_consumed = int((totals["debit"] or 0) - (totals["credit"] or 0))

    trend = {start_date + timedelta(days=index): {"date": (start_date + timedelta(days=index)).isoformat(), "revenue": 0, "activations": 0, "attempts": 0} for index in range((end_date - start_date).days)}
    for row in cards_in_range.values("activated_at", "quota_cost"):
        bucket = trend.get(_date_key(row["activated_at"]))
        if bucket is not None:
            bucket["revenue"] += int(row["quota_cost"])
            bucket["activations"] += 1
    for row in audits.values("occurred_at", "outcome"):
        bucket = trend.get(_date_key(row["occurred_at"]))
        if bucket is not None:
            bucket["attempts"] += 1

    breakdown = defaultdict(lambda: {"software_id": "", "software_name": "", "revenue": 0, "activations": 0})
    for row in cards_in_range.values("software_id", "software__name", "quota_cost"):
        item = breakdown[row["software_id"]]
        item["software_id"] = row["software_id"]
        item["software_name"] = row["software__name"]
        item["revenue"] += int(row["quota_cost"])
        item["activations"] += 1

    today = timezone.localdate(timezone=LOCAL_TIMEZONE)
    month_start = today.replace(day=1)
    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
    revenue = {
        "today": _sum_card_revenue(software=software, downstream=downstream, start=_local_midnight(today), end=_local_midnight(today + timedelta(days=1))),
        "month": _sum_card_revenue(software=software, downstream=downstream, start=_local_midnight(month_start), end=_local_midnight(next_month)),
        "total": _sum_card_revenue(software=software, downstream=downstream),
    }
    window_activity = bool(cards_in_range.exists() or all_cards_in_range.exists() or audits.exists() or ledger.exists() or devices.exists())
    has_data = False if window == "empty" else bool(window_activity or instances.exists() or revenue["total"])
    filters = {
        "software": [{"id": item.software_id, "name": item.name} for item in software_options],
        # Options already carry the deleted-downstream bucket so the management
        # total stays equal to the sum of everything the page lets you click.
        "downstream": downstream_options,
    }
    result = {
        "revenue": revenue,
        "active_authorizations": instances.count(),
        "activation_success_rate": activation_success_rate,
        "quota_net_consumed": quota_net_consumed,
        "risk_pending": devices.count() + frozen_cards.count(),
        "has_data": has_data,
        "window": window,
        "range": {"from": start_date.isoformat(), "to": (end_date - timedelta(days=1)).isoformat()},
        "timezone": str(LOCAL_TIMEZONE),
        "generated_at": timezone.now().isoformat(),
        "trend": list(trend.values()),
        "software_breakdown": list(breakdown.values()),
        "filters": filters,
    }
    if role == "downstream":
        own_profile = downstream.profile
        account = QuotaAccount.objects.filter(downstream_public_id=own_profile.public_id).first() if own_profile else None
        reclaimable = _apply_card_scope(LicenseCard.objects.filter(status=LicenseCardStatus.UNUSED), software=software, downstream=downstream).count()
        issued = _apply_card_scope(
            LicenseCard.objects.exclude(status=LicenseCardStatus.DELETED_TOMBSTONE),
            software=software,
            downstream=downstream,
        ).count()
        result["downstream"] = {
            "balance": account.available_balance if account else 0,
            "active": instances.count(),
            "issued": issued,
            "reclaimable": reclaimable,
        }
    return result
