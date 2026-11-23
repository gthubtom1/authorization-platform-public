from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, time, timedelta
from functools import wraps
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone

from authorization_platform.accounts.api_views import (
    _api_methods,
    _error,
    _read_json,
    _role_for_request,
    _success,
)
from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.core.csv_utils import csv_safe_row
from authorization_platform.core.time import format_beijing_wall_clock

from .models import (
    QuotaAccount,
    QuotaCard,
    QuotaCardStatus,
    QuotaLedgerDirection,
    QuotaLedgerEntry,
    QuotaLedgerOperation,
)
from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus

from .services import (
    QuotaOperationError,
    archive_quota_cards,
    credit_quota,
    decrypt_quota_card,
    delete_quota_cards,
    get_quota_account,
    get_quota_platform_settings,
    issue_quota_card_batch,
    normalize_quota_card_code,
    quota_card_hash,
    redeem_quota_card,
    recover_deleted_downstream_credits,
    recover_downstream_credits,
    reveal_quota_card,
    revoke_quota_card,
    update_quota_purchase_url,
)


MAX_JSON_BODY = 32 * 1024
DEFAULT_PAGE_SIZE = 5
MAX_PAGE_SIZE = 100
EXPORT_LIMIT = 1000
_BEIJING = ZoneInfo("Asia/Shanghai")


def _beijing_today_range():
    now = timezone.now().astimezone(_BEIJING)
    start = datetime.combine(now.date(), time.min, tzinfo=_BEIJING)
    return start, start + timedelta(days=1)


def _csv_export_response(
    *,
    request: HttpRequest,
    identity,
    filename: str,
    header: list[str],
    rows: list[list],
    action: str,
    total: int,
) -> HttpResponse:
    import csv as csv_module
    import io

    truncated = total > EXPORT_LIMIT
    output = io.StringIO(newline="")
    writer = csv_module.writer(output)
    writer.writerow(csv_safe_row(header))
    for row in rows:
        writer.writerow(csv_safe_row(row))
    record_event(
        actor=identity,
        action=action,
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        metadata={"exported": len(rows), "total": total, "truncated": truncated, "filename": filename},
    )
    response = HttpResponse("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, private"
    if truncated:
        response["X-Export-Truncated"] = "1"
        response["X-Export-Total"] = str(total)
    return response


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied.encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _read_json_local(request: HttpRequest) -> tuple[dict | None, JsonResponse | None]:
    if len(request.body) > MAX_JSON_BODY:
        return None, _error(request, "INVALID_REQUEST", "请求内容过大。", status=400)
    return _read_json(request)


def _idempotency_key(request: HttpRequest) -> str | None:
    value = request.headers.get("Idempotency-Key", "").strip()
    if not value or len(value) > 128:
        return None
    return value


def _strict_positive_int(payload: dict, key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise QuotaOperationError("INVALID_AMOUNT", "面额和生成数量必须是正整数。")
    return value


def _page_number(request: HttpRequest, key: str) -> int:
    raw = request.GET.get(key, "1")
    try:
        page = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(1, page)


def _query_page_size(request: HttpRequest, key: str, default: int = DEFAULT_PAGE_SIZE) -> int:
    raw = request.GET.get(key)
    if raw in (None, ""):
        return default
    try:
        return min(MAX_PAGE_SIZE, max(1, int(raw)))
    except (TypeError, ValueError):
        return default


def _page_payload(queryset, *, page: int, serializer, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    paginator = Paginator(queryset, min(max(page_size, 1), MAX_PAGE_SIZE))
    page_obj = paginator.get_page(page)
    return {
        "items": [serializer(item) for item in page_obj.object_list],
        "pagination": {
            "page": page_obj.number,
            "page_size": paginator.per_page,
            "total": paginator.count,
            "total_pages": paginator.num_pages,
            "has_previous": page_obj.has_previous(),
            "has_next": page_obj.has_next(),
        },
    }


def _quota_code_suffix(card: QuotaCard, *, code: str | None = None) -> str:
    try:
        plaintext = (
            code
            if code is not None
            else decrypt_quota_card(card.card_ciphertext, key_version=card.encryption_key_version)
        )
        suffix = normalize_quota_card_code(plaintext)[-4:]
        return suffix or "????"
    except QuotaOperationError:
        return "????"


def _card_payload(card: QuotaCard, *, code: str | None = None) -> dict:
    payload = {
        "public_id": str(card.public_id),
        "amount": card.amount,
        "status": card.status,
        "issued_at": card.issued_at.isoformat(),
        "redeemed_by": card.redeemed_by.user.username if card.redeemed_by_id and card.redeemed_by else None,
        "redeemed_by_public_id": str(card.redeemed_by_public_id) if card.redeemed_by_public_id else None,
        "redeemed_at": card.redeemed_at.isoformat() if card.redeemed_at else None,
        "redeemed_ip_digest": f"sha256:{card.redeemed_ip_digest[:16]}" if card.redeemed_ip_digest else None,
        "revoked_at": card.revoked_at.isoformat() if card.revoked_at else None,
        "revoke_reason": card.revoke_reason or None,
        "masked_code": f"••••-••••-{(suffix := _quota_code_suffix(card, code=code))}",
        "code_suffix": suffix,
    }
    if code is not None:
        payload["code"] = code
    return payload


def _entry_payload(entry: QuotaLedgerEntry) -> dict:
    sign = 1 if entry.direction == "credit" else -1
    return {
        "public_id": str(entry.public_id),
        "downstream_public_id": str(entry.downstream_public_id),
        "direction": entry.direction,
        "amount": entry.amount,
        "delta": sign * entry.amount,
        "operation_type": entry.operation_type,
        "source_type": entry.source_type,
        "source_public_id": entry.source_public_id or None,
        "reason": entry.reason,
        "balance_before": entry.balance_before,
        "balance_after": entry.balance_after,
        "occurred_at": entry.occurred_at.isoformat(),
    }


LEDGER_SEARCH_ALIASES = {
    "人工充值": QuotaLedgerOperation.MANUAL_CREDIT,
    "充值": QuotaLedgerOperation.MANUAL_CREDIT,
    "额度卡兑换": QuotaLedgerOperation.CARD_REDEEM,
    "兑换": QuotaLedgerOperation.CARD_REDEEM,
    "生成授权卡密": QuotaLedgerOperation.LICENSE_CARD_ISSUE,
    "生成授权卡": QuotaLedgerOperation.LICENSE_CARD_ISSUE,
    "发卡": QuotaLedgerOperation.LICENSE_CARD_ISSUE,
    "回收授权卡密": QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
    "回收未激活卡": QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
    "回收": QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
    "管理员调整": QuotaLedgerOperation.ADMIN_ADJUSTMENT,
    "管理员扣回": QuotaLedgerOperation.ADMIN_ADJUSTMENT,
    "调整": QuotaLedgerOperation.ADMIN_ADJUSTMENT,
}


def _apply_ledger_search(entries, request: HttpRequest):
    query = (request.GET.get("ledger_q") or "").strip()
    if not query:
        return entries, None
    if len(query) > 128:
        return None, _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
    search = (
        Q(account__downstream__user__username__icontains=query)
        | Q(operation_type__icontains=query)
        | Q(reason__icontains=query)
        | Q(actor__username__icontains=query)
        | Q(source_type__icontains=query)
    )
    mapped = LEDGER_SEARCH_ALIASES.get(query)
    if mapped:
        search |= Q(operation_type=mapped)
    else:
        for label, operation in LEDGER_SEARCH_ALIASES.items():
            if query in label:
                search |= Q(operation_type=operation)
    return entries.filter(search), None


def _account_payload(account) -> dict:
    profile = account.downstream
    return {
        "public_id": str(account.public_id),
        "downstream_public_id": str(account.downstream_public_id),
        "username": profile.user.username if profile and profile.user_id else None,
        "status": profile.status if profile else "deleted",
        "available_balance": account.available_balance,
    }


def _quota_error_status(error: QuotaOperationError) -> int:
    if error.code == "QUOTA_CARD_NOT_FOUND":
        return 404
    if error.code in {"IDEMPOTENCY_CONFLICT", "LIFECYCLE_RETRYABLE"}:
        return 409
    if error.code in {"QUOTA_CARD_UNAVAILABLE", "INSUFFICIENT_QUOTA", "QUOTA_CARD_NOT_ARCHIVABLE", "QUOTA_CARD_NOT_YET_ARCHIVABLE", "QUOTA_CARD_ALREADY_ARCHIVED", "QUOTA_CARD_NOT_DELETABLE"}:
        return 409
    return 400


def _admin_credit_required(view):
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        role, identity = _role_for_request(request)
        if role == "anonymous":
            return _error(request, "UNAUTHORIZED", "请先登录管理端。", status=401)
        if role != "platform_admin":
            return _error(request, "FORBIDDEN", "当前账号没有访问额度管理的权限。", status=403)
        return view(request, identity, *args, **kwargs)

    return wrapped


def _downstream_credit_required(view):
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        role, identity = _role_for_request(request)
        if role == "anonymous":
            return _error(request, "UNAUTHORIZED", "请先登录下游端。", status=401)
        if role != "downstream":
            return _error(request, "FORBIDDEN", "当前账号没有访问额度的权限。", status=403)
        return view(request, identity, *args, **kwargs)

    return wrapped


@_api_methods("GET")
def api_public_quota_settings(request: HttpRequest) -> JsonResponse:
    settings_row = get_quota_platform_settings()
    return _success({"purchase_url": settings_row.purchase_url or None})


def _manage_quota_cards_queryset(request: HttpRequest):
    scope = request.GET.get("scope", "current").strip().casefold()
    if scope not in {"current", "archived", "all"}:
        return None, _error(request, "INVALID_QUERY", "额度兑换码分类不正确。", status=400)
    cards = QuotaCard.objects.select_related("redeemed_by__user").order_by("-issued_at", "-public_id")
    cards = cards.exclude(status=QuotaCardStatus.DELETED_TOMBSTONE)
    if scope == "current":
        cards = cards.exclude(status=QuotaCardStatus.ARCHIVED)
    elif scope == "archived":
        cards = cards.filter(status=QuotaCardStatus.ARCHIVED)
    raw_status = request.GET.get("status", "").strip().casefold()
    if raw_status:
        allowed_statuses = {choice.value for choice in QuotaCardStatus if choice.value != QuotaCardStatus.DELETED_TOMBSTONE}
        if raw_status not in allowed_statuses:
            return None, _error(request, "INVALID_QUERY", "额度兑换码状态筛选不正确。", status=400)
        cards = cards.filter(status=raw_status)
    raw_amount = request.GET.get("amount", "").strip()
    if raw_amount:
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError):
            return None, _error(request, "INVALID_QUERY", "额度兑换码面额筛选不正确。", status=400)
        if amount <= 0:
            return None, _error(request, "INVALID_QUERY", "额度兑换码面额筛选不正确。", status=400)
        cards = cards.filter(amount=amount)
    redeemed_by = request.GET.get("redeemed_by", "").strip()
    if len(redeemed_by) > 128:
        return None, _error(request, "INVALID_QUERY", "兑换下游筛选内容过长。", status=400)
    if redeemed_by:
        cards = cards.filter(redeemed_by__user__username__iexact=redeemed_by)
    query = request.GET.get("q", "").strip()
    if len(query) > 128:
        return None, _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
    if query:
        normalized = normalize_quota_card_code(query)
        hashed = (
            cards.filter(card_hash=quota_card_hash(normalized)).first()
            if len(normalized) >= 16
            else None
        )
        if hashed is not None:
            cards = cards.filter(pk=hashed.pk)
        else:
            matched = Q(redeemed_by__user__username__icontains=query)
            if query.isdigit():
                matched |= Q(amount=int(query))
            cards = cards.filter(matched)
    return cards, None


@_api_methods("GET")
@_admin_credit_required
def api_manage_credits(request: HttpRequest, identity) -> JsonResponse:
    cards, error = _manage_quota_cards_queryset(request)
    if error is not None:
        return error
    settings_row = get_quota_platform_settings()
    entries = QuotaLedgerEntry.objects.select_related("account__downstream__user", "actor").order_by("-occurred_at", "-public_id")
    entries, ledger_error = _apply_ledger_search(entries, request)
    if ledger_error is not None:
        return ledger_error
    accounts = get_quota_accounts_for_api()
    card_page = _page_payload(
        cards,
        page=_page_number(request, "card_page"),
        serializer=_card_payload,
        page_size=_query_page_size(request, "card_page_size"),
    )
    ledger_page = _page_payload(
        entries,
        page=_page_number(request, "ledger_page"),
        serializer=_entry_payload,
        page_size=_query_page_size(request, "ledger_page_size"),
    )
    return _success(
        {
            "purchase_url": settings_row.purchase_url or None,
            "cards": card_page["items"],
            "cards_pagination": card_page["pagination"],
            "cards_scope": request.GET.get("scope", "current").strip().casefold() or "current",
            "ledger": ledger_page["items"],
            "ledger_pagination": ledger_page["pagination"],
            "accounts": [_account_payload(account) for account in accounts],
            "operating_available_balance": _operating_available_balance(accounts),
        }
    )


def _operating_available_balance(accounts) -> int:
    return int(sum(account.available_balance for account in accounts if account.downstream_id is not None))


def get_quota_accounts_for_api():
    accounts = list(QuotaAccount.objects.select_related("downstream__user").order_by("downstream_public_id"))
    seen = {account.downstream_public_id for account in accounts}
    extras = []
    for profile in DownstreamProfile.objects.select_related("user").filter(status=DownstreamStatus.ACTIVE).order_by("public_id"):
        if profile.public_id in seen:
            continue
        extras.append(
            SimpleNamespace(
                public_id=profile.public_id,
                downstream_public_id=profile.public_id,
                downstream=profile,
                downstream_id=profile.pk,
                available_balance=0,
            )
        )
    combined = accounts + extras
    combined.sort(key=lambda item: str(item.downstream_public_id))
    return combined


@_api_methods("POST")
@_admin_credit_required
def api_update_quota_settings(request: HttpRequest, identity) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    try:
        settings_row = update_quota_purchase_url(
            actor=identity,
            purchase_url=payload.get("purchase_url", ""),
            idempotency_key=key,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        return _error(request, exc.code, exc.message, status=_quota_error_status(exc))
    return _success({"purchase_url": settings_row.purchase_url or None})


@_api_methods("POST")
@_admin_credit_required
def api_adjust_credits(request: HttpRequest, identity) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    adjustment_type = str(payload.get("adjustment_type") or "").strip().casefold()
    if adjustment_type not in {"credit", "debit"}:
        return _error(request, "INVALID_REQUEST", "调整类型只能是增加额度或管理员扣回。", status=400)
    amount = payload.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
        return _error(request, "INVALID_AMOUNT", "额度数量必须是正整数。", status=400)
    try:
        downstream = DownstreamProfile.objects.select_related("user").get(public_id=payload.get("downstream_public_id"))
    except (DownstreamProfile.DoesNotExist, ValueError, TypeError, ValidationError):
        return _error(request, "DOWNSTREAM_NOT_FOUND", "目标下游不存在。", status=404)
    try:
        if adjustment_type == "credit":
            entry = credit_quota(
                actor=identity,
                downstream=downstream,
                amount=amount,
                reason=payload.get("reason", ""),
                idempotency_key=key,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        else:
            entry = recover_downstream_credits(
                actor=identity,
                downstream=downstream,
                amount=amount,
                reason=payload.get("reason", ""),
                idempotency_key=key,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
    except QuotaOperationError as exc:
        return _error(request, exc.code, exc.message, status=_quota_error_status(exc))
    return _success({"item": _entry_payload(entry)})


@_api_methods("POST")
@_admin_credit_required
def api_recover_deleted_credits(request: HttpRequest, identity) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    amount = payload.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
        return _error(request, "INVALID_AMOUNT", "额度数量必须是正整数。", status=400)
    try:
        downstream_public_id = uuid.UUID(str(payload.get("downstream_public_id", "")))
    except (ValueError, TypeError, AttributeError):
        return _error(request, "INVALID_REQUEST", "下游公开标识不正确。", status=400)
    try:
        entry = recover_deleted_downstream_credits(
            actor=identity,
            downstream_public_id=downstream_public_id,
            amount=amount,
            reason=payload.get("reason", ""),
            idempotency_key=key,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        status = 404 if exc.code in {"QUOTA_ACCOUNT_NOT_FOUND"} else _quota_error_status(exc)
        if exc.code == "DOWNSTREAM_STILL_PRESENT":
            status = 409
        return _error(request, exc.code, exc.message, status=status)
    return _success({"item": _entry_payload(entry)})


@_api_methods("POST")
@_admin_credit_required
def api_issue_quota_cards(request: HttpRequest, identity) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    try:
        batch, issued = issue_quota_card_batch(
            actor=identity,
            amount=_strict_positive_int(payload, "amount"),
            quantity=_strict_positive_int(payload, "quantity"),
            idempotency_key=key,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        return _error(request, exc.code, exc.message, status=_quota_error_status(exc))
    return _success(
        {
            "items": [_card_payload(QuotaCard.objects.get(public_id=item.public_id), code=item.code) for item in issued],
            "amount": batch.amount,
            "quantity": batch.quantity,
            "total_amount": batch.amount * batch.quantity,
        },
        status=201,
    )


@_api_methods("POST")
@_admin_credit_required
def api_revoke_quota_card(request: HttpRequest, identity, public_id) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    try:
        card = revoke_quota_card(
            actor=identity,
            card_public_id=public_id,
            reason=payload.get("reason", ""),
            idempotency_key=key,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        return _error(request, exc.code, exc.message, status=_quota_error_status(exc))
    return _success({"item": _card_payload(card)})


def _quota_lifecycle(request: HttpRequest, *, action: str) -> JsonResponse:
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    payload = payload or {}
    try:
        if action == "archive":
            result = archive_quota_cards(
                actor=request.user,
                card_ids=payload.get("card_ids", []),
                reason=payload.get("reason", ""),
                idempotency_key=key,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        else:
            result = delete_quota_cards(
                actor=request.user,
                card_ids=payload.get("card_ids", []),
                reason=payload.get("reason", ""),
                idempotency_key=key,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
    except QuotaOperationError as exc:
        return _error(request, exc.code, exc.message, status=_quota_error_status(exc), retryable=exc.code == "LIFECYCLE_RETRYABLE")
    return _success(result)


@_api_methods("POST")
@_admin_credit_required
def api_manage_quota_card_archive(request: HttpRequest, identity) -> JsonResponse:
    return _quota_lifecycle(request, action="archive")


@_api_methods("POST")
@_admin_credit_required
def api_manage_quota_card_delete(request: HttpRequest, identity) -> JsonResponse:
    return _quota_lifecycle(request, action="delete")


@_api_methods("GET")
@_admin_credit_required
def api_manage_quota_card_export(request: HttpRequest, identity) -> HttpResponse:
    cards, error = _manage_quota_cards_queryset(request)
    if error is not None:
        return error
    total = cards.count()
    rows = [
        [
            str(card.public_id),
            card.amount,
            card.get_status_display(),
            format_beijing_wall_clock(card.issued_at),
            card.redeemed_by.user.username if card.redeemed_by and card.redeemed_by.user else "",
            format_beijing_wall_clock(card.redeemed_at),
        ]
        for card in cards[:EXPORT_LIMIT]
    ]
    return _csv_export_response(
        request=request,
        identity=identity,
        filename="quota-cards.csv",
        header=["公开ID", "面额", "状态", "发行时间", "兑换下游", "兑换时间"],
        rows=rows,
        action="quota_card.export",
        total=total,
    )


@_api_methods("GET")
@_admin_credit_required
def api_manage_credit_ledger_export(request: HttpRequest, identity) -> HttpResponse:
    entries = QuotaLedgerEntry.objects.select_related("account__downstream__user", "actor").order_by(
        "-occurred_at", "-public_id"
    )
    entries, error = _apply_ledger_search(entries, request)
    if error is not None:
        return error
    total = entries.count()
    rows = [
        [
            format_beijing_wall_clock(entry.occurred_at),
            entry.account.downstream.user.username if entry.account and entry.account.downstream and entry.account.downstream.user else "",
            entry.get_operation_type_display(),
            f"{'+' if entry.direction == QuotaLedgerDirection.CREDIT else '-'}{entry.amount}",
            entry.balance_before,
            entry.balance_after,
            entry.reason,
        ]
        for entry in entries[:EXPORT_LIMIT]
    ]
    return _csv_export_response(
        request=request,
        identity=identity,
        filename="credit-ledger.csv",
        header=["时间", "下游", "动作", "金额", "变更前余额", "变更后余额", "原因"],
        rows=rows,
        action="quota.ledger.export",
        total=total,
    )


@_api_methods("POST")
@_admin_credit_required
def api_search_quota_card(request: HttpRequest, identity) -> JsonResponse:
    rate_identity = f"{_ip_address(request) or 'unknown'}:{request.user.pk}"
    if not allow_rate("quota-card-search-api", rate_identity, limit=settings.QUOTA_CARD_SEARCH_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="quota_card.search",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "quota-card-search-api"},
        )
        response = _error(request, "RATE_LIMITED", "搜索额度兑换码过于频繁，请稍后再试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return response

    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    code = payload.get("code")
    normalized = normalize_quota_card_code(code)
    if not normalized or len(normalized) > 128:
        return _error(request, "QUOTA_CARD_NOT_FOUND", "额度兑换码不存在。", status=404)
    card = QuotaCard.objects.select_related("redeemed_by__user").exclude(
        status=QuotaCardStatus.DELETED_TOMBSTONE
    ).filter(card_hash=quota_card_hash(normalized)).first()
    if card is None:
        return _error(request, "QUOTA_CARD_NOT_FOUND", "额度兑换码不存在。", status=404)
    return _success({"item": _card_payload(card)})


@_api_methods("POST")
@_admin_credit_required
def api_reveal_quota_card(request: HttpRequest, identity, public_id) -> JsonResponse:
    rate_identity = f"{_ip_address(request) or 'unknown'}:{request.user.pk}"
    if not allow_rate("quota-card-reveal-api", rate_identity, limit=settings.QUOTA_CARD_REVEAL_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="quota_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "quota-card-reveal-api"},
        )
        response = _error(request, "RATE_LIMITED", "查看额度兑换码过于频繁，请稍后再试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
        return response

    try:
        card, plaintext = reveal_quota_card(
            actor=request.user,
            card_public_id=public_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        status = 404 if exc.code == "QUOTA_CARD_NOT_FOUND" else _quota_error_status(exc)
        return _error(request, exc.code, exc.message, status=status)

    return _success({"item": _card_payload(card), "code": plaintext})


@_api_methods("GET", "POST")
@_downstream_credit_required
def api_downstream_credits(request: HttpRequest, profile) -> JsonResponse:
    if request.method == "GET":
        account = get_quota_account(profile)
        entries = QuotaLedgerEntry.objects.filter(account=account).order_by("-occurred_at", "-public_id")
        entries, ledger_error = _apply_ledger_search(entries, request)
        if ledger_error is not None:
            return ledger_error
        page = _page_payload(
            entries,
            page=_page_number(request, "ledger_page"),
            serializer=_entry_payload,
            page_size=_query_page_size(request, "ledger_page_size"),
        )
        start, end = _beijing_today_range()
        today_consumed = (
            QuotaLedgerEntry.objects.filter(
                account=account,
                direction=QuotaLedgerDirection.DEBIT,
                occurred_at__gte=start,
                occurred_at__lt=end,
            ).aggregate(total=Sum("amount"))["total"]
            or 0
        )
        settings_row = get_quota_platform_settings()
        return _success(
            {
                "purchase_url": settings_row.purchase_url or None,
                "account": _account_payload(account),
                "ledger": page["items"],
                "ledger_pagination": page["pagination"],
                "today_consumed": int(today_consumed),
            }
        )

    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "缺少有效的重复提交标识。", status=400)
    if not allow_rate(
        "quota-redeem-api",
        f"{_ip_address(request) or 'unknown'}:{profile.public_id}",
        limit=settings.QUOTA_REDEEM_RATE_LIMIT,
    ):
        record_event(
            actor=request.user,
            action="quota_card.redeem",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"source": "api"},
        )
        return _error(request, "RATE_LIMITED", "兑换尝试过于频繁，请稍后再试。", status=429, retryable=True)
    payload, parse_error = _read_json_local(request)
    if parse_error:
        return parse_error
    try:
        result = redeem_quota_card(
            actor=request.user,
            card_code=payload.get("card_code", ""),
            idempotency_key=key,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        return _error(request, exc.code, exc.message, status=_quota_error_status(exc))
    return _success(
        {
            "repeated": result.repeated,
            "account": _account_payload(get_quota_account(profile)),
            "entry": _entry_payload(result.entry),
            "card": _card_payload(result.card),
        }
    )
