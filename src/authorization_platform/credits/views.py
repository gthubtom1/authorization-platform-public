from __future__ import annotations

import hashlib
import secrets
import uuid

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from authorization_platform.accounts.decorators import active_downstream_required, platform_admin_required
from authorization_platform.core.legacy_html import close_legacy_html
from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.accounts.services import get_downstream_profile
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .forms import ManualCreditForm, QuotaCardIssueForm, QuotaRecoveryForm, RedeemQuotaCardForm
from .models import QuotaCard, QuotaCardStatus, QuotaLedgerEntry
from .services import (
    QuotaOperationError,
    credit_quota,
    get_quota_account,
    issued_cards_for_batch,
    issue_quota_card_batch,
    list_quota_accounts,
    list_quota_entries,
    normalize_quota_card_code,
    quota_card_hash,
    recover_downstream_credits,
    redeem_quota_card,
    reveal_quota_card,
)


def _request_id(request: HttpRequest) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if supplied:
        return f"client-{hashlib.sha256(supplied.encode('utf-8')).hexdigest()}"
    return f"req-{uuid.uuid4().hex}"


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _token_cache_key(namespace: str, token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"credits:{namespace}:{digest}"


def _ensure_token(request: HttpRequest, session_key: str) -> str:
    token = request.session.get(session_key)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[session_key] = token
    return token


def _claim_token(request: HttpRequest, *, session_key: str, namespace: str, supplied: str) -> bool:
    expected = request.session.get(session_key, "")
    return bool(
        supplied
        and supplied == expected
        and cache.add(_token_cache_key(namespace, supplied), True, timeout=900)
    )


def _rotate_token(request: HttpRequest, session_key: str) -> None:
    request.session[session_key] = secrets.token_urlsafe(32)


@never_cache
@require_http_methods(["GET", "POST"])
@platform_admin_required
@close_legacy_html
def admin_dashboard(request: HttpRequest) -> HttpResponse:
    action = request.POST.get("action", "") if request.method == "POST" else ""
    issue_form = QuotaCardIssueForm(request.POST if action == "issue_cards" else None)
    credit_form = ManualCreditForm(request.POST if action == "manual_credit" else None)
    recovery_form = QuotaRecoveryForm(request.POST if action == "recover_credits" else None)
    issued = None

    if request.method == "POST" and action == "issue_cards" and issue_form.is_valid():
        token = request.POST.get("issue_token", "")
        if not _claim_token(request, session_key="quota_card_issue_token", namespace="issue", supplied=token):
            issue_form.add_error(None, "这个发行请求已经处理或已失效，请刷新页面后重试。")
        else:
            try:
                batch, _ = issue_quota_card_batch(
                    actor=request.user,
                    amount=issue_form.cleaned_data["amount"],
                    quantity=issue_form.cleaned_data["quantity"],
                    idempotency_key=token,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            except QuotaOperationError as exc:
                cache.delete(_token_cache_key("issue", token))
                issue_form.add_error(None, exc.message)
            else:
                request.session["new_quota_card_batch"] = str(batch.public_id)
                _rotate_token(request, "quota_card_issue_token")
                return redirect("credits:admin_dashboard")

    if request.method == "POST" and action == "manual_credit" and credit_form.is_valid():
        token = request.POST.get("credit_token", "")
        if not _claim_token(request, session_key="quota_manual_credit_token", namespace="manual-credit", supplied=token):
            credit_form.add_error(None, "这个充值请求已经处理或已失效，请刷新页面后重试。")
        else:
            try:
                credit_quota(
                    actor=request.user,
                    downstream=credit_form.cleaned_data["downstream"],
                    amount=credit_form.cleaned_data["amount"],
                    reason=credit_form.cleaned_data["reason"],
                    idempotency_key=token,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            except QuotaOperationError as exc:
                cache.delete(_token_cache_key("manual-credit", token))
                credit_form.add_error(None, exc.message)
            else:
                messages.success(request, "人工充值已入账，余额和额度流水已同步更新。")
                _rotate_token(request, "quota_manual_credit_token")
                return redirect("credits:admin_dashboard")

    if request.method == "POST" and action == "recover_credits" and recovery_form.is_valid():
        token = request.POST.get("recovery_token", "")
        if not _claim_token(request, session_key="quota_recovery_token", namespace="recovery", supplied=token):
            recovery_form.add_error(None, "这个回收请求已经处理或已失效，请刷新页面后重试。")
        else:
            try:
                recover_downstream_credits(
                    actor=request.user,
                    downstream=recovery_form.cleaned_data["downstream"],
                    amount=recovery_form.cleaned_data["amount"],
                    reason=recovery_form.cleaned_data["reason"],
                    idempotency_key=token,
                    request_id=_request_id(request),
                    ip_address=_ip_address(request),
                )
            except QuotaOperationError as exc:
                cache.delete(_token_cache_key("recovery", token))
                recovery_form.add_error(None, exc.message)
            else:
                messages.success(request, "管理员额度回收已入账，余额和不可变流水已同步更新。")
                _rotate_token(request, "quota_recovery_token")
                return redirect("credits:admin_dashboard")

    if request.method == "GET":
        batch_id = request.session.pop("new_quota_card_batch", None)
        if batch_id:
            try:
                issued = issued_cards_for_batch(actor=request.user, batch_public_id=batch_id)
            except QuotaOperationError as exc:
                messages.error(request, exc.message)

    cards = QuotaCard.objects.select_related("batch", "target_downstream__user", "redeemed_by__user").order_by("-issued_at")[:50]
    entries = QuotaLedgerEntry.objects.select_related("account__downstream__user", "actor").order_by("-occurred_at")[:50]
    return render(
        request,
        "credits/admin_dashboard.html",
        {
            "issue_form": issue_form,
            "credit_form": credit_form,
            "recovery_form": recovery_form,
            "issue_token": _ensure_token(request, "quota_card_issue_token"),
            "credit_token": _ensure_token(request, "quota_manual_credit_token"),
            "recovery_token": _ensure_token(request, "quota_recovery_token"),
            "issued": issued,
            "cards": cards,
            "accounts": list(list_quota_accounts(actor=request.user)),
            "entries": entries,
        },
    )


@never_cache
@require_POST
@platform_admin_required
@close_legacy_html
def card_reveal(request: HttpRequest, public_id) -> HttpResponse:
    rate_identity = f"{_ip_address(request) or 'unknown'}:{request.user.pk}"
    if not allow_rate("quota-card-reveal", rate_identity, limit=settings.QUOTA_CARD_REVEAL_RATE_LIMIT):
        record_event(
            actor=request.user,
            action="quota_card.reveal",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            reason_code="RATE_LIMITED",
            metadata={"rate_scope": "quota-card-reveal"},
        )
        messages.error(request, "查看额度卡过于频繁，请稍后再试。")
        return redirect("credits:admin_dashboard")
    try:
        card, plaintext = reveal_quota_card(
            actor=request.user,
            card_public_id=public_id,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except QuotaOperationError as exc:
        messages.error(request, exc.message)
        return redirect("credits:admin_dashboard")
    return render(request, "credits/quota_card_reveal.html", {"card": card, "plaintext": plaintext})


@never_cache
@require_http_methods(["GET", "POST"])
@active_downstream_required
@close_legacy_html
def downstream_ledger(request: HttpRequest) -> HttpResponse:
    profile = get_downstream_profile(request.user)
    form = RedeemQuotaCardForm(request.POST or None)
    rate_allowed = request.method != "POST" or allow_rate(
        "quota-redeem",
        f"{_ip_address(request) or 'unknown'}:{profile.public_id}",
        limit=settings.QUOTA_REDEEM_RATE_LIMIT,
    )
    if request.method == "POST" and not rate_allowed:
        form.add_error(None, "兑换尝试过于频繁，请稍后再试。")
    if request.method == "POST" and rate_allowed and form.is_valid():
        try:
            result = redeem_quota_card(
                actor=request.user,
                card_code=form.cleaned_data["card_code"],
                request_id=_request_id(request),
                ip_address=_ip_address(request),
            )
        except QuotaOperationError as exc:
            form.add_error(None, exc.message)
        else:
            if result.repeated:
                messages.info(request, f"这张额度卡已经兑换过，本次没有重复入账；当前余额为 {result.entry.balance_after}。")
            else:
                messages.success(request, f"额度卡兑换成功：{result.entry.balance_before} → +{result.entry.amount} → {result.entry.balance_after}。")
            return redirect("credits:downstream_ledger")

    account = get_quota_account(profile)
    return render(
        request,
        "credits/downstream_ledger.html",
        {
            "profile": profile,
            "account": account,
            "entries": list_quota_entries(profile=profile),
            "form": form,
        },
    )
