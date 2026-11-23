from __future__ import annotations

import json
import uuid
import ipaddress

from django.core.paginator import Paginator
from django.conf import settings
from django.db.models import Q
from django.http import FileResponse, HttpRequest, JsonResponse
from django.utils import timezone

from authorization_platform.accounts.api_views import _admin_required, _api_methods, _error, _request_id, _success
from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.core.object_storage import ObjectStorageError
from authorization_platform.licensing.models import AuthorizationState, LicenseCard, LicenseCardStatus, LicenseInstance
from authorization_platform.licensing.services import license_card_hash, normalize_license_card_code

from .models import Release, ReleaseStatus
from .services import (
    ReleaseOperationError,
    archive_release,
    create_and_publish_external_release,
    create_release_draft,
    delete_withdrawn_release_package,
    discard_release_draft,
    latest_public_release,
    open_release_package,
    publish_release,
    release_package_available,
    release_payload,
    safe_release_filename,
    update_external_release_url,
    update_release_version,
    withdraw_release,
)


def _json_body(request: HttpRequest) -> dict:
    if not request.body:
        return {}
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _ip_address(request: HttpRequest) -> str | None:
    return request.META.get("REMOTE_ADDR") or None


def _release_id(value: str):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise ReleaseOperationError("INVALID_REQUEST", "版本标识不正确。")


def _handle_error(request: HttpRequest, error: ReleaseOperationError) -> JsonResponse:
    return _error(request, error.code, error.message, status=error.status)


@_admin_required
@_api_methods("GET", "POST")
def api_manage_releases(request: HttpRequest, _identity) -> JsonResponse:
    if request.method == "GET":
        queryset = Release.objects.select_related("software", "profile").all()
        software_id = request.GET.get("software_id", "").strip()
        status = request.GET.get("status", "").strip()
        if software_id and software_id != "all":
            queryset = queryset.filter(software_id=software_id)
        if status and status != "all":
            if status not in {choice for choice, _label in ReleaseStatus.choices}:
                return _error(request, "INVALID_FILTER", "版本状态筛选不正确。", status=400)
            queryset = queryset.filter(status=status)
        else:
            queryset = queryset.exclude(status__in=(ReleaseStatus.DISCARDED, ReleaseStatus.ARCHIVED))
        query = request.GET.get("q", "").strip()
        if len(query) > 128:
            return _error(request, "INVALID_QUERY", "搜索内容不能超过 128 个字符。", status=400)
        if query:
            queryset = queryset.filter(
                Q(version__icontains=query)
                | Q(notes__icontains=query)
                | Q(channel__icontains=query)
                | Q(software__name__icontains=query)
                | Q(software_id__icontains=query)
            )
        try:
            page_number = max(1, int(request.GET.get("page", "1")))
            page_size = min(200, max(1, int(request.GET.get("page_size", "50"))))
        except (TypeError, ValueError):
            page_number, page_size = 1, 50
        paginator = Paginator(queryset.order_by("-created_at", "-release_id"), page_size)
        page = paginator.get_page(page_number)
        return _success({"items": [release_payload(item) for item in page.object_list], "count": paginator.count, "pagination": {"page": page.number, "page_size": paginator.per_page, "total": paginator.count, "total_pages": paginator.num_pages, "has_previous": page.has_previous(), "has_next": page.has_next()}, "request_id": _request_id(request)})

    uploaded_file = request.FILES.get("release_package")
    if uploaded_file is None:
        return _error(request, "PACKAGE_REQUIRED", "请选择客户端 ZIP 构建包。", status=400)
    try:
        payload = create_release_draft(
            actor=request.user,
            uploaded_file=uploaded_file,
            software_id=request.POST.get("software_id", ""),
            profile_id=request.POST.get("profile_id") or None,
            channel=request.POST.get("channel", ""),
            notes=request.POST.get("notes", ""),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload, status=201 if not payload.get("repeated") else 200)


@_admin_required
@_api_methods("POST")
def api_publish_external_release(request: HttpRequest, _identity) -> JsonResponse:
    body = _json_body(request)
    try:
        payload = create_and_publish_external_release(
            actor=request.user,
            software_id=str(body.get("software_id") or ""),
            profile_id=body.get("profile_id") or None,
            channel=str(body.get("channel") or "stable"),
            version=str(body.get("version") or ""),
            notes=str(body.get("notes") or ""),
            external_download_url=str(body.get("external_download_url") or ""),
            package_sha256=body.get("package_sha256") or None,
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload, status=201 if not payload.get("repeated") and not payload.get("replaced") else 200)


@_admin_required
@_api_methods("POST")
def api_update_external_release_url(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    body = _json_body(request)
    try:
        payload = update_external_release_url(
            actor=request.user,
            release_id=_release_id(release_id),
            external_download_url=str(body.get("external_download_url") or ""),
            package_sha256=body.get("package_sha256"),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_publish_release(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    try:
        parsed_id = _release_id(release_id)
        notes = request.POST.get("notes", "")
        if not notes and request.body:
            import json

            try:
                notes = json.loads(request.body.decode("utf-8")).get("notes", "")
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                notes = ""
        payload = publish_release(
            actor=request.user,
            release_id=parsed_id,
            notes=notes,
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_withdraw_release(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    try:
        parsed_id = _release_id(release_id)
        reason = request.POST.get("reason", "")
        if not reason and request.body:
            import json

            try:
                reason = json.loads(request.body.decode("utf-8")).get("reason", "")
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                reason = ""
        payload = withdraw_release(
            actor=request.user,
            release_id=parsed_id,
            reason=reason,
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_delete_release_package(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    try:
        body = _json_body(request)
        confirmed = body.get("confirmed")
        if confirmed is None:
            confirmed = request.POST.get("confirmed")
        payload = delete_withdrawn_release_package(
            actor=request.user,
            release_id=_release_id(release_id),
            confirmed=bool(confirmed),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_discard_release(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    try:
        payload = discard_release_draft(
            actor=request.user,
            release_id=_release_id(release_id),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_archive_release(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    body = _json_body(request)
    try:
        payload = archive_release(
            actor=request.user,
            release_id=_release_id(release_id),
            reason=str(body.get("reason") or request.POST.get("reason") or ""),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_update_release_version(request: HttpRequest, _identity, release_id: str) -> JsonResponse:
    body = _json_body(request)
    try:
        payload = update_release_version(
            actor=request.user,
            release_id=_release_id(release_id),
            version=str(body.get("version") or request.POST.get("version") or ""),
            reason=str(body.get("reason") or request.POST.get("reason") or ""),
            idempotency_key=request.headers.get("Idempotency-Key", ""),
            request_id=_request_id(request),
            ip_address=_ip_address(request),
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    payload["request_id"] = _request_id(request)
    return _success(payload)


@_api_methods("GET")
def api_public_release_registry(request: HttpRequest, software_id: str, profile_id: str) -> JsonResponse:
    client_ip = request.META.get("REMOTE_ADDR") or "unknown"
    if not allow_rate(
        "public-release-registry",
        f"{client_ip}:{software_id}:{profile_id}",
        limit=settings.PUBLIC_RELEASE_REGISTRY_RATE_LIMIT,
        timeout=settings.PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS,
    ):
        response = _error(request, "RATE_LIMITED", "版本查询请求过于频繁，请稍后重试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS)
        return response
    required = {
        "client_id": request.GET.get("client_id", "").strip(),
        "target": request.GET.get("target", "").strip(),
        "arch": request.GET.get("arch", "").strip(),
        "channel": request.GET.get("channel", "").strip(),
    }
    if any(not value for value in required.values()):
        return _error(request, "INVALID_REQUEST", "客户端身份参数不完整。", status=400)
    try:
        profile, release, has_update = latest_public_release(
            software_id=software_id,
            profile_id=profile_id,
            client_id=required["client_id"],
            target=required["target"],
            arch=required["arch"],
            channel=required["channel"],
            current_version=request.GET.get("version") or None,
        )
    except ReleaseOperationError as exc:
        return _handle_error(request, exc)
    return _success(
        {
            "software_id": software_id,
            "profile_id": profile_id,
            "minimum_client_version": profile.minimum_client_version,
            "has_update": has_update,
            "release": release_payload(release, include_download=True, public=True) if release else None,
            "generated_at": timezone.now().isoformat(),
        }
    )


@_api_methods("GET")
def api_public_release_download(request: HttpRequest, software_id: str, profile_id: str, release_id: str) -> FileResponse | JsonResponse:
    # Same-host ZIP is optional. Default updates open external_download_url.
    # Hosted packages are public; do not put license keys in the URL.
    if not settings.RELEASE_DOWNLOAD_REQUIRE_AUTH:
        return _public_release_download_unprotected(request, software_id, profile_id, release_id)
    client_ip = request.META.get("REMOTE_ADDR") or ""
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        return _error(request, "DOWNLOAD_FORBIDDEN", "当前网络地址无法验证。", status=403)
    try:
        parsed_id = _release_id(release_id)
        release = Release.objects.select_related("software", "profile").get(
            release_id=parsed_id,
            software_id=software_id,
            profile__profile_id=profile_id,
            software__status__in=("active", "testing"),
            profile__status__in=("active", "testing"),
            status=ReleaseStatus.PUBLISHED,
        )
        if settings.RELEASE_REQUIRE_VERIFIED_SIGNATURE and release.signature_status != "verified":
            raise Release.DoesNotExist
    except (Release.DoesNotExist, ReleaseOperationError):
        return _error(request, "RELEASE_NOT_FOUND", "可下载的版本不存在。", status=404)
    license_key = request.headers.get("X-License-Key", "").strip()
    try:
        normalized_key = normalize_license_card_code(license_key)
    except (ValueError, TypeError):
        normalized_key = ""
    if not normalized_key:
        return _error(request, "DOWNLOAD_AUTH_REQUIRED", "下载需要有效的授权卡密。", status=403)
    card = LicenseCard.objects.filter(card_hash=license_card_hash(normalized_key), status=LicenseCardStatus.ACTIVATED).first()
    authorization = LicenseInstance.objects.filter(
        license_card=card,
        software_id=software_id,
        profile__profile_id=profile_id,
        state__in=(AuthorizationState.ACTIVE, AuthorizationState.GRACE),
        expires_at__gt=timezone.now(),
    ).first() if card else None
    if authorization is None:
        return _error(request, "DOWNLOAD_FORBIDDEN", "当前卡密没有可用的版本下载权限。", status=403)
    if not release_package_available(
        release.package_path,
        expected_size=release.package_size,
        expected_sha256=release.package_sha256,
    ):
        return _error(request, "PACKAGE_UNAVAILABLE", "版本包暂时不可用。", status=410)
    subject_allowed = allow_rate(
        "public-release-download",
        f"{card.card_hash}:{software_id}:{profile_id}",
        limit=settings.PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT,
        timeout=settings.PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS,
    )
    ip_allowed = allow_rate("public-release-download-ip", client_ip, limit=settings.PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT, timeout=settings.PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS)
    if not subject_allowed or not ip_allowed:
        response = _error(request, "RATE_LIMITED", "版本下载请求过于频繁，请稍后重试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS)
        return response
    try:
        package = open_release_package(
            release.package_path,
            expected_size=release.package_size,
            expected_sha256=release.package_sha256,
        )
    except (ObjectStorageError, OSError, ReleaseOperationError):
        return _error(request, "PACKAGE_UNAVAILABLE", "版本包暂时不可用。", status=410)
    response = FileResponse(package, as_attachment=True, filename=safe_release_filename(release.package_name), content_type="application/zip")
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "private, no-store"
    return response


def _public_release_download_unprotected(request: HttpRequest, software_id: str, profile_id: str, release_id: str):
    """Public same-host ZIP. Card check is not required."""
    client_ip = request.META.get("REMOTE_ADDR") or ""
    try:
        parsed_id = _release_id(release_id)
        release = Release.objects.select_related("software", "profile").get(
            release_id=parsed_id,
            software_id=software_id,
            profile__profile_id=profile_id,
            software__status__in=("active", "testing"),
            profile__status__in=("active", "testing"),
            status=ReleaseStatus.PUBLISHED,
        )
        if settings.RELEASE_REQUIRE_VERIFIED_SIGNATURE and release.signature_status != "verified":
            raise Release.DoesNotExist
    except (Release.DoesNotExist, ReleaseOperationError):
        return _error(request, "RELEASE_NOT_FOUND", "可下载的版本不存在。", status=404)
    if not release.package_path:
        return _error(request, "PACKAGE_UNAVAILABLE", "版本包暂时不可用。", status=410)
    try:
        ipaddress.ip_address(client_ip)
        rate_key = client_ip
    except ValueError:
        rate_key = "unknown"
    ip_allowed = allow_rate(
        "public-release-download-ip",
        rate_key,
        limit=settings.PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT,
        timeout=settings.PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS,
    )
    if not ip_allowed:
        response = _error(request, "RATE_LIMITED", "版本下载请求过于频繁，请稍后重试。", status=429, retryable=True)
        response["Retry-After"] = str(settings.PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS)
        return response
    try:
        package = open_release_package(release.package_path, expected_size=release.package_size, expected_sha256=release.package_sha256)
    except (ObjectStorageError, OSError, ReleaseOperationError):
        return _error(request, "PACKAGE_UNAVAILABLE", "版本包暂时不可用。", status=410)
    response = FileResponse(package, as_attachment=True, filename=safe_release_filename(release.package_name), content_type="application/zip")
    response["X-Content-Type-Options"] = "nosniff"
    return response
