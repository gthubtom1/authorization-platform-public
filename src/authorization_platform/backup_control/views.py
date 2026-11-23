from __future__ import annotations

import hashlib
import json
import uuid

from django.http import FileResponse, Http404, HttpRequest, JsonResponse
from django.db import OperationalError, transaction
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from authorization_platform.accounts.api_views import (
    _admin_required,
    _api_methods,
    _error,
    _ip_address,
    _read_json,
    _request_id,
    _success,
)
from authorization_platform.accounts.decorators import platform_admin_required
from authorization_platform.core.legacy_html import close_legacy_html
from authorization_platform.accounts.rate_limit import allow as allow_rate
from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.storage_cleanup.services import StorageCleanupError, execute_cleanup

from .services import (
    BackupControlError,
    confirm_restore,
    dashboard_payload,
    download_path,
    existing_operation,
    get_policy,
    inspect_restore_upload,
    list_downloads,
    probe_backup_destinations,
    request_backup_run,
    store_operation,
    update_policy,
    delete_encrypted_download,
    _locked_policy,
)


def _idempotency_key(request: HttpRequest) -> str:
    return (request.headers.get("Idempotency-Key") or "").strip()


def _validate_idempotency_key(request: HttpRequest, message: str) -> tuple[str, JsonResponse | None]:
    key = _idempotency_key(request)
    if not key:
        return "", _error(request, "IDEMPOTENCY_REQUIRED", message, status=400)
    if len(key) > 128:
        return "", _error(request, "INVALID_IDEMPOTENCY_KEY", "幂等键不能超过 128 个字符。", status=400)
    return key, None


def _request_hash(payload: dict) -> str:
    canonical = json.dumps(payload or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@platform_admin_required
@require_http_methods(["GET", "POST"])
@close_legacy_html
def dashboard(request: HttpRequest):
    if request.method == "POST":
        values = {}
        for name in ("enabled", "schedule_enabled", "database_enabled", "github_enabled", "cleanup_enabled"):
            values[name] = request.POST.get(name) == "on"
        values["full_time"] = request.POST.get("full_time", "")
        try:
            values["diff_interval_hours"] = int(request.POST.get("diff_interval_hours", ""))
        except ValueError:
            values["diff_interval_hours"] = 0
        for name in ("retention_full", "retention_diff", "retention_archive", "github_retention_count"):
            try:
                values[name] = int(request.POST.get(name, ""))
            except ValueError:
                values[name] = 0
        try:
            update_policy(actor=request.user, values=values)
        except ValueError as exc:
            return render(
                request,
                "backup_control/dashboard.html",
                {"data": dashboard_payload(), "downloads": list_downloads(), "error": str(exc)},
            )
        record_event(
            actor=request.user,
            action="backup.policy.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=_request_id(request),
            ip_address=request.META.get("REMOTE_ADDR"),
            metadata={"enabled": values["enabled"], "database_enabled": values["database_enabled"], "github_enabled": values["github_enabled"], "cleanup_enabled": values["cleanup_enabled"]},
        )
        return redirect("backup_control:dashboard")
    return render(request, "backup_control/dashboard.html", {"data": dashboard_payload(), "downloads": list_downloads()})


@platform_admin_required
def download_backup(request: HttpRequest, name: str):
    try:
        path = download_path(name)
    except (ValueError, FileNotFoundError):
        raise Http404
    record_event(
        actor=request.user,
        action="backup.download",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=request.META.get("REMOTE_ADDR"),
        object_type="BackupArtifact",
        object_public_id=path.name,
        metadata={"size": path.stat().st_size, "sha256_suffix": _sha256_suffix(path)},
    )
    response = FileResponse(path.open("rb"), as_attachment=True, filename=path.name, content_type="application/octet-stream")
    response["Cache-Control"] = "no-store"
    return response


@platform_admin_required
@require_http_methods(["POST"])
@close_legacy_html
def cleanup(request: HttpRequest):
    if request.POST.get("confirmation") != "1":
        return redirect("backup_control:dashboard")
    if not get_policy().cleanup_enabled:
        from django.contrib import messages

        messages.error(request, "自动清理已关闭，请先在备份中心打开清理开关。")
        return redirect("backup_control:dashboard")
    try:
        result = execute_cleanup(
            actor=request.user,
            idempotency_key=f"web-{uuid.uuid4().hex}",
            request_body=b"{}",
            request_id=_request_id(request),
            ip_address=request.META.get("REMOTE_ADDR"),
        )
    except StorageCleanupError as exc:
        from django.contrib import messages

        messages.error(request, exc.message)
    else:
        from django.contrib import messages

        messages.success(request, f"清理完成：删除 {result['deleted_count']} 个文件，共 {result['deleted_bytes']} bytes。")
    return redirect("backup_control:dashboard")


def _sha256_suffix(path):
    from .services import _sha256_suffix as suffix

    return suffix(path)


@_admin_required
@_api_methods("GET", "POST")
def api_dashboard(request: HttpRequest, _identity) -> JsonResponse:
    if request.method == "GET":
        return _success(dashboard_payload())
    payload, error = _read_json(request)
    if error:
        return error
    key, key_error = _validate_idempotency_key(request, "备份设置必须提供幂等键。")
    if key_error:
        return key_error
    request_hash = _request_hash(payload or {})
    try:
        with transaction.atomic():
            _locked_policy()
            replay = existing_operation(actor=request.user, action="policy.update", key=key, request_hash=request_hash)
            if replay is not None:
                return _success(replay)
            policy = update_policy(actor=request.user, values=payload or {})
            record_event(
                actor=request.user,
                action="backup.policy.update",
                outcome=AuditOutcome.SUCCESS,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                metadata={
                    "enabled": policy.enabled,
                    "schedule_enabled": policy.schedule_enabled,
                    "github_enabled": policy.github_enabled,
                    "full_time": f"{policy.schedule_full_hour:02d}:{policy.schedule_full_minute:02d}",
                    "github_repository": policy.github_repository,
                },
            )
            response = dashboard_payload()
            store_operation(actor=request.user, action="policy.update", key=key, request_hash=request_hash, response=response)
            return _success(response)
    except BackupControlError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    except OperationalError:
        return _error(request, "BACKUP_STORAGE_UNAVAILABLE", "备份设置暂时无法保存，请稍后重试。", status=503, retryable=True)


@_admin_required
@_api_methods("POST")
def api_backup_run(request: HttpRequest, _identity) -> JsonResponse:
    payload, error = _read_json(request)
    if error:
        return error
    key, key_error = _validate_idempotency_key(request, "排队备份必须提供幂等键。")
    if key_error:
        return key_error
    request_hash = _request_hash(payload or {})
    try:
        with transaction.atomic():
            _locked_policy()
            replay = existing_operation(actor=request.user, action="run.create", key=key, request_hash=request_hash)
            if replay is not None:
                return _success(replay)
            if not allow_rate("backup-run", str(request.user.pk), limit=5, timeout=3600):
                return _error(request, "RATE_LIMITED", "排队备份过于频繁，请稍后再试。", status=429, retryable=True)
            run = request_backup_run(actor=request.user, backup_type=str((payload or {}).get("backup_type") or "full"))
            record_event(
                actor=request.user,
                action="backup.run.request",
                outcome=AuditOutcome.SUCCESS,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                object_type="BackupRunRequest",
                object_public_id=str(run.public_id),
                metadata={"backup_type": run.backup_type, "status": run.status},
            )
            response = dashboard_payload()
            store_operation(actor=request.user, action="run.create", key=key, request_hash=request_hash, response=response)
            return _success(response)
    except BackupControlError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    except OperationalError:
        return _error(request, "BACKUP_STORAGE_UNAVAILABLE", "备份任务暂时无法排队，请稍后重试。", status=503, retryable=True)


@_admin_required
@_api_methods("POST")
def api_backup_destination_probe(request: HttpRequest, _identity) -> JsonResponse:
    if not allow_rate("backup-destination-probe", str(request.user.pk), limit=10, timeout=3600):
        return _error(request, "RATE_LIMITED", "试连过于频繁，请稍后再试。", status=429, retryable=True)
    try:
        payload = probe_backup_destinations()
    except BackupControlError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    record_event(
        actor=request.user,
        action="backup.destinations.probe",
        outcome=AuditOutcome.SUCCESS if payload.get("ok") else AuditOutcome.FAILURE,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        metadata={
            "ok": payload.get("ok"),
            "targets": [item.get("target") for item in payload.get("results") or []],
            "uploaded": False,
        },
    )
    return _success(payload)


@_admin_required
@_api_methods("GET")
def api_download_backup(request: HttpRequest, _identity, name: str):
    try:
        path = download_path(name)
    except ValueError:
        return _error(request, "INVALID_BACKUP_FILE", "备份文件名无效。", status=400)
    except FileNotFoundError:
        return _error(request, "BACKUP_FILE_NOT_FOUND", "备份文件不存在。", status=404)
    record_event(
        actor=request.user,
        action="backup.download",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        object_type="BackupArtifact",
        object_public_id=path.name,
        metadata={"size": path.stat().st_size, "sha256_suffix": _sha256_suffix(path)},
    )
    response = FileResponse(path.open("rb"), as_attachment=True, filename=path.name, content_type="application/octet-stream")
    response["Cache-Control"] = "no-store"
    return response


@_admin_required
@_api_methods("POST")
def api_delete_backup_download(request: HttpRequest, _identity, name: str) -> JsonResponse:
    from .download_deletion import recoverable_delete
    payload, error = _read_json(request)
    if error:
        return error
    key, key_error = _validate_idempotency_key(request, "删除加密备份必须提供幂等键。")
    if key_error:
        return key_error
    if not allow_rate("backup-download-delete", str(request.user.pk), limit=20, timeout=3600):
        return _error(request, "RATE_LIMITED", "删除备份过于频繁，请稍后再试。", status=429, retryable=True)
    body = payload or {}
    request_hash = _request_hash({"name": name, "confirmed": bool(body.get("confirmed"))})
    try:
        with recoverable_delete(actor=request.user, key=key, request_hash=request_hash), transaction.atomic():
            # Acquire the shared DB lock before the idempotency read or any
            # file effect. Keep it through result persistence, so a waiter
            # sees the committed result/conflict before touching another file.
            _locked_policy()
            replay = existing_operation(actor=request.user, action="download.delete", key=key, request_hash=request_hash)
            if replay is not None:
                return _success(replay)
            result = delete_encrypted_download(name=name, confirmed=bool(body.get("confirmed")))
            record_event(
                actor=request.user,
                action="backup.download.delete",
                outcome=AuditOutcome.SUCCESS,
                request_id=_request_id(request),
                ip_address=_ip_address(request),
                object_type="BackupArtifact",
                object_public_id=result["deleted"],
                metadata={
                    "name": result["deleted"],
                    "size": result["size"],
                    "sha256_suffix": result["sha256_suffix"],
                    "remaining_count": result["remaining_count"],
                    "retention_count": result["retention_count"],
                },
            )
            store_operation(
                actor=request.user,
                action="download.delete",
                key=key,
                request_hash=request_hash,
                response=result,
            )
            return _success(result)
    except BackupControlError as exc:
        record_event(
            actor=request.user,
            action="backup.download.delete",
            outcome=AuditOutcome.FAILURE,
            request_id=_request_id(request),
            ip_address=_ip_address(request),
            object_type="BackupArtifact",
            object_public_id=name,
            metadata={"code": exc.code, "name": name},
        )
        return _error(request, exc.code, exc.message, status=exc.status)
    except OperationalError:
        return _error(request, "BACKUP_STORAGE_UNAVAILABLE", "暂时无法确认删除结果，请刷新列表后使用原请求重试。", status=503, retryable=True)


@_admin_required
@_api_methods("POST")
def api_restore_inspect(request: HttpRequest, _identity) -> JsonResponse:
    if not allow_rate("backup-restore-inspect", str(request.user.pk), limit=10, timeout=3600):
        return _error(request, "RATE_LIMITED", "核对备份过于频繁，请稍后再试。", status=429, retryable=True)
    upload = request.FILES.get("file") or request.FILES.get("backup_file")
    passphrase = str(request.POST.get("passphrase") or "")
    if upload is None:
        return _error(request, "INVALID_BACKUP_FILE", "请选择加密备份文件。", status=400)
    try:
        payload = inspect_restore_upload(actor=request.user, upload=upload, passphrase=passphrase)
    except BackupControlError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    record_event(
        actor=request.user,
        action="backup.restore.inspect",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        object_type="BackupRestoreStaging",
        object_public_id=str(payload.get("staging_id") or ""),
        metadata={
            "original_name": payload.get("original_name"),
            "backup_time_beijing": payload.get("backup_time_beijing"),
            "sha256_suffix": payload.get("sha256_suffix"),
            "site_empty": payload.get("site_empty"),
            "can_restore": payload.get("can_restore"),
        },
    )
    return _success(payload)


@_admin_required
@_api_methods("POST")
def api_restore_apply(request: HttpRequest, _identity) -> JsonResponse:
    payload, error = _read_json(request)
    if error:
        return error
    key = _idempotency_key(request)
    if not key:
        return _error(request, "IDEMPOTENCY_REQUIRED", "确认导入必须提供幂等键。", status=400)
    if not allow_rate("backup-restore-apply", str(request.user.pk), limit=3, timeout=3600):
        return _error(request, "RATE_LIMITED", "导入过于频繁，请稍后再试。", status=429, retryable=True)
    body = payload or {}
    request_hash = _request_hash(
        {
            "staging_id": str(body.get("staging_id") or ""),
            "confirmed_backup_time": str(body.get("confirmed_backup_time") or ""),
        }
    )
    try:
        replay = existing_operation(actor=request.user, action="restore.apply", key=key, request_hash=request_hash)
    except BackupControlError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    if replay is not None:
        return _success(replay)
    try:
        result = confirm_restore(
            actor=request.user,
            staging_id=str(body.get("staging_id") or ""),
            passphrase=str(body.get("passphrase") or ""),
            confirmed_backup_time=str(body.get("confirmed_backup_time") or ""),
        )
    except BackupControlError as exc:
        return _error(request, exc.code, exc.message, status=exc.status)
    record_event(
        actor=request.user,
        action="backup.restore.apply",
        outcome=AuditOutcome.SUCCESS,
        request_id=_request_id(request),
        ip_address=_ip_address(request),
        object_type="BackupRestoreStaging",
        object_public_id=str(body.get("staging_id") or ""),
        metadata={
            "backup_time_beijing": result.get("backup_time_beijing"),
            "restore_command_finished": True,
            "inventory_compared": False,
        },
    )
    store_operation(actor=request.user, action="restore.apply", key=key, request_hash=request_hash, response=result)
    return _success(result)
