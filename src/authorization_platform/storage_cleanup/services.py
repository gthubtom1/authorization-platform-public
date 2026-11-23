from __future__ import annotations

import hashlib
import os
from datetime import timedelta
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.core.object_storage import ObjectStorageError, configured_object_store
from authorization_platform.releases.models import Release, ReleaseStatus

from .models import StorageCleanupOperation, StorageCleanupState


class StorageCleanupError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class CleanupCandidate:
    path: Path | None
    relative_path: str
    size: int
    reason: str
    release_id: str = ""
    expected_sha256: str = ""
    object_key: str = ""
    modified_at: float = 0.0


def _root() -> Path:
    return Path(getattr(settings, "STORAGE_ROOT", Path(settings.BASE_DIR) / "storage")).resolve()


def _release_root() -> Path:
    return Path(getattr(settings, "RELEASE_STORAGE_ROOT", _root() / "releases")).resolve()


def _ensure_local_storage_adapter() -> None:
    provider = str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower()
    if provider != "local":
        raise StorageCleanupError(
            "OBJECT_STORAGE_PROVIDER_UNAVAILABLE",
            "当前对象存储 provider 尚未接入，已拒绝清理本地路径。",
            status=503,
        )


def _retention_seconds() -> int:
    return max(0, int(getattr(settings, "STORAGE_CLEANUP_RETENTION_DAYS", 30))) * 86400


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _candidate(path: Path, root: Path, *, reason: str, release_id: str = "", expected_sha256: str = "") -> CleanupCandidate | None:
    if not path.exists() or not path.is_file() or path.is_symlink() or not _under(path, root):
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    return CleanupCandidate(
        path=path.resolve(),
        relative_path=relative,
        size=stat.st_size,
        reason=reason,
        release_id=release_id,
        expected_sha256=expected_sha256,
    )


def scan_cleanup_candidates(*, now=None) -> tuple[list[CleanupCandidate], bool]:
    now = now or timezone.now()
    cutoff = now.timestamp() - _retention_seconds()
    candidates: dict[str, CleanupCandidate] = {}
    release_root = _release_root()
    provider = str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower()
    remote_store = configured_object_store(root=release_root) if provider in {"s3", "s3-compatible"} else None
    withdrawn = Release.objects.filter(status=ReleaseStatus.WITHDRAWN, withdrawn_at__isnull=False, withdrawn_at__lte=now).only(
        "release_id", "package_path", "package_sha256", "withdrawn_at"
    )
    for release in withdrawn.iterator():
        if release.withdrawn_at and release.withdrawn_at.timestamp() > cutoff:
            continue
        if not release.package_path:
            continue
        if remote_store is not None:
            try:
                stored = remote_store.head(release.package_path)
            except ObjectStorageError as exc:
                if exc.status_code != 404:
                    continue
                item = CleanupCandidate(
                    path=None,
                    relative_path=release.package_path,
                    size=release.package_size,
                    reason="withdrawn_release_package",
                    release_id=str(release.release_id),
                    expected_sha256=release.package_sha256,
                    object_key=release.package_path,
                )
                candidates[item.object_key] = item
                continue
            if release.package_sha256 and (not stored.sha256 or stored.sha256.lower() != release.package_sha256.lower()):
                continue
            item = CleanupCandidate(
                path=None,
                relative_path=release.package_path,
                size=stored.size,
                reason="withdrawn_release_package",
                release_id=str(release.release_id),
                expected_sha256=release.package_sha256,
                object_key=release.package_path,
            )
            candidates[item.object_key] = item
            continue
        path = Path(release.package_path)
        if not path.is_absolute():
            path = release_root / path
        item = _candidate(
            path,
            release_root,
            reason="withdrawn_release_package",
            release_id=str(release.release_id),
            expected_sha256=release.package_sha256,
        )
        if item:
            candidates[str(item.path)] = item

    if remote_store is not None and hasattr(remote_store, "list_prefix"):
        known_keys = set(
            Release.objects.exclude(package_path="").values_list("package_path", flat=True)
        )
        try:
            listed_objects = remote_store.list_prefix("pending/")
        except ObjectStorageError:
            listed_objects = []
        for entry in listed_objects:
            object_key = str(entry.get("key", ""))
            modified_at = float(entry.get("last_modified", 0.0) or 0.0)
            if not object_key or object_key in known_keys or modified_at > cutoff:
                continue
            item = CleanupCandidate(
                path=None,
                relative_path=object_key,
                size=max(0, int(entry.get("size", 0) or 0)),
                reason="orphan_release_package",
                object_key=object_key,
                modified_at=modified_at,
            )
            candidates[object_key] = item
    # The application volume still owns temporary exports and logs when the
    # release package itself lives in S3.  Keep this local scan independent
    # from the release/object-store provider so a production S3 deployment
    # cannot silently skip files that are able to fill the VPS disk.
    root = _root()
    for directory_name, reason in (("tmp", "temporary_file"), ("exports", "expired_export"), ("logs", "old_log_residue")):
        directory = (root / directory_name).resolve()
        if not _under(directory, root) or not directory.exists() or not directory.is_dir() or directory.is_symlink():
            continue
        for path in directory.rglob("*"):
            if path.is_symlink():
                continue
            try:
                if path.is_file() and path.stat().st_mtime <= cutoff:
                    item = _candidate(path, root, reason=reason)
                    if item:
                        candidates[str(item.path)] = item
            except OSError:
                continue
    ordered = sorted(candidates.values(), key=lambda item: (item.relative_path, item.reason))
    return _apply_cleanup_window(ordered)


def _apply_cleanup_window(ordered: list[CleanupCandidate]) -> tuple[list[CleanupCandidate], bool]:
    max_files = max(1, int(getattr(settings, "STORAGE_CLEANUP_MAX_FILES", 1000)))
    max_bytes = max(1, int(getattr(settings, "STORAGE_CLEANUP_MAX_BYTES", 5 * 1024 * 1024 * 1024)))
    result: list[CleanupCandidate] = []
    total = 0
    truncated = False
    for item in ordered:
        if len(result) >= max_files:
            truncated = True
            break
        if total + item.size > max_bytes:
            truncated = True
            continue
        result.append(item)
        total += item.size
    return result, truncated


def candidates_payload(candidates: list[CleanupCandidate], *, truncated: bool = False) -> dict[str, Any]:
    return {
        "candidate_count": len(candidates),
        "candidate_bytes": sum(item.size for item in candidates),
        "truncated": truncated,
        "candidates": [
            {"path": item.relative_path, "size": item.size, "reason": item.reason, "release_id": item.release_id or None}
            for item in candidates
        ],
        "retention_days": int(getattr(settings, "STORAGE_CLEANUP_RETENTION_DAYS", 30)),
    }


def _key(value: str | None) -> str:
    value = (value or "").strip()
    if not value or len(value) > 128:
        raise StorageCleanupError("INVALID_REQUEST", "缺少有效的重复提交标识。")
    return value


def inspect_cleanup() -> dict[str, Any]:
    candidates, truncated = scan_cleanup_candidates()
    return candidates_payload(candidates, truncated=truncated)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_still_matches(item: CleanupCandidate) -> bool:
    """Recheck the file immediately before deletion to avoid deleting changed content."""
    if item.object_key:
        try:
            stored = configured_object_store(root=_release_root()).head(item.object_key)
        except ObjectStorageError as exc:
            return exc.status_code == 404
        return (
            stored.size == item.size
            and bool(stored.sha256)
            and (not item.expected_sha256 or stored.sha256.lower() == item.expected_sha256.lower())
        )
    if item.path is None:
        return False
    try:
        if item.path.is_symlink() or not item.path.is_file():
            return False
        root = _release_root() if item.release_id else _root()
        if not _under(item.path, root):
            return False
        stat = item.path.stat()
        if stat.st_size != item.size:
            return False
        if item.expected_sha256 and _sha256_file(item.path) != item.expected_sha256.lower():
            return False
    except OSError:
        return False
    return True


def execute_cleanup(*, actor, idempotency_key: str, request_body: bytes, request_id: str, ip_address: str | None) -> dict[str, Any]:
    key = _key(idempotency_key)
    request_hash = hashlib.sha256(request_body).hexdigest()
    existing = StorageCleanupOperation.objects.filter(actor=actor, idempotency_key=key).first()
    if existing:
        if existing.request_hash != request_hash:
            raise StorageCleanupError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
        payload = dict(existing.response)
        payload["repeated"] = True
        return payload
    with transaction.atomic():
        StorageCleanupState.objects.get_or_create(key="default")
        state = StorageCleanupState.objects.select_for_update().get(key="default")
        existing = StorageCleanupOperation.objects.filter(actor=actor, idempotency_key=key).first()
        if existing:
            if existing.request_hash != request_hash:
                raise StorageCleanupError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
            payload = dict(existing.response)
            payload["repeated"] = True
            return payload
        candidates, truncated = scan_cleanup_candidates()
        deleted_count = 0
        deleted_bytes = 0
        skipped_count = 0
        for item in candidates:
            try:
                if not _candidate_still_matches(item):
                    skipped_count += 1
                    continue
                if item.object_key:
                    configured_object_store(root=_release_root()).delete(item.object_key)
                else:
                    assert item.path is not None
                    item.path.unlink()
                deleted_count += 1
                deleted_bytes += item.size
                if item.release_id:
                    Release.objects.filter(
                        release_id=item.release_id,
                        package_path=item.object_key or str(item.path),
                    ).update(package_path="", package_deleted_at=timezone.now())
            except FileNotFoundError:
                skipped_count += 1
            except (OSError, ObjectStorageError):
                skipped_count += 1
        state.updated_at = max(timezone.now(), state.updated_at + timedelta(microseconds=1))
        state.save(update_fields=("updated_at",))
        payload = {
            "candidate_count": len(candidates),
            "candidate_bytes": sum(item.size for item in candidates),
            "truncated": truncated,
            "deleted_count": deleted_count,
            "deleted_bytes": deleted_bytes,
            "skipped_count": skipped_count,
            "repeated": False,
        }
        try:
            StorageCleanupOperation.objects.create(actor=actor, idempotency_key=key, request_hash=request_hash, response=payload)
        except IntegrityError:
            other = StorageCleanupOperation.objects.get(actor=actor, idempotency_key=key)
            if other.request_hash != request_hash:
                raise StorageCleanupError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
            result = dict(other.response)
            result["repeated"] = True
            return result
        record_event(actor=actor, action="storage.cleanup", outcome=AuditOutcome.SUCCESS, request_id=request_id, ip_address=ip_address, object_type="StorageCleanup", object_public_id=key, metadata={"candidate_count": len(candidates), "deleted_count": deleted_count, "deleted_bytes": deleted_bytes, "skipped_count": skipped_count})
        return payload
