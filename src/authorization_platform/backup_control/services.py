from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from typing import Any
import http.client
import ssl
from uuid import UUID
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.db import IntegrityError, connections, transaction
from django.utils import timezone

try:  # psycopg is a production dependency; local SQLite runs may not have it.
    import psycopg
except ImportError:  # pragma: no cover - exercised only without the driver
    psycopg = None

from authorization_platform.core.backup_governance import backup_health, disk_capacity_for_path
from authorization_platform.storage_cleanup.services import inspect_cleanup

from .models import BackupControlOperation, BackupPolicy, BackupRestoreStaging, BackupRunRequest

BEIJING_TZ = ZoneInfo("Asia/Shanghai")
LOGGER = logging.getLogger(__name__)
GITHUB_REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?/[A-Za-z0-9._-][A-Za-z0-9._-]{0,98}$"
)
BACKUP_FILENAME_RE = re.compile(r"authorization-platform-enc-(\d{8})-(\d{6})\.dump\.enc$", re.IGNORECASE)
OPENSSL_MAGIC = b"Salted__"
OPENSSL_PBKDF2_ITERATIONS = 10000
PGDMP_MAGIC = b"PGDMP"
STALE_RUNNING_MINUTES = 90
RESTORE_STAGING_TTL = timedelta(minutes=30)
SCHEDULE_SLOT_STAMP_PREFIX = "schedule-slot-v1:"
PASSPHRASE_ERROR = "口令不对，或这不是本平台的加密备份。"
SITE_NONEMPTY_MESSAGE = "当前有业务数据，不能导入。"
INSPECT_PASSPHRASE_OK_NONEMPTY = "文件和口令对，但当前有业务数据，不能导入。"
SITE_EMPTY_READY_MESSAGE = "当前没有业务数据，可以核对应导入的备份。"

REMOVED_NETDISK_KEYS = frozenset(
    {
        "netdisk_preset",
        "netdisk_kind",
        "s3_enabled",
        "s3_endpoint",
        "s3_bucket",
        "s3_region",
        "s3_access_key_id",
        "s3_secret",
        "s3_secret_configured",
        "webdav_enabled",
        "webdav_endpoint",
        "webdav_username",
        "webdav_remote_path",
        "webdav_password",
        "webdav_password_configured",
    }
)


class BackupControlError(ValueError):
    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def get_policy() -> BackupPolicy:
    policy, created = BackupPolicy.objects.get_or_create(key="default")
    if created:
        policy.retention_full = max(1, int(getattr(settings, "BACKUP_RETENTION_FULL", 7) or 7))
        policy.retention_diff = max(1, int(getattr(settings, "BACKUP_RETENTION_DIFF", 14) or 14))
        policy.retention_archive = max(1, int(getattr(settings, "BACKUP_RETENTION_ARCHIVE", 14) or 14))
        policy.github_retention_count = policy.retention_full
        policy.save(
            update_fields=(
                "retention_full",
                "retention_diff",
                "retention_archive",
                "github_retention_count",
                "updated_at",
            )
        )
    return policy


def _locked_policy() -> BackupPolicy:
    """Serialize every queue mutation through the singleton policy row."""
    policy = get_policy()
    return BackupPolicy.objects.select_for_update().get(pk=policy.pk)


def _status_path() -> Path | None:
    configured = str(getattr(settings, "BACKUP_STATUS_FILE", "") or "").strip()
    if not configured:
        return None
    return Path(configured).expanduser()


def _read_status() -> dict[str, Any] | None:
    path = _status_path()
    if path is None:
        return None
    try:
        if not path.is_file() or path.is_symlink():
            return None
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    return document if isinstance(document, dict) else None


def _proof_summary(status: dict[str, Any] | None) -> dict[str, Any]:
    proof = status.get("last_success_proof") if isinstance(status, dict) else None
    if not isinstance(proof, dict):
        return {"available": False}
    repositories = []
    for item in proof.get("repositories", []):
        if isinstance(item, dict):
            repositories.append(
                {
                    "name": str(item.get("name", "repository")),
                    "status": str(item.get("status", "unknown")),
                    "sha256_suffix": str(item.get("backup_sha256", ""))[-12:],
                }
            )
    wal = proof.get("wal") if isinstance(proof.get("wal"), dict) else {}
    objects = proof.get("object_manifest") if isinstance(proof.get("object_manifest"), dict) else {}
    inventory = proof.get("recovery_inventory") if isinstance(proof.get("recovery_inventory"), dict) else {}
    return {
        "available": True,
        "run_id": str(proof.get("backup_run_id", "")),
        "completed_at_utc": str(proof.get("completed_at_utc", "")),
        "repositories": repositories,
        "wal": {
            "status": str(wal.get("status", "unknown")),
            "archive_ready": bool(wal.get("archive_ready", False)),
            "start_lsn": str(wal.get("start_lsn", "")),
            "end_lsn": str(wal.get("end_lsn", "")),
        },
        "objects": {"status": str(objects.get("status", "unknown")), "object_count": int(objects.get("object_count", 0) or 0)},
        "recovery_inventory": {
            "status": str(inventory.get("status", "unknown")),
            "matches": bool(inventory.get("matches", False)),
            "ciphertext_verified": bool(inventory.get("ciphertext_verification", False)),
        },
    }


def _fernet() -> Fernet:
    key = settings.INVITATION_ENCRYPTION_KEY
    return Fernet(key.encode("ascii") if isinstance(key, str) else key)


def _encrypt_secret(plain: str) -> str:
    value = (plain or "").strip()
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt_secret(ciphertext: str) -> str:
    token = (ciphertext or "").strip()
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, UnicodeError):
        return ""


def _secret_configured(ciphertext: str) -> bool:
    return bool(_decrypt_secret(ciphertext))


def _normalize_github_repository(value: object) -> str:
    text = _bounded_string(value, field="GitHub 仓库", maximum=200)
    if not text:
        return ""
    text = text.rstrip("/")
    if text.lower().endswith(".git"):
        text = text[:-4]
    lowered = text.lower()
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if lowered.startswith(prefix):
            text = text[len(prefix) :]
            lowered = text.lower()
            break
    text = text.split("/", 2)
    if len(text) >= 2:
        text = f"{text[0]}/{text[1]}"
    else:
        text = text[0]
    if "://" in text or text.startswith("git@") or not GITHUB_REPO_RE.fullmatch(text):
        raise BackupControlError("INVALID_POLICY", "GitHub 仓库请填写 owner/repo，例如 your-name/authorization-platform-backup。")
    return text


KEY_FILE_NAMES = frozenset(
    {
        "github-token.txt",
    }
)


def _keys_dir() -> Path:
    configured = str(getattr(settings, "BACKUP_KEYS_DIR", "") or "").strip()
    if not configured:
        configured = str(Path(settings.BASE_DIR) / "storage" / "backup-keys")
    root = Path(configured).expanduser().resolve()
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise BackupControlError("INVALID_POLICY", "备份凭据目录不是普通目录。")
    return root


def _keys_target(path: Path, filename: str) -> Path:
    if filename not in KEY_FILE_NAMES:
        raise BackupControlError("INVALID_POLICY", "凭据文件名不受支持。")
    requested = Path(path).expanduser()
    if not requested.is_absolute() or requested.name != filename:
        raise BackupControlError("INVALID_POLICY", f"凭据只能写入名为 {filename} 的绝对路径。")
    if requested.parent.exists() and requested.parent.is_symlink():
        raise BackupControlError("INVALID_POLICY", "凭据目录不能是符号链接。")
    keys = _keys_dir()
    if keys.exists() and keys.is_symlink():
        raise BackupControlError("INVALID_POLICY", "备份凭据目录不能是符号链接。")
    keys.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(keys, 0o700)
    except OSError:
        pass
    resolved = requested.resolve(strict=False)
    try:
        resolved.relative_to(keys)
    except ValueError as exc:
        raise BackupControlError("INVALID_POLICY", "凭据只能写入配置的备份密钥目录。") from exc
    if resolved.name != filename:
        raise BackupControlError("INVALID_POLICY", f"凭据只能写入名为 {filename} 的绝对路径。")
    return keys / filename


def _write_secret_file(target: Path, secret: str) -> None:
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise BackupControlError("INVALID_POLICY", "凭据目标不是普通文件。")
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow and os.name != "nt":
        flags |= nofollow
    try:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        fd = os.open(target, flags, 0o600)
        try:
            os.write(fd, secret.encode("utf-8"))
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(fd, 0o600)
        finally:
            os.close(fd)
    except OSError as exc:
        raise BackupControlError("INVALID_POLICY", "备份凭据目录无法写入。", status=500) from exc
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def write_github_token_file(path: Path) -> str:
    target = _keys_target(path, "github-token.txt")
    policy = get_policy()
    if not policy.github_enabled:
        if target.is_file() and not target.is_symlink():
            _write_secret_file(target, "")
        return "disabled"
    secret = _decrypt_secret(policy.github_token_ciphertext)
    if not secret:
        raise BackupControlError("INVALID_POLICY", "GitHub 副本已开启，但服务器上没有可用令牌。")
    _write_secret_file(target, secret)
    return "written"


def _bounded_string(value: object, *, field: str, maximum: int, allow_empty: bool = True) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise BackupControlError("INVALID_POLICY", f"{field} 必须是文本。")
    text = value.strip()
    if not text:
        if allow_empty:
            return ""
        raise BackupControlError("INVALID_POLICY", f"{field} 不能为空。")
    if len(text) > maximum:
        raise BackupControlError("INVALID_POLICY", f"{field} 过长。")
    return text


def _int_in_range(value: object, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        value = int(value.strip())
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackupControlError("INVALID_POLICY", f"{field} 必须是整数。")
    if not minimum <= value <= maximum:
        raise BackupControlError("INVALID_POLICY", f"{field} 必须在 {minimum} 到 {maximum} 之间。")
    return value


def _optional_bool(value: object, *, field: str) -> bool:
    if not isinstance(value, bool):
        raise BackupControlError("INVALID_POLICY", f"{field} 必须是开关值。")
    return value


def _reject_removed_netdisk(values: dict[str, Any]) -> None:
    if any(key in values for key in REMOVED_NETDISK_KEYS):
        raise BackupControlError("INVALID_POLICY", "备份去向只有这台服务器和可选 GitHub，不能再配置网盘。")


def _schedule_payload(policy: BackupPolicy) -> dict[str, Any]:
    hour = int(policy.schedule_full_hour)
    minute = int(policy.schedule_full_minute)
    return {
        "timezone": "Asia/Shanghai",
        "full_hour": hour,
        "full_minute": minute,
        "full_time": f"{hour:02d}:{minute:02d}",
        "diff_interval_hours": int(policy.diff_interval_hours),
    }


def _run_payload(item: BackupRunRequest) -> dict[str, Any]:
    return {
        "public_id": str(item.public_id),
        "backup_type": item.backup_type,
        "scheduled_for_utc": item.scheduled_for.isoformat() if item.scheduled_for else "",
        "status": item.status,
        "message": item.message,
        "created_at": item.created_at.isoformat(),
    }


def _policy_public(policy: BackupPolicy) -> dict[str, Any]:
    return {
        "enabled": policy.enabled,
        "schedule_enabled": bool(policy.schedule_enabled),
        "database_enabled": policy.database_enabled,
        "github_enabled": policy.github_enabled,
        "github_repository": policy.github_repository,
        "github_token_configured": _secret_configured(policy.github_token_ciphertext),
        "cleanup_enabled": policy.cleanup_enabled,
        "retention_full": policy.retention_full,
        "retention_diff": policy.retention_diff,
        "retention_archive": policy.retention_archive,
        "github_retention_count": policy.github_retention_count,
        "schedule": _schedule_payload(policy),
        "updated_at": policy.updated_at.isoformat(),
    }


def _effective_rpo_minutes(policy) -> int:
    """健康检查的「多久算过期」必须跟真实备份节奏走。

    旧实现固定用 ``BACKUP_RPO_MINUTES``（默认 15）——那是**巡检**节奏，不是备份
    节奏：全量一天一次、增量每 6 小时一次，于是每次成功备份几十分钟后就被判"过期"，
    管理端一直显示 critical。这里按当前策略的增量间隔算：两个周期 + 一小时余量。
    备份真的卡住（超过两个增量周期没有新备份）仍然会亮红灯；显式配大的值也照旧尊重。
    """

    configured = int(getattr(settings, "BACKUP_RPO_MINUTES", 0) or 0)
    interval_hours = max(1, int(getattr(policy, "diff_interval_hours", 6) or 6))
    cadence = interval_hours * 60 * 2 + 60
    return max(configured, cadence, 1)


def dashboard_payload() -> dict[str, Any]:
    policy = get_policy()
    status = _read_status()
    last_success = status.get("last_success_at_utc") if status else None
    disk = None
    try:
        disk = disk_capacity_for_path(Path(getattr(settings, "BASE_DIR", ".")))
    except OSError:
        pass
    health = (
        backup_health(
            status_document=status,
            now=datetime.now(dt_timezone.utc),
            rpo_minutes=_effective_rpo_minutes(policy),
            disk=disk,
        )
        if disk
        else {"status": "unknown", "reasons": ["disk_status_unavailable"]}
    )
    try:
        cleanup = inspect_cleanup()
    except Exception:
        cleanup = {
            "candidate_count": 0,
            "candidate_bytes": 0,
            "candidates": [],
            "retention_days": int(getattr(settings, "STORAGE_CLEANUP_RETENTION_DAYS", 30)),
            "status": "unavailable",
        }
    runs = [_run_payload(item) for item in BackupRunRequest.objects.all()[:20]]
    return {
        "policy": _policy_public(policy),
        "status": {
            "last_result": status.get("last_result") if status else "missing",
            "last_success_at_utc": last_success,
            "last_failure_at_utc": status.get("last_failure_at_utc") if status else None,
            "last_failure_code": status.get("last_failure_code") if status else None,
            "health": health,
            "proof": _proof_summary(status),
        },
        "status_file_configured": _status_path() is not None,
        "cleanup": cleanup,
        "runs": runs,
        "downloads": list_downloads(),
        "restore": site_restore_status(),
    }


def update_policy(*, actor, values: dict[str, Any]) -> BackupPolicy:
    with transaction.atomic():
        policy = _locked_policy()
        _reject_removed_netdisk(values)
        for name, label in (
            ("enabled", "备份总开关"),
            ("schedule_enabled", "定时备份"),
            ("database_enabled", "数据库备份"),
            ("github_enabled", "GitHub 副本"),
            ("cleanup_enabled", "自动清理"),
        ):
            if name in values:
                setattr(policy, name, _optional_bool(values[name], field=label))
        for name in ("retention_full", "retention_diff", "retention_archive", "github_retention_count"):
            if name in values:
                setattr(policy, name, _int_in_range(values[name], field=name, minimum=1, maximum=3650))
        if "schedule_full_hour" in values or "schedule_full_minute" in values or "full_time" in values:
            hour = policy.schedule_full_hour
            minute = policy.schedule_full_minute
            if "full_time" in values:
                raw = _bounded_string(values.get("full_time"), field="全量备份时间", maximum=5, allow_empty=False)
                match = re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", raw)
                if not match:
                    raise BackupControlError("INVALID_POLICY", "全量备份时间必须是 HH:MM，不能带秒数。")
                hour = int(match.group(0)[:2])
                minute = int(match.group(0)[3:])
            if "schedule_full_hour" in values:
                hour = _int_in_range(values["schedule_full_hour"], field="全量备份小时", minimum=0, maximum=23)
            if "schedule_full_minute" in values:
                minute = _int_in_range(values["schedule_full_minute"], field="全量备份分钟", minimum=0, maximum=59)
            policy.schedule_full_hour = hour
            policy.schedule_full_minute = minute
        if "diff_interval_hours" in values:
            policy.diff_interval_hours = _int_in_range(values["diff_interval_hours"], field="增量间隔小时", minimum=1, maximum=24)
        if "github_repository" in values:
            policy.github_repository = _normalize_github_repository(values.get("github_repository"))
        if "github_token" in values:
            token = _bounded_string(values.get("github_token"), field="GitHub 令牌", maximum=255)
            if token:
                policy.github_token_ciphertext = _encrypt_secret(token)
        if policy.github_enabled and (not policy.github_repository or not _secret_configured(policy.github_token_ciphertext)):
            raise BackupControlError("INVALID_POLICY", "开启 GitHub 加密副本时必须填写仓库（owner/repo）和访问令牌。")
        policy.updated_by = actor
        policy.save()
        return policy


def runner_export() -> dict[str, Any]:
    policy = get_policy()
    pending = BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).order_by("created_at").first()
    return {
        "enabled": policy.enabled,
        "schedule_enabled": bool(policy.schedule_enabled),
        "database_enabled": policy.database_enabled,
        "github_enabled": policy.github_enabled,
        "github_repository": policy.github_repository,
        "cleanup_enabled": policy.cleanup_enabled,
        "schedule": _schedule_payload(policy),
        "retention_full": policy.retention_full,
        "retention_diff": policy.retention_diff,
        "retention_archive": policy.retention_archive,
        "github_retention_count": policy.github_retention_count,
        "pending_run": _run_payload(pending) if pending else None,
        "secret_values_exposed": False,
        "github_token_configured": _secret_configured(policy.github_token_ciphertext),
    }


def _backup_trigger_path() -> Path:
    configured = str(getattr(settings, "BACKUP_ROOT", "") or "").strip()
    if configured:
        return Path(configured).expanduser().resolve() / "queue" / "need-run"
    return _download_root().parent / "queue" / "need-run"


def _touch_backup_trigger() -> None:
    path = _backup_trigger_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("1", encoding="utf-8")
    except OSError as exc:
        raise BackupControlError(
            "BACKUP_TRIGGER_UNAVAILABLE",
            "备份已排队，但无法唤醒主机备份程序，请检查备份目录权限。",
            status=503,
        ) from exc


def enqueue_change_backup(*, actor=None) -> BackupRunRequest | None:
    with transaction.atomic():
        policy = _locked_policy()
        if not policy.enabled:
            return None
        if BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).exists():
            return None
        now = timezone.now()
        user = actor if getattr(actor, "pk", None) else None
        row = BackupRunRequest.objects.create(
            backup_type=BackupRunRequest.BackupType.FULL,
            status=BackupRunRequest.Status.PENDING,
            actor=user,
            message="账本有变动，已排队备份到这台服务器和 GitHub。各留 3 份，满了覆盖最旧的。",
            created_at=now,
            updated_at=now,
        )
        running = BackupRunRequest.objects.filter(status=BackupRunRequest.Status.RUNNING).exists()
        if not running:
            transaction.on_commit(_touch_backup_trigger)
        return row


def schedule_change_backup(*, actor=None) -> None:
    def _run() -> None:
        try:
            enqueue_change_backup(actor=actor)
        except Exception:
            LOGGER.exception("backup trigger could not be queued after a business change")

    try:
        if transaction.get_connection().in_atomic_block:
            transaction.on_commit(_run)
        else:
            _run()
    except Exception:
        return


def request_backup_run(*, actor, backup_type: str) -> BackupRunRequest:
    chosen = (backup_type or BackupRunRequest.BackupType.FULL).strip()
    if chosen not in {BackupRunRequest.BackupType.FULL, BackupRunRequest.BackupType.DIFF}:
        raise BackupControlError("INVALID_POLICY", "备份类型只能是全量或增量。")
    pending_error: BackupControlError | None = None
    row: BackupRunRequest | None = None
    with transaction.atomic():
        policy = _locked_policy()
        if not policy.enabled:
            raise BackupControlError("BACKUP_DISABLED", "请先打开备份总开关，再点现在备份。", status=409)
        pending = BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).first()
        running = BackupRunRequest.objects.filter(status=BackupRunRequest.Status.RUNNING).exists()
        if pending is not None:
            if not running:
                transaction.on_commit(_touch_backup_trigger)
            pending_error = BackupControlError("BACKUP_RUN_PENDING", "已有一次备份在排队，已立即叫醒备份程序。", status=409)
        else:
            now = timezone.now()
            row = BackupRunRequest.objects.create(
                backup_type=chosen,
                status=BackupRunRequest.Status.PENDING,
                actor=actor,
                message="已开始备份。会先写到这台服务器；打开了 GitHub 会再拷一份。各留 3 份，满了覆盖最旧的。",
                created_at=now,
                updated_at=now,
            )
            if not running:
                transaction.on_commit(_touch_backup_trigger)
    if pending_error is not None:
        raise pending_error
    if row is None:
        raise BackupControlError("BACKUP_RUN_PENDING", "排队记录不存在。", status=500)
    return row


def _aware(moment: datetime) -> datetime:
    if timezone.is_naive(moment):
        return moment.replace(tzinfo=dt_timezone.utc)
    return moment


def _stamp_dir() -> Path:
    root = Path(
        getattr(settings, "BACKUP_SCHEDULE_STAMP_DIR", Path(settings.BASE_DIR) / "storage" / "backup-stamps")
    ).resolve()
    try:
        root.mkdir(parents=True, exist_ok=True)
        with os.scandir(root):
            pass
    except OSError as exc:
        raise BackupControlError(
            "BACKUP_SCHEDULE_UNAVAILABLE",
            "定时备份记录目录不可读，请检查备份目录权限。",
            status=503,
        ) from exc
    return root


def _stamp_path(kind: str) -> Path:
    if kind not in {"full", "diff"}:
        raise BackupControlError("INVALID_POLICY", "备份类型只能是全量或增量。")
    return _stamp_dir() / f"last-{kind}"


def read_schedule_stamp(kind: str) -> datetime | None:
    path = _stamp_path(kind)
    try:
        if path.is_symlink() or not path.is_file():
            return None
        content = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BackupControlError(
            "BACKUP_SCHEDULE_UNAVAILABLE",
            "定时备份记录不可读，请检查备份目录权限。",
            status=503,
        ) from exc
    if kind == "full":
        # Full stamps written before slot binding recorded completion time only.
        # They cannot prove that the current day's scheduled slot ran.
        if not content.startswith(SCHEDULE_SLOT_STAMP_PREFIX):
            return None
        content = content[len(SCHEDULE_SLOT_STAMP_PREFIX) :].strip()
    try:
        return _aware(datetime.fromisoformat(content))
    except ValueError:
        return None


def mark_schedule_stamp(kind: str, *, now: datetime | None = None) -> None:
    moment = _aware(now or timezone.now())
    path = _stamp_path(kind)
    content = moment.isoformat()
    if kind == "full":
        content = f"{SCHEDULE_SLOT_STAMP_PREFIX}{content}"
    try:
        temporary = None
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise BackupControlError(
            "BACKUP_SCHEDULE_UNAVAILABLE",
            "定时备份记录无法安全写入，请检查备份目录权限。",
            status=503,
        ) from exc


def scheduled_full_is_due(*, now: datetime | None = None) -> bool:
    return _scheduled_full_is_due(get_policy(), now=now)


def _scheduled_full_is_due(policy: BackupPolicy, *, now: datetime | None = None) -> bool:
    current = _aware(now or timezone.now()).astimezone(BEIJING_TZ)
    scheduled = current.replace(
        hour=int(policy.schedule_full_hour),
        minute=int(policy.schedule_full_minute),
        second=0,
        microsecond=0,
    )
    if current < scheduled:
        return False
    last = read_schedule_stamp("full")
    if last is not None and last.astimezone(BEIJING_TZ) == scheduled:
        return False
    return True


def _scheduled_full_slot(policy: BackupPolicy, *, now: datetime | None = None) -> datetime:
    current = _aware(now or timezone.now()).astimezone(BEIJING_TZ)
    return current.replace(
        hour=int(policy.schedule_full_hour),
        minute=int(policy.schedule_full_minute),
        second=0,
        microsecond=0,
    ).astimezone(dt_timezone.utc)


def scheduled_diff_is_due(*, now: datetime | None = None) -> bool:
    return _scheduled_diff_is_due(get_policy(), now=now)


def _scheduled_diff_is_due(policy: BackupPolicy, *, now: datetime | None = None) -> bool:
    current = _aware(now or timezone.now())
    last = read_schedule_stamp("diff")
    if last is None:
        return True
    return (current - last).total_seconds() >= int(policy.diff_interval_hours) * 3600


def _fail_stale_running_requests_locked(*, backup_type: str | None = None, now: datetime | None = None) -> int:
    current = _aware(now or timezone.now())
    cutoff = current - timedelta(minutes=STALE_RUNNING_MINUTES)
    requests = BackupRunRequest.objects.filter(
        status=BackupRunRequest.Status.RUNNING,
    )
    if backup_type is not None:
        requests = requests.filter(backup_type=backup_type)
    return requests.filter(updated_at__lt=cutoff).update(
        status=BackupRunRequest.Status.FAILED,
        attempt_token="",
        message="备份程序中断，没有写回结果。",
        updated_at=current,
    )


def fail_stale_running_requests(*, backup_type: str) -> int:
    chosen = (backup_type or "").strip()
    if chosen not in {BackupRunRequest.BackupType.FULL, BackupRunRequest.BackupType.DIFF}:
        raise BackupControlError("INVALID_POLICY", "备份类型只能是全量或增量。")
    with transaction.atomic():
        _locked_policy()
        return _fail_stale_running_requests_locked(backup_type=chosen)


def _claim_pending_run_locked(*, backup_type: str, now: datetime | None = None) -> BackupRunRequest | None:
    _fail_stale_running_requests_locked(now=now)
    if BackupRunRequest.objects.filter(status=BackupRunRequest.Status.RUNNING).exists():
        return None
    row = (
        BackupRunRequest.objects.select_for_update()
        .filter(status=BackupRunRequest.Status.PENDING)
        .order_by("created_at", "public_id")
        .first()
    )
    if row is None or row.backup_type != backup_type:
        return None
    current = _aware(now or timezone.now())
    attempt_token = uuid.uuid4().hex
    row.status = BackupRunRequest.Status.RUNNING
    row.attempt_token = attempt_token
    row.message = "备份程序正在执行。"
    row.updated_at = current
    row.save(update_fields=["status", "attempt_token", "message", "updated_at"])
    return row


def claim_pending_run(*, backup_type: str, now: datetime | None = None) -> BackupRunRequest | None:
    chosen = (backup_type or "").strip()
    if chosen not in {BackupRunRequest.BackupType.FULL, BackupRunRequest.BackupType.DIFF}:
        raise BackupControlError("INVALID_POLICY", "备份类型只能是全量或增量。")
    with transaction.atomic():
        _locked_policy()
        return _claim_pending_run_locked(backup_type=chosen, now=now)


def finish_backup_run(*, run_id: str, result: str, attempt_token: str = "", message: str = "") -> None:
    chosen = (result or "").strip()
    if chosen not in {BackupRunRequest.Status.SUCCEEDED, BackupRunRequest.Status.FAILED}:
        raise BackupControlError("INVALID_POLICY", "备份结果只能是成功或失败。")
    try:
        uid = UUID(str(run_id or "").strip())
    except (TypeError, ValueError) as exc:
        raise BackupControlError("BACKUP_RUN_PENDING", "排队记录不存在。", status=404) from exc
    with transaction.atomic():
        _locked_policy()
        row = BackupRunRequest.objects.select_for_update().filter(public_id=uid).first()
        if row is None:
            raise BackupControlError("BACKUP_RUN_PENDING", "排队记录不存在。", status=404)
        if row.status in {BackupRunRequest.Status.SUCCEEDED, BackupRunRequest.Status.FAILED}:
            return
        if row.status != BackupRunRequest.Status.RUNNING or not attempt_token or row.attempt_token != attempt_token:
            raise BackupControlError("BACKUP_RUN_OWNERSHIP", "备份任务已被其他执行者接管，不能写回结果。", status=409)
        row.status = chosen
        row.attempt_token = ""
        row.message = (message or "").strip()[:255]
        row.updated_at = timezone.now()
        row.save(update_fields=["status", "attempt_token", "message", "updated_at"])
        if BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING).exists():
            transaction.on_commit(_touch_backup_trigger)


def renew_backup_run(*, run_id: str, attempt_token: str) -> None:
    """Refresh the lease while a host runner is doing slow external work."""

    try:
        uid = UUID(str(run_id or "").strip())
    except (TypeError, ValueError) as exc:
        raise BackupControlError("BACKUP_RUN_PENDING", "排队记录不存在。", status=404) from exc
    token = str(attempt_token or "").strip()
    if not token:
        raise BackupControlError("BACKUP_RUN_OWNERSHIP", "备份任务缺少执行令牌。", status=409)
    with transaction.atomic():
        _locked_policy()
        row = BackupRunRequest.objects.select_for_update().filter(public_id=uid).first()
        if row is None:
            raise BackupControlError("BACKUP_RUN_PENDING", "排队记录不存在。", status=404)
        if row.status != BackupRunRequest.Status.RUNNING or row.attempt_token != token:
            raise BackupControlError("BACKUP_RUN_OWNERSHIP", "备份任务已被其他执行者接管。", status=409)
        row.updated_at = timezone.now()
        row.save(update_fields=["updated_at"])


def schedule_due_backups(*, now: datetime | None = None) -> dict[str, Any]:
    """Create at most one scheduled queue row and wake the host runner."""
    current = _aware(now or timezone.now())
    with transaction.atomic():
        policy = _locked_policy()
        pending = (
            BackupRunRequest.objects.filter(status=BackupRunRequest.Status.PENDING)
            .order_by("created_at", "public_id")
            .first()
        )
        if pending is not None:
            transaction.on_commit(_touch_backup_trigger)
            return {
                "queued": False,
                "backup_type": pending.backup_type,
                "reason": "pending",
                "pending_id": str(pending.public_id),
                "secret_values_exposed": False,
            }
        if not policy.enabled:
            return {
                "queued": False,
                "backup_type": "",
                "reason": "disabled",
                "pending_id": "",
                "secret_values_exposed": False,
            }
        if not policy.schedule_enabled:
            return {
                "queued": False,
                "backup_type": "",
                "reason": "schedule_disabled",
                "pending_id": "",
                "secret_values_exposed": False,
            }

        stale_running = _fail_stale_running_requests_locked(now=current)
        if BackupRunRequest.objects.filter(status=BackupRunRequest.Status.RUNNING).exists():
            return {
                "queued": False,
                "backup_type": "",
                "reason": "running",
                "pending_id": "",
                "stale_running_failed": stale_running,
                "secret_values_exposed": False,
            }

        scheduled_for = None
        if _scheduled_full_is_due(policy, now=current):
            backup_type = BackupRunRequest.BackupType.FULL
            reason = "full_due"
            message = "定时全量备份已排队，主机巡检会唤醒备份程序。"
            scheduled_for = _scheduled_full_slot(policy, now=current)
        elif _scheduled_diff_is_due(policy, now=current):
            backup_type = BackupRunRequest.BackupType.DIFF
            reason = "diff_due"
            message = "定时增量备份已排队，主机巡检会唤醒备份程序。"
        else:
            return {
                "queued": False,
                "backup_type": "",
                "reason": "not_due",
                "pending_id": "",
                "stale_running_failed": stale_running,
                "secret_values_exposed": False,
            }

        row = BackupRunRequest.objects.create(
            backup_type=backup_type,
            status=BackupRunRequest.Status.PENDING,
            actor=None,
            message=message,
            scheduled_for=scheduled_for,
            created_at=current,
            updated_at=current,
        )
        transaction.on_commit(_touch_backup_trigger)
        return {
            "queued": True,
            "backup_type": backup_type,
            "reason": reason,
            "pending_id": str(row.public_id),
            "stale_running_failed": stale_running,
            "secret_values_exposed": False,
        }


def decide_backup_run(*, backup_type: str, now: datetime | None = None) -> dict[str, Any]:
    chosen = (backup_type or "").strip()
    if chosen not in {BackupRunRequest.BackupType.FULL, BackupRunRequest.BackupType.DIFF}:
        raise BackupControlError("INVALID_POLICY", "备份类型只能是全量或增量。")
    pending = claim_pending_run(backup_type=chosen, now=now)
    # Read switches after the claim transaction so a concurrent policy update
    # cannot leave the host runner using a stale destination/retention view.
    policy = get_policy()
    execute = False
    reason = "not_due"
    if pending is not None:
        execute = True
        reason = "pending"
    elif not policy.enabled:
        reason = "disabled"
    else:
        reason = "idle"
    return {
        "execute": execute,
        "reason": reason,
        "backup_type": chosen,
        "pending_id": str(pending.public_id) if pending else "",
        "attempt_token": pending.attempt_token if pending else "",
        "scheduled_for_utc": pending.scheduled_for.isoformat() if pending and pending.scheduled_for else "",
        "github_enabled": bool(policy.github_enabled),
        "database_enabled": bool(policy.database_enabled),
        "cleanup_enabled": bool(policy.cleanup_enabled),
        "schedule_enabled": bool(policy.schedule_enabled),
        "netdisk": "disabled",
        "github_repository": policy.github_repository,
        "secret_values_exposed": False,
    }


def upload_encrypted_backup(path: Path) -> str:
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise BackupControlError("INVALID_BACKUP_FILE", "只能上传加密的 .enc 备份文件。")
    root = Path(getattr(settings, "BACKUP_DOWNLOAD_DIR", raw.parent)).expanduser().resolve()
    target = raw.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise BackupControlError("INVALID_BACKUP_FILE", "只能上传下载目录内的加密备份。") from exc
    if target.is_symlink() or not target.is_file() or not target.name.lower().endswith(".enc"):
        raise BackupControlError("INVALID_BACKUP_FILE", "只能上传加密的 .enc 备份文件。")
    return "skipped"


def _https_probe(
    *,
    host: str,
    path: str,
    method: str,
    headers: list[tuple[str, str]],
    body: bytes | None = None,
    port: int | None = None,
    host_header: str | None = None,
) -> int:
    connection = http.client.HTTPSConnection(
        host,
        port=port,
        timeout=15,
        context=ssl.create_default_context(),
    )
    try:
        connection.putrequest(method, path, skip_accept_encoding=True)
        connection.putheader("Host", host_header or host)
        for key, value in headers:
            connection.putheader(key, value)
        if body is None:
            connection.putheader("Content-Length", "0")
            connection.endheaders()
        else:
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders()
            connection.send(body)
        response = connection.getresponse()
        status = response.status
        response.read(4096)
        return status
    except (OSError, http.client.HTTPException) as exc:
        raise BackupControlError("DESTINATION_UNREACHABLE", "连不上这个去向。") from exc
    finally:
        connection.close()


def _probe_github(policy: BackupPolicy) -> dict[str, Any]:
    repo = policy.github_repository
    token = _decrypt_secret(policy.github_token_ciphertext)
    if not repo or not token:
        return {"target": "github", "ok": False, "message": "GitHub 仓库或令牌还没记下。"}
    try:
        status = _https_probe(
            host="api.github.com",
            path=f"/repos/{repo}",
            method="GET",
            headers=[
                ("Authorization", f"Bearer {token}"),
                ("User-Agent", "authorization-platform-backup-probe"),
                ("Accept", "application/vnd.github+json"),
            ],
        )
    except BackupControlError:
        return {"target": "github", "ok": False, "message": "GitHub 连不上。"}
    ok = status == 200
    return {
        "target": "github",
        "ok": ok,
        "message": "GitHub 连通正常。" if ok else "GitHub 仓库或令牌连不上。",
    }


def probe_backup_destinations() -> dict[str, Any]:
    policy = get_policy()
    if not policy.github_enabled:
        raise BackupControlError("DESTINATION_NOT_CONFIGURED", "还没有勾选 GitHub，保存后再试连。")
    results = [_probe_github(policy)]
    ok = all(item["ok"] for item in results)
    if ok:
        message = "连通正常。没有上传备份。"
    else:
        message = "；".join(item["message"] for item in results if not item["ok"]) or "试连失败。"
    return {"ok": ok, "results": results, "message": message, "uploaded": False}


def existing_operation(*, actor, action: str, key: str, request_hash: str) -> dict[str, Any] | None:
    existing = BackupControlOperation.objects.filter(actor=actor, action=action, idempotency_key=key).first()
    if existing is None:
        return None
    if existing.request_hash != request_hash:
        raise BackupControlError("IDEMPOTENCY_CONFLICT", "同一请求键不能用于不同的备份内容。", status=409)
    return existing.response


def store_operation(*, actor, action: str, key: str, request_hash: str, response: dict[str, Any]) -> None:
    try:
        with transaction.atomic():
            BackupControlOperation.objects.create(
                actor=actor,
                action=action,
                idempotency_key=key,
                request_hash=request_hash,
                response=response,
            )
    except IntegrityError as exc:
        replay = existing_operation(actor=actor, action=action, key=key, request_hash=request_hash)
        if replay is None:
            raise BackupControlError("IDEMPOTENCY_CONFLICT", "同一请求键不能用于不同的备份内容。", status=409) from exc


def _download_root() -> Path:
    return Path(getattr(settings, "BACKUP_DOWNLOAD_DIR", Path(settings.BASE_DIR) / "storage" / "backups")).resolve()


def list_downloads() -> list[dict[str, Any]]:
    from .download_deletion import recover_pending
    recover_pending()
    root = _download_root()
    try:
        if not root.exists() or root.is_symlink() or not root.is_dir():
            return []
        entries = list(root.iterdir())
    except OSError:
        return []
    items: list[dict[str, Any]] = []
    for path in entries:
        try:
            if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".enc":
                continue
            stat = path.stat()
        except OSError:
            continue
        items.append(
            {
                "name": path.name,
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=dt_timezone.utc).isoformat(),
                "sha256_suffix": _sha256_suffix(path),
            }
        )
    return sorted(items, key=lambda item: (item["modified_at"], item["name"]), reverse=True)


def _sha256_suffix(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()[-12:]


def download_path(name: str) -> Path:
    from .download_deletion import recover_pending
    recover_pending()
    if not name or len(name) > 180 or Path(name).name != name or Path(name).suffix.lower() != ".enc":
        raise ValueError("备份文件名无效。")
    root = _download_root()
    path = (root / name).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("备份文件路径无效。") from exc
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(name)
    return path


def download_retention_floor() -> int:
    return max(1, min(int(get_policy().github_retention_count or 1), 3650))


def delete_encrypted_download(*, name: str, confirmed: bool = False) -> dict[str, Any]:
    if not confirmed:
        raise BackupControlError("CONFIRMATION_REQUIRED", "删除加密备份必须确认。", status=400)
    root = _download_root()
    lock_path = root / ".download-delete.lock"
    try:
        root.mkdir(parents=True, exist_ok=True)
        lock_path.touch(exist_ok=True)
    except OSError as exc:
        raise BackupControlError("BACKUP_DELETE_FAILED", "下载目录无法写入，不能删除备份文件。", status=500) from exc
    from .download_deletion import file_lock, remove_or_stage
    with file_lock():
        try:
            path = download_path(name)
        except ValueError as exc:
            raise BackupControlError("INVALID_BACKUP_FILE", "备份文件名无效。", status=400) from exc
        except FileNotFoundError as exc:
            raise BackupControlError("BACKUP_FILE_NOT_FOUND", "备份文件不存在。", status=404) from exc
        items = list_downloads()
        if path.name not in {item["name"] for item in items}:
            raise BackupControlError("BACKUP_FILE_NOT_FOUND", "备份文件不存在。", status=404)
        floor = download_retention_floor()
        remaining_if_deleted = len(items) - 1
        if remaining_if_deleted < floor:
            raise BackupControlError(
                "BACKUP_RETENTION_FLOOR",
                f"下载目录至少留 {floor} 份加密备份，现在不能再删。",
                status=409,
            )
        suffix = _sha256_suffix(path)
        size = path.stat().st_size
        remaining = remaining_if_deleted
        result = {
            "deleted": path.name,
            "remaining_count": remaining,
            "retention_count": floor,
            "size": size,
            "sha256_suffix": suffix,
            "message": f"已删除 {path.name}。下载目录还剩 {remaining} 份，至少留 {floor} 份。",
        }
        try:
            remove_or_stage(path, result)
        except OSError as exc:
            raise BackupControlError("BACKUP_DELETE_FAILED", "删除备份文件失败。", status=500) from exc
        return result


def _format_beijing(moment: datetime) -> str:
    if timezone.is_naive(moment):
        moment = moment.replace(tzinfo=dt_timezone.utc)
    return moment.astimezone(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def parse_backup_filename_time(name: str) -> datetime:
    filename = Path(name or "").name
    match = BACKUP_FILENAME_RE.fullmatch(filename)
    if not match:
        raise BackupControlError(
            "BACKUP_TIME_UNKNOWN",
            "文件名里没有备份时间。请使用平台下载的加密备份，例如 authorization-platform-enc-20260904-090000.dump.enc。",
        )
    naive = datetime.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M%S")
    return naive.replace(tzinfo=dt_timezone.utc)


def _openssl_key_iv(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=salt,
        iterations=OPENSSL_PBKDF2_ITERATIONS,
    )
    material = kdf.derive(passphrase.encode("utf-8"))
    return material[:32], material[32:48]


def _openssl_passphrase_candidates(passphrase: str) -> list[str]:
    """Match both UI paste (strip) and OpenSSL -pass file: on Windows CRLF files.

    OpenSSL reads the first line and drops the LF, but keeps a trailing CR.
    """
    raw = passphrase or ""
    stripped = raw.strip()
    first_line = raw.splitlines()[0] if raw else ""
    openssl_file = first_line.rstrip("\n")
    ordered: list[str] = []
    for candidate in (stripped, openssl_file, f"{stripped}\r" if stripped else ""):
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered


def openssl_encrypt_aes256_cbc(plaintext: bytes, passphrase: str) -> bytes:
    secret = (passphrase or "").strip()
    if not secret:
        raise BackupControlError("INVALID_BACKUP_PASSPHRASE", "请填写备份口令。")
    salt = os.urandom(8)
    key, iv = _openssl_key_iv(secret, salt)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return OPENSSL_MAGIC + salt + encryptor.update(padded) + encryptor.finalize()


def _decrypt_openssl_blob(blob: bytes, secret: str) -> bytes:
    key, iv = _openssl_key_iv(secret, blob[8:16])
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(blob[16:]) + decryptor.finalize()
    if not padded:
        raise ValueError("empty plaintext")
    pad = padded[-1]
    if pad < 1 or pad > 16 or len(padded) < pad or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return padded[:-pad]


def openssl_decrypt_aes256_cbc(blob: bytes, passphrase: str) -> bytes:
    if not _openssl_passphrase_candidates(passphrase):
        raise BackupControlError("INVALID_BACKUP_PASSPHRASE", "请填写备份口令。")
    if len(blob) < 32 or not blob.startswith(OPENSSL_MAGIC) or (len(blob) - 16) % 16:
        raise BackupControlError("INVALID_BACKUP_FILE", "这不是本平台的加密备份文件。")
    last_error: Exception | None = None
    for secret in _openssl_passphrase_candidates(passphrase):
        try:
            return _decrypt_openssl_blob(blob, secret)
        except ValueError as exc:
            last_error = exc
    raise BackupControlError("INVALID_BACKUP_PASSPHRASE", PASSPHRASE_ERROR) from last_error


# Models that legitimately hold rows on a brand-new site: the installer creates
# an administrator, the platform writes audit rows for its own bookkeeping, and
# the backup screens keep queue/policy/staging state.  F-023 documents these as
# not counting as business data, so they stay excluded here.
#
# Everything else is guarded.  A previous version of this check only looked at
# ten tables, so a site holding devices, releases, batches, lifecycle
# operations or cleanup state was reported as "empty" and then had those rows
# silently dropped by `pg_restore --clean`.
RESTORE_IGNORED_MODELS = frozenset(
    {
        "admin.LogEntry",
        "auth.Group",
        "auth.Permission",
        "auth.User",
        "audit.AuditEvent",
        "backup_control.BackupControlOperation",
        "backup_control.BackupPolicy",
        "backup_control.BackupRestoreStaging",
        "backup_control.BackupRunRequest",
        "contenttypes.ContentType",
        "sessions.Session",
    }
)

RESTORE_IGNORED_APP_LABELS = frozenset({"admin", "auth", "contenttypes", "sessions"})

# Positive sentinel used when a model's row count raises. It must be non-zero so
# the emptiness gate blocks, and it is translated to a reason code before the
# value reaches the API.
RESTORE_UNCOUNTABLE_SENTINEL = -1
RESTORE_UNCOUNTABLE_LABEL = "uncountable"


def _restore_counts() -> dict[str, int]:
    """Count business rows across every application model.

    Only the explicitly ignored models above are skipped, so a model added
    later is automatically covered instead of silently escaping the gate.

    A model whose count raises is reported as ``uncountable`` (never as 0):
    the emptiness gate must fail closed, and the operator must see a stable
    reason code rather than a negative row count.
    """

    from django.apps import apps

    counts: dict[str, int] = {}
    for model in apps.get_models():
        if model._meta.app_label in RESTORE_IGNORED_APP_LABELS:
            continue
        label = f"{model._meta.app_label}.{model.__name__}"
        if label in RESTORE_IGNORED_MODELS:
            continue
        try:
            total = model.objects.count()
        except Exception:
            # Unknown models must never be treated as empty. Use a positive
            # sentinel so the gate blocks, but surface it as a reason code in
            # the API instead of a nonsensical row count.
            total = RESTORE_UNCOUNTABLE_SENTINEL
        if total:
            counts[label] = total
    return counts


def _ignored_restore_counts() -> dict[str, int]:
    """Rows that the import would overwrite but that F-023 calls non-blocking.

    Reported so the operator can see exactly what history the restore discards
    instead of having to guess.
    """

    from django.apps import apps

    counts: dict[str, int] = {}
    for model in apps.get_models():
        label = f"{model._meta.app_label}.{model.__name__}"
        if label not in RESTORE_IGNORED_MODELS:
            continue
        try:
            total = model.objects.count()
        except Exception:
            continue
        if total:
            counts[label] = total
    return counts


def _restore_uses_postgresql() -> bool:
    engine = str(settings.DATABASES.get("default", {}).get("ENGINE", "")).lower()
    return "postgresql" in engine


def site_restore_status() -> dict[str, Any]:
    counts = _restore_counts()
    empty = all(value == 0 for value in counts.values())
    postgresql = _restore_uses_postgresql()
    can_restore = empty and postgresql
    if not empty:
        message = SITE_NONEMPTY_MESSAGE
    elif not postgresql:
        message = "当前开发库不是 PostgreSQL，核对后不能导入。"
    else:
        message = SITE_EMPTY_READY_MESSAGE
    return {
        "site_empty": empty,
        "can_restore": can_restore,
        "blocking_counts": {} if empty else counts,
        "overwritten_counts": _ignored_restore_counts(),
        "max_upload_bytes": int(getattr(settings, "BACKUP_RESTORE_MAX_BYTES", 100 * 1024 * 1024)),
        "message": message,
    }


def _staging_root() -> Path:
    return Path(getattr(settings, "BACKUP_RESTORE_STAGING_DIR", Path(settings.BASE_DIR) / "storage" / "backup-restore-staging")).resolve()


def _staging_path(staging_id) -> Path:
    root = _staging_root()
    path = (root / f"{staging_id}.enc").resolve()
    path.relative_to(root)
    return path


def _delete_staging(row: BackupRestoreStaging | None) -> None:
    if row is None:
        return
    path = _staging_path(row.public_id)
    try:
        if path.is_file() and not path.is_symlink():
            path.unlink()
    except OSError:
        pass
    row.delete()


def _cleanup_expired_stagings() -> None:
    now = timezone.now()
    for row in BackupRestoreStaging.objects.filter(expires_at__lte=now):
        _delete_staging(row)


def _write_upload(upload, destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    max_bytes = int(getattr(settings, "BACKUP_RESTORE_MAX_BYTES", 100 * 1024 * 1024))
    with destination.open("wb") as handle:
        for chunk in upload.chunks():
            written += len(chunk)
            if written > max_bytes:
                handle.close()
                destination.unlink(missing_ok=True)
                raise BackupControlError("BACKUP_FILE_TOO_LARGE", "备份文件过大。")
            handle.write(chunk)
    if written <= 0:
        destination.unlink(missing_ok=True)
        raise BackupControlError("INVALID_BACKUP_FILE", "请选择加密备份文件。")
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
    return written


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decrypt_dump_file(path: Path, passphrase: str) -> bytes:
    blob = path.read_bytes()
    plaintext = openssl_decrypt_aes256_cbc(blob, passphrase)
    if not plaintext.startswith(PGDMP_MAGIC):
        raise BackupControlError("INVALID_BACKUP_FILE", "解密后不是本平台的数据库备份。")
    return plaintext


def inspect_restore_upload(*, actor, upload, passphrase: str) -> dict[str, Any]:
    _cleanup_expired_stagings()
    name = Path(getattr(upload, "name", "") or "").name
    if not name or Path(name).suffix.lower() != ".enc":
        raise BackupControlError("INVALID_BACKUP_FILE", "请上传加密的 .enc 备份文件。")
    backup_time = parse_backup_filename_time(name)
    size = int(getattr(upload, "size", 0) or 0)
    max_bytes = int(getattr(settings, "BACKUP_RESTORE_MAX_BYTES", 100 * 1024 * 1024))
    if size > max_bytes:
        raise BackupControlError("BACKUP_FILE_TOO_LARGE", "备份文件过大。")
    root = _staging_root()
    root.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="restore-", suffix=".enc", dir=root)
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        _write_upload(upload, tmp_path)
        _decrypt_dump_file(tmp_path, passphrase)
        sha256 = _file_sha256(tmp_path)
        status = site_restore_status()
        payload = {
            "original_name": name,
            "backup_time_utc": backup_time.isoformat().replace("+00:00", "Z"),
            "backup_time_beijing": _format_beijing(backup_time),
            "sha256_suffix": sha256[-12:],
            "site_empty": status["site_empty"],
            "can_restore": status["can_restore"],
            "blocking_counts": status["blocking_counts"],
            "message": (
                f"请核对该备份时间：{_format_beijing(backup_time)}（北京时间）。确认无误后再导入。"
                if status["can_restore"]
                else (
                    INSPECT_PASSPHRASE_OK_NONEMPTY
                    if not status["site_empty"]
                    else status["message"]
                )
            ),
        }
        if not status["site_empty"]:
            tmp_path.unlink(missing_ok=True)
            payload["staging_id"] = ""
            return payload
        row = BackupRestoreStaging.objects.create(
            actor=actor,
            original_name=name,
            sha256=sha256,
            backup_time_utc=backup_time,
            expires_at=timezone.now() + RESTORE_STAGING_TTL,
        )
        final_path = _staging_path(row.public_id)
        tmp_path.replace(final_path)
        payload["staging_id"] = str(row.public_id)
        return payload
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def confirm_restore(*, actor, staging_id: str, passphrase: str, confirmed_backup_time: str) -> dict[str, Any]:
    _cleanup_expired_stagings()
    try:
        uid = UUID(str(staging_id or "").strip())
    except (TypeError, ValueError) as exc:
        raise BackupControlError("RESTORE_STAGING_NOT_FOUND", "请先核对备份，再确认导入。") from exc

    root = _staging_root()
    lock_path = root / ".restore.lock"
    try:
        root.mkdir(parents=True, exist_ok=True)
        lock_path.touch(exist_ok=True)
    except OSError as exc:
        raise BackupControlError("RESTORE_FAILED", "恢复暂存目录无法写入，不能开始导入。", status=500) from exc

    from django.core.files.locks import LOCK_EX, LOCK_NB, lock, unlock

    with lock_path.open("a+b") as lock_handle:
        if not lock(lock_handle, LOCK_EX | LOCK_NB):
            raise BackupControlError("RESTORE_IN_PROGRESS", "另一个恢复正在进行中，不能重复执行。", status=409)
        try:
            with transaction.atomic():
                row = BackupRestoreStaging.objects.select_for_update().filter(public_id=uid).first()
                if row is None or row.expires_at <= timezone.now():
                    if row is not None:
                        _delete_staging(row)
                    raise BackupControlError("RESTORE_STAGING_NOT_FOUND", "核对已过期，请重新上传备份。", status=404)
                expected = _format_beijing(row.backup_time_utc)
                if (confirmed_backup_time or "").strip() != expected:
                    raise BackupControlError("BACKUP_TIME_MISMATCH", f"请填写刚才显示的备份时间：{expected}。")
                BackupPolicy.objects.select_for_update().get_or_create(key="default")
                status = site_restore_status()
                if not status["site_empty"]:
                    raise BackupControlError("SITE_NOT_EMPTY", status["message"], status=409)

            path = _staging_path(row.public_id)
            if path.is_symlink() or not path.is_file():
                _delete_staging(row)
                raise BackupControlError("RESTORE_STAGING_NOT_FOUND", "核对文件已丢失，请重新上传备份。", status=404)
            plaintext = _decrypt_dump_file(path, passphrase)
            engine = str(settings.DATABASES.get("default", {}).get("ENGINE", ""))
            if engine != "django.db.backends.postgresql":
                raise BackupControlError(
                    "RESTORE_REQUIRES_POSTGRESQL",
                    "当前是空站点，备份时间和口令都已核对。导入只能在 PostgreSQL 上执行，本地测试库不会覆盖数据。",
                )
            # The emptiness check and pg_restore --clean cannot share a row lock:
            # the check must commit before the restore runs, so other workers
            # could write business rows in between and have them silently
            # dropped.  Hold a dedicated advisory lock across the restore and
            # re-check emptiness while holding it.
            with _restore_exclusion_lock():
                if not site_restore_status()["site_empty"]:
                    raise BackupControlError("SITE_NOT_EMPTY", SITE_NONEMPTY_MESSAGE, status=409)
                _apply_postgres_restore(plaintext)
            _delete_staging(row)
            return {
                "restore_command_finished": True,
                "inventory_compared": False,
                "backup_time_beijing": expected,
                "message": "导入命令已结束，尚未做隔离恢复核对。请用备份里的管理员账号重新登录，并按部署与恢复手册核对。",
            }
        finally:
            unlock(lock_handle)


# Arbitrary but stable key for the restore exclusion lock.  Every writer that
# must not race a restore should take the same advisory lock before committing.
RESTORE_EXCLUSION_LOCK_KEY = 4_171_949_001


def _live_database_vendor() -> str:
    """Vendor of the connection Django would actually use.

    Read through a helper so tests can exercise the PostgreSQL branch without a
    real PostgreSQL server, and so the decision never depends on the configured
    engine string (a settings override must not make this open a real
    PostgreSQL connection against a SQLite test database).
    """

    from django.db import connection as django_connection

    return django_connection.vendor


@contextmanager
def _restore_exclusion_lock():
    """Serialize restores and re-check emptiness immediately before pg_restore.

    The lock is taken on its OWN raw connection, not on the Django default
    connection: `_apply_postgres_restore` calls `connections.close_all()`, which
    would drop a lock held by a managed connection.  Session-level advisory
    locks die with their session, so a dedicated connection keeps the lock for
    exactly the restore window and releases it when that connection closes.

    Honest scope: this closes the "two restores at once" hole and narrows the
    window in which another worker could write business rows after the final
    emptiness check.  It does not put the application into maintenance mode, so
    a writer that commits in the remaining sub-second window can still have its
    rows dropped by `pg_restore --clean`.  Full protection requires taking the
    site offline for the import, which the operator does manually per
    `部署与恢复/03-新VPS怎么装怎么导备份.md`.
    """

    if _live_database_vendor() != "postgresql":
        yield
        return

    database = settings.DATABASES.get("default", {})
    if psycopg is None:
        raise BackupControlError(
            "RESTORE_TOOL_MISSING",
            "服务器没有安装 PostgreSQL 驱动，不能安全开始导入。",
            status=500,
        )

    kwargs: dict[str, Any] = {
        "dbname": str(database.get("NAME") or ""),
        "user": str(database.get("USER") or ""),
        "password": str(database.get("PASSWORD") or ""),
        "host": str(database.get("HOST") or ""),
        "port": str(database.get("PORT") or ""),
        "connect_timeout": 10,
    }
    try:
        lock_connection = psycopg.connect(**kwargs, autocommit=True)
    except Exception as exc:  # noqa: BLE001
        raise BackupControlError(
            "RESTORE_FAILED",
            "无法建立恢复专用连接，不能安全开始导入。",
            status=500,
        ) from exc

    try:
        with lock_connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s)", [RESTORE_EXCLUSION_LOCK_KEY])
            acquired = cursor.fetchone()[0]
        if not acquired:
            raise BackupControlError(
                "RESTORE_IN_PROGRESS",
                "另一个恢复正在进行中，不能重复执行。",
                status=409,
            )
        try:
            yield
        finally:
            try:
                with lock_connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_unlock(%s)", [RESTORE_EXCLUSION_LOCK_KEY])
            except Exception:
                # The lock dies with the connection; a failed unlock must not
                # mask the restore outcome.
                pass
    finally:
        lock_connection.close()


def _apply_postgres_restore(plaintext: bytes) -> None:
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        raise BackupControlError("RESTORE_TOOL_MISSING", "服务器还没有安装恢复工具，不能把备份写进数据库。")
    database = settings.DATABASES["default"]
    env = os.environ.copy()
    password = str(database.get("PASSWORD") or "")
    if password:
        env["PGPASSWORD"] = password
    with tempfile.NamedTemporaryFile(prefix="restore-dump-", suffix=".dump", delete=False) as handle:
        handle.write(plaintext)
        dump_path = Path(handle.name)
    try:
        connections.close_all()
        command = [
            pg_restore,
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-acl",
            "--exit-on-error",
            "--single-transaction",
            "--dbname",
            str(database.get("NAME") or ""),
        ]
        host = str(database.get("HOST") or "")
        port = str(database.get("PORT") or "")
        user = str(database.get("USER") or "")
        if host:
            command.extend(["--host", host])
        if port:
            command.extend(["--port", port])
        if user:
            command.extend(["--username", user])
        command.append(str(dump_path))
        completed = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
        if completed.returncode != 0:
            raise BackupControlError("RESTORE_FAILED", "导入没有完成，数据库可能已被部分改写，不要当成成功。")
    finally:
        dump_path.unlink(missing_ok=True)
        env.pop("PGPASSWORD", None)
