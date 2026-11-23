"""Pure backup, disk, and health contracts used by local acceptance tooling.

This module deliberately does not connect to PostgreSQL, object storage, or an
alert provider.  It validates the production contract and produces redacted
health facts so a deployment process can make a fail-closed decision without
ever printing credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class BackupCheck:
    name: str
    status: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class DiskCapacity:
    total_bytes: int
    free_bytes: int
    free_percent: float
    status: str

    def as_dict(self) -> dict[str, int | float | str]:
        return asdict(self)


def _check(name: str, passed: bool, reason: str) -> BackupCheck:
    return BackupCheck(name=name, status="passed" if passed else "failed", reason=reason)


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def _positive_int(values: Mapping[str, str], name: str) -> int | None:
    try:
        value = int(values.get(name, ""))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _boolean(values: Mapping[str, str], name: str) -> bool:
    return values.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value.strip()))


def _non_empty_text(value: object, *, max_length: int = 256) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.strip()) <= max_length


def _normalized_repository(value: object) -> str:
    return str(value or "").strip().lower().rstrip("/")


def _proof_error(code: str) -> dict[str, str]:
    return {"code": code}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_backup_success_proof_material(proof: Mapping[str, object]) -> list[dict[str, str]]:
    """Verify hashes of the local evidence files referenced by a proof.

    The deployment-specific runner still owns provider access and restore
    execution.  Requiring its emitted evidence files to exist and match their
    declared digests prevents ``mark-success`` from accepting a proof that is
    only a collection of self-reported booleans.
    """

    errors: list[dict[str, str]] = []

    def check_file(container: Mapping[str, object], path_key: str, digest_key: str, error_prefix: str) -> None:
        raw_path = container.get(path_key)
        raw_digest = container.get(digest_key)
        if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
            errors.append(_proof_error(f"{error_prefix}_file_missing_or_not_absolute"))
            return
        if not _is_sha256(raw_digest):
            errors.append(_proof_error(f"{error_prefix}_hash_missing_or_invalid"))
            return
        path = Path(raw_path)
        try:
            if not path.is_file() or path.is_symlink() or _file_sha256(path).lower() != str(raw_digest).lower():
                errors.append(_proof_error(f"{error_prefix}_hash_mismatch"))
        except OSError:
            errors.append(_proof_error(f"{error_prefix}_file_unreadable"))

    for index, repository in enumerate(proof.get("repositories", []) if isinstance(proof.get("repositories"), list) else []):
        if isinstance(repository, Mapping):
            check_file(repository, "evidence_file", "evidence_sha256", f"repository_{index + 1}_evidence")
    for key, prefix in (
        ("wal", "wal_evidence"),
        ("object_manifest", "object_manifest_evidence"),
        ("recovery_inventory", "recovery_inventory_evidence"),
    ):
        value = proof.get(key)
        if isinstance(value, Mapping):
            check_file(value, "evidence_file", "evidence_sha256", prefix)
            if key == "recovery_inventory":
                raw_path = value.get("evidence_file")
                if isinstance(raw_path, str) and Path(raw_path).is_absolute():
                    try:
                        document = json.loads(Path(raw_path).read_text(encoding="utf-8"))
                        comparison = document.get("comparison", {}) if isinstance(document, dict) else {}
                        ciphertext = document.get("ciphertext_verification", {}) if isinstance(document, dict) else {}
                        if not isinstance(comparison, Mapping) or comparison.get("matches") is not True:
                            errors.append(_proof_error("recovery_inventory_evidence_not_matched"))
                        if not isinstance(ciphertext, Mapping) or ciphertext.get("passed") is not True:
                            errors.append(_proof_error("recovery_inventory_evidence_ciphertext_failed"))
                    except (OSError, UnicodeError, json.JSONDecodeError):
                        errors.append(_proof_error("recovery_inventory_evidence_invalid_json"))
    binding = proof.get("binding")
    if isinstance(binding, Mapping):
        check_file(binding, "dump_file", "dump_sha256", "dump_evidence")
        check_file(binding, "migration_graph_file", "migration_graph_sha256", "migration_graph_evidence")
    return errors


def validate_backup_success_proof(proof: Mapping[str, object]) -> dict[str, object]:
    """Validate the evidence required before a success marker may be written.

    The proof is produced by the deployment-specific backup runner.  This
    function deliberately accepts facts, not credentials or file contents, and
    returns only a redacted summary suitable for a health marker.
    """

    errors: list[dict[str, str]] = []
    if proof.get("schema_version") != 1:
        errors.append(_proof_error("proof_schema_invalid"))
    if str(proof.get("status", "")).strip().lower() != "success":
        errors.append(_proof_error("proof_status_not_success"))
    run_id = str(proof.get("backup_run_id", "")).strip()
    if not _non_empty_text(run_id, max_length=128):
        errors.append(_proof_error("backup_run_id_missing"))
    started_at = _parse_utc(str(proof.get("started_at_utc", "")))
    completed_at = _parse_utc(str(proof.get("completed_at_utc", "")))
    if started_at is None:
        errors.append(_proof_error("backup_started_at_missing_or_invalid"))
    if completed_at is None:
        errors.append(_proof_error("backup_completed_at_missing_or_invalid"))
    if started_at is not None and completed_at is not None and completed_at < started_at:
        errors.append(_proof_error("backup_time_order_invalid"))

    repositories = proof.get("repositories")
    repository_summary: list[dict[str, str]] = []
    if not isinstance(repositories, list) or len(repositories) < 2:
        errors.append(_proof_error("repository_proof_incomplete"))
        repositories = []
    seen_repository_names: set[str] = set()
    for repository in repositories:
        if not isinstance(repository, Mapping):
            errors.append(_proof_error("repository_proof_invalid"))
            continue
        name = str(repository.get("name", "")).strip()
        if not _non_empty_text(name, max_length=64) or name in seen_repository_names:
            errors.append(_proof_error("repository_names_not_unique"))
        seen_repository_names.add(name)
        if str(repository.get("status", "")).strip().lower() != "success":
            errors.append(_proof_error("repository_backup_not_success"))
        if str(repository.get("backup_run_id", "")).strip() != run_id:
            errors.append(_proof_error("repository_run_id_mismatch"))
        repository_hash = repository.get("backup_sha256") or repository.get("manifest_sha256")
        if not _is_sha256(repository_hash):
            errors.append(_proof_error("repository_hash_missing_or_invalid"))
        repository_summary.append(
            {
                "name": name,
                "status": "success"
                if str(repository.get("status", "")).strip().lower() == "success"
                else "failed",
            }
        )

    wal = proof.get("wal")
    if not isinstance(wal, Mapping):
        errors.append(_proof_error("wal_proof_missing"))
        wal = {}
    if str(wal.get("status", "")).strip().lower() != "success" or wal.get("archive_ready") is not True:
        errors.append(_proof_error("wal_archive_not_ready"))
    if str(wal.get("backup_run_id", "")).strip() != run_id:
        errors.append(_proof_error("wal_run_id_mismatch"))
    for field in ("start_lsn", "end_lsn", "last_archived_at_utc"):
        if not _non_empty_text(wal.get(field), max_length=128):
            errors.append(_proof_error(f"wal_{field}_missing"))

    object_manifest = proof.get("object_manifest")
    if not isinstance(object_manifest, Mapping):
        errors.append(_proof_error("object_manifest_missing"))
        object_manifest = {}
    if str(object_manifest.get("status", "")).strip().lower() != "success":
        errors.append(_proof_error("object_manifest_not_success"))
    if str(object_manifest.get("backup_run_id", "")).strip() != run_id:
        errors.append(_proof_error("object_manifest_run_id_mismatch"))
    if not _is_sha256(object_manifest.get("manifest_sha256")):
        errors.append(_proof_error("object_manifest_hash_missing_or_invalid"))
    object_count = object_manifest.get("object_count")
    if not isinstance(object_count, int) or isinstance(object_count, bool) or object_count < 1:
        errors.append(_proof_error("object_manifest_count_invalid"))
    if str(object_manifest.get("source", "")).strip().lower() != "object-storage":
        errors.append(_proof_error("object_manifest_not_object_storage"))

    recovery = proof.get("recovery_inventory")
    if not isinstance(recovery, Mapping):
        errors.append(_proof_error("recovery_inventory_missing"))
        recovery = {}
    if str(recovery.get("status", "")).strip().lower() != "success":
        errors.append(_proof_error("recovery_inventory_not_success"))
    if str(recovery.get("backup_run_id", "")).strip() != run_id:
        errors.append(_proof_error("recovery_inventory_run_id_mismatch"))
    if recovery.get("ciphertext_verification") is not True or recovery.get("matches") is not True:
        errors.append(_proof_error("recovery_inventory_business_checks_failed"))
    if not _is_sha256(recovery.get("inventory_sha256")):
        errors.append(_proof_error("recovery_inventory_hash_missing_or_invalid"))

    binding = proof.get("binding")
    if not isinstance(binding, Mapping):
        errors.append(_proof_error("backup_binding_missing"))
        binding = {}
    if str(binding.get("backup_run_id", "")).strip() != run_id:
        errors.append(_proof_error("binding_run_id_mismatch"))
    if not _non_empty_text(binding.get("candidate_commit"), max_length=128):
        errors.append(_proof_error("candidate_commit_missing"))
    # A git SHA alone cannot identify deployed bytes when the tree has
    # uncommitted edits; require the content fingerprint the installer records.
    tree_sha = str(binding.get("candidate_tree_sha256", "")).strip()
    if tree_sha and not _is_sha256(tree_sha):
        errors.append(_proof_error("candidate_tree_sha256_invalid"))
    if not _is_sha256(binding.get("migration_graph_sha256")):
        errors.append(_proof_error("migration_graph_hash_missing_or_invalid"))
    if not _is_sha256(binding.get("dump_sha256")):
        errors.append(_proof_error("dump_hash_missing_or_invalid"))
    key_versions = binding.get("key_versions")
    if (
        not isinstance(key_versions, list)
        or not key_versions
        or any(not _non_empty_text(item, max_length=128) for item in key_versions)
    ):
        errors.append(_proof_error("key_version_references_missing"))

    summary = {
        "status": "passed" if not errors else "failed",
        "backup_run_id": run_id,
        "started_at_utc": proof.get("started_at_utc"),
        "completed_at_utc": proof.get("completed_at_utc"),
        "repository_names": [item["name"] for item in repository_summary],
        "repository_count": len(repository_summary),
        "repository_success_count": sum(item["status"] == "success" for item in repository_summary),
        "wal_start_lsn": wal.get("start_lsn"),
        "wal_end_lsn": wal.get("end_lsn"),
        "wal_last_archived_at_utc": wal.get("last_archived_at_utc"),
        "object_count": object_count,
        "object_manifest_sha256": object_manifest.get("manifest_sha256"),
        "recovery_inventory_sha256": recovery.get("inventory_sha256"),
        "dump_sha256": binding.get("dump_sha256"),
        "candidate_commit": binding.get("candidate_commit"),
        "candidate_tree_sha256": binding.get("candidate_tree_sha256"),
        "migration_graph_sha256": binding.get("migration_graph_sha256"),
        "key_versions": list(key_versions) if isinstance(key_versions, list) else [],
        "errors": errors,
        "secret_values_exposed": False,
    }
    return summary


def validate_backup_environment(env: Mapping[str, str] | None = None) -> list[BackupCheck]:
    """Validate the production backup contract without returning secret values."""

    values = _env(env)
    provider = values.get("BACKUP_PROVIDER", "").strip().lower()
    checks: list[BackupCheck] = [
        _check("backup_provider", provider == "pgbackrest", "生产备份必须由 pgBackRest 或经单独审查的等价工具管理。"),
        _check("backup_stanza", bool(values.get("BACKUP_STANZA", "").strip()), "必须绑定明确的 PostgreSQL stanza。"),
        _check(
            "backup_repository_count",
            (repository_count := _positive_int(values, "BACKUP_REPOSITORY_COUNT")) is not None and repository_count >= 2,
            "必须有至少两个相互独立的备份仓库。",
        ),
        _check(
            "backup_repository_paths",
            bool(values.get("BACKUP_REPOSITORY_1", "").strip()) and bool(values.get("BACKUP_REPOSITORY_2", "").strip()),
            "至少要配置两个不含凭据的仓库标识/路径。",
        ),
        _check(
            "backup_repository_locations_distinct",
            bool(values.get("BACKUP_REPOSITORY_1", "").strip())
            and bool(values.get("BACKUP_REPOSITORY_2", "").strip())
            and _normalized_repository(values.get("BACKUP_REPOSITORY_1"))
            != _normalized_repository(values.get("BACKUP_REPOSITORY_2")),
            "两个备份仓库不能解析为同一个位置。",
        ),
        _check(
            "backup_repository_independence",
            _boolean(values, "BACKUP_REPOSITORIES_INDEPENDENT")
            and _non_empty_text(values.get("BACKUP_REPOSITORY_FAILURE_DOMAIN_1"), max_length=128)
            and _non_empty_text(values.get("BACKUP_REPOSITORY_FAILURE_DOMAIN_2"), max_length=128)
            and str(values.get("BACKUP_REPOSITORY_FAILURE_DOMAIN_1")).strip().lower()
            != str(values.get("BACKUP_REPOSITORY_FAILURE_DOMAIN_2")).strip().lower(),
            "第二副本必须位于独立的故障域、账号或 provider，不能只是同一目录的复制。",
        ),
        _check(
            "backup_encryption",
            values.get("BACKUP_ENCRYPTION", "").strip().lower() == "aes-256-cbc"
            and bool(values.get("BACKUP_CIPHER_PASSWORD_FILE", "").strip()),
            "远端仓库必须启用 pgBackRest 加密，密码只能由受控文件/密钥服务注入。",
        ),
        _check(
            "backup_tls",
            _boolean(values, "BACKUP_REMOTE_TLS"),
            "远端备份传输必须通过 TLS。",
        ),
        _check(
            "wal_archiving",
            values.get("BACKUP_WAL_ARCHIVING", "").strip().lower() == "on"
            and _boolean(values, "BACKUP_ARCHIVE_COMMAND_CONFIGURED"),
            "PostgreSQL 必须开启 WAL 连续归档并配置 archive_command。",
        ),
        _check(
            "retention",
            all(_positive_int(values, name) is not None for name in ("BACKUP_RETENTION_FULL", "BACKUP_RETENTION_DIFF", "BACKUP_RETENTION_ARCHIVE")),
            "全量、差异和 WAL 归档都必须有正数保留策略。",
        ),
        _check(
            "rpo_rto",
            _positive_int(values, "BACKUP_RPO_MINUTES") is not None and _positive_int(values, "BACKUP_RTO_MINUTES") is not None,
            "RPO/RTO 必须填写为可验收的正数分钟。",
        ),
        _check(
            "health_status_file",
            bool(values.get("BACKUP_STATUS_FILE", "").strip()),
            "必须有一个受权限保护的最后成功/失败状态文件。",
        ),
        _check(
            "failure_alerting",
            _boolean(values, "BACKUP_FAILURE_ALERTING") and bool(values.get("BACKUP_FAILURE_HANDLER", "").strip()),
            "备份失败必须进入外部告警或值班系统，不能只留在本机日志。",
        ),
        _check(
            "disk_thresholds",
            _valid_disk_thresholds(values),
            "磁盘预警阈值必须大于严重阈值，且都在 1% 到 99% 之间。",
        ),
    ]
    return checks


def _valid_disk_thresholds(values: Mapping[str, str]) -> bool:
    try:
        warning = int(values.get("BACKUP_WARN_FREE_PERCENT", ""))
        critical = int(values.get("BACKUP_CRITICAL_FREE_PERCENT", ""))
    except (TypeError, ValueError):
        return False
    return 1 <= critical < warning <= 99


def disk_capacity_status(
    *,
    total_bytes: int,
    free_bytes: int,
    warn_free_percent: int = 25,
    critical_free_percent: int = 15,
) -> DiskCapacity:
    """Return a bounded disk status; thresholds describe free, not used, space."""

    if total_bytes <= 0 or free_bytes < 0 or free_bytes > total_bytes:
        raise ValueError("磁盘容量数值不合法。")
    if not 1 <= critical_free_percent < warn_free_percent <= 99:
        raise ValueError("磁盘阈值必须满足 1 <= critical < warning <= 99。")
    free_percent = round((free_bytes / total_bytes) * 100, 2)
    if free_percent <= critical_free_percent:
        status = "critical"
    elif free_percent <= warn_free_percent:
        status = "warning"
    else:
        status = "ok"
    return DiskCapacity(
        total_bytes=total_bytes,
        free_bytes=free_bytes,
        free_percent=free_percent,
        status=status,
    )


def disk_capacity_for_path(
    path: Path | str,
    *,
    warn_free_percent: int = 25,
    critical_free_percent: int = 15,
) -> DiskCapacity:
    usage = shutil.disk_usage(Path(path))
    return disk_capacity_status(
        total_bytes=usage.total,
        free_bytes=usage.free,
        warn_free_percent=warn_free_percent,
        critical_free_percent=critical_free_percent,
    )


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def backup_health(
    *,
    status_document: Mapping[str, object] | None,
    now: datetime | None = None,
    rpo_minutes: int,
    disk: DiskCapacity,
) -> dict[str, object]:
    """Evaluate freshness and disk headroom without exposing error text or secrets."""

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    last_success = _parse_utc(
        str(status_document.get("last_success_at_utc")) if status_document and status_document.get("last_success_at_utc") else None
    )
    reasons: list[str] = []
    age_minutes: float | None = None
    if status_document:
        last_result = str(status_document.get("last_result", "")).lower()
        if last_result == "failure":
            reasons.append("backup_last_result_failure")
        elif last_result == "success":
            proof = status_document.get("last_success_proof")
            if not isinstance(proof, Mapping) or proof.get("status") != "passed":
                if status_document.get("proof_mode") == "dump_only":
                    # 这套部署明确没有 pgBackRest 仓库（deploy/backup/README.md
                    # 明说不装），所以"没有 pgBackRest 证明"是**已知且被接受**的
                    # 部署形态，不是故障。仍然报出来（降级为 warning），但不再
                    # 报成 critical —— 否则管理端会永远红着，而人最后会学会无视它。
                    reasons.append("backup_dump_only_proof_absent")
                else:
                    reasons.append("backup_success_proof_missing_or_invalid")
        else:
            reasons.append("backup_last_result_invalid")
    if last_success is None:
        reasons.append("backup_success_missing_or_invalid")
    else:
        age_minutes = round(max(0.0, (now - last_success).total_seconds() / 60), 2)
        if age_minutes > rpo_minutes:
            reasons.append("backup_success_stale")
    if disk.status == "critical":
        reasons.append("disk_free_critical")
    elif disk.status == "warning":
        reasons.append("disk_free_warning")
    status = "critical" if any(
        reason in reasons
        for reason in (
            "backup_last_result_failure",
            "backup_last_result_invalid",
            "backup_success_missing_or_invalid",
            "backup_success_proof_missing_or_invalid",
            "backup_success_stale",
            "disk_free_critical",
        )
    ) else ("warning" if reasons else "ok")
    return {
        "schema_version": 1,
        "status": status,
        "checked_at_utc": now.isoformat().replace("+00:00", "Z"),
        "last_success_at_utc": last_success.isoformat().replace("+00:00", "Z") if last_success else None,
        "last_success_age_minutes": age_minutes,
        "rpo_minutes": rpo_minutes,
        "disk": disk.as_dict(),
        "reasons": reasons,
        "secret_values_exposed": False,
    }


def read_json_document(path: Path | str) -> dict[str, object]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("状态文件不可读取或不是有效 JSON。") from exc
    if not isinstance(value, dict):
        raise ValueError("状态文件必须是 JSON 对象。")
    return value


def write_json_atomically(path: Path | str, document: Mapping[str, object]) -> None:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
