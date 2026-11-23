"""Write and inspect a redacted backup health marker.

The command is intentionally provider-neutral.  pgBackRest/systemd invokes
``mark-success`` only after a successful backup and invokes ``record-failure``
from the failure path.  Monitoring can run ``check`` without reading secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authorization_platform.core.backup_governance import (
    backup_health,
    disk_capacity_for_path,
    read_json_document,
    validate_backup_success_proof,
    verify_backup_success_proof_material,
    write_json_atomically,
)
from authorization_platform.core.backup_markers import (
    marker_lock,
    publish_marker_for_app,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _status_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("status-file 必须是绝对路径。")
    return path


def _proof_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("proof-file 必须是绝对路径下的普通文件。")
    return path


def _write_marker(path: Path, document: dict[str, Any]) -> None:
    document = {
        "schema_version": 1,
        **document,
        "secret_values_exposed": False,
    }
    write_json_atomically(path, document)
    _publish_marker_for_app(path)


def _publish_marker_for_app(path: Path) -> None:
    """Keep the marker readable by the app user (uid 10001) after root umask 0077 writes."""

    publish_marker_for_app(path)


_marker_lock = marker_lock


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def mark_success(path: Path, proof: dict[str, object]) -> dict[str, Any]:
    proof_summary = validate_backup_success_proof(proof)
    material_errors = verify_backup_success_proof_material(proof)
    if proof_summary["status"] != "passed" or material_errors:
        raise ValueError("备份成功证明不完整，拒绝写入成功 marker。")
    incoming_time = _parse_utc(proof_summary.get("completed_at_utc"))
    if incoming_time is None:
        raise ValueError("备份成功证明缺少有效完成时间。")
    with _marker_lock(path):
        previous = read_json_document(path) if path.exists() else {}
        previous_event = _parse_utc(previous.get("last_event_at_utc"))
        previous_proof = previous.get("last_success_proof") if isinstance(previous.get("last_success_proof"), dict) else {}
        incoming_run = str(proof_summary.get("backup_run_id") or "")
        previous_run = str(previous_proof.get("backup_run_id") or "")
        if previous_event is not None and incoming_time <= previous_event:
            if previous.get("last_result") == "success" and incoming_run and incoming_run == previous_run:
                return previous
            raise ValueError("备份成功证明晚到且早于当前 marker，拒绝覆盖更新事件。")
        document = {
            "last_event_at_utc": proof_summary["completed_at_utc"],
            "last_success_at_utc": proof_summary["completed_at_utc"],
            "last_result": "success",
            "last_failure_at_utc": None,
            "last_failure_code": None,
            "last_success_proof": proof_summary,
        }
        _write_marker(path, document)
        return document


def record_failure(path: Path, reason_code: str) -> dict[str, Any]:
    normalized = reason_code.strip().lower().replace(" ", "_")
    if not normalized or len(normalized) > 64 or not normalized.replace("_", "").isalnum():
        raise ValueError("reason-code 必须是简单的稳定错误码。")
    with _marker_lock(path):
        previous: dict[str, Any] = {}
        if path.exists():
            try:
                previous = read_json_document(path)
            except ValueError:
                previous = {}
        failure_at = _utc_now()
        document = {
            "last_event_at_utc": failure_at,
            "last_success_at_utc": previous.get("last_success_at_utc"),
            "last_result": "failure",
            "last_failure_at_utc": failure_at,
            "last_failure_code": normalized,
            "last_success_proof": previous.get("last_success_proof"),
        }
        _write_marker(path, document)
        return document


def check_health(*, path: Path, disk_path: Path, rpo_minutes: int, warn_free_percent: int, critical_free_percent: int) -> dict[str, Any]:
    status_document = read_json_document(path) if path.exists() else None
    disk = disk_capacity_for_path(
        disk_path,
        warn_free_percent=warn_free_percent,
        critical_free_percent=critical_free_percent,
    )
    return backup_health(
        status_document=status_document,
        now=datetime.now(timezone.utc),
        rpo_minutes=rpo_minutes,
        disk=disk,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="检查或更新脱敏备份健康状态。")
    parser.add_argument("command", choices=("mark-success", "record-failure", "check"))
    parser.add_argument("--status-file", required=True, type=_status_path)
    parser.add_argument("--proof-file", type=_proof_path, help="备份成功证明 JSON；mark-success 必须提供。")
    parser.add_argument("--reason-code", default="backup_service_failed")
    parser.add_argument("--disk-path", type=Path, default=Path("/srv/authorization-platform"))
    parser.add_argument("--rpo-minutes", type=int, default=int(os.getenv("BACKUP_RPO_MINUTES", "15")))
    parser.add_argument("--warn-free-percent", type=int, default=int(os.getenv("BACKUP_WARN_FREE_PERCENT", "25")))
    parser.add_argument("--critical-free-percent", type=int, default=int(os.getenv("BACKUP_CRITICAL_FREE_PERCENT", "15")))
    args = parser.parse_args(argv)
    try:
        if args.command == "mark-success":
            if args.proof_file is None:
                raise ValueError("mark-success 必须提供 proof-file。")
            result = mark_success(args.status_file, read_json_document(args.proof_file))
        elif args.command == "record-failure":
            result = record_failure(args.status_file, args.reason_code)
        else:
            result = check_health(
                path=args.status_file,
                disk_path=args.disk_path,
                rpo_minutes=args.rpo_minutes,
                warn_free_percent=args.warn_free_percent,
                critical_free_percent=args.critical_free_percent,
            )
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema_version": 1, "status": "critical", "reasons": ["health_check_error"], "secret_values_exposed": False}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if args.command != "check" or result.get("status") == "ok" else (1 if result.get("status") == "warning" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
