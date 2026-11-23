"""Deliver a redacted backup failure event to an approved local alert bridge.

The bridge receives JSON on stdin.  This script never forwards raw command
output, database values, card codes, passwords, tokens, or encryption keys.
The real bridge is deployment-owned; ``--dry-run`` is the local contract
check and does not contact an external service.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authorization_platform.core.backup_governance import read_json_document


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reason_code(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "_")
    if not normalized or len(normalized) > 64 or not normalized.replace("_", "").isalnum():
        raise ValueError("reason-code 必须是简单的稳定错误码。")
    return normalized


def build_alert_payload(*, status_document: dict[str, object], reason_code: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event": "authorization_platform_backup_failure",
        "occurred_at_utc": _utc_now(),
        "reason_code": _reason_code(reason_code),
        "last_result": str(status_document.get("last_result", "unknown")),
        "last_success_at_utc": status_document.get("last_success_at_utc"),
        "last_failure_at_utc": status_document.get("last_failure_at_utc"),
        "secret_values_exposed": False,
    }


def deliver_alert(*, handler: Path, payload: dict[str, Any], timeout_seconds: int = 10) -> None:
    if not handler.is_absolute():
        raise ValueError("alert handler 必须是绝对路径。")
    if handler.is_symlink() or not handler.is_file():
        raise ValueError("alert handler 不存在或不是普通文件。")
    completed = subprocess.run(
        [str(handler)],
        input=json.dumps(payload, ensure_ascii=False, sort_keys=True),
        text=True,
        capture_output=True,
        timeout=max(1, timeout_seconds),
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("alert handler 返回失败。")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="向受控告警桥发送脱敏备份失败事件。")
    parser.add_argument("--status-file", required=True, type=Path)
    parser.add_argument("--handler", required=True, type=Path)
    parser.add_argument("--reason-code", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        status = read_json_document(args.status_file) if args.status_file.exists() else {}
        payload = build_alert_payload(status_document=status, reason_code=args.reason_code)
        if args.dry_run:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            deliver_alert(handler=args.handler, payload=payload, timeout_seconds=args.timeout_seconds)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print(json.dumps({"schema_version": 1, "status": "critical", "reason": "alert_delivery_failed", "secret_values_exposed": False}, ensure_ascii=False))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
