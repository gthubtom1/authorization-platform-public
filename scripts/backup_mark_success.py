"""Bind a backup proof to the current runner invocation before marking success."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from backup_health import mark_success  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-file", required=True, type=Path)
    parser.add_argument("--proof-file", required=True, type=Path)
    parser.add_argument("--run-id-file", required=True, type=Path)
    parser.add_argument("--skip-sentinel", type=Path, default=None)
    args = parser.parse_args()
    skip_sentinel = args.skip_sentinel
    if skip_sentinel is None:
        stamp_dir = os.environ.get("BACKUP_SCHEDULE_STAMP_DIR", "").strip()
        if stamp_dir:
            skip_sentinel = Path(stamp_dir) / "last-exec-skipped"
    if skip_sentinel is not None and skip_sentinel.is_file():
        skip_sentinel.unlink(missing_ok=True)
        print(json.dumps({"schema_version": 1, "status": "skipped", "reasons": ["schedule_skip_leftover_proof_ignored"], "secret_values_exposed": False}, ensure_ascii=False, sort_keys=True))
        return 0
    if not args.proof_file.is_file() or not args.run_id_file.is_file():
        print(json.dumps({"schema_version": 1, "status": "critical", "reasons": ["proof_or_run_id_missing"], "secret_values_exposed": False}, ensure_ascii=False, sort_keys=True))
        return 2
    try:
        proof = json.loads(args.proof_file.read_text(encoding="utf-8"))
        current_run_id = args.run_id_file.read_text(encoding="utf-8").strip()
        if not isinstance(proof, dict) or not current_run_id or str(proof.get("backup_run_id", "")) != current_run_id:
            raise ValueError("backup proof does not match the current runner invocation")
        result = mark_success(args.status_file, proof)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"schema_version": 1, "status": "critical", "reasons": ["proof_invalid_or_run_id_mismatch"], "secret_values_exposed": False}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
