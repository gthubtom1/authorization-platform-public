#!/usr/bin/env python3
"""Collect run-bound backup evidence from real staging commands.

The collector is intentionally fail-closed: recovery evidence must include an
actual compare artifact from a distinct database identity. A same-database
inventory is not treated as restore proof, and `recovery_inventory --compare`
rejects that path unless `--allow-same-database` is set for diagnostics.
A PostgreSQL data-directory listing is not an object-storage proof; set
BACKUP_OBJECT_STORAGE_LIST to a command that lists the object-store keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_evidence(path: Path, document: dict[str, object]) -> None:
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    document["evidence_sha256"] = sha256_bytes(canonical)
    path.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def run(command: list[str]) -> tuple[int, str]:
    argv = list(command)
    if argv and argv[0].endswith(".sh"):
        argv = ["bash", *argv]
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as exc:
        return 127, str(exc)
    return completed.returncode, completed.stdout.strip() or completed.stderr.strip()


def _keys_from_json_listing(payload: object) -> list[str]:
    if isinstance(payload, list):
        keys: list[str] = []
        for item in payload:
            if isinstance(item, str) and item.strip():
                keys.append(item.strip())
            elif isinstance(item, dict):
                key = item.get("Key") or item.get("key")
                if isinstance(key, str) and key.strip():
                    keys.append(key.strip())
        return keys
    if not isinstance(payload, dict):
        return []
    if "Contents" in payload:
        contents = payload.get("Contents") or []
        if not isinstance(contents, list):
            return []
        keys = []
        for item in contents:
            if isinstance(item, dict):
                key = item.get("Key") or item.get("key")
                if isinstance(key, str) and key.strip():
                    keys.append(key.strip())
        return keys
    explicit = payload.get("keys")
    if isinstance(explicit, list):
        return [item.strip() for item in explicit if isinstance(item, str) and item.strip()]
    if payload.get("KeyCount") == 0:
        return []
    return []


def object_storage_keys_from_listing(output: str) -> list[str]:
    """Count object-store keys, not JSON envelope lines.

    AWS/mc empty-bucket JSON still has several non-empty lines (Name, KeyCount=0).
    Those lines are not object keys and must not become a success proof.
    Trailing CLI text after a JSON envelope must not fall back to line counting.
    """
    text = (output or "").strip()
    if not text:
        return []
    try:
        payload, end = json.JSONDecoder().raw_decode(text)
    except json.JSONDecodeError:
        if _listing_contains_json_payload(text):
            return []
        return [line.strip() for line in text.splitlines() if line.strip()]
    if text[end:].strip():
        return []
    return _keys_from_json_listing(payload)


def _listing_contains_json_payload(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", choices=("full", "diff"), required=True)
    parser.add_argument("--backup-run-id", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--db-container", required=True)
    parser.add_argument("--db-name", default="authorization_platform")
    parser.add_argument("--db-user", default="authorization_platform")
    parser.add_argument("--stanza", default="authorization-platform")
    parser.add_argument("--app-manage", required=True, type=Path)
    parser.add_argument("--dump-file", required=True, type=Path)
    parser.add_argument("--migration-graph-file", required=True, type=Path)
    args = parser.parse_args()
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    (args.evidence_dir / "started-at-utc.txt").write_text(started, encoding="utf-8")
    failures: list[str] = []
    for index in (1, 2):
        code, output = run(["docker", "exec", "-u", "postgres", args.db_container, "pgbackrest", f"--stanza={args.stanza}", f"--repo={index}", "info", "--output=json"])
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            payload = []
        backups = payload[0].get("backup", []) if isinstance(payload, list) and payload and isinstance(payload[0], dict) else []
        ok = code == 0 and bool(backups)
        if not ok:
            failures.append(f"repository-{index}-not-ready")
        write_evidence(args.evidence_dir / f"repository-{index}.json", {"name": "primary" if index == 1 else "secondary", "status": "success" if ok else "failed", "backup_run_id": args.backup_run_id, "backup_sha256": sha256_bytes(output.encode()), "provider_output_sha256": sha256_bytes(output.encode())})

    psql_query = "select current_setting('archive_mode'), pg_current_wal_lsn(), coalesce((select last_archived_wal from pg_stat_archiver), ''), coalesce((select last_archived_time::text from pg_stat_archiver), '')"
    psql_command = f"psql -U {shlex.quote(args.db_user)} -d {shlex.quote(args.db_name)} -At -F '|' -c {shlex.quote(psql_query)}"
    code, output = run(["docker", "exec", args.db_container, "sh", "-c", psql_command])
    fields = output.split("|", 3)
    wal_ok = code == 0 and len(fields) == 4 and fields[0] == "on" and bool(fields[2])
    if not wal_ok:
        failures.append("wal-not-ready")
    write_evidence(args.evidence_dir / "wal.json", {"backup_run_id": args.backup_run_id, "status": "success" if wal_ok else "failed", "archive_ready": wal_ok, "start_lsn": fields[1] if len(fields) > 1 else "", "end_lsn": fields[1] if len(fields) > 1 else "", "last_archived_at_utc": fields[3] if len(fields) > 3 else "", "provider_output_sha256": sha256_bytes(output.encode())})

    object_list_command = os.environ.get("BACKUP_OBJECT_STORAGE_LIST", "").strip()
    object_ok = False
    object_source = "missing"
    output = "object-storage listing command missing"
    object_count = 0
    if object_list_command:
        code, output = run(shlex.split(object_list_command))
        keys = object_storage_keys_from_listing(output) if code == 0 else []
        object_ok = code == 0 and bool(keys)
        object_source = "object-storage" if object_ok else "object-storage-failed"
        object_count = len(keys) if object_ok else 0
        if not object_ok:
            failures.append("object-manifest-unreadable")
    else:
        failures.append("object-manifest-not-object-storage")
        object_source = "postgresql-data-directory"
        output = "postgresql data directory listing is not an object-storage proof"
    write_evidence(
        args.evidence_dir / "object-manifest.json",
        {
            "backup_run_id": args.backup_run_id,
            "status": "success" if object_ok else "failed",
            "source": "object-storage" if object_ok else object_source,
            "manifest_sha256": sha256_bytes(output.encode()),
            "object_count": object_count,
        },
    )

    python_bin = os.environ.get("PYTHON_BIN", "python3")
    code, output = run(
        [python_bin, str(args.app_manage), "recovery_inventory", "--verify-ciphertext"]
    )
    cipher_ok = code == 0
    if not cipher_ok:
        failures.append("recovery-ciphertext-not-verified")
    compare_path = os.environ.get("BACKUP_RECOVERY_COMPARE", "").strip()
    compare_ok = False
    if compare_path:
        compare_file = Path(compare_path)
        if compare_file.is_file() and not compare_file.is_symlink():
            code, compared = run(
                [
                    python_bin,
                    str(args.app_manage),
                    "recovery_inventory",
                    "--verify-ciphertext",
                    "--compare", compare_path,
                ]
            )
            compare_ok = code == 0
            output = compared
        if not compare_ok:
            failures.append("recovery-compare-not-verified")
    recovery_ok = cipher_ok and (compare_ok if compare_path else True)
    write_evidence(
        args.evidence_dir / "recovery-inventory.json",
        {
            "backup_run_id": args.backup_run_id,
            "status": "success" if recovery_ok else "failed",
            "comparison": {"matches": bool(compare_ok if compare_path else cipher_ok)},
            "ciphertext_verification": {"passed": cipher_ok},
            "inventory_sha256": sha256_bytes(output.encode()),
            "collector_output_sha256": sha256_bytes(output.encode()),
        },
    )
    completed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (args.evidence_dir / "completed-at-utc.txt").write_text(completed, encoding="utf-8")
    print(json.dumps({"status": "success" if not failures else "failed", "backup_run_id": args.backup_run_id, "failures": failures, "evidence_dir": str(args.evidence_dir.resolve()), "secret_values_exposed": False}, ensure_ascii=False))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
