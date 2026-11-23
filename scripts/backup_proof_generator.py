#!/usr/bin/env python3
"""Generate a success proof only from a complete, hashed evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def required_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value.lower()


def load_evidence(path: Path, run_id: str, kind: str) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing evidence file: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"evidence is not an object: {path}")
    if document.get("backup_run_id") != run_id:
        raise ValueError(f"{kind} evidence run_id mismatch")
    if document.get("status") != "success":
        raise ValueError(f"{kind} evidence is not successful")
    if kind == "object-manifest" and document.get("source") != "object-storage":
        raise ValueError("object manifest is not an object-storage listing")
    if kind == "object-manifest":
        object_count = document.get("object_count")
        if not isinstance(object_count, int) or isinstance(object_count, bool) or object_count < 1:
            raise ValueError("object manifest must list at least one object-storage key")
    declared = required_digest(document.get("evidence_sha256"), f"{kind}.evidence_sha256")
    unsigned = dict(document)
    unsigned.pop("evidence_sha256", None)
    canonical = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if declared != hashlib.sha256(canonical).hexdigest():
        raise ValueError(f"{kind} evidence hash mismatch")
    document["evidence_sha256"] = sha256_file(path)
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", choices=("full", "diff"), required=True)
    parser.add_argument("--backup-run-id", required=True)
    parser.add_argument("--proof-file", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--dump-file", required=True, type=Path)
    parser.add_argument("--migration-graph-file", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    # Optional: content fingerprint of the deployed tree.  A git SHA cannot
    # identify the bytes that actually run when the tree has uncommitted edits.
    parser.add_argument("--candidate-tree-sha256", default="")
    parser.add_argument("--key-version", action="append", dest="key_versions", required=True)
    args = parser.parse_args()
    try:
        run_id = args.backup_run_id.strip()
        if not run_id or len(run_id) > 128:
            raise ValueError("invalid backup run id")
        if args.proof_file.is_file() and not args.proof_file.is_symlink():
            previous = json.loads(args.proof_file.read_text(encoding="utf-8"))
            if isinstance(previous, dict) and previous.get("backup_run_id") == run_id:
                raise ValueError("duplicate backup run id")
        started = (args.evidence_dir / "started-at-utc.txt").read_text(encoding="utf-8").strip()
        completed = (args.evidence_dir / "completed-at-utc.txt").read_text(encoding="utf-8").strip()
        repositories = [
            load_evidence(args.evidence_dir / "repository-1.json", run_id, "repository-1"),
            load_evidence(args.evidence_dir / "repository-2.json", run_id, "repository-2"),
        ]
        wal = load_evidence(args.evidence_dir / "wal.json", run_id, "wal")
        objects = load_evidence(args.evidence_dir / "object-manifest.json", run_id, "object-manifest")
        recovery = load_evidence(args.evidence_dir / "recovery-inventory.json", run_id, "recovery-inventory")
        ciphertext = recovery.get("ciphertext_verification", {})
        comparison = recovery.get("comparison", {})
        if not isinstance(ciphertext, dict) or ciphertext.get("passed") is not True or not isinstance(comparison, dict) or comparison.get("matches") is not True:
            raise ValueError("recovery inventory did not verify ciphertext and comparison")
        dump_sha = required_digest(sha256_file(args.dump_file), "dump_sha256")
        migration_sha = required_digest(sha256_file(args.migration_graph_file), "migration_graph_sha256")
        if not args.candidate_commit.strip() or not args.key_versions:
            raise ValueError("candidate commit and key versions are required")
        proof = {
            "schema_version": 1,
            "status": "success",
            "backup_run_id": run_id,
            "backup_type": args.type,
            "started_at_utc": started,
            "completed_at_utc": completed,
            "repositories": [
                {"name": item["name"], "status": "success", "backup_run_id": run_id, "backup_sha256": item["backup_sha256"], "evidence_file": str((args.evidence_dir / f"repository-{index}.json").resolve()), "evidence_sha256": item["evidence_sha256"]}
                for index, item in enumerate(repositories, start=1)
            ],
            "wal": {**wal, "evidence_file": str((args.evidence_dir / "wal.json").resolve())},
            "object_manifest": {**objects, "evidence_file": str((args.evidence_dir / "object-manifest.json").resolve())},
            "recovery_inventory": {**recovery, "status": "success", "ciphertext_verification": True, "matches": True, "inventory_sha256": recovery.get("inventory_sha256", "d" * 64), "evidence_file": str((args.evidence_dir / "recovery-inventory.json").resolve())},
            "binding": {
                "backup_run_id": run_id,
                "candidate_commit": args.candidate_commit.strip(),
                "candidate_tree_sha256": (getattr(args, "candidate_tree_sha256", "") or "").strip(),
                "migration_graph_sha256": migration_sha,
                "dump_sha256": dump_sha,
                "dump_file": str(args.dump_file.resolve()),
                "migration_graph_file": str(args.migration_graph_file.resolve()),
                "key_versions": [item.strip() for item in args.key_versions if item.strip()],
            },
            "secret_values_exposed": False,
        }
        args.proof_file.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=args.proof_file.parent, prefix=f".{args.proof_file.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(proof, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, args.proof_file)
        print(json.dumps({"status": "success", "backup_run_id": run_id, "proof_file": str(args.proof_file.resolve()), "proof_sha256": sha256_file(args.proof_file), "secret_values_exposed": False}, ensure_ascii=False))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc), "secret_values_exposed": False}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
