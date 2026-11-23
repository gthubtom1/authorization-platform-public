"""Atomic local application pointer used to rehearse application rollback."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RollbackError(Exception):
    pass


def _safe_version(value: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise RollbackError("版本标识不安全。")
    return value


def tree_sha256(root: Path) -> str:
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise RollbackError("候选目录不存在或不是安全目录。")
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _state_path(root: Path) -> Path:
    return root.resolve() / "active-release.json"


def read_state(root: Path) -> dict[str, Any]:
    path = _state_path(root)
    if not path.is_file():
        return {"schema_version": 1, "active": None, "previous": None}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RollbackError("应用指针损坏。") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RollbackError("应用指针版本不受支持。")
    return value


def activate_candidate(root: Path, candidate: Path, version: str, *, health_verified: bool) -> dict[str, Any]:
    version = _safe_version(version)
    if not health_verified:
        raise RollbackError("候选未通过健康检查，禁止切换。")
    root = root.resolve()
    candidate = candidate.resolve()
    digest = tree_sha256(candidate)
    current = read_state(root)
    active = {"version": version, "path": str(candidate), "tree_sha256": digest}
    state = {
        "schema_version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "active": active,
        "previous": current.get("active"),
    }
    _atomic_json(_state_path(root), state)
    return state


def rollback_candidate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    current = read_state(root)
    previous = current.get("previous")
    if not isinstance(previous, dict) or not previous.get("path") or not previous.get("tree_sha256"):
        raise RollbackError("没有可验证的上一候选，禁止回滚。")
    previous_path = Path(str(previous["path"]))
    if tree_sha256(previous_path) != previous["tree_sha256"]:
        raise RollbackError("上一候选内容哈希已变化，禁止回滚。")
    state = {
        "schema_version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "active": previous,
        "previous": current.get("active"),
    }
    _atomic_json(_state_path(root), state)
    return state


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rehearse an atomic application rollback pointer locally.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    activate = subparsers.add_parser("activate")
    activate.add_argument("--root", type=Path, required=True)
    activate.add_argument("--candidate", type=Path, required=True)
    activate.add_argument("--version", required=True)
    activate.add_argument("--health-verified", action="store_true")
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--root", type=Path, required=True)
    status = subparsers.add_parser("status")
    status.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "activate":
            result = activate_candidate(args.root, args.candidate, args.version, health_verified=args.health_verified)
        elif args.command == "rollback":
            result = rollback_candidate(args.root)
        else:
            result = read_state(args.root)
    except RollbackError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
