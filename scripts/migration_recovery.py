"""Fail-closed migration recovery decision contract."""

from __future__ import annotations

import argparse
import json
from typing import Sequence


def migration_recovery_plan(*, migration_started: bool, backup_verified: bool, schema_compatible: bool) -> dict[str, object]:
    if not migration_started:
        return {
            "action": "rollback_application_checkpoint",
            "requires_backup": False,
            "reason": "迁移尚未开始，应用可以回到上一个兼容候选。",
        }
    if not backup_verified:
        return {
            "action": "stop_and_escalate",
            "requires_backup": True,
            "reason": "迁移已开始但没有可验证备份，禁止猜测反向迁移。",
        }
    if not schema_compatible:
        return {
            "action": "restore_isolated_then_forward_fix",
            "requires_backup": True,
            "reason": "迁移中间状态与应用不兼容，先隔离恢复并验证向前修复。",
        }
    return {
        "action": "forward_fix_after_isolated_rehearsal",
        "requires_backup": True,
        "reason": "已有备份且 schema 兼容，只允许经过隔离演练的向前修复。",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the migration failure recovery decision.")
    parser.add_argument("--migration-started", action="store_true")
    parser.add_argument("--backup-verified", action="store_true")
    parser.add_argument("--schema-compatible", action="store_true")
    args = parser.parse_args(argv)
    print(json.dumps(migration_recovery_plan(migration_started=args.migration_started, backup_verified=args.backup_verified, schema_compatible=args.schema_compatible), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
