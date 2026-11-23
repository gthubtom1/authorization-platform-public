from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import OperationalError

from authorization_platform.core.recovery_inventory import collect_recovery_inventory, compare_recovery_inventories


class Command(BaseCommand):
    help = "生成脱敏恢复核对清单，并可验证卡密密文与密钥版本是否仍可用。"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--verify-ciphertext",
            action="store_true",
            help="在内存中解密邀请码、额度卡和授权卡，并重新核对 HMAC；不输出明文。",
        )
        parser.add_argument(
            "--output",
            type=Path,
            help="把 JSON 清单写到指定路径；写入内容不含密码、完整卡密、密钥或数据库连接信息。",
        )
        parser.add_argument(
            "--compare",
            type=Path,
            help="与之前生成的源库清单比较；默认拒绝同一数据库自比，不能当作隔离恢复证明。",
        )
        parser.add_argument(
            "--allow-same-database",
            action="store_true",
            help="仅诊断用：允许源清单与当前库是同一数据库。隔离恢复核对不得使用。",
        )

    def handle(self, *args, **options):
        try:
            inventory = collect_recovery_inventory(verify_ciphertext=options["verify_ciphertext"])
        except OperationalError as exc:
            raise CommandError("恢复清单无法读取完整业务表；请先在目标数据库执行全部迁移。") from exc
        verification = inventory.get("ciphertext_verification")
        if verification and not verification.get("passed", False):
            self._write_result(inventory, options.get("output"))
            raise CommandError("恢复清单发现卡密密文无法通过解密/HMAC 校验。")
        ledger_integrity = inventory.get("tables", {}).get("quota_ledger_entries", {}).get("integrity")
        if options["verify_ciphertext"] and ledger_integrity and not ledger_integrity.get("passed", False):
            self._write_result(inventory, options.get("output"))
            raise CommandError("恢复清单发现额度流水链或余额不一致。")

        if options.get("compare"):
            expected = self._read_document(options["compare"])
            comparison = compare_recovery_inventories(
                expected,
                inventory,
                require_distinct_source=not options.get("allow_same_database"),
            )
            inventory["comparison"] = comparison
            self._write_result(inventory, options.get("output"))
            if not comparison["matches"]:
                raise CommandError(comparison.get("reason") or "恢复库与源库的脱敏业务指纹不一致。")
        else:
            self._write_result(inventory, options.get("output"))

        self.stdout.write(json.dumps(inventory, ensure_ascii=False, sort_keys=True, indent=2))

    def _read_document(self, path: Path) -> dict[str, object]:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CommandError("源恢复清单不可读取或不是有效 JSON。") from exc
        if not isinstance(document, dict):
            raise CommandError("源恢复清单必须是 JSON 对象。")
        return document

    def _write_result(self, document: dict[str, object], output: Path | None) -> None:
        if output is None:
            return
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
