from __future__ import annotations

import json
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from authorization_platform.backup_control.models import BackupRunRequest
from authorization_platform.core.backup_governance import read_json_document, write_json_atomically
from authorization_platform.core.backup_markers import marker_lock, publish_marker_for_app


def _parse_utc(value: object):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return parsed.astimezone(dt_timezone.utc)


class Command(BaseCommand):
    help = (
        "把备份健康标记与数据库里的真实运行记录对齐（dump-only 部署形态）。"
        "只在最新一次运行确实成功时写成功；不伪造 pgBackRest 证明。"
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--status-file",
            required=True,
            type=Path,
            help="健康标记 JSON 的绝对路径（宿主 BACKUP_ROOT 下的 backup-status.json）。",
        )

    def handle(self, *args, **options):
        path: Path = options["status_file"]
        if not path.is_absolute():
            raise CommandError("status-file 必须是绝对路径。")

        latest = BackupRunRequest.objects.order_by("-created_at").first()
        if latest is None:
            result = {"status": "no_runs", "changed": False}
            self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return
        if str(latest.status) != "succeeded":
            # 最新一次是失败：失败路径自己会写标记，这里绝不能把它翻绿。
            result = {
                "status": "latest_run_not_successful",
                "changed": False,
                "latest_status": str(latest.status),
            }
            self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return

        finished = getattr(latest, "finished_at", None) or latest.created_at
        success_at = finished.astimezone(dt_timezone.utc).isoformat().replace("+00:00", "Z")

        with marker_lock(path):
            previous = read_json_document(path) if path.exists() else {}
            recorded = _parse_utc(previous.get("last_success_at_utc"))
            incoming = _parse_utc(success_at)
            if (
                previous.get("last_result") == "success"
                and recorded is not None
                and incoming is not None
                and recorded >= incoming
            ):
                result = {
                    "status": "already_current",
                    "changed": False,
                    "last_success_at_utc": previous.get("last_success_at_utc"),
                }
                self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
                return
            document = {
                "schema_version": 1,
                "last_event_at_utc": success_at,
                "last_success_at_utc": success_at,
                "last_result": "success",
                "last_failure_at_utc": None,
                "last_failure_code": None,
                # 明确不伪造证明：这套部署没有 pgBackRest 仓库，未经双仓/WAL 校验。
                "last_success_proof": None,
                "proof_mode": "dump_only",
                "reconciled_from": "backup_run_request",
                "reconciled_note": "按数据库运行记录对齐；本部署没有 pgBackRest 仓库，未经双仓/WAL 证明校验。",
                "secret_values_exposed": False,
            }
            write_json_atomically(path, document)
            publish_marker_for_app(path)
            result = {"status": "reconciled", "changed": True, "last_success_at_utc": success_at}
            self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
