from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from authorization_platform.backup_control.services import (
    BackupControlError,
    decide_backup_run,
    finish_backup_run,
    get_policy,
    renew_backup_run,
    runner_export,
    schedule_due_backups,
    upload_encrypted_backup,
    write_github_token_file,
)


class Command(BaseCommand):
    help = "检查管理员备份策略，供 systemd runner 使用。"

    def add_arguments(self, parser):
        parser.add_argument("--check", action="store_true")
        parser.add_argument("--github-retention", action="store_true")
        parser.add_argument("--database-check", action="store_true")
        parser.add_argument("--github-check", action="store_true")
        parser.add_argument("--full-retention", action="store_true")
        parser.add_argument("--diff-retention", action="store_true")
        parser.add_argument("--archive-retention", action="store_true")
        parser.add_argument("--cleanup-check", action="store_true")
        parser.add_argument("--export-json", action="store_true")
        parser.add_argument("--schedule-full", action="store_true")
        parser.add_argument("--schedule", action="store_true")
        parser.add_argument("--pending-run", action="store_true")
        parser.add_argument("--github-repo", action="store_true")
        parser.add_argument("--write-github-token", metavar="PATH")
        parser.add_argument("--decide", action="store_true")
        parser.add_argument("--type", choices=("full", "diff"))
        parser.add_argument("--complete-run", metavar="ID")
        parser.add_argument("--heartbeat-run", metavar="ID")
        parser.add_argument("--attempt-token", metavar="TOKEN")
        parser.add_argument("--result", choices=("succeeded", "failed"))
        parser.add_argument("--message", default="")
        parser.add_argument("--upload-enc", metavar="PATH")

    def handle(self, *args, **options):
        try:
            self._handle(options)
        except BackupControlError as exc:
            raise CommandError(exc.message) from exc

    def _handle(self, options: dict) -> None:
        policy = get_policy()
        if options.get("schedule"):
            result = schedule_due_backups()
            self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
        elif options.get("write_github_token"):
            result = write_github_token_file(Path(options["write_github_token"]))
            self.stdout.write(result)
        elif options.get("decide"):
            backup_type = options.get("type") or "full"
            self.stdout.write(json.dumps(decide_backup_run(backup_type=backup_type), ensure_ascii=False))
        elif options.get("complete_run"):
            if not options.get("result"):
                raise CommandError("完成排队备份时必须提供结果。")
            finish_backup_run(
                run_id=str(options["complete_run"]),
                result=str(options["result"]),
                attempt_token=str(options.get("attempt_token") or ""),
                message=str(options.get("message") or ""),
            )
            self.stdout.write("ok")
        elif options.get("heartbeat_run"):
            renew_backup_run(
                run_id=str(options["heartbeat_run"]),
                attempt_token=str(options.get("attempt_token") or ""),
            )
            self.stdout.write("ok")
        elif options.get("upload_enc"):
            result = upload_encrypted_backup(Path(options["upload_enc"]))
            self.stdout.write(result)
        elif options.get("github_repo"):
            self.stdout.write(str(policy.github_repository or ""))
        elif options.get("export_json"):
            self.stdout.write(json.dumps(runner_export(), ensure_ascii=False))
        elif options.get("schedule_full"):
            self.stdout.write(f"{int(policy.schedule_full_hour):02d}:{int(policy.schedule_full_minute):02d}")
        elif options.get("pending_run"):
            pending = runner_export().get("pending_run") or {}
            self.stdout.write(str(pending.get("backup_type") or "none"))
        elif options.get("cleanup_check"):
            self.stdout.write("enabled" if policy.cleanup_enabled else "disabled")
        elif options.get("full_retention"):
            self.stdout.write(str(policy.retention_full))
        elif options.get("diff_retention"):
            self.stdout.write(str(policy.retention_diff))
        elif options.get("archive_retention"):
            self.stdout.write(str(policy.retention_archive))
        elif options.get("database_check"):
            self.stdout.write("enabled" if policy.database_enabled else "disabled")
        elif options.get("github_check"):
            self.stdout.write("enabled" if policy.github_enabled else "disabled")
        elif options.get("github_retention"):
            self.stdout.write(str(policy.github_retention_count))
        else:
            self.stdout.write("enabled" if policy.enabled else "disabled")
