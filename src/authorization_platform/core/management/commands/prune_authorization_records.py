from __future__ import annotations

import json
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.licensing.models import AuthorizationRequestRecord


class Command(BaseCommand):
    help = (
        "按保留期清理授权请求记录（幂等台账）。默认 dry-run，必须显式 --apply 才真删。"
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--days",
            type=int,
            default=None,
            help="保留天数；缺省用 settings.AUTHORIZATION_REQUEST_RECORD_RETENTION_DAYS。",
        )
        parser.add_argument("--batch-size", type=int, default=1000, help="每批删除的行数。")
        parser.add_argument(
            "--max-batches",
            type=int,
            default=20,
            help="单次运行最多删多少批，避免一次清掉整个窗口。",
        )
        parser.add_argument("--apply", action="store_true", help="真正执行删除；缺省只统计。")

    def handle(self, *args, **options):
        days = (
            options["days"]
            if options["days"] is not None
            else int(settings.AUTHORIZATION_REQUEST_RECORD_RETENTION_DAYS)
        )
        if days <= 0:
            # 这张表是幂等台账。清空它等于让所有历史重试重新走完整判定。
            raise CommandError("保留天数必须为正数；授权请求记录不允许被整体清空。")

        cutoff = timezone.now() - timedelta(days=days)
        total = AuthorizationRequestRecord.objects.count()
        eligible = AuthorizationRequestRecord.objects.filter(created_at__lt=cutoff).count()
        summary = {
            "retention_days": days,
            "cutoff": cutoff.isoformat(),
            "rows_total": total,
            "rows_eligible": eligible,
            "mode": "apply" if options["apply"] else "dry-run",
        }

        if not options["apply"]:
            summary["rows_deleted"] = 0
            self.stdout.write(json.dumps(summary, ensure_ascii=False, sort_keys=True))
            return

        removed = AuthorizationRequestRecord.purge_older_than(
            cutoff=cutoff,
            batch_size=options["batch_size"],
            max_batches=options["max_batches"],
        )
        summary["rows_deleted"] = removed
        summary["rows_remaining"] = AuthorizationRequestRecord.objects.count()
        record_event(
            actor=None,
            action="licensing.request_record_prune",
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "retention_days": days,
                "cutoff": cutoff.isoformat(),
                "rows_deleted": removed,
                "rows_eligible": eligible,
            },
        )
        self.stdout.write(json.dumps(summary, ensure_ascii=False, sort_keys=True))
