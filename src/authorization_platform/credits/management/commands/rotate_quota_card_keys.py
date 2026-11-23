from __future__ import annotations

import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from authorization_platform.credits.services import (
    QuotaOperationError,
    migrate_quota_card_encryption_keys,
)


class Command(BaseCommand):
    help = "Validate or re-encrypt quota-card ciphertext from a legacy key version."

    def add_arguments(self, parser):
        parser.add_argument("--from-version", dest="from_version", default=None)
        parser.add_argument("--to-version", dest="to_version", default=None)
        parser.add_argument("--batch-size", dest="batch_size", type=int, default=500)
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Write the re-encrypted ciphertext; without this flag the command only validates.",
        )

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        if apply_changes and settings.APP_ENV == "production" and os.getenv("ALLOW_QUOTA_CARD_KEY_ROTATION") != "1":
            raise CommandError(
                "生产环境必须显式设置 ALLOW_QUOTA_CARD_KEY_ROTATION=1 后才能执行 --apply。"
            )
        try:
            result = migrate_quota_card_encryption_keys(
                from_version=options["from_version"],
                to_version=options["to_version"],
                dry_run=not apply_changes,
                batch_size=options["batch_size"],
            )
        except QuotaOperationError as exc:
            raise CommandError(f"{exc.code}: {exc.message}") from exc

        mode = "已迁移" if result.migrated else "仅校验"
        self.stdout.write(
            self.style.SUCCESS(
                f"{mode}额度卡密：from={result.from_version} to={result.to_version} "
                f"scanned={result.scanned} migrated={result.migrated}"
            )
        )
