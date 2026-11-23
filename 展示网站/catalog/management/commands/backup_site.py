import json
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = '备份本站SQLite与媒体，不包含环境密钥。'

    def add_arguments(self, parser):
        parser.add_argument('--output', required=True)

    def handle(self, *args, **options):
        output = Path(options['output']).resolve()
        if output.exists():
            raise CommandError('目标文件已存在，拒绝覆盖。')
        media = Path(settings.MEDIA_ROOT).resolve()
        if output.is_relative_to(media):
            raise CommandError('不能把备份写进媒体目录。')
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / 'site.sqlite3'
            with closing(sqlite3.connect(settings.DATABASES['default']['NAME'])) as source, closing(sqlite3.connect(db)) as target:
                source.backup(target)
            with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(db, 'site.sqlite3')
                for file in media.rglob('*') if media.exists() else []:
                    if file.is_file() and not file.is_symlink():
                        archive.write(file, 'media/' + file.relative_to(media).as_posix())
                archive.writestr('manifest.json', json.dumps({'schema': 1, 'created_at': datetime.now(timezone.utc).isoformat(), 'application': 'software-showcase', 'secrets_included': False}))
        self.stdout.write(self.style.SUCCESS(f'备份已生成：{output}。请妥善保管，另存.env。'))
