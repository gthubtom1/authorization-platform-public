import hashlib
import json
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from files.models import Blob
from files.storage import blob_path, checked_path, hash_file, site_lock


class Command(BaseCommand):
    help = '在写锁内备份数据库与全部保留文件；输出不包含站点密钥，备份须妥善保护。'

    def add_arguments(self, parser):
        parser.add_argument('output')

    def handle(self, *args, **options):
        output = Path(options['output']).resolve()
        if output.exists() or settings.DATA_DIR == output.parent or settings.DATA_DIR in output.parents:
            raise CommandError('备份目标必须是数据目录外的新文件。')
        output.parent.mkdir(parents=True, exist_ok=True)
        created_output = False
        try:
            with site_lock(timeout=120), tempfile.TemporaryDirectory() as temp:
                if output.exists():
                    raise CommandError('备份目标已存在，未覆盖或删除。')
                db = Path(temp) / 'site.sqlite3'
                with closing(sqlite3.connect(settings.DATA_DIR / 'site.sqlite3')) as source, closing(sqlite3.connect(db)) as destination:
                    source.backup(destination)
                manifest = {'format': 'directlink-backup.v1', 'files': {}}
                with output.open('xb') as output_stream:
                    created_output = True
                    with zipfile.ZipFile(output_stream, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as z:
                        z.write(db, 'site.sqlite3')
                        manifest['files']['site.sqlite3'] = {'size': db.stat().st_size, 'sha256': hashlib.sha256(db.read_bytes()).hexdigest()}
                        for b in Blob.objects.filter(removed=False, item__deleted=False):
                            p = checked_path(blob_path(b.id))
                            if not p.exists() or p.stat().st_size != b.size or hash_file(p) != b.sha256:
                                raise CommandError('保留文件缺失或校验失败，备份未完成。')
                            name = 'files/' + p.name
                            z.write(p, name)
                            manifest['files'][name] = {'size': b.size, 'sha256': b.sha256}
                        z.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False))
            output.chmod(0o600)
        except Exception:
            if created_output:
                output.unlink(missing_ok=True)
            raise
        self.stdout.write('BACKUP_OK ' + str(output))
