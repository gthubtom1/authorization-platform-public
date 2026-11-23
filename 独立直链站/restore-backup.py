"""Offline restoration into a NEW data directory. Never overwrite a running site."""
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from contextlib import closing


def restore(archive, target):
    target = Path(target).resolve()
    if target.exists():
        raise ValueError('恢复目标必须是不存在的新目录，不能覆盖正在使用的数据。')
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as temp:
        staging = Path(temp) / 'restored'
        staging.mkdir()
        with zipfile.ZipFile(archive) as z:
            entries = z.infolist()
            names = [e.filename for e in entries]
            if len(names) != len(set(names)) or 'manifest.json' not in names:
                raise ValueError('备份含重复条目或缺少清单。')
            if z.getinfo('manifest.json').file_size > 16 * 1024 * 1024:
                raise ValueError('备份清单过大。')
            manifest = json.loads(z.read('manifest.json'))
            files = manifest.get('files', {})
            if manifest.get('format') != 'directlink-backup.v1' or not isinstance(files, dict) or set(names) != set(files) | {'manifest.json'} or 'site.sqlite3' not in files:
                raise ValueError('备份格式或条目不匹配。')
            total = sum(e.file_size for e in entries)
            if total + 256 * 1024 * 1024 > shutil.disk_usage(target.parent).free:
                raise ValueError('恢复空间不足。')
            for name, meta in files.items():
                p = PurePosixPath(name)
                if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or (name != 'site.sqlite3' and not re.fullmatch(r'files/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.bin', name)):
                    raise ValueError('备份路径不安全。')
                info = z.getinfo(name)
                if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError('备份不接受符号链接。')
                dest = staging.joinpath(*p.parts)
                if not dest.resolve().is_relative_to(staging.resolve()):
                    raise ValueError('恢复路径越过目标目录。')
                dest.parent.mkdir(exist_ok=True)
                h = hashlib.sha256()
                with z.open(name) as source, dest.open('xb') as out:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        h.update(chunk)
                        out.write(chunk)
                if dest.stat().st_size != meta['size'] or h.hexdigest() != meta['sha256']:
                    raise ValueError('文件校验失败。')
            with closing(sqlite3.connect(staging / 'site.sqlite3')) as db:
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('数据库不完整。')
                if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
                    raise ValueError('数据库外键引用不完整。')
                pointers = db.execute('SELECT id,current_id,previous_id FROM files_item WHERE deleted=0').fetchall()
                for item_id, current_id, previous_id in pointers:
                    if not current_id:
                        raise ValueError('当前文件引用缺失。')
                    for blob_id in (current_id, previous_id):
                        if blob_id is None:
                            continue
                        blob = db.execute('SELECT item_id,removed FROM files_blob WHERE id=?',(blob_id,)).fetchone()
                        if blob is None or blob[0] != item_id or blob[1]:
                            raise ValueError('当前或上一份文件归属/保留状态不完整。')
                # Upload sessions have no partial-file backup; restored clients start over.
                db.execute("UPDATE files_upload SET status='cancelled' WHERE status='uploading'")
                db.execute('DELETE FROM django_session')
                rows = db.execute('SELECT b.id,b.size,b.sha256 FROM files_blob b JOIN files_item i ON i.id=b.item_id WHERE b.removed=0 AND i.deleted=0').fetchall()
                import uuid
                for ident, size, digest in rows:
                    name = 'files/' + str(uuid.UUID(ident)) + '.bin'
                    if name not in files or files[name]['size'] != size or files[name]['sha256'] != digest:
                        raise ValueError('数据库与文件不成套。')
                db.commit()
            os.rename(staging, target)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('用法：python restore-backup.py 备份.zip 新数据目录')
    restore(sys.argv[1], sys.argv[2])
    print('RESTORE_OK')
