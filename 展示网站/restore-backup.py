"""Restore only to a new empty directory; never overwrites a running site."""
import argparse
import json
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path

parser = argparse.ArgumentParser(description='将展示网站备份恢复到新的空数据目录')
parser.add_argument('archive', type=Path)
parser.add_argument('destination', type=Path)
args = parser.parse_args()
destination = args.destination.resolve()
if destination.exists() and any(destination.iterdir()):
    parser.error('目标目录必须为空；停止站点后恢复到新的目录，再调整数据卷。')
with zipfile.ZipFile(args.archive) as archive:
    names = archive.namelist()
    manifest = json.loads(archive.read('manifest.json'))
    if manifest.get('application') != 'software-showcase' or manifest.get('schema') != 1:
        parser.error('不是本站支持的备份。')
    if 'site.sqlite3' not in names or sum(x.file_size for x in archive.infolist()) > 10 * 1024**3:
        parser.error('备份不完整或超过10GB。')
    for name in names:
        target = (destination / name).resolve()
        if not target.is_relative_to(destination) or ('/' in name and not name.startswith('media/')):
            parser.error('备份路径不合法。')
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        if name == 'manifest.json':
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not name.endswith('/'):
            with archive.open(name) as source, target.open('xb') as output:
                import shutil
                shutil.copyfileobj(source, output)
    with closing(sqlite3.connect(destination / 'site.sqlite3')) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            parser.error('数据库完整性检查失败，不要启动恢复数据。')
        if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
            parser.error('数据库外键检查失败，不要启动恢复数据。')
        for (name,) in db.execute('SELECT file FROM catalog_productimage'):
            if not isinstance(name, str) or not name or '\\' in name or ':' in name:
                parser.error('数据库中的图片路径不安全，恢复未完成。')
            relative = Path(name)
            media_root = destination / 'media'
            picture = (media_root / relative).resolve()
            if relative.is_absolute() or '..' in relative.parts or not picture.is_relative_to(media_root) or not picture.is_file() or picture.is_symlink():
                parser.error('数据库引用的图片缺失或路径不安全，恢复未完成。')
        db.execute('DELETE FROM django_session')
        db.commit()
print('恢复及数据库、图片引用检查完成。请使用原本站.env，不要复制授权平台密钥。')
