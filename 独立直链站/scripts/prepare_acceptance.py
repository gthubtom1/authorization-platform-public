"""Isolated local acceptance fixtures. Never pointed at normal or production data."""
import io
import json
import os
from pathlib import Path
import secrets
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
os.environ['DL_DEBUG'] = '1'
os.environ['DL_DATA_DIR'] = str(BASE / 'data' / 'acceptance')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'directsite.settings')
import django
django.setup()
from django.core.management import call_command
from django.contrib.auth import get_user_model
from files import services as s
from files.models import Item

call_command('migrate', interactive=False, verbosity=0)
result = BASE / 'test-results'
result.mkdir(exist_ok=True)
access_file = result / 'local-access.json'
if access_file.exists():
    access = json.loads(access_file.read_text())
else:
    access = {'username': 'local-review', 'password': secrets.token_urlsafe(24), 'url': 'http://127.0.0.1:8780/manage/'}
    access_file.write_text(json.dumps(access), encoding='utf-8')
    access_file.chmod(0o600)
user, created = get_user_model().objects.get_or_create(username=access['username'], defaults={'is_staff': True})
if created:
    user.set_password(access['password']); user.save()
if not Item.objects.filter(deleted=False).exists():
    import hashlib
    import uuid
    for i in range(23):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as z:
            z.writestr('本地验收样例.txt', '此文件仅用于本地界面验收，不是真实软件。' * (i + 1))
        data = buffer.getvalue()
        fp = hashlib.sha256(hashlib.sha256(data).digest() + str(len(data)).encode()).hexdigest()
        names = ['文档助手', '文件整理工具', '素材管理', '桌面工具箱']
        request = {'key': str(uuid.uuid4()), 'name': f'本地验收 · {names[i % 4]} {i + 1:02}', 'filename': f'acceptance-{i + 1:02}.zip', 'size': len(data), 'fingerprint': fp}
        u = s.begin_upload(user, request)
        s.accept_chunk(user, u['id'], 0, data)
        s.finish_upload(user, u['id'])
print('LOCAL_ACCEPTANCE_READY; credentials kept only in ignored test-results/local-access.json')
