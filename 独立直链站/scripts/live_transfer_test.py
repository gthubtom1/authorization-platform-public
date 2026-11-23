"""Real socket upload, full download, ranges, backup and isolated restore."""
import hashlib
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = Path(__file__).resolve().parents[1]
BASE_URL = 'http://127.0.0.1:8780'
access = json.loads((BASE / 'test-results/local-access.json').read_text())
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
opener.open(BASE_URL + '/manage/login/').read()
csrf = next(c.value for c in jar if c.name == 'directlink_csrf')
opener.open(urllib.request.Request(BASE_URL + '/manage/login/', data=urllib.parse.urlencode({'username': access['username'], 'password': access['password'], 'csrfmiddlewaretoken': csrf}).encode())).read()
csrf = next(c.value for c in jar if c.name == 'directlink_csrf')


def req(path, data=None, method=None, raw=False):
    payload = data if raw else json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(BASE_URL + path, data=payload, method=method, headers={'X-CSRFToken': csrf, 'Content-Type': 'application/octet-stream' if raw else 'application/json'})
    return opener.open(request, timeout=180)


sizes = [300 * 1024**2, 500 * 1024**2, 1024**3 + 123]
result = []
block_size = 8 * 1024**2
block = bytes(block_size)
for size in sizes:
    parts = []
    expected = hashlib.sha256()
    for offset in range(0, size, block_size):
        part = block[:min(block_size, size - offset)]
        parts.append(hashlib.sha256(part).digest()); expected.update(part)
    fingerprint = hashlib.sha256(b''.join(parts) + str(size).encode()).hexdigest()
    body = {'key':str(uuid.uuid4()), 'name':f'本地大文件验收 {size}', 'filename':'large-acceptance.zip','size':size,'fingerprint':fingerprint}
    u = json.load(req('/manage/api/uploads/',body))
    offset = 0
    while offset < size:
        part = block[:min(block_size,size-offset)]
        state = json.load(req(f"/manage/api/uploads/{u['id']}/chunk/?offset={offset}",part,raw=True))
        offset = state['received']
        if offset == min(block_size,size):
            # Emulate reconnect / lost response, then recover acknowledged state.
            state2=json.load(req(f"/manage/api/uploads/{u['id']}/"))
            assert state2['received']==offset
            retry=json.load(req(f"/manage/api/uploads/{u['id']}/chunk/?offset=0",part,raw=True))
            assert retry['received']==offset
    finish=json.load(req(f"/manage/api/uploads/{u['id']}/finish/",{},method='POST'))
    info=json.load(req(f"/manage/api/files/{finish['item_id']}/"))
    assert info['sha256']==expected.hexdigest()
    digest=hashlib.sha256(); received=0
    with opener.open(info['fixed'],timeout=180) as response:
        for chunk in iter(lambda:response.read(1024**2),b''):
            digest.update(chunk);received+=len(chunk)
    assert received==size and digest.hexdigest()==expected.hexdigest()
    request=urllib.request.Request(info['content_url'],headers={'Range':f'bytes={size-123}-'})
    with opener.open(request,timeout=30) as response:
        assert response.status==206 and len(response.read())==123
    result.append({'bytes':size,'full_upload':True,'reconnected_and_retried':True,'full_download_sha256_match':True,'range_tail':True})
    # Retain only the smallest fixture for backup; remove large test data after validation.
    if size != sizes[0]:
        json.load(req('/manage/api/actions/',{'key':str(uuid.uuid4()),'action':'delete','items':[{'id':finish['item_id'],'revision':info['revision']}]},method='POST'))
    print('SOCKET_TRANSFER_PASS',size,flush=True)

(BASE/'test-results/transfer-result.json').write_text(json.dumps({'transfers':result},indent=2),encoding='utf-8')
env={**os.environ,'DL_DEBUG':'1','DL_DATA_DIR':str(BASE/'data/acceptance')}
backup=BASE/'test-results/real-backup.zip'
backup.unlink(missing_ok=True)
subprocess.run([sys.executable,str(BASE/'manage.py'),'backup_site',str(backup)],env=env,cwd=BASE,check=True)
target=BASE/'test-results'/('restored-'+uuid.uuid4().hex[:8])
subprocess.run([sys.executable,str(BASE/'restore-backup.py'),str(backup),str(target)],check=True)
import sqlite3
with sqlite3.connect(target/'site.sqlite3') as db:
    assert db.execute('select count(*) from django_session').fetchone()[0]==0
    assert db.execute('pragma integrity_check').fetchone()[0]=='ok'
report={'transfers':result,'backup_restore':True,'restore_path':str(target)}
(BASE/'test-results/live-transfer-result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print('LIVE_TRANSFER_AND_RESTORE_PASS',flush=True)
