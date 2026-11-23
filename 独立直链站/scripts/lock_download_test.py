"""Prove a separate publisher holding the file lock does not block new downloads."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid

BASE = Path(__file__).resolve().parents[1]
with sqlite3.connect(BASE/'data/acceptance/site.sqlite3') as db:
    row=db.execute('SELECT i.id FROM files_item i JOIN files_blob b ON b.id=i.current_id WHERE i.deleted=0 AND i.paused=0 AND b.size<1000000 LIMIT 1').fetchone()
assert row
code="""
import os,time
os.environ.setdefault('DJANGO_SETTINGS_MODULE','directsite.settings')
import django
django.setup()
from files.storage import site_lock
with site_lock():
 print('LOCKED',flush=True)
 time.sleep(3)
"""
env={**os.environ,'DL_DEBUG':'1','DL_DATA_DIR':str(BASE/'data/acceptance')}
p=subprocess.Popen([sys.executable,'-c',code],cwd=BASE,env=env,stdout=subprocess.PIPE,text=True)
try:
    assert p.stdout.readline().strip()=='LOCKED'
    start=time.monotonic()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:8780/d/'+str(uuid.UUID(row[0]))+'/',timeout=2) as response:
        content=response.read()
        assert response.status==200 and content
    elapsed=time.monotonic()-start
    assert elapsed<1.5,elapsed
    result={'publisher_lock_seconds':3,'public_download_seconds':elapsed,'separate_process':True,'passed':True}
    (BASE/'test-results/download-lock-result.json').write_text(json.dumps(result,indent=2))
    print('DOWNLOAD_LOCK_ISOLATION_PASS',round(elapsed,3))
finally:
    p.wait(timeout=5)
