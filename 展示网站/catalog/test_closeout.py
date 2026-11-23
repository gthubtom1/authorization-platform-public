import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from django.conf import settings
from django.test import SimpleTestCase


class RestoreCloseoutTests(SimpleTestCase):
    def test_missing_referenced_picture_cannot_report_restore_success(self):
        for picture in ('products/missing.webp','../outside.webp','products/present.webp'):
            with self.subTest(picture=picture), tempfile.TemporaryDirectory() as temp:
                root=Path(temp);database=root/'source.sqlite3'
                db=sqlite3.connect(database)
                db.executescript('CREATE TABLE catalog_productimage(file TEXT);CREATE TABLE django_session(id TEXT);')
                db.execute('INSERT INTO catalog_productimage VALUES(?)',(picture,));db.commit();db.close()
                with zipfile.ZipFile(root/'backup.zip','w') as z:
                    z.write(database,'site.sqlite3')
                    z.writestr('manifest.json',json.dumps({'application':'software-showcase','schema':1}))
                    if picture=='products/present.webp':z.writestr('media/'+picture,b'fixture-image-bytes')
                result=subprocess.run([sys.executable,str(settings.BASE_DIR/'restore-backup.py'),str(root/'backup.zip'),str(root/'restored')],capture_output=True,text=True,encoding='utf-8')
                self.assertEqual(result.returncode==0,picture=='products/present.webp',result.stdout+result.stderr)


class InstallerCloseoutTests(SimpleTestCase):
    def test_update_stops_writes_then_backs_up_stopped_and_running_sites(self):
        bash=shutil.which('bash');self.assertIsNotNone(bash,'Bash must be on PATH')
        source=Path(os.environ.get('SHOWCASE_INSTALL_SOURCE',settings.BASE_DIR/'deploy/install-site.sh')).read_text(encoding='utf-8')
        body=source.split('docker compose config --quiet',1)[1].split('\nsed ',1)[0]
        for running in ('0','1'):
            for failure in ('0','1'):
                with self.subTest(running=running,failure=failure), tempfile.TemporaryDirectory() as temp:
                    root=Path(temp);log=root/'trace';state=root/'running';state.write_text(running)
                    env=dict(os.environ,TRACE=str(log).replace('\\','/'),STATE=str(state).replace('\\','/'),FAIL_BACKUP=failure)
                    fake='''set -euo pipefail
python3(){ echo showcase.test; }
docker(){
 printf '%s\\n' "$*" >> "$TRACE"
 if [[ "$*" == "compose stop app" ]]; then printf 0 > "$STATE"; fi
 if [[ "$*" == "compose ps --status running --services" ]] && [[ "$(cat "$STATE")" == 1 ]]; then echo app; fi
 if [[ "$*" == *pre-update-backup.py* && "$FAIL_BACKUP" == 1 ]]; then return 42; fi
 return 0
}
'''
                    result=subprocess.run([bash,'-c',fake+body],env=env,cwd=root,text=True,capture_output=True)
                    commands=log.read_text().splitlines()
                    backup=next((i for i,c in enumerate(commands) if 'backup' in c),None)
                    self.assertIsNotNone(backup,'Old persistent data must be checked even if app is stopped')
                    self.assertLess(commands.index('compose stop app'),backup)
                    migration=next((i for i,c in enumerate(commands) if 'migrate' in c),None)
                    if failure=='1':self.assertNotEqual(result.returncode,0);self.assertIsNone(migration)
                    else:self.assertEqual(result.returncode,0,result.stderr);self.assertLess(backup,migration)
