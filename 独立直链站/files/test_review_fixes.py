from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import uuid
import zipfile
from unittest.mock import patch
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from . import services as s
from .storage import Busy, part_path, site_lock


class ReviewFixTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.data = self.base / 'data'; self.data.mkdir()
        self.override = override_settings(DATA_DIR=self.data, SPACE_RESERVE=100)
        self.override.enable(); self.addCleanup(self.override.disable)
        self.user = get_user_model().objects.create_user('review', is_staff=True)

    def test_unacknowledged_tail_reclaimed_before_space_check(self):
        content = b'0123456789'
        fp = hashlib.sha256(hashlib.sha256(content).digest()+b'10').hexdigest()
        with patch('files.services.free_space', return_value=110):
            u = s.begin_upload(self.user, {'key':str(uuid.uuid4()), 'filename':'file.zip', 'size':10, 'fingerprint':fp})
        p = part_path(u['id']); p.write_bytes(b'0123')
        with patch('files.services.free_space', side_effect=lambda:110-p.stat().st_size):
            result = s.accept_chunk(self.user,u['id'],0,b'0123')
        self.assertEqual(result['received'],4)

    def test_thread_lock_wait_included_in_timeout(self):
        result=[]; started=threading.Event()
        def contender():
            started.set()
            try:
                with site_lock(timeout=.02):result.append('acquired')
            except Busy:result.append('timeout')
        with site_lock():
            t=threading.Thread(target=contender);t.start();started.wait(1);t.join(.15)
        t.join(1)
        self.assertEqual(result,['timeout'])

    def test_rate_lock_not_blocked_by_file_publication_lock(self):
        result=[]
        def contender():
            try:
                with site_lock(timeout=.03, namespace='rate'):result.append('acquired')
            except Exception as e:result.append(type(e).__name__)
        with site_lock():
            t=threading.Thread(target=contender);t.start();t.join(.15)
        t.join(1)
        self.assertEqual(result,['acquired'])

    def test_restore_rejects_windows_drive_escape_before_any_outside_write(self):
        db=self.base/'source.sqlite3'
        conn=sqlite3.connect(db)
        conn.executescript('CREATE TABLE files_upload(status TEXT);CREATE TABLE django_session(id TEXT);CREATE TABLE files_item(id TEXT,deleted INTEGER);CREATE TABLE files_blob(id TEXT,item_id TEXT,size INTEGER,sha256 TEXT,removed INTEGER);')
        conn.close()
        payload={'site.sqlite3':db.read_bytes(),'files/C:escape.bin':b'escape'}
        manifest={'format':'directlink-backup.v1','files':{n:{'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for n,b in payload.items()}}
        archive=self.base/'bad.zip'
        with zipfile.ZipFile(archive,'w') as z:
            for name,content in payload.items():z.writestr(name,content)
            z.writestr('manifest.json',json.dumps(manifest))
        spec=importlib.util.spec_from_file_location('restore_review',settings.BASE_DIR/'restore-backup.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        original_open=Path.open;original_mkdir=Path.mkdir
        def guarded_open(p,*args,**kwargs):
            if args and any(x in str(args[0]) for x in ['w','x']) and not p.resolve().is_relative_to(self.base):
                raise AssertionError('Outside write prevented by test guard')
            return original_open(p,*args,**kwargs)
        def guarded_mkdir(p,*args,**kwargs):
            if not p.resolve().is_relative_to(self.base):raise AssertionError('Outside mkdir prevented by test guard')
            return original_mkdir(p,*args,**kwargs)
        with patch.object(Path,'open',guarded_open),patch.object(Path,'mkdir',guarded_mkdir):
            with self.assertRaises(ValueError):module.restore(archive,self.base/'restored')
        self.assertFalse((self.base/'restored').exists())

    def test_backup_competitor_output_never_deleted(self):
        output=self.base/'backup.zip'
        @contextmanager
        def competing_backup(*args,**kwargs):
            with zipfile.ZipFile(output,'x') as z:z.writestr('winner.txt','successful other backup')
            yield
        with patch('files.management.commands.backup_site.site_lock',competing_backup):
            with self.assertRaises(Exception):call_command('backup_site',str(output),verbosity=0)
        self.assertTrue(output.exists(),'A failed backup must not unlink another backup')
        with zipfile.ZipFile(output) as z:self.assertEqual(z.read('winner.txt'),b'successful other backup')
