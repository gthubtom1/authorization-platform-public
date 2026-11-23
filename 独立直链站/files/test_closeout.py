import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import uuid
import zipfile
from django.conf import settings
from django.test import SimpleTestCase, TestCase
from . import tests as fixtures


class DownloadCloseoutTests(TestCase):
    setUp = fixtures.DirectLinkTests.setUp
    request_for = fixtures.DirectLinkTests.request_for
    upload = fixtures.DirectLinkTests.upload

    def test_head_ignores_all_range_forms_but_get_keeps_protection(self):
        item = self.upload(b'0123456789')
        for value in ('bytes=2-5','bytes=999-','nonsense'):
            r = self.client.head(f'/f/{item.current_id}/', HTTP_RANGE=value)
            self.assertEqual(r.status_code,200)
            self.assertEqual(r['Content-Length'],'10')
            self.assertNotIn('Content-Range',r)
            self.assertEqual(r.content,b'')
            self.assertEqual(self.client.head(f'/d/{item.id}/', HTTP_RANGE=value).status_code,302)
        self.assertEqual(self.client.get(f'/d/{item.id}/', HTTP_RANGE='bytes=2-').status_code,409)
        r=self.client.get(f'/f/{item.current_id}/', HTTP_RANGE='bytes=2-5')
        self.assertEqual(b''.join(r.streaming_content),b'2345')


class RestoreCloseoutTests(SimpleTestCase):
    def test_installer_rejects_redirect_unrelated_and_wrong_instance_health(self):
        spec=importlib.util.spec_from_file_location('verify_closeout',settings.BASE_DIR/'deploy/verify-site.py')
        verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)
        from .deployment import identity
        expected=identity()
        verify.require_response(200,json.dumps(expected),expected)
        for status,value in ((302,expected),(200,{'status':'ok'}),(200,{**expected,'instance':'another'}),(200,{**expected,'source_sha256':'old'})):
            with self.subTest(status=status,value=value),self.assertRaises(RuntimeError):
                verify.require_response(status,json.dumps(value),expected)

    def test_restore_checks_foreign_keys_current_ownership_removed_and_previous(self):
        spec=importlib.util.spec_from_file_location('closeout_restore',settings.BASE_DIR/'restore-backup.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        for broken in ('missing','foreign','removed','previous','valid'):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as temp:
                root=Path(temp); db=sqlite3.connect(root/'source')
                db.executescript('CREATE TABLE files_item(id TEXT PRIMARY KEY,deleted INTEGER,current_id TEXT REFERENCES files_blob(id),previous_id TEXT REFERENCES files_blob(id)); CREATE TABLE files_blob(id TEXT PRIMARY KEY,item_id TEXT REFERENCES files_item(id),size INTEGER,sha256 TEXT,removed INTEGER); CREATE TABLE files_upload(status TEXT); CREATE TABLE django_session(id TEXT);')
                item, other, blob, missing=[uuid.uuid4().hex for _ in range(4)]
                digest=hashlib.sha256(b'abc').hexdigest()
                db.execute('INSERT INTO files_item VALUES(?,0,?,?)',(item,missing if broken=='missing' else blob,missing if broken=='previous' else None))
                db.execute('INSERT INTO files_item VALUES(?,1,NULL,NULL)',(other,))
                db.execute('INSERT INTO files_blob VALUES(?,?,3,?,?)',(blob,other if broken=='foreign' else item,digest,int(broken=='removed')))
                db.commit(); db.close()
                members={'site.sqlite3':(root/'source').read_bytes()}
                if broken!='removed': members['files/'+str(uuid.UUID(blob))+'.bin']=b'abc'
                manifest={'format':'directlink-backup.v1','files':{name:{'size':len(value),'sha256':hashlib.sha256(value).hexdigest()} for name,value in members.items()}}
                archive=root/'backup.zip'
                with zipfile.ZipFile(archive,'w') as z:
                    for name,value in members.items():z.writestr(name,value)
                    z.writestr('manifest.json',json.dumps(manifest))
                target=root/'restored'
                if broken=='valid': module.restore(archive,target); self.assertTrue(target.is_dir())
                else:
                    with self.assertRaises(ValueError):module.restore(archive,target)
                    self.assertFalse(target.exists())
