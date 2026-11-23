import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import uuid
from datetime import timedelta
from unittest.mock import patch
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from . import services as s
from .models import Blob, Budget, Event, Item, Operation, Upload
from .storage import Busy, blob_path, part_path, site_lock


class DirectLinkTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.override = override_settings(DATA_DIR=Path(self.tmp.name), SPACE_RESERVE=0)
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.user = get_user_model().objects.create_user('owner', password='a-strong-example-Z73!', is_staff=True)
        self.client.force_login(self.user)

    def request_for(self, content=b'file-content', target=None, name='', filename='example.zip'):
        parts = b''.join(hashlib.sha256(content[i:i+settings.CHUNK_BYTES]).digest() for i in range(0,len(content),settings.CHUNK_BYTES))
        d = {'key':str(uuid.uuid4()), 'name':name, 'filename':filename, 'size':len(content), 'fingerprint':hashlib.sha256(parts+str(len(content)).encode()).hexdigest()}
        if target:
            d.update(target=str(target.id),revision=target.revision)
        return d

    def upload(self, content=b'file-content', target=None, name='', filename='example.zip'):
        d = self.request_for(content,target,name,filename)
        u = s.begin_upload(self.user,d)
        s.accept_chunk(self.user,u['id'],0,content)
        result=s.finish_upload(self.user,u['id'])
        return Item.objects.get(id=result['item_id'])

    def action(self, item, action, **kwargs):
        return s.action(self.user,{'key':str(uuid.uuid4()),'action':action,'items':[{'id':str(item.id),'revision':item.revision}],**kwargs})

    def test_upload_optional_name_and_no_version_then_replace_fixed_link(self):
        item=self.upload(b'old',filename='old.zip')
        self.assertEqual(item.title,'old.zip')
        link=f'/d/{item.id}/'
        first=self.client.get(link)
        self.assertEqual(first.status_code,302)
        self.assertEqual(first['Cache-Control'],'no-store')
        old_url=first['Location']
        item=self.upload(b'new-content',target=item,filename='new.zip')
        self.assertEqual(item.title,'new.zip')
        self.assertNotEqual(self.client.get(link)['Location'],old_url)
        self.assertEqual(b''.join(self.client.get(old_url).streaming_content),b'old')
        self.assertEqual(b''.join(self.client.get(self.client.get(link)['Location']).streaming_content),b'new-content')

    def test_custom_name_preserved_and_server_hash_is_real(self):
        item=self.upload(b'first',name='工具')
        item=self.upload(b'second',target=item,filename='different.exe')
        self.assertEqual(item.title,'工具')
        self.assertEqual(item.current.sha256,hashlib.sha256(b'second').hexdigest())

    def test_chunk_duplicate_retry_and_wrong_bytes_rejected(self):
        content=b'abcdef'
        u=s.begin_upload(self.user,self.request_for(content))
        s.accept_chunk(self.user,u['id'],0,b'abc')
        self.assertEqual(s.accept_chunk(self.user,u['id'],0,b'abc')['received'],3)
        with self.assertRaises(Busy):s.accept_chunk(self.user,u['id'],0,b'xxx')
        with self.assertRaises(Busy):s.accept_chunk(self.user,u['id'],5,b'f')
        s.accept_chunk(self.user,u['id'],3,b'def')
        r=s.finish_upload(self.user,u['id'])
        self.assertEqual(s.finish_upload(self.user,u['id']),r)
        self.assertEqual(Blob.objects.count(),1)

    def test_begin_idempotency_and_cannot_change_file_or_owner(self):
        d=self.request_for(b'abc')
        first=s.begin_upload(self.user,d)
        self.assertEqual(s.begin_upload(self.user,d),first)
        with self.assertRaises(Busy):s.begin_upload(self.user,{**d,'filename':'other.zip'})
        other=get_user_model().objects.create_user('other',password='Secret-123-Z',is_staff=True)
        with self.assertRaises(Busy):s.begin_upload(other,d)
        with self.assertRaises(Busy):s.owned_upload(other,first['id'])

    def test_hash_mismatch_or_incomplete_cannot_publish(self):
        u=s.begin_upload(self.user,self.request_for(b'abcdef'))
        s.accept_chunk(self.user,u['id'],0,b'abc')
        with self.assertRaises(Busy):s.finish_upload(self.user,u['id'])
        s.accept_chunk(self.user,u['id'],3,b'xxx')
        with self.assertRaises(Busy):s.finish_upload(self.user,u['id'])
        self.assertEqual(Item.objects.count(),0)

    def test_middle_bytes_of_large_reselected_file_are_verified(self):
        with override_settings(CHUNK_BYTES=4):
            u=s.begin_upload(self.user,self.request_for(b'abcdefghij'))
            s.accept_chunk(self.user,u['id'],0,b'abcd')
            s.accept_chunk(self.user,u['id'],4,b'XXgh')
            s.accept_chunk(self.user,u['id'],8,b'ij')
            with self.assertRaises(Busy):s.finish_upload(self.user,u['id'])

    def test_cancel_keeps_existing_file_and_releases_reservation(self):
        item=self.upload(b'old')
        u=s.begin_upload(self.user,self.request_for(b'new',target=item))
        s.accept_chunk(self.user,u['id'],0,b'n')
        s.cancel_upload(self.user,u['id'])
        self.assertFalse(part_path(u['id']).exists())
        with self.assertRaises(Busy):s.finish_upload(self.user,u['id'])
        item.refresh_from_db();self.assertEqual(blob_path(item.current_id).read_bytes(),b'old')

    def test_disk_reservation_counts_concurrent_uploads(self):
        with patch('files.services.free_space',return_value=10):
            s.begin_upload(self.user,self.request_for(b'123456'))
            with self.assertRaises(Busy) as e:s.begin_upload(self.user,self.request_for(b'12345'))
            self.assertEqual(e.exception.status,507)

    def test_write_failure_preserves_recorded_offset_and_old_file(self):
        item=self.upload(b'old')
        u=s.begin_upload(self.user,self.request_for(b'new',target=item))
        with patch('files.services.os.fsync',side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):s.accept_chunk(self.user,u['id'],0,b'new')
        self.assertEqual(Upload.objects.get(id=u['id']).received,0)
        s.accept_chunk(self.user,u['id'],0,b'new')
        self.assertEqual(Item.objects.get(id=item.id).current_id,item.current_id)

    def test_db_write_failure_after_rename_can_retry(self):
        u=s.begin_upload(self.user,self.request_for(b'file'))
        s.accept_chunk(self.user,u['id'],0,b'file')
        with patch('files.services.audit',side_effect=RuntimeError('DB failure')):
            with self.assertRaises(RuntimeError):s.finish_upload(self.user,u['id'])
        self.assertTrue(part_path(u['id']).exists())
        self.assertEqual(Item.objects.count(),0)
        s.finish_upload(self.user,u['id'])
        self.assertEqual(Item.objects.count(),1)

    def test_process_death_after_rename_recovered_without_second_upload(self):
        u=s.begin_upload(self.user,self.request_for(b'file'))
        s.accept_chunk(self.user,u['id'],0,b'file')
        os.replace(part_path(u['id']),blob_path(u['id']))
        with site_lock():s.maintenance()
        self.assertTrue(blob_path(u['id']).exists())
        item=s.finish_upload(self.user,u['id'])
        self.assertEqual(Blob.objects.count(),1)
        self.assertEqual(Item.objects.get(id=item['item_id']).current.size,4)

    def test_conflicting_window_cannot_silently_overwrite(self):
        item=self.upload(b'old')
        d=self.request_for(b'late',target=item)
        u=s.begin_upload(self.user,d)
        newer=self.upload(b'new',target=item)
        s.accept_chunk(self.user,u['id'],0,b'late')
        with self.assertRaises(Busy):s.finish_upload(self.user,u['id'])
        newer.refresh_from_db();self.assertEqual(blob_path(newer.current_id).read_bytes(),b'new')

    def test_restore_pause_delete_and_action_replay(self):
        item=self.upload(b'old');item=self.upload(b'new',target=item)
        self.action(item,'restore');item.refresh_from_db()
        self.assertEqual(blob_path(item.current_id).read_bytes(),b'old')
        d={'key':str(uuid.uuid4()),'action':'pause','items':[{'id':str(item.id),'revision':item.revision}]}
        a=s.action(self.user,d);self.assertEqual(s.action(self.user,d),a)
        self.assertEqual(self.client.get(f'/d/{item.id}/').status_code,404)
        self.assertEqual(self.client.get(f'/f/{item.current_id}/').status_code,404)
        item.refresh_from_db();self.action(item,'resume');item.refresh_from_db()
        self.action(item,'delete')
        self.assertFalse(blob_path(item.current_id).exists())
        self.assertEqual(self.client.get(f'/d/{item.id}/').status_code,404)
        self.assertTrue(Event.objects.filter(action='file.delete').exists())

    def test_bad_batch_is_atomic_and_stale_selection_rejected(self):
        item=self.upload()
        with self.assertRaises(Busy):
            s.action(self.user,{'key':str(uuid.uuid4()),'action':'delete','items':[{'id':str(item.id),'revision':item.revision},{'id':str(uuid.uuid4()),'revision':1}]})
        item.refresh_from_db();self.assertFalse(item.deleted)

    def test_ranges_head_suffix_malformed_and_if_range(self):
        item=self.upload(b'0123456789');url=f'/f/{item.current_id}/'
        response=self.client.get(url,HTTP_RANGE='bytes=2-5')
        self.assertEqual(response.status_code,206);self.assertEqual(response['Content-Range'],'bytes 2-5/10')
        self.assertEqual(b''.join(response.streaming_content),b'2345')
        self.assertEqual(self.client.head(url)['Content-Length'],'10')
        self.assertEqual(b''.join(self.client.get(url,HTTP_RANGE='bytes=-3').streaming_content),b'789')
        for value in ['bytes=20-','bytes=4-2','bytes=0-1,3-4','bytes=-0','bytes=','bytes='+'9'*5000+'-']:
            self.assertEqual(self.client.get(url,HTTP_RANGE=value).status_code,416)
        response=self.client.get(url,HTTP_RANGE='bytes=3-',HTTP_IF_RANGE='"wrong"')
        self.assertEqual(response.status_code,200);self.assertEqual(b''.join(response.streaming_content),b'0123456789')

    def test_fixed_range_requires_original_identity_and_can_find_retained_file(self):
        item=self.upload(b'old');old=item.current
        item=self.upload(b'new',target=item)
        self.assertEqual(self.client.get(f'/d/{item.id}/',HTTP_RANGE='bytes=1-').status_code,409)
        r=self.client.get(f'/d/{item.id}/',HTTP_RANGE='bytes=1-',HTTP_IF_RANGE='"'+old.sha256+'"')
        self.assertEqual(r['Location'],f'/f/{old.id}/')

    def test_download_open_before_update_stays_on_original_bytes(self):
        item=self.upload(b'old-contents')
        response=self.client.get(f'/f/{item.current_id}/')
        self.upload(b'new-contents',target=item)
        self.assertEqual(b''.join(response.streaming_content),b'old-contents')

    def test_file_corruption_is_not_downloaded(self):
        item=self.upload();blob_path(item.current_id).write_bytes(b'x')
        self.assertEqual(self.client.get(f'/f/{item.current_id}/').status_code,503)

    def test_login_required_api_csrf_password_change_invalidates_other_session(self):
        anonymous=Client()
        self.assertEqual(anonymous.get('/manage/').status_code,302)
        self.assertEqual(anonymous.post('/manage/api/uploads/',data='{}',content_type='application/json').status_code,401)
        csrf=Client(enforce_csrf_checks=True);csrf.force_login(self.user)
        self.assertEqual(csrf.post('/manage/api/uploads/',data='{}',content_type='application/json').status_code,403)
        other=Client();other.force_login(self.user)
        r=self.client.post('/manage/settings/',{'old_password':'a-strong-example-Z73!','new_password1':'another-safe-Z94!','new_password2':'another-safe-Z94!'})
        self.assertEqual(r.status_code,302)
        self.assertEqual(other.get('/manage/').status_code,302)
        self.assertEqual(self.client.get('/manage/').status_code,302)

    def test_login_rate_expires_and_spoofed_forwarded_ip_is_ignored(self):
        c=Client()
        for _ in range(10):self.assertEqual(c.post('/manage/login/',{'username':'owner','password':'bad'},HTTP_X_REAL_IP=str(uuid.uuid4())).status_code,200)
        self.assertEqual(c.post('/manage/login/',{'username':'owner','password':'a-strong-example-Z73!'}).status_code,429)
        Budget.objects.update(until=timezone.now()-timedelta(seconds=1))
        self.assertEqual(c.post('/manage/login/',{'username':'owner','password':'a-strong-example-Z73!'}).status_code,302)

    def test_pagination_uniform_blanks_10_20_and_long_names(self):
        self.upload(name='长名字'*30)
        r=self.client.get('/manage/?size=10');self.assertContains(r,'class="blank-row"',count=9)
        r=self.client.get('/manage/?size=20');self.assertContains(r,'class="blank-row"',count=19)
        self.assertEqual(r.cookies['dl_rows'].value,'20')
        for bad in ['<script>', '9'*5000]:self.assertEqual(self.client.get('/manage/',{'page':bad}).status_code,200)

    def test_upload_filename_path_and_cross_owner_and_size_are_rejected(self):
        for filename in ['../x.zip','x\\x.zip','a.html','a.zip\r\nX:1']:
            with self.assertRaises(Busy):s.begin_upload(self.user,self.request_for(filename=filename))
        for size in [0,-1,True,1.1,'10']:
            with self.assertRaises(Busy):s.begin_upload(self.user,{**self.request_for(),'size':size})

    def test_expired_upload_removed_without_touching_retained_blob(self):
        item=self.upload()
        u=s.begin_upload(self.user,self.request_for(b'abc'))
        s.accept_chunk(self.user,u['id'],0,b'a')
        Upload.objects.filter(id=u['id']).update(touched=timezone.now()-timedelta(hours=25))
        with site_lock():s.maintenance()
        self.assertFalse(part_path(u['id']).exists())
        self.assertTrue(blob_path(item.current_id).exists())

    def test_clean_keeps_current_previous_and_recent_files(self):
        item=self.upload(b'one');old=item.current
        item=self.upload(b'two',target=item);item=self.upload(b'three',target=item)
        self.action(item,'clean');item.refresh_from_db();self.assertTrue(blob_path(old.id).exists())
        Blob.objects.filter(id=old.id).update(created=timezone.now()-timedelta(hours=25))
        self.action(item,'clean');self.assertFalse(blob_path(old.id).exists())
        self.assertTrue(blob_path(item.current_id).exists());self.assertTrue(blob_path(item.previous_id).exists())

    def test_binary_attachment_security_headers(self):
        item=self.upload(filename='中文安装包.exe')
        r=self.client.get(f'/f/{item.current_id}/')
        self.assertEqual(r['X-Content-Type-Options'],'nosniff')
        self.assertTrue(r['Content-Disposition'].startswith('attachment;'))
        r.close()

    def test_backup_and_restore_match_files_and_clear_sessions(self):
        # Real DB-file backup requires committed storage; separate integration covers it.
        spec=importlib.util.spec_from_file_location('restore',settings.BASE_DIR/'restore-backup.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        existing=Path(self.tmp.name)/'existing';existing.mkdir()
        with self.assertRaises(ValueError):module.restore('absent.zip',existing)
