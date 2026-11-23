"""Recoverable same-filesystem deletion, coordinated with the durable DB result.

The policy DB row is acquired first by the API. The file lock is retained until
that DB transaction has committed/rolled back. A durable journal precedes rename;
after a crash a matching committed operation permits cleanup, otherwise restore.
"""
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from django.core.files.locks import LOCK_EX, lock, unlock
from .models import BackupControlOperation

_current = ContextVar('backup_download_delete', default=None)
_held = ContextVar('backup_download_file_lock', default=False)


def _root():
    from .services import _download_root
    return _download_root()


def _failure(message):
    from .services import BackupControlError
    return BackupControlError('BACKUP_DELETE_RECOVERY_REQUIRED', message, status=503)


def _sync_directory(root):
    if os.name != 'nt':
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


@contextmanager
def file_lock():
    state = _current.get()
    if _held.get():
        yield
        return
    root = _root(); root.mkdir(parents=True, exist_ok=True)
    handle = (root/'.download-delete.lock').open('a+b')
    lock(handle, LOCK_EX)
    held_token = _held.set(True)
    def release():
        try: unlock(handle); handle.close()
        finally: _held.reset(held_token)
    if state is not None:
        state['locked'] = True
        state['stack'].callback(release)
        yield
    else:
        try: yield
        finally: release()


def _matches(path, record):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != record['size']:
        return False
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''): h.update(block)
    return h.hexdigest() == record['sha256']


def recover_pending(*, include_current=False):
    root = _root()
    journals = list(root.glob('.delete-*.json'))
    if not journals: return
    state = _current.get()
    with file_lock():
        for journal in journals:
            if not journal.exists(): continue
            if not include_current and state and journal in state['journals']: continue
            if journal.is_symlink() or journal.stat().st_size > 16384:
                raise _failure('备份删除恢复记录无效，请维护者核对。')
            record = json.loads(journal.read_text(encoding='utf-8'))
            name = record['name']; payload_name = record['payload']
            if Path(name).name != name or '/' in name or '\\' in name or ':' in name or Path(name).suffix.lower() != '.enc' or not re.fullmatch(r'\.delete-[0-9a-f]{32}\.payload',payload_name):
                raise _failure('备份删除恢复路径无效。')
            original, payload = root/name, root/payload_name
            operation = BackupControlOperation.objects.filter(actor_id=record['actor'], action='download.delete', idempotency_key=record['key']).first()
            if operation is not None and (operation.request_hash != record['request_hash'] or operation.response != record['result']):
                raise _failure('删除记录与原请求不一致，请维护者核对。')
            if payload.exists():
                if not _matches(payload,record): raise _failure('隔离备份身份不一致，未清理文件。')
                if operation is not None:
                    payload.unlink()
                else:
                    # link is exclusive: a later same-named backup is never overwritten.
                    if original.exists():
                        if not os.path.samefile(original,payload):
                            raise _failure('备份原位置出现新文件，已保留隔离件等待核对。')
                    else:
                        os.link(payload,original)
                    payload.unlink()
            elif operation is None and not _matches(original,record):
                raise _failure('原备份及隔离件均无法确认，请维护者核对。')
            journal.unlink()
            _sync_directory(root)


@contextmanager
def recoverable_delete(*, actor, key, request_hash):
    with ExitStack() as stack:
        state = dict(actor=actor.pk,key=key,request_hash=request_hash,stack=stack,locked=False,journals=set())
        token = _current.set(state)
        try:
            yield
        finally:
            # The caller's DB atomic block has exited before this point. A DB
            # outage leaves journal+payload intact; a retry can recover them.
            try:
                try: recover_pending(include_current=True)
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    raise _failure('删除恢复尚未完成，请保留原请求并重试。') from exc
            finally: _current.reset(token)


def remove_or_stage(path, result):
    state = _current.get()
    if state is None:
        path.unlink()
        return
    ident = uuid.uuid4().hex
    root = path.parent
    payload = root/('.delete-'+ident+'.payload')
    journal = root/('.delete-'+ident+'.json')
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''): digest.update(block)
    record = dict(actor=state['actor'], key=state['key'],request_hash=state['request_hash'],name=path.name,payload=payload.name,sha256=digest.hexdigest(),size=path.stat().st_size,result=result)
    with journal.open('x',encoding='utf-8') as out:
        json.dump(record,out,ensure_ascii=False); out.flush(); os.fsync(out.fileno())
    state['journals'].add(journal)
    _sync_directory(root)
    path.rename(payload)
    _sync_directory(root)
