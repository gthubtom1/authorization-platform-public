import hashlib
import ipaddress
import json
import os
import re
import uuid
from datetime import timedelta
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from .models import Blob, Budget, Event, Item, Operation, Upload
from .storage import Busy, blob_path, checked_path, free_space, hash_file, part_path, site_lock, unlink, root

ALLOWED_EXTENSIONS = ('.exe', '.msi', '.zip', '.7z', '.rar', '.tar', '.gz', '.xz', '.bz2', '.dmg', '.pkg', '.apk', '.deb', '.rpm', '.appimage')


def uuid_value(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise Busy('请求标识不正确。')


def integer(value, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 2**53 - 1:
        raise Busy('文件大小或进度不正确。')
    return value


def request_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()


def client_ip(request):
    addr = request.META.get('REMOTE_ADDR', '')
    try:
        parsed = ipaddress.ip_address(addr)
        if settings.TRUST_PROXY and parsed.is_loopback:
            return str(ipaddress.ip_address(request.META.get('HTTP_X_REAL_IP', addr)))
        return str(parsed)
    except ValueError:
        return 'unknown'


def allowance(request, category, limit, seconds, global_limit=None):
    now = timezone.now()
    ip = client_ip(request)
    keys = [(category + ':' + hashlib.sha256(ip.encode()).hexdigest()[:40], limit)]
    if global_limit:
        keys.append((category + ':global', global_limit))
    with site_lock(namespace='rate'), transaction.atomic():
        for key, cap in keys:
            b, _ = Budget.objects.get_or_create(key=key, defaults={'until': now + timedelta(seconds=seconds)})
            if b.until <= now:
                b.count = 0
                b.until = now + timedelta(seconds=seconds)
            if b.count >= cap:
                return False
            b.count += 1
            b.save()
    return True


def audit(user, action, item=None):
    Event.objects.create(actor=user.get_username()[:150], action=action, item_ref=str(item.id) if item else '')


def clean_name(value, max_length=160):
    if not isinstance(value, str) or len(value.strip()) > max_length or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Busy('名称太长或包含不可用字符。')
    return value.strip()


def clean_filename(value):
    name = clean_name(value, 240)
    if not name or any(c in name for c in '/\\') or name in ('.', '..') or not name.lower().endswith(ALLOWED_EXTENSIONS):
        raise Busy('请选择安装包或压缩文件，例如EXE、MSI、ZIP、7Z。')
    return name


def maintenance():
    # Caller owns the site lock. Safe to repeat after an interrupted request.
    cutoff = timezone.now() - timedelta(hours=24)
    Upload.objects.filter(status='uploading', touched__lt=cutoff).update(status='expired')
    active = set(str(x) for x in Upload.objects.filter(status='uploading').values_list('id', flat=True))
    for p in root().glob('*.part'):
        if p.stem not in active:
            unlink(p)
    retained = set(str(x) for x in Blob.objects.filter(removed=False, item__deleted=False).values_list('id', flat=True)) | active
    for p in root().glob('*.bin'):
        if p.stem not in retained:
            unlink(p)


def ensure_space(needed, exclude=None):
    qs = Upload.objects.filter(status='uploading')
    if exclude:
        qs = qs.exclude(id=exclude)
    pending = sum(max(0, total - got) for total, got in qs.values_list('size', 'received'))
    if needed + pending + settings.SPACE_RESERVE > free_space():
        raise Busy('剩余磁盘空间不足，请先清理历史文件或扩容后重试。', 507)


def upload_payload(u):
    return {'id': str(u.id), 'status': u.status, 'received': u.received, 'size': u.size,
            'fingerprint': u.fingerprint, 'filename': u.filename,
            'item_id': str(u.result_id) if u.result_id else None}


def owned_upload(user, ident):
    try:
        return Upload.objects.get(id=ident, owner=user)
    except Upload.DoesNotExist:
        raise Busy('上传任务不存在或不属于当前账号。', 404)


def begin_upload(user, data):
    key = uuid_value(data.get('key'))
    filename = clean_filename(data.get('filename'))
    name = clean_name(data.get('name', ''))
    size = integer(data.get('size'), 1)
    fingerprint = data.get('fingerprint', '')
    if not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint):
        raise Busy('文件指纹不正确，请重新选择文件。')
    target_id = uuid_value(data['target']) if data.get('target') else None
    revision = integer(data.get('revision'), 1) if target_id else None
    normalized = {'name': name, 'filename': filename, 'size': size, 'fingerprint': fingerprint, 'target': str(target_id) if target_id else None, 'revision': revision}
    digest = request_hash(normalized)
    with site_lock():
        maintenance()
        old = Upload.objects.filter(key=key).first()
        if old:
            if old.owner_id != user.id or old.request_hash != digest:
                raise Busy('同一上传请求不能更换文件，请取消后重新上传。', 409)
            return upload_payload(old)
        target = None
        if target_id:
            target = Item.objects.filter(id=target_id, deleted=False).first()
            if not target:
                raise Busy('软件不存在或已删除。', 404)
            if target.revision != revision:
                raise Busy('文件已在其他窗口改变，请刷新后重试。', 409)
        if Upload.objects.filter(owner=user, status='uploading').count() >= 3:
            raise Busy('同时最多保留3个上传任务，请先完成或取消已有任务。', 409)
        ensure_space(size)
        with transaction.atomic():
            u = Upload.objects.create(owner=user, key=key, request_hash=digest, name=name, filename=filename, size=size, fingerprint=fingerprint, target=target, expected_revision=revision)
        return upload_payload(u)


def accept_chunk(user, upload_id, offset, content):
    offset = integer(offset)
    if not content or len(content) > settings.CHUNK_BYTES:
        raise Busy('分块大小不正确。')
    with site_lock():
        u = owned_upload(user, upload_id)
        if u.status != 'uploading' or u.touched < timezone.now() - timedelta(hours=24):
            raise Busy('上传任务已结束或过期，请重新上传。', 409)
        if offset > u.received or offset + len(content) > u.size:
            raise Busy('上传进度不一致，请读取任务进度后继续。', 409)
        p = checked_path(part_path(u.id))
        if offset < u.received:
            if offset + len(content) > u.received or not p.exists():
                raise Busy('分块进度不一致。', 409)
            with p.open('rb') as f:
                f.seek(offset)
                if f.read(len(content)) != content:
                    raise Busy('重试的文件内容不一致，请重新选择原文件。', 409)
            u.touched = timezone.now()
            u.save(update_fields=['touched'])
            return upload_payload(u)
        # If a prior crash wrote bytes without recording offset, discard that unacknowledged tail.
        if not p.exists() and u.received:
            raise Busy('上传暂存文件缺失，请取消后重新上传。', 409)
        with p.open('r+b' if p.exists() else 'w+b') as f:
            if os.fstat(f.fileno()).st_size < u.received:
                raise Busy('上传暂存文件不完整，请重新上传。', 409)
            f.truncate(u.received)
            f.flush()
            os.fsync(f.fileno())
            ensure_space(u.size - u.received, exclude=u.id)
            f.seek(u.received)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        u.received += len(content)
        u.touched = timezone.now()
        u.save(update_fields=['received', 'touched'])
        return upload_payload(u)


def fingerprint_path(path, size):
    parts = bytearray()
    with checked_path(path).open('rb') as f:
        for part in iter(lambda: f.read(settings.CHUNK_BYTES), b''):
            parts.extend(hashlib.sha256(part).digest())
    return hashlib.sha256(parts + str(size).encode()).hexdigest()


def finish_upload(user, upload_id):
    with site_lock():
        u = owned_upload(user, upload_id)
        if u.status == 'done':
            return upload_payload(u)
        if u.status != 'uploading' or u.received != u.size or u.touched < timezone.now() - timedelta(hours=24):
            raise Busy('文件尚未上传完整，或任务已取消。', 409)
        destination = checked_path(blob_path(u.id))
        p = checked_path(part_path(u.id))
        if not p.exists() and destination.exists():
            # A previous process may have died after rename but before DB commit.
            p = destination
        if not p.exists() or p.stat().st_size != u.size:
            raise Busy('上传文件不完整，请重新上传。', 409)
        if fingerprint_path(p, u.size) != u.fingerprint:
            raise Busy('文件与最初选择的文件不一致，请重新上传。', 409)
        digest = hash_file(p)
        blob_id = u.id
        # Copy-free rename on the same volume; recoverable if the DB transaction fails.
        with transaction.atomic():
            if u.target_id:
                item = Item.objects.get(id=u.target_id)
                if item.deleted or item.revision != u.expected_revision:
                    raise Busy('文件已在其他窗口改变，请取消本次更新并刷新。', 409)
            else:
                item = Item.objects.create(name=u.name)
            if p != destination:
                os.replace(p, destination)
            try:
                blob = Blob.objects.create(id=blob_id, item=item, filename=u.filename, size=u.size, sha256=digest)
                item.previous_id = item.current_id
                item.current = blob
                item.revision += 1
                item.updated = timezone.now()
                item.save()
                u.status = 'done'
                u.result = item
                u.save(update_fields=['status', 'result'])
                audit(user, 'file.replace' if u.target_id else 'file.create', item)
            except Exception:
                if p != destination:
                    os.replace(destination, p)
                raise
        return upload_payload(u)


def cancel_upload(user, upload_id):
    with site_lock(), transaction.atomic():
        u = owned_upload(user, upload_id)
        if u.status == 'done':
            raise Busy('上传已完成，请刷新列表查看结果。', 409)
        u.status = 'cancelled'
        u.save(update_fields=['status'])
        unlink(part_path(u.id))
        return upload_payload(u)


def action(user, data):
    key = uuid_value(data.get('key'))
    verb = data.get('action')
    if verb not in ['pause', 'resume', 'delete', 'rename', 'restore', 'clean']:
        raise Busy('操作不正确。')
    rows = data.get('items')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20 or (verb in ['rename', 'restore', 'clean'] and len(rows) != 1):
        raise Busy('请选择本页需要处理的软件。')
    targets = []
    for row in rows:
        if not isinstance(row, dict):
            raise Busy('选择不正确。')
        targets.append((uuid_value(row.get('id')), integer(row.get('revision'), 1)))
    if len(set(x[0] for x in targets)) != len(targets):
        raise Busy('选择中有重复软件。')
    name = clean_name(data.get('name', '')) if verb == 'rename' else ''
    digest = request_hash({'action': verb, 'items': [(str(i), r) for i, r in targets], 'name': name})
    with site_lock():
        maintenance()
        old = Operation.objects.filter(key=key).first()
        if old:
            if old.owner_id != user.id or old.request_hash != digest:
                raise Busy('重试请求与原操作不一致。', 409)
            return old.result
        with transaction.atomic():
            items = []
            for ident, revision in targets:
                item = Item.objects.filter(id=ident, deleted=False).first()
                if not item or item.revision != revision:
                    raise Busy('所选文件已变化，请刷新后重新选择。', 409)
                items.append(item)
            for item in items:
                if verb == 'pause':
                    item.paused = True
                elif verb == 'resume':
                    item.paused = False
                elif verb == 'delete':
                    item.deleted = True
                    Upload.objects.filter(target=item, status='uploading').update(status='cancelled')
                    Blob.objects.filter(item=item).update(removed=True)
                elif verb == 'rename':
                    item.name = name
                elif verb == 'restore':
                    if not item.previous_id or item.previous.removed or not blob_path(item.previous_id).is_file():
                        raise Busy('没有可恢复的上一次文件。', 409)
                    item.current_id, item.previous_id = item.previous_id, item.current_id
                elif verb == 'clean':
                    Blob.objects.filter(item=item, removed=False, created__lt=timezone.now() - timedelta(hours=24)).exclude(id__in=[item.current_id, item.previous_id]).update(removed=True)
                item.revision += 1
                item.updated = timezone.now()
                item.save()
                audit(user, 'file.' + verb, item)
            result = {'count': len(items), 'message': '操作已完成。'}
            Operation.objects.create(key=key, owner=user, request_hash=digest, result=result)
        maintenance()
        return result
