import functools
import json
import os
import re
from urllib.parse import urlencode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.core.paginator import Paginator
from django.db import OperationalError
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import content_disposition_header
from django.views.decorators.http import require_http_methods, require_POST
from . import services as s
from .models import Blob, Item, Upload
from .storage import Busy, blob_path, checked_path, free_space, site_lock


def root(request):
    return HttpResponse('页面不存在。', status=404)


def health(request):
    from .deployment import identity
    response = JsonResponse(identity())
    response['Cache-Control'] = 'no-store'
    return response


def managed(fn):
    @functools.wraps(fn)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_active or not request.user.is_staff:
            if '/api/' in request.path:
                return JsonResponse({'error': '请重新登录后继续。'}, status=401)
            return redirect('login')
        return fn(request, *args, **kwargs)
    return wrapped


def api(methods):
    def decorate(fn):
        @require_http_methods(methods)
        @managed
        @functools.wraps(fn)
        def wrapped(request, *args, **kwargs):
            try:
                return JsonResponse(fn(request, *args, **kwargs))
            except Busy as e:
                return JsonResponse({'error': e.message, 'definitive': True}, status=e.status)
            except (OSError, OperationalError):
                return JsonResponse({'error': '存储暂不可用，结果可能尚未确认。请保留当前任务并重试。'}, status=503)
        return wrapped
    return decorate


def body(request):
    if int(request.META.get('CONTENT_LENGTH') or 0) > 65536:
        raise Busy('请求过大。', 413)
    try:
        data = json.loads(request.body)
    except (ValueError, UnicodeError):
        raise Busy('请求格式不正确。')
    if not isinstance(data, dict):
        raise Busy('请求格式不正确。')
    return data


@require_http_methods(['GET', 'POST'])
def sign_in(request):
    error = ''
    status = 200
    if request.method == 'POST':
        if not s.allowance(request, 'login', 10, 60, global_limit=100):
            error = '尝试过于频繁，请一分钟后再试。'
            status = 429
        else:
            username = request.POST.get('username', '')[:150]
            password = request.POST.get('password', '')
            user = authenticate(request, username=username, password=password) if len(password) <= 1024 else None
            if user and user.is_active and user.is_staff:
                login(request, user)
                with site_lock():
                    s.audit(user, 'login.success')
                return redirect('index')
            error = '账号或密码不正确。'
    response = render(request, 'login.html', {'error': error}, status=status)
    if status == 429:
        response['Retry-After'] = '60'
    return response


@require_POST
def sign_out(request):
    logout(request)
    return redirect('login')


@managed
def index(request):
    q = request.GET.get('q', '').strip()[:160]
    page_size = 20 if request.GET.get('size', request.COOKIES.get('dl_rows', '10')) == '20' else 10
    rows = Item.objects.filter(deleted=False, current__isnull=False).select_related('current')
    if q:
        from django.db.models import Q
        rows = rows.filter(Q(name__icontains=q) | Q(current__filename__icontains=q))
    paginator = Paginator(rows.order_by('-updated', 'id'), page_size)
    page = paginator.get_page(request.GET.get('page', '1'))
    response = render(request, 'files.html', {'page': page, 'q': q, 'page_size': page_size,
        'blank_rows': range(page_size - len(page.object_list)) if paginator.count else [],
        'query': urlencode({'q': q, 'size': page_size}), 'chunk_size': settings.CHUNK_BYTES})
    response.set_cookie('dl_rows', str(page_size), max_age=31536000, samesite='Lax', secure=not settings.DEBUG)
    return response


@require_http_methods(['GET', 'POST'])
@managed
def site_settings(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        with site_lock():
            form.save()
            s.audit(request.user, 'password.change')
        logout(request)
        messages.success(request, '密码已修改，请使用新密码登录。')
        return redirect('login')
    return render(request, 'settings.html', {'form': form, 'free_bytes': free_space()})


@api(['POST'])
def upload_start(request):
    return s.begin_upload(request.user, body(request))


@api(['GET', 'DELETE'])
def upload_detail(request, upload_id):
    if request.method == 'DELETE':
        return s.cancel_upload(request.user, upload_id)
    with site_lock():
        s.maintenance()
        return s.upload_payload(s.owned_upload(request.user, upload_id))


@api(['POST'])
def upload_chunk(request, upload_id):
    try:
        offset = int(request.GET.get('offset', '-1'))
    except ValueError:
        raise Busy('上传进度不正确。')
    length = int(request.META.get('CONTENT_LENGTH') or 0)
    if length > settings.CHUNK_BYTES:
        raise Busy('分块过大。', 413)
    content = request.read(settings.CHUNK_BYTES + 1)
    return s.accept_chunk(request.user, upload_id, offset, content)


@api(['POST'])
def upload_finish(request, upload_id):
    return s.finish_upload(request.user, upload_id)


@api(['POST'])
def actions(request):
    return s.action(request.user, body(request))


@api(['GET'])
def details(request, item_id):
    item = Item.objects.filter(id=item_id, deleted=False).select_related('current', 'previous').first()
    if not item:
        raise Busy('软件不存在或已删除。', 404)
    current = item.current
    return {'id': str(item.id), 'name': item.name, 'title': item.title, 'revision': item.revision,
            'paused': item.paused, 'fixed': request.build_absolute_uri(reverse('fixed', args=[item.id])),
            'filename': current.filename, 'size': current.size, 'sha256': current.sha256,
            'content_url': request.build_absolute_uri(reverse('file', args=[current.id])),
            'can_restore': bool(item.previous_id and not item.previous.removed),
            'history_count': item.blobs.filter(removed=False).count()}


def download_guard(request):
    if request.method not in ['GET', 'HEAD']:
        return HttpResponse('只支持下载。', status=405)
    if not s.allowance(request, 'download', 1200, 60, global_limit=12000):
        response = HttpResponse('下载请求过于频繁，请稍后重试。', status=429)
        response['Retry-After'] = '60'
        return response
    return None


def fixed_download(request, item_id):
    try:
        if limited := download_guard(request):
            return limited
        item = Item.objects.filter(id=item_id, deleted=False, paused=False).select_related('current').first()
        if not item or not item.current_id:
            return HttpResponse('文件不存在或已暂停下载。', status=404)
        blob = item.current
        if request.method == 'GET' and request.headers.get('Range'):
            original = request.headers.get('If-Range', '')
            if not re.fullmatch(r'"[0-9a-f]{64}"', original):
                return HttpResponse('请重新开始下载，或使用已开始下载的文件地址继续。', status=409)
            blob = item.blobs.filter(sha256=original.strip('"'), removed=False).first()
            if not blob:
                return HttpResponse('原文件已清理，请重新下载。', status=410)
        response = HttpResponse(status=302)
        response['Location'] = reverse('file', args=[blob.id])
        response['Cache-Control'] = 'no-store'
        return response
    except (Busy, OperationalError, OSError):
        return HttpResponse('下载服务忙，请稍后重试。', status=503)


def file_download(request, blob_id):
    try:
        if limited := download_guard(request):
            return limited
        blob = Blob.objects.select_related('item').filter(id=blob_id, removed=False, item__deleted=False, item__paused=False).first()
        if not blob:
            return HttpResponse('文件不存在或已暂停下载。', status=404)
        p = checked_path(blob_path(blob.id))
        f = p.open('rb')
        if os.fstat(f.fileno()).st_size != blob.size:
            f.close()
            return HttpResponse('文件不完整，暂不可下载。', status=503)
        etag = '"' + blob.sha256 + '"'
        start, end, status = 0, blob.size - 1, 200
        range_header = request.headers.get('Range', '') if request.method == 'GET' else ''
        if range_header and request.headers.get('If-Range', etag) == etag:
            match = re.fullmatch(r'bytes=(\d*)-(\d*)', range_header)
            if not match or not any(match.groups()):
                f.close()
                return range_error(blob.size)
            try:
                left, right = match.groups()
                if left:
                    start = int(left)
                    end = min(int(right), end) if right else end
                else:
                    suffix = int(right)
                    if suffix <= 0:
                        raise ValueError
                    start = max(0, blob.size - suffix)
                if start > end or start >= blob.size:
                    raise ValueError
            except ValueError:
                f.close()
                return range_error(blob.size)
            status = 206
        length = end - start + 1
        if request.method == 'HEAD':
            f.close()
            response = HttpResponse(status=status)
        elif settings.USE_ACCEL:
            f.close()
            response = HttpResponse(status=200)
            response['X-Accel-Redirect'] = '/_protected_files/' + str(blob.id) + '.bin'
            # nginx handles Range itself, using the validated immutable file.
        else:
            response = StreamingHttpResponse(FileSlice(f, start, length), status=status, content_type='application/octet-stream')
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = content_disposition_header(True, blob.filename)
        response['Content-Length'] = str(length)
        response['Accept-Ranges'] = 'bytes'
        response['ETag'] = etag
        response['Cache-Control'] = 'private, no-store'
        if status == 206:
            response['Content-Range'] = f'bytes {start}-{end}/{blob.size}'
        return response
    except (Busy, OperationalError, OSError):
        return HttpResponse('下载服务忙或文件不可用，请稍后重试。', status=503)


class FileSlice:
    def __init__(self, file, offset, length):
        self.file = file
        self.file.seek(offset)
        self.remaining = length

    def __iter__(self):
        return self

    def __next__(self):
        if self.remaining <= 0:
            self.close()
            raise StopIteration
        part = self.file.read(min(256 * 1024, self.remaining))
        if not part:
            self.close()
            raise StopIteration
        self.remaining -= len(part)
        return part

    def close(self):
        self.file.close()


def range_error(size):
    response = HttpResponse('续传范围不正确。', status=416)
    response['Content-Range'] = f'bytes */{size}'
    return response


def csrf_failure(request, reason=''):
    if '/api/' in request.path:
        return JsonResponse({'error': '页面验证已过期，请刷新并重新登录。'}, status=403)
    return render(request, 'error.html', {'message': '页面验证已过期，请刷新后重试。'}, status=403)


def not_found(request, exception=None):
    return render(request, 'error.html', {'message': '页面或文件不存在。'}, status=404)


def server_error(request):
    return render(request, 'error.html', {'message': '服务暂不可用，请稍后重试。'}, status=500)
