import hashlib
import mimetypes
import time
import uuid
from functools import wraps
from pathlib import Path
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.core.files.base import ContentFile
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Q
from django.http import FileResponse, Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST
from .forms import CategoryForm, ProductForm, SiteForm, web_url
from .models import Category, LoginBudget, Product, ProductImage, SiteSettings


def staff(view):
    @never_cache
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if not request.user.is_active or not request.user.is_staff:
            return render(request, 'error.html', {'heading': '没有管理权限', 'detail': '请使用网站管理员账号登录。'}, status=403)
        return view(request, *args, **kwargs)
    return wrapped


def published():
    return Product.objects.filter(status=Product.LIVE, deleted=False, category__visible=True)


def bounded_integer(value):
    if not isinstance(value, str) or not value or len(value) > 19 or any(c < '0' or c > '9' for c in value):
        return None
    number = int(value)
    return number if number <= 2**63 - 1 else None


def card_context(items):
    cards = []
    for product in items:
        images = list(product.images.all())
        images.sort(key=lambda x: (not x.is_cover, x.position, x.id))
        cards.append({'item': product, 'pictures': images})
    return cards


def catalog(request):
    available = Category.objects.filter(visible=True).annotate(count=Count('products', filter=Q(products__status=Product.LIVE, products__deleted=False)))
    selected = request.GET.get('category', '')
    query = request.GET.get('q', '').strip()[:200]
    items = published().select_related('category').prefetch_related('images')
    category = None
    if selected:
        selected_id = bounded_integer(selected)
        category = available.filter(pk=selected_id).first() if selected_id is not None else None
        if not category:
            return redirect('catalog')
        items = items.filter(category=category)
    if query:
        items = items.filter(Q(name__icontains=query) | Q(description__icontains=query))
    config = SiteSettings.current()
    page = Paginator(items, config.page_size).get_page(request.GET.get('page'))
    from urllib.parse import urlencode
    params = {'category': selected, 'q': query}
    return render(request, 'catalog.html', {'categories': available, 'category': category, 'query': query, 'page': page, 'cards': card_context(page), 'total': published().count(), 'page_query': urlencode({k: v for k, v in params.items() if v}), 'title': '搜索结果' if query else (category.name if category else '全部软件')})


def image(request, pk):
    picture = get_object_or_404(ProductImage.objects.select_related('product__category'), pk=pk)
    if not picture.product.public and not (request.user.is_authenticated and request.user.is_active and request.user.is_staff):
        raise Http404
    try:
        response = FileResponse(picture.file.open('rb'), content_type='image/webp')
    except FileNotFoundError:
        raise Http404
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = 'private, max-age=300' if picture.product.public else 'private, no-store'
    return response


def outbound(request, pk, action):
    product = get_object_or_404(published(), pk=pk)
    if action not in ('download', 'purchase'):
        raise Http404
    url = product.download_url if action == 'download' else product.purchase_url
    from django.core.exceptions import ValidationError
    try:
        web_url(url)
    except (ValidationError, ValueError):
        url = ''
    if not url:
        return render(request, 'error.html', {'heading': '链接暂不可用', 'detail': '请稍后再试。'}, status=404)
    response = HttpResponseRedirect(url)
    response['Cache-Control'] = 'no-store'
    response['Referrer-Policy'] = 'no-referrer'
    return response


def consume_login_budget(request):
    window = int(time.time()) // 900
    # The direct peer is deliberate; no untrusted forwarded address is consumed.
    keys = [hashlib.sha256((kind + ':' + value).encode()).hexdigest() for kind, value in [('ip', request.META.get('REMOTE_ADDR', 'unknown')), ('account', request.POST.get('username', '').strip().casefold()[:180])]]
    blocked = False
    with transaction.atomic():
        for key, limit in zip(sorted(keys), [30, 30]):
            budget, _ = LoginBudget.objects.get_or_create(key=key, defaults={'window': window})
            LoginBudget.objects.filter(pk=budget.pk).exclude(window=window).update(window=window, attempts=0)
            if LoginBudget.objects.filter(pk=budget.pk, window=window, attempts__lt=limit).update(attempts=F('attempts') + 1) == 0:
                blocked = True
        if LoginBudget.objects.count() > 20000:
            LoginBudget.objects.filter(window__lt=window - 4).delete()
    return not blocked


@never_cache
def sign_in(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('products')
    form = AuthenticationForm(request, data=request.POST if request.method == 'POST' else None)
    status = 200
    if request.method == 'POST':
        if not consume_login_budget(request):
            form.add_error(None, '登录尝试过于频繁，请15分钟后再试。')
            status = 429
        elif form.is_valid():
            if form.get_user().is_staff:
                login(request, form.get_user())
                return redirect('products')
            form.add_error(None, '账号或密码不正确。')
    return render(request, 'login.html', {'form': form}, status=status)


@require_POST
def sign_out(request):
    logout(request)
    return redirect('login')


@staff
def password(request):
    form = PasswordChangeForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)
        messages.success(request, '密码已更新。')
        return redirect('products')
    return render(request, 'password.html', {'form': form, 'section': 'password'})


@staff
def products(request):
    query = request.GET.get('q', '').strip()[:200]
    mode = request.GET.get('status', '')
    items = Product.objects.filter(deleted=mode == 'deleted').select_related('category').prefetch_related('images')
    if mode in (Product.DRAFT, Product.LIVE, Product.OFFLINE):
        items = items.filter(status=mode)
    if query:
        items = items.filter(Q(name__icontains=query) | Q(category__name__icontains=query))
    page = Paginator(items, 20).get_page(request.GET.get('page'))
    from urllib.parse import urlencode
    return render(request, 'products.html', {'page': page, 'query': query, 'mode': mode, 'section': 'products', 'page_query': urlencode({'q': query, 'status': mode})})


def stale(form):
    form.add_error(None, '这条内容已在其他页面修改。请复制本次填写的内容，重新打开页面后再保存。')


@staff
def product_edit(request, pk=None):
    instance = get_object_or_404(Product, pk=pk, deleted=False) if pk else Product()
    form = ProductForm(request.POST if request.method == 'POST' else None, request.FILES or None, instance=instance)
    status = 200
    stored_files = []
    if request.method == 'POST' and form.is_valid():
        try:
            with transaction.atomic():
                if pk:
                    values = {key: form.cleaned_data[key] for key in ProductForm.Meta.fields}
                    values.update(revision=F('revision') + 1)
                    from django.utils import timezone
                    values['updated_at'] = timezone.now()
                    if not Product.objects.filter(pk=pk, deleted=False, revision=form.cleaned_data['revision']).update(**values):
                        stale(form)
                        status = 409
                    else:
                        instance.refresh_from_db()
                else:
                    instance = form.save()
                if status != 409:
                    current = {f'e{x.id}': x for x in instance.images.all()}
                    for i, data in enumerate(form.prepared):
                        picture = ProductImage(product=instance)
                        picture.file.save(uuid.uuid4().hex + '.webp', ContentFile(data), save=False)
                        stored_files.append(picture.file.name)
                        current[f'n{i}'] = picture
                    for index, key in enumerate(form.layout):
                        picture = current[key]
                        picture.position = index
                        picture.is_cover = key == form.cover_key
                        picture.save()
                    instance.images.exclude(pk__in=[current[key].pk for key in form.layout]).delete()
            if status != 409:
                messages.success(request, '软件已保存。' if instance.status != Product.LIVE else '已保存并上架。')
                return redirect('product_edit', pk=instance.pk)
        except (OSError, IntegrityError):
            from django.core.files.storage import default_storage
            for file in stored_files:
                try:
                    default_storage.delete(file)
                except OSError:
                    pass
            form.add_error(None, '保存没有完成，请检查磁盘空间后重试。')
            status = 503
    pictures = list(instance.images.all()) if instance.pk else []
    return render(request, 'product_edit.html', {'form': form, 'item': instance, 'pictures': pictures, 'section': 'products', 'upload_reselect': request.method == 'POST' and bool(request.FILES)}, status=status)


@staff
def product_preview(request, pk):
    product = get_object_or_404(Product.objects.select_related('category').prefetch_related('images'), pk=pk, deleted=False)
    return render(request, 'preview.html', {'cards': card_context([product]), 'item': product})


@staff
@require_POST
def product_action(request, pk):
    product = get_object_or_404(Product, pk=pk)
    action = request.POST.get('action')
    updates = {'revision': F('revision') + 1}
    if action == 'offline':
        updates['status'] = Product.OFFLINE
    elif action == 'delete':
        updates.update(deleted=True, status=Product.OFFLINE)
    elif action == 'restore':
        updates.update(deleted=False, status=Product.DRAFT)
    else:
        raise Http404
    revision = bounded_integer(request.POST.get('revision'))
    changed = Product.objects.filter(pk=pk, revision=revision if revision is not None else -1).update(**updates)
    if changed:
        messages.success(request, {'offline': '软件已下架。', 'delete': '已移入回收站。', 'restore': '已恢复为草稿。'}[action])
    else:
        messages.error(request, '内容已变更，本次没有操作，请刷新后再试。')
    return redirect('products')


@staff
def categories(request):
    return render(request, 'categories.html', {'items': Category.objects.annotate(count=Count('products', filter=Q(products__deleted=False))), 'section': 'categories'})


@staff
def category_edit(request, pk=None):
    instance = get_object_or_404(Category, pk=pk) if pk else Category()
    form = CategoryForm(request.POST if request.method == 'POST' else None, instance=instance)
    status = 200
    if request.method == 'POST' and form.is_valid():
        try:
            with transaction.atomic():
                if pk:
                    changed = Category.objects.filter(pk=pk, revision=form.cleaned_data['revision']).update(name=form.cleaned_data['name'], position=form.cleaned_data['position'], visible=form.cleaned_data['visible'], revision=F('revision') + 1)
                    if not changed:
                        stale(form)
                        status = 409
                else:
                    form.save()
            if status == 200:
                messages.success(request, '分类已保存。')
                return redirect('categories')
        except IntegrityError:
            form.add_error('name', '该分类名称已存在。')
    return render(request, 'category_edit.html', {'form': form, 'item': instance, 'section': 'categories'}, status=status)


@staff
def category_delete(request, pk):
    item = get_object_or_404(Category, pk=pk)
    error = ''
    if request.method == 'POST':
        target_id = bounded_integer(request.POST.get('target', ''))
        with transaction.atomic():
            current = Category.objects.select_for_update().get(pk=pk)
            if request.POST.get('revision') != str(current.revision):
                error = '分类已变更，请刷新后重新确认。'
            elif current.products.exists() and target_id is None:
                error = '请为该分类中的软件选择一个新分类。'
            else:
                target = Category.objects.filter(pk=target_id).exclude(pk=pk).first() if target_id is not None else None
                if current.products.exists() and not target:
                    error = '请选择一个有效的新分类。'
                else:
                    if target:
                        current.products.update(category=target, revision=F('revision') + 1)
                    current.delete()
                    messages.success(request, '分类已删除，所属软件已按选择转移。' if target else '分类已删除。')
                    return redirect('categories')
    return render(request, 'category_delete.html', {'item': item, 'count': item.products.count(), 'targets': Category.objects.exclude(pk=pk), 'error': error, 'section': 'categories'})


@staff
def site_edit(request):
    instance = SiteSettings.current()
    form = SiteForm(request.POST if request.method == 'POST' else None, instance=instance)
    status = 200
    if request.method == 'POST' and form.is_valid():
        if SiteSettings.objects.filter(pk=1, revision=form.cleaned_data['revision']).update(**{k: form.cleaned_data[k] for k in SiteForm.Meta.fields}, revision=F('revision') + 1):
            messages.success(request, '网站设置已保存。')
            return redirect('site_settings')
        stale(form)
        status = 409
    return render(request, 'settings.html', {'form': form, 'section': 'settings'}, status=status)


def health(request):
    SiteSettings.objects.exists()
    return HttpResponse('ok', content_type='text/plain')


def not_found(request, exception=None):
    return render(request, 'error.html', {'heading': '页面不存在', 'detail': '内容可能已下架或地址已更改。'}, status=404)


def server_error(request):
    return HttpResponse('网站暂时不可用，请稍后重试。', status=500, content_type='text/plain; charset=utf-8')


def csrf_failure(request, reason=''):
    return render(request, 'error.html', {'heading': '页面已过期', 'detail': '请返回原页面刷新后重试。本次操作没有提交。'}, status=403)
