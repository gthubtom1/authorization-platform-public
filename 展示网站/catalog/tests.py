import io
import tempfile
from pathlib import Path
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from PIL import Image
from .models import Category, Product, ProductImage, SiteSettings


def upload(name='picture.png', color='red'):
    output = io.BytesIO()
    Image.new('RGB', (100, 60), color).save(output, 'PNG')
    return SimpleUploadedFile(name, output.getvalue(), content_type='image/png')


class CatalogTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        setting = override_settings(MEDIA_ROOT=self.temp.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.admin = get_user_model().objects.create_user('owner', password='a-long-test-password', is_staff=True)
        self.category = Category.objects.create(name='英雄联盟')
        self.private = Category.objects.create(name='隐藏分类', visible=False)
        self.product = Product.objects.create(name='完整软件', category=self.category, description='第一段\n\n' + '完整介绍' * 200, download_url='https://files.example.com/a.zip', purchase_url='https://shop.example.com/a', status='live')
        self.picture = ProductImage.objects.create(product=self.product, file=upload(), is_cover=True)

    def log_in(self):
        self.client.force_login(self.admin)

    def body(self, product=None, **kwargs):
        p = product or self.product
        result = {'name': p.name, 'category': p.category_id, 'description': p.description, 'download_url': p.download_url, 'purchase_url': p.purchase_url, 'position': p.position, 'status': p.status, 'revision': p.revision, 'images_managed': '1', 'image_layout': ','.join(f'e{x.pk}' for x in p.images.all()), 'cover': f'e{p.images.first().pk}' if p.images.exists() else ''}
        result.update(kwargs)
        return result

    def test_public_visibility_and_media_access(self):
        draft = Product.objects.create(name='私人草稿', category=self.category, description='private')
        private_img = ProductImage.objects.create(product=draft, file=upload('draft.png'))
        hidden = Product.objects.create(name='分类隐藏商品', category=self.private, description='secret', status='live')
        self.assertContains(self.client.get('/'), self.product.description.split('\n\n')[1])
        self.assertNotContains(self.client.get('/'), draft.name)
        self.assertNotContains(self.client.get('/'), hidden.name)
        self.assertEqual(self.client.get(f'/image/{private_img.pk}/').status_code, 404)
        self.assertEqual(self.client.get(f'/go/{draft.pk}/download/').status_code, 404)
        response = self.client.get(f'/image/{self.picture.pk}/')
        self.assertEqual(response.status_code, 200)
        response.close()
        self.log_in()
        response = self.client.get(f'/image/{private_img.pk}/')
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_redirect_uses_software_link_not_client_destination(self):
        response = self.client.get(f'/go/{self.product.pk}/download/?url=https://evil.example')
        self.assertEqual(response.url, self.product.download_url)
        self.assertEqual(self.client.get(f'/go/{self.product.pk}/purchase/').url, self.product.purchase_url)
        Product.objects.filter(pk=self.product.pk).update(download_url='javascript:alert(1)')
        self.assertEqual(self.client.get(f'/go/{self.product.pk}/download/').status_code, 404)

    def test_search_pagination_and_html_escaped(self):
        for i in range(11):
            Product.objects.create(name=f'软件{i}', category=self.category, description='demo', status='live')
        self.assertEqual(len(self.client.get('/').context['cards']), 8)
        self.assertEqual(len(self.client.get('/?page=2').context['cards']), 4)
        self.assertEqual(self.client.get('/?category=invalid').status_code, 302)
        self.assertEqual(len(self.client.get('/?q=完整软件').context['cards']), 1)
        Product.objects.filter(pk=self.product.pk).update(name='<img src=x onerror=alert(1)>')
        self.assertNotContains(self.client.get('/'), '<img src=x onerror=alert(1)>')

    def test_all_management_requires_staff_and_csrf(self):
        for url in ['/manage/', '/manage/products/new/', '/manage/categories/', '/manage/settings/', f'/manage/products/{self.product.pk}/preview/']:
            self.assertEqual(self.client.get(url).status_code, 302)
        user = get_user_model().objects.create_user('regular')
        self.client.force_login(user)
        self.assertEqual(self.client.get('/manage/').status_code, 403)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.admin)
        self.assertEqual(csrf.post(f'/manage/products/{self.product.pk}/action/', {'action': 'delete'}).status_code, 403)
        self.assertEqual(csrf.post('/manage/logout/').status_code, 403)

    def test_create_upload_reencode_cover_and_reorder(self):
        self.log_in()
        body = self.body(name='新软件', revision=0, image_layout='n1,n0', cover='n1', uploads=[upload('first.png', 'red'), upload('second.png', 'blue')])
        response = self.client.post('/manage/products/new/', body)
        self.assertEqual(response.status_code, 302)
        product = Product.objects.get(name='新软件')
        pictures = list(product.images.all())
        self.assertTrue(pictures[0].is_cover)
        with Image.open(pictures[0].file.path) as image:
            self.assertEqual(image.format, 'WEBP')
            self.assertGreater(image.getpixel((1, 1))[2], 200)
        body = self.body(product, image_layout=','.join(f'e{x.pk}' for x in reversed(pictures)), cover=f'e{pictures[1].pk}')
        self.assertEqual(self.client.post(f'/manage/products/{product.pk}/', body).status_code, 302)
        self.assertEqual(product.images.first().pk, pictures[1].pk)

    def test_publish_validation_and_all_images_can_be_removed_in_draft(self):
        self.log_in()
        response = self.client.post('/manage/products/new/', self.body(name='缺图软件', revision=0, image_layout='', cover='', download_url='javascript:bad'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '至少上传一张')
        self.assertFalse(Product.objects.filter(name='缺图软件').exists())
        body = self.body(status='draft', image_layout='', cover='')
        self.assertEqual(self.client.post(f'/manage/products/{self.product.pk}/', body).status_code, 302)
        self.assertEqual(self.product.images.count(), 0)

    def test_foreign_image_reference_rejected(self):
        self.log_in()
        other = Product.objects.create(name='其他', category=self.category, description='other')
        photo = ProductImage.objects.create(product=other, file=upload())
        result = self.client.post(f'/manage/products/{self.product.pk}/', self.body(image_layout=f'e{photo.pk}', cover=f'e{photo.pk}'))
        self.assertEqual(result.status_code, 200)
        self.assertTrue(ProductImage.objects.filter(pk=self.picture.pk).exists())

    def test_fake_svg_and_large_image_rejected_without_product(self):
        self.log_in()
        svg = SimpleUploadedFile('x.png', b'<svg onload="alert(1)"></svg>', content_type='image/png')
        response = self.client.post('/manage/products/new/', self.body(name='坏图软件', revision=0, uploads=[svg], image_layout='n0', cover='n0'))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Product.objects.filter(name='坏图软件').exists())

    def test_stale_product_write_preserves_newer_data_and_images(self):
        self.log_in()
        body = self.body(name='旧页面覆盖')
        Product.objects.filter(pk=self.product.pk).update(name='较新修改', revision=2)
        result = self.client.post(f'/manage/products/{self.product.pk}/', body)
        self.assertEqual(result.status_code, 409)
        self.product.refresh_from_db()
        self.assertEqual(self.product.name, '较新修改')
        self.assertTrue(self.product.images.exists())

    def test_soft_delete_restore_and_hidden_media(self):
        self.log_in()
        result = self.client.post(f'/manage/products/{self.product.pk}/action/', {'action': 'delete', 'revision': 1})
        self.assertEqual(result.status_code, 302)
        public = Client()
        self.assertEqual(public.get(f'/image/{self.picture.pk}/').status_code, 404)
        self.assertEqual(public.get(f'/go/{self.product.pk}/purchase/').status_code, 404)
        self.client.post(f'/manage/products/{self.product.pk}/action/', {'action': 'restore', 'revision': 2})
        self.product.refresh_from_db()
        self.assertEqual(self.product.status, 'draft')
        self.assertFalse(self.product.deleted)
        self.assertTrue(self.product.images.exists())

    def test_delete_category_requires_transfer_and_retains_products(self):
        self.log_in()
        self.client.post(f'/manage/categories/{self.category.pk}/delete/', {'revision': 1})
        self.assertTrue(Category.objects.filter(pk=self.category.pk).exists())
        self.client.post(f'/manage/categories/{self.category.pk}/delete/', {'revision': 1, 'target': self.private.pk})
        self.product.refresh_from_db()
        self.assertEqual(self.product.category_id, self.private.pk)
        self.assertEqual(Client().get(f'/go/{self.product.pk}/download/').status_code, 404)

    def test_duplicate_category_and_stale_settings(self):
        self.log_in()
        response = self.client.post('/manage/categories/new/', {'name': self.category.name, 'position': 1, 'visible': 'on', 'revision': 0})
        self.assertEqual(response.status_code, 200)
        site = SiteSettings.current()
        body = {'name': '新名字', 'tagline': '', 'footer': '', 'page_size': 8, 'revision': site.revision}
        self.assertEqual(self.client.post('/manage/settings/', body).status_code, 302)
        self.assertEqual(self.client.post('/manage/settings/', body).status_code, 409)

    def test_login_budget_counts_failures_and_returns_429(self):
        for i in range(30):
            response = self.client.post('/manage/login/', {'username': 'owner', 'password': 'wrong'})
            self.assertEqual(response.status_code, 200)
        result = self.client.post('/manage/login/', {'username': 'owner', 'password': 'wrong'})
        self.assertEqual(result.status_code, 429)

    def test_storage_failure_rolls_back_metadata(self):
        self.log_in()
        body = self.body(name='不该保存', uploads=[upload()], image_layout=f'e{self.picture.pk},n0', cover=f'e{self.picture.pk}')
        with patch('django.core.files.storage.FileSystemStorage._save', side_effect=OSError('full')):
            result = self.client.post(f'/manage/products/{self.product.pk}/', body)
        self.assertEqual(result.status_code, 503)
        self.product.refresh_from_db()
        self.assertEqual(self.product.name, '完整软件')

    def test_image_arrows_are_inside_image_and_full_text_no_collapse(self):
        response = self.client.get('/')
        self.assertNotContains(response, '展开完整')
        self.assertNotContains(response, 'gallery-footer')
        self.assertContains(response, self.product.description.split('\n\n')[-1])

    def test_invalid_integer_parameters_do_not_raise(self):
        self.log_in()
        for value in ['²', '①', '9' * 5000, '-1', '0', '9' * 30]:
            with self.subTest(value=value[:20]):
                from urllib.parse import urlencode
                self.assertEqual(self.client.get('/?' + urlencode({'category': value})).status_code, 302)
                self.assertEqual(self.client.post(f'/manage/products/{self.product.pk}/action/', {'action': 'offline', 'revision': value}).status_code, 302)
                self.assertEqual(self.client.post(f'/manage/categories/{self.category.pk}/delete/', {'target': value, 'revision': self.category.revision}).status_code, 200)
        self.product.refresh_from_db()
        self.assertEqual(self.product.status, 'live')
        self.assertTrue(Category.objects.filter(pk=self.category.pk).exists())

    def test_without_js_new_upload_appends_in_selection_order(self):
        self.log_in()
        body = self.body(name='无脚本新软件', revision=0, image_layout='', cover='', uploads=[upload()])
        body.pop('images_managed')
        self.assertEqual(self.client.post('/manage/products/new/', body).status_code, 302)
        product = Product.objects.get(name='无脚本新软件')
        self.assertEqual(product.images.count(), 1)
        self.assertTrue(product.images.first().is_cover)

    def test_without_js_edit_upload_retains_existing_and_appends(self):
        self.log_in()
        body = self.body(uploads=[upload()])
        body.pop('images_managed')
        self.assertEqual(self.client.post(f'/manage/products/{self.product.pk}/', body).status_code, 302)
        self.assertEqual(self.product.images.count(), 2)
        self.assertEqual(self.product.images.first().pk, self.picture.pk)
        self.assertTrue(self.product.images.first().is_cover)
