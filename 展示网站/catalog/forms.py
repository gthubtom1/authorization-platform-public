import io
import warnings
from urllib.parse import urlsplit
from django import forms
from PIL import Image, ImageOps, UnidentifiedImageError
from .models import Category, Product, SiteSettings


def web_url(value):
    if not value:
        return value
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise forms.ValidationError('请填写完整的 http:// 或 https:// 网址，不要包含账号或密码。')
    return value


class MultipleInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class UploadField(forms.FileField):
    widget = MultipleInput

    def clean(self, data, initial=None):
        return [super(UploadField, self).clean(x, initial) for x in (data or [])]


def prepare_image(upload):
    if upload.size > 8 * 1024 * 1024:
        raise forms.ValidationError(f'“{upload.name}”超过8MB，请压缩后重新选择。')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(upload) as source:
                if source.format not in ('JPEG', 'PNG', 'WEBP'):
                    raise forms.ValidationError('图片只支持 JPG、PNG、WebP，不支持动图或 SVG。')
                if source.width * source.height > 16_000_000:
                    raise forms.ValidationError('单张图片不能超过1600万像素。')
                source.load()
                im = ImageOps.exif_transpose(source).convert('RGB')
                im.thumbnail((2560, 2560))
                output = io.BytesIO()
                im.save(output, 'WEBP', quality=90, method=4)
                return output.getvalue()
    except forms.ValidationError:
        raise
    except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise forms.ValidationError(f'“{upload.name}”不是可读取的图片，请重新选择。')


class ProductForm(forms.ModelForm):
    revision = forms.IntegerField(widget=forms.HiddenInput(), min_value=0, initial=0)
    uploads = UploadField(label='上传图片', required=False, widget=MultipleInput(attrs={'accept': 'image/png,image/jpeg,image/webp', 'id': 'imageUploads'}))
    image_layout = forms.CharField(required=False, widget=forms.HiddenInput())
    images_managed = forms.BooleanField(required=False, widget=forms.HiddenInput())
    cover = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'download_url', 'purchase_url', 'position', 'status']
        widgets = {'description': forms.Textarea(attrs={'rows': 10, 'placeholder': '介绍软件功能与使用方式，可分段填写。'}), 'download_url': forms.URLInput(attrs={'placeholder': 'https://你的文件域名/software.zip'}), 'purchase_url': forms.URLInput(attrs={'placeholder': 'https://你的售卡网站/商品地址'})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields['revision'].initial = self.instance.revision
            existing = list(self.instance.images.all())
            self.fields['image_layout'].initial = ','.join(f'e{x.pk}' for x in existing)
            cover = next((x for x in existing if x.is_cover), existing[0] if existing else None)
            self.fields['cover'].initial = f'e{cover.pk}' if cover else ''
        self.prepared = []
        self.layout = []
        self.cover_key = ''

    def clean(self):
        cleaned = super().clean()
        for field in ('download_url', 'purchase_url'):
            if field in cleaned:
                try:
                    cleaned[field] = web_url(cleaned[field])
                except forms.ValidationError as e:
                    self.add_error(field, e)
        uploads = cleaned.get('uploads', [])
        if len(uploads) > 12:
            self.add_error('uploads', '一次最多上传12张图片。')
            return cleaned
        for upload in uploads:
            try:
                self.prepared.append(prepare_image(upload))
            except forms.ValidationError as e:
                self.add_error('uploads', e)
        existing_order = [f'e{x.id}' for x in self.instance.images.all()] if self.instance.pk else []
        existing = set(existing_order)
        new_order = [f'n{i}' for i in range(len(uploads))]
        new = set(new_order)
        raw = cleaned.get('image_layout', '')
        self.layout = (raw.split(',') if raw else []) if cleaned.get('images_managed') else existing_order + new_order
        if len(self.layout) != len(set(self.layout)) or any(x not in existing | new for x in self.layout) or not new.issubset(set(self.layout)):
            self.add_error('uploads', '图片列表有变化，请重新打开编辑页再试。')
        if len(self.layout) > 12:
            self.add_error('uploads', '每款软件最多保留12张图片。')
        self.cover_key = cleaned.get('cover') or (self.layout[0] if self.layout else '')
        if self.cover_key and self.cover_key not in self.layout:
            self.add_error('uploads', '封面已被移除，请重新指定封面。')
        if cleaned.get('status') == Product.LIVE:
            if not cleaned.get('download_url'):
                self.add_error('download_url', '上架前请填写下载链接。')
            if not cleaned.get('purchase_url'):
                self.add_error('purchase_url', '上架前请填写购买网址。')
            if not self.layout:
                self.add_error('uploads', '上架前请至少上传一张图片。')
            if cleaned.get('category') and not cleaned['category'].visible:
                self.add_error('category', '该分类已隐藏，先显示分类或改存草稿。')
        return cleaned


class CategoryForm(forms.ModelForm):
    revision = forms.IntegerField(widget=forms.HiddenInput(), min_value=0, initial=0)

    class Meta:
        model = Category
        fields = ['name', 'position', 'visible']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields['revision'].initial = self.instance.revision


class SiteForm(forms.ModelForm):
    revision = forms.IntegerField(widget=forms.HiddenInput())

    class Meta:
        model = SiteSettings
        fields = ['name', 'tagline', 'footer', 'page_size']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['revision'].initial = self.instance.revision
