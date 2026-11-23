from django.db import models


class SiteSettings(models.Model):
    name = models.CharField('网站名称', max_length=40, default='软件集')
    tagline = models.CharField('侧栏说明', max_length=160, blank=True, default='浏览介绍，下载适合你的软件。')
    footer = models.CharField('页脚文字', max_length=200, blank=True)
    page_size = models.PositiveSmallIntegerField('每页软件数量', default=8, choices=[(6, '6 款'), (8, '8 款'), (12, '12 款')])
    demo = models.BooleanField(default=False)
    revision = models.PositiveIntegerField(default=1)

    @classmethod
    def current(cls):
        return cls.objects.get_or_create(pk=1)[0]


class Category(models.Model):
    name = models.CharField('分类名称', max_length=60, unique=True)
    position = models.PositiveIntegerField('显示顺序', default=100)
    visible = models.BooleanField('在前台显示', default=True)
    revision = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['position', 'id']

    def __str__(self):
        return self.name


class Product(models.Model):
    DRAFT, LIVE, OFFLINE = 'draft', 'live', 'offline'
    name = models.CharField('软件名称', max_length=140)
    category = models.ForeignKey(Category, on_delete=models.PROTECT, verbose_name='所属分类', related_name='products')
    description = models.TextField('完整介绍', max_length=30000)
    download_url = models.URLField('下载直链', max_length=2000, blank=True)
    purchase_url = models.URLField('卡密购买网址', max_length=2000, blank=True)
    position = models.PositiveIntegerField('显示顺序', default=100)
    status = models.CharField('展示状态', max_length=10, choices=[(DRAFT, '草稿'), (LIVE, '已上架'), (OFFLINE, '已下架')], default=DRAFT)
    deleted = models.BooleanField(default=False)
    revision = models.PositiveIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['position', 'id']

    @property
    def public(self):
        return self.status == self.LIVE and not self.deleted and self.category.visible


class ProductImage(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='images')
    file = models.FileField(upload_to='products/')
    position = models.PositiveIntegerField(default=0)
    is_cover = models.BooleanField(default=False)
    label = models.CharField(max_length=160, blank=True)

    class Meta:
        ordering = ['position', 'id']


class LoginBudget(models.Model):
    key = models.CharField(max_length=64, unique=True)
    window = models.PositiveBigIntegerField()
    attempts = models.PositiveIntegerField(default=0)
