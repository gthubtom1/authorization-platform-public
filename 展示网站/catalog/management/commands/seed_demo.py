import io
import os
import uuid
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from PIL import Image, ImageDraw, ImageFont
from catalog.models import Category, Product, ProductImage, SiteSettings


def artwork(title, index, theme):
    image = Image.new('RGB', (1280, 800), '#151b20')
    draw = ImageDraw.Draw(image)
    font_path = 'C:/Windows/Fonts/msyh.ttc'
    if not os.path.exists(font_path):
        font_path = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
    def font(size):
        try:
            return ImageFont.truetype(font_path, size)
        except OSError:
            return ImageFont.load_default(size=size)
    draw.rectangle((0, 0, 1280, 64), fill='#262f36')
    draw.text((32, 17), title, fill='#d8e1e7', font=font(22))
    draw.rectangle((0, 64, 270, 800), fill='#1b242b')
    draw.text((32, 110), '我的工作台', fill=theme, font=font(30))
    for i, name in enumerate(['方案管理', '历史记录', '本地备份', '偏好设置']):
        y = 190 + i * 88
        if i == index % 3:
            draw.rounded_rectangle((20, y - 10, 248, y + 50), 8, fill='#35434a')
        draw.text((44, y), name, fill=theme if i == index % 3 else '#c2cdd5', font=font(24))
    draw.text((330, 130), ['日常配置', '历史方案', '配置预览'][index % 3], fill='#eef2f5', font=font(42))
    draw.text((332, 208), '为不同场景保存自己的设置', fill='#a3b2bd', font=font(24))
    for i, (name, value) in enumerate([('显示模式', '无边框窗口'), ('画面分辨率', '2560 × 1440'), ('画面设置', '个人方案'), ('自动备份', '已开启')]):
        y = 310 + i * 92
        draw.text((332, y + 10), name, fill='#c0cdd6', font=font(25))
        draw.rounded_rectangle((740, y, 1190, y + 58), 8, fill='#2a353e')
        draw.text((764, y + 10), value, fill=theme if i == 3 else '#d9e1e7', font=font(24))
    draw.text((960, 744), f'示意界面 {index + 1}', fill='#a3b2bd', font=font(20))
    out = io.BytesIO()
    image.save(out, 'WEBP', quality=90)
    return out.getvalue()


class Command(BaseCommand):
    help = '仅向空的本地验收环境填入示例，不创建管理员。'

    def handle(self, *args, **options):
        if os.environ.get('SITE_ALLOW_DEMO') != '1':
            raise CommandError('只允许显式设置 SITE_ALLOW_DEMO=1 的本地验收环境。')
        if Product.objects.exists() or Category.objects.exists():
            raise CommandError('数据库已有内容，拒绝覆盖或混入示例。')
        names = ['联盟画面配置管理器', '训练笔记与对局复盘', '回放文件整理工具', '阵容与英雄备忘录', '游戏录制文件助手', '常用配置备份工具', '训练计划清单', '游戏截图归档', '设备设置备忘录', '英雄资料收藏夹', '准星配置收藏夹', '地图训练笔记', '桌面文件整理助手']
        descriptions = [
            '把分辨率、窗口模式、画面质量和常用按键配置整理在一起。为日常排位、训练与录制分别保存方案，需要时切换使用。\n\n支持导入、导出与本地备份。更换电脑或重新安装后，可以找回自己熟悉的配置，减少重复设置。',
            '把每次训练遇到的问题、对局中的关键节点和下一次要练习的内容，记录到同一个地方。可以按英雄、位置和日期整理，不用在聊天记录与零散文档之间来回查找。\n\n每条记录支持填写对线思路、补刀目标、视野习惯与团战复盘，也可以附上自己的截图。训练结束后，将需要继续练习的项目加入下一次计划，逐步形成自己的复盘习惯。\n\n已有记录可以通过关键词快速查找，也支持导出备份。适合希望长期整理训练资料的玩家，以及需要按不同英雄保存笔记的用户。内容在本地管理，不需要给每一篇笔记重新选择保存位置。',
            '按日期与自定义标签整理本地文件，快速找到想重新查看的内容。支持添加备注和打开所在文件夹。',
        ]
        with transaction.atomic():
            cats = [Category.objects.create(name=x, position=i * 10) for i, x in enumerate(['英雄联盟', 'CS / 反恐精英', '其他工具'])]
            for i, name in enumerate(names):
                product = Product.objects.create(name=name, category=cats[0 if i < 10 else (1 if i < 12 else 2)], description=descriptions[min(i, 2)], download_url='https://example.com/download.zip', purchase_url='https://example.com/buy', position=i * 10, status=Product.LIVE)
                for n in range(3 if i == 0 else (2 if i == 1 else 1)):
                    p = ProductImage(product=product, position=n, is_cover=n == 0)
                    p.file.save(uuid.uuid4().hex + '.webp', ContentFile(artwork(name, n, ['#a8c392', '#a1b8dc', '#c6b48e'][i % 3])))
            site = SiteSettings.current()
            site.demo = True
            site.save()
        self.stdout.write(self.style.SUCCESS('已创建本地验收示例。生产环境不要执行此命令。'))
