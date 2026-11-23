from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("releases", "0004_external_download_url"),
    ]

    operations = [
        migrations.AlterField(
            model_name="releaseoperation",
            name="action",
            field=models.CharField(
                choices=[
                    ("upload", "上传"),
                    ("publish", "发布"),
                    ("publish_link", "发布网盘地址"),
                    ("withdraw", "撤回"),
                    ("discard", "丢弃"),
                    ("delete_package", "删除安装包"),
                    ("update_link", "修改网盘地址"),
                ],
                max_length=16,
            ),
        ),
    ]
