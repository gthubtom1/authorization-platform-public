from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("releases", "0003_alter_releaseoperation_action"),
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
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="release",
            name="package_name",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AlterField(
            model_name="release",
            name="package_sha256",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="release",
            name="external_download_url",
            field=models.CharField(blank=True, default="", max_length=2048),
        ),
    ]
