from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("releases", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="release",
            name="status",
            field=models.CharField(
                choices=[("draft", "草稿"), ("published", "已发布"), ("withdrawn", "已撤回"), ("discarded", "已丢弃")],
                db_index=True,
                default="draft",
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="releaseoperation",
            name="action",
            field=models.CharField(
                choices=[("upload", "上传"), ("publish", "发布"), ("withdraw", "撤回"), ("discard", "丢弃")],
                max_length=16,
            ),
        ),
        migrations.RemoveConstraint(
            model_name="release",
            name="releases_identity_version_unique",
        ),
        migrations.AddConstraint(
            model_name="release",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status", "discarded"), _negated=True),
                fields=("software", "profile", "version", "target", "arch", "channel"),
                name="releases_identity_version_unique",
            ),
        ),
    ]
