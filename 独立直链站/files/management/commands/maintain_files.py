from django.core.management.base import BaseCommand
from files.services import maintenance
from files.storage import site_lock


class Command(BaseCommand):
    help = '清理过期上传及已删除文件，不清理仍保留的历史文件。'

    def handle(self, *args, **options):
        with site_lock():
            maintenance()
        self.stdout.write('MAINTENANCE_OK')
