"""Run in a one-off container after the service has stopped, before migrations."""
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('DJANGO_SETTINGS_MODULE','showcase.settings')
import django
django.setup()
from django.conf import settings
from django.core.management import call_command
from datetime import datetime,timezone

database=Path(settings.DATABASES['default']['NAME'])
if database.exists() and database.stat().st_size:
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    call_command('backup_site',output=str(settings.DATA_DIR/'backups'/('pre-update-'+stamp+'.zip')))
else:
    print('FIRST_INSTALL: no existing database; pre-update backup not required')
