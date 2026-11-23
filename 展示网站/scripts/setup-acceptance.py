"""Explicit local QA fixture; never called by startup or deployment."""
import json
import os
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
os.environ['SITE_DEBUG'] = '1'
os.environ['SITE_DATA_DIR'] = str(root / 'data' / 'acceptance')
os.environ['SITE_ALLOW_DEMO'] = '1'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'showcase.settings')
import django
django.setup()
from django.core.management import call_command
from django.contrib.auth import get_user_model
from catalog.models import Category

call_command('migrate', verbosity=0)
credentials = root / 'data' / 'acceptance' / 'credentials.json'
if not credentials.exists():
    password = secrets.token_urlsafe(24)
    get_user_model().objects.create_superuser('owner', password=password)
    credentials.write_text(json.dumps({'username': 'owner', 'password': password}), encoding='utf-8')
if not Category.objects.exists():
    call_command('seed_demo')
print('本地验收环境已准备。账号仅存于本地data/acceptance/credentials.json，不是生产账号。')
