import os
import secrets
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get('DL_DATA_DIR', BASE_DIR / 'data')).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEBUG = os.environ.get('DL_DEBUG', '0') == '1'
SECRET_KEY = os.environ.get('DL_SECRET_KEY', '')
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured('请设置独立的DL_SECRET_KEY；本地启动使用start-local.py。')
    secret = DATA_DIR / 'local-secret.txt'
    try:
        with secret.open('x', encoding='utf-8') as out:
            out.write(secrets.token_urlsafe(64))
        secret.chmod(0o600)
    except FileExistsError:
        pass
    SECRET_KEY = secret.read_text().strip()
ALLOWED_HOSTS = [x.strip() for x in os.environ.get('DL_HOSTS', 'localhost,127.0.0.1,[::1]' if DEBUG else '').split(',') if x.strip()]
if not DEBUG and (len(SECRET_KEY) < 50 or not ALLOWED_HOSTS or '*' in ALLOWED_HOSTS):
    raise ImproperlyConfigured('正式环境需要明确DL_HOSTS和至少50字符的独立站点密钥。')
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles', 'files']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware', 'files.middleware.SafeHeaders']
ROOT_URLCONF = 'directsite.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]
WSGI_APPLICATION = 'directsite.wsgi.application'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': DATA_DIR / 'site.sqlite3', 'OPTIONS': {'timeout': 30}}}
AUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'}, {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}}, {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'}, {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'}]
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_TZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
LOGIN_URL = '/manage/login/'
SESSION_COOKIE_NAME = 'directlink_session'
CSRF_COOKIE_NAME = 'directlink_csrf'
SESSION_COOKIE_AGE = 8 * 3600
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 3600 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
SILENCED_SYSTEM_CHECKS = ['security.W005', 'security.W021']
CSRF_TRUSTED_ORIGINS = [x for x in os.environ.get('DL_CSRF_ORIGINS', '').split(',') if x]
TRUST_PROXY = os.environ.get('DL_TRUST_PROXY') == '1'
if TRUST_PROXY:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
DATA_UPLOAD_MAX_MEMORY_SIZE = 9 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
CHUNK_BYTES = 8 * 1024 * 1024
SPACE_RESERVE = int(os.environ.get('DL_SPACE_RESERVE', str(256 * 1024 * 1024)))
if SPACE_RESERVE < 0:
    raise ImproperlyConfigured('DL_SPACE_RESERVE不能为负数。')
USE_ACCEL = os.environ.get('DL_USE_ACCEL') == '1'
CSRF_FAILURE_VIEW = 'files.views.csrf_failure'
