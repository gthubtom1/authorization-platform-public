import os
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get('SITE_DATA_DIR', BASE_DIR / 'data')).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEBUG = os.environ.get('SITE_DEBUG', '0') == '1'
SECRET_KEY = os.environ.get('SITE_SECRET_KEY', '')
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured('请设置 SITE_SECRET_KEY；本地预览请使用 start-local.py。')
    secret = DATA_DIR / 'local-secret.txt'
    if not secret.exists():
        import secrets
        try:
            with secret.open('x', encoding='utf-8') as f:
                f.write(secrets.token_urlsafe(64))
        except FileExistsError:
            pass
    SECRET_KEY = secret.read_text(encoding='utf-8').strip()
ALLOWED_HOSTS = [s.strip() for s in os.environ.get('SITE_HOSTS', 'localhost,127.0.0.1,[::1]' if DEBUG else '').split(',') if s.strip()]
if not DEBUG and (not ALLOWED_HOSTS or '*' in ALLOWED_HOSTS or len(SECRET_KEY) < 50):
    raise ImproperlyConfigured('正式部署需要明确 SITE_HOSTS 和至少50字符的独立站点密钥。')
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles', 'catalog']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware']
ROOT_URLCONF = 'showcase.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages', 'catalog.context.site_context']}}]
WSGI_APPLICATION = 'showcase.wsgi.application'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': DATA_DIR / 'site.sqlite3', 'OPTIONS': {'timeout': 20}}}
AUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'}, {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}}, {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'}, {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'}]
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = True
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
MEDIA_ROOT = DATA_DIR / 'media'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGIN_URL = '/manage/login/'
LOGIN_REDIRECT_URL = '/manage/'
LOGOUT_REDIRECT_URL = '/manage/login/'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 8 * 60 * 60
SESSION_SAVE_EVERY_REQUEST = False
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
CSRF_TRUSTED_ORIGINS = [x for x in os.environ.get('SITE_CSRF_ORIGINS', '').split(',') if x]
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 3600 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
# Only this site is in scope. Do not enlist sibling/subdomains or a browser
# preload program before the domain owner has explicitly chosen that policy.
SILENCED_SYSTEM_CHECKS = ['security.W005', 'security.W021']
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
if os.environ.get('SITE_TRUST_PROXY') == '1':
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
DATA_UPLOAD_MAX_MEMORY_SIZE = 90 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FILES = 12
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
CSRF_FAILURE_VIEW = 'catalog.views.csrf_failure'
