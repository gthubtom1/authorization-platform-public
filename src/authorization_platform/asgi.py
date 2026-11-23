"""ASGI config for the authorization platform."""

from __future__ import annotations

import os

from django.core.asgi import get_asgi_application


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
application = get_asgi_application()
