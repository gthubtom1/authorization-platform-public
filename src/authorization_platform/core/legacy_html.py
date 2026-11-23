from __future__ import annotations

from functools import wraps

from django.http import HttpResponse
from django.middleware.csrf import get_token

CONTROL_ROOM_COPY = "请从当前控制室进入。"
FORBIDDEN_API_COPY = "请改用同源 /api/v1/ 管理接口"
LEGACY_HTML_STATUS = 410


def legacy_html_closed_response() -> HttpResponse:
    return HttpResponse(
        (
            "<!DOCTYPE html><html lang=\"zh-Hans\"><head><meta charset=\"utf-8\">"
            f"<title>已停用</title></head><body><p>{CONTROL_ROOM_COPY}</p></body></html>"
        ),
        status=LEGACY_HTML_STATUS,
        content_type="text/html; charset=utf-8",
    )


def close_legacy_html(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        get_token(request)
        return legacy_html_closed_response()

    return wrapped
