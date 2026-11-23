"""Serve the frozen 8123 preview and proxy the real Django API on the same origin.

This is a local development gateway only. Production routing remains the
responsibility of the deployment reverse proxy and is intentionally not
configured here.
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import posixpath
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote, urlsplit


LOGGER = logging.getLogger("authorization_platform.static_proxy")
ROOT_404_COPY = "这个地址没有页面。请打开下游登录页 downstream-login.html。"
ROOT_404_HTML = (
    "<!DOCTYPE html><html lang=\"zh-Hans\"><head><meta charset=\"utf-8\">"
    "<title>没有这个页面</title></head><body>"
    f"<p>{ROOT_404_COPY}</p>"
    "<p><a href=\"/downstream-login.html\">downstream-login.html</a></p>"
    "</body></html>"
)
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024


def is_root_path(request_target: str) -> bool:
    """Return whether a static request targets the hidden domain root.

    Literal `/` and equivalent paths such as `/./`, `/.`, `/%2e/`,
    `/%5c/` and `/foo/../` must all 404 so the 8123 gateway cannot list
    `entry.html`. Windows backslash encodings are treated as `/`.
    """

    raw_path = urlsplit(request_target).path or "/"
    decoded = unquote(raw_path).replace("\\", "/")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized.lstrip("/")
    while normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized == "/"


def is_upstream_path(request_target: str) -> bool:
    """Return whether a request belongs to the fixed local Django upstream."""

    path = urlsplit(request_target).path
    return path in {"/api", "/healthz", "/healthz/"} or path.startswith("/api/")


def filtered_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Copy browser headers while removing hop-by-hop and proxy-owned headers."""

    filtered: dict[str, str] = {}
    for name, value in headers.items():
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS or lower_name in {"host", "content-length"}:
            continue
        filtered[name] = value
    return filtered


class StaticProxyHandler(SimpleHTTPRequestHandler):
    """Static handler with a narrowly scoped local Django HTTP upstream."""

    server_version = "AuthorizationPlatform8123/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if is_root_path(self.path):
            self._send_root_404()
            return
        if is_upstream_path(self.path):
            self._proxy_request()
        else:
            super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        if is_root_path(self.path):
            self._send_root_404()
            return
        if is_upstream_path(self.path):
            self._proxy_request()
        else:
            super().do_HEAD()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._proxy_request()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._proxy_request()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._proxy_request()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._proxy_request()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        if is_root_path(self.path):
            self._send_root_404()
            return
        if is_upstream_path(self.path):
            self._proxy_request()
        else:
            self.send_error(405, "Method Not Allowed")

    def _send_root_404(self) -> None:
        body = ROOT_404_HTML.encode("utf-8")
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _proxy_request(self) -> None:
        if not is_upstream_path(self.path):
            self.send_error(404, "Not Found")
            return

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length < 0 or content_length > MAX_REQUEST_BODY_BYTES:
            self._send_json_error(413, "REQUEST_TOO_LARGE", "请求体过大。")
            return
        body = self.rfile.read(content_length) if content_length else None
        upstream_host = self.server.backend_host  # type: ignore[attr-defined]
        upstream_port = self.server.backend_port  # type: ignore[attr-defined]
        upstream_target = urlsplit(self.path)
        target = upstream_target.path or "/"
        if upstream_target.query:
            target += "?" + upstream_target.query
        headers = filtered_request_headers(self.headers)
        headers["Host"] = f"{upstream_host}:{upstream_port}"
        headers["Connection"] = "close"

        connection: http.client.HTTPConnection | None = None
        try:
            connection = http.client.HTTPConnection(upstream_host, upstream_port, timeout=30)
            connection.request(self.command, target, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                lower_name = name.lower()
                if lower_name in HOP_BY_HOP_HEADERS or lower_name == "content-length":
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)
        except (ConnectionError, OSError, http.client.HTTPException) as exc:
            LOGGER.warning("Django upstream unavailable: %s", exc)
            self._send_json_error(502, "UPSTREAM_UNAVAILABLE", "本地 Django 服务暂时不可用。")
        finally:
            if connection is not None:
                connection.close()

    def _send_json_error(self, status: int, code: str, message: str) -> None:
        payload = json.dumps(
            {"error": {"code": code, "message": message, "retryable": status >= 500}},
            ensure_ascii=False,
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:
        LOGGER.info("%s - %s", self.address_string(), format % args)


def build_server(*, bind: str, port: int, directory: Path, backend_host: str, backend_port: int) -> ThreadingHTTPServer:
    handler = partial(StaticProxyHandler, directory=str(directory))
    server = ThreadingHTTPServer((bind, port), handler)
    server.backend_host = backend_host  # type: ignore[attr-defined]
    server.backend_port = backend_port  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve frozen 8123 pages and proxy local Django API.")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8123)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1] / "docs" / "ui-preview")
    parser.add_argument("--backend-host", default="127.0.0.1")
    parser.add_argument("--backend-port", type=int, default=8000)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_dir():
        parser.error(f"静态目录不存在：{directory}")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = build_server(
        bind=args.bind,
        port=args.port,
        directory=directory,
        backend_host=args.backend_host,
        backend_port=args.backend_port,
    )
    LOGGER.info("8123 gateway listening on http://%s:%s/; static=%s; django=%s:%s", args.bind, args.port, directory, args.backend_host, args.backend_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("8123 gateway stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
