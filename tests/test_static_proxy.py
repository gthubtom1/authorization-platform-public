from __future__ import annotations

import http.client
import threading
import unittest
from pathlib import Path

from scripts.static_proxy import ROOT_404_COPY, build_server, filtered_request_headers, is_root_path, is_upstream_path
class StaticProxyHelperTests(unittest.TestCase):
    def test_hidden_root_is_recognized_with_query_strings(self):
        self.assertTrue(is_root_path("/"))
        self.assertTrue(is_root_path("/?from=browser"))
        self.assertTrue(is_root_path("/./"))
        self.assertTrue(is_root_path("/."))
        self.assertTrue(is_root_path("/%2e/"))
        self.assertTrue(is_root_path("/%2E"))
        self.assertTrue(is_root_path("/foo/../"))
        self.assertTrue(is_root_path("/%5c/"))
        self.assertTrue(is_root_path("/%5C/"))
        self.assertTrue(is_root_path("/%5c"))
        self.assertTrue(is_root_path("/\\\\/"))
        self.assertFalse(is_root_path("/entry.html"))
        self.assertFalse(is_root_path("/./entry.html"))

    def test_hidden_root_returns_404_from_static_server(self):
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        server = build_server(
            bind="127.0.0.1",
            port=0,
            directory=root,
            backend_host="127.0.0.1",
            backend_port=1,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        forbidden_names = (b"entry.html", b"manage-login.html", b"manage.html")
        try:
            for path in ("/?from=test", "/./", "/%5c/", "/%5c"):
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("GET", path)
                response = connection.getresponse()
                body = response.read()
                self.assertEqual(response.status, 404)
                self.assertIn(ROOT_404_COPY.encode("utf-8"), body)
                self.assertIn(b"downstream-login.html", body)
                self.assertIn(b'href="/downstream-login.html"', body)
                for name in forbidden_names:
                    self.assertNotIn(name, body)
                location = response.getheader("Location")
                self.assertIsNone(location)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_registration_page_matches_server_password_minimum(self):
        page = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "ui-preview"
            / "downstream-register.html"
        ).read_text(encoding="utf-8")

        self.assertEqual(page.count('name="password"'), 1)
        self.assertEqual(page.count('name="password_confirm"'), 1)
        self.assertEqual(page.count('minlength="10"'), 2)

        manage_page = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "ui-preview"
            / "manage.html"
        ).read_text(encoding="utf-8")
        self.assertIn('name="password" type="password" required minlength="10"', manage_page)

    def test_only_api_and_health_paths_are_forwarded(self):
        self.assertTrue(is_upstream_path("/api/v1/session/"))
        self.assertTrue(is_upstream_path("/healthz/?check=local"))
        self.assertFalse(is_upstream_path("/manage.html"))
        self.assertFalse(is_upstream_path("/static/api/example.js"))

    def test_static_credential_source_does_not_embed_plaintext(self):
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        for filename in ("manage.html", "downstream.html", "downstream-login.html", "downstream-register.html", "preview.js"):
            page = (root / filename).read_text(encoding="utf-8")
            self.assertNotIn("data-full-code", page)
            for code in (
                "INV-7F3K-92PX-9K2D",
                "QUOTA-500-X7P2-A91K",
                "LIC-ALPHA-2026-4M9Q",
                "Alpha Desktop",
                "Beta Studio",
                "渠道 A",
            ):
                self.assertNotIn(code, page)

    def test_live_pages_and_script_do_not_link_hidden_entry(self):
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        for filename in (
            "downstream.html",
            "downstream-login.html",
            "downstream-register.html",
            "manage.html",
            "manage-login.html",
            "preview.js",
        ):
            page = (root / filename).read_text(encoding="utf-8")
            self.assertNotIn("entry.html", page)

    def test_live_business_pages_hide_preview_until_authenticated(self):
        root = Path(__file__).resolve().parents[1] / "docs" / "ui-preview"
        for filename in ("manage.html", "downstream.html"):
            page = (root / filename).read_text(encoding="utf-8")
            self.assertIn('classList.add("live-auth-pending")', page)
            self.assertIn('window.location.port !== "8123"', page)

        script = (root / "preview.js").read_text(encoding="utf-8")
        self.assertIn('document.documentElement.classList.remove("live-auth-pending")', script)
        self.assertIn('applyQuotaPurchaseLink("")', script)
        self.assertIn("静态预览不保存真实购买链接", script)
        self.assertIn("静态预览不执行真实管理操作", script)

        css = (root / "preview.css").read_text(encoding="utf-8")
        self.assertIn("html.live-auth-pending body.preview-app > .app-shell", css)
        self.assertIn('content: "正在验证登录状态…"', css)

        for filename in ("downstream-login.html", "downstream-register.html"):
            page = (root / filename).read_text(encoding="utf-8")
            self.assertIn('data-quota-purchase-link href="#" hidden', page)

    def test_proxy_owned_and_hop_by_hop_headers_are_removed(self):
        headers = filtered_request_headers(
            {
                "Host": "127.0.0.1:8123",
                "Connection": "keep-alive",
                "Content-Length": "12",
                "Cookie": "sessionid=demo",
                "Origin": "http://127.0.0.1:8123",
                "X-CSRFToken": "csrf",
            }
        )
        self.assertNotIn("Host", headers)
        self.assertNotIn("Connection", headers)
        self.assertNotIn("Content-Length", headers)
        self.assertEqual(headers["Cookie"], "sessionid=demo")
        self.assertEqual(headers["Origin"], "http://127.0.0.1:8123")
        self.assertEqual(headers["X-CSRFToken"], "csrf")
