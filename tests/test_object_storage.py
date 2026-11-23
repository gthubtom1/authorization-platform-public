from __future__ import annotations

import hashlib
import tempfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from authorization_platform.core.object_storage import (
    LocalObjectStore,
    ObjectStorageError,
    S3ObjectStore,
    configured_object_store,
    object_storage_contract,
)


class _FakeResponse:
    status = 200

    def __init__(self, headers=None):
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.closed = False

    def read(self, _size=-1):
        return b""

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def close(self):
        self.closed = True


class _FakeConnection:
    def __init__(self, *_args, **_kwargs):
        self.request = None
        self.headers = {}
        self.body = bytearray()
        self.response = _FakeResponse()
        self.closed = False

    def putrequest(self, method, path, **_kwargs):
        self.request = (method, path)

    def putheader(self, name, value):
        self.headers[name.lower()] = value

    def endheaders(self):
        return None

    def send(self, chunk):
        self.body.extend(chunk)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class ObjectStorageContractTests(SimpleTestCase):
    def test_local_store_writes_atomically_and_rechecks_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalObjectStore(Path(directory))
            payload = b"release-payload"
            expected = hashlib.sha256(payload).hexdigest()
            stored = store.put_file(BytesIO(payload), "releases/v1/package.zip", expected_sha256=expected)
            self.assertEqual(stored.size, len(payload))
            self.assertEqual(store.head("releases/v1/package.zip").sha256, expected)
            with store.open("releases/v1/package.zip") as source:
                self.assertEqual(source.read(), payload)

    def test_path_traversal_and_checksum_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalObjectStore(Path(directory))
            with self.assertRaises(ObjectStorageError):
                store.put_bytes(b"x", "../outside.bin")
            with self.assertRaises(ObjectStorageError):
                store.put_bytes(b"x", "safe.bin", expected_sha256="0" * 64)
            self.assertFalse((Path(directory) / "safe.bin").exists())

    def test_contract_reports_provider_without_exposing_secret_values(self):
        contract = object_storage_contract(
            env={
                "OBJECT_STORAGE_PROVIDER": "s3-compatible",
                "OBJECT_STORAGE_ENDPOINT": "https://objects.example.invalid",
                "OBJECT_STORAGE_BUCKET": "authorization-platform",
                "OBJECT_STORAGE_REGION": "test-1",
                "OBJECT_STORAGE_ACCESS_KEY_ID": "access-id",
                "OBJECT_STORAGE_SECRET_ACCESS_KEY": "super-secret",
            }
        )
        self.assertTrue(contract["production_ready"])
        self.assertFalse(contract["secret_values_exposed"])
        self.assertNotIn("super-secret", repr(contract))

    @override_settings(
        OBJECT_STORAGE_PROVIDER="s3-compatible",
        OBJECT_STORAGE_ENDPOINT="http://objects.internal:9000",
        OBJECT_STORAGE_BUCKET="authorization-platform",
        OBJECT_STORAGE_REGION="internal-1",
        OBJECT_STORAGE_ACCESS_KEY_ID="access-id",
        OBJECT_STORAGE_SECRET_ACCESS_KEY="super-secret",
        OBJECT_STORAGE_PATH_STYLE=True,
    )
    def test_s3_put_signs_path_style_request_and_streams_payload(self):
        connection = _FakeConnection()
        with patch("authorization_platform.core.object_storage.http.client.HTTPConnection", return_value=connection):
            store = configured_object_store()
            self.assertIsInstance(store, S3ObjectStore)
            stored = store.put_bytes(b"release-payload", "releases/v1/package.zip")

        self.assertEqual(stored.size, len(b"release-payload"))
        self.assertEqual(bytes(connection.body), b"release-payload")
        self.assertEqual(connection.request, ("PUT", "/authorization-platform/releases/v1/package.zip"))
        self.assertIn("AWS4-HMAC-SHA256", connection.headers["authorization"])
        self.assertIn("x-amz-content-sha256", connection.headers["authorization"].lower())
        self.assertNotIn("super-secret", repr(connection.headers))
        self.assertEqual(connection.headers["x-amz-meta-sha256"], stored.sha256)

    @override_settings(
        OBJECT_STORAGE_PROVIDER="s3-compatible",
        OBJECT_STORAGE_ENDPOINT="http://objects.internal:9000",
        OBJECT_STORAGE_BUCKET="authorization-platform",
        OBJECT_STORAGE_REGION="internal-1",
        OBJECT_STORAGE_ACCESS_KEY_ID="access-id",
        OBJECT_STORAGE_SECRET_ACCESS_KEY="super-secret",
    )
    def test_remote_store_rejects_checksum_before_network_and_does_not_fallback(self):
        with patch("authorization_platform.core.object_storage.http.client.HTTPConnection") as connection_class:
            store = configured_object_store()
            with self.assertRaises(ObjectStorageError):
                store.put_bytes(b"x", "safe.bin", expected_sha256="0" * 64)
        connection_class.assert_not_called()

    def test_production_contract_requires_https_and_rejects_endpoint_userinfo(self):
        contract = object_storage_contract(
            env={
                "OBJECT_STORAGE_PROVIDER": "s3-compatible",
                "OBJECT_STORAGE_ENDPOINT": "http://objects.example.invalid",
                "OBJECT_STORAGE_BUCKET": "authorization-platform",
                "OBJECT_STORAGE_REGION": "test-1",
                "OBJECT_STORAGE_ACCESS_KEY_ID": "access-id",
                "OBJECT_STORAGE_SECRET_ACCESS_KEY": "secret",
            }
        )
        self.assertFalse(contract["https_endpoint"])
        self.assertFalse(contract["production_ready"])
        with self.assertRaises(ObjectStorageError):
            S3ObjectStore(
                endpoint="https://" + "user" + ":" + "password" + "@objects.example.invalid",
                bucket="authorization-platform",
                region="test-1",
                access_key_id="access-id",
                secret_access_key="secret",
            )

    def test_remote_verified_open_checks_head_metadata_and_content(self):
        from io import BytesIO

        payload = b"verified release"
        expected = hashlib.sha256(payload).hexdigest()
        store = S3ObjectStore(
            endpoint="https://objects.example.invalid",
            bucket="authorization-platform",
            region="test-1",
            access_key_id="access-id",
            secret_access_key="secret",
        )
        with patch.object(store, "head", return_value=type("Stored", (), {"size": len(payload), "sha256": expected})()), patch.object(store, "open", return_value=BytesIO(payload)):
            with store.open_verified("releases/v1/package.zip", expected_size=len(payload), expected_sha256=expected) as source:
                self.assertEqual(source.read(), payload)
