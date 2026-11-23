"""Small provider-neutral object storage contract.

The platform keeps release metadata in PostgreSQL and stores package bytes behind
an object-storage boundary.  Local development uses an atomic filesystem
adapter.  Production configuration is deliberately fail-closed until an
S3-compatible provider and its secret/configuration store are supplied; this
module does not silently turn a production object into a local file.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import os
import ssl
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import quote, urlsplit

from django.conf import settings


class ObjectStorageError(Exception):
    """Raised when an object cannot be safely stored or read."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class StoredObject:
    key: str
    size: int
    sha256: str


def normalize_object_key(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ObjectStorageError("object key is required")
    key = value.strip().replace("\\", "/")
    path = PurePosixPath(key)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ObjectStorageError("object key is outside the storage namespace")
    normalized = "/".join(path.parts)
    if len(normalized) > 512 or "\x00" in normalized:
        raise ObjectStorageError("object key is invalid")
    return normalized


def _sha256_stream(source: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _has_symlink_component(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


class LocalObjectStore:
    """Atomic local adapter used by tests and local development only."""

    def __init__(self, root: Path | str | None = None):
        configured = root if root is not None else getattr(settings, "STORAGE_ROOT", Path(settings.BASE_DIR) / "storage")
        self.root = Path(configured).resolve()

    def _path(self, key: str) -> Path:
        normalized = normalize_object_key(key)
        candidate = (self.root / normalized).resolve()
        if not _under(candidate, self.root) or _has_symlink_component(self.root / normalized, self.root):
            raise ObjectStorageError("object key is outside the storage namespace")
        return candidate

    def put_file(self, source: BinaryIO, key: str, *, expected_sha256: str | None = None) -> StoredObject:
        normalized = normalize_object_key(key)
        destination = self._path(normalized)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.upload"
        try:
            with temporary.open("wb") as target:
                size, sha256 = _sha256_stream_from_to(source, target)
                target.flush()
                os.fsync(target.fileno())
            if expected_sha256 and sha256.lower() != expected_sha256.lower():
                raise ObjectStorageError("object checksum does not match")
            os.replace(temporary, destination)
            return StoredObject(key=normalized, size=size, sha256=sha256)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def put_bytes(self, payload: bytes, key: str, *, expected_sha256: str | None = None) -> StoredObject:
        from io import BytesIO

        return self.put_file(BytesIO(payload), key, expected_sha256=expected_sha256)

    def open(self, key: str) -> BinaryIO:
        path = self._path(key)
        if not path.is_file() or path.is_symlink():
            raise ObjectStorageError("object is unavailable")
        return path.open("rb")

    def head(self, key: str) -> StoredObject:
        path = self._path(key)
        if not path.is_file() or path.is_symlink():
            raise ObjectStorageError("object is unavailable")
        with path.open("rb") as source:
            size, sha256 = _sha256_stream(source)
        return StoredObject(key=normalize_object_key(key), size=size, sha256=sha256)

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if not path.is_file() or path.is_symlink():
            return False
        path.unlink()
        return True


class _RemoteResponseStream:
    """File-like response that keeps the HTTP connection alive while reading."""

    def __init__(self, connection: http.client.HTTPConnection, response: http.client.HTTPResponse):
        self._connection = connection
        self._response = response
        self._closed = False

    def read(self, size: int = -1) -> bytes:
        return self._response.read(size)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def writable(self) -> bool:
        return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        finally:
            self._connection.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def _hmac_sha256(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


class S3ObjectStore:
    """Small AWS Signature V4 adapter for S3-compatible object stores.

    It deliberately supports only the operations used by the release and
    cleanup flows.  The adapter uses a single signed PUT rather than silently
    falling back to local storage or introducing an unbounded in-memory buffer.
    """

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        bucket: str | None = None,
        region: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        path_style: bool | None = None,
        ca_cert: str | None = None,
    ):
        self.endpoint = (endpoint if endpoint is not None else getattr(settings, "OBJECT_STORAGE_ENDPOINT", "")).strip().rstrip("/")
        self.bucket = (bucket if bucket is not None else getattr(settings, "OBJECT_STORAGE_BUCKET", "")).strip()
        self.region = (region if region is not None else getattr(settings, "OBJECT_STORAGE_REGION", "")).strip()
        self.access_key_id = (access_key_id if access_key_id is not None else getattr(settings, "OBJECT_STORAGE_ACCESS_KEY_ID", "")).strip()
        self.secret_access_key = secret_access_key if secret_access_key is not None else getattr(settings, "OBJECT_STORAGE_SECRET_ACCESS_KEY", "")
        self.path_style = bool(getattr(settings, "OBJECT_STORAGE_PATH_STYLE", False)) if path_style is None else path_style
        self.ca_cert = (ca_cert if ca_cert is not None else getattr(settings, "OBJECT_STORAGE_CA_CERT", "")).strip()
        parsed = urlsplit(self.endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
            raise ObjectStorageError("object storage endpoint is invalid")
        if parsed.username is not None or parsed.password is not None:
            raise ObjectStorageError("object storage endpoint must not contain credentials")
        if parsed.path not in {"", "/"}:
            raise ObjectStorageError("object storage endpoint path is not supported")
        if not all((self.bucket, self.region, self.access_key_id, self.secret_access_key)):
            raise ObjectStorageError("object storage credentials are incomplete")
        self._parsed_endpoint = parsed

    @property
    def _service(self) -> str:
        return "s3"

    def _target(self, key: str | None) -> tuple[str, int | None, str, str]:
        normalized = normalize_object_key(key) if key else ""
        parsed = self._parsed_endpoint
        port = parsed.port
        base_path = parsed.path.rstrip("/")
        encoded_key = quote(normalized, safe="/-_.~")
        if self.path_style:
            host = parsed.hostname or ""
            host_header = parsed.netloc
            path = f"{base_path}/{quote(self.bucket, safe='-_.~')}"
            if encoded_key:
                path += f"/{encoded_key}"
        else:
            host = f"{self.bucket}.{parsed.hostname}"
            host_header = host if port is None else f"{host}:{port}"
            path = f"{base_path}/{encoded_key}" if encoded_key else base_path
        return host, port, host_header, path or "/"

    def _request(
        self,
        method: str,
        key: str,
        *,
        body: BinaryIO | None = None,
        content_length: int | None = None,
        payload_sha256: str | None = None,
        metadata: dict[str, str] | None = None,
        query: str = "",
    ) -> _RemoteResponseStream:
        host, port, host_header, path = self._target(key)
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        short_date = now.strftime("%Y%m%d")
        payload_hash = payload_sha256 or hashlib.sha256(b"").hexdigest()
        headers: dict[str, str] = {
            "host": host_header,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        for name, value in (metadata or {}).items():
            headers[f"x-amz-meta-{name.lower()}"] = str(value)
        canonical_headers = "".join(
            f"{name}:{' '.join(value.strip().split())}\n" for name, value in sorted(headers.items())
        )
        signed_headers = ";".join(sorted(headers))
        canonical_request = "\n".join(
            (method, path, query, canonical_headers, signed_headers, payload_hash)
        )
        scope = f"{short_date}/{self.region}/{self._service}/aws4_request"
        string_to_sign = "\n".join(
            ("AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest())
        )
        date_key = _hmac_sha256(("AWS4" + self.secret_access_key).encode("utf-8"), short_date)
        region_key = hmac.new(date_key, self.region.encode("utf-8"), hashlib.sha256).digest()
        service_key = hmac.new(region_key, self._service.encode("utf-8"), hashlib.sha256).digest()
        signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        connection_cls = http.client.HTTPSConnection if self._parsed_endpoint.scheme == "https" else http.client.HTTPConnection
        connection_kwargs = {"timeout": 60}
        if connection_cls is http.client.HTTPSConnection:
            try:
                context = ssl.create_default_context(cafile=self.ca_cert or None)
            except (OSError, ssl.SSLError) as exc:
                raise ObjectStorageError("object storage TLS trust configuration is invalid") from exc
            connection_kwargs["context"] = context
        connection = connection_cls(host, port=port, **connection_kwargs)
        try:
            request_target = path + (f"?{query}" if query else "")
            connection.putrequest(method, request_target, skip_host=True, skip_accept_encoding=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            if content_length is not None:
                connection.putheader("Content-Length", str(content_length))
            connection.endheaders()
            if body is not None:
                for chunk in iter(lambda: body.read(1024 * 1024), b""):
                    connection.send(chunk)
            response = connection.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise ObjectStorageError("object storage request failed") from exc
        if not 200 <= response.status < 300:
            response.read(4096)
            status = response.status
            response.close()
            connection.close()
            raise ObjectStorageError("object storage request was rejected", status_code=status)
        return _RemoteResponseStream(connection, response)

    def put_file(self, source: BinaryIO, key: str, *, expected_sha256: str | None = None) -> StoredObject:
        normalized = normalize_object_key(key)
        with tempfile.TemporaryFile(mode="w+b") as spool:
            size, sha256 = _sha256_stream_from_to(source, spool)
            if expected_sha256 and sha256.lower() != expected_sha256.lower():
                raise ObjectStorageError("object checksum does not match")
            spool.seek(0)
            response = self._request(
                "PUT",
                normalized,
                body=spool,
                content_length=size,
                payload_sha256=sha256,
                metadata={"sha256": sha256, "size": str(size)},
            )
            response.close()
        return StoredObject(key=normalized, size=size, sha256=sha256)

    def put_bytes(self, payload: bytes, key: str, *, expected_sha256: str | None = None) -> StoredObject:
        from io import BytesIO

        return self.put_file(BytesIO(payload), key, expected_sha256=expected_sha256)

    def open(self, key: str) -> BinaryIO:
        return self._request("GET", key)

    def list_prefix(self, prefix: str, *, max_keys: int = 1000) -> list[dict[str, object]]:
        normalized_prefix = normalize_object_key(prefix.rstrip("/")) + "/" if prefix else ""
        query = f"list-type=2&max-keys={max(1, min(max_keys, 1000))}&prefix={quote(normalized_prefix, safe='')}"
        response = self._request("GET", None, query=query)
        try:
            raw = response.read()
        finally:
            response.close()
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ObjectStorageError("object storage list response is invalid") from exc
        result: list[dict[str, object]] = []
        for contents in root.iter():
            if contents.tag.rsplit("}", 1)[-1] != "Contents":
                continue
            values = {child.tag.rsplit("}", 1)[-1]: (child.text or "") for child in contents}
            try:
                modified = datetime.fromisoformat(values.get("LastModified", "").replace("Z", "+00:00")).timestamp()
                size = int(values.get("Size", "0"))
            except (TypeError, ValueError) as exc:
                raise ObjectStorageError("object storage list metadata is invalid") from exc
            result.append({"key": values.get("Key", ""), "size": size, "last_modified": modified})
        return result

    def open_verified(self, key: str, *, expected_size: int, expected_sha256: str) -> BinaryIO:
        normalized = normalize_object_key(key)
        metadata = self.head(normalized)
        if metadata.size != expected_size or not metadata.sha256 or metadata.sha256.lower() != expected_sha256.lower():
            raise ObjectStorageError("object metadata does not match the release record")
        response = self.open(normalized)
        spool = tempfile.TemporaryFile(mode="w+b")
        digest = hashlib.sha256()
        size = 0
        success = False
        try:
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
                if size > expected_size:
                    raise ObjectStorageError("object content is larger than the release record")
                spool.write(chunk)
            if size != expected_size or digest.hexdigest().lower() != expected_sha256.lower():
                raise ObjectStorageError("object content does not match the release record")
            spool.seek(0)
            success = True
            return spool
        except (OSError, http.client.HTTPException):
            raise ObjectStorageError("object download failed")
        finally:
            response.close()
            if not success:
                spool.close()

    def head(self, key: str) -> StoredObject:
        normalized = normalize_object_key(key)
        response = self._request("HEAD", normalized)
        try:
            size = int(response._response.getheader("Content-Length", "0"))
            sha256 = response._response.getheader("x-amz-meta-sha256", "")
        finally:
            response.close()
        return StoredObject(key=normalized, size=size, sha256=sha256)

    def delete(self, key: str) -> bool:
        try:
            response = self._request("DELETE", key)
        except ObjectStorageError as exc:
            if exc.status_code == 404:
                return True
            raise
        response.close()
        return True


def _sha256_stream_from_to(source: BinaryIO, target: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        target.write(chunk)
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def object_storage_contract(*, env: dict[str, str] | None = None) -> dict[str, object]:
    values = os.environ if env is None else env
    provider = values.get("OBJECT_STORAGE_PROVIDER", "local").strip().lower()
    required = {
        "endpoint": bool(values.get("OBJECT_STORAGE_ENDPOINT", "").strip()),
        "bucket": bool(values.get("OBJECT_STORAGE_BUCKET", "").strip()),
        "region": bool(values.get("OBJECT_STORAGE_REGION", "").strip()),
        "access_key": bool(values.get("OBJECT_STORAGE_ACCESS_KEY_ID", "").strip()),
        "secret_key": bool(values.get("OBJECT_STORAGE_SECRET_ACCESS_KEY", "")),
    }
    return {
        "provider": provider,
        "https_endpoint": values.get("OBJECT_STORAGE_ENDPOINT", "").strip().lower().startswith("https://"),
        "production_ready": provider in {"s3", "s3-compatible"}
        and all(required.values())
        and values.get("OBJECT_STORAGE_ENDPOINT", "").strip().lower().startswith("https://"),
        "required": required,
        "secret_values_exposed": False,
    }


def configured_object_store(*, root: Path | str | None = None) -> LocalObjectStore | S3ObjectStore:
    provider = str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower()
    if provider == "local":
        return LocalObjectStore(root)
    if provider in {"s3", "s3-compatible"}:
        return S3ObjectStore()
    raise ObjectStorageError("object storage provider is unsupported")
