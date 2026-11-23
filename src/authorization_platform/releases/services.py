from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone
from urllib.parse import urlsplit

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.models import ProfileStatus, Software, SoftwareProfile, SoftwareStatus
from authorization_platform.core.object_storage import ObjectStorageError, configured_object_store

from .models import Release, ReleaseOperation, ReleaseOperationAction, ReleaseSignatureStatus, ReleaseStatus


VERSION_RE = re.compile(r"^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")
PUBLISH_VERSION_RE = re.compile(r"^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
MANIFEST_SCHEMA = "client-release.v1"
MAX_MANIFEST_BYTES = 128 * 1024
PACKAGE_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ReleaseOperationError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _max_package_bytes() -> int:
    return int(getattr(settings, "RELEASE_MAX_PACKAGE_BYTES", 500 * 1024 * 1024))


def _storage_root() -> Path:
    return Path(getattr(settings, "RELEASE_STORAGE_ROOT", Path(settings.BASE_DIR) / "storage" / "releases")).resolve()


def _ensure_local_storage_adapter() -> None:
    provider = str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower()
    if provider != "local":
        raise ReleaseOperationError(
            "OBJECT_STORAGE_PROVIDER_UNAVAILABLE",
            "当前对象存储 provider 尚未接入，已拒绝回退到本地文件系统。",
            status=503,
        )


def _configured_storage_adapter():
    try:
        return configured_object_store(root=_storage_root())
    except ObjectStorageError as exc:
        raise ReleaseOperationError("OBJECT_STORAGE_UNAVAILABLE", "对象存储配置不可用，已拒绝版本操作。", status=503) from exc


def _safe_storage_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ReleaseOperationError("STORAGE_PATH_INVALID", "版本包存储路径不安全。", status=500) from exc
    return candidate


def _has_symlink_component(path: Path, root: Path) -> bool:
    """Reject package paths that traverse a symlink inside the release root."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current /= part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def resolve_release_package_path(package_path: str | None) -> Path | None:
    """Resolve a stored package only when it remains a regular file under storage."""
    if not package_path:
        return None
    if str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower() != "local":
        return None
    root = _storage_root()
    raw_path = Path(package_path)
    candidate = raw_path if raw_path.is_absolute() else root / raw_path
    try:
        path = candidate.resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    if _has_symlink_component(candidate, root) or not path.is_file():
        return None
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_package_available(package_path: str | None, *, expected_size: int | None = None, expected_sha256: str | None = None) -> bool:
    if not package_path:
        return False
    if str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower() == "local":
        path = resolve_release_package_path(package_path)
        if path is None:
            return False
        if expected_size is not None and path.stat().st_size != expected_size:
            return False
        return expected_sha256 is None or _sha256_file(path).lower() == expected_sha256.lower()
    try:
        stored = _configured_storage_adapter().head(package_path)
    except (ObjectStorageError, ReleaseOperationError):
        return False
    return (
        (expected_size is None or stored.size == expected_size)
        and (expected_sha256 is None or bool(stored.sha256) and stored.sha256.lower() == expected_sha256.lower())
    )


def open_release_package(package_path: str | None, *, expected_size: int, expected_sha256: str):
    if not package_path:
        raise ObjectStorageError("object package is unavailable")
    if str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower() == "local":
        path = resolve_release_package_path(package_path)
        if path is None:
            raise ObjectStorageError("object package is unavailable")
        if path.stat().st_size != expected_size or _sha256_file(path).lower() != expected_sha256.lower():
            raise ObjectStorageError("object package does not match the release record")
        return path.open("rb")
    storage = _configured_storage_adapter()
    if hasattr(storage, "open_verified"):
        return storage.open_verified(package_path, expected_size=expected_size, expected_sha256=expected_sha256)
    raise ObjectStorageError("configured object storage cannot verify release content")


def safe_release_filename(value: str | None) -> str:
    """Return a conservative download name that cannot inject a header/path."""
    name = Path(value or "release.zip").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "release.zip"


def _idempotency_key(value: str | None) -> str:
    value = (value or "").strip()
    if not value or len(value) > 128:
        raise ReleaseOperationError("INVALID_REQUEST", "缺少有效的重复提交标识。")
    return value


def _required_string(value: Any, label: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ReleaseOperationError("INVALID_INPUT", f"{label}格式不正确。")
    return value.strip()


def _optional_string(value: Any, label: str, max_length: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value.strip()) > max_length:
        raise ReleaseOperationError("INVALID_INPUT", f"{label}格式不正确。")
    return value.strip()


def _external_download_url(value: Any) -> str:
    text = _required_string(value, "网盘下载地址", 2048)
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ReleaseOperationError("INVALID_DOWNLOAD_URL", "网盘地址只能使用不带账号密码的 HTTP 或 HTTPS 链接。")
    return text


def release_is_client_distributable(release: Release) -> bool:
    # URL-only releases are opened in the customer's browser; there is no ZIP
    # and no platform-signed package, so `RELEASE_REQUIRE_VERIFIED_SIGNATURE`
    # (which governs uploaded packages) does not apply to them.  The optional
    # 64-hex `package_sha256` is the only integrity signal available here and
    # stays optional, matching the documented product contract.
    if str(release.external_download_url or "").strip():
        return True
    if getattr(settings, "RELEASE_REQUIRE_VERIFIED_SIGNATURE", False) and release.signature_status != ReleaseSignatureStatus.VERIFIED:
        return False
    return release_package_available(
        release.package_path,
        expected_size=release.package_size,
        expected_sha256=release.package_sha256,
    )


def release_signature_coverage(release: Release) -> str:
    """Describe what integrity coverage this release actually has.

    External (cloud-drive) releases carry no platform signature at all, so
    reporting them as "verified" would overstate the guarantee.  This is
    surfaced in the admin payload so the operator can see the difference.
    """

    if str(release.external_download_url or "").strip():
        return "external_sha256" if PACKAGE_SHA256_RE.fullmatch(str(release.package_sha256 or "")) else "external_unverified"
    return str(release.signature_status or "")


def _version(value: Any) -> str:
    value = _required_string(value, "版本号", 64)
    match = PUBLISH_VERSION_RE.fullmatch(value)
    if not match:
        raise ReleaseOperationError("INVALID_VERSION", "版本号必须是三段数字，例如 1.2.3。不要写成 2.8、2.7.6-beta 或日期号。")
    return value.removeprefix("v")


def _version_tuple(value: str) -> tuple[int, int, int, str]:
    if not isinstance(value, str) or len(value) > 64:
        return (0, 0, 0, "")
    match = VERSION_RE.fullmatch(value)
    if not match:
        return (0, 0, 0, value)
    numeric = tuple(int(match.group(index)) for index in range(1, 4))
    suffix = value[match.end(3):]
    return (*numeric, suffix)


def _canonical_manifest(manifest: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_signature(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ReleaseOperationError("INVALID_SIGNATURE", "Manifest 签名格式不正确。") from exc


def _signature_info(manifest: dict[str, Any], package_sha256: str) -> tuple[str, str, str]:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        raise ReleaseOperationError("MANIFEST_SIGNATURE_REQUIRED", "Manifest 必须包含签名信息。")
    algorithm = _required_string(signature.get("algorithm"), "签名算法", 32).lower()
    key_id = _required_string(signature.get("key_id"), "签名 Key ID", 128)
    value = _required_string(signature.get("value"), "签名值", 4096)
    if algorithm != "ed25519":
        raise ReleaseOperationError("SIGNATURE_ALGORITHM_UNSUPPORTED", "只接受 ed25519 发布签名。")
    configured_key_id = str(getattr(settings, "RELEASE_SIGNING_KEY_ID", "")).strip()
    if configured_key_id and key_id != configured_key_id:
        raise ReleaseOperationError("SIGNING_KEY_UNKNOWN", "Manifest 使用了未登记的发布签名 Key ID。", status=422)
    declared_hash = manifest.get("package_sha256")
    if declared_hash is not None and (not isinstance(declared_hash, str) or declared_hash.lower() != package_sha256):
        raise ReleaseOperationError("PACKAGE_HASH_MISMATCH", "Manifest 中的包 SHA-256 与服务端计算结果不一致。")

    public_key = getattr(settings, "RELEASE_SIGNING_PUBLIC_KEY", "")
    if public_key:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            key_bytes = base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(_decode_signature(value), _canonical_manifest(manifest))
        except Exception as exc:
            raise ReleaseOperationError("SIGNATURE_INVALID", "发布签名验证失败。", status=422) from exc
        return algorithm, key_id, ReleaseSignatureStatus.VERIFIED
    if getattr(settings, "RELEASE_REQUIRE_VERIFIED_SIGNATURE", False):
        raise ReleaseOperationError("SIGNING_KEY_UNAVAILABLE", "平台没有可用的发布签名公钥，已拒绝发布。", status=503)
    return algorithm, key_id, ReleaseSignatureStatus.DECLARED


def _payload_sha256(archive: zipfile.ZipFile, manifest_info: zipfile.ZipInfo) -> str:
    """Hash deterministic payload records without creating a self-referential ZIP hash."""
    digest = hashlib.sha256()
    seen_names: set[str] = set()
    total_uncompressed = 0
    for info in archive.infolist():
        if info is manifest_info or info.is_dir():
            continue
        posix = PurePosixPath(info.filename.replace("\\", "/"))
        name = posix.as_posix()
        if not name or name in seen_names:
            raise ReleaseOperationError("PACKAGE_PATH_INVALID", "ZIP 包包含重复或无效的文件路径。")
        seen_names.add(name)
        total_uncompressed += info.file_size
        if total_uncompressed > _max_package_bytes():
            raise ReleaseOperationError("PACKAGE_TOO_LARGE", "ZIP 解压后的内容超过允许大小。", status=413)
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(info.file_size).encode("ascii"))
        digest.update(b"\0")
        with archive.open(info, "r") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _read_manifest(path: Any, *, package_sha256: str) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            unsafe = []
            for info in infos:
                posix = PurePosixPath(info.filename.replace("\\", "/"))
                if info.filename.startswith(("/", "\\")) or ".." in posix.parts:
                    unsafe.append(info.filename)
                    continue
                # A Windows drive prefix ("C:/evil.exe") survives the checks
                # above but escapes the extraction root when the customer
                # unzips the package on Windows.
                if PureWindowsPath(info.filename.replace("\\", "/")).drive:
                    unsafe.append(info.filename)
                    continue
                # Symlink entries are stored as regular files with the link
                # mode bit set; extracting them can write outside the target.
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    unsafe.append(info.filename)
            if unsafe:
                raise ReleaseOperationError("PACKAGE_PATH_INVALID", "ZIP 包包含不安全的文件路径。")
            candidates = [
                info for info in infos
                if info.filename in {"client-release.v1.json", "client-release.v1/manifest.json"}
            ]
            if len(candidates) != 1:
                raise ReleaseOperationError("MANIFEST_NOT_FOUND", "ZIP 包必须包含唯一的 client-release.v1 Manifest。")
            info = candidates[0]
            payload_sha256 = _payload_sha256(archive, info)
            if info.file_size > MAX_MANIFEST_BYTES:
                raise ReleaseOperationError("MANIFEST_TOO_LARGE", "Manifest 文件过大。")
            raw = archive.read(info)
    except zipfile.BadZipFile as exc:
        raise ReleaseOperationError("INVALID_PACKAGE", "上传文件不是有效的 ZIP 构建包。") from exc
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseOperationError("INVALID_MANIFEST", "Manifest 不是有效的 UTF-8 JSON。") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise ReleaseOperationError("INVALID_MANIFEST", "Manifest schema 必须是 client-release.v1。")
    _version(manifest.get("version"))
    for key, label, max_length in (
        ("software_id", "软件 ID", 64),
        ("profile_id", "Profile ID", 64),
        ("target", "平台", 32),
        ("arch", "架构", 32),
        ("channel", "发布通道", 32),
    ):
        _required_string(manifest.get(key), label, max_length)
    if manifest.get("minimum_client_version") is not None:
        _optional_string(manifest.get("minimum_client_version"), "最低客户端版本", 64)
    declared_payload_sha256 = manifest.get("payload_sha256")
    if declared_payload_sha256 is None and getattr(settings, "RELEASE_REQUIRE_VERIFIED_SIGNATURE", False):
        raise ReleaseOperationError("PAYLOAD_HASH_REQUIRED", "生产发布 Manifest 必须包含 payload_sha256。", status=422)
    if declared_payload_sha256 is not None:
        if not isinstance(declared_payload_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared_payload_sha256):
            raise ReleaseOperationError("PAYLOAD_HASH_INVALID", "Manifest 的 payload_sha256 格式不正确。", status=422)
        if declared_payload_sha256.lower() != payload_sha256:
            raise ReleaseOperationError("PAYLOAD_HASH_MISMATCH", "Manifest 中的 payload_sha256 与服务端计算结果不一致。", status=422)
    _signature_info(manifest, package_sha256)
    return manifest


def _write_upload(uploaded_file) -> tuple[Path, int, str]:
    root = _storage_root()
    root.mkdir(parents=True, exist_ok=True)
    temp = root / f".upload-{uuid.uuid4().hex}.tmp"
    total = 0
    digest = hashlib.sha256()
    try:
        with temp.open("wb") as output:
            chunks = uploaded_file.chunks() if hasattr(uploaded_file, "chunks") else iter(lambda: uploaded_file.read(1024 * 1024), b"")
            for chunk in chunks:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise ReleaseOperationError("INVALID_PACKAGE", "上传内容格式不正确。")
                total += len(chunk)
                if total > _max_package_bytes():
                    raise ReleaseOperationError("PACKAGE_TOO_LARGE", "构建包超过允许大小。", status=413)
                digest.update(chunk)
                output.write(chunk)
        if total == 0:
            raise ReleaseOperationError("INVALID_PACKAGE", "构建包不能为空。")
        return temp, total, digest.hexdigest()
    except Exception:
        temp.unlink(missing_ok=True)
        raise


PUBLIC_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "version",
        "software_id",
        "profile_id",
        "target",
        "arch",
        "channel",
        "minimum_client_version",
        "payload_sha256",
        "package_sha256",
        "notes",
        "signature",
    }
)


def public_manifest_projection(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {}
    return {key: manifest[key] for key in sorted(PUBLIC_MANIFEST_FIELDS) if key in manifest}


def release_payload(release: Release, *, include_download: bool = False, public: bool = False) -> dict[str, Any]:
    payload = {
        "release_id": str(release.release_id),
        "software_id": release.software_id,
        "software_name": release.software.name,
        "profile_id": release.profile.profile_id,
        "version": release.version,
        "target": release.target,
        "arch": release.arch,
        "channel": release.channel,
        "minimum_client_version": release.minimum_client_version,
        "notes": release.notes,
        "manifest": public_manifest_projection(release.manifest) if public else release.manifest,
        "package_name": release.package_name,
        "package_size": release.package_size,
        "package_sha256": release.package_sha256,
        "external_download_url": release.external_download_url or "",
        "distribution": "external_url" if str(release.external_download_url or "").strip() else "platform_package",
        "signature": {
            "algorithm": release.signature_algorithm,
            "key_id": release.signature_key_id,
            "status": release.signature_status,
            "coverage": release_signature_coverage(release),
        },
        "status": release.status,
        "created_at": release.created_at.isoformat(),
        "published_at": release.published_at.isoformat() if release.published_at else None,
        "withdrawn_at": release.withdrawn_at.isoformat() if release.withdrawn_at else None,
        "withdrawal_reason": release.withdrawal_reason,
        "archived_at": release.archived_at.isoformat() if release.archived_at else None,
        "archived_from_status": release.archived_from_status,
        "archive_reason": release.archive_reason,
        "package_available": release_package_available(
            release.package_path,
            expected_size=release.package_size,
            expected_sha256=release.package_sha256,
        ),
    }
    if include_download and release.status == ReleaseStatus.PUBLISHED:
        # Prefer the cloud-drive URL. Same-host ZIP is optional and public.
        if str(release.external_download_url or "").strip():
            payload["update_open_url"] = release.external_download_url
        elif release_package_available(
            release.package_path,
            expected_size=release.package_size,
            expected_sha256=release.package_sha256,
        ):
            payload["download_url"] = f"/api/v1/public/software/{release.software_id}/profiles/{release.profile.profile_id}/releases/{release.release_id}/download/"
    return payload


def _operation_response(release: Release, *, repeated: bool) -> dict[str, Any]:
    return {"item": release_payload(release), "repeated": repeated}


def _existing_operation(*, actor, action: str, key: str, request_hash: str) -> dict[str, Any] | None:
    operation = ReleaseOperation.objects.filter(actor=actor, action=action, idempotency_key=key).first()
    if operation is None:
        return None
    if operation.request_hash != request_hash:
        raise ReleaseOperationError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
    response = dict(operation.response)
    response["repeated"] = True
    return response


def create_release_draft(*, actor, uploaded_file, software_id: str, channel: str, profile_id: str | None, notes: str, idempotency_key: str, request_id: str, ip_address: str | None) -> dict[str, Any]:
    storage = _configured_storage_adapter()
    software_id = _required_string(software_id, "软件 ID", 64).casefold()
    channel = _required_string(channel, "发布通道", 32).casefold()
    profile_id = _optional_string(profile_id, "Profile ID", 64).casefold()
    notes = _optional_string(notes, "更新说明", 2000)
    key = _idempotency_key(idempotency_key)
    temp, package_size, package_sha256 = _write_upload(uploaded_file)
    release = None
    storage_key = None
    try:
        request_hash = hashlib.sha256(f"{software_id}|{channel}|{profile_id}|{notes}|{package_sha256}|{package_size}".encode("utf-8")).hexdigest()
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.UPLOAD, key=key, request_hash=request_hash)
        if existing is not None:
            temp.unlink(missing_ok=True)
            return existing
        manifest = _read_manifest(temp, package_sha256=package_sha256)
        if manifest["software_id"].casefold() != software_id or manifest["channel"].casefold() != channel:
            raise ReleaseOperationError("MANIFEST_SCOPE_MISMATCH", "Manifest 的软件或发布通道与当前选择不一致。", status=422)
        resolved_profile_id = profile_id or manifest["profile_id"].casefold()
        if manifest["profile_id"].casefold() != resolved_profile_id:
            raise ReleaseOperationError("MANIFEST_SCOPE_MISMATCH", "Manifest 的 Profile 与当前选择不一致。", status=422)
        try:
            software = Software.objects.get(software_id=software_id)
            profile = SoftwareProfile.objects.get(software=software, profile_id=resolved_profile_id)
        except (Software.DoesNotExist, SoftwareProfile.DoesNotExist) as exc:
            raise ReleaseOperationError("PROFILE_NOT_FOUND", "软件或 Profile 不存在。", status=404) from exc
        if manifest["target"] != profile.target or manifest["arch"] != profile.arch or manifest["channel"] != profile.channel:
            raise ReleaseOperationError("MANIFEST_SCOPE_MISMATCH", "Manifest 的平台、架构或通道与 Profile 不一致。", status=422)
        algorithm, key_id, signature_status = _signature_info(manifest, package_sha256)
        version = _version(manifest["version"])
        relative = Path("pending") / f"{uuid.uuid4().hex}.zip"
        storage_key = relative.as_posix()
        with temp.open("rb") as source:
            stored = storage.put_file(source, storage_key, expected_sha256=package_sha256)
        if str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower() == "local":
            package_path = str(_safe_storage_path(_storage_root(), storage_key))
        else:
            package_path = stored.key
        with transaction.atomic():
            try:
                release = Release.objects.create(
                    software=software,
                    profile=profile,
                    version=version,
                    target=manifest["target"],
                    arch=manifest["arch"],
                    channel=manifest["channel"],
                    minimum_client_version=_optional_string(manifest.get("minimum_client_version"), "最低客户端版本", 64),
                    notes=notes or _optional_string(manifest.get("notes"), "更新说明", 2000),
                    manifest=manifest,
                    package_name=str(getattr(uploaded_file, "name", "release.zip"))[:255],
                    package_path=package_path,
                    package_size=package_size,
                    package_sha256=package_sha256,
                    signature_algorithm=algorithm,
                    signature_key_id=key_id,
                    signature_status=signature_status,
                    created_by=actor,
                )
                response = _operation_response(release, repeated=False)
                ReleaseOperation.objects.create(
                    actor=actor,
                    release=release,
                    action=ReleaseOperationAction.UPLOAD,
                    idempotency_key=key,
                    request_hash=request_hash,
                    response=response,
                )
                record_event(actor=actor, action="release.upload", outcome=AuditOutcome.SUCCESS, request_id=request_id, ip_address=ip_address, object_type="Release", object_public_id=release.release_id, metadata={"software_id": software_id, "profile_id": resolved_profile_id, "version": version, "package_size": package_size, "package_sha256": package_sha256, "signature_status": signature_status})
                return response
            except IntegrityError as exc:
                raise ReleaseOperationError("RELEASE_ALREADY_EXISTS", "同一软件、Profile、平台和通道的版本已经存在。", status=409) from exc
    except Exception:
        if storage_key is not None:
            try:
                storage.delete(storage_key)
            except ObjectStorageError:
                pass
        if temp.exists():
            temp.unlink(missing_ok=True)
        raise
    finally:
        temp.unlink(missing_ok=True)


def create_and_publish_external_release(
    *,
    actor,
    software_id: str,
    version: str,
    notes: str,
    external_download_url: str,
    package_sha256: str | None = None,
    channel: str,
    profile_id: str | None,
    idempotency_key: str,
    request_id: str,
    ip_address: str | None,
) -> dict[str, Any]:
    software_id = _required_string(software_id, "软件 ID", 64).casefold()
    channel = _required_string(channel or "stable", "发布通道", 32).casefold()
    profile_id = _optional_string(profile_id, "Profile ID", 64).casefold()
    notes = _required_string(notes, "更新说明", 2000)
    if len(notes) < 4:
        raise ReleaseOperationError("INVALID_INPUT", "更新说明至少需要 4 个字符。")
    version = _version(version)
    url = _external_download_url(external_download_url)
    clean_sha256 = None
    if package_sha256 is not None:
        raw_sha = str(package_sha256).strip().lower()
        if raw_sha:
            if not re.fullmatch(r"[0-9a-f]{64}", raw_sha):
                raise ReleaseOperationError("INVALID_INPUT", "package_sha256 必须是 64 位十六进制散列值。")
            clean_sha256 = raw_sha
        else:
            clean_sha256 = ""
    key = _idempotency_key(idempotency_key)
    sha_token = "__NONE__" if clean_sha256 is None else ("__EMPTY__" if clean_sha256 == "" else clean_sha256)
    request_hash = hashlib.sha256(
        f"{software_id}|{channel}|{profile_id}|{version}|{notes}|{url}|{sha_token}".encode("utf-8")
    ).hexdigest()
    existing = _existing_operation(actor=actor, action=ReleaseOperationAction.PUBLISH_LINK, key=key, request_hash=request_hash)
    if existing is not None:
        return existing
    try:
        software = Software.objects.get(software_id=software_id)
    except Software.DoesNotExist as exc:
        raise ReleaseOperationError("PROFILE_NOT_FOUND", "软件或 Profile 不存在。", status=404) from exc
    if software.status not in (SoftwareStatus.ACTIVE, SoftwareStatus.TESTING):
        raise ReleaseOperationError("PROFILE_UNAVAILABLE", "软件当前不可用。", status=404)
    profiles = SoftwareProfile.objects.filter(
        software=software,
        channel=channel,
        status__in=(ProfileStatus.ACTIVE, ProfileStatus.TESTING),
    )
    if profile_id:
        profile = profiles.filter(profile_id=profile_id).first()
    elif profiles.count() == 1:
        profile = profiles.get()
    else:
        profile = None
    if profile is None:
        raise ReleaseOperationError("PROFILE_NOT_FOUND", "软件或 Profile 不存在。", status=404)
    manifest = {
        "schema": "client-release.v1",
        "distribution": "external_url",
        "version": version,
        "software_id": software.software_id,
        "profile_id": profile.profile_id,
        "target": profile.target,
        "arch": profile.arch,
        "channel": profile.channel,
        "notes": notes,
    }
    if clean_sha256:
        manifest["package_sha256"] = clean_sha256
    with transaction.atomic():
        existing_op = _existing_operation(actor=actor, action=ReleaseOperationAction.PUBLISH_LINK, key=key, request_hash=request_hash)
        if existing_op is not None:
            return existing_op
        existing = (
            Release.objects.select_for_update()
            .filter(
                software=software,
                profile=profile,
                version=version,
                target=profile.target,
                arch=profile.arch,
                channel=profile.channel,
            )
            .exclude(status=ReleaseStatus.DISCARDED)
            .first()
        )
        candidate_releases = Release.objects.filter(
            software=software,
            profile=profile,
            target=profile.target,
            arch=profile.arch,
            channel=profile.channel,
            status=ReleaseStatus.PUBLISHED,
        ).exclude(pk=existing.pk if existing else None)
        target_v = _version_tuple(version)
        older_releases = [r for r in candidate_releases if _version_tuple(r.version) < target_v]
        previous = max(older_releases, key=lambda r: _version_tuple(r.version), default=None)
        if existing is not None:
            if existing.status == ReleaseStatus.DRAFT:
                raise ReleaseOperationError(
                    "RELEASE_ALREADY_EXISTS",
                    "这个版本号还有未发布的草稿。请先丢掉草稿，或换一个版本号。",
                    status=409,
                )
            existing.notes = notes
            was_zip = bool(existing.package_path)
            if clean_sha256 is None:
                manifest = dict(manifest)
                if not was_zip and existing.package_sha256:
                    manifest["package_sha256"] = existing.package_sha256
                else:
                    manifest.pop("package_sha256", None)
            elif clean_sha256 == "":
                manifest = dict(manifest)
                manifest.pop("package_sha256", None)
            existing.manifest = manifest
            existing.external_download_url = url
            existing.status = ReleaseStatus.PUBLISHED
            existing.withdrawn_at = None
            existing.withdrawal_reason = ""
            if not existing.published_at:
                existing.published_at = timezone.now()
            if not existing.previous_release_id and previous:
                existing.previous_release = previous
            existing.package_name = ""
            existing.package_path = ""
            existing.package_size = 0
            if clean_sha256 is None:
                existing.package_sha256 = "" if was_zip else (existing.package_sha256 or "")
            else:
                existing.package_sha256 = clean_sha256
            existing.package_deleted_at = None
            existing.signature_algorithm = ""
            existing.signature_key_id = ""
            existing.signature_status = ReleaseSignatureStatus.DECLARED
            # 重发同一个版本号等于把这一行重新拿出来用，归档标记要清掉。
            existing.archived_at = None
            existing.archived_from_status = ""
            existing.archive_reason = ""
            cover_fields = [
                "notes",
                "manifest",
                "external_download_url",
                "status",
                "withdrawn_at",
                "withdrawal_reason",
                "published_at",
                "previous_release",
                "package_name",
                "package_path",
                "package_size",
                "package_sha256",
                "package_deleted_at",
                "signature_algorithm",
                "signature_key_id",
                "signature_status",
                "archived_at",
                "archived_from_status",
                "archive_reason",
            ]
            existing.save(update_fields=tuple(cover_fields))
            release = existing
            replaced = True
        else:
            try:
                release = Release.objects.create(
                    software=software,
                    profile=profile,
                    version=version,
                    target=profile.target,
                    arch=profile.arch,
                    channel=profile.channel,
                    notes=notes,
                    manifest=manifest,
                    package_name="",
                    package_path="",
                    package_size=0,
                    package_sha256=clean_sha256 or "",
                    external_download_url=url,
                    signature_algorithm="",
                    signature_key_id="",
                    signature_status=ReleaseSignatureStatus.DECLARED,
                    status=ReleaseStatus.PUBLISHED,
                    created_by=actor,
                    published_at=timezone.now(),
                    previous_release=previous,
                )
            except IntegrityError as exc:
                existing_op = _existing_operation(actor=actor, action=ReleaseOperationAction.PUBLISH_LINK, key=key, request_hash=request_hash)
                if existing_op is not None:
                    return existing_op
                raise ReleaseOperationError("RELEASE_ALREADY_EXISTS", "同一软件、通道的这个版本号无法保存。", status=409) from exc
            replaced = False
        response = _operation_response(release, repeated=False)
        response["replaced"] = replaced
        try:
            ReleaseOperation.objects.create(
                actor=actor,
                release=release,
                action=ReleaseOperationAction.PUBLISH_LINK,
                idempotency_key=key,
                request_hash=request_hash,
                response=response,
            )
        except IntegrityError:
            existing_op = _existing_operation(actor=actor, action=ReleaseOperationAction.PUBLISH_LINK, key=key, request_hash=request_hash)
            if existing_op is not None:
                return existing_op
            raise ReleaseOperationError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
        record_event(
            actor=actor,
            action="release.publish_link",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Release",
            object_public_id=release.release_id,
            metadata={
                "software_id": software.software_id,
                "profile_id": profile.profile_id,
                "version": version,
                "channel": profile.channel,
                "distribution": "external_url",
                "replaced": replaced,
            },
        )
        return response


def update_external_release_url(
    *,
    actor,
    release_id,
    external_download_url: str,
    package_sha256: str | None = None,
    idempotency_key: str,
    request_id: str,
    ip_address: str | None,
) -> dict[str, Any]:
    url = _external_download_url(external_download_url)
    clean_sha256 = None
    if package_sha256 is not None:
        raw_sha = str(package_sha256).strip().lower()
        if raw_sha:
            if not re.fullmatch(r"[0-9a-f]{64}", raw_sha):
                raise ReleaseOperationError("INVALID_INPUT", "package_sha256 必须是 64 位十六进制散列值。")
            clean_sha256 = raw_sha
        else:
            clean_sha256 = ""
    key = _idempotency_key(idempotency_key)
    sha_token = "__NONE__" if clean_sha256 is None else ("__EMPTY__" if clean_sha256 == "" else clean_sha256)
    request_hash = hashlib.sha256(f"{release_id}|{url}|{sha_token}".encode("utf-8")).hexdigest()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.UPDATE_LINK, key=key, request_hash=request_hash)
        if existing is not None:
            return existing
        if release.status != ReleaseStatus.PUBLISHED:
            raise ReleaseOperationError("RELEASE_NOT_PUBLISHED", "只有已发布版本可以改网盘地址。", status=409)
        if not str(release.external_download_url or "").strip():
            raise ReleaseOperationError("NOT_EXTERNAL_RELEASE", "只有网盘发布的版本可以改地址。", status=409)
        previous_url = release.external_download_url
        release.external_download_url = url
        manifest = dict(release.manifest or {})
        manifest["distribution"] = "external_url"
        update_fields = ["external_download_url", "manifest"]
        if clean_sha256 is not None:
            release.package_sha256 = clean_sha256
            if clean_sha256:
                manifest["package_sha256"] = clean_sha256
            else:
                manifest.pop("package_sha256", None)
            update_fields.append("package_sha256")
        release.manifest = manifest
        release.save(update_fields=tuple(update_fields))
        response = _operation_response(release, repeated=False)
        try:
            ReleaseOperation.objects.create(
                actor=actor,
                release=release,
                action=ReleaseOperationAction.UPDATE_LINK,
                idempotency_key=key,
                request_hash=request_hash,
                response=response,
            )
        except IntegrityError:
            existing = _existing_operation(actor=actor, action=ReleaseOperationAction.UPDATE_LINK, key=key, request_hash=request_hash)
            if existing is not None:
                return existing
            raise ReleaseOperationError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
        record_event(
            actor=actor,
            action="release.update_link",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Release",
            object_public_id=release.release_id,
            metadata={
                "software_id": release.software_id,
                "profile_id": release.profile.profile_id,
                "version": release.version,
                "channel": release.channel,
                "previous_host": urlsplit(previous_url).netloc,
                "new_host": urlsplit(url).netloc,
                "url_changed": previous_url != url,
            },
        )
        return response


def publish_release(*, actor, release_id, notes: str, idempotency_key: str, request_id: str, ip_address: str | None) -> dict[str, Any]:
    key = _idempotency_key(idempotency_key)
    notes = _required_string(notes, "更新说明", 2000)
    if len(notes) < 4:
        raise ReleaseOperationError("INVALID_INPUT", "更新说明至少需要 4 个字符。")
    request_hash = hashlib.sha256(f"{release_id}|{notes}".encode("utf-8")).hexdigest()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.PUBLISH, key=key, request_hash=request_hash)
        if existing is not None:
            return existing
        if release.status != ReleaseStatus.DRAFT:
            raise ReleaseOperationError("RELEASE_NOT_DRAFT", "只有草稿版本可以确认发布。", status=409)
        try:
            with open_release_package(
                release.package_path,
                expected_size=release.package_size,
                expected_sha256=release.package_sha256,
            ) as package:
                manifest = _read_manifest(package, package_sha256=release.package_sha256)
        except (ObjectStorageError, ReleaseOperationError) as exc:
            raise ReleaseOperationError("PACKAGE_UNAVAILABLE", "发布前无法重新验证版本包，已拒绝发布。", status=409) from exc
        if (
            _version(manifest.get("version")) != release.version
            or manifest.get("software_id", "").casefold() != release.software_id
            or manifest.get("profile_id", "").casefold() != release.profile.profile_id
            or manifest.get("target") != release.target
            or manifest.get("arch") != release.arch
            or manifest.get("channel", "").casefold() != release.channel
        ):
            raise ReleaseOperationError("MANIFEST_SCOPE_MISMATCH", "发布前 Manifest 与版本记录不一致，已拒绝发布。", status=409)
        algorithm, key_id, signature_status = _signature_info(manifest, release.package_sha256)
        previous = Release.objects.filter(software=release.software, profile=release.profile, target=release.target, arch=release.arch, channel=release.channel, status=ReleaseStatus.PUBLISHED).order_by("-published_at", "-created_at").first()
        release.status = ReleaseStatus.PUBLISHED
        release.notes = notes
        release.published_at = timezone.now()
        release.previous_release = previous
        release.signature_algorithm = algorithm
        release.signature_key_id = key_id
        release.signature_status = signature_status
        release.manifest = manifest
        release.save(update_fields=("status", "notes", "published_at", "previous_release", "signature_algorithm", "signature_key_id", "signature_status", "manifest"))
        response = _operation_response(release, repeated=False)
        ReleaseOperation.objects.create(actor=actor, release=release, action=ReleaseOperationAction.PUBLISH, idempotency_key=key, request_hash=request_hash, response=response)
        record_event(actor=actor, action="release.publish", outcome=AuditOutcome.SUCCESS, request_id=request_id, ip_address=ip_address, object_type="Release", object_public_id=release.release_id, metadata={"software_id": release.software_id, "profile_id": release.profile.profile_id, "version": release.version, "channel": release.channel, "signature_status": release.signature_status})
        return response


def withdraw_release(*, actor, release_id, reason: str, idempotency_key: str, request_id: str, ip_address: str | None) -> dict[str, Any]:
    key = _idempotency_key(idempotency_key)
    reason = _required_string(reason, "撤回原因", 255)
    if len(reason) < 4:
        raise ReleaseOperationError("INVALID_INPUT", "撤回原因至少需要 4 个字符。")
    request_hash = hashlib.sha256(f"{release_id}|{reason}".encode("utf-8")).hexdigest()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.WITHDRAW, key=key, request_hash=request_hash)
        if existing is not None:
            return existing
        if release.status != ReleaseStatus.PUBLISHED:
            raise ReleaseOperationError("RELEASE_NOT_PUBLISHED", "只有已发布版本可以撤回。", status=409)
        release.status = ReleaseStatus.WITHDRAWN
        release.withdrawn_at = timezone.now()
        release.withdrawal_reason = reason
        release.save(update_fields=("status", "withdrawn_at", "withdrawal_reason"))
        fallback_version = _registry_fallback_version(release)
        response = _operation_response(release, repeated=False)
        response["registry_fallback_version"] = fallback_version
        ReleaseOperation.objects.create(actor=actor, release=release, action=ReleaseOperationAction.WITHDRAW, idempotency_key=key, request_hash=request_hash, response=response)
        record_event(actor=actor, action="release.withdraw", outcome=AuditOutcome.SUCCESS, request_id=request_id, ip_address=ip_address, object_type="Release", object_public_id=release.release_id, reason_code="WITHDRAWN", metadata={"software_id": release.software_id, "profile_id": release.profile.profile_id, "version": release.version, "channel": release.channel, "reason_length": len(reason)})
        return response


def _package_storage_key(release: Release) -> str | None:
    if not release.package_path:
        return None
    provider = str(getattr(settings, "OBJECT_STORAGE_PROVIDER", "local")).strip().lower()
    if provider != "local":
        return release.package_path
    try:
        return Path(release.package_path).resolve().relative_to(_storage_root()).as_posix()
    except ValueError:
        return None


def discard_release_draft(*, actor, release_id, idempotency_key: str, request_id: str, ip_address: str | None) -> dict[str, Any]:
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(f"{release_id}|discard".encode("utf-8")).hexdigest()
    storage = _configured_storage_adapter()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.DISCARD, key=key, request_hash=request_hash)
        if existing is not None:
            return existing
        if release.status != ReleaseStatus.DRAFT:
            raise ReleaseOperationError("RELEASE_NOT_DRAFT", "只有草稿可以丢弃。", status=409)
        storage_key = _package_storage_key(release)
        if storage_key:
            try:
                storage.delete(storage_key)
            except ObjectStorageError as exc:
                raise ReleaseOperationError("OBJECT_STORAGE_UNAVAILABLE", "草稿安装包无法删除，已拒绝丢弃。", status=503) from exc
        release.status = ReleaseStatus.DISCARDED
        release.package_path = ""
        release.package_deleted_at = timezone.now()
        release.save(update_fields=("status", "package_path", "package_deleted_at"))
        response = _operation_response(release, repeated=False)
        ReleaseOperation.objects.create(actor=actor, release=release, action=ReleaseOperationAction.DISCARD, idempotency_key=key, request_hash=request_hash, response=response)
        record_event(actor=actor, action="release.discard", outcome=AuditOutcome.SUCCESS, request_id=request_id, ip_address=ip_address, object_type="Release", object_public_id=release.release_id, metadata={"software_id": release.software_id, "profile_id": release.profile.profile_id, "version": release.version, "channel": release.channel})
        return response


def delete_withdrawn_release_package(*, actor, release_id, confirmed: bool, idempotency_key: str, request_id: str, ip_address: str | None) -> dict[str, Any]:
    if not confirmed:
        raise ReleaseOperationError("CONFIRMATION_REQUIRED", "删除已撤回安装包必须确认。", status=400)
    key = _idempotency_key(idempotency_key)
    request_hash = hashlib.sha256(f"{release_id}|delete_package".encode("utf-8")).hexdigest()
    storage = _configured_storage_adapter()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.DELETE_PACKAGE, key=key, request_hash=request_hash)
        if existing is not None:
            return existing
        if release.status != ReleaseStatus.WITHDRAWN:
            raise ReleaseOperationError("RELEASE_NOT_WITHDRAWN", "只有已撤回版本可以删除安装包。", status=409)
        already_empty = not release.package_path
        storage_key = _package_storage_key(release)
        if release.package_path and not storage_key:
            raise ReleaseOperationError("OBJECT_STORAGE_UNAVAILABLE", "已撤回安装包无法定位，已拒绝删除。", status=503)
        if storage_key:
            try:
                storage.delete(storage_key)
            except ObjectStorageError as exc:
                raise ReleaseOperationError("OBJECT_STORAGE_UNAVAILABLE", "已撤回安装包无法删除，已拒绝操作。", status=503) from exc
        if not already_empty:
            release.package_path = ""
            release.package_deleted_at = timezone.now()
            release.save(update_fields=("package_path", "package_deleted_at"))
        response = _operation_response(release, repeated=False)
        ReleaseOperation.objects.create(actor=actor, release=release, action=ReleaseOperationAction.DELETE_PACKAGE, idempotency_key=key, request_hash=request_hash, response=response)
        record_event(
            actor=actor,
            action="release.package.delete",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Release",
            object_public_id=release.release_id,
            metadata={
                "software_id": release.software_id,
                "profile_id": release.profile.profile_id,
                "version": release.version,
                "channel": release.channel,
                "already_empty": already_empty,
            },
        )
        return response


def latest_public_release(*, software_id: str, profile_id: str, client_id: str, target: str, arch: str, channel: str, current_version: str | None = None) -> tuple[SoftwareProfile, Release | None, bool]:
    try:
        software = Software.objects.get(software_id=software_id)
        profile = SoftwareProfile.objects.get(software=software, profile_id=profile_id)
    except (Software.DoesNotExist, SoftwareProfile.DoesNotExist) as exc:
        raise ReleaseOperationError("PROFILE_NOT_FOUND", "软件或 Profile 不存在。", status=404) from exc
    if software.status not in (SoftwareStatus.ACTIVE, SoftwareStatus.TESTING) or profile.status not in (ProfileStatus.ACTIVE, ProfileStatus.TESTING):
        raise ReleaseOperationError("PROFILE_UNAVAILABLE", "软件或 Profile 当前不可用。", status=404)
    if (client_id, target, arch, channel) != (profile.client_id, profile.target, profile.arch, profile.channel):
        raise ReleaseOperationError("CLIENT_SCOPE_MISMATCH", "客户端身份与 Profile 不匹配。", status=403)
    releases = Release.objects.filter(
        software=software,
        profile=profile,
        target=target,
        arch=arch,
        channel=channel,
        status=ReleaseStatus.PUBLISHED,
    ).order_by("-published_at", "-created_at")
    release = next(
        (
            candidate
            for candidate in sorted(releases, key=lambda item: _version_tuple(item.version), reverse=True)
            if release_is_client_distributable(candidate)
        ),
        None,
    )
    if not isinstance(current_version, str) or not current_version.strip() or len(current_version) > 64 or not PUBLISH_VERSION_RE.fullmatch(current_version.strip()):
        raise ReleaseOperationError("INVALID_VERSION", "请提供当前软件的三段版本号，例如 1.2.3。", status=400)
    current = _version_tuple(_version(current_version))
    has_update = bool(release and _version_tuple(release.version) > current)
    return profile, release, has_update


def _registry_fallback_version(release: Release) -> str | None:
    """Highest version still published **and reachable by clients** in this scope.

    `latest_public_release` skips a published release when it has neither a
    download URL nor a verified package on disk.  The fallback hint shown to
    administrators has to use the same rule, otherwise the page can promise
    "clients will move to v2.0.5" while clients actually receive v2.0.3.
    """

    remaining = [
        item
        for item in Release.objects.filter(
            software_id=release.software_id,
            profile=release.profile,
            channel=release.channel,
            status=ReleaseStatus.PUBLISHED,
        )
        if release_is_client_distributable(item)
    ]
    fallback = max(remaining, key=lambda item: _version_tuple(item.version), default=None)
    return fallback.version if fallback else None


def archive_release(*, actor, release_id, reason: str, idempotency_key: str, request_id: str, ip_address: str | None) -> dict[str, Any]:
    """Hide one historical version from the default list without deleting it.

    Archiving keeps the version number occupied, keeps the operation history and
    keeps the audit trail.  Archiving a published version also removes it from
    the public registry, so the response reports the fallback version.
    """

    key = _idempotency_key(idempotency_key)
    reason = _required_string(reason, "归档原因", 255)
    if len(reason) < 4:
        raise ReleaseOperationError("INVALID_INPUT", "归档原因至少需要 4 个字符。")
    request_hash = hashlib.sha256(f"{release_id}|archive|{reason}".encode("utf-8")).hexdigest()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(actor=actor, action=ReleaseOperationAction.ARCHIVE, key=key, request_hash=request_hash)
        if existing is not None:
            return existing
        if release.status not in {ReleaseStatus.PUBLISHED, ReleaseStatus.WITHDRAWN}:
            raise ReleaseOperationError(
                "RELEASE_NOT_ARCHIVABLE",
                "只有已发布或已撤回的版本可以归档；草稿请直接丢弃。",
                status=409,
            )
        previous_status = release.status
        release.status = ReleaseStatus.ARCHIVED
        release.archived_at = timezone.now()
        release.archived_from_status = previous_status
        release.archive_reason = reason
        release.save(update_fields=("status", "archived_at", "archived_from_status", "archive_reason"))
        fallback_version = _registry_fallback_version(release) if previous_status == ReleaseStatus.PUBLISHED else None
        response = _operation_response(release, repeated=False)
        response["registry_fallback_version"] = fallback_version
        ReleaseOperation.objects.create(
            actor=actor,
            release=release,
            action=ReleaseOperationAction.ARCHIVE,
            idempotency_key=key,
            request_hash=request_hash,
            response=response,
        )
        record_event(
            actor=actor,
            action="release.archive",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Release",
            object_public_id=release.release_id,
            metadata={
                "software_id": release.software_id,
                "profile_id": release.profile.profile_id,
                "version": release.version,
                "channel": release.channel,
                "before_status": previous_status,
                "after_status": ReleaseStatus.ARCHIVED,
                "registry_fallback_version": fallback_version,
                "reason_length": len(reason),
            },
        )
        return response


def update_release_version(
    *,
    actor,
    release_id,
    version: str,
    reason: str,
    idempotency_key: str,
    request_id: str,
    ip_address: str | None,
) -> dict[str, Any]:
    """Rename the version number of a published external-link release in place.

    This exists for the "same download URL, replaced file" workflow: bumping the
    number is what makes clients see an update, and doing it in place keeps the
    history list from growing. Uploaded ZIP manifests are signed and cannot be
    rewritten. The new number must be highest in its own published scope.
    """

    key = _idempotency_key(idempotency_key)
    reason = _required_string(reason, "改号原因", 255)
    if len(reason) < 4:
        raise ReleaseOperationError("INVALID_INPUT", "改号原因至少需要 4 个字符。")
    new_version = _version(version)
    request_hash = hashlib.sha256(
        f"{release_id}|version|{new_version}|{reason}".encode("utf-8")
    ).hexdigest()
    with transaction.atomic():
        try:
            release = Release.objects.select_for_update().select_related("software", "profile").get(pk=release_id)
        except Release.DoesNotExist as exc:
            raise ReleaseOperationError("RELEASE_NOT_FOUND", "版本不存在。", status=404) from exc
        existing = _existing_operation(
            actor=actor,
            action=ReleaseOperationAction.UPDATE_VERSION,
            key=key,
            request_hash=request_hash,
        )
        if existing is not None:
            return existing
        if release.status != ReleaseStatus.PUBLISHED:
            raise ReleaseOperationError(
                "RELEASE_NOT_RENUMBERABLE",
                "只有已发布版本可以改版本号；已撤回版本请归档，草稿请丢弃后重发。",
                status=409,
            )
        if not str(release.external_download_url or "").strip():
            raise ReleaseOperationError(
                "RELEASE_NOT_RENUMBERABLE",
                "本站 ZIP 不能就地改版本号，请重新构建并签名后发布新版本。",
                status=409,
            )
        previous_version = release.version
        if previous_version == new_version:
            raise ReleaseOperationError("VERSION_UNCHANGED", "新版本号与当前版本号相同。", status=409)
        conflict = (
            Release.objects.filter(
                software=release.software,
                profile=release.profile,
                target=release.target,
                arch=release.arch,
                channel=release.channel,
                version=new_version,
            )
            .exclude(status=ReleaseStatus.DISCARDED)
            .exclude(pk=release.pk)
            .exists()
        )
        if conflict:
            raise ReleaseOperationError(
                "VERSION_ALREADY_EXISTS",
                "这个版本号已被同一软件、平台和通道的另一条版本占用。",
                status=409,
            )
        highest_other = max(
            (
                item
                for item in Release.objects.filter(
                    software=release.software,
                    profile=release.profile,
                    target=release.target,
                    arch=release.arch,
                    channel=release.channel,
                    status=ReleaseStatus.PUBLISHED,
                ).exclude(pk=release.pk)
            ),
            key=lambda item: _version_tuple(item.version),
            default=None,
        )
        if highest_other is not None and _version_tuple(new_version) <= _version_tuple(highest_other.version):
            raise ReleaseOperationError(
                "VERSION_NOT_HIGHEST",
                f"新版本号必须高于当前分发中的 v{highest_other.version}，否则客户端收不到更新。",
                status=409,
            )
        manifest = dict(release.manifest or {})
        manifest["version"] = new_version
        release.version = new_version
        release.manifest = manifest
        release.save(update_fields=("version", "manifest"))
        response = _operation_response(release, repeated=False)
        response["previous_version"] = previous_version
        try:
            ReleaseOperation.objects.create(
                actor=actor,
                release=release,
                action=ReleaseOperationAction.UPDATE_VERSION,
                idempotency_key=key,
                request_hash=request_hash,
                response=response,
            )
        except IntegrityError:
            existing = _existing_operation(
                actor=actor,
                action=ReleaseOperationAction.UPDATE_VERSION,
                key=key,
                request_hash=request_hash,
            )
            if existing is not None:
                return existing
            raise ReleaseOperationError("IDEMPOTENCY_CONFLICT", "重复提交标识对应了不同请求。", status=409)
        record_event(
            actor=actor,
            action="release.version.update",
            outcome=AuditOutcome.SUCCESS,
            request_id=request_id,
            ip_address=ip_address,
            object_type="Release",
            object_public_id=release.release_id,
            metadata={
                "software_id": release.software_id,
                "profile_id": release.profile.profile_id,
                "channel": release.channel,
                "before_version": previous_version,
                "after_version": new_version,
                "reason_length": len(reason),
            },
        )
        return response
