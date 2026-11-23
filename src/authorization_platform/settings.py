"""Small, explicit settings module for the local-first platform skeleton."""

from __future__ import annotations

import os
import base64
import hashlib
import ipaddress
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_networks(values: list[str], *, setting_name: str) -> tuple:
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise RuntimeError(f"{setting_name} contains an invalid network: {value}") from exc
    return tuple(networks)


def _is_valid_ed25519_public_key(value: str) -> bool:
    """Validate the raw public-key encoding without ever returning key material."""
    if not value:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if len(raw) != 32:
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError, base64.binascii.Error):
        return False
    return True


PLACEHOLDER_SECRET_PREFIXES = ("replace-with", "replace-this", "changeme", "change-me", "local-development-only")


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return any(lowered.startswith(prefix) for prefix in PLACEHOLDER_SECRET_PREFIXES)


def _secret_entropy_ok(value: str) -> tuple[bool, str]:
    """Judge whether a secret looks machine-generated rather than typed.

    Returns (ok, reason).  The check must accept every ordinary generator
    output — a 64-char hex token from `secrets.token_hex(32)` has only two
    character classes but is perfectly strong — so character-class diversity is
    not required on its own.  What is rejected is a value that is too short, or
    one built from a tiny alphabet of repeated material (the published
    placeholder shape).
    """

    # 43 characters is the base64url encoding of 32 bytes, i.e. the shortest
    # encoding that still carries 256 bits.  Anything shorter cannot be a
    # full-strength generated secret regardless of how it looks.
    if len(value) < 43:
        return False, f"{len(value)} characters is shorter than the required 43"
    if len(set(value)) < 12:
        return False, "uses fewer than 12 distinct characters"
    classes = sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )
    # Two classes are enough when the alphabet is wide (hex, base64url); a
    # single-class value of only letters or only digits is too easy to guess.
    if classes >= 2:
        return True, ""
    return False, "uses only one character class (letters or digits alone)"


def _require_strong_secret(name: str, value: str | None) -> None:
    """Non-local environments must inject real, non-placeholder secrets."""

    if not value:
        raise RuntimeError(f"{name} must be configured outside local development")
    if _looks_like_placeholder(value):
        raise RuntimeError(f"{name} must not use the published example placeholder")
    ok, reason = _secret_entropy_ok(value)
    if not ok:
        raise RuntimeError(f"{name} is not a strong random secret: {reason}")


def _require_distinct_production_secrets(values: dict[str, str | None]) -> None:
    if APP_ENV == "local":
        return
    empty = sorted(name for name, value in values.items() if not value)
    if empty:
        raise RuntimeError("missing production key settings: " + ", ".join(empty))
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for name, value in values.items():
        assert value is not None
        if value == SECRET_KEY:
            duplicates.append(f"{name}=DJANGO_SECRET_KEY")
        previous = seen.get(value)
        if previous:
            duplicates.append(f"{name}={previous}")
        else:
            seen[value] = name
    if duplicates:
        raise RuntimeError("production key settings must be independent: " + ", ".join(sorted(duplicates)))


APP_ENV = os.getenv("APP_ENV", "local").strip().lower()
if APP_ENV not in {"local", "test", "production"}:
    raise RuntimeError("APP_ENV must be one of local, test, or production")
DEBUG = env_bool("DJANGO_DEBUG", APP_ENV == "local")
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "local-development-only-change-me")
# Non-local environments (test platform, production) must never run on the
# published example values: session signing and several derived keys depend on
# this secret, so a placeholder would be publicly derivable.
if APP_ENV != "local":
    _require_strong_secret("DJANGO_SECRET_KEY", SECRET_KEY)
if APP_ENV != "local" and DEBUG:
    raise RuntimeError("DJANGO_DEBUG must be false outside local development")

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "127.0.0.1,localhost")
AUTHORIZATION_PUBLIC_BASE_URL = os.getenv("AUTHORIZATION_PUBLIC_BASE_URL", "").strip().rstrip("/")
CSRF_TRUSTED_ORIGINS = env_list(
    "CSRF_TRUSTED_ORIGINS",
    "http://127.0.0.1:8123,http://localhost:8123",
)
TRUSTED_PROXY_IPS = env_list("TRUSTED_PROXY_IPS", "")
TRUSTED_PROXY_NETWORKS = _parse_networks(TRUSTED_PROXY_IPS, setting_name="TRUSTED_PROXY_IPS")
TRUST_PROXY_SSL_HEADER = env_bool("TRUST_PROXY_SSL_HEADER", False)

if APP_ENV != "local":
    if not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS or any(host in {"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"} for host in ALLOWED_HOSTS):
        raise RuntimeError("ALLOWED_HOSTS must contain explicit production hostnames")
    if not CSRF_TRUSTED_ORIGINS or any(not origin.lower().startswith("https://") for origin in CSRF_TRUSTED_ORIGINS):
        raise RuntimeError("CSRF_TRUSTED_ORIGINS must contain only https origins in production")
    if TRUST_PROXY_SSL_HEADER and not TRUSTED_PROXY_NETWORKS:
        raise RuntimeError("TRUSTED_PROXY_IPS is required when TRUST_PROXY_SSL_HEADER is enabled")
    if not TRUSTED_PROXY_NETWORKS:
        raise RuntimeError("TRUSTED_PROXY_IPS must be configured outside local development")

_invitation_key = os.getenv("INVITATION_ENCRYPTION_KEY")
if APP_ENV != "local" and not _invitation_key:
    raise RuntimeError("INVITATION_ENCRYPTION_KEY must be configured outside local development")
if APP_ENV != "local" and _looks_like_placeholder(_invitation_key or ""):
    raise RuntimeError("INVITATION_ENCRYPTION_KEY must not use the published example placeholder")
if not _invitation_key:
    _invitation_key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()).decode("ascii")
INVITATION_ENCRYPTION_KEY = _invitation_key
INVITATION_ENCRYPTION_KEY_VERSION = os.getenv("INVITATION_ENCRYPTION_KEY_VERSION", "v1")
INVITATION_MAX_BATCH_SIZE = int(os.getenv("INVITATION_MAX_BATCH_SIZE", "1000"))
INVITATION_ISSUE_TOKEN_TTL_SECONDS = int(os.getenv("INVITATION_ISSUE_TOKEN_TTL_SECONDS", "900"))
INVITATION_ISSUE_RATE_LIMIT = int(os.getenv("INVITATION_ISSUE_RATE_LIMIT", "20"))
INVITATION_REVEAL_RATE_LIMIT = int(os.getenv("INVITATION_REVEAL_RATE_LIMIT", "20"))
INVITATION_SEARCH_RATE_LIMIT = int(os.getenv("INVITATION_SEARCH_RATE_LIMIT", "30"))
if APP_ENV != "local" and INVITATION_ISSUE_RATE_LIMIT <= 0:
    raise RuntimeError("production cannot disable INVITATION_ISSUE_RATE_LIMIT")
AUTH_LOGIN_RATE_LIMIT = int(os.getenv("AUTH_LOGIN_RATE_LIMIT", "10"))
AUTH_REGISTER_RATE_LIMIT = int(os.getenv("AUTH_REGISTER_RATE_LIMIT", "10"))
AUTH_PASSWORD_CHANGE_RATE_LIMIT = int(os.getenv("AUTH_PASSWORD_CHANGE_RATE_LIMIT", "5"))
AUTH_PASSWORD_RESET_RATE_LIMIT = int(os.getenv("AUTH_PASSWORD_RESET_RATE_LIMIT", "10"))
AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "300"))
# A zero or one-second window silently disables login/password brute-force
# protection. Only local development may turn these off.
if APP_ENV != "local":
    if AUTH_RATE_LIMIT_WINDOW_SECONDS < 10:
        raise RuntimeError("AUTH_RATE_LIMIT_WINDOW_SECONDS must be at least 10 outside local development")
    _disabled_auth_limits = [
        name
        for name, value in {
            "AUTH_LOGIN_RATE_LIMIT": AUTH_LOGIN_RATE_LIMIT,
            "AUTH_REGISTER_RATE_LIMIT": AUTH_REGISTER_RATE_LIMIT,
            "AUTH_PASSWORD_CHANGE_RATE_LIMIT": AUTH_PASSWORD_CHANGE_RATE_LIMIT,
            "AUTH_PASSWORD_RESET_RATE_LIMIT": AUTH_PASSWORD_RESET_RATE_LIMIT,
        }.items()
        if value <= 0
    ]
    if _disabled_auth_limits:
        raise RuntimeError("production cannot disable: " + ", ".join(sorted(_disabled_auth_limits)))
_password_operation_hash_key = os.getenv("PASSWORD_OPERATION_HASH_KEY")
if APP_ENV != "local" and not _password_operation_hash_key:
    raise RuntimeError("PASSWORD_OPERATION_HASH_KEY must be configured outside local development")
PASSWORD_OPERATION_HASH_KEY = _password_operation_hash_key or SECRET_KEY
_account_operation_hash_key = os.getenv("ACCOUNT_OPERATION_HASH_KEY")
if APP_ENV != "local" and not _account_operation_hash_key:
    raise RuntimeError("ACCOUNT_OPERATION_HASH_KEY must be configured outside local development")
ACCOUNT_OPERATION_HASH_KEY = _account_operation_hash_key or SECRET_KEY
PUBLIC_LICENSE_RATE_LIMIT = int(os.getenv("PUBLIC_LICENSE_RATE_LIMIT", "120"))
if APP_ENV != "local" and PUBLIC_LICENSE_RATE_LIMIT <= 0:
    raise RuntimeError("production cannot disable PUBLIC_LICENSE_RATE_LIMIT")
PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT = int(os.getenv("PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT", "3"))
PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT = int(os.getenv("PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT", "100"))
PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS = int(os.getenv("PUBLIC_RELEASE_DOWNLOAD_WINDOW_SECONDS", "1800"))
PUBLIC_RELEASE_REGISTRY_RATE_LIMIT = int(os.getenv("PUBLIC_RELEASE_REGISTRY_RATE_LIMIT", "60"))
PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS = int(os.getenv("PUBLIC_RELEASE_REGISTRY_WINDOW_SECONDS", "60"))
if APP_ENV != "local" and PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT <= 0:
    raise RuntimeError("production cannot disable PUBLIC_RELEASE_DOWNLOAD_RATE_LIMIT")
if APP_ENV != "local" and PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT <= 0:
    raise RuntimeError("production cannot disable PUBLIC_RELEASE_DOWNLOAD_IP_RATE_LIMIT")
if APP_ENV != "local" and env_bool("RELEASE_DOWNLOAD_REQUIRE_AUTH", False):
    raise RuntimeError("production cannot require card-gated release downloads")
RELEASE_DOWNLOAD_REQUIRE_AUTH = env_bool("RELEASE_DOWNLOAD_REQUIRE_AUTH", False)
DISABLE_LEGACY_BATCH_VIEWS = env_bool("DISABLE_LEGACY_BATCH_VIEWS", APP_ENV == "production")
QUOTA_CARD_MAX_BATCH_SIZE = int(os.getenv("QUOTA_CARD_MAX_BATCH_SIZE", "1000"))
QUOTA_CARD_MAX_AMOUNT = int(os.getenv("QUOTA_CARD_MAX_AMOUNT", "1000000000"))
_quota_card_hash_key = os.getenv("QUOTA_CARD_HASH_KEY")
if APP_ENV != "local" and not _quota_card_hash_key:
    raise RuntimeError("QUOTA_CARD_HASH_KEY must be configured outside local development")
QUOTA_CARD_HASH_KEY = _quota_card_hash_key or SECRET_KEY
_quota_redeem_ip_hash_key = os.getenv("QUOTA_REDEEM_IP_HASH_KEY")
if APP_ENV != "local" and not _quota_redeem_ip_hash_key:
    raise RuntimeError("QUOTA_REDEEM_IP_HASH_KEY must be configured outside local development")
QUOTA_REDEEM_IP_HASH_KEY = _quota_redeem_ip_hash_key or SECRET_KEY
QUOTA_REDEEM_RATE_LIMIT = int(os.getenv("QUOTA_REDEEM_RATE_LIMIT", "10"))
QUOTA_CARD_REVEAL_RATE_LIMIT = int(os.getenv("QUOTA_CARD_REVEAL_RATE_LIMIT", "20"))
QUOTA_CARD_SEARCH_RATE_LIMIT = int(os.getenv("QUOTA_CARD_SEARCH_RATE_LIMIT", "30"))
_quota_card_key = os.getenv("QUOTA_CARD_ENCRYPTION_KEY")
if APP_ENV != "local" and not _quota_card_key:
    raise RuntimeError("QUOTA_CARD_ENCRYPTION_KEY must be configured outside local development")
if not _quota_card_key:
    _quota_card_key = base64.urlsafe_b64encode(
        hashlib.sha256(f"quota-card:{SECRET_KEY}".encode("utf-8")).digest()
    ).decode("ascii")
QUOTA_CARD_ENCRYPTION_KEY = _quota_card_key
QUOTA_CARD_ENCRYPTION_KEY_VERSION = os.getenv("QUOTA_CARD_ENCRYPTION_KEY_VERSION", "v2")
# Existing local/early-candidate quota cards used the invitation key and are
# marked v1. Production must inject this legacy key when such rows still exist;
# an empty value deliberately makes legacy reveal/rotation fail closed.
QUOTA_CARD_LEGACY_ENCRYPTION_KEY = os.getenv(
    "QUOTA_CARD_LEGACY_ENCRYPTION_KEY",
    INVITATION_ENCRYPTION_KEY if APP_ENV == "local" else "",
)
QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION = os.getenv("QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION", "v1")
LICENSE_CARD_MAX_BATCH_SIZE = int(os.getenv("LICENSE_CARD_MAX_BATCH_SIZE", "1000"))
LICENSE_CARD_MAX_TOTAL_COST = int(os.getenv("LICENSE_CARD_MAX_TOTAL_COST", "1000000000"))
LICENSE_CARD_PREVIEW_TTL_SECONDS = int(os.getenv("LICENSE_CARD_PREVIEW_TTL_SECONDS", "600"))
_license_card_hash_key = os.getenv("LICENSE_CARD_HASH_KEY")
if APP_ENV != "local" and not _license_card_hash_key:
    raise RuntimeError("LICENSE_CARD_HASH_KEY must be configured outside local development")
LICENSE_CARD_HASH_KEY = _license_card_hash_key or SECRET_KEY
_license_card_key = os.getenv("LICENSE_CARD_ENCRYPTION_KEY")
if APP_ENV != "local" and not _license_card_key:
    raise RuntimeError("LICENSE_CARD_ENCRYPTION_KEY must be configured outside local development")
if not _license_card_key:
    _license_card_key = base64.urlsafe_b64encode(
        hashlib.sha256(f"license-card:{SECRET_KEY}".encode("utf-8")).digest()
    ).decode("ascii")
LICENSE_CARD_ENCRYPTION_KEY = _license_card_key
LICENSE_CARD_ENCRYPTION_KEY_VERSION = os.getenv("LICENSE_CARD_ENCRYPTION_KEY_VERSION", "v1")
# Local databases created before the dedicated key was introduced used the
# invitation key. Keep that key only as an explicit legacy-read path; new
# cards are always encrypted with LICENSE_CARD_ENCRYPTION_KEY. Production
# deployments must provide a legacy key explicitly if they still have v1 data.
LICENSE_CARD_LEGACY_ENCRYPTION_KEY = os.getenv(
    "LICENSE_CARD_LEGACY_ENCRYPTION_KEY",
    INVITATION_ENCRYPTION_KEY if APP_ENV == "local" else "",
)
LICENSE_CARD_REVEAL_RATE_LIMIT = int(os.getenv("LICENSE_CARD_REVEAL_RATE_LIMIT", "20"))
LICENSE_CARD_PREVIEW_RATE_LIMIT = int(os.getenv("LICENSE_CARD_PREVIEW_RATE_LIMIT", "30"))
LICENSE_CARD_ISSUE_RATE_LIMIT = int(os.getenv("LICENSE_CARD_ISSUE_RATE_LIMIT", "20"))
LICENSE_CARD_SEARCH_RATE_LIMIT = int(os.getenv("LICENSE_CARD_SEARCH_RATE_LIMIT", "30"))
LICENSE_CARD_RECLAIM_RATE_LIMIT = int(os.getenv("LICENSE_CARD_RECLAIM_RATE_LIMIT", "20"))
LICENSE_CARD_LIFECYCLE_RATE_LIMIT = int(os.getenv("LICENSE_CARD_LIFECYCLE_RATE_LIMIT", "20"))
LICENSE_CARD_EXPORT_RATE_LIMIT = int(os.getenv("LICENSE_CARD_EXPORT_RATE_LIMIT", "10"))
AUTHORIZATION_ADMIN_ACTION_REF_TTL_SECONDS = int(os.getenv("AUTHORIZATION_ADMIN_ACTION_REF_TTL_SECONDS", "900"))
AUTHORIZATION_SIGNING_PRIVATE_KEY = os.getenv("AUTHORIZATION_SIGNING_PRIVATE_KEY", "")
AUTHORIZATION_SIGNING_KEY_ID = os.getenv("AUTHORIZATION_SIGNING_KEY_ID", "platform-dev-v1")
_authorization_nonce_hash_key = os.getenv("AUTHORIZATION_NONCE_HASH_KEY")
_authorization_device_hash_key = os.getenv("AUTHORIZATION_DEVICE_HASH_KEY")
if APP_ENV != "local" and not _authorization_nonce_hash_key:
    raise RuntimeError("AUTHORIZATION_NONCE_HASH_KEY must be configured outside local development")
if APP_ENV != "local" and not _authorization_device_hash_key:
    raise RuntimeError("AUTHORIZATION_DEVICE_HASH_KEY must be configured outside local development")
AUTHORIZATION_NONCE_HASH_KEY = _authorization_nonce_hash_key or SECRET_KEY
AUTHORIZATION_DEVICE_HASH_KEY = _authorization_device_hash_key or SECRET_KEY

if APP_ENV != "local" and not AUTHORIZATION_SIGNING_PRIVATE_KEY:
    raise RuntimeError("AUTHORIZATION_SIGNING_PRIVATE_KEY must be configured outside local development")
if APP_ENV != "local" and _looks_like_placeholder(AUTHORIZATION_SIGNING_PRIVATE_KEY):
    raise RuntimeError("AUTHORIZATION_SIGNING_PRIVATE_KEY must not use the published example placeholder")
if APP_ENV != "local" and AUTHORIZATION_SIGNING_KEY_ID == "platform-dev-v1":
    raise RuntimeError("AUTHORIZATION_SIGNING_KEY_ID must identify a managed production key")

RELEASE_MAX_PACKAGE_BYTES = int(os.getenv("RELEASE_MAX_PACKAGE_BYTES", str(500 * 1024 * 1024)))
RELEASE_SIGNING_PUBLIC_KEY = os.getenv("RELEASE_SIGNING_PUBLIC_KEY", "").strip()
RELEASE_SIGNING_KEY_ID = os.getenv("RELEASE_SIGNING_KEY_ID", "").strip()
if APP_ENV != "local" and os.getenv("RELEASE_REQUIRE_VERIFIED_SIGNATURE") is not None and not env_bool("RELEASE_REQUIRE_VERIFIED_SIGNATURE", True):
    raise RuntimeError("production cannot disable RELEASE_REQUIRE_VERIFIED_SIGNATURE")
RELEASE_REQUIRE_VERIFIED_SIGNATURE = True if APP_ENV != "local" else env_bool("RELEASE_REQUIRE_VERIFIED_SIGNATURE", False)
STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", str(BASE_DIR / "storage"))).resolve()
RELEASE_STORAGE_ROOT = Path(os.getenv("RELEASE_STORAGE_ROOT", str(STORAGE_ROOT / "releases"))).resolve()
STORAGE_CLEANUP_RETENTION_DAYS = int(os.getenv("STORAGE_CLEANUP_RETENTION_DAYS", "30"))
# 授权请求记录（幂等台账）的保留期。每次成功的 verify 会写一行，而它带完整签名
# 响应体，实测约 1.8KB/行，不清就是无界增长。客户端的重试窗口以分钟计，30 天
# 远超运营需求；超期后同 key 重试会按 REPLAY_DETECTED 拒绝，这是有意的。
AUTHORIZATION_REQUEST_RECORD_RETENTION_DAYS = int(
    os.getenv("AUTHORIZATION_REQUEST_RECORD_RETENTION_DAYS", "30")
)
STORAGE_CLEANUP_MAX_FILES = int(os.getenv("STORAGE_CLEANUP_MAX_FILES", "1000"))
STORAGE_CLEANUP_MAX_BYTES = int(os.getenv("STORAGE_CLEANUP_MAX_BYTES", str(5 * 1024 * 1024 * 1024)))

OBJECT_STORAGE_PROVIDER = os.getenv("OBJECT_STORAGE_PROVIDER", "local").strip().lower()
OBJECT_STORAGE_ENDPOINT = os.getenv("OBJECT_STORAGE_ENDPOINT", "").strip().rstrip("/")
OBJECT_STORAGE_BUCKET = os.getenv("OBJECT_STORAGE_BUCKET", "").strip()
OBJECT_STORAGE_REGION = os.getenv("OBJECT_STORAGE_REGION", "").strip()
OBJECT_STORAGE_ACCESS_KEY_ID = os.getenv("OBJECT_STORAGE_ACCESS_KEY_ID", "").strip()
OBJECT_STORAGE_SECRET_ACCESS_KEY = os.getenv("OBJECT_STORAGE_SECRET_ACCESS_KEY", "")
OBJECT_STORAGE_CA_CERT = os.getenv("OBJECT_STORAGE_CA_CERT", "").strip()
OBJECT_STORAGE_PUBLIC_BASE_URL = os.getenv("OBJECT_STORAGE_PUBLIC_BASE_URL", "").strip().rstrip("/")
OBJECT_STORAGE_PATH_STYLE = env_bool("OBJECT_STORAGE_PATH_STYLE", False)
OBJECT_STORAGE_SIGNED_URL_TTL_SECONDS = int(os.getenv("OBJECT_STORAGE_SIGNED_URL_TTL_SECONDS", "300"))

AUTHORIZATION_PLATFORM_WORKERS = int(os.getenv("AUTHORIZATION_PLATFORM_WORKERS", "2"))
DATABASE_CONN_MAX_AGE = int(os.getenv("DATABASE_CONN_MAX_AGE", "60"))

# Disaster recovery is a production prerequisite, not an optional admin
# convenience.  Local/test environments may leave this contract unconfigured;
# production settings fail closed before Django starts when it is incomplete.
BACKUP_PROVIDER = os.getenv("BACKUP_PROVIDER", "").strip().lower()
BACKUP_STANZA = os.getenv("BACKUP_STANZA", "").strip()
BACKUP_REPOSITORY_COUNT = int(os.getenv("BACKUP_REPOSITORY_COUNT", "0") or "0")
BACKUP_REPOSITORY_1 = os.getenv("BACKUP_REPOSITORY_1", "").strip()
BACKUP_REPOSITORY_2 = os.getenv("BACKUP_REPOSITORY_2", "").strip()
BACKUP_REPOSITORIES_INDEPENDENT = env_bool("BACKUP_REPOSITORIES_INDEPENDENT", False)
BACKUP_ENCRYPTION = os.getenv("BACKUP_ENCRYPTION", "").strip().lower()
BACKUP_CIPHER_PASSWORD_FILE = os.getenv("BACKUP_CIPHER_PASSWORD_FILE", "").strip()
BACKUP_REMOTE_TLS = env_bool("BACKUP_REMOTE_TLS", False)
BACKUP_WAL_ARCHIVING = os.getenv("BACKUP_WAL_ARCHIVING", "").strip().lower()
BACKUP_ARCHIVE_COMMAND_CONFIGURED = env_bool("BACKUP_ARCHIVE_COMMAND_CONFIGURED", False)
BACKUP_RETENTION_FULL = int(os.getenv("BACKUP_RETENTION_FULL", "0") or "0")
BACKUP_RETENTION_DIFF = int(os.getenv("BACKUP_RETENTION_DIFF", "0") or "0")
BACKUP_RETENTION_ARCHIVE = int(os.getenv("BACKUP_RETENTION_ARCHIVE", "0") or "0")
BACKUP_RPO_MINUTES = int(os.getenv("BACKUP_RPO_MINUTES", "0") or "0")
BACKUP_RTO_MINUTES = int(os.getenv("BACKUP_RTO_MINUTES", "0") or "0")
BACKUP_STATUS_FILE = os.getenv("BACKUP_STATUS_FILE", "").strip()
BACKUP_DOWNLOAD_DIR = Path(os.getenv("BACKUP_DOWNLOAD_DIR", str(BASE_DIR / "storage" / "backups"))).resolve()
BACKUP_ROOT = Path(os.getenv("BACKUP_ROOT", str(BACKUP_DOWNLOAD_DIR.parent))).resolve()
BACKUP_KEYS_DIR = Path(os.getenv("BACKUP_KEYS_DIR", str(BASE_DIR / "storage" / "backup-keys"))).resolve()
BACKUP_SCHEDULE_STAMP_DIR = Path(
    os.getenv("BACKUP_SCHEDULE_STAMP_DIR", str(BASE_DIR / "storage" / "backup-stamps"))
).resolve()
BACKUP_RESTORE_STAGING_DIR = Path(
    os.getenv("BACKUP_RESTORE_STAGING_DIR", str(BASE_DIR / "storage" / "backup-restore-staging"))
).resolve()
BACKUP_RESTORE_MAX_BYTES = int(os.getenv("BACKUP_RESTORE_MAX_BYTES", str(100 * 1024 * 1024)))
DATA_UPLOAD_MAX_MEMORY_SIZE = max(BACKUP_RESTORE_MAX_BYTES, int(os.getenv("DATA_UPLOAD_MAX_MEMORY_SIZE", str(100 * 1024 * 1024))))
FILE_UPLOAD_MAX_MEMORY_SIZE = int(os.getenv("FILE_UPLOAD_MAX_MEMORY_SIZE", str(2 * 1024 * 1024)))
BACKUP_FAILURE_ALERTING = env_bool("BACKUP_FAILURE_ALERTING", False)
BACKUP_FAILURE_HANDLER = os.getenv("BACKUP_FAILURE_HANDLER", "").strip()
BACKUP_WARN_FREE_PERCENT = int(os.getenv("BACKUP_WARN_FREE_PERCENT", "25") or "25")
BACKUP_CRITICAL_FREE_PERCENT = int(os.getenv("BACKUP_CRITICAL_FREE_PERCENT", "15") or "15")

if APP_ENV != "local":
    # Every secret that protects credentials or signed payloads must be its own
    # value.  Reusing DJANGO_SECRET_KEY (or another key) here would let a leak of
    # the session secret forge password-request digests and admin operations.
    #
    # The two legacy decryption keys are included when they are set: a non-local
    # environment must not silently alias the invitation key, because that would
    # make old card ciphertext decryptable with a key that also protects a
    # different credential class.
    _secrets_to_separate = {
        "INVITATION_ENCRYPTION_KEY": INVITATION_ENCRYPTION_KEY,
        "PASSWORD_OPERATION_HASH_KEY": PASSWORD_OPERATION_HASH_KEY,
        "ACCOUNT_OPERATION_HASH_KEY": ACCOUNT_OPERATION_HASH_KEY,
        "QUOTA_CARD_HASH_KEY": QUOTA_CARD_HASH_KEY,
        "QUOTA_REDEEM_IP_HASH_KEY": QUOTA_REDEEM_IP_HASH_KEY,
        "QUOTA_CARD_ENCRYPTION_KEY": QUOTA_CARD_ENCRYPTION_KEY,
        "LICENSE_CARD_HASH_KEY": LICENSE_CARD_HASH_KEY,
        "LICENSE_CARD_ENCRYPTION_KEY": LICENSE_CARD_ENCRYPTION_KEY,
        "AUTHORIZATION_NONCE_HASH_KEY": AUTHORIZATION_NONCE_HASH_KEY,
        "AUTHORIZATION_DEVICE_HASH_KEY": AUTHORIZATION_DEVICE_HASH_KEY,
        "AUTHORIZATION_SIGNING_PRIVATE_KEY": AUTHORIZATION_SIGNING_PRIVATE_KEY,
    }
    if QUOTA_CARD_LEGACY_ENCRYPTION_KEY:
        _secrets_to_separate["QUOTA_CARD_LEGACY_ENCRYPTION_KEY"] = QUOTA_CARD_LEGACY_ENCRYPTION_KEY
    if LICENSE_CARD_LEGACY_ENCRYPTION_KEY:
        _secrets_to_separate["LICENSE_CARD_LEGACY_ENCRYPTION_KEY"] = LICENSE_CARD_LEGACY_ENCRYPTION_KEY
    _require_distinct_production_secrets(_secrets_to_separate)

if APP_ENV == "production":
    if AUTHORIZATION_PLATFORM_WORKERS < 2:
        raise RuntimeError("AUTHORIZATION_PLATFORM_WORKERS must be at least 2 in production")
    if not RELEASE_SIGNING_KEY_ID or RELEASE_SIGNING_KEY_ID == "release-dev-v1":
        raise RuntimeError("RELEASE_SIGNING_KEY_ID must identify a managed production key")
    if not RELEASE_SIGNING_PUBLIC_KEY:
        raise RuntimeError("RELEASE_SIGNING_PUBLIC_KEY must be configured for production releases")
    if not _is_valid_ed25519_public_key(RELEASE_SIGNING_PUBLIC_KEY):
        raise RuntimeError("RELEASE_SIGNING_PUBLIC_KEY must be a valid base64url Ed25519 public key")
    if OBJECT_STORAGE_PROVIDER not in {"s3", "s3-compatible"}:
        raise RuntimeError("production requires OBJECT_STORAGE_PROVIDER=s3 or s3-compatible")
    if not OBJECT_STORAGE_ENDPOINT.lower().startswith("https://"):
        raise RuntimeError("production object storage endpoint must use HTTPS")
    _missing_object_storage = [
        name
        for name, value in {
            "OBJECT_STORAGE_ENDPOINT": OBJECT_STORAGE_ENDPOINT,
            "OBJECT_STORAGE_BUCKET": OBJECT_STORAGE_BUCKET,
            "OBJECT_STORAGE_REGION": OBJECT_STORAGE_REGION,
            "OBJECT_STORAGE_ACCESS_KEY_ID": OBJECT_STORAGE_ACCESS_KEY_ID,
            "OBJECT_STORAGE_SECRET_ACCESS_KEY": OBJECT_STORAGE_SECRET_ACCESS_KEY,
        }.items()
        if not value
    ]
    if _missing_object_storage:
        raise RuntimeError("missing production object storage settings: " + ", ".join(_missing_object_storage))
    from authorization_platform.core.backup_governance import validate_backup_environment

    _missing_backup_contract = [
        check.name for check in validate_backup_environment() if check.status != "passed"
    ]
    if _missing_backup_contract:
        raise RuntimeError("invalid production backup contract: " + ", ".join(_missing_backup_contract))

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "authorization_platform.core",
    "authorization_platform.audit",
    "authorization_platform.accounts",
    "authorization_platform.catalog",
    "authorization_platform.credits",
    "authorization_platform.licensing",
    "authorization_platform.releases",
    "authorization_platform.analytics",
    "authorization_platform.storage_cleanup",
    "authorization_platform.backup_control",
]

MIDDLEWARE = [
    "authorization_platform.core.middleware.TrustedProxyHeadersMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

CSRF_FAILURE_VIEW = "authorization_platform.accounts.api_views.api_csrf_failure"

ROOT_URLCONF = "authorization_platform.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "src" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "authorization_platform.accounts.context_processors.account_roles",
            ],
        },
    }
]

WSGI_APPLICATION = "authorization_platform.wsgi.application"
ASGI_APPLICATION = "authorization_platform.asgi.application"

DATABASE_ENGINE = os.getenv("DATABASE_ENGINE", "sqlite").strip().lower()
if APP_ENV == "production" and DATABASE_ENGINE != "postgresql":
    raise RuntimeError("production must use PostgreSQL")
if DATABASE_ENGINE == "postgresql":
    if APP_ENV == "production":
        _required_database_env = ("DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_HOST", "DATABASE_PORT")
        _missing_database_env = [name for name in _required_database_env if not os.getenv(name)]
        if _missing_database_env:
            raise RuntimeError("missing production database settings: " + ", ".join(_missing_database_env))
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DATABASE_NAME", "authorization_platform"),
            "USER": os.getenv("DATABASE_USER", "authorization_platform"),
            "PASSWORD": os.getenv("DATABASE_PASSWORD", ""),
            "HOST": os.getenv("DATABASE_HOST", "127.0.0.1"),
            "PORT": os.getenv("DATABASE_PORT", "5432"),
            "CONN_MAX_AGE": DATABASE_CONN_MAX_AGE,
            "CONN_HEALTH_CHECKS": True,
        }
    }
elif DATABASE_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / os.getenv("DATABASE_NAME", "local.sqlite3"),
        }
    }
else:
    raise RuntimeError("DATABASE_ENGINE must be sqlite or postgresql")

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "Asia/Shanghai"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = APP_ENV != "local"
CSRF_COOKIE_SECURE = APP_ENV != "local"
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
LOGIN_URL = "/auth/login/"

SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", APP_ENV == "production")
SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "31536000" if APP_ENV == "production" else "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", APP_ENV == "production")
SECURE_HSTS_PRELOAD = env_bool("SECURE_HSTS_PRELOAD", False)
SECURE_REFERRER_POLICY = os.getenv("SECURE_REFERRER_POLICY", "same-origin")
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if TRUST_PROXY_SSL_HEADER else None

# Only shared backends are allowed outside local development.  A DummyCache
# makes every rate-limit call succeed, and a per-process cache cannot enforce
# a shared limit across workers; both silently disable abuse protection.
SHARED_CACHE_BACKENDS = {
    "django.core.cache.backends.db.DatabaseCache",
    "django.core.cache.backends.redis.RedisCache",
    "django.core.cache.backends.memcached.PyMemcacheCache",
    "django.core.cache.backends.memcached.PyLibMCCache",
}
_cache_backend = os.getenv(
    "DJANGO_CACHE_BACKEND",
    "django.core.cache.backends.db.DatabaseCache" if APP_ENV != "local" else "django.core.cache.backends.locmem.LocMemCache",
)
if APP_ENV != "local" and _cache_backend not in SHARED_CACHE_BACKENDS:
    raise RuntimeError(
        "production cannot use this cache backend; configure a shared backend from SHARED_CACHE_BACKENDS"
    )
_cache_location = os.getenv("DJANGO_CACHE_LOCATION", "authorization_platform_cache" if APP_ENV == "local" else "django_cache")

# DatabaseCache culls by cache_key order once MAX_ENTRIES is exceeded, and the
# cull deletes rows that have not expired yet.  With the Django default of 300
# an attacker can flush its own rate-limit bucket by creating unrelated keys,
# so the ceiling must stay well above the expected number of live identities.
#
# MAX_ENTRIES is only meaningful for DatabaseCache.  Redis and memcached pass
# OPTIONS straight through to their client constructors, where MAX_ENTRIES is
# not a valid keyword, so sending it there would fail at first use.
_CACHE_BACKENDS_ACCEPTING_MAX_ENTRIES = {
    "django.core.cache.backends.db.DatabaseCache",
    "django.core.cache.backends.locmem.LocMemCache",
    "django.core.cache.backends.filebased.FileBasedCache",
}
_cache_options: dict[str, int] = {}
if _cache_backend in _CACHE_BACKENDS_ACCEPTING_MAX_ENTRIES:
    _cache_options["MAX_ENTRIES"] = int(os.getenv("DJANGO_CACHE_MAX_ENTRIES", "100000"))

CACHES = {
    "default": {
        "BACKEND": _cache_backend,
        "LOCATION": _cache_location,
        "TIMEOUT": int(os.getenv("DJANGO_CACHE_TIMEOUT", "300")),
        "OPTIONS": _cache_options,
    }
}

# Without an explicit LOGGING block Django only configures `django.*` loggers
# through the default dictConfig, and unhandled 500s from application code are
# invisible in the container logs.  A production incident that leaves no trace
# is worse than the incident itself, so route application and request errors to
# stderr at a level the operator can actually find.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(asctime)s %(levelname)s %(name)s %(process)d %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
    },
    "loggers": {
        # Unhandled view exceptions reach this logger and must be recorded.
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "authorization_platform": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_APP_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
    },
}

USE_X_FORWARDED_HOST = False
