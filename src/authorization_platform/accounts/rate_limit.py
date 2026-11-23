from __future__ import annotations

import base64
import hashlib
import math
import pickle
import time
import unicodedata
import uuid
from datetime import datetime, timezone as dt_timezone
from threading import RLock

from django.conf import settings
from django.core.cache import cache, caches
from django.core.cache.backends.db import DatabaseCache
from django.core.cache.backends.locmem import LocMemCache
from django.core.cache.backends.memcached import BaseMemcachedCache
from django.core.cache.backends.redis import RedisCache
from django.db import IntegrityError, connections, router, transaction

_LOCAL_LOCK = RLock()
_MAX_ATTEMPTS = 16


def login_rate_identity(entrypoint: str, ip_address: str | None, username: str) -> str:
    # Match AuthenticationForm.UsernameField's length guard and NFKC behavior.
    normalized = unicodedata.normalize("NFKC", username) if len(username) <= 150 else username
    return f"{entrypoint}:{ip_address or 'unknown'}:{normalized.strip().casefold()}"


def login_allowed(entrypoint: str, ip_address: str | None, username: str) -> bool:
    source = f"{entrypoint}:{ip_address or 'unknown'}"
    return allow("login-source", source, limit=settings.AUTH_LOGIN_RATE_LIMIT) and allow(
        "login", login_rate_identity(entrypoint, ip_address, username), limit=settings.AUTH_LOGIN_RATE_LIMIT
    )


def registration_allowed(ip_address: str | None, invitation_hash: str) -> bool:
    source = ip_address or "unknown"
    return allow("register-source", source, limit=settings.AUTH_REGISTER_RATE_LIMIT) and allow(
        "register", f"{source}:{invitation_hash}", limit=settings.AUTH_REGISTER_RATE_LIMIT
    )


def _cache_key(scope: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"authorization-rate:{scope}:{digest}"


def _new_window(now: float, window: int) -> dict[str, float | int]:
    return {"count": 1, "expires_at": now + window}


def _read_window(raw, *, now: float) -> tuple[int, float]:
    if isinstance(raw, dict):
        try:
            return int(raw["count"]), float(raw["expires_at"])
        except (KeyError, TypeError, ValueError):
            return 0, now
    # DatabaseCache.incr 会把旧整数计数的 TTL 续成默认 300 秒。这类残留一律当窗口已过。
    return 0, now


def _local_allow(scope: str, identity: str, *, limit: int, timeout: int | None = None) -> bool:
    if limit <= 0:
        return True
    key = _cache_key(scope, identity)
    window = settings.AUTH_RATE_LIMIT_WINDOW_SECONDS if timeout is None else max(1, int(timeout))
    now = time.time()
    starter = _new_window(now, window)
    if cache.add(key, starter, timeout=window):
        return True
    raw = cache.get(key)
    if raw is None:
        if cache.add(key, starter, timeout=window):
            return True
        raw = cache.get(key)
        if raw is None:
            cache.set(key, starter, timeout=window)
            return True
    count, expires_at = _read_window(raw, now=now)
    if now >= expires_at:
        cache.set(key, _new_window(now, window), timeout=window)
        return True
    count += 1
    remaining = max(1, math.ceil(expires_at - now))
    cache.set(key, {"count": count, "expires_at": expires_at}, timeout=remaining)
    return count <= limit


def _database_allow(backend, key: str, *, limit: int, window: int) -> bool:
    """Compare-and-swap Django's existing cache row; never renew a live window.

    DatabaseCache.incr() is a get/set pair. Compare both serialized value and
    database expiry so simultaneous readers cannot both spend the same slot.
    Each failed insert is contained in a savepoint before retrying.
    """
    db = router.db_for_write(backend.cache_model_class)
    connection = connections[db]
    table = connection.ops.quote_name(backend._table)
    db_key = backend.make_and_validate_key(key)
    for _ in range(_MAX_ATTEMPTS):
        now = time.time()
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT value, expires FROM {table} WHERE cache_key = %s", [db_key])
            row = cursor.fetchone()
            if row:
                encoded, old_expiry = row
                raw = pickle.loads(base64.b64decode(connection.ops.process_clob(encoded).encode()))
                count, expires_at = _read_window(raw, now=now)
                replacement = _new_window(now, window) if now >= expires_at else {"count": count + 1, "expires_at": expires_at}
                new_value = base64.b64encode(pickle.dumps(replacement, backend.pickle_protocol)).decode("latin1")
                if now >= expires_at:
                    expiry = datetime.fromtimestamp(replacement["expires_at"], tz=dt_timezone.utc if settings.USE_TZ else None)
                    new_expiry = connection.ops.adapt_datetimefield_value(expiry)
                else:
                    new_expiry = old_expiry
                cursor.execute(
                    f"UPDATE {table} SET value = %s, expires = %s WHERE cache_key = %s AND value = %s AND expires = %s",
                    [new_value, new_expiry, db_key, encoded, old_expiry],
                )
                if cursor.rowcount == 1:
                    return replacement["count"] <= limit
            else:
                starter = _new_window(now, window)
                new_value = base64.b64encode(pickle.dumps(starter, backend.pickle_protocol)).decode("latin1")
                expiry = datetime.fromtimestamp(starter["expires_at"], tz=dt_timezone.utc if settings.USE_TZ else None)
                expiry = connection.ops.adapt_datetimefield_value(expiry)
                # Preserve the cache backend's expiry cleanup and capacity policy.
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                num = cursor.fetchone()[0]
                if num > backend._max_entries:
                    from django.utils import timezone
                    backend._cull(db, cursor, timezone.now(), num)
                try:
                    with transaction.atomic(using=db):
                        cursor.execute(f"INSERT INTO {table} (cache_key, value, expires) VALUES (%s, %s, %s)", [db_key, new_value, expiry])
                except IntegrityError:
                    continue
                return True
    return False


def _native_allow(backend, key: str, *, limit: int, window: int) -> bool:
    # A generation-specific counter prevents expiry/reset racing a new window.
    # Metadata is published once with add(); losing initializers never overwrite it.
    now = time.time()
    metadata = backend.get(key)
    if not isinstance(metadata, dict) or "generation" not in metadata:
        starter = {"expires_at": now + window, "generation": uuid.uuid4().hex}
        if backend.add(key, starter, timeout=window):
            metadata = starter
            if not backend.add(key + ":" + metadata["generation"], 0, timeout=window):
                return False
        else:
            metadata = backend.get(key)
    if not isinstance(metadata, dict) or not metadata.get("generation") or now >= metadata.get("expires_at", 0):
        return False
    counter = key + ":" + metadata["generation"]
    if isinstance(backend, RedisCache):
        # Django RedisCache.incr uses EXISTS then INCR. Do both atomically to
        # prevent expiration between them creating a permanent, unbounded key.
        db_key = backend.make_and_validate_key(counter)
        client = backend._cache.get_client(db_key, write=True)
        count = client.eval("if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end; return redis.call('INCR', KEYS[1])", 1, db_key)
        if count < 0:
            return False
    else:
        count = backend.incr(counter)  # Memcached INCR fails if the key expired.
    return time.time() < metadata["expires_at"] and count <= limit


def allow(scope: str, identity: str, *, limit: int, timeout: int | None = None) -> bool:
    if limit <= 0:
        return True
    backend = caches["default"]
    window = settings.AUTH_RATE_LIMIT_WINDOW_SECONDS if timeout is None else max(1, int(timeout))
    try:
        if isinstance(backend, DatabaseCache):
            return _database_allow(backend, _cache_key(scope, identity), limit=limit, window=window)
        if isinstance(backend, LocMemCache):
            with _LOCAL_LOCK:
                return _local_allow(scope, identity, limit=limit, timeout=window)
        if isinstance(backend, (RedisCache, BaseMemcachedCache)):
            return _native_allow(backend, _cache_key(scope, identity), limit=limit, window=window)
    except Exception:
        # An unavailable cache, malformed old row, or lost contention budget
        # must not turn an authentication/abuse budget into an allow result.
        return False
    return False


def blocked(scope: str, identity: str, *, limit: int) -> bool:
    """Read-only ceiling check.

    Used where a counter must be incremented only on failure (so that a
    successful request is never charged to the failure budget) but the
    decision to refuse has to be made before the expensive work runs.

    Mirrors ``allow``'s boundary: ``allow`` refuses the (limit + 1)-th call in
    a window, so the budget counts as exhausted once ``limit`` calls have been
    recorded.
    """

    if limit <= 0:
        return False
    try:
        key = _cache_key(scope, identity)
        raw = cache.get(key)
        if isinstance(raw, dict) and raw.get("generation"):
            count = cache.get(key + ":" + raw["generation"])
            return time.time() < raw["expires_at"] and (count is None or count >= limit)
        count, expires_at = _read_window(raw, now=time.time())
        return time.time() < expires_at and count >= limit
    except Exception:
        return True


def reset(scope: str, identity: str) -> None:
    try:
        # Generation counters expire naturally. Removing the metadata starts an
        # independent window; an in-flight old request cannot change that window.
        cache.delete(_cache_key(scope, identity))
    except Exception:
        pass
