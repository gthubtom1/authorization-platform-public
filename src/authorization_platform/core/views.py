from __future__ import annotations

import ipaddress
import logging
import uuid

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder
from django.http import JsonResponse
from django.shortcuts import render

from .time import BEIJING, SystemClock, iso_z, to_beijing


logger = logging.getLogger(__name__)


def _is_internal_caller(request) -> bool:
    """True for our own nginx / host, false for the public internet.

    The cache round-trip must not be triggerable by an anonymous caller, but
    the probe also has to actually run in the real deployment: behind the
    container bridge the peer address is neither loopback nor obviously local,
    so "loopback only" would silently skip the check exactly where it matters.
    """

    raw = request.META.get("REMOTE_ADDR") or ""
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    return any(address in network for network in getattr(settings, "TRUSTED_PROXY_NETWORKS", ()))


def _unapplied_migrations() -> list[str]:
    """Leaf migrations the database has not applied yet.

    Code that references a column the database does not have yet answers 500
    while the connection is perfectly healthy, so a plain connectivity probe
    cannot see it.  Returns an empty list when the check itself cannot run --
    an unreadable disk must not be reported as a broken site.
    """

    try:
        applied = set(MigrationRecorder(connection).applied_migrations())
        leaves = set(MigrationLoader(connection, ignore_no_migrations=True).graph.leaf_nodes())
        return sorted(leaves - applied)
    except Exception:
        logger.warning("health check could not read migration state", exc_info=True)
        return []


def healthz(request):
    """Operational probe.

    503 means "requests will fail right now": the database is unreachable, the
    shared cache is unreachable (every rate limit in the platform is built on
    it, and a missing cache table makes the login path raise), or migrations
    are pending.  Disk pressure and a low cache headroom are reported as
    warnings instead, because the node can still serve and restarting it would
    not help.

    The cache round-trip writes one short-lived key, so it only runs for
    internal callers (our own nginx, the host, the app-guard timer).  An
    unauthenticated external probe must not be able to churn the cache table
    that the rate limiter depends on.
    """

    now = SystemClock().now()
    base = {
        "service": "authorization-platform",
        "server_time": iso_z(now),
        "display_time": to_beijing(now).isoformat(timespec="seconds"),
        "display_timezone": str(BEIJING),
    }

    try:
        connection.ensure_connection()
    except Exception:
        logger.warning("health check database connection failed")
        return JsonResponse({**base, "status": "error", "database": "unavailable"}, status=503)

    blockers: list[str] = []
    warnings: list[str] = []

    pending = _unapplied_migrations()
    migrations = "ok"
    if pending:
        # Report the count, not the names: migration labels are internal and
        # this endpoint is unauthenticated.
        migrations = "pending"
        blockers.append("migrations_pending")
        logger.error("health check found %d unapplied migration(s)", len(pending))

    cache_status = "skipped"
    if _is_internal_caller(request):
        key = f"healthz:{uuid.uuid4().hex}"
        try:
            cache.set(key, "1", timeout=10)
            reachable = cache.get(key) == "1"
        except Exception:
            logger.warning("health check cache round trip failed", exc_info=True)
            reachable = False
        finally:
            try:
                cache.delete(key)
            except Exception:
                pass
        if reachable:
            cache_status = "ok"
        else:
            cache_status = "unavailable"
            blockers.append("cache_unavailable")

    disk: dict[str, int | float | str] = {}
    try:
        from .backup_governance import disk_capacity_for_path

        capacity = disk_capacity_for_path(str(settings.STORAGE_ROOT or "/"))
        disk = capacity.as_dict()
        if capacity.status != "ok":
            warnings.append(f"disk_{capacity.status}")
    except Exception:
        logger.warning("health check could not read disk capacity", exc_info=True)

    payload = {
        **base,
        "database": "ok",
        "migrations": migrations,
        "cache": cache_status,
    }
    if disk:
        payload["disk"] = disk
    if blockers:
        payload["status"] = "error"
        payload["blockers"] = blockers
        return JsonResponse(payload, status=503)
    payload["status"] = "ok"
    if warnings:
        payload["warnings"] = warnings
    return JsonResponse(payload)


def home(request):
    now = SystemClock().now()
    return render(
        request,
        "core/home.html",
        {
            "server_time": iso_z(now),
            "display_time": to_beijing(now).strftime("%Y-%m-%d %H:%M:%S"),
            "display_timezone": str(BEIJING),
        },
    )


def permission_denied(request, exception):
    """Render a safe, role-aware page for browser permission failures."""

    return render(request, "core/403.html", status=403)
