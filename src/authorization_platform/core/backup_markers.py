"""Shared marker helpers for the backup health file.

These live in the app package (not in ``scripts/``) because the hourly
maintenance job runs inside the application container, where ``scripts/`` is
not present -- the Docker image only copies ``manage.py`` and ``src/``.  The
host-side ``scripts/backup_health.py`` imports the same functions so there is
exactly one implementation of the locking and permission handling.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def marker_lock(path: Path):
    """Serialize success/failure updates across overlapping systemd units."""

    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def publish_marker_for_app(path: Path) -> None:
    """Keep the marker readable by the app user (uid 10001) after root umask 0077 writes."""

    try:
        os.chmod(path, 0o640)
        parent = path.parent
        os.chown(path, parent.stat().st_uid, parent.stat().st_gid)
    except (AttributeError, OSError, NotImplementedError):
        return
