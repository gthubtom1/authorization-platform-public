"""Stable, display-only device code derivation.

The authorization protocol continues to use ``installation_id`` as the
stable device identity.  This module derives a shorter support-facing code
without changing that identity or weakening device proof verification.
"""

from __future__ import annotations

import hashlib
import re

_COMPACT_CODE_RE = re.compile(r"^GS-(?:[A-F0-9]{4}-){3,4}[A-F0-9]{4}$", re.IGNORECASE)
_HEX64_RE = re.compile(r"^[0-9A-Fa-f]{64}$")


def compact_device_code(installation_id: str | None) -> str | None:
    """Return a stable, human-friendly code for a client installation.

    Existing ``GS-`` codes are canonicalized and other short opaque IDs are
    preserved.  The current 64-character hexadecimal hardware fingerprints
    are hashed before taking 80 display bits, so the result is not a simple
    truncation of the internal value and remains stable across restarts.
    """

    if installation_id is None:
        return None
    value = str(installation_id).strip()
    if not value:
        return None
    if _COMPACT_CODE_RE.fullmatch(value):
        return value.upper()
    if _HEX64_RE.fullmatch(value):
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest().upper()[:20]
        return "GS-" + "-".join(digest[index : index + 4] for index in range(0, 20, 4))
    return value
