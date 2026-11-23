"""Test-station batch renewal acceptance: all bound authorizations of one software.

Runs INSIDE the test-station app container (has DB + admin). Steps:
1. Pick software (default godskin), list renewable authorizations that have an
   ACTIVE device binding (= filtered to bound devices, select-all).
2. Renew the whole set by +1 day, assert every item grew by exactly 86400s.
3. Renew the same set by +1 hour, assert every item grew by exactly 3600s.
4. Assert revision bumped (clients see the new expiry on next verify).

Writes a receipt to output/batch-renewal/receipt-<software>.json (no card codes).
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _setup_django() -> None:
    import os
    import sys

    root = Path(__file__).resolve().parents[1]
    for candidate in (root / "src", root):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    import django

    django.setup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--software-id", default="godskin")
    parser.add_argument("--output", default="output/batch-renewal/receipt.json")
    parser.add_argument("--max-items", type=int, default=200)
    args = parser.parse_args()

    _setup_django()
    from django.contrib.auth import get_user_model
    from django.utils import timezone as dj_timezone

    from authorization_platform.licensing.admin import extend_authorization
    from authorization_platform.licensing.models import (
        AuthorizationState,
        DeviceBindingState,
        LicenseCardStatus,
        LicenseInstance,
    )

    now = dj_timezone.now()
    candidates = list(
        LicenseInstance.objects.select_related("license_card")
        .filter(
            software_id=args.software_id,
            state__in=(AuthorizationState.ACTIVE, AuthorizationState.GRACE),
            expires_at__gt=now,
            license_card__status=LicenseCardStatus.ACTIVATED,
        )
        .order_by("activated_at")
    )
    bound = []
    for instance in candidates:
        has_active = instance.device_bindings.filter(state=DeviceBindingState.ACTIVE).exists()
        if has_active:
            bound.append(instance)
    picked = bound[: args.max_items]

    admin = get_user_model().objects.filter(is_superuser=True, is_active=True).order_by("id").first()
    if admin is None:
        raise RuntimeError("no platform admin in this database")

    receipt: dict = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "software_id": args.software_id,
        "candidate_total": len(candidates),
        "bound_total": len(bound),
        "picked": len(picked),
        "rounds": [],
    }
    print(f"candidates={len(candidates)} bound={len(bound)} picked={len(picked)}", flush=True)

    for unit, seconds in (("day", 86400), ("hour", 3600)):
        ok = 0
        failed: list[dict] = []
        for instance in picked:
            before_expires = instance.expires_at
            before_revision = instance.authorization_revision
            try:
                result = extend_authorization(
                    actor=admin,
                    authorization_id=instance.authorization_id,
                    added_seconds=seconds,
                    reason=f"测试站批量验收续1{unit}",
                    request_id=f"test-site-batch-{unit}-{uuid.uuid4().hex}",
                )
            except Exception as exc:  # noqa: BLE001 - record and continue per-item
                failed.append({"authorization_id": str(instance.authorization_id), "error": str(exc)})
                continue
            growth = int((result.new_expires_at - before_expires).total_seconds())
            instance.refresh_from_db()
            if growth == seconds and instance.authorization_revision == before_revision + 1:
                ok += 1
            else:
                failed.append(
                    {
                        "authorization_id": str(instance.authorization_id),
                        "growth": growth,
                        "expected": seconds,
                        "revision_ok": instance.authorization_revision == before_revision + 1,
                    }
                )
        receipt["rounds"].append({"unit": unit, "seconds": seconds, "ok": ok, "failed": failed})
        print(f"round unit={unit}: ok={ok} failed={len(failed)}", flush=True)
        for item in failed[:10]:
            print(f"  FAILED: {item}", flush=True)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"receipt: {out_path}", flush=True)
    total_failed = sum(len(r["failed"]) for r in receipt["rounds"])
    if not picked:
        print("NO_BOUND_AUTHORIZATIONS", flush=True)
        return 2
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
