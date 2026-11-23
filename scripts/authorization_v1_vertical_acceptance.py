"""Run a local, product-neutral authorization.v1 vertical acceptance flow.

The issued test card remains in the platform's immutable local audit history,
but its plaintext is kept only in process memory and never written to output.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _setup_django() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    import django

    django.setup()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _authorization_suffix(value: object) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return digest[-12:]


def _http_post(base_url: str, action: str, payload: dict) -> tuple[int, dict]:
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/public/licenses/{action}",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Request-Id": payload["request_id"],
            "Idempotency-Key": payload["idempotency_key"],
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _signed_request(
    *,
    action: str,
    profile: Any,
    installation_id: str,
    private_key: Ed25519PrivateKey,
    proof_message: Callable[[dict], bytes],
    authorization_id: str | None = None,
    license_key: str | None = None,
) -> dict:
    request_id = f"local-v1-{action}-{uuid.uuid4().hex}"
    public_key = _base64url(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    payload = {
        "request_id": request_id,
        "idempotency_key": request_id,
        "software_id": profile.software_id,
        "profile_id": profile.profile_id,
        "client_id": profile.client_id,
        "contract_version": profile.contract_version,
        "target": profile.target,
        "arch": profile.arch,
        "channel": profile.channel,
        "installation_id": installation_id,
        "device_public_key": public_key,
        "client_version": "1.0.0",
        "nonce": f"nonce-{uuid.uuid4().hex}",
    }
    if action == "activate":
        assert license_key is not None
        payload["license_key"] = license_key
    else:
        assert authorization_id is not None
        payload["authorization_id"] = authorization_id
    signed = {**payload, "action": action}
    payload["device_proof"] = _base64url(private_key.sign(proof_message(signed)))
    return payload


def _record_response(
    name: str,
    status: int,
    payload: dict,
    trusted_keys: dict,
    verify_response: Callable[[dict, dict], None],
) -> dict:
    integrity_verified = False
    if "integrity" in payload:
        verify_response(payload, trusted_keys)
        integrity_verified = True
    return {
        "step": name,
        "http_status": status,
        "decision": payload.get("decision"),
        "state_code": payload.get("state_code"),
        "error_code": payload.get("error", {}).get("code"),
        "authorization_id_hash_suffix": _authorization_suffix(payload["authorization_id"])
        if payload.get("authorization_id")
        else None,
        "response_signature_verified": integrity_verified,
    }


def run(*, base_url: str, software_id: str, profile_id: str, downstream_username: str, output: Path) -> dict:
    _setup_django()
    from django.conf import settings

    from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus
    from authorization_platform.catalog.models import Plan, PlanStatus, ProfileStatus, SoftwareProfile, SoftwareStatus
    from authorization_platform.licensing.authorization import (
        authorization_signing_public_key,
        device_proof_message,
        verify_authorization_response,
    )
    from authorization_platform.licensing.services import generate_license_batch

    profile = SoftwareProfile.objects.select_related("software").get(
        software_id=software_id,
        profile_id=profile_id,
    )
    if profile.software.status not in {SoftwareStatus.TESTING, SoftwareStatus.ACTIVE}:
        raise RuntimeError("software is not available for local authorization acceptance")
    if profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
        raise RuntimeError("profile is not available for local authorization acceptance")
    downstream = DownstreamProfile.objects.select_related("user").get(user__username=downstream_username)
    if downstream.status != DownstreamStatus.ACTIVE or not downstream.user.is_active:
        raise RuntimeError("downstream is not active")
    plan = (
        Plan.objects.filter(
            software_id=software_id,
            profile=profile,
            status=PlanStatus.ACTIVE,
            test_only=True,
        )
        .order_by("id")
        .first()
    )
    if plan is None:
        raise RuntimeError("no active test_only plan exists for the requested profile")
    snapshot = plan.latest_snapshot
    if snapshot is None:
        raise RuntimeError("test_only plan has no snapshot")

    issued = generate_license_batch(
        actor=downstream.user,
        software_id=software_id,
        plan_snapshot_id=snapshot.snapshot_id,
        quantity=1,
        idempotency_key=f"local-v1-vertical-issue-{uuid.uuid4().hex}",
    )
    license_key = issued.cards[0].code
    private_key = Ed25519PrivateKey.generate()
    installation_id = f"local-v1-{uuid.uuid4().hex}"
    trusted_keys = {settings.AUTHORIZATION_SIGNING_KEY_ID: authorization_signing_public_key()}
    results: list[dict] = []

    activate = _signed_request(
        action="activate",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        license_key=license_key,
    )
    status, payload = _http_post(base_url, "activate", activate)
    results.append(_record_response("activate", status, payload, trusted_keys, verify_authorization_response))
    if status != 200 or payload.get("decision") != "active":
        raise RuntimeError("activate did not produce an active authorization")
    authorization_id = payload["authorization_id"]
    expires_at = int(payload["expires_at"])

    verify = _signed_request(
        action="verify",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        authorization_id=authorization_id,
    )
    status, payload = _http_post(base_url, "verify", verify)
    results.append(_record_response("verify", status, payload, trusted_keys, verify_authorization_response))
    if status != 200:
        raise RuntimeError("verify did not succeed before expiry")

    deactivate = _signed_request(
        action="deactivate",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        authorization_id=authorization_id,
    )
    status, payload = _http_post(base_url, "deactivate", deactivate)
    results.append(_record_response("deactivate", status, payload, trusted_keys, verify_authorization_response))
    if status != 200 or payload.get("state_code") != "unbound":
        raise RuntimeError("deactivate did not produce an unbound response")

    # Rebind the same device without extending the original expires_at so the
    # following request exercises the server's signed expiration path.
    rebound = _signed_request(
        action="activate",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        license_key=license_key,
    )
    status, payload = _http_post(base_url, "activate", rebound)
    results.append(_record_response("reactivate_same_device", status, payload, trusted_keys, verify_authorization_response))
    if status != 200 or int(payload.get("expires_at", 0)) != expires_at:
        raise RuntimeError("same-device reactivation changed the original expiry")

    sleep_seconds = max(0, expires_at - int(datetime.now(timezone.utc).timestamp()) + 1)
    time.sleep(sleep_seconds)
    expired_verify = _signed_request(
        action="verify",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        authorization_id=authorization_id,
    )
    status, payload = _http_post(base_url, "verify", expired_verify)
    results.append(_record_response("verify_after_expiry", status, payload, trusted_keys, verify_authorization_response))
    if status != 403 or payload.get("error", {}).get("code") != "LICENSE_EXPIRED":
        raise RuntimeError("verify after expiry was not rejected as LICENSE_EXPIRED")

    report = {
        "schema": "authorization-v1-local-vertical-acceptance.v1",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "software_id": profile.software_id,
        "profile_id": profile.profile_id,
        "plan_snapshot_id": str(snapshot.snapshot_id),
        "test_only": bool(snapshot.test_only),
        "duration_seconds": snapshot.duration_seconds,
        "steps": results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--software-id", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--downstream-username", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(**vars(args))
    print(json.dumps({"output": str(args.output), "steps": report["steps"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
