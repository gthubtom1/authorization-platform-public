from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")

import django

django.setup()

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import create_plan, create_policy_version, create_profile, create_software, set_downstream_software_access
from authorization_platform.core.time import FixedClock
from authorization_platform.licensing.authorization import activate_license, device_proof_message
from authorization_platform.licensing.models import Device, LicenseCard
from authorization_platform.licensing.services import decrypt_license_card, generate_license_batch


def _fixture_password(*public_ids) -> str:
    seed = "".join(str(public_id).replace("-", "") for public_id in public_ids)
    return f"Browser-fixture-{seed[:48]}-123"


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _activation_request(
    *,
    license_key: str,
    software_id: str,
    profile,
    private_key: Ed25519PrivateKey,
    request_id: str = "browser-acceptance-activate",
    installation_id: str = "browser-acceptance-installation",
    nonce: str = "browser-acceptance-nonce",
) -> dict:
    request = {
        "request_id": request_id,
        "idempotency_key": request_id,
        "software_id": software_id,
        "profile_id": profile.profile_id,
        "client_id": profile.client_id,
        "contract_version": "authorization.v1",
        "target": profile.target,
        "arch": profile.arch,
        "channel": profile.channel,
        "license_key": license_key,
        "installation_id": installation_id,
        "device_public_key": _public_key(private_key),
        "client_version": "1.0.0",
        "nonce": nonce,
    }
    signed = dict(request)
    signed["action"] = "activate"
    signature = private_key.sign(device_proof_message(signed))
    request["device_proof"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return request


def _create_users():
    user_model = get_user_model()
    admin = user_model.objects.create_superuser(
        username="browser-acceptance-admin",
        password=secrets.token_urlsafe(32),
    )
    downstream_a = create_downstream_direct(
        actor=admin,
        username="browser-acceptance-a",
        password=secrets.token_urlsafe(32),
    )
    downstream_b = create_downstream_direct(
        actor=admin,
        username="browser-acceptance-b",
        password=secrets.token_urlsafe(32),
    )
    fixture_password = _fixture_password(downstream_a.public_id, downstream_b.public_id)
    for user in (admin, downstream_a.user, downstream_b.user):
        user.set_password(fixture_password)
        user.save(update_fields=("password",))
    return admin, downstream_a, downstream_b


def _create_authorization(*, admin, downstream):
    software = create_software(
        actor=admin,
        software_id="browser-acceptance-software",
        name="Browser Acceptance Software",
        status=SoftwareStatus.ACTIVE,
    )
    profile = create_profile(
        actor=admin,
        software_id=software.software_id,
        profile_id="stable",
        client_id="browser-acceptance-client",
        status=ProfileStatus.ACTIVE,
    )
    policy = create_policy_version(
        actor=admin,
        software_id=software.software_id,
        profile_id=profile.profile_id,
        version="policy-1",
        max_devices=2,
        allow_device_switch=False,
        device_proof_required=True,
        verify_interval_seconds=60,
        status=PolicyStatus.ACTIVE,
    )
    _, snapshot = create_plan(
        actor=admin,
        software_id=software.software_id,
        profile_id=profile.profile_id,
        policy_version=policy.version,
        name="Browser acceptance plan",
        duration_seconds=3600,
        quota_cost=0,
        test_only=True,
        status=PlanStatus.ACTIVE,
    )
    set_downstream_software_access(
        actor=admin,
        downstream_public_id=downstream.public_id,
        software_id=software.software_id,
        enabled=True,
        all_plans_allowed=True,
    )
    issued = generate_license_batch(
        actor=downstream.user,
        software_id=software.software_id,
        plan_snapshot_id=snapshot.snapshot_id,
        quantity=1,
        idempotency_key="browser-acceptance-issue",
    )
    card = LicenseCard.objects.get(public_id=issued.cards[0].public_id)
    private_key = Ed25519PrivateKey.generate()
    now = timezone.now().replace(microsecond=0)
    result = activate_license(
        request=_activation_request(
            license_key=decrypt_license_card(card.card_ciphertext),
            software_id=software.software_id,
            profile=profile,
            private_key=private_key,
        ),
        clock=FixedClock(now),
    )
    if result.status_code != 200:
        raise SystemExit(f"browser acceptance authorization setup failed: {result.status_code}")
    authorization_id = str(result.payload["authorization_id"])
    second_private_key = Ed25519PrivateKey.generate()
    second_result = activate_license(
        request=_activation_request(
            license_key=decrypt_license_card(card.card_ciphertext),
            software_id=software.software_id,
            profile=profile,
            private_key=second_private_key,
            request_id="browser-acceptance-activate-second",
            installation_id="browser-acceptance-installation-second",
            nonce="browser-acceptance-nonce-second",
        ),
        clock=FixedClock(now + timedelta(seconds=1)),
    )
    if second_result.status_code != 200 or second_result.payload.get("authorization_id") != authorization_id:
        raise SystemExit(f"browser acceptance second device setup failed: {second_result.status_code}")
    devices = list(Device.objects.order_by("first_seen_at", "public_id"))
    if len(devices) != 2:
        raise SystemExit(f"browser acceptance expected two devices, got {len(devices)}")
    return {
        "authorization_id": authorization_id,
        "device_id": str(devices[0].public_id),
        "other_device_id": str(devices[1].public_id),
        "software_id": software.software_id,
        "client_id": profile.client_id,
    }


def _create_audit_events(*, admin, downstream_a, downstream_b):
    record_event(
        actor=admin,
        action="browser.scope",
        outcome=AuditOutcome.SUCCESS,
        object_type="DownstreamProfile",
        object_public_id=str(downstream_a.public_id),
        request_id="browser-scope-a",
        metadata={"secret": "browser-scope-secret-a"},
    )
    record_event(
        actor=admin,
        action="browser.scope",
        outcome=AuditOutcome.SUCCESS,
        object_type="DownstreamProfile",
        object_public_id=str(downstream_b.public_id),
        request_id="browser-scope-b",
        metadata={"secret": "browser-scope-secret-b"},
    )

    now = timezone.now().replace(microsecond=0)
    events = []
    for index in range(1001):
        object_public_id = f"browser-row-{index}"
        metadata = {"row_number": index}
        if index == 0:
            object_public_id = "=browser-formula"
            metadata["secret"] = "browser-secret"
        events.append(
            AuditEvent(
                actor=admin,
                actor_role="platform_admin",
                action="browser.acceptance",
                outcome=AuditOutcome.SUCCESS,
                object_type="Custom",
                object_public_id=object_public_id,
                request_id=f"browser-acceptance-{index}",
                occurred_at=now - timedelta(milliseconds=index),
                metadata=metadata,
            )
        )
    AuditEvent.objects.bulk_create(events, batch_size=250)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an isolated local browser acceptance dataset.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    admin, downstream_a, downstream_b = _create_users()
    authorization = _create_authorization(admin=admin, downstream=downstream_a)
    _create_audit_events(admin=admin, downstream_a=downstream_a, downstream_b=downstream_b)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "admin_username": admin.username,
                "downstream_a_username": downstream_a.user.username,
                "downstream_b_username": downstream_b.user.username,
                "downstream_a_public_id": str(downstream_a.public_id),
                "downstream_b_public_id": str(downstream_b.public_id),
                **authorization,
            },
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps({"status": "ready", **authorization}, ensure_ascii=True))


if __name__ == "__main__":
    main()
