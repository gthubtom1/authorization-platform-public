"""Run a local renewal (补时间) vertical acceptance flow.

Client side talks to a real HTTP server with real Ed25519 device proofs and a
real one-time nonce.  Administrator side goes through the real Django admin API
(route, permission, idempotency and serialization included).

The issued card's plaintext stays in process memory and is never written to the
receipt, to the log or to the repository.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _setup_django() -> None:
    import sys

    root = Path(__file__).resolve().parents[1]
    for candidate in (root / "src", root):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    import django

    django.setup()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


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
        with urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raw = error.read().decode("utf-8", "replace")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {"raw_body_prefix": raw[:400]}


def _signed_request(
    *,
    action: str,
    profile,
    installation_id: str,
    private_key: Ed25519PrivateKey,
    proof_message: Callable[[dict], bytes],
    authorization_id: str | None = None,
    license_key: str | None = None,
    known_authorization_revision: int | None = None,
) -> dict:
    request_id = f"local-renewal-{action}-{uuid.uuid4().hex}"
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
    if known_authorization_revision is not None:
        payload["known_authorization_revision"] = known_authorization_revision
    signed = {**payload, "action": action}
    payload["device_proof"] = _base64url(private_key.sign(proof_message(signed)))
    return payload


def _json_body(response) -> dict:
    raw = response.content.decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw_body_prefix": raw[:400], "http_status": response.status_code}


def _record_step(name: str, status: int, payload: dict, trusted_keys: dict, verify_response) -> dict:
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
        "authorization_revision": payload.get("authorization_revision"),
        "expires_at": payload.get("expires_at"),
        "response_signature_verified": integrity_verified,
    }


def run(
    *,
    base_url: str,
    software_id: str,
    profile_id: str,
    downstream_username: str,
    admin_username: str | None,
    unit: str,
    amount: int,
    output: Path,
    server_name: str | None = None,
) -> dict:
    _setup_django()
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.test import Client
    from django.urls import reverse

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
        raise RuntimeError("软件当前不可用")
    if profile.status not in {ProfileStatus.TESTING, ProfileStatus.ACTIVE}:
        raise RuntimeError("Profile 当前不可用")
    downstream = DownstreamProfile.objects.select_related("user").get(user__username=downstream_username)
    if downstream.status != DownstreamStatus.ACTIVE or not downstream.user.is_active:
        raise RuntimeError("下游账号不是 active")

    plan = (
        Plan.objects.filter(
            software_id=software_id,
            profile=profile,
            status=PlanStatus.ACTIVE,
            test_only=True,
        )
        .order_by("-duration_seconds")
        .first()
    )
    if plan is None:
        raise RuntimeError("这个 Profile 没有 active 的 test_only 套餐")
    snapshot = plan.latest_snapshot
    if snapshot is None:
        raise RuntimeError("test_only 套餐没有快照")

    user_model = get_user_model()
    admin = None
    if admin_username:
        admin = user_model.objects.filter(username=admin_username, is_superuser=True).first()
    if admin is None:
        admin = user_model.objects.filter(is_superuser=True, is_active=True).order_by("id").first()
    if admin is None:
        raise RuntimeError("本地库没有可用的平台管理员账号")

    issued = generate_license_batch(
        actor=downstream.user,
        software_id=software_id,
        plan_snapshot_id=snapshot.snapshot_id,
        quantity=1,
        idempotency_key=f"renewal-acceptance-issue-{uuid.uuid4().hex}",
    )
    license_key = issued.cards[0].code
    card_public_id = issued.cards[0].public_id
    private_key = Ed25519PrivateKey.generate()
    installation_id = f"local-renewal-{uuid.uuid4().hex}"
    trusted_keys = {settings.AUTHORIZATION_SIGNING_KEY_ID: authorization_signing_public_key()}
    steps: list[dict] = []

    activate = _signed_request(
        action="activate",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        license_key=license_key,
    )
    status, payload = _http_post(base_url, "activate", activate)
    steps.append(_record_step("activate", status, payload, trusted_keys, verify_authorization_response))
    if status != 200 or payload.get("decision") != "active":
        raise RuntimeError(f"activate 没有拿到 active：{status} {payload.get('error')}")
    authorization_id = payload["authorization_id"]
    revision_before = int(payload["authorization_revision"])

    before_verify = _signed_request(
        action="verify",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        authorization_id=authorization_id,
        known_authorization_revision=revision_before,
    )
    status, payload = _http_post(base_url, "verify", before_verify)
    steps.append(_record_step("verify_before_renewal", status, payload, trusted_keys, verify_authorization_response))
    if status != 200:
        raise RuntimeError(f"续期前的 verify 没有成功：{status} {payload.get('error')}")
    before_expires = int(payload["expires_at"])

    # 生产配置开了 SECURE_SSL_REDIRECT：django.test.Client 的 secure 是每个请求
    # 方法的参数（不是构造参数），不传就会被 301 到 https:// 而拿不到 JSON。
    admin_client = Client(SERVER_NAME=server_name or "127.0.0.1")
    admin_client.force_login(admin)
    preview_response = admin_client.get(
        reverse("licensing:api_manage_authorization_renew_preview"),
        {"unit": unit, "amount": str(amount), "software_id": software_id},
        secure=True,
    )
    preview_body = _json_body(preview_response)
    frozen_ids = list(preview_body.get("authorization_ids") or [])
    steps.append(
        {
            "step": "admin_renew_preview",
            "http_status": preview_response.status_code,
            "renewable_count": preview_body.get("renewable_count"),
            "added_seconds": preview_body.get("added_seconds"),
            "target_in_frozen_ids": authorization_id in frozen_ids,
            "body_prefix": preview_body.get("raw_body_prefix"),
        }
    )
    if preview_response.status_code != 200 or authorization_id not in frozen_ids:
        raise RuntimeError(f"续期预览没有选中刚激活的授权：{preview_response.status_code} {preview_body}")

    confirm_response = admin_client.post(
        reverse("licensing:api_manage_authorization_renew"),
        data=json.dumps(
            {
                "authorization_ids": [authorization_id],
                "unit": unit,
                "amount": amount,
                "reason": "本地续期纵向验收",
            }
        ),
        content_type="application/json",
        secure=True,
        HTTP_IDEMPOTENCY_KEY=f"renewal-acceptance-{uuid.uuid4().hex}",
    )
    confirm_body = _json_body(confirm_response)
    renewed_ids = {item.get("authorization_id") for item in (confirm_body.get("items") or [])}
    steps.append(
        {
            "step": "admin_renew_confirm",
            "http_status": confirm_response.status_code,
            "renewed_count": confirm_body.get("renewed_count"),
            "failed_count": confirm_body.get("failed_count"),
            "failures": confirm_body.get("failures"),
            "target_renewed": authorization_id in renewed_ids,
        }
    )
    if confirm_response.status_code != 200 or authorization_id not in renewed_ids:
        raise RuntimeError(f"续期确认没有成功：{confirm_response.status_code} {confirm_body}")

    after_verify = _signed_request(
        action="verify",
        profile=profile,
        installation_id=installation_id,
        private_key=private_key,
        proof_message=device_proof_message,
        authorization_id=authorization_id,
        known_authorization_revision=revision_before,
    )
    status, payload = _http_post(base_url, "verify", after_verify)
    steps.append(_record_step("verify_after_renewal", status, payload, trusted_keys, verify_authorization_response))
    if status != 200:
        raise RuntimeError(f"续期后的 verify 没有成功：{status} {payload.get('error')}")
    after_expires = int(payload["expires_at"])
    revision_after = int(payload["authorization_revision"])

    expected_growth = amount * (3600 if unit == "hour" else 86400)
    receipt = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "software_id": software_id,
        "profile_id": profile_id,
        "plan_name": plan.name,
        "plan_duration_seconds": snapshot.duration_seconds,
        "card_public_id": str(card_public_id),
        "authorization_id": authorization_id,
        "renewal_unit": unit,
        "renewal_amount": amount,
        "expected_growth_seconds": expected_growth,
        "expires_at_before": before_expires,
        "expires_at_after": after_expires,
        "expiry_grew_by_seconds": after_expires - before_expires,
        "revision_before": revision_before,
        "revision_after": revision_after,
        "decision_after_renewal": payload.get("decision"),
        "state_code_after_renewal": payload.get("state_code"),
        "client_received_new_expiry": after_expires == before_expires + expected_growth,
        "revision_advanced": revision_after > revision_before,
        "steps": steps,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="本地续期纵向验收（真实 HTTP 客户端 + 真实管理端 API）")
    parser.add_argument("--base-url", default="http://127.0.0.1:8123")
    parser.add_argument("--software-id", default="browser-tool")
    parser.add_argument("--profile-id", default="stable")
    parser.add_argument("--downstream-username", default="browser_downstream")
    parser.add_argument("--admin-username", default=None)
    parser.add_argument("--unit", default="day", choices=("day", "hour"))
    parser.add_argument("--amount", type=int, default=1)
    parser.add_argument("--server-name", default=None, help="管理端 API 的 Host 头，默认取 base-url 的主机名")
    parser.add_argument("--output", default="output/renewal-acceptance/receipt.json")
    args = parser.parse_args()
    server_name = args.server_name or urlsplit(args.base_url).hostname or "127.0.0.1"
    receipt = run(
        base_url=args.base_url,
        software_id=args.software_id,
        profile_id=args.profile_id,
        downstream_username=args.downstream_username,
        admin_username=args.admin_username,
        unit=args.unit,
        amount=args.amount,
        output=Path(args.output),
        server_name=server_name,
    )
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0 if receipt["client_received_new_expiry"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
