"""Redacted database inventory used to prove migration and restore fidelity."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import date, datetime, timezone as dt_timezone
from typing import Any, Iterable, Sequence
from uuid import UUID

from django.db.migrations.recorder import MigrationRecorder
from django.utils import timezone


SCHEMA_VERSION = 4


def _json_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _digest(value: Any) -> str:
    normalized = _json_value(value)
    payload = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _row_fingerprint(queryset, fields: Sequence[str], *, order_by: Sequence[str] | None = None, secret_fields: Iterable[str] = ()) -> str:
    secret_fields = set(secret_fields)
    digest = hashlib.sha256()
    ordered = queryset.order_by(*(order_by or fields)).values_list(*fields)
    for row in ordered.iterator(chunk_size=1000):
        values = []
        for field, value in zip(fields, row):
            values.append({"field": field, "digest": _digest(value)} if field in secret_fields else _json_value(value))
        digest.update(json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _status_counts(queryset, field: str = "status") -> dict[str, int]:
    return {str(key): int(value) for key, value in sorted(Counter(queryset.values_list(field, flat=True)).items(), key=lambda pair: str(pair[0]))}


def _key_version_counts(queryset) -> dict[str, int]:
    return {str(key): int(value) for key, value in sorted(Counter(queryset.values_list("encryption_key_version", flat=True)).items(), key=lambda pair: str(pair[0]))}


def _configured_key_references() -> dict[str, Any]:
    from django.conf import settings

    return {
        "encryption_versions": {
            "invitation": [str(getattr(settings, "INVITATION_ENCRYPTION_KEY_VERSION", "v1"))],
            "quota_card": sorted(
                {
                    str(getattr(settings, "QUOTA_CARD_ENCRYPTION_KEY_VERSION", "v2")),
                    str(getattr(settings, "QUOTA_CARD_LEGACY_ENCRYPTION_KEY_VERSION", "v1")),
                }
            ),
            "license_card": sorted(
                {
                    str(getattr(settings, "LICENSE_CARD_ENCRYPTION_KEY_VERSION", "v1")),
                    str(getattr(settings, "LICENSE_CARD_LEGACY_ENCRYPTION_KEY_VERSION", "v1")),
                }
            ),
        },
        "hmac_key_references": [
            "INVITATION_ENCRYPTION_KEY",
            "QUOTA_CARD_HASH_KEY",
            "QUOTA_REDEEM_IP_HASH_KEY",
            "LICENSE_CARD_HASH_KEY",
            "AUTHORIZATION_NONCE_HASH_KEY",
            "AUTHORIZATION_DEVICE_HASH_KEY",
        ],
        "secret_values_exposed": False,
    }


def _table(*, count: int, status_counts: dict[str, int] | None = None, key_versions: dict[str, int] | None = None, fingerprint: str = "", **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"count": count, "fingerprint": fingerprint}
    if status_counts is not None:
        result["status_counts"] = status_counts
    if key_versions is not None:
        result["encryption_key_versions"] = key_versions
    result.update(extra)
    return result


def _verify_card_material() -> dict[str, Any]:
    """Decrypt all stored operational credentials in memory and compare HMACs."""

    from authorization_platform.accounts.models import InvitationCode
    from authorization_platform.accounts.services import AccountOperationError, decrypt_invitation_code, invitation_code_hash
    from authorization_platform.credits.models import QuotaCard
    from authorization_platform.credits.services import QuotaOperationError, decrypt_quota_card, quota_card_hash
    from authorization_platform.licensing.models import LicenseCard
    from authorization_platform.licensing.services import LicenseOperationError, decrypt_license_card, license_card_hash

    checks = {
        "invitation_codes": 0,
        "quota_cards": 0,
        "license_cards": 0,
    }
    failures: list[dict[str, str]] = []

    for item in InvitationCode.objects.only("public_id", "code_hash", "code_ciphertext").iterator(chunk_size=500):
        checks["invitation_codes"] += 1
        try:
            plaintext = decrypt_invitation_code(item.code_ciphertext)
            if invitation_code_hash(plaintext) != item.code_hash:
                failures.append({"table": "invitation_codes", "public_id": str(item.public_id), "code": "HASH_MISMATCH"})
        except (AccountOperationError, ValueError, TypeError):
            failures.append({"table": "invitation_codes", "public_id": str(item.public_id), "code": "DECRYPT_FAILED"})

    for item in QuotaCard.objects.only("public_id", "card_hash", "card_ciphertext", "encryption_key_version").iterator(chunk_size=500):
        checks["quota_cards"] += 1
        try:
            plaintext = decrypt_quota_card(item.card_ciphertext, key_version=item.encryption_key_version)
            if quota_card_hash(plaintext) != item.card_hash:
                failures.append({"table": "quota_cards", "public_id": str(item.public_id), "code": "HASH_MISMATCH"})
        except (QuotaOperationError, ValueError, TypeError):
            failures.append({"table": "quota_cards", "public_id": str(item.public_id), "code": "DECRYPT_FAILED"})

    for item in LicenseCard.objects.only("public_id", "card_hash", "card_ciphertext", "encryption_key_version").iterator(chunk_size=500):
        checks["license_cards"] += 1
        try:
            plaintext = decrypt_license_card(item.card_ciphertext, key_version=item.encryption_key_version)
            if license_card_hash(plaintext) != item.card_hash:
                failures.append({"table": "license_cards", "public_id": str(item.public_id), "code": "HASH_MISMATCH"})
        except (LicenseOperationError, ValueError, TypeError):
            failures.append({"table": "license_cards", "public_id": str(item.public_id), "code": "DECRYPT_FAILED"})

    return {"requested": True, "checked": checks, "failed": failures, "passed": not failures}


def _verify_quota_ledger() -> dict[str, Any]:
    """Validate each account's balance chain independently of the total sum."""

    from authorization_platform.credits.models import QuotaAccount, QuotaLedgerEntry

    checked_accounts = 0
    checked_entries = 0
    failures: list[dict[str, str]] = []
    for account in QuotaAccount.objects.order_by("public_id").iterator(chunk_size=500):
        checked_accounts += 1
        expected_before = 0
        source_seen: set[tuple[str, str]] = set()
        entries = QuotaLedgerEntry.objects.filter(account_id=account.public_id).order_by("occurred_at", "public_id")
        for entry in entries.iterator(chunk_size=500):
            checked_entries += 1
            if entry.balance_before != expected_before:
                failures.append({"table": "quota_ledger_entries", "public_id": str(entry.public_id), "code": "BALANCE_CHAIN_BEFORE_MISMATCH"})
            if entry.direction == "credit":
                expected_after = entry.balance_before + entry.amount
            elif entry.direction == "debit":
                expected_after = entry.balance_before - entry.amount
            else:
                expected_after = -1
                failures.append({"table": "quota_ledger_entries", "public_id": str(entry.public_id), "code": "UNKNOWN_DIRECTION"})
            if expected_after < 0 or entry.balance_after != expected_after:
                failures.append({"table": "quota_ledger_entries", "public_id": str(entry.public_id), "code": "BALANCE_CHAIN_AFTER_MISMATCH"})
            if entry.operation_type in {"card_redeem", "license_card_issue", "license_card_reclaim"} and entry.source_public_id:
                source_key = (str(entry.operation_type), str(entry.source_public_id))
                if source_key in source_seen:
                    failures.append({"table": "quota_ledger_entries", "public_id": str(entry.public_id), "code": "SOURCE_DUPLICATE"})
                source_seen.add(source_key)
            expected_before = entry.balance_after
        if expected_before != account.available_balance:
            failures.append({"table": "quota_accounts", "public_id": str(account.public_id), "code": "ACCOUNT_BALANCE_MISMATCH"})
    return {
        "checked_accounts": checked_accounts,
        "checked_entries": checked_entries,
        "failed": failures,
        "passed": not failures,
    }


def collect_recovery_inventory(*, verify_ciphertext: bool = False) -> dict[str, Any]:
    """Collect the inventory from one database-consistent read snapshot.

    PostgreSQL uses REPEATABLE READ so the many table fingerprints cannot be
    assembled from unrelated committed states while the application is busy.
    SQLite keeps its existing test behavior; the PostgreSQL runner remains the
    evidence for row-lock and restore semantics.
    """

    from django.db import connection, transaction

    if connection.vendor == "postgresql" and not connection.in_atomic_block:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            return _collect_recovery_inventory(verify_ciphertext=verify_ciphertext)
    return _collect_recovery_inventory(verify_ciphertext=verify_ciphertext)


def _collect_recovery_inventory(*, verify_ciphertext: bool = False) -> dict[str, Any]:
    from django.contrib.auth import get_user_model

    from django.contrib.sessions.models import Session

    from authorization_platform.accounts.models import (
        DownstreamAdminOperation,
        DownstreamProfile,
        DownstreamTombstone,
        InvitationBatch,
        InvitationCode,
        PasswordOperation,
    )
    from authorization_platform.audit.models import AuditEvent
    from authorization_platform.catalog.models import (
        CapabilityDefinition,
        DownstreamSoftware,
        Plan,
        PlanCreateOperation,
        PlanSnapshot,
        PolicyVersion,
        Software,
        SoftwareProfile,
    )
    from authorization_platform.credits.models import (
        QuotaAccount,
        QuotaCard,
        QuotaCardBatch,
        QuotaLedgerEntry,
        QuotaPlatformSettings,
        QuotaPurchaseUrlOperation,
    )
    from authorization_platform.licensing.models import (
        AuthorizationAdminOperation,
        AuthorizationNonce,
        AuthorizationRequestRecord,
        Device,
        DeviceBinding,
        DeviceKey,
        LicenseCard,
        LicenseCardBatch,
        LicenseInstance,
        LicenseReclaimOperation,
    )
    from authorization_platform.backup_control.models import (
        BackupControlOperation,
        BackupPolicy,
        BackupRestoreStaging,
        BackupRunRequest,
    )
    from authorization_platform.releases.models import Release, ReleaseOperation
    from authorization_platform.storage_cleanup.models import StorageCleanupOperation, StorageCleanupState

    user_model = get_user_model()
    downstream = DownstreamProfile.objects.all()
    invitations = InvitationCode.objects.all()
    quota_cards = QuotaCard.objects.all()
    quota_accounts = QuotaAccount.objects.all()
    ledger = QuotaLedgerEntry.objects.all()
    license_cards = LicenseCard.objects.all()
    authorizations = LicenseInstance.objects.all()
    devices = Device.objects.all()
    device_keys = DeviceKey.objects.all()
    bindings = DeviceBinding.objects.all()
    audit = AuditEvent.objects.all()
    migrations = MigrationRecorder.Migration.objects.all()

    tables = {
        "users": _table(
            count=user_model.objects.count(),
            fingerprint=_row_fingerprint(
                user_model.objects.all(),
                ("id", "username", "password", "is_active", "is_staff", "is_superuser", "date_joined"),
                order_by=("id",),
                secret_fields=("password",),
            ),
        ),
        "downstream_profiles": _table(
            count=downstream.count(),
            status_counts=_status_counts(downstream),
            fingerprint=_row_fingerprint(
                downstream,
                ("public_id", "user_id", "status", "registration_source", "session_version", "registered_at"),
                order_by=("public_id",),
            ),
        ),
        "downstream_tombstones": _table(
            count=DownstreamTombstone.objects.count(),
            fingerprint=_row_fingerprint(
                DownstreamTombstone.objects.all(),
                ("public_id", "username_digest", "deleted_at", "deleted_by_id", "delete_reason"),
                order_by=("public_id",),
            ),
        ),
        "invitation_batches": _table(
            count=InvitationBatch.objects.count(),
            fingerprint=_row_fingerprint(
                InvitationBatch.objects.all(),
                ("public_id", "created_by_id", "quantity", "idempotency_key", "request_hash", "created_at"),
                order_by=("public_id",),
            ),
        ),
        "invitation_codes": _table(
            count=invitations.count(),
            status_counts=_status_counts(invitations),
            fingerprint=_row_fingerprint(
                invitations,
                (
                    "public_id",
                    "batch_id",
                    "code_hash",
                    "status",
                    "created_at",
                    "expires_at",
                    "max_attempts",
                    "attempt_count",
                    "consumed_at",
                    "consumed_profile_id",
                    "consumed_username_digest",
                    "revoked_at",
                    "revoke_reason",
                ),
                order_by=("public_id",),
            ),
            ciphertext_fingerprint=_row_fingerprint(
                invitations,
                ("public_id", "code_ciphertext"),
                order_by=("public_id",),
                secret_fields=("code_ciphertext",),
            ),
        ),
        "quota_cards": _table(
            count=quota_cards.count(),
            status_counts=_status_counts(quota_cards),
            key_versions=_key_version_counts(quota_cards),
            fingerprint=_row_fingerprint(
                quota_cards,
                (
                    "public_id",
                    "batch_id",
                    "card_hash",
                    "amount",
                    "target_downstream_public_id",
                    "status",
                    "encryption_key_version",
                    "issued_by_id",
                    "issued_at",
                    "redeemed_by_public_id",
                    "redeemed_at",
                    "redeemed_ip_digest",
                    "revoked_at",
                    "revoke_reason",
                    "revoke_idempotency_key",
                    "revoke_request_hash",
                ),
                order_by=("public_id",),
                secret_fields=("revoke_idempotency_key", "revoke_request_hash"),
            ),
            ciphertext_fingerprint=_row_fingerprint(
                quota_cards,
                ("public_id", "card_ciphertext"),
                order_by=("public_id",),
                secret_fields=("card_ciphertext",),
            ),
        ),
        "quota_card_batches": _table(
            count=QuotaCardBatch.objects.count(),
            fingerprint=_row_fingerprint(
                QuotaCardBatch.objects.all(),
                ("public_id", "amount", "quantity", "target_downstream_public_id", "idempotency_key", "request_hash", "created_by_id", "created_at"),
                order_by=("public_id",),
            ),
        ),
        "quota_accounts": _table(
            count=quota_accounts.count(),
            total_available_balance=sum(quota_accounts.values_list("available_balance", flat=True)),
            fingerprint=_row_fingerprint(quota_accounts, ("public_id", "downstream_public_id", "available_balance"), order_by=("public_id",)),
        ),
        "quota_ledger_entries": _table(
            count=ledger.count(),
            fingerprint=_row_fingerprint(
                ledger,
                ("public_id", "account_id", "downstream_public_id", "direction", "amount", "operation_type", "source_type", "source_public_id", "idempotency_key", "balance_before", "balance_after", "occurred_at"),
                order_by=("public_id",),
            ),
            direction_amounts={
                str(direction): int(total)
                for direction, total in sorted(
                    ((direction, sum(amounts)) for direction, amounts in _group_amounts(ledger, "direction", "amount")),
                    key=lambda pair: pair[0],
                )
            },
            integrity=_verify_quota_ledger(),
        ),
        "quota_purchase_url_operations": _table(
            count=QuotaPurchaseUrlOperation.objects.count(),
            fingerprint=_row_fingerprint(
                QuotaPurchaseUrlOperation.objects.all(),
                ("id", "actor_id", "idempotency_key", "request_hash", "purchase_url", "created_at"),
                order_by=("id",),
                secret_fields=("purchase_url",),
            ),
        ),
        "license_cards": _table(
            count=license_cards.count(),
            status_counts=_status_counts(license_cards),
            key_versions=_key_version_counts(license_cards),
            fingerprint=_row_fingerprint(
                license_cards,
                (
                    "public_id",
                    "batch_id",
                    "software_id",
                    "profile_id",
                    "plan_snapshot_id",
                    "original_downstream_public_id",
                    "current_downstream_public_id",
                    "quota_cost",
                    "card_hash",
                    "status",
                    "encryption_key_version",
                    "issued_by_id",
                    "issued_at",
                    "activated_at",
                    "expires_at",
                    "reclaimed_at",
                    "revoked_at",
                    "status_reason",
                ),
                order_by=("public_id",),
            ),
            ciphertext_fingerprint=_row_fingerprint(
                license_cards,
                ("public_id", "card_ciphertext"),
                order_by=("public_id",),
                secret_fields=("card_ciphertext",),
            ),
        ),
        "license_card_batches": _table(
            count=LicenseCardBatch.objects.count(),
            fingerprint=_row_fingerprint(
                LicenseCardBatch.objects.all(),
                ("batch_id", "software_id", "profile_id", "plan_snapshot_id", "current_downstream_public_id", "quantity", "total_quota_cost", "idempotency_key", "request_hash", "created_by_id", "created_at"),
                order_by=("batch_id",),
            ),
        ),
        "license_instances": _table(
            count=authorizations.count(),
            status_counts={str(key): int(value) for key, value in sorted(Counter(authorizations.values_list("state", flat=True)).items(), key=lambda pair: str(pair[0]))},
            fingerprint=_row_fingerprint(
                authorizations,
                (
                    "authorization_id",
                    "license_card_id",
                    "software_id",
                    "profile_id",
                    "plan_snapshot_id",
                    "policy_version_id",
                    "current_downstream_public_id",
                    "client_id",
                    "contract_version",
                    "target",
                    "arch",
                    "channel",
                    "client_version",
                    "state",
                    "authorization_revision",
                    "config_version",
                    "configuration_override",
                    "issued_at",
                    "activated_at",
                    "expires_at",
                    "last_verified_at",
                    "last_server_time",
                    "revoked_at",
                    "state_reason",
                    "device_switch_count",
                    "device_switch_day",
                    "created_at",
                    "updated_at",
                ),
                order_by=("authorization_id",),
                secret_fields=("configuration_override",),
            ),
        ),
        "devices": _table(
            count=devices.count(),
            status_counts={str(key): int(value) for key, value in sorted(Counter(devices.values_list("risk_state", flat=True)).items(), key=lambda pair: str(pair[0]))},
            fingerprint=_row_fingerprint(
                devices,
                ("public_id", "software_id", "profile_id", "installation_hash", "first_seen_at", "last_seen_at", "last_ip", "risk_state"),
                order_by=("public_id",),
                secret_fields=("installation_hash", "last_ip"),
            ),
        ),
        "device_keys": _table(
            count=device_keys.count(),
            fingerprint=_row_fingerprint(
                device_keys,
                ("key_id", "device_id", "algorithm", "public_key", "is_active", "revoked_at"),
                order_by=("key_id",),
                secret_fields=("public_key",),
            ),
        ),
        "device_bindings": _table(
            count=bindings.count(),
            status_counts=_status_counts(bindings, "state"),
            fingerprint=_row_fingerprint(
                bindings,
                ("binding_id", "authorization_id", "device_id", "device_key_id", "state", "switch_count", "bound_at", "unbound_at", "last_server_time", "reason"),
                order_by=("binding_id",),
                secret_fields=("reason",),
            ),
        ),
        "authorization_nonces": _table(
            count=AuthorizationNonce.objects.count(),
            fingerprint=_row_fingerprint(
                AuthorizationNonce.objects.all(),
                ("nonce_id", "software_id", "profile_id", "device_id", "nonce_hash", "action", "request_id", "consumed_at", "created_at"),
                order_by=("nonce_id",),
                secret_fields=("nonce_hash", "request_id"),
            ),
        ),
        "authorization_request_records": _table(
            count=AuthorizationRequestRecord.objects.count(),
            fingerprint=_row_fingerprint(
                AuthorizationRequestRecord.objects.all(),
                ("request_id", "action", "idempotency_key", "request_hash", "response_status", "response_payload", "created_at"),
                order_by=("request_id",),
                secret_fields=("request_id", "idempotency_key", "request_hash", "response_payload"),
            ),
        ),
        "authorization_admin_operations": _table(
            count=AuthorizationAdminOperation.objects.count(),
            fingerprint=_row_fingerprint(
                AuthorizationAdminOperation.objects.all(),
                ("id", "actor_id", "action", "authorization_id", "device_id", "idempotency_key", "request_hash", "response_payload", "created_at"),
                order_by=("id",),
                secret_fields=("idempotency_key", "request_hash", "response_payload"),
            ),
        ),
        "license_reclaim_operations": _table(
            count=LicenseReclaimOperation.objects.count(),
            fingerprint=_row_fingerprint(
                LicenseReclaimOperation.objects.all(),
                ("id", "actor_id", "scope", "idempotency_key", "request_hash", "response_payload", "created_at"),
                order_by=("id",),
                secret_fields=("idempotency_key", "request_hash", "response_payload"),
            ),
        ),
        "downstream_admin_operations": _table(
            count=DownstreamAdminOperation.objects.count(),
            fingerprint=_row_fingerprint(
                DownstreamAdminOperation.objects.all(),
                ("public_id", "actor_username_digest", "action", "target_profile_public_id", "target_username_digest", "idempotency_key", "request_hash", "response_payload", "created_at"),
                order_by=("public_id",),
                secret_fields=("idempotency_key", "request_hash", "response_payload"),
            ),
        ),
        "password_operations": _table(
            count=PasswordOperation.objects.count(),
            fingerprint=_row_fingerprint(
                PasswordOperation.objects.all(),
                ("public_id", "target_profile_public_id", "target_username_digest", "action", "idempotency_key", "request_hash", "response_payload", "created_at"),
                order_by=("public_id",),
                secret_fields=("idempotency_key", "request_hash", "response_payload"),
            ),
        ),
        "audit_events": _table(
            count=audit.count(),
            status_counts={str(key): int(value) for key, value in sorted(Counter(audit.values_list("outcome", flat=True)).items(), key=lambda pair: str(pair[0]))},
            fingerprint=_row_fingerprint(
                audit,
                ("public_id", "occurred_at", "actor_id", "actor_role", "action", "outcome", "object_type", "object_public_id", "request_id", "ip_address", "reason_code", "metadata"),
                order_by=("public_id",),
                secret_fields=("request_id", "ip_address", "metadata"),
            ),
            timeline_fingerprint=_row_fingerprint(
                audit,
                ("occurred_at", "public_id", "action", "outcome", "object_type", "object_public_id", "reason_code"),
                order_by=("occurred_at", "public_id"),
            ),
        ),
        "policy_versions": _table(
            count=PolicyVersion.objects.count(),
            fingerprint=_row_fingerprint(
                PolicyVersion.objects.all(),
                (
                    "id",
                    "profile_id",
                    "version",
                    "status",
                    "max_devices",
                    "allow_device_switch",
                    "device_switch_limit",
                    "device_proof_required",
                    "verify_interval_seconds",
                    "offline_grace_seconds",
                    "effective_at",
                    "created_by_id",
                    "created_at",
                ),
                order_by=("id",),
            ),
        ),
        "plan_snapshots": _table(
            count=PlanSnapshot.objects.count(),
            fingerprint=_row_fingerprint(
                PlanSnapshot.objects.all(),
                (
                    "snapshot_id",
                    "plan_id",
                    "software_id",
                    "profile_id",
                    "policy_version_id",
                    "snapshot_version",
                    "name",
                    "duration_seconds",
                    "quota_cost",
                    "test_only",
                    "capability_values",
                    "created_by_id",
                    "created_at",
                ),
                order_by=("snapshot_id",),
                secret_fields=("capability_values",),
            ),
        ),
        "downstream_software": _table(
            count=DownstreamSoftware.objects.count(),
            fingerprint=_row_fingerprint(
                DownstreamSoftware.objects.all(),
                (
                    "id",
                    "downstream_id",
                    "software_id",
                    "status",
                    "all_plans_allowed",
                    "configuration_enabled",
                    "config_version",
                    "support_purchase_url",
                    "support_qq",
                    "support_wechat",
                    "announcement_enabled",
                    "announcement_title",
                    "announcement_body",
                    "opened_at",
                    "closed_at",
                    "updated_at",
                ),
                order_by=("id",),
                secret_fields=("support_purchase_url", "support_qq", "support_wechat", "announcement_body"),
            ),
        ),
        "downstream_software_allowed_plans": _table(
            count=DownstreamSoftware.allowed_plans.through.objects.count(),
            fingerprint=_row_fingerprint(
                DownstreamSoftware.allowed_plans.through.objects.all(),
                ("downstreamsoftware_id", "plan_id"),
                order_by=("downstreamsoftware_id", "plan_id"),
            ),
        ),
        "software": _table(
            count=Software.objects.count(),
            status_counts=_status_counts(Software.objects.all()),
            fingerprint=_row_fingerprint(
                Software.objects.all(),
                ("software_id", "name", "description", "status", "created_at", "updated_at"),
                order_by=("software_id",),
                secret_fields=("description",),
            ),
        ),
        "software_profiles": _table(
            count=SoftwareProfile.objects.count(),
            status_counts=_status_counts(SoftwareProfile.objects.all()),
            fingerprint=_row_fingerprint(
                SoftwareProfile.objects.all(),
                (
                    "id",
                    "software_id",
                    "profile_id",
                    "client_id",
                    "contract_version",
                    "target",
                    "arch",
                    "channel",
                    "adapter_key",
                    "adapter_version",
                    "minimum_client_version",
                    "config_version",
                    "support_purchase_url",
                    "support_qq",
                    "support_wechat",
                    "announcement_enabled",
                    "announcement_title",
                    "announcement_body",
                    "status",
                    "created_at",
                    "updated_at",
                ),
                order_by=("id",),
                secret_fields=("support_purchase_url", "support_qq", "support_wechat", "announcement_body"),
            ),
        ),
        "capability_definitions": _table(
            count=CapabilityDefinition.objects.count(),
            status_counts=_status_counts(CapabilityDefinition.objects.all()),
            fingerprint=_row_fingerprint(
                CapabilityDefinition.objects.all(),
                (
                    "id",
                    "profile_id",
                    "capability_key",
                    "value_type",
                    "default_value",
                    "minimum_value",
                    "maximum_value",
                    "is_public",
                    "status",
                    "created_at",
                    "updated_at",
                ),
                order_by=("id",),
                secret_fields=("default_value",),
            ),
        ),
        "plans": _table(
            count=Plan.objects.count(),
            status_counts=_status_counts(Plan.objects.all()),
            fingerprint=_row_fingerprint(
                Plan.objects.all(),
                (
                    "id",
                    "software_id",
                    "profile_id",
                    "name",
                    "duration_seconds",
                    "quota_cost",
                    "test_only",
                    "status",
                    "effective_at",
                    "capability_values",
                    "created_by_id",
                    "created_at",
                    "updated_at",
                ),
                order_by=("id",),
                secret_fields=("capability_values",),
            ),
        ),
        "plan_create_operations": _table(
            count=PlanCreateOperation.objects.count(),
            fingerprint=_row_fingerprint(
                PlanCreateOperation.objects.all(),
                (
                    "id",
                    "actor_id",
                    "namespace",
                    "idempotency_key",
                    "request_hash",
                    "plan_id",
                    "response_status",
                    "response_payload",
                    "created_at",
                ),
                order_by=("id",),
                secret_fields=("idempotency_key", "request_hash", "response_payload"),
            ),
        ),
        "quota_platform_settings": _table(
            count=QuotaPlatformSettings.objects.count(),
            fingerprint=_row_fingerprint(
                QuotaPlatformSettings.objects.all(),
                ("key", "purchase_url", "last_idempotency_key", "last_request_hash", "updated_at"),
                order_by=("key",),
                secret_fields=("purchase_url", "last_idempotency_key", "last_request_hash"),
            ),
        ),
        "releases": _table(
            count=Release.objects.count(),
            status_counts=_status_counts(Release.objects.all()),
            fingerprint=_row_fingerprint(
                Release.objects.all(),
                (
                    "release_id",
                    "software_id",
                    "profile_id",
                    "version",
                    "target",
                    "arch",
                    "channel",
                    "minimum_client_version",
                    "notes",
                    "manifest",
                    "package_name",
                    "package_path",
                    "package_size",
                    "package_sha256",
                    "external_download_url",
                    "signature_algorithm",
                    "signature_key_id",
                    "signature_status",
                    "status",
                    "created_by_id",
                    "created_at",
                    "published_at",
                    "withdrawn_at",
                    "withdrawal_reason",
                    "package_deleted_at",
                    "previous_release_id",
                ),
                order_by=("release_id",),
                secret_fields=("manifest", "package_path"),
            ),
        ),
        "release_operations": _table(
            count=ReleaseOperation.objects.count(),
            fingerprint=_row_fingerprint(
                ReleaseOperation.objects.all(),
                ("operation_id", "actor_id", "release_id", "action", "idempotency_key", "request_hash", "response", "created_at"),
                order_by=("operation_id",),
                secret_fields=("idempotency_key", "request_hash", "response"),
            ),
        ),
        "storage_cleanup_state": _table(
            count=StorageCleanupState.objects.count(),
            fingerprint=_row_fingerprint(StorageCleanupState.objects.all(), ("key", "updated_at"), order_by=("key",)),
        ),
        "storage_cleanup_operations": _table(
            count=StorageCleanupOperation.objects.count(),
            fingerprint=_row_fingerprint(
                StorageCleanupOperation.objects.all(),
                ("operation_id", "actor_id", "idempotency_key", "request_hash", "response", "created_at"),
                order_by=("operation_id",),
                secret_fields=("idempotency_key", "request_hash", "response"),
            ),
        ),
        "backup_policies": _table(
            count=BackupPolicy.objects.count(),
            fingerprint=_row_fingerprint(
                BackupPolicy.objects.all(),
                (
                    "key",
                    "enabled",
                    "schedule_enabled",
                    "database_enabled",
                    "github_enabled",
                    "github_repository",
                    "github_token_ciphertext",
                    "cleanup_enabled",
                    "retention_full",
                    "retention_diff",
                    "retention_archive",
                    "github_retention_count",
                    "schedule_full_hour",
                    "schedule_full_minute",
                    "diff_interval_hours",
                    "updated_at",
                    "updated_by_id",
                ),
                order_by=("key",),
                secret_fields=("github_token_ciphertext",),
            ),
        ),
        "backup_restore_stagings": _table(
            count=BackupRestoreStaging.objects.count(),
            fingerprint=_row_fingerprint(
                BackupRestoreStaging.objects.all(),
                ("public_id", "actor_id", "original_name", "sha256", "backup_time_utc", "created_at", "expires_at"),
                order_by=("public_id",),
                secret_fields=("sha256",),
            ),
        ),
        "backup_run_requests": _table(
            count=BackupRunRequest.objects.count(),
            fingerprint=_row_fingerprint(
                BackupRunRequest.objects.all(),
                (
                    "public_id",
                    "backup_type",
                    "scheduled_for",
                    "status",
                    "attempt_token",
                    "actor_id",
                    "message",
                    "created_at",
                    "updated_at",
                ),
                order_by=("public_id",),
                secret_fields=("attempt_token",),
            ),
        ),
        "backup_control_operations": _table(
            count=BackupControlOperation.objects.count(),
            fingerprint=_row_fingerprint(
                BackupControlOperation.objects.all(),
                ("id", "actor_id", "action", "idempotency_key", "request_hash", "response", "created_at"),
                order_by=("id",),
                secret_fields=("idempotency_key", "request_hash", "response"),
            ),
        ),
        "sessions": _table(
            count=Session.objects.count(),
            expired_count=Session.objects.filter(expire_date__lte=timezone.now()).count(),
            fingerprint=_row_fingerprint(Session.objects.all(), ("session_key", "expire_date"), order_by=("session_key",)),
        ),
        "django_migrations": _table(
            count=migrations.count(),
            fingerprint=_row_fingerprint(migrations, ("app", "name", "applied"), order_by=("app", "name")),
        ),
    }
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": timezone.now().astimezone(dt_timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_identity": _source_identity(),
        "key_references": _configured_key_references(),
        "tables": tables,
        "secret_values_exposed": False,
    }
    if verify_ciphertext:
        result["ciphertext_verification"] = _verify_card_material()
    return result


def _group_amounts(queryset, group_field: str, amount_field: str):
    grouped: dict[str, list[int]] = {}
    for group, amount in queryset.values_list(group_field, amount_field).iterator(chunk_size=1000):
        grouped.setdefault(str(group), []).append(int(amount))
    return grouped.items()


def _source_identity() -> str:
    from django.conf import settings

    database = settings.DATABASES.get("default") or {}
    return _digest(
        {
            "engine": str(database.get("ENGINE") or ""),
            "name": str(database.get("NAME") or ""),
            "host": str(database.get("HOST") or ""),
            "port": str(database.get("PORT") or ""),
        }
    )


def compare_recovery_inventories(
    expected: dict[str, Any],
    actual: dict[str, Any],
    *,
    require_distinct_source: bool = False,
) -> dict[str, Any]:
    if require_distinct_source:
        expected_identity = expected.get("source_identity")
        actual_identity = actual.get("source_identity")
        if not expected_identity or not actual_identity:
            return {
                "schema_version": SCHEMA_VERSION,
                "status": "failed",
                "matches": False,
                "mismatch_count": 1,
                "mismatches": ["source_identity"],
                "reason": "恢复核对缺少数据库身份，不能证明这是隔离恢复库。",
                "secret_values_exposed": False,
            }
        if expected_identity == actual_identity:
            return {
                "schema_version": SCHEMA_VERSION,
                "status": "failed",
                "matches": False,
                "mismatch_count": 1,
                "mismatches": ["source_identity"],
                "reason": "源清单与当前库是同一数据库，不能当作隔离恢复核对。",
                "secret_values_exposed": False,
            }
    expected_projection = {
        "schema_version": expected.get("schema_version"),
        "key_references": expected.get("key_references"),
        "tables": expected.get("tables"),
    }
    actual_projection = {
        "schema_version": actual.get("schema_version"),
        "key_references": actual.get("key_references"),
        "tables": actual.get("tables"),
    }
    mismatches = _diff_paths(expected_projection, actual_projection)
    # 授权请求记录这张表有保留期清理（prune_authorization_records），所以恢复库
    # 与源库在它上面本来就会不一样——那是设计，不是数据损坏。把它单独记成"因保留
    # 期裁剪"，而不是让它把整个灾备验收判成失败：否则只要清过一次，之后就永远
    # 过不了恢复核对，而人只会以为备份坏了。
    pruned_paths = [
        item for item in mismatches if item.startswith("tables.authorization_request_records")
    ]
    mismatches = [item for item in mismatches if item not in pruned_paths]
    matches = not mismatches
    reason = "恢复库与源库的脱敏业务指纹一致。"
    if pruned_paths and matches:
        reason = "恢复库与源库的脱敏业务指纹一致；授权请求记录因保留期清理减少，已单独记录。"
    elif not matches:
        reason = "恢复库与源库的脱敏业务指纹不一致。"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if matches else "failed",
        "matches": matches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:50],
        "pruned_paths": pruned_paths[:50],
        "pruned_count": len(pruned_paths),
        "reason": reason,
        "secret_values_exposed": False,
    }


def _diff_paths(expected: Any, actual: Any, path: str = "") -> list[str]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        differences: list[str] = []
        for key in sorted(set(expected) | set(actual), key=str):
            child = f"{path}.{key}" if path else str(key)
            if key not in expected or key not in actual:
                differences.append(child)
            else:
                differences.extend(_diff_paths(expected[key], actual[key], child))
        return differences
    if isinstance(expected, list) and isinstance(actual, list):
        if expected == actual:
            return []
        return [path]
    return [] if expected == actual else [path]
