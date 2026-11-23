from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from authorization_platform.accounts.models import (
    DownstreamProfile,
    DownstreamStatus,
    InvitationBatch,
    InvitationCode,
    InvitationStatus,
    RegistrationSource,
)
from authorization_platform.accounts.services import encrypt_invitation_code, invitation_code_hash
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.catalog.models import (
    DownstreamSoftware,
    Plan,
    PlanSnapshot,
    PlanStatus,
    PolicyStatus,
    PolicyVersion,
    ProfileStatus,
    Software,
    SoftwareProfile,
    SoftwareStatus,
)
from authorization_platform.credits.models import (
    QuotaAccount,
    QuotaCard,
    QuotaCardBatch,
    QuotaCardStatus,
    QuotaLedgerDirection,
    QuotaLedgerEntry,
    QuotaLedgerOperation,
)
from authorization_platform.credits.services import encrypt_quota_card, quota_card_hash
from authorization_platform.licensing.models import (
    AuthorizationState,
    Device,
    DeviceBinding,
    DeviceBindingState,
    DeviceKey,
    LicenseCard,
    LicenseCardBatch,
    LicenseCardStatus,
    LicenseInstance,
)
from authorization_platform.licensing.services import encrypt_license_card, license_card_hash


class Command(BaseCommand):
    help = "在新建的隔离数据库中写入包含卡密、额度、授权、设备和审计的恢复验收夹具。"

    @transaction.atomic
    def handle(self, *args, **options):
        if Software.objects.filter(software_id="recovery-fixture").exists():
            self.stdout.write("恢复验收夹具已存在，跳过重复写入。")
            return

        user_model = get_user_model()
        admin = user_model.objects.create(
            username="recovery-fixture-admin",
            is_active=True,
            is_staff=True,
            is_superuser=True,
        )
        admin.set_unusable_password()
        admin.save(update_fields=("password",))
        downstream_user = user_model.objects.create(username="recovery-fixture-downstream", is_active=True)
        downstream_user.set_unusable_password()
        downstream_user.save(update_fields=("password",))
        profile = DownstreamProfile.objects.create(
            user=downstream_user,
            status=DownstreamStatus.ACTIVE,
            registration_source=RegistrationSource.DIRECT,
            created_by=admin,
        )

        software = Software.objects.create(
            software_id="recovery-fixture",
            name="恢复验收夹具",
            status=SoftwareStatus.ACTIVE,
        )
        client_profile = SoftwareProfile.objects.create(
            software=software,
            profile_id="stable",
            client_id="recovery-fixture-client",
            status=ProfileStatus.ACTIVE,
        )
        policy = PolicyVersion.objects.create(
            profile=client_profile,
            version="policy-1",
            status=PolicyStatus.ACTIVE,
            max_devices=2,
            allow_device_switch=True,
            device_switch_limit=1,
            created_by=admin,
        )
        plan = Plan.objects.create(
            software=software,
            profile=client_profile,
            name="恢复验收套餐",
            duration_seconds=86400,
            quota_cost=10,
            status=PlanStatus.ACTIVE,
            created_by=admin,
        )
        snapshot = PlanSnapshot.objects.create(
            plan=plan,
            software=software,
            profile=client_profile,
            policy_version=policy,
            snapshot_version=1,
            name=plan.name,
            duration_seconds=plan.duration_seconds,
            quota_cost=plan.quota_cost,
            created_by=admin,
        )
        DownstreamSoftware.objects.create(
            downstream=profile,
            software=software,
            status="active",
            all_plans_allowed=True,
        )

        now = timezone.now()
        quota_account = QuotaAccount.objects.create(
            downstream=profile,
            downstream_public_id=profile.public_id,
            available_balance=0,
        )
        QuotaLedgerEntry.objects.create(
            account=quota_account,
            downstream_public_id=profile.public_id,
            direction=QuotaLedgerDirection.CREDIT,
            amount=100,
            operation_type=QuotaLedgerOperation.MANUAL_CREDIT,
            source_type="RecoveryFixture",
            source_public_id="quota-opening",
            idempotency_key="recovery-fixture-opening",
            request_hash="recovery-fixture-opening-hash",
            actor=admin,
            reason="恢复验收夹具期初额度",
            balance_before=0,
            balance_after=100,
            occurred_at=now,
        )
        quota_batch = QuotaCardBatch.objects.create(
            amount=50,
            quantity=3,
            idempotency_key="recovery-fixture-quota-batch",
            request_hash="recovery-fixture-quota-batch-hash",
            created_by=admin,
            created_at=now,
        )
        quota_codes = (
            ("RECOVERY-QUOTA-ISSUED", QuotaCardStatus.ISSUED),
            ("RECOVERY-QUOTA-REDEEMED", QuotaCardStatus.REDEEMED),
            ("RECOVERY-QUOTA-REVOKED", QuotaCardStatus.REVOKED),
        )
        for code, status in quota_codes:
            card = QuotaCard.objects.create(
                batch=quota_batch,
                amount=50,
                card_hash=quota_card_hash(code),
                card_ciphertext=encrypt_quota_card(code),
                status=status,
                issued_by=admin,
                issued_at=now,
            )
            if status == QuotaCardStatus.REDEEMED:
                QuotaLedgerEntry.objects.create(
                    account=quota_account,
                    downstream_public_id=profile.public_id,
                    direction=QuotaLedgerDirection.CREDIT,
                    amount=50,
                    operation_type=QuotaLedgerOperation.CARD_REDEEM,
                    source_type="QuotaCard",
                    source_public_id=str(card.public_id),
                    idempotency_key="recovery-fixture-quota-redeem",
                    request_hash="recovery-fixture-quota-redeem-hash",
                    actor=downstream_user,
                    reason="恢复验收夹具兑换额度",
                    balance_before=100,
                    balance_after=150,
                    occurred_at=now + timedelta(seconds=1),
                )
                card.redeemed_by = profile
                card.redeemed_by_public_id = profile.public_id
                card.redeemed_at = now
                card.save(update_fields=("redeemed_by", "redeemed_by_public_id", "redeemed_at"), _allow_mutation=True)
            elif status == QuotaCardStatus.REVOKED:
                card.revoked_at = now
                card.revoke_reason = "恢复验收夹具作废"
                card.revoke_idempotency_key = "recovery-fixture-quota-revoke"
                card.revoke_request_hash = "recovery-fixture-quota-revoke-hash"
                card.save(
                    update_fields=("revoked_at", "revoke_reason", "revoke_idempotency_key", "revoke_request_hash"),
                    _allow_mutation=True,
                )
        quota_account.available_balance = 150
        quota_account.save(update_fields=("available_balance", "updated_at"), _allow_mutation=True)

        invitation_batch = InvitationBatch.objects.create(created_by=admin, quantity=2)
        issued_invitation = "RECOVERY-INVITATION-ISSUED"
        consumed_invitation = "RECOVERY-INVITATION-CONSUMED"
        InvitationCode.objects.create(
            batch=invitation_batch,
            code_hash=invitation_code_hash(issued_invitation),
            code_ciphertext=encrypt_invitation_code(issued_invitation),
            status=InvitationStatus.ISSUED,
        )
        InvitationCode.objects.create(
            batch=invitation_batch,
            code_hash=invitation_code_hash(consumed_invitation),
            code_ciphertext=encrypt_invitation_code(consumed_invitation),
            status=InvitationStatus.CONSUMED,
            consumed_at=now,
            consumed_profile=profile,
            consumed_username=downstream_user.username,
            consumed_username_digest=invitation_code_hash(downstream_user.username),
        )

        license_batch = LicenseCardBatch.objects.create(
            software=software,
            profile=client_profile,
            plan_snapshot=snapshot,
            original_downstream=profile,
            current_downstream=profile,
            original_downstream_public_id=profile.public_id,
            current_downstream_public_id=profile.public_id,
            quantity=3,
            quota_cost_per_card=10,
            total_quota_cost=30,
            source="recovery-fixture",
            idempotency_key="recovery-fixture-license-batch",
            request_hash="recovery-fixture-license-batch-hash",
            created_by=downstream_user,
            created_at=now,
        )
        license_specs = (
            ("RECOVERY-LICENSE-UNUSED", LicenseCardStatus.UNUSED),
            ("RECOVERY-LICENSE-ACTIVATED", LicenseCardStatus.ACTIVATED),
            ("RECOVERY-LICENSE-RECLAIMED", LicenseCardStatus.RECLAIMED),
        )
        activated_card = None
        for code, status in license_specs:
            card = LicenseCard.objects.create(
                batch=license_batch,
                software=software,
                profile=client_profile,
                plan_snapshot=snapshot,
                original_downstream=profile,
                current_downstream=profile,
                original_downstream_public_id=profile.public_id,
                current_downstream_public_id=profile.public_id,
                quota_cost=10,
                card_hash=license_card_hash(code),
                card_ciphertext=encrypt_license_card(code),
                status=status,
                issued_by=downstream_user,
                issued_at=now,
                activated_at=now if status == LicenseCardStatus.ACTIVATED else None,
                expires_at=now + timedelta(days=1) if status == LicenseCardStatus.ACTIVATED else None,
                reclaimed_at=now if status == LicenseCardStatus.RECLAIMED else None,
                status_reason="恢复验收夹具状态",
            )
            if status == LicenseCardStatus.ACTIVATED:
                activated_card = card

        device = Device.objects.create(
            software=software,
            profile=client_profile,
            installation_hash="recovery-fixture-installation-hash",
            first_seen_at=now,
            last_seen_at=now,
        )
        device_key = DeviceKey.objects.create(
            key_id="recovery-fixture-device-key",
            device=device,
            public_key="recovery-fixture-public-key",
        )
        authorization = LicenseInstance.objects.create(
            license_card=activated_card,
            software=software,
            profile=client_profile,
            plan_snapshot=snapshot,
            policy_version=policy,
            current_downstream_public_id=profile.public_id,
            client_id=client_profile.client_id,
            client_version="1.0.0-fixture",
            target="windows",
            arch="x86_64",
            channel="stable",
            state=AuthorizationState.ACTIVE,
            expires_at=now + timedelta(days=1),
        )
        DeviceBinding.objects.create(
            authorization=authorization,
            device=device,
            device_key=device_key,
            state=DeviceBindingState.ACTIVE,
            bound_at=now,
        )
        AuditEvent.objects.create(
            actor=admin,
            actor_role="platform_admin",
            action="recovery.fixture.created",
            outcome=AuditOutcome.SUCCESS,
            object_type="RecoveryFixture",
            object_public_id="recovery-fixture",
            request_id="recovery-fixture-request",
            reason_code="",
            metadata={"purpose": "isolated_restore_acceptance", "cards": 3, "quota_cards": 3},
            occurred_at=now,
        )
        self.stdout.write("恢复验收夹具已准备：包含邀请码、额度卡、额度流水、未激活/已激活/已回收授权卡、授权实例、设备绑定和审计事件。")
