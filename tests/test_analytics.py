from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone as datetime_timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import create_plan, create_policy_version, create_profile, create_software, set_downstream_software_access
from authorization_platform.credits.models import QuotaAccount, QuotaLedgerDirection, QuotaLedgerEntry, QuotaLedgerOperation
from authorization_platform.licensing.models import AuthorizationState, LicenseCard, LicenseCardBatch, LicenseCardStatus, LicenseInstance


User = get_user_model()
BEIJING = ZoneInfo("Asia/Shanghai")


def _beijing_today_noon():
    today = timezone.localdate(timezone=BEIJING)
    return timezone.make_aware(datetime.combine(today, time(12, 0)), BEIJING)


class AnalyticsApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="analytics-admin", password="Admin-password-123")
        self.downstream = create_downstream_direct(actor=self.admin, username="analytics-downstream", password="Downstream-password-123")
        self.other = create_downstream_direct(actor=self.admin, username="analytics-other", password="Downstream-password-123")
        self.software = create_software(actor=self.admin, software_id="analytics-tool", name="Analytics Tool", status=SoftwareStatus.ACTIVE)
        self.profile = create_profile(actor=self.admin, software_id="analytics-tool", profile_id="stable", client_id="analytics-tool-windows", status=ProfileStatus.ACTIVE)
        self.policy = create_policy_version(actor=self.admin, software_id="analytics-tool", profile_id="stable", version="policy-1", status=PolicyStatus.ACTIVE)
        self.plan, self.snapshot = create_plan(actor=self.admin, software_id="analytics-tool", profile_id="stable", policy_version="policy-1", name="月卡", duration_seconds=30 * 86400, quota_cost=15, status=PlanStatus.ACTIVE)
        set_downstream_software_access(actor=self.admin, downstream_public_id=self.downstream.public_id, software_id="analytics-tool", enabled=True, all_plans_allowed=True)
        today_noon = _beijing_today_noon()
        issued_at = today_noon - timedelta(hours=1)
        self.batch = LicenseCardBatch.objects.create(
            software=self.software, profile=self.profile, plan_snapshot=self.snapshot,
            original_downstream=self.downstream, current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id, current_downstream_public_id=self.downstream.public_id,
            quantity=1, quota_cost_per_card=15, total_quota_cost=15, idempotency_key="analytics-batch", request_hash="a" * 64,
            created_by=self.downstream.user, created_at=issued_at,
        )
        self.card = LicenseCard.objects.create(
            batch=self.batch, software=self.software, profile=self.profile, plan_snapshot=self.snapshot,
            original_downstream=self.downstream, current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id, current_downstream_public_id=self.downstream.public_id,
            quota_cost=15, card_hash="b" * 64, card_ciphertext="cipher", status=LicenseCardStatus.ACTIVATED,
            issued_by=self.downstream.user, issued_at=issued_at, activated_at=today_noon, expires_at=today_noon + timedelta(days=29),
        )
        self.instance = LicenseInstance.objects.create(
            license_card=self.card, software=self.software, profile=self.profile, plan_snapshot=self.snapshot, policy_version=self.policy,
            current_downstream_public_id=self.downstream.public_id, client_id=self.profile.client_id, contract_version="authorization.v1",
            target="windows", arch="x64", channel="stable", client_version="1.0.0", state=AuthorizationState.ACTIVE,
            activated_at=today_noon, expires_at=today_noon + timedelta(days=29),
        )
        account = QuotaAccount.objects.create(downstream=self.downstream, downstream_public_id=self.downstream.public_id, available_balance=85)
        QuotaLedgerEntry.objects.create(
            account=account, downstream_public_id=self.downstream.public_id, direction=QuotaLedgerDirection.DEBIT,
            amount=15, operation_type=QuotaLedgerOperation.LICENSE_CARD_ISSUE, source_type="LicenseCardBatch", source_public_id=str(self.batch.batch_id),
            idempotency_key="analytics-ledger", request_hash="c" * 64, actor=self.downstream.user, balance_before=100, balance_after=85,
        )
        record_event(actor=None, action="authorization.activate", outcome=AuditOutcome.SUCCESS, request_id="analytics-success", object_type="LicenseInstance", object_public_id=self.instance.authorization_id, metadata={"software_id": "analytics-tool", "downstream_public_id": str(self.downstream.public_id)})

    def _login_downstream(self, client):
        client.force_login(self.downstream.user)
        session = client.session
        session["downstream_session_version"] = self.downstream.session_version
        session.save()

    def test_admin_summary_uses_real_records_and_filters_server_side(self):
        client = Client()
        client.force_login(self.admin)
        response = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-tool", "downstream_id": str(self.downstream.public_id), "window": "7d"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["revenue"]["total"], 15)
        self.assertEqual(payload["active_authorizations"], 1)
        self.assertEqual(payload["quota_net_consumed"], 15)
        self.assertEqual(payload["activation_success_rate"], 100.0)
        self.assertTrue(payload["has_data"])
        unused = LicenseCard.objects.create(
            batch=self.batch, software=self.software, profile=self.profile, plan_snapshot=self.snapshot,
            original_downstream=self.downstream, current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id, current_downstream_public_id=self.downstream.public_id,
            quota_cost=40, card_hash="unactivated" + "0" * 53, card_ciphertext="cipher-unused", status=LicenseCardStatus.UNUSED,
            issued_by=self.downstream.user, issued_at=timezone.now(),
        )
        unused_check = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-tool", "window": "7d"})
        self.assertEqual(unused_check.status_code, 200)
        self.assertEqual(unused_check.json()["revenue"]["total"], 15)
        older_activated = timezone.now() - timedelta(days=40)
        LicenseCard.objects.create(
            batch=self.batch, software=self.software, profile=self.profile, plan_snapshot=self.snapshot,
            original_downstream=self.downstream, current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id, current_downstream_public_id=self.downstream.public_id,
            quota_cost=7, card_hash="older" + "0" * 59, card_ciphertext="cipher-older", status=LicenseCardStatus.ACTIVATED,
            issued_by=self.downstream.user, issued_at=older_activated, activated_at=older_activated,
            expires_at=older_activated + timedelta(days=29),
        )
        exported = client.get(
            reverse("analytics:manage_summary_export"),
            {"software_id": "analytics-tool", "downstream_id": str(self.downstream.public_id), "window": "7d"},
        )
        self.assertEqual(exported.status_code, 200)
        body = exported.content.decode("utf-8").replace("\ufeff", "")
        self.assertIn("今日收入(额度),15,", body)
        self.assertIn("本月收入(额度),15,", body)
        self.assertIn("累计收入(额度),22,", body)
        self.assertTrue(AuditEvent.objects.filter(action="analytics.export").exists())
        empty = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-tool", "window": "empty"})
        self.assertEqual(empty.status_code, 200)
        empty_payload = empty.json()
        self.assertFalse(empty_payload["has_data"])
        self.assertEqual(empty_payload["quota_net_consumed"], 0)
        self.assertEqual(empty_payload["software_breakdown"], [])
        self.assertEqual(empty_payload["active_authorizations"], 1)
        self.assertTrue(all(item["activations"] == 0 and item["revenue"] == 0 for item in empty_payload["trend"]))
        self.assertEqual(empty_payload["revenue"]["today"], 15)
        self.assertEqual(empty_payload["revenue"]["month"], 15)
        self.assertEqual(empty_payload["revenue"]["total"], 22)
        month = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-tool", "window": "30d"})
        self.assertEqual(month.status_code, 200)
        self.assertEqual(month.json()["window"], "30d")
        self.assertGreaterEqual((date.fromisoformat(month.json()["range"]["to"]) - date.fromisoformat(month.json()["range"]["from"])).days, 29)

    def test_risk_pending_includes_frozen_cards_not_just_blocked_devices(self):
        client = Client()
        client.force_login(self.admin)
        before = client.get(reverse("analytics:manage_summary"), {"window": "30d"}).json()["risk_pending"]
        self.instance.state = AuthorizationState.BLOCKED
        self.instance.save(update_fields=("state",), _allow_mutation=True)
        after = client.get(reverse("analytics:manage_summary"), {"window": "30d"}).json()["risk_pending"]
        self.assertEqual(after, before + 1)

    def test_downstream_scope_cannot_be_forged_and_empty_window_is_real(self):
        client = Client()
        self._login_downstream(client)
        forged = client.get(reverse("analytics:downstream_summary"), {"software_id": "analytics-tool", "downstream_id": str(self.other.public_id), "window": "7d"})
        self.assertEqual(forged.status_code, 200)
        self.assertEqual(forged.json()["revenue"]["total"], 15)
        empty = client.get(reverse("analytics:downstream_summary"), {"software_id": "analytics-tool", "window": "empty"})
        self.assertEqual(empty.status_code, 200)
        empty_payload = empty.json()
        self.assertFalse(empty_payload["has_data"])
        self.assertEqual(empty_payload["quota_net_consumed"], 0)
        self.assertEqual(empty_payload["software_breakdown"], [])
        self.assertEqual(empty_payload["revenue"]["total"], 15)
        self.assertEqual(empty_payload["downstream"]["balance"], 85)
        self.assertEqual(empty_payload["downstream"]["active"], 1)

    def test_revenue_day_boundary_is_explicitly_beijing_time(self):
        beijing_midnight = datetime(2026, 1, 31, 16, 0, tzinfo=datetime_timezone.utc)
        boundary_batch = LicenseCardBatch.objects.create(
            software=self.software, profile=self.profile, plan_snapshot=self.snapshot,
            original_downstream=self.downstream, current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id, current_downstream_public_id=self.downstream.public_id,
            quantity=1, quota_cost_per_card=15, total_quota_cost=15, idempotency_key="analytics-boundary-batch", request_hash="d" * 64,
            created_by=self.downstream.user, created_at=beijing_midnight,
        )
        LicenseCard.objects.create(
            batch=boundary_batch, software=self.software, profile=self.profile, plan_snapshot=self.snapshot,
            original_downstream=self.downstream, current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id, current_downstream_public_id=self.downstream.public_id,
            quota_cost=15, card_hash="e" * 64, card_ciphertext="cipher-boundary", status=LicenseCardStatus.ACTIVATED,
            issued_by=self.downstream.user, issued_at=beijing_midnight, activated_at=beijing_midnight,
            expires_at=beijing_midnight + timedelta(days=29),
        )
        with patch("authorization_platform.analytics.services.timezone.now", return_value=datetime(2026, 2, 1, 0, 30, tzinfo=datetime_timezone.utc)), patch(
            "authorization_platform.analytics.services.timezone.localdate", return_value=date(2026, 2, 1)
        ):
            client = Client()
            client.force_login(self.admin)
            response = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-tool", "window": "7d"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["timezone"], "Asia/Shanghai")
        self.assertEqual(payload["revenue"]["today"], 15)
        self.assertEqual(payload["revenue"]["month"], 15)
        self.assertEqual(payload["trend"][-1]["date"], "2026-02-01")
        self.assertEqual(payload["trend"][-1]["revenue"], 15)

    def test_quota_net_consumed_does_not_include_other_software_ledger(self):
        other_software = create_software(
            actor=self.admin,
            software_id="analytics-other-tool",
            name="Analytics Other",
            status=SoftwareStatus.ACTIVE,
        )
        other_profile = create_profile(
            actor=self.admin,
            software_id="analytics-other-tool",
            profile_id="stable",
            client_id="analytics-other-windows",
            status=ProfileStatus.ACTIVE,
        )
        create_policy_version(
            actor=self.admin,
            software_id="analytics-other-tool",
            profile_id="stable",
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        _plan, other_snapshot = create_plan(
            actor=self.admin,
            software_id="analytics-other-tool",
            profile_id="stable",
            policy_version="policy-1",
            name="季卡",
            duration_seconds=90 * 86400,
            quota_cost=40,
            status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream.public_id,
            software_id="analytics-other-tool",
            enabled=True,
            all_plans_allowed=True,
        )
        now = timezone.now()
        other_batch = LicenseCardBatch.objects.create(
            software=other_software,
            profile=other_profile,
            plan_snapshot=other_snapshot,
            original_downstream=self.downstream,
            current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id,
            current_downstream_public_id=self.downstream.public_id,
            quantity=1,
            quota_cost_per_card=40,
            total_quota_cost=40,
            idempotency_key="analytics-other-batch",
            request_hash="f" * 64,
            created_by=self.downstream.user,
            created_at=now,
        )
        other_card = LicenseCard.objects.create(
            batch=other_batch,
            software=other_software,
            profile=other_profile,
            plan_snapshot=other_snapshot,
            original_downstream=self.downstream,
            current_downstream=self.downstream,
            original_downstream_public_id=self.downstream.public_id,
            current_downstream_public_id=self.downstream.public_id,
            quota_cost=10,
            card_hash="g" * 64,
            card_ciphertext="cipher-other",
            status=LicenseCardStatus.RECLAIMED,
            issued_by=self.downstream.user,
            issued_at=now,
            reclaimed_at=now,
        )
        account = QuotaAccount.objects.get(downstream_public_id=self.downstream.public_id)
        QuotaLedgerEntry.objects.create(
            account=account,
            downstream_public_id=self.downstream.public_id,
            direction=QuotaLedgerDirection.DEBIT,
            amount=40,
            operation_type=QuotaLedgerOperation.LICENSE_CARD_ISSUE,
            source_type="LicenseCardBatch",
            source_public_id=str(other_batch.batch_id),
            idempotency_key=f"license-batch:{other_batch.batch_id}",
            request_hash="f0" * 32,
            actor=self.downstream.user,
            balance_before=85,
            balance_after=45,
        )
        QuotaLedgerEntry.objects.create(
            account=account,
            downstream_public_id=self.downstream.public_id,
            direction=QuotaLedgerDirection.DEBIT,
            amount=99,
            operation_type=QuotaLedgerOperation.LICENSE_CARD_ISSUE,
            source_type="LicenseCard",
            source_public_id=str(other_card.public_id),
            idempotency_key="analytics-decoy-card-issue",
            request_hash="h" * 64,
            actor=self.downstream.user,
            balance_before=100,
            balance_after=1,
        )
        QuotaLedgerEntry.objects.create(
            account=account,
            downstream_public_id=self.downstream.public_id,
            direction=QuotaLedgerDirection.CREDIT,
            amount=10,
            operation_type=QuotaLedgerOperation.LICENSE_CARD_RECLAIM,
            source_type="LicenseCard",
            source_public_id=str(other_card.public_id),
            idempotency_key="analytics-other-reclaim",
            request_hash="i" * 64,
            actor=self.downstream.user,
            balance_before=45,
            balance_after=55,
        )
        client = Client()
        client.force_login(self.admin)
        scoped_a = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-tool", "window": "7d"})
        scoped_b = client.get(reverse("analytics:manage_summary"), {"software_id": "analytics-other-tool", "window": "7d"})
        unscoped = client.get(reverse("analytics:manage_summary"), {"window": "7d"})
        self.assertEqual(scoped_a.status_code, 200)
        self.assertEqual(scoped_b.status_code, 200)
        self.assertEqual(unscoped.status_code, 200)
        self.assertEqual(scoped_a.json()["quota_net_consumed"], 15)
        self.assertEqual(scoped_a.json()["revenue"]["total"], 15)
        self.assertEqual(scoped_b.json()["quota_net_consumed"], 30)
        self.assertEqual(scoped_b.json()["revenue"]["total"], 0)
        self.assertEqual(unscoped.json()["quota_net_consumed"], 45)
        self._login_downstream(client)
        downstream_a = client.get(reverse("analytics:downstream_summary"), {"software_id": "analytics-tool", "window": "7d"})
        self.assertEqual(downstream_a.status_code, 200)
        self.assertEqual(downstream_a.json()["quota_net_consumed"], 15)


class ActivatedRevenueContractTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="revenue-admin", password="Admin-password-123")
        self.alpha = create_downstream_direct(actor=self.admin, username="revenue-alpha", password="Downstream-password-123")
        self.beta = create_downstream_direct(actor=self.admin, username="revenue-beta", password="Downstream-password-123")
        self.software = create_software(actor=self.admin, software_id="revenue-shop", name="Revenue Shop", status=SoftwareStatus.ACTIVE)
        self.profile = create_profile(actor=self.admin, software_id="revenue-shop", profile_id="stable", client_id="revenue-shop-windows", status=ProfileStatus.ACTIVE)
        self.policy = create_policy_version(actor=self.admin, software_id="revenue-shop", profile_id="stable", version="policy-1", status=PolicyStatus.ACTIVE)
        self.monthly, self.monthly_snap = create_plan(
            actor=self.admin, software_id="revenue-shop", profile_id="stable", policy_version="policy-1",
            name="月卡", duration_seconds=30 * 86400, quota_cost=10, status=PlanStatus.ACTIVE,
        )
        self.daily, self.daily_snap = create_plan(
            actor=self.admin, software_id="revenue-shop", profile_id="stable", policy_version="policy-1",
            name="天卡", duration_seconds=86400, quota_cost=1, status=PlanStatus.ACTIVE,
        )
        self.trial, self.trial_snap = create_plan(
            actor=self.admin, software_id="revenue-shop", profile_id="stable", policy_version="policy-1",
            name="测试卡", duration_seconds=60, quota_cost=0, test_only=True, status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(actor=self.admin, downstream_public_id=self.alpha.public_id, software_id="revenue-shop", enabled=True, all_plans_allowed=True)
        set_downstream_software_access(actor=self.admin, downstream_public_id=self.beta.public_id, software_id="revenue-shop", enabled=True, all_plans_allowed=True)
        self.now = _beijing_today_noon()
        self._seq = 0

    def _login_downstream(self, client, profile):
        client.force_login(profile.user)
        session = client.session
        session["downstream_session_version"] = profile.session_version
        session.save()

    def _next_token(self, prefix):
        self._seq += 1
        return f"{prefix}{self._seq:04d}".ljust(64, "0")

    def _make_batch(self, *, downstream, snapshot, unit, qty, key):
        return LicenseCardBatch.objects.create(
            software=self.software, profile=self.profile, plan_snapshot=snapshot,
            original_downstream=downstream, current_downstream=downstream,
            original_downstream_public_id=downstream.public_id, current_downstream_public_id=downstream.public_id,
            quantity=qty, quota_cost_per_card=unit, total_quota_cost=unit * qty,
            idempotency_key=key, request_hash=key.ljust(64, "b")[:64],
            created_by=downstream.user, created_at=self.now,
        )

    def _make_card(self, *, batch, downstream, snapshot, cost, activated=False, with_instance=False):
        card = LicenseCard.objects.create(
            batch=batch, software=self.software, profile=self.profile, plan_snapshot=snapshot,
            original_downstream=downstream, current_downstream=downstream,
            original_downstream_public_id=downstream.public_id, current_downstream_public_id=downstream.public_id,
            quota_cost=cost, card_hash=self._next_token("card"), card_ciphertext=f"cipher-{self._seq}",
            status=LicenseCardStatus.ACTIVATED if activated else LicenseCardStatus.UNUSED,
            issued_by=downstream.user, issued_at=self.now,
            activated_at=self.now if activated else None,
            expires_at=(self.now + timedelta(days=29)) if activated else None,
        )
        if with_instance:
            LicenseInstance.objects.create(
                license_card=card, software=self.software, profile=self.profile, plan_snapshot=snapshot,
                policy_version=self.policy, current_downstream_public_id=downstream.public_id,
                client_id=self.profile.client_id, contract_version="authorization.v1",
                target="windows", arch="x64", channel="stable", client_version="1.0.0",
                state=AuthorizationState.ACTIVE, activated_at=self.now, expires_at=self.now + timedelta(days=29),
            )
        return card

    def _issue(self, *, downstream, snapshot, cost, qty, key, activated=False, with_instance=False):
        batch = self._make_batch(downstream=downstream, snapshot=snapshot, unit=cost, qty=qty, key=key)
        return [self._make_card(batch=batch, downstream=downstream, snapshot=snapshot, cost=cost, activated=activated, with_instance=with_instance) for _ in range(qty)]

    def test_downstream_revenue_is_activated_plan_cost_and_admin_is_the_sum(self):
        self._issue(downstream=self.alpha, snapshot=self.monthly_snap, cost=10, qty=10, key="alpha-month-on", activated=True)
        self._issue(downstream=self.alpha, snapshot=self.daily_snap, cost=1, qty=5, key="alpha-day-on", activated=True)
        self._issue(downstream=self.alpha, snapshot=self.monthly_snap, cost=10, qty=3, key="alpha-month-off")
        self._issue(downstream=self.beta, snapshot=self.monthly_snap, cost=10, qty=2, key="beta-month-on", activated=True)

        admin = Client()
        admin.force_login(self.admin)
        alpha_client = Client()
        self._login_downstream(alpha_client, self.alpha)
        beta_client = Client()
        self._login_downstream(beta_client, self.beta)

        alpha = alpha_client.get(reverse("analytics:downstream_summary"), {"software_id": "all", "window": "7d"})
        beta = beta_client.get(reverse("analytics:downstream_summary"), {"software_id": "all", "window": "7d"})
        platform = admin.get(reverse("analytics:manage_summary"), {"software_id": "all", "downstream_id": "all", "window": "7d"})
        only_alpha = admin.get(reverse("analytics:manage_summary"), {"software_id": "all", "downstream_id": str(self.alpha.public_id), "window": "7d"})

        self.assertEqual(alpha.status_code, 200)
        self.assertEqual(beta.status_code, 200)
        self.assertEqual(platform.status_code, 200)
        self.assertEqual(alpha.json()["revenue"], {"today": 105, "month": 105, "total": 105})
        self.assertEqual(beta.json()["revenue"], {"today": 20, "month": 20, "total": 20})
        self.assertEqual(platform.json()["revenue"]["total"], 125)
        self.assertEqual(platform.json()["revenue"]["today"], 125)
        self.assertEqual(platform.json()["revenue"]["month"], 125)
        self.assertEqual(only_alpha.json()["revenue"]["total"], 105)
        self.assertEqual(platform.json()["revenue"]["total"], alpha.json()["revenue"]["total"] + beta.json()["revenue"]["total"])

    def test_admin_total_still_equals_the_sum_after_a_downstream_is_deleted(self):
        """删掉一个有过已激活真卡的下游之后，管理端总额必须仍等于各桶之和。

        以前删除只把外键置空、裸 UUID 留在卡上，于是总额继续算着这笔钱，
        而下拉框里已经没有它能列的地方——差额无声发生，而且永久不自愈。
        现在它进「已删除下游」这个桶，点得进去、看得见。
        """
        from authorization_platform.accounts.models import DownstreamStatus
        from authorization_platform.accounts.services import delete_archived_downstream
        from authorization_platform.credits.models import QuotaAccount

        self._issue(downstream=self.alpha, snapshot=self.monthly_snap, cost=10, qty=1, key="gone-on", activated=True)
        self._issue(downstream=self.beta, snapshot=self.monthly_snap, cost=10, qty=1, key="stay-on", activated=True)

        admin = Client()
        admin.force_login(self.admin)
        url = reverse("analytics:manage_summary")

        before = admin.get(url, {"software_id": "all", "downstream_id": "all", "window": "7d"}).json()
        self.assertEqual(before["revenue"]["total"], 20)

        QuotaAccount.objects.filter(downstream_public_id=self.alpha.public_id).update(available_balance=0)
        self.alpha.status = DownstreamStatus.CLOSED
        self.alpha.save(update_fields=["status"])
        delete_archived_downstream(actor=self.admin, public_id=self.alpha.public_id, reason="测试删除")

        after = admin.get(url, {"software_id": "all", "downstream_id": "all", "window": "7d"}).json()
        # 总额不变：历史收入不会因为账号被删就凭空消失。
        self.assertEqual(after["revenue"]["total"], 20)

        options = after["filters"]["downstream"]
        bucket = next((item for item in options if item["id"] == "deleted"), None)
        self.assertIsNotNone(bucket, options)
        self.assertIn("已删除下游", bucket["name"])
        self.assertNotIn(
            self.alpha.user.username,
            [item["name"] for item in options],
            "a deleted downstream must not reappear by name; the tombstone keeps only a digest",
        )

        # 逐桶求和必须等于总额——这就是合同里那句"等于各下游之和"。
        total = after["revenue"]["total"]
        listed = 0
        for option in options:
            row = admin.get(url, {"software_id": "all", "downstream_id": option["id"], "window": "7d"}).json()
            listed += row["revenue"]["total"]
        self.assertEqual(listed, total)

        gone = admin.get(url, {"software_id": "all", "downstream_id": "deleted", "window": "7d"}).json()
        self.assertEqual(gone["revenue"]["total"], 10)

    def test_zero_cost_activated_cards_keep_live_count_without_revenue(self):
        self._issue(downstream=self.alpha, snapshot=self.trial_snap, cost=0, qty=7, key="alpha-trial-on", activated=True, with_instance=True)
        self._issue(downstream=self.alpha, snapshot=self.trial_snap, cost=0, qty=1, key="alpha-trial-off")

        client = Client()
        self._login_downstream(client, self.alpha)
        payload = client.get(reverse("analytics:downstream_summary"), {"software_id": "all", "window": "7d"}).json()
        self.assertEqual(payload["downstream"]["active"], 7)
        self.assertEqual(payload["downstream"]["reclaimable"], 1)
        self.assertEqual(payload["revenue"], {"today": 0, "month": 0, "total": 0})
