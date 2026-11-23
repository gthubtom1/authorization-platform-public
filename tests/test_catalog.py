from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent
from types import SimpleNamespace

from authorization_platform.catalog.configuration import (
    ConfigurationOperationError,
    _base_configuration_for_authorization,
    _configuration_response,
    update_downstream_configuration,
    update_profile_configuration,
)
from authorization_platform.catalog.models import (
    CapabilityValueType,
    DownstreamSoftware,
    DownstreamSoftwareOperation,
    Plan,
    PlanCreateOperation,
    PlanLifecycleOperation,
    PlanRevisionOperation,
    PlanSnapshot,
    PlanStatus,
    PolicyRevisionOperation,
    PolicyStatus,
    PolicyVersion,
    ProfileStatus,
    Software,
    SoftwareStatus,
    SoftwareProfile,
)
from authorization_platform.catalog.services import (
    CatalogOperationError,
    accessible_plans_for,
    backfill_default_daily_device_switch,
    create_capability_definition,
    create_plan,
    create_policy_version,
    create_profile,
    create_software,
    delete_plan,
    list_accessible_software,
    revise_plan,
    revise_policy_version,
    set_downstream_software_access,
    set_plan_status,
    update_software_status,
)
from authorization_platform.credits.services import credit_quota, get_quota_account
from authorization_platform.licensing.models import LicenseCard, LicenseCardStatus
from authorization_platform.licensing.services import generate_license_batch
from authorization_platform.core.legacy_html import CONTROL_ROOM_COPY, FORBIDDEN_API_COPY


User = get_user_model()


class CatalogServiceTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")

    def _software_graph(self, software_id="software-a", *, capability_key="feature.export"):
        software = create_software(actor=self.admin, software_id=software_id, name=f"软件 {software_id}", status=SoftwareStatus.ACTIVE)
        profile = create_profile(actor=self.admin, software_id=software.software_id, profile_id="stable", client_id=f"{software_id}-windows", status=ProfileStatus.ACTIVE)
        policy = create_policy_version(actor=self.admin, software_id=software.software_id, profile_id=profile.profile_id, version="policy-1", status=PolicyStatus.ACTIVE)
        capability = create_capability_definition(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            capability_key=capability_key,
            value_type=CapabilityValueType.BOOLEAN,
            default_value=False,
        )
        return software, profile, policy, capability

    def test_software_profile_policy_capability_and_snapshot_are_created_together(self):
        software, profile, policy, capability = self._software_graph()
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="一分钟测试卡",
            duration_seconds=60,
            quota_cost=2,
            test_only=True,
            capability_values={capability.capability_key: True},
            status=PlanStatus.ACTIVE,
        )

        self.assertEqual(snapshot.duration_seconds, 60)
        self.assertEqual(snapshot.quota_cost, 2)
        self.assertTrue(snapshot.test_only)
        self.assertEqual(snapshot.capability_values, {"feature.export": True})
        self.assertEqual(plan.latest_snapshot.snapshot_id, snapshot.snapshot_id)
        self.assertEqual(profile.policy_versions.get().profile_id, profile.id)
        self.assertEqual(policy.verify_interval_seconds, 60)

    def test_software_namespaces_allow_same_profile_and_capability_ids(self):
        first = self._software_graph("software-a")
        second = self._software_graph("software-b")

        self.assertEqual(first[1].profile_id, second[1].profile_id)
        self.assertEqual(first[3].capability_key, second[3].capability_key)
        self.assertNotEqual(first[1].software_id, second[1].software_id)
        self.assertEqual(first[1].capabilities.count(), 1)
        self.assertEqual(second[1].capabilities.count(), 1)

    def test_plan_revisions_create_new_snapshot_without_mutating_old_snapshot(self):
        software, profile, policy, capability = self._software_graph()
        plan, first_snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="基础套餐",
            duration_seconds=60,
            quota_cost=1,
            capability_values={capability.capability_key: False},
            status=PlanStatus.ACTIVE,
        )
        _, second_snapshot = revise_plan(
            actor=self.admin,
            plan_id=plan.pk,
            policy_version=policy.version,
            name="基础套餐升级",
            duration_seconds=3600,
            quota_cost=1,
            capability_values={capability.capability_key: True},
            status=PlanStatus.ACTIVE,
        )

        self.assertEqual(PlanSnapshot.objects.filter(plan=plan).count(), 2)
        first_snapshot.refresh_from_db()
        self.assertEqual(first_snapshot.snapshot_version, 1)
        self.assertEqual(first_snapshot.duration_seconds, 60)
        self.assertEqual(first_snapshot.capability_values, {capability.capability_key: False})
        self.assertEqual(second_snapshot.snapshot_version, 2)
        self.assertEqual(second_snapshot.duration_seconds, 3600)
        self.assertEqual(second_snapshot.capability_values, {capability.capability_key: True})
        with self.assertRaises(ValueError):
            PlanSnapshot.objects.filter(pk=first_snapshot.pk).update(quota_cost=0)
        with self.assertRaises(ValueError):
            PlanSnapshot.objects.filter(pk=first_snapshot.pk).delete()

    def test_plan_archive_and_restore_preserve_snapshot_history(self):
        software, profile, policy, _ = self._software_graph()
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="可归档套餐",
            duration_seconds=3600,
            quota_cost=4,
            status=PlanStatus.ACTIVE,
        )

        archived, changed = set_plan_status(
            actor=self.admin,
            plan_id=plan.pk,
            status=PlanStatus.ARCHIVED,
            reason="下线旧套餐",
        )
        self.assertTrue(changed)
        self.assertEqual(archived.status, PlanStatus.ARCHIVED)
        self.assertEqual(PlanSnapshot.objects.filter(plan=plan).count(), 1)
        self.assertEqual(snapshot.snapshot_version, 1)

        restored, changed = set_plan_status(
            actor=self.admin,
            plan_id=plan.pk,
            status=PlanStatus.ACTIVE,
            reason="恢复销售套餐",
        )
        self.assertTrue(changed)
        self.assertEqual(restored.status, PlanStatus.ACTIVE)
        self.assertEqual(PlanSnapshot.objects.filter(plan=plan).count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="plan.status.update").count(), 2)

    def test_archived_plan_cannot_be_restored_when_policy_is_not_active(self):
        software, profile, policy, _ = self._software_graph("archived-policy")
        plan, _ = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="策略归档套餐",
            duration_seconds=3600,
            quota_cost=1,
            status=PlanStatus.ARCHIVED,
        )
        policy.status = PolicyStatus.ARCHIVED
        policy.save(_allow_mutation=True, update_fields=("status",))
        with self.assertRaises(CatalogOperationError) as error:
            set_plan_status(
                actor=self.admin,
                plan_id=plan.pk,
                status=PlanStatus.ACTIVE,
                reason="尝试恢复套餐",
            )
        self.assertEqual(error.exception.code, "POLICY_NOT_ACTIVE")

    def test_archived_plan_delete_reclaims_unused_cards_and_hides_from_catalog(self):
        from authorization_platform.catalog.api_views import _software_payload

        software, profile, policy, _ = self._software_graph("delete-plan")
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="待删测试套餐",
            duration_seconds=60,
            quota_cost=4,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        kept_plan, kept_snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="留下的套餐",
            duration_seconds=86400,
            quota_cost=1,
            status=PlanStatus.ACTIVE,
        )
        downstream = create_downstream_direct(
            actor=self.admin,
            username="delete-plan-downstream",
            password="Downstream-password-123",
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=downstream.public_id,
            software_id=software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        credit_quota(
            actor=self.admin,
            downstream=downstream,
            amount=20,
            reason="套餐删除测试额度",
            idempotency_key="delete-plan-credit",
        )
        generate_license_batch(
            actor=downstream.user,
            software_id=software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=2,
            idempotency_key="delete-plan-issue",
        )
        generate_license_batch(
            actor=downstream.user,
            software_id=software.software_id,
            plan_snapshot_id=kept_snapshot.snapshot_id,
            quantity=1,
            idempotency_key="delete-plan-kept-issue",
        )

        set_plan_status(actor=self.admin, plan_id=plan.pk, status=PlanStatus.ARCHIVED, reason="下线测试套餐")
        result = delete_plan(actor=self.admin, plan_id=plan.pk, reason="清理测试套餐堆积")

        self.assertTrue(result.changed)
        self.assertEqual(result.unused_invalidated, 2)
        self.assertEqual(result.activated_revoked, 0)
        self.assertEqual(result.quota_refunded, 8)
        plan.refresh_from_db()
        self.assertEqual(plan.status, PlanStatus.DELETED)
        self.assertEqual(PlanSnapshot.objects.filter(plan=plan).count(), 1)
        self.assertEqual(
            set(LicenseCard.objects.filter(plan_snapshot__plan=plan).values_list("status", flat=True)),
            {LicenseCardStatus.RECLAIMED},
        )
        kept_card = LicenseCard.objects.get(plan_snapshot=kept_snapshot)
        self.assertEqual(kept_card.status, LicenseCardStatus.UNUSED)
        self.assertEqual(get_quota_account(downstream).available_balance, 19)

        names = [item["name"] for item in _software_payload(software)["plans"]]
        self.assertNotIn("待删测试套餐", names)
        self.assertIn("留下的套餐", names)

        with self.assertRaises(CatalogOperationError) as restore_error:
            set_plan_status(actor=self.admin, plan_id=plan.pk, status=PlanStatus.ACTIVE, reason="尝试恢复已删套餐")
        self.assertEqual(restore_error.exception.code, "PLAN_DELETED")
        repeated = delete_plan(actor=self.admin, plan_id=plan.pk, reason="再次删除已删套餐")
        self.assertFalse(repeated.changed)

    def test_active_plan_cannot_be_deleted(self):
        software, profile, policy, _ = self._software_graph("active-delete")
        plan, _ = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="仍在卖的套餐",
            duration_seconds=3600,
            quota_cost=1,
            status=PlanStatus.ACTIVE,
        )
        with self.assertRaises(CatalogOperationError) as error:
            delete_plan(actor=self.admin, plan_id=plan.pk, reason="直接删除在卖套餐")
        self.assertEqual(error.exception.code, "PLAN_NOT_ARCHIVED")
        plan.refresh_from_db()
        self.assertEqual(plan.status, PlanStatus.ACTIVE)

    def test_unregistered_or_wrong_type_capability_is_rejected(self):
        software, profile, policy, _ = self._software_graph()
        with self.assertRaises(CatalogOperationError) as unknown:
            create_plan(
                actor=self.admin,
                software_id=software.software_id,
                profile_id=profile.profile_id,
                policy_version=policy.version,
                name="错误套餐",
                duration_seconds=60,
                quota_cost=1,
                capability_values={"feature.unknown": True},
            )
        self.assertEqual(unknown.exception.code, "CAPABILITY_NOT_REGISTERED")

        with self.assertRaises(CatalogOperationError) as wrong_type:
            create_plan(
                actor=self.admin,
                software_id=software.software_id,
                profile_id=profile.profile_id,
                policy_version=policy.version,
                name="错误类型套餐",
                duration_seconds=60,
                quota_cost=1,
                capability_values={"feature.export": "yes"},
            )
        self.assertEqual(wrong_type.exception.code, "INVALID_CAPABILITY_VALUE")

    def test_official_plan_rejects_zero_quota_cost_while_test_plan_allows_zero(self):
        software, profile, policy, _ = self._software_graph("zero-cost")
        with self.assertRaises(CatalogOperationError) as official:
            create_plan(
                actor=self.admin,
                software_id=software.software_id,
                profile_id=profile.profile_id,
                policy_version=policy.version,
                name="零成本正式套餐",
                duration_seconds=86400,
                quota_cost=0,
                test_only=False,
                status=PlanStatus.ACTIVE,
            )
        self.assertEqual(official.exception.code, "INVALID_QUOTA_COST")
        plan, snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=policy.version,
            name="零成本测试套餐",
            duration_seconds=60,
            quota_cost=0,
            test_only=True,
            status=PlanStatus.ACTIVE,
        )
        self.assertEqual(snapshot.quota_cost, 0)
        self.assertTrue(plan.test_only)
        with self.assertRaises(CatalogOperationError) as revised:
            revise_plan(
                actor=self.admin,
                plan_id=plan.pk,
                policy_version=policy.version,
                name="测试改成正式零成本",
                duration_seconds=60,
                quota_cost=0,
                test_only=False,
                status=PlanStatus.ACTIVE,
            )
        self.assertEqual(revised.exception.code, "INVALID_QUOTA_COST")


    def test_policy_revision_creates_new_active_version_and_archives_old_policy(self):
        software, profile, old_policy, _ = self._software_graph("policy-revision")
        revised = revise_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            max_devices=3,
            allow_device_switch=True,
            device_switch_limit=2,
            device_proof_required=True,
            verify_interval_seconds=1800,
            offline_grace_seconds=7200,
            request_id="policy-revision-test",
        )
        self.assertNotEqual(revised.version, old_policy.version)
        self.assertEqual(revised.status, PolicyStatus.ACTIVE)
        self.assertEqual(revised.max_devices, 3)
        self.assertTrue(revised.allow_device_switch)
        self.assertEqual(revised.device_switch_limit, 2)
        self.assertEqual(revised.verify_interval_seconds, 1800)
        self.assertEqual(revised.offline_grace_seconds, 7200)
        self.assertEqual(PolicyVersion.objects.get(pk=old_policy.pk).status, PolicyStatus.ARCHIVED)
        self.assertTrue(AuditEvent.objects.filter(action="policy_version.revise").exists())

    def test_backfill_default_daily_device_switch_is_noop_when_empty(self):
        self.assertEqual(backfill_default_daily_device_switch(actor=self.admin), [])

    def test_backfill_default_daily_device_switch_skips_customized_and_revises_closed(self):
        closed_software, closed_profile, closed_policy, capability = self._software_graph("closed-switch")
        plan, first_snapshot = create_plan(
            actor=self.admin,
            software_id=closed_software.software_id,
            profile_id=closed_profile.profile_id,
            policy_version=closed_policy.version,
            name="关换机套餐",
            duration_seconds=3600,
            quota_cost=1,
            capability_values={capability.capability_key: True},
            status=PlanStatus.ACTIVE,
        )
        custom_software, custom_profile, custom_policy, _ = self._software_graph("custom-switch")
        customized = revise_policy_version(
            actor=self.admin,
            software_id=custom_software.software_id,
            profile_id=custom_profile.profile_id,
            max_devices=custom_policy.max_devices,
            allow_device_switch=True,
            device_switch_limit=2,
            device_proof_required=True,
            verify_interval_seconds=custom_policy.verify_interval_seconds,
            offline_grace_seconds=custom_policy.offline_grace_seconds,
            request_id="custom-switch-keep",
        )
        created = backfill_default_daily_device_switch(actor=self.admin)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].profile_id, closed_profile.pk)
        self.assertTrue(created[0].allow_device_switch)
        self.assertEqual(created[0].device_switch_limit, 5)
        self.assertEqual(created[0].max_devices, closed_policy.max_devices)
        self.assertEqual(PolicyVersion.objects.get(pk=closed_policy.pk).status, PolicyStatus.ARCHIVED)
        latest = plan.latest_snapshot
        self.assertNotEqual(latest.snapshot_id, first_snapshot.snapshot_id)
        self.assertEqual(latest.policy_version_id, created[0].pk)
        kept = PolicyVersion.objects.get(pk=customized.pk)
        self.assertEqual(kept.status, PolicyStatus.ACTIVE)
        self.assertTrue(kept.allow_device_switch)
        self.assertEqual(kept.device_switch_limit, 2)

    def test_policy_revision_mints_new_snapshots_so_plans_can_restore_and_issue(self):
        software, profile, old_policy, capability = self._software_graph("policy-revision-snapshot")
        plan, first_snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            policy_version=old_policy.version,
            name="策略修订后仍可发卡",
            duration_seconds=3600,
            quota_cost=1,
            capability_values={capability.capability_key: True},
            status=PlanStatus.ACTIVE,
        )
        revised = revise_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id=profile.profile_id,
            max_devices=4,
            allow_device_switch=False,
            device_switch_limit=0,
            device_proof_required=True,
            verify_interval_seconds=900,
            offline_grace_seconds=0,
        )
        latest = Plan.objects.get(pk=plan.pk).latest_snapshot
        self.assertNotEqual(latest.snapshot_id, first_snapshot.snapshot_id)
        self.assertEqual(latest.policy_version_id, revised.pk)
        self.assertEqual(PlanSnapshot.objects.get(pk=first_snapshot.snapshot_id).policy_version_id, old_policy.pk)
        restored, changed = set_plan_status(
            actor=self.admin,
            plan_id=plan.pk,
            status=PlanStatus.ARCHIVED,
            reason="先归档再恢复",
        )
        self.assertTrue(changed)
        restored, changed = set_plan_status(
            actor=self.admin,
            plan_id=plan.pk,
            status=PlanStatus.ACTIVE,
            reason="策略修订后恢复套餐",
        )
        self.assertTrue(changed)
        self.assertEqual(restored.status, PlanStatus.ACTIVE)


class DownstreamScopeTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(actor=self.admin, username="downstream-a", password="Downstream-password-123")
        self.downstream_b = create_downstream_direct(actor=self.admin, username="downstream-b", password="Downstream-password-123")
        self.software = create_software(actor=self.admin, software_id="software-a", name="软件 A", status=SoftwareStatus.ACTIVE)
        self.profile = create_profile(actor=self.admin, software_id="software-a", profile_id="stable", client_id="software-a-windows", status=ProfileStatus.ACTIVE)
        self.policy = create_policy_version(actor=self.admin, software_id="software-a", profile_id="stable", version="policy-1", status=PolicyStatus.ACTIVE)
        self.plan_one, _ = create_plan(actor=self.admin, software_id="software-a", profile_id="stable", policy_version="policy-1", name="一分钟测试卡", duration_seconds=60, test_only=True, status=PlanStatus.ACTIVE)
        self.plan_two, _ = create_plan(actor=self.admin, software_id="software-a", profile_id="stable", policy_version="policy-1", name="一天正式卡", duration_seconds=86400, quota_cost=1, status=PlanStatus.ACTIVE)

    def test_downstream_sees_only_opened_software_and_selected_plans(self):
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            enabled=True,
            all_plans_allowed=False,
            allowed_plan_ids=[self.plan_one.pk],
        )

        visible = list(list_accessible_software(self.downstream_a.user))
        plans = list(accessible_plans_for(self.downstream_a.user, self.software.software_id))
        self.assertEqual([item.software_id for item in visible], ["software-a"])
        self.assertEqual([item.pk for item in plans], [self.plan_one.pk])
        self.assertEqual(list(list_accessible_software(self.downstream_b.user)), [])
        self.assertEqual(DownstreamSoftware.objects.filter(downstream=self.downstream_b).count(), 0)

    def test_cross_software_plan_cannot_be_granted(self):
        other = create_software(actor=self.admin, software_id="software-b", name="软件 B", status=SoftwareStatus.ACTIVE)
        with self.assertRaises(CatalogOperationError) as invalid:
            set_downstream_software_access(
                actor=self.admin,
                downstream_public_id=self.downstream_a.public_id,
                software_id=other.software_id,
                enabled=True,
                all_plans_allowed=False,
                allowed_plan_ids=[self.plan_one.pk],
            )
        self.assertEqual(invalid.exception.code, "PLAN_SCOPE_REQUIRED")
        self.assertFalse(DownstreamSoftware.objects.filter(downstream=self.downstream_a, software=other).exists())

    def test_archived_downstream_cannot_receive_new_software_scope(self):
        self.downstream_a.status = "closed"
        self.downstream_a.user.is_active = False
        self.downstream_a.user.save(update_fields=["is_active"])
        self.downstream_a.save(update_fields=["status", "updated_at"])
        with self.assertRaises(CatalogOperationError) as invalid:
            set_downstream_software_access(
                actor=self.admin,
                downstream_public_id=self.downstream_a.public_id,
                software_id=self.software.software_id,
                enabled=True,
            )
        self.assertEqual(invalid.exception.code, "DOWNSTREAM_NOT_ACTIVE")

    def test_archiving_software_closes_existing_downstream_scope_without_reopening_it(self):
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            enabled=True,
        )
        update_software_status(actor=self.admin, software_id=self.software.software_id, status=SoftwareStatus.ARCHIVED)
        access = DownstreamSoftware.objects.get(downstream=self.downstream_a, software=self.software)
        self.assertEqual(access.status, "closed")
        self.assertEqual(list(list_accessible_software(self.downstream_a.user)), [])
        update_software_status(actor=self.admin, software_id=self.software.software_id, status=SoftwareStatus.ACTIVE)
        self.assertEqual(list(list_accessible_software(self.downstream_a.user)), [])


class ConfigurationServiceTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(actor=self.admin, username="downstream-a", password="Downstream-password-123")
        self.downstream_b = create_downstream_direct(actor=self.admin, username="downstream-b", password="Downstream-password-123")
        self.software = create_software(actor=self.admin, software_id="config-tool", name="配置软件", status=SoftwareStatus.ACTIVE)
        self.profile = SoftwareProfile.objects.get(
            pk=create_profile(
                actor=self.admin,
                software_id=self.software.software_id,
                profile_id="stable",
                client_id="config-tool-windows",
                status=ProfileStatus.ACTIVE,
            ).pk
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            enabled=True,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_b.public_id,
            software_id=self.software.software_id,
            enabled=True,
        )

    @staticmethod
    def _values(prefix: str) -> dict:
        return {
            "purchase_url": f"https://{prefix}.example.test/buy",
            "qq": f"{prefix}-qq",
            "wechat": f"{prefix}-wechat",
            "announcement_enabled": True,
            "announcement_title": f"{prefix}公告",
            "announcement_body": f"{prefix}内容",
        }

    def test_profile_and_downstream_configuration_versions_change_and_clear_disables_override(self):
        original_version = self.profile.config_version
        updated_profile = update_profile_configuration(
            actor=self.admin,
            profile=self.profile,
            values=self._values("profile"),
        )
        self.assertNotEqual(updated_profile.config_version, original_version)
        profile_version = updated_profile.config_version

        access = update_downstream_configuration(
            actor=self.downstream_a.user,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            values=self._values("downstream"),
        )
        self.assertTrue(access.configuration_enabled)
        downstream_version = access.config_version
        self.assertNotEqual(downstream_version, profile_version)
        self.assertEqual(SoftwareProfile.objects.get(pk=self.profile.pk).config_version, profile_version)
        self.assertEqual(access.support_purchase_url, "https://downstream.example.test/buy")

        cleared = update_downstream_configuration(
            actor=self.downstream_a.user,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            clear=True,
        )
        self.assertFalse(cleared.configuration_enabled)
        self.assertEqual(cleared.support_purchase_url, "")
        self.assertEqual(cleared.announcement_title, "")
        self.assertNotEqual(cleared.config_version, downstream_version)
        self.assertEqual(SoftwareProfile.objects.get(pk=self.profile.pk).config_version, profile_version)

    def test_downstream_configuration_is_tenant_scoped_and_validated(self):
        with self.assertRaises(ConfigurationOperationError) as forbidden:
            update_downstream_configuration(
                actor=self.downstream_a.user,
                downstream_public_id=self.downstream_b.public_id,
                software_id=self.software.software_id,
                values=self._values("attacker"),
            )
        self.assertEqual(forbidden.exception.code, "FORBIDDEN")

        with self.assertRaises(ConfigurationOperationError) as unsafe_url:
            update_downstream_configuration(
                actor=self.downstream_a.user,
                downstream_public_id=self.downstream_a.public_id,
                software_id=self.software.software_id,
                values={**self._values("safe"), "purchase_url": "javascript:alert(1)"},
            )
        self.assertEqual(unsafe_url.exception.code, "INVALID_CONFIGURATION_URL")

        with self.assertRaises(ConfigurationOperationError) as empty_announcement:
            update_profile_configuration(
                actor=self.admin,
                profile=self.profile,
                values={"announcement_enabled": True},
            )
        self.assertEqual(empty_announcement.exception.code, "INVALID_CONFIGURATION")

    def test_empty_downstream_wechat_does_not_inherit_profile_contact(self):
        update_profile_configuration(
            actor=self.admin,
            profile=self.profile,
            values=self._values("profile"),
        )
        instance = SimpleNamespace(
            profile=SoftwareProfile.objects.get(pk=self.profile.pk),
            current_downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
        )
        unset_values, _ = _base_configuration_for_authorization(instance)
        self.assertEqual(unset_values["purchase_url"], "")
        self.assertEqual(unset_values["qq"], "")
        self.assertEqual(unset_values["wechat"], "")
        self.assertIsNone(_configuration_response(unset_values)["support"])

        update_downstream_configuration(
            actor=self.downstream_a.user,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            values={
                "purchase_url": "https://shop.example/cdk",
                "qq": "",
                "wechat": "",
            },
        )
        values, _ = _base_configuration_for_authorization(instance)
        self.assertEqual(values["purchase_url"], "https://shop.example/cdk")
        self.assertEqual(values["qq"], "")
        self.assertEqual(values["wechat"], "")
        payload = _configuration_response(values)
        self.assertEqual(payload["support"]["purchase_url"], "https://shop.example/cdk")
        self.assertIsNone(payload["support"]["qq"])
        self.assertIsNone(payload["support"]["wechat"])

    def test_omitted_downstream_wechat_keeps_stored_value_without_inheriting_profile(self):
        update_profile_configuration(
            actor=self.admin,
            profile=self.profile,
            values=self._values("profile"),
        )
        update_downstream_configuration(
            actor=self.downstream_a.user,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            values={
                "purchase_url": "https://shop.example/cdk",
                "qq": "keep-qq",
                "wechat": "keep-wechat",
            },
        )
        update_downstream_configuration(
            actor=self.downstream_a.user,
            downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
            values={"purchase_url": "https://shop.example/new", "qq": "new-qq"},
        )
        access = DownstreamSoftware.objects.get(
            downstream=self.downstream_a,
            software_id=self.software.software_id,
        )
        self.assertEqual(access.support_purchase_url, "https://shop.example/new")
        self.assertEqual(access.support_qq, "new-qq")
        self.assertEqual(access.support_wechat, "keep-wechat")
        instance = SimpleNamespace(
            profile=SoftwareProfile.objects.get(pk=self.profile.pk),
            current_downstream_public_id=self.downstream_a.public_id,
            software_id=self.software.software_id,
        )
        values, _ = _base_configuration_for_authorization(instance)
        self.assertEqual(values["wechat"], "keep-wechat")
        self.assertNotEqual(values["wechat"], "profile-wechat")


class CatalogViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="admin", password="Admin-password-123")

    def test_admin_can_create_software_from_control_room(self):
        client = Client()
        client.force_login(self.admin)
        response = client.post(
            reverse("catalog:software_create"),
            {"software_id": "skin-tool", "name": "Skin Tool", "description": "测试软件", "status": "active"},
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)
        self.assertFalse(Software.objects.filter(software_id="skin-tool").exists())

    def test_downstream_cannot_open_management_catalog_and_sees_no_unopened_software(self):
        software = create_software(actor=self.admin, software_id="hidden-tool", name="隐藏软件", status=SoftwareStatus.ACTIVE)
        create_downstream_direct(actor=self.admin, username="downstream", password="Downstream-password-123")
        client = Client()
        login_response = client.post(reverse("accounts:downstream_login"), {"username": "downstream", "password": "Downstream-password-123"})
        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(client.get(reverse("catalog:software_list")).status_code, 403)
        response = client.get(reverse("catalog:downstream_software"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "管理员还没有开放软件")
        self.assertNotContains(response, software.name)

    def test_admin_can_build_profile_policy_capability_and_plan_from_pages(self):
        client = Client()
        client.force_login(self.admin)
        software_response = client.post(
            reverse("catalog:software_create"),
            {"software_id": "page-tool", "name": "Page Tool", "description": "页面流程", "status": "active"},
        )
        self.assertContains(software_response, CONTROL_ROOM_COPY, status_code=410)
        profile_response = client.post(
            reverse("catalog:profile_create", kwargs={"software_id": "page-tool"}),
            {"profile_id": "stable", "client_id": "page-tool-windows", "contract_version": "authorization.v1", "target": "windows", "arch": "x64", "channel": "stable", "adapter_key": "generic-online-v1", "adapter_version": "1", "status": "active"},
        )
        self.assertContains(profile_response, CONTROL_ROOM_COPY, status_code=410)
        policy_response = client.post(
            reverse("catalog:policy_create", kwargs={"software_id": "page-tool", "profile_id": "stable"}),
            {"version": "policy-1", "max_devices": 1, "device_switch_limit": 0, "device_proof_required": "on", "verify_interval_seconds": 21600, "offline_grace_seconds": 0, "status": "active"},
        )
        self.assertContains(policy_response, CONTROL_ROOM_COPY, status_code=410)
        capability_response = client.post(
            reverse("catalog:capability_create", kwargs={"software_id": "page-tool", "profile_id": "stable"}),
            {"capability_key": "feature.export", "value_type": "boolean", "default_value": "false", "is_public": "on", "status": "active"},
        )
        self.assertContains(capability_response, CONTROL_ROOM_COPY, status_code=410)
        plan_response = client.post(
            reverse("catalog:plan_create", kwargs={"software_id": "page-tool"}),
            {"profile": 1, "policy_version": 1, "name": "页面测试卡", "duration_value": 1, "duration_unit": "minute", "quota_cost": 0, "test_only": "on", "capability_values": '{"feature.export": true}', "status": "active"},
        )
        self.assertContains(plan_response, CONTROL_ROOM_COPY, status_code=410)
        self.assertFalse(Software.objects.filter(software_id="page-tool").exists())
        self.assertEqual(PlanSnapshot.objects.filter(plan__software_id="page-tool").count(), 0)


class CatalogApiTests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.admin = User.objects.create_superuser(username="api-admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(
            actor=self.admin,
            username="api-downstream-a",
            password="Downstream-password-123",
        )
        self.downstream_b = create_downstream_direct(
            actor=self.admin,
            username="api-downstream-b",
            password="Downstream-password-123",
        )

    def csrf_headers(self):
        response = self.client.get(reverse("accounts:api_session"))
        self.assertEqual(response.status_code, 200)
        return {"HTTP_X_CSRFTOKEN": self.client.cookies["csrftoken"].value}

    def post_json(self, url, payload, *, headers=None):
        request_headers = self.csrf_headers()
        request_headers.update(headers or {})
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            **request_headers,
        )

    @staticmethod
    def bundle_payload(software_id="api-alpha", *, name="Alpha Desktop", quota_cost=15):
        return {
            "software_id": software_id,
            "name": name,
            "description": "API test software",
            "target": "windows",
            "profile_id": f"{software_id}-profile",
            "client_id": f"{software_id}-client",
            "contract_version": "authorization.v1",
            "arch": "x64",
            "channel": "stable",
            "adapter_key": "generic-online-v1",
            "adapter_version": "1",
            "minimum_client_version": "",
            "policy_version": "policy-1",
            "policy_status": "active",
            "profile_status": "active",
            "software_status": "active",
            "plan_status": "active",
            "max_devices": 1,
            "allow_device_switch": False,
            "device_switch_limit": 0,
            "device_proof_required": True,
            "verify_interval_minutes": 15,
            "offline_grace_hours": 0,
            "plan_name": "月卡",
            "duration_value": 30,
            "duration_unit": "day",
            "quota_cost": quota_cost,
            "test_only": False,
            "capability_values": {},
        }

    def create_bundle(self, payload=None, *, key=None):
        self.client.force_login(self.admin)
        return self.post_json(
            reverse("catalog:api_catalog_collection"),
            payload or self.bundle_payload(),
            headers={"HTTP_IDEMPOTENCY_KEY": key or f"catalog-create-{payload or 'default'}"},
        )

    def test_catalog_collection_is_role_and_csrf_protected(self):
        anonymous = self.client.get(reverse("catalog:api_catalog_collection"))
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(anonymous.json()["error"]["code"], "UNAUTHORIZED")

        self.client.logout()
        downstream_login = self.post_json(
            reverse("accounts:api_login"),
            {
                "username": "api-downstream-a",
                "password": "Downstream-password-123",
                "entrypoint": "downstream",
            },
        )
        self.assertEqual(downstream_login.status_code, 200)
        wrong_role = self.client.get(reverse("catalog:api_catalog_collection"))
        self.assertEqual(wrong_role.status_code, 403)
        self.assertEqual(wrong_role.json()["error"]["code"], "FORBIDDEN")

        self.client.force_login(self.admin)
        missing_csrf = self.client.post(
            reverse("catalog:api_catalog_collection"),
            data=json.dumps(self.bundle_payload()),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY="catalog-csrf-missing",
        )
        self.assertEqual(missing_csrf.status_code, 403)
        self.assertEqual(missing_csrf.json()["error"]["code"], "CSRF_FAILED")

    def test_client_request_id_is_hashed_before_catalog_audit(self):
        supplied = "catalog-client-request-secret"
        self.client.force_login(self.admin)
        response = self.post_json(
            reverse("catalog:api_catalog_collection"),
            self.bundle_payload(software_id="audit-api-alpha"),
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-audit-key", "HTTP_X_REQUEST_ID": supplied},
        )
        self.assertEqual(response.status_code, 201)
        event = AuditEvent.objects.filter(action="software.create").latest("occurred_at")
        self.assertNotIn(supplied, event.request_id)
        self.assertTrue(event.request_id.startswith("client-"))

    def test_admin_can_create_catalog_bundle_and_get_same_source(self):
        response = self.create_bundle(key="catalog-create-success")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["software"]["software_id"], "api-alpha")
        self.assertEqual(response.json()["plan"]["latest_snapshot"]["quota_cost"], 15)
        self.assertEqual(response.json()["snapshot"]["duration_seconds"], 30 * 24 * 60 * 60)

        listing = self.client.get(reverse("catalog:api_catalog_collection"))
        self.assertEqual(listing.status_code, 200)
        self.assertEqual([item["software_id"] for item in listing.json()["items"]], ["api-alpha"])
        self.assertEqual(listing.json()["items"][0]["plans"][0]["name"], "月卡")

    def test_admin_catalog_collection_is_server_paginated(self):
        for index in range(25):
            create_software(actor=self.admin, software_id=f"api-page-{index:02d}", name=f"分页软件 {index:02d}", status=SoftwareStatus.ACTIVE)
        self.client.force_login(self.admin)
        listing = self.client.get(reverse("catalog:api_catalog_collection"), {"page": 2, "page_size": 10})
        self.assertEqual(listing.status_code, 200)
        payload = listing.json()
        self.assertEqual(payload["pagination"]["total"], 25)
        self.assertEqual(payload["pagination"]["total_pages"], 3)
        self.assertEqual(len(payload["items"]), 10)

    def test_bundle_failure_rolls_back_all_created_objects(self):
        payload = self.bundle_payload("api-rollback")
        payload["profile_status"] = "draft"
        response = self.create_bundle(payload, key="catalog-create-rollback")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "PROFILE_NOT_ACTIVE")
        self.assertFalse(Software.objects.filter(software_id="api-rollback").exists())
        self.assertFalse(SoftwareProfile.objects.filter(software__software_id="api-rollback").exists())
        self.assertFalse(PolicyVersion.objects.filter(profile__software__software_id="api-rollback").exists())
        self.assertFalse(PlanSnapshot.objects.filter(software__software_id="api-rollback").exists())

    def test_create_is_idempotent_and_conflicting_replay_is_rejected(self):
        payload = self.bundle_payload("api-idempotent")
        first = self.create_bundle(payload, key="catalog-create-replay")
        repeated = self.create_bundle(payload, key="catalog-create-replay")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json(), first.json())
        self.assertEqual(Software.objects.filter(software_id="api-idempotent").count(), 1)

        changed = dict(payload)
        changed["quota_cost"] = 99
        conflict = self.create_bundle(changed, key="catalog-create-replay")
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_invalid_types_and_unknown_plan_return_stable_json_errors(self):
        payload = self.bundle_payload("api-invalid")
        payload["max_devices"] = 1.5
        response = self.create_bundle(payload, key="catalog-invalid-float")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "INVALID_NUMBER")

        self.client.force_login(self.admin)
        unknown = self.post_json(
            reverse("catalog:api_catalog_plan_revise", kwargs={"plan_id": "999999"}),
            {
                "name": "不存在",
                "duration_value": 1,
                "duration_unit": "day",
                "quota_cost": 0,
                "test_only": False,
                "capability_values": {},
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-revise-unknown"},
        )
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.json()["error"]["code"], "PLAN_NOT_FOUND")

    def test_plan_revision_creates_new_snapshot_and_preserves_old_values(self):
        created = self.create_bundle(key="catalog-revise-create")
        plan_id = created.json()["plan"]["id"]
        first_snapshot_id = created.json()["snapshot"]["snapshot_id"]
        revised = self.post_json(
            reverse("catalog:api_catalog_plan_revise", kwargs={"plan_id": plan_id}),
            {
                "name": "月卡升级",
                "duration_value": 60,
                "duration_unit": "day",
                "quota_cost": 20,
                "test_only": False,
                "capability_values": {},
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-revise-success"},
        )
        self.assertEqual(revised.status_code, 200)
        self.assertEqual(revised.json()["snapshot"]["snapshot_version"], 2)
        self.assertEqual(revised.json()["snapshot"]["quota_cost"], 20)
        first = PlanSnapshot.objects.get(snapshot_id=first_snapshot_id)
        self.assertEqual(first.quota_cost, 15)
        self.assertEqual(first.snapshot_version, 1)
        self.assertEqual(PlanSnapshot.objects.filter(plan_id=plan_id).count(), 2)

    def test_plan_revision_idempotency_survives_cache_clear(self):
        created = self.create_bundle(key="catalog-revise-durable-base")
        plan_id = created.json()["plan"]["id"]
        payload = {
            "name": "月卡升级",
            "duration_value": 60,
            "duration_unit": "day",
            "quota_cost": 20,
            "test_only": False,
            "capability_values": {},
        }
        first = self.post_json(
            reverse("catalog:api_catalog_plan_revise", kwargs={"plan_id": plan_id}),
            payload,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-revise-durable"},
        )
        self.assertEqual(first.status_code, 200)
        cache.clear()
        repeated = self.post_json(
            reverse("catalog:api_catalog_plan_revise", kwargs={"plan_id": plan_id}),
            payload,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-revise-durable"},
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json(), first.json())
        self.assertEqual(PlanRevisionOperation.objects.count(), 1)
        self.assertEqual(PlanSnapshot.objects.filter(plan_id=plan_id).count(), 2)
        changed = dict(payload)
        changed["quota_cost"] = 99
        conflict = self.post_json(
            reverse("catalog:api_catalog_plan_revise", kwargs={"plan_id": plan_id}),
            changed,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-revise-durable"},
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_downstream_scope_idempotency_survives_cache_clear(self):
        created = self.create_bundle(key="catalog-access-durable-base")
        payload = {
            "software_id": "api-alpha",
            "enabled": True,
            "all_plans_allowed": False,
            "allowed_plan_ids": [created.json()["plan"]["id"]],
        }
        url = reverse("catalog:api_catalog_access", kwargs={"downstream_public_id": self.downstream_a.public_id})
        first = self.post_json(url, payload, headers={"HTTP_IDEMPOTENCY_KEY": "catalog-access-durable"})
        self.assertEqual(first.status_code, 200)
        cache.clear()
        repeated = self.post_json(url, payload, headers={"HTTP_IDEMPOTENCY_KEY": "catalog-access-durable"})
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json(), first.json())
        self.assertEqual(DownstreamSoftwareOperation.objects.count(), 1)
        changed = dict(payload)
        changed["enabled"] = False
        conflict = self.post_json(url, changed, headers={"HTTP_IDEMPOTENCY_KEY": "catalog-access-durable"})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_plan_status_archive_restore_is_durable_and_filters_downstream_catalog(self):
        created = self.create_bundle(key="catalog-status-base")
        plan_id = created.json()["plan"]["id"]
        plan_name = created.json()["plan"]["name"]
        access = self.post_json(
            reverse("catalog:api_catalog_access", kwargs={"downstream_public_id": self.downstream_a.public_id}),
            {"software_id": "api-alpha", "enabled": True, "all_plans_allowed": True, "allowed_plan_ids": []},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-status-access"},
        )
        self.assertEqual(access.status_code, 200)

        archived_payload = {"status": "archived", "reason": "下线旧销售套餐"}
        archived = self.post_json(
            reverse("catalog:api_catalog_plan_status", kwargs={"plan_id": plan_id}),
            archived_payload,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-status-archive"},
        )
        self.assertEqual(archived.status_code, 200)
        self.assertEqual(archived.json()["plan"]["status"], "archived")
        self.assertTrue(archived.json()["changed"])
        cache.clear()
        repeated = self.post_json(
            reverse("catalog:api_catalog_plan_status", kwargs={"plan_id": plan_id}),
            archived_payload,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-status-archive"},
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json(), archived.json())
        self.assertEqual(PlanLifecycleOperation.objects.count(), 1)
        self.assertEqual(PlanSnapshot.objects.filter(plan_id=plan_id).count(), 1)

        downstream_catalog = self.client.get(reverse("catalog:api_downstream_catalog"))
        self.assertEqual(downstream_catalog.status_code, 403)
        self.client.force_login(self.downstream_a.user)
        session = self.client.session
        session["downstream_session_version"] = self.downstream_a.session_version
        session.save()
        downstream_catalog = self.client.get(reverse("catalog:api_downstream_catalog"))

        self.assertEqual(downstream_catalog.status_code, 200)
        self.assertEqual(downstream_catalog.json()["items"][0]["plans"], [])

        self.client.force_login(self.admin)
        conflict = self.post_json(
            reverse("catalog:api_catalog_plan_status", kwargs={"plan_id": plan_id}),
            {"status": "archived", "reason": "换一个原因"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-status-archive"},
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

        restored = self.post_json(
            reverse("catalog:api_catalog_plan_status", kwargs={"plan_id": plan_id}),
            {"status": "active", "reason": "恢复销售套餐"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-status-restore"},
        )
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.json()["plan"]["name"], plan_name)
        self.assertEqual(restored.json()["plan"]["status"], "active")
        self.client.force_login(self.downstream_a.user)
        session = self.client.session
        session["downstream_session_version"] = self.downstream_a.session_version
        session.save()
        restored_catalog = self.client.get(reverse("catalog:api_downstream_catalog"))

        self.assertEqual(restored_catalog.status_code, 200)
        self.assertEqual(restored_catalog.json()["items"][0]["plans"][0]["name"], plan_name)

    def test_archived_plan_delete_is_durable_and_hides_from_catalog(self):
        created = self.create_bundle(key="catalog-delete-base")
        plan_id = created.json()["plan"]["id"]
        archived = self.post_json(
            reverse("catalog:api_catalog_plan_status", kwargs={"plan_id": plan_id}),
            {"status": "archived", "reason": "下线旧销售套餐"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-delete-archive"},
        )
        self.assertEqual(archived.status_code, 200)

        deleted = self.post_json(
            reverse("catalog:api_catalog_plan_delete", kwargs={"plan_id": plan_id}),
            {"reason": "清理测试套餐堆积"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-plan-delete"},
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json()["plan"]["status"], "deleted")
        self.assertTrue(deleted.json()["changed"])
        cache.clear()
        repeated = self.post_json(
            reverse("catalog:api_catalog_plan_delete", kwargs={"plan_id": plan_id}),
            {"reason": "清理测试套餐堆积"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-plan-delete"},
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json(), deleted.json())

        catalog = self.client.get(reverse("catalog:api_catalog_collection"))
        self.assertEqual(catalog.status_code, 200)
        plans = catalog.json()["items"][0]["plans"]
        self.assertFalse(any(item["id"] == plan_id for item in plans))

        conflict = self.post_json(
            reverse("catalog:api_catalog_plan_delete", kwargs={"plan_id": plan_id}),
            {"reason": "换一个删除原因"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-plan-delete"},
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

        restored = self.post_json(
            reverse("catalog:api_catalog_plan_status", kwargs={"plan_id": plan_id}),
            {"status": "active", "reason": "尝试恢复已删套餐"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-delete-restore"},
        )
        self.assertEqual(restored.status_code, 400)
        self.assertEqual(restored.json()["error"]["code"], "PLAN_DELETED")

    def test_active_plan_delete_api_is_rejected(self):
        created = self.create_bundle(key="catalog-delete-active")
        plan_id = created.json()["plan"]["id"]
        deleted = self.post_json(
            reverse("catalog:api_catalog_plan_delete", kwargs={"plan_id": plan_id}),
            {"reason": "直接删除在卖套餐"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-delete-active-key"},
        )
        self.assertEqual(deleted.status_code, 400)
        self.assertEqual(deleted.json()["error"]["code"], "PLAN_NOT_ARCHIVED")

    def test_official_plan_api_rejects_zero_quota_cost_while_test_plan_allows_zero(self):
        created = self.create_bundle(self.bundle_payload("api-zero-cost"), key="catalog-zero-cost-base")
        self.assertEqual(created.status_code, 201)
        profile_id = created.json()["profile"]["profile_id"]
        policy_version = created.json()["policy"]["version"]
        official = self.post_json(
            reverse("catalog:api_catalog_plan_create"),
            {
                "software_id": "api-zero-cost",
                "profile_id": profile_id,
                "policy_version": policy_version,
                "name": "零成本正式",
                "duration_value": 1,
                "duration_unit": "day",
                "quota_cost": 0,
                "test_only": False,
                "capability_values": {},
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-official-zero"},
        )
        self.assertEqual(official.status_code, 400)
        self.assertEqual(official.json()["error"]["code"], "INVALID_QUOTA_COST")
        test_plan = self.post_json(
            reverse("catalog:api_catalog_plan_create"),
            {
                "software_id": "api-zero-cost",
                "profile_id": profile_id,
                "policy_version": policy_version,
                "name": "零成本测试",
                "duration_value": 1,
                "duration_unit": "minute",
                "quota_cost": 0,
                "test_only": True,
                "capability_values": {},
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-test-zero"},
        )
        self.assertEqual(test_plan.status_code, 201)
        self.assertEqual(test_plan.json()["plan"]["quota_cost"], 0)
        self.assertTrue(test_plan.json()["plan"]["test_only"])
        official_plan_id = created.json()["plan"]["id"]
        revised = self.post_json(
            reverse("catalog:api_catalog_plan_revise", kwargs={"plan_id": official_plan_id}),
            {
                "name": "月卡改零",
                "duration_value": 30,
                "duration_unit": "day",
                "quota_cost": 0,
                "test_only": False,
                "capability_values": {},
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-revise-official-zero"},
        )
        self.assertEqual(revised.status_code, 400)
        self.assertEqual(revised.json()["error"]["code"], "INVALID_QUOTA_COST")

    def test_software_status_archive_json_and_legacy_html_stays_gone(self):
        created = self.create_bundle(self.bundle_payload("api-unlist"), key="catalog-unlist-base")
        self.assertEqual(created.status_code, 201)
        archived = self.post_json(
            reverse("catalog:api_catalog_software_status", kwargs={"software_id": "api-unlist"}),
            {"status": "archived", "reason": "停止新发"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-unlist"},
        )
        self.assertEqual(archived.status_code, 200)
        self.assertEqual(archived.json()["software"]["status"], "archived")
        repeated = self.post_json(
            reverse("catalog:api_catalog_software_status", kwargs={"software_id": "api-unlist"}),
            {"status": "archived", "reason": "停止新发"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-unlist"},
        )
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json(), archived.json())
        cache.clear()
        after_clear = self.post_json(
            reverse("catalog:api_catalog_software_status", kwargs={"software_id": "api-unlist"}),
            {"status": "archived", "reason": "停止新发"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-unlist"},
        )
        self.assertEqual(after_clear.status_code, 200)
        self.assertEqual(after_clear.json()["software"]["status"], "archived")
        draft = self.post_json(
            reverse("catalog:api_catalog_software_status", kwargs={"software_id": "api-unlist"}),
            {"status": "draft", "reason": "改成草稿"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-unlist-draft"},
        )
        self.assertEqual(draft.status_code, 400)
        unknown = self.post_json(
            reverse("catalog:api_catalog_software_status", kwargs={"software_id": "missing-tool"}),
            {"status": "archived", "reason": "停止新发"},
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-unlist-missing"},
        )
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(unknown.json()["error"]["code"], "SOFTWARE_NOT_FOUND")
        html_client = Client()
        html_client.force_login(self.admin)
        html = html_client.post(
            reverse("catalog:software_status_update", kwargs={"software_id": "api-unlist"}),
            {"status": "archived"},
        )
        self.assertContains(html, CONTROL_ROOM_COPY, status_code=410)

    def test_admin_can_add_multiple_plans_to_existing_software_and_downstream_reads_them(self):
        created = self.create_bundle(key="catalog-multi-plan-base")
        base = created.json()
        profile_id = base["profile"]["profile_id"]
        policy_version = base["policy"]["version"]
        payload = {
            "software_id": "api-alpha",
            "profile_id": profile_id,
            "policy_version": policy_version,
            "name": "小时卡",
            "duration_value": 1,
            "duration_unit": "hour",
            "quota_cost": 4,
            "test_only": False,
            "status": "active",
            "capability_values": {},
        }
        created_plan = self.post_json(
            reverse("catalog:api_catalog_plan_create"),
            payload,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-add-hour-plan"},
        )
        self.assertEqual(created_plan.status_code, 201)
        self.assertEqual(created_plan.json()["plan"]["name"], "小时卡")
        self.assertEqual(created_plan.json()["snapshot"]["duration_seconds"], 3600)
        self.assertEqual(Plan.objects.filter(software_id="api-alpha").count(), 2)
        self.assertEqual(PlanSnapshot.objects.filter(software_id="api-alpha").count(), 2)
        self.assertEqual(
            PlanCreateOperation.objects.filter(
                actor=self.admin,
                namespace="plan-create",
                idempotency_key="catalog-add-hour-plan",
            ).count(),
            1,
        )

        cache.clear()
        repeated = self.post_json(
            reverse("catalog:api_catalog_plan_create"),
            payload,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-add-hour-plan"},
        )
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json(), created_plan.json())
        self.assertEqual(Plan.objects.filter(software_id="api-alpha").count(), 2)
        self.assertEqual(
            PlanCreateOperation.objects.filter(
                actor=self.admin,
                namespace="plan-create",
                idempotency_key="catalog-add-hour-plan",
            ).count(),
            1,
        )

        changed = dict(payload)
        changed["quota_cost"] = 9
        conflict = self.post_json(
            reverse("catalog:api_catalog_plan_create"),
            changed,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-add-hour-plan"},
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "IDEMPOTENCY_CONFLICT")

        wrong_profile = dict(payload)
        wrong_profile["profile_id"] = "missing-profile"
        invalid = self.post_json(
            reverse("catalog:api_catalog_plan_create"),
            wrong_profile,
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-add-invalid-profile"},
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["error"]["code"], "PROFILE_NOT_FOUND")
        self.assertEqual(Plan.objects.filter(software_id="api-alpha").count(), 2)

        access = self.post_json(
            reverse("catalog:api_catalog_access", kwargs={"downstream_public_id": self.downstream_a.public_id}),
            {
                "software_id": "api-alpha",
                "enabled": True,
                "all_plans_allowed": True,
                "allowed_plan_ids": [],
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-multi-plan-access"},
        )
        self.assertEqual(access.status_code, 200)
        self.client.logout()
        downstream_login = self.post_json(
            reverse("accounts:api_login"),
            {
                "username": "api-downstream-a",
                "password": "Downstream-password-123",
                "entrypoint": "downstream",
            },
        )
        self.assertEqual(downstream_login.status_code, 200)
        visible = self.client.get(reverse("catalog:api_downstream_catalog"))
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(
            {item["name"] for item in visible.json()["items"][0]["plans"]},
            {"月卡", "小时卡"},
        )

    def test_same_plan_name_is_isolated_between_software_records(self):
        first = self.create_bundle(self.bundle_payload("api-alpha-name", quota_cost=11), key="catalog-name-alpha")
        second = self.create_bundle(self.bundle_payload("api-beta-name", name="Beta Studio", quota_cost=22), key="catalog-name-beta")
        self.assertEqual(first.json()["plan"]["name"], second.json()["plan"]["name"])
        self.assertNotEqual(first.json()["software"]["software_id"], second.json()["software"]["software_id"])
        self.assertNotEqual(first.json()["plan"]["quota_cost"], second.json()["plan"]["quota_cost"])

    def test_scope_api_and_downstream_catalog_are_server_filtered(self):
        created = self.create_bundle(key="catalog-scope-create")
        software_id = created.json()["software"]["software_id"]
        plan_id = created.json()["plan"]["id"]
        access = self.post_json(
            reverse("catalog:api_catalog_access", kwargs={"downstream_public_id": self.downstream_a.public_id}),
            {
                "software_id": software_id,
                "enabled": True,
                "all_plans_allowed": False,
                "allowed_plan_ids": [plan_id],
            },
            headers={"HTTP_IDEMPOTENCY_KEY": "catalog-scope-a"},
        )
        self.assertEqual(access.status_code, 200)
        self.assertEqual(access.json()["access"]["allowed_plan_ids"], [plan_id])

        self.client.logout()
        downstream_login = self.post_json(
            reverse("accounts:api_login"),
            {
                "username": "api-downstream-a",
                "password": "Downstream-password-123",
                "entrypoint": "downstream",
            },
        )
        self.assertEqual(downstream_login.status_code, 200)
        visible = self.client.get(reverse("catalog:api_downstream_catalog"))
        self.assertEqual(visible.status_code, 200)
        self.assertEqual([item["software_id"] for item in visible.json()["items"]], [software_id])
        self.assertEqual([item["id"] for item in visible.json()["items"][0]["plans"]], [plan_id])

        self.client.logout()
        downstream_login = self.post_json(
            reverse("accounts:api_login"),
            {
                "username": "api-downstream-b",
                "password": "Downstream-password-123",
                "entrypoint": "downstream",
            },
        )
        self.assertEqual(downstream_login.status_code, 200)
        hidden = self.client.get(reverse("catalog:api_downstream_catalog"))
        self.assertEqual(hidden.status_code, 200)
        self.assertEqual(hidden.json(), {"items": []})

    def test_legacy_downstream_configuration_route_no_longer_raises_name_error(self):
        software = create_software(actor=self.admin, software_id="api-config", name="配置软件", status=SoftwareStatus.ACTIVE)
        create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="api-config-client",
            status=ProfileStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=software.software_id,
            enabled=True,
        )
        legacy_client = Client()
        legacy_client.post(
            reverse("accounts:downstream_login"),
            {"username": "api-downstream-a", "password": "Downstream-password-123"},
        )
        response = legacy_client.get(
            reverse("catalog:downstream_configuration", kwargs={"software_id": software.software_id})
        )
        self.assertContains(response, CONTROL_ROOM_COPY, status_code=410)
        self.assertNotContains(response, "客户支持信息", status_code=410)
        self.assertNotContains(response, FORBIDDEN_API_COPY, status_code=410)

    def test_policy_revision_api_is_versioned_and_idempotent(self):
        payload = self.bundle_payload("api-policy")
        created = self.create_bundle(payload, key="api-policy-bundle")
        self.assertEqual(created.status_code, 201)
        url = reverse(
            "catalog:api_catalog_policy_revise",
            kwargs={"software_id": "api-policy", "profile_id": "api-policy-profile"},
        )
        body = {
            "max_devices": 3,
            "allow_device_switch": True,
            "device_switch_limit": 2,
            "device_proof_required": True,
            "verify_interval_seconds": 1800,
            "offline_grace_seconds": 7200,
        }
        first = self.post_json(url, body, headers={"HTTP_IDEMPOTENCY_KEY": "api-policy-revise-1"})
        replay = self.post_json(url, body, headers={"HTTP_IDEMPOTENCY_KEY": "api-policy-revise-1"})
        conflict = self.post_json(
            url,
            {**body, "max_devices": 4},
            headers={"HTTP_IDEMPOTENCY_KEY": "api-policy-revise-1"},
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(first.json(), replay.json())
        self.assertEqual(first.json()["policy"]["max_devices"], 3)
        self.assertEqual(first.json()["policy"]["verify_interval_seconds"], 1800)
        profile = SoftwareProfile.objects.get(software_id="api-policy", profile_id="api-policy-profile")
        self.assertEqual(profile.policy_versions.filter(status=PolicyStatus.ACTIVE).count(), 1)
        self.assertEqual(profile.policy_versions.count(), 2)
        self.assertEqual(PolicyRevisionOperation.objects.filter(actor=self.admin, profile=profile).count(), 1)
        active_policy = profile.policy_versions.get(status=PolicyStatus.ACTIVE)
        active_policy.status = PolicyStatus.ARCHIVED
        active_policy.save(update_fields=("status",), _allow_mutation=True)
        replay_after_archive = self.post_json(url, body, headers={"HTTP_IDEMPOTENCY_KEY": "api-policy-revise-1"})
        self.assertEqual(replay_after_archive.status_code, 200)
        self.assertEqual(replay_after_archive.json(), first.json())
        with self.assertRaises(ValueError):
            PolicyVersion.objects.filter(pk=active_policy.pk).update(status=PolicyStatus.ACTIVE)
        with self.assertRaises(ValueError):
            PolicyVersion.objects.filter(pk=active_policy.pk).delete()

    def test_catalog_create_omits_switch_fields_default_to_daily_five(self):
        payload = self.bundle_payload("api-switch-default")
        payload.pop("allow_device_switch")
        payload.pop("device_switch_limit")
        created = self.create_bundle(payload, key="api-switch-default")
        self.assertEqual(created.status_code, 201)
        policy = PolicyVersion.objects.get(profile__software_id="api-switch-default", status=PolicyStatus.ACTIVE)
        self.assertTrue(policy.allow_device_switch)
        self.assertEqual(policy.device_switch_limit, 5)

    def test_catalog_create_omits_verify_interval_defaults_to_sixty(self):
        payload = self.bundle_payload("api-interval-default")
        payload.pop("verify_interval_minutes")
        created = self.create_bundle(payload, key="api-interval-default")
        self.assertEqual(created.status_code, 201)
        policy = PolicyVersion.objects.get(profile__software_id="api-interval-default", status=PolicyStatus.ACTIVE)
        self.assertEqual(policy.verify_interval_seconds, 60)
