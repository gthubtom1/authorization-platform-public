from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from authorization_platform.accounts.services import create_downstream_direct
from authorization_platform.audit.models import AuditEvent, AuditOutcome
from authorization_platform.audit.queries import present_event
from authorization_platform.audit.services import record_event
from authorization_platform.catalog.models import PlanStatus, PolicyStatus, ProfileStatus, SoftwareStatus
from authorization_platform.catalog.services import create_plan, create_policy_version, create_profile, create_software, set_downstream_software_access
from authorization_platform.credits.services import credit_quota
from authorization_platform.licensing.services import generate_license_batch


User = get_user_model()


class AuditQueryTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="audit-admin", password="Admin-password-123")
        self.downstream_a = create_downstream_direct(
            actor=self.admin,
            username="audit-downstream-a",
            password="Downstream-password-123",
        )
        self.downstream_b = create_downstream_direct(
            actor=self.admin,
            username="audit-downstream-b",
            password="Downstream-password-123",
        )
        self.admin_client = Client()
        self.admin_client.force_login(self.admin)

        record_event(
            actor=self.admin,
            action="audit.scope",
            outcome=AuditOutcome.SUCCESS,
            object_type="DownstreamProfile",
            object_public_id=self.downstream_a.public_id,
            metadata={"amount": 8, "secret": "password-value"},
        )
        record_event(
            actor=self.admin,
            action="audit.scope",
            outcome=AuditOutcome.FAILURE,
            object_type="DownstreamProfile",
            object_public_id=self.downstream_b.public_id,
            reason_code="FORBIDDEN",
        )
        record_event(
            actor=self.downstream_a.user,
            action="audit.self",
            outcome=AuditOutcome.SUCCESS,
            object_type="DownstreamProfile",
            object_public_id=self.downstream_a.public_id,
        )
        record_event(
            actor=self.downstream_b.user,
            action="audit.self",
            outcome=AuditOutcome.SUCCESS,
            object_type="DownstreamProfile",
            object_public_id=self.downstream_b.public_id,
        )
        record_event(
            actor=self.admin,
            action="audit.global",
            outcome=AuditOutcome.SUCCESS,
            object_type="Software",
            object_public_id="generic-software",
        )

    @staticmethod
    def _login_downstream(client: Client, profile) -> None:
        client.force_login(profile.user)
        session = client.session
        session["downstream_session_version"] = profile.session_version
        session.save()

    def test_admin_can_filter_all_events_and_view_only_safe_metadata(self):
        response = self.admin_client.get(reverse("audit:admin_log"), {"action": "audit.scope"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, str(self.downstream_a.public_id))
        self.assertContains(response, str(self.downstream_b.public_id))
        self.assertContains(response, "失败")
        self.assertContains(response, "额度=8")
        self.assertNotContains(response, "password-value")

    def test_client_authorization_audit_shows_device_source_and_downstream_object(self):
        device_code = "GS-65FB-F502-B439-270C"
        event = record_event(
            actor=None,
            action="authorization.activate",
            outcome=AuditOutcome.FAILURE,
            object_type="",
            metadata={
                "installation_id": device_code,
                "downstream_public_id": str(self.downstream_a.public_id),
                "device_id": "device-audit-uuid",
                "secret": "must-not-display",
            },
            reason_code="DEVICE_KEY_MISMATCH",
        )

        row = present_event(event)
        self.assertEqual(row.actor_label, device_code)
        self.assertEqual(row.actor_role_label, "客户端设备")
        self.assertEqual(row.object_label, self.downstream_a.user.username)
        self.assertEqual(row.object_summary, "客户端授权请求")
        self.assertEqual(row.reason_code, "DEVICE_KEY_MISMATCH")
        self.assertNotIn("must-not-display", " ".join(item.value for item in row.metadata_items))

        response = self.admin_client.get(reverse("audit:api_manage_audit"), {"q": device_code})
        self.assertEqual(response.status_code, 200)
        item = response.json()["items"][0]
        self.assertEqual(item["actor_label"], device_code)
        self.assertEqual(item["actor_role"], "客户端设备")
        self.assertEqual(item["object_label"], self.downstream_a.user.username)

        downstream_client = Client()
        self._login_downstream(downstream_client, self.downstream_a)
        visible = downstream_client.get(reverse("audit:api_downstream_audit"), {"q": device_code})
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.json()["items"][0]["object_label"], self.downstream_a.user.username)

        hidden_client = Client()
        self._login_downstream(hidden_client, self.downstream_b)
        hidden = hidden_client.get(reverse("audit:api_downstream_audit"), {"q": device_code})
        self.assertEqual(hidden.status_code, 200)
        self.assertEqual(hidden.json()["count"], 0)

    def test_downstream_scope_comes_from_session_and_server_relations(self):
        client = Client()
        self._login_downstream(client, self.downstream_a)

        response = client.get(reverse("audit:downstream_log"), {"action": "audit.scope"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, str(self.downstream_a.public_id))
        self.assertNotContains(response, str(self.downstream_b.public_id))
        self.assertNotContains(response, "password-value")

        forged = client.get(
            reverse("audit:downstream_log"),
            {"action": "audit.scope", "object_public_id": str(self.downstream_b.public_id)},
        )
        self.assertEqual(forged.status_code, 200)
        self.assertContains(forged, "当前范围没有符合条件的审计记录。")
        self.assertNotContains(forged, "audit-downstream-b")
        self.assertNotContains(forged, "FORBIDDEN")

    def test_downstream_scope_resolves_license_batch_primary_key(self):
        software = create_software(
            actor=self.admin,
            software_id="audit-license-tool",
            name="Audit License Tool",
            status=SoftwareStatus.ACTIVE,
        )
        create_profile(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            client_id="audit-license-tool-client",
            status=ProfileStatus.ACTIVE,
        )
        policy = create_policy_version(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            version="policy-1",
            status=PolicyStatus.ACTIVE,
        )
        _, snapshot = create_plan(
            actor=self.admin,
            software_id=software.software_id,
            profile_id="stable",
            policy_version=policy.version,
            name="审计授权套餐",
            duration_seconds=3600,
            quota_cost=1,
            status=PlanStatus.ACTIVE,
        )
        set_downstream_software_access(
            actor=self.admin,
            downstream_public_id=self.downstream_a.public_id,
            software_id=software.software_id,
            enabled=True,
            all_plans_allowed=True,
        )
        credit_quota(
            actor=self.admin,
            downstream=self.downstream_a,
            amount=1,
            reason="审计批次范围测试",
            idempotency_key="audit-batch-credit",
        )
        result = generate_license_batch(
            actor=self.downstream_a.user,
            software_id=software.software_id,
            plan_snapshot_id=snapshot.snapshot_id,
            quantity=1,
            idempotency_key="audit-batch-scope",
        )
        record_event(
            actor=self.admin,
            action="audit.batch-scope",
            outcome=AuditOutcome.SUCCESS,
            object_type="LicenseCardBatch",
            object_public_id=result.batch.batch_id,
        )

        downstream_a_client = Client()
        self._login_downstream(downstream_a_client, self.downstream_a)
        visible = downstream_a_client.get(reverse("audit:downstream_log"), {"action": "audit.batch-scope"})
        self.assertEqual(visible.status_code, 200)
        self.assertContains(visible, str(result.batch.batch_id))

        downstream_b_client = Client()
        self._login_downstream(downstream_b_client, self.downstream_b)
        hidden = downstream_b_client.get(reverse("audit:downstream_log"), {"action": "audit.batch-scope"})
        self.assertEqual(hidden.status_code, 200)
        self.assertContains(hidden, "当前范围没有符合条件的审计记录。")
        self.assertNotContains(hidden, str(result.batch.batch_id))

        from django.db.models import QuerySet

        from authorization_platform.audit.queries import audit_events_for_user

        scoped = audit_events_for_user(user=self.downstream_a.user, filters={"action": "audit.batch-scope"})
        self.assertIsInstance(scoped, QuerySet)
        self.assertEqual(list(scoped.values_list("object_public_id", flat=True)), [str(result.batch.batch_id)])

    def test_roles_are_separated(self):
        downstream_client = Client()
        self._login_downstream(downstream_client, self.downstream_a)
        self.assertEqual(downstream_client.get(reverse("audit:admin_log")).status_code, 403)

        staff = User.objects.create_user(username="plain-staff", password="Staff-password-123", is_staff=True)
        staff_client = Client()
        staff_client.force_login(staff)
        self.assertEqual(staff_client.get(reverse("audit:admin_log")).status_code, 403)

    def test_time_and_result_filters_use_local_date_boundary(self):
        old_event = AuditEvent.objects.create(
            actor=self.admin,
            actor_role="platform_admin",
            action="audit.old",
            outcome=AuditOutcome.SUCCESS,
            object_type="Software",
            object_public_id="old-software",
            request_id="old-request",
            occurred_at=timezone.now() - timedelta(days=3),
        )
        today = timezone.localdate().isoformat()
        response = self.admin_client.get(
            reverse("audit:admin_log"),
            {"from_date": today, "to_date": today, "outcome": AuditOutcome.SUCCESS},
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, str(old_event.public_id))
        self.assertNotContains(response, "audit.old")
        self.assertContains(response, "audit.global")

    def test_invalid_date_range_is_reported_without_querying(self):
        response = self.admin_client.get(
            reverse("audit:admin_log"),
            {"from_date": "2026-08-20", "to_date": "2026-08-19"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "起始日期不能晚于结束日期。")
        self.assertContains(response, "当前范围没有符合条件的审计记录。")

    def test_export_is_redacted_no_store_and_audited(self):
        record_event(
            actor=self.admin,
            action="audit.csv-safety",
            outcome=AuditOutcome.SUCCESS,
            object_type="Custom",
            object_public_id="=formula",
            metadata={"secret": "token-value"},
        )

        response = self.admin_client.get(reverse("audit:admin_export"), {"action": "audit.csv-safety"})
        body = response.content.decode("utf-8-sig")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("'=formula", body)
        self.assertNotIn("token-value", body)
        self.assertTrue(AuditEvent.objects.filter(action="audit.export", outcome=AuditOutcome.SUCCESS).exists())

    def test_export_is_capped_at_one_thousand_rows(self):
        AuditEvent.objects.bulk_create(
            [
                AuditEvent(
                    actor=self.admin,
                    actor_role="platform_admin",
                    action="audit.limit",
                    outcome=AuditOutcome.SUCCESS,
                    request_id=f"audit-limit-{index}",
                )
                for index in range(1001)
            ],
            batch_size=250,
        )

        response = self.admin_client.get(reverse("audit:admin_export"), {"action": "audit.limit"})
        body = response.content.decode("utf-8-sig")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(body.splitlines()), 1001)  # header + 1000 rows
        self.assertEqual(body.count("audit.limit"), 1000)
        export_event = AuditEvent.objects.filter(action="audit.export").order_by("-occurred_at").first()
        self.assertIsNotNone(export_event)
        self.assertEqual(export_event.metadata["row_count"], 1000)
        self.assertTrue(export_event.metadata["limited"])

    def test_audit_pagination_keeps_fifty_rows_per_page(self):
        for index in range(51):
            record_event(
                actor=self.admin,
                action="audit.page",
                outcome=AuditOutcome.SUCCESS,
                request_id=f"audit-page-{index}",
            )

        response = self.admin_client.get(reverse("audit:admin_log"), {"action": "audit.page", "page": 2})
        page_obj = response.context["page_obj"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(page_obj.paginator.per_page, 50)
        self.assertEqual(page_obj.paginator.count, 51)
        self.assertEqual(page_obj.number, 2)
        self.assertEqual(len(page_obj.object_list), 1)
        self.assertContains(response, "第 2 / 2 页")

    def test_audit_events_are_immutable_through_all_orm_write_paths(self):
        event = AuditEvent.objects.get(action="audit.global")
        event.action = "audit.changed"

        with self.assertRaises(ValueError):
            event.save(update_fields=["action"])
        with self.assertRaises(ValueError):
            AuditEvent.objects.filter(public_id=event.public_id).update(action="audit.changed")
        with self.assertRaises(ValueError):
            AuditEvent.objects.bulk_update([event], ["action"])
        with self.assertRaises(ValueError):
            AuditEvent.objects.filter(public_id=event.public_id).delete()

        self.assertTrue(AuditEvent.objects.filter(action="audit.global").exists())
        self.assertFalse(AuditEvent.objects.filter(action="audit.changed").exists())

    def test_audit_routes_are_read_only(self):
        before = AuditEvent.objects.count()
        self.assertEqual(self.admin_client.post(reverse("audit:admin_log")).status_code, 405)
        self.assertEqual(AuditEvent.objects.count(), before)
        with self.assertRaises(ValueError):
            AuditEvent.objects.first().delete()

    def test_object_summary_uses_event_metadata_not_current_state(self):
        event = record_event(
            actor=self.admin,
            action="authorization.activate",
            outcome=AuditOutcome.SUCCESS,
            object_type="LicenseInstance",
            object_public_id="hist-auth-keep-past",
            metadata={
                "software_id": "audit-license-tool",
                "state": "active",
                "downstream_public_id": "ds-public-keep-past",
            },
        )
        row = present_event(event)
        self.assertIn("LicenseInstance", row.object_summary)
        self.assertIn("audit-license-tool", row.object_summary)
        self.assertIn("active", row.object_summary)
        self.assertNotIn("已过期", row.object_summary)
        self.assertNotIn("hist-auth-keep-past", row.object_summary)
        labels = {item.label for item in row.metadata_items}
        self.assertIn("下游公开 ID", labels)
        self.assertIn("软件 ID", labels)
