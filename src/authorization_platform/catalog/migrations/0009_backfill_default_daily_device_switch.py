import uuid

from django.conf import settings
from django.db import migrations
from django.utils import timezone


def forwards(apps, schema_editor):
    # Never import runtime services/models: this runs against the 0008 schema.
    alias = schema_editor.connection.alias
    PolicyVersion = apps.get_model("catalog", "PolicyVersion")
    Profile = apps.get_model("catalog", "SoftwareProfile")
    Plan = apps.get_model("catalog", "Plan")
    Snapshot = apps.get_model("catalog", "PlanSnapshot")
    AuditEvent = apps.get_model("audit", "AuditEvent")
    User = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    actor = User.objects.using(alias).filter(is_superuser=True).order_by("pk").first()
    if actor is None:
        return
    profile_ids = PolicyVersion.objects.using(alias).filter(
        status="active", allow_device_switch=False, device_switch_limit=0,
    ).values_list("profile_id", flat=True).distinct()
    for profile in Profile.objects.using(alias).select_related("software").filter(pk__in=profile_ids).order_by("pk"):
        if profile.status == "archived" or profile.software.status == "archived":
            continue
        active = list(PolicyVersion.objects.using(alias).filter(profile=profile, status="active").order_by("-effective_at", "-created_at"))
        if not active or active[0].allow_device_switch or active[0].device_switch_limit != 0:
            continue
        current = active[0]
        number = 1
        while PolicyVersion.objects.using(alias).filter(profile=profile, version=f"policy-{number}").exists():
            number += 1
        PolicyVersion.objects.using(alias).filter(pk__in=[row.pk for row in active]).update(status="archived")
        policy = PolicyVersion.objects.using(alias).create(
            profile=profile, version=f"policy-{number}", status="active",
            max_devices=current.max_devices, allow_device_switch=True, device_switch_limit=5,
            device_proof_required=current.device_proof_required,
            verify_interval_seconds=current.verify_interval_seconds,
            offline_grace_seconds=current.offline_grace_seconds,
            effective_at=timezone.now(), created_by=actor,
        )
        archived_ids = {row.pk for row in active}
        for plan in Plan.objects.using(alias).filter(profile=profile).order_by("pk"):
            latest = Snapshot.objects.using(alias).filter(plan=plan).order_by("-snapshot_version").first()
            if latest is None or latest.policy_version_id not in archived_ids:
                continue
            Snapshot.objects.using(alias).create(
                plan=plan, software_id=plan.software_id, profile=profile, policy_version=policy,
                snapshot_version=latest.snapshot_version + 1, name=plan.name,
                duration_seconds=plan.duration_seconds, quota_cost=plan.quota_cost,
                test_only=plan.test_only, capability_values=plan.capability_values, created_by=actor,
            )
        AuditEvent.objects.using(alias).create(
            actor_id=actor.pk, actor_role="platform_admin", action="policy_version.revise", outcome="success",
            request_id=f"local-{uuid.uuid4().hex}", object_type="PolicyVersion",
            object_public_id=f"{profile.software_id}/{profile.profile_id}/{policy.version}",
            metadata={
                "previous_versions": [row.version for row in active], "version": policy.version,
                "max_devices": policy.max_devices, "allow_device_switch": True, "device_switch_limit": 5,
                "device_proof_required": policy.device_proof_required,
                "verify_interval_seconds": policy.verify_interval_seconds,
                "offline_grace_seconds": policy.offline_grace_seconds,
            },
        )


def backwards(apps, schema_editor):
    return


class Migration(migrations.Migration):

    dependencies = [
        ("catalog", "0008_policy_revision_operation"),
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
