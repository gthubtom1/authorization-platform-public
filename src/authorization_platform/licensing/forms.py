from __future__ import annotations

from django import forms
from django.conf import settings

from authorization_platform.catalog.forms import PublicConfigurationForm
from authorization_platform.catalog.models import Plan, ProfileStatus, Software
from authorization_platform.catalog.services import accessible_plans_for, list_accessible_software


class LicenseBatchPreviewForm(forms.Form):
    software = forms.ModelChoiceField(label="软件", queryset=Software.objects.none(), empty_label="请选择已开放的软件")
    plan = forms.ModelChoiceField(label="套餐", queryset=Plan.objects.none(), empty_label="请选择套餐")
    quantity = forms.IntegerField(label="生成数量", min_value=1, max_value=settings.LICENSE_CARD_MAX_BATCH_SIZE, initial=1)

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields["software"].queryset = list_accessible_software(user)
        plan_ids: list[int] = []
        for software in self.fields["software"].queryset:
            plan_ids.extend(accessible_plans_for(user, software.software_id).values_list("pk", flat=True))
        self.fields["plan"].queryset = (
            Plan.objects.filter(pk__in=plan_ids, profile__status__in=(ProfileStatus.TESTING, ProfileStatus.ACTIVE))
            .select_related("software", "profile")
            .order_by("software__name", "name", "pk")
        )

    def clean(self):
        cleaned = super().clean()
        software = cleaned.get("software")
        plan = cleaned.get("plan")
        if software and plan and plan.software_id != software.software_id:
            self.add_error("plan", "所选套餐不属于当前软件，请重新选择。")
        return cleaned


class LicenseBatchConfirmForm(forms.Form):
    software_id = forms.CharField(widget=forms.HiddenInput)
    plan_snapshot_id = forms.UUIDField(widget=forms.HiddenInput)
    quantity = forms.IntegerField(min_value=1, max_value=settings.LICENSE_CARD_MAX_BATCH_SIZE, widget=forms.HiddenInput)
    idempotency_key = forms.CharField(min_length=1, max_length=128, widget=forms.HiddenInput)
    preview_token = forms.CharField(min_length=1, widget=forms.HiddenInput)


class AuthorizationAdminActionForm(forms.Form):
    reason = forms.CharField(
        label="操作原因",
        min_length=2,
        max_length=255,
        strip=True,
        help_text="原因会写入审计记录；解除设备阻断不会自动恢复历史绑定。",
    )


class AuthorizationConfigurationOverrideForm(PublicConfigurationForm):
    clear_override = forms.BooleanField(label="清除客户覆盖并使用下游/Profile默认", required=False)
