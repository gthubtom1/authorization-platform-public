from __future__ import annotations

import json

from django import forms

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus

from .models import (
    CapabilityStatus,
    CapabilityValueType,
    DEFAULT_VERIFY_INTERVAL_SECONDS,
    Plan,
    PlanStatus,
    PolicyStatus,
    PolicyVersion,
    ProfileStatus,
    Software,
    SoftwareProfile,
    SoftwareStatus,
)


class PublicConfigurationForm(forms.Form):
    purchase_url = forms.CharField(label="购买链接", max_length=2048, required=False, help_text="只接受 HTTP 或 HTTPS 地址，不保存账号密码。")
    qq = forms.CharField(label="QQ", max_length=64, required=False)
    wechat = forms.CharField(label="微信", max_length=64, required=False)
    announcement_enabled = forms.BooleanField(label="显示公告", required=False)
    announcement_title = forms.CharField(label="公告标题", max_length=120, required=False)
    announcement_body = forms.CharField(label="公告内容", max_length=2000, required=False, widget=forms.Textarea(attrs={"rows": 5}))

    def clean(self):
        cleaned = super().clean()
        if not cleaned:
            return cleaned
        from .configuration import CONFIGURATION_KEYS, ConfigurationOperationError, normalize_configuration

        try:
            configuration_values = {key: value for key, value in cleaned.items() if key in CONFIGURATION_KEYS}
            self.cleaned_configuration = normalize_configuration(configuration_values)
        except ConfigurationOperationError as exc:
            self.add_error(None, exc.message)
        return cleaned


class ProfileConfigurationForm(PublicConfigurationForm):
    pass


class DownstreamConfigurationForm(PublicConfigurationForm):
    clear_configuration = forms.BooleanField(label="清除下游覆盖并回退到 Profile 默认", required=False)


class SoftwareForm(forms.Form):
    software_id = forms.SlugField(label="软件 ID", max_length=64, help_text="稳定标识，只用小写字母、数字、点、下划线或短横线。")
    name = forms.CharField(label="软件名称", max_length=120)
    description = forms.CharField(label="说明", required=False, widget=forms.Textarea(attrs={"rows": 3}))
    status = forms.ChoiceField(label="初始状态", choices=SoftwareStatus.choices, initial=SoftwareStatus.DRAFT)


class SoftwareStatusForm(forms.Form):
    status = forms.ChoiceField(label="软件状态", choices=SoftwareStatus.choices)


class ProfileForm(forms.Form):
    profile_id = forms.SlugField(label="Profile ID", max_length=64, initial="stable")
    client_id = forms.CharField(label="客户端 ID", max_length=128)
    contract_version = forms.CharField(label="公共合同版本", max_length=64, initial="authorization.v1")
    target = forms.CharField(label="目标平台", max_length=32, initial="windows")
    arch = forms.CharField(label="架构", max_length=32, initial="x64")
    channel = forms.CharField(label="发布通道", max_length=32, initial="stable")
    adapter_key = forms.CharField(label="平台适配器", max_length=64, initial="generic-online-v1")
    adapter_version = forms.CharField(label="适配器版本", max_length=32, initial="1")
    minimum_client_version = forms.CharField(label="最低客户端版本", max_length=64, required=False)
    status = forms.ChoiceField(label="状态", choices=ProfileStatus.choices, initial=ProfileStatus.DRAFT)


class PolicyVersionForm(forms.Form):
    version = forms.SlugField(label="策略版本", max_length=64, initial="policy-1")
    max_devices = forms.IntegerField(label="最大设备数", min_value=1, initial=1)
    allow_device_switch = forms.BooleanField(label="允许换机", required=False)
    device_switch_limit = forms.IntegerField(label="换机次数", min_value=0, initial=0)
    device_proof_required = forms.BooleanField(label="要求设备证明", required=False, initial=True)
    verify_interval_seconds = forms.IntegerField(label="验证间隔（秒）", min_value=0, initial=DEFAULT_VERIFY_INTERVAL_SECONDS)
    offline_grace_seconds = forms.IntegerField(label="断网宽限（秒）", min_value=0, initial=0)
    status = forms.ChoiceField(label="状态", choices=PolicyStatus.choices, initial=PolicyStatus.DRAFT)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("allow_device_switch") and not cleaned.get("device_switch_limit"):
            self.add_error("device_switch_limit", "允许换机时，次数至少为 1。")
        if not cleaned.get("allow_device_switch") and cleaned.get("device_switch_limit", 0) != 0:
            self.add_error("device_switch_limit", "不允许换机时，次数必须为 0。")
        return cleaned


class CapabilityForm(forms.Form):
    capability_key = forms.CharField(label="能力键", max_length=128, help_text="必须带命名空间，例如 feature.export。")
    value_type = forms.ChoiceField(label="值类型", choices=CapabilityValueType.choices, initial=CapabilityValueType.BOOLEAN)
    default_value = forms.CharField(label="默认值", max_length=255, help_text='填写 JSON 值，例如 true、5 或 "pro"。')
    minimum_value = forms.IntegerField(label="最小值（整数类型可填）", min_value=0, required=False)
    maximum_value = forms.IntegerField(label="最大值（整数类型可填）", min_value=0, required=False)
    is_public = forms.BooleanField(label="允许客户端读取", required=False, initial=True)
    status = forms.ChoiceField(label="状态", choices=CapabilityStatus.choices, initial=CapabilityStatus.ACTIVE)

    def clean_default_value(self):
        raw = self.cleaned_data["default_value"]
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise forms.ValidationError("默认值必须是有效的 JSON 值，例如 true、5 或 \"pro\"。") from exc


class PlanForm(forms.Form):
    profile = forms.ModelChoiceField(label="绑定 Profile", queryset=SoftwareProfile.objects.none())
    policy_version = forms.ModelChoiceField(label="策略版本", queryset=PolicyVersion.objects.none(), empty_label="请选择策略版本")
    name = forms.CharField(label="套餐名称", max_length=120)
    duration_value = forms.IntegerField(label="有效期数值", min_value=1, initial=1)
    duration_unit = forms.ChoiceField(label="有效期单位", choices=(("minute", "分钟"), ("hour", "小时"), ("day", "天")), initial="day")
    quota_cost = forms.IntegerField(label="额度成本", min_value=0, initial=0)
    test_only = forms.BooleanField(label="测试套餐", required=False)
    capability_values = forms.CharField(label="能力覆盖（可选 JSON）", required=False, initial="{}", widget=forms.Textarea(attrs={"rows": 4}), help_text="只允许填写当前 Profile 已登记的能力键。")
    status = forms.ChoiceField(label="状态", choices=PlanStatus.choices, initial=PlanStatus.DRAFT)

    def __init__(self, *args, software=None, **kwargs):
        super().__init__(*args, **kwargs)
        profile_queryset = SoftwareProfile.objects.filter(software=software).exclude(status=ProfileStatus.ARCHIVED) if software else SoftwareProfile.objects.none()
        self.fields["profile"].queryset = profile_queryset.select_related("software")
        self.fields["policy_version"].queryset = PolicyVersion.objects.filter(profile__in=profile_queryset).exclude(status=PolicyStatus.ARCHIVED).select_related("profile")

    def clean_capability_values(self):
        raw = self.cleaned_data["capability_values"] or "{}"
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise forms.ValidationError("能力覆盖必须是 JSON 对象。") from exc
        if not isinstance(value, dict):
            raise forms.ValidationError("能力覆盖必须是 JSON 对象。")
        return value

    def clean(self):
        cleaned = super().clean()
        profile = cleaned.get("profile")
        policy = cleaned.get("policy_version")
        if profile and policy and policy.profile_id != profile.id:
            self.add_error("policy_version", "策略版本必须属于所选 Profile。")
        return cleaned


class DownstreamAccessForm(forms.Form):
    downstream = forms.ModelChoiceField(label="下游账号", queryset=DownstreamProfile.objects.none())
    enabled = forms.BooleanField(label="开放经营", required=False, initial=True)
    all_plans_allowed = forms.BooleanField(label="允许使用该软件的全部可用套餐", required=False, initial=True)
    allowed_plans = forms.ModelMultipleChoiceField(label="限定套餐（取消全部套餐后生效）", queryset=Plan.objects.none(), required=False, widget=forms.CheckboxSelectMultiple)

    def __init__(self, *args, software=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["downstream"].queryset = DownstreamProfile.objects.filter(status=DownstreamStatus.ACTIVE, user__is_active=True).select_related("user") if software else DownstreamProfile.objects.none()
        self.fields["allowed_plans"].queryset = Plan.objects.filter(software=software, status=PlanStatus.ACTIVE).order_by("name", "id") if software else Plan.objects.none()

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("enabled") and not cleaned.get("all_plans_allowed") and not cleaned.get("allowed_plans"):
            self.add_error("allowed_plans", "限制套餐范围时，至少选择一个可用套餐。")
        return cleaned
