from __future__ import annotations

from django import forms
from django.conf import settings

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus


class QuotaCardIssueForm(forms.Form):
    amount = forms.IntegerField(label="额度面额", min_value=1, max_value=settings.QUOTA_CARD_MAX_AMOUNT)
    quantity = forms.IntegerField(label="生成数量", min_value=1, max_value=settings.QUOTA_CARD_MAX_BATCH_SIZE, initial=1)


class ManualCreditForm(forms.Form):
    downstream = forms.ModelChoiceField(
        label="下游账号",
        queryset=DownstreamProfile.objects.none(),
        empty_label="请选择下游账号",
    )
    amount = forms.IntegerField(label="充值额度", min_value=1, max_value=settings.QUOTA_CARD_MAX_AMOUNT)
    reason = forms.CharField(label="充值原因", min_length=2, max_length=255, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["downstream"].queryset = DownstreamProfile.objects.filter(
            status=DownstreamStatus.ACTIVE,
            user__is_active=True,
        ).select_related("user")


class QuotaRecoveryForm(forms.Form):
    downstream = forms.ModelChoiceField(
        label="下游账号",
        queryset=DownstreamProfile.objects.none(),
        empty_label="请选择下游账号",
    )
    amount = forms.IntegerField(label="回收额度", min_value=1, max_value=settings.QUOTA_CARD_MAX_AMOUNT)
    reason = forms.CharField(label="回收原因", min_length=2, max_length=255, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["downstream"].queryset = DownstreamProfile.objects.filter(
            status=DownstreamStatus.ACTIVE,
            user__is_active=True,
        ).select_related("user")


class RedeemQuotaCardForm(forms.Form):
    card_code = forms.CharField(label="额度卡密", max_length=128, strip=True, help_text="输入完整额度卡；兑换成功后余额会增加一次。")
