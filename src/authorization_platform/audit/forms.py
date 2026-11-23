from __future__ import annotations

from django import forms

from .models import AuditOutcome


class AuditFilterForm(forms.Form):
    from_date = forms.DateField(
        label="起始日期",
        required=False,
        input_formats=("%Y-%m-%d",),
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )
    to_date = forms.DateField(
        label="结束日期",
        required=False,
        input_formats=("%Y-%m-%d",),
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )
    action = forms.CharField(label="动作", required=False, max_length=64)
    outcome = forms.ChoiceField(
        label="结果",
        required=False,
        choices=(("", "全部结果"), *AuditOutcome.choices),
    )
    object_type = forms.CharField(label="对象类型", required=False, max_length=64)
    object_public_id = forms.CharField(label="对象 ID", required=False, max_length=128)

    def clean_action(self) -> str:
        return self.cleaned_data["action"].strip()

    def clean_object_type(self) -> str:
        return self.cleaned_data["object_type"].strip()

    def clean_object_public_id(self) -> str:
        return self.cleaned_data["object_public_id"].strip()

    def clean(self):
        cleaned = super().clean()
        from_date = cleaned.get("from_date")
        to_date = cleaned.get("to_date")
        if from_date and to_date and from_date > to_date:
            raise forms.ValidationError("起始日期不能晚于结束日期。")
        return cleaned
