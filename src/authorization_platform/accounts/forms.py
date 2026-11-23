from __future__ import annotations

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator

from .models import DownstreamStatus
from .services import AccountOperationError, get_downstream_profile, is_active_downstream, is_platform_admin, normalize_username


USERNAME_VALIDATOR = RegexValidator(
    regex=r"^[a-z0-9][a-z0-9_.-]{2,149}$",
    message="用户名需为 3-150 位小写字母、数字、点、下划线或短横线。",
)


def _cleaned_username(value: str) -> str:
    try:
        username = normalize_username(value)
    except AccountOperationError as exc:
        raise forms.ValidationError(USERNAME_VALIDATOR.message) from exc
    USERNAME_VALIDATOR(username)
    return username


class LoginForm(AuthenticationForm):
    error_messages = {
        "invalid_login": "用户名或密码不正确。",
        "inactive": "当前账号不可用。",
        "suspended": "账号已暂停。",
    }

    def __init__(self, *args, expected_role: str | None = None, **kwargs):
        self.expected_role = expected_role
        super().__init__(*args, **kwargs)

    def clean_username(self) -> str:
        submitted = str(self.cleaned_data.get("username") or "").strip()
        if not submitted:
            return submitted
        user_model = get_user_model()
        exact = user_model.objects.filter(username=submitted).first()
        if exact is not None:
            return exact.username
        folded = submitted.casefold()
        folded_match = user_model.objects.filter(username=folded).first()
        if folded_match is not None:
            return folded_match.username
        ci_matches = list(user_model.objects.filter(username__iexact=submitted)[:2])
        if len(ci_matches) == 1:
            return ci_matches[0].username
        return folded

    def confirm_login_allowed(self, user) -> None:
        super().confirm_login_allowed(user)
        if self.expected_role == "admin":
            if not is_platform_admin(user):
                raise ValidationError(self.error_messages["invalid_login"], code="invalid_login")
            return
        if self.expected_role == "downstream":
            if is_platform_admin(user):
                raise ValidationError(self.error_messages["invalid_login"], code="invalid_login")
            profile = get_downstream_profile(user)
            if profile is not None and profile.status == DownstreamStatus.SUSPENDED:
                raise ValidationError(self.error_messages["suspended"], code="suspended")
            if not is_active_downstream(user):
                raise ValidationError(self.error_messages["invalid_login"], code="invalid_login")
            return
        if not (is_platform_admin(user) or is_active_downstream(user)):
            raise ValidationError(self.error_messages["invalid_login"], code="invalid_login")


class RegistrationForm(forms.Form):
    invitation_code = forms.CharField(label="邀请码", max_length=128, strip=True)
    username = forms.CharField(label="用户名", max_length=150, strip=True)
    password = forms.CharField(
        label="密码",
        min_length=10,
        widget=forms.PasswordInput,
        strip=False,
        help_text="至少 10 位，不能全是数字，不能是常见密码。",
    )
    password_confirm = forms.CharField(label="确认密码", min_length=10, widget=forms.PasswordInput, strip=False)

    def clean_username(self) -> str:
        return _cleaned_username(self.cleaned_data["username"])

    def clean_password(self) -> str:
        password = self.cleaned_data["password"]
        try:
            validate_password(password)
        except ValidationError as exc:
            raise forms.ValidationError("密码不符合安全要求。") from exc
        return password

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") and cleaned.get("password_confirm") and cleaned["password"] != cleaned["password_confirm"]:
            self.add_error("password_confirm", "两次输入的密码不一致。")
        return cleaned


class AdminDownstreamForm(forms.Form):
    username = forms.CharField(label="用户名", max_length=150, strip=True)
    password = forms.CharField(label="初始密码", min_length=10, widget=forms.PasswordInput, strip=False)
    password_confirm = forms.CharField(label="确认密码", min_length=10, widget=forms.PasswordInput, strip=False)

    def clean_username(self) -> str:
        return _cleaned_username(self.cleaned_data["username"])

    def clean_password(self) -> str:
        password = self.cleaned_data["password"]
        try:
            validate_password(password)
        except ValidationError as exc:
            raise forms.ValidationError("密码不符合安全要求。") from exc
        return password

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") and cleaned.get("password_confirm") and cleaned["password"] != cleaned["password_confirm"]:
            self.add_error("password_confirm", "两次输入的密码不一致。")
        return cleaned


class PasswordChangeForm(forms.Form):
    current_password = forms.CharField(label="当前密码", max_length=256, widget=forms.PasswordInput, strip=False)
    new_password = forms.CharField(label="新密码", min_length=10, max_length=256, widget=forms.PasswordInput, strip=False)
    new_password_confirm = forms.CharField(label="确认新密码", min_length=10, max_length=256, widget=forms.PasswordInput, strip=False)

    def clean_new_password(self) -> str:
        password = self.cleaned_data["new_password"]
        try:
            validate_password(password)
        except ValidationError as exc:
            raise forms.ValidationError("密码不符合安全要求。") from exc
        return password

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("new_password") and cleaned.get("new_password_confirm") and cleaned["new_password"] != cleaned["new_password_confirm"]:
            self.add_error("new_password_confirm", "两次输入的新密码不一致。")
        return cleaned


class PasswordResetForm(forms.Form):
    new_password = forms.CharField(label="新密码", min_length=10, max_length=256, widget=forms.PasswordInput, strip=False)
    new_password_confirm = forms.CharField(label="确认新密码", min_length=10, max_length=256, widget=forms.PasswordInput, strip=False)
    reason = forms.CharField(label="重置原因", min_length=2, max_length=255, widget=forms.Textarea(attrs={"rows": 3}))

    def clean_new_password(self) -> str:
        password = self.cleaned_data["new_password"]
        try:
            validate_password(password)
        except ValidationError as exc:
            raise forms.ValidationError("密码不符合安全要求。") from exc
        return password

    def clean_reason(self) -> str:
        return self.cleaned_data["reason"].strip()

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("new_password") and cleaned.get("new_password_confirm") and cleaned["new_password"] != cleaned["new_password_confirm"]:
            self.add_error("new_password_confirm", "两次输入的新密码不一致。")
        return cleaned


class InvitationBatchForm(forms.Form):
    quantity = forms.IntegerField(label="生成数量", min_value=1, max_value=settings.INVITATION_MAX_BATCH_SIZE)


class ArchiveForm(forms.Form):
    reason = forms.CharField(label="归档原因", max_length=255, min_length=2, widget=forms.Textarea(attrs={"rows": 3}))


class DeleteArchivedForm(forms.Form):
    confirmation = forms.BooleanField(label="确认删除", required=True)
    reason = forms.CharField(label="删除原因", max_length=255, min_length=2)
