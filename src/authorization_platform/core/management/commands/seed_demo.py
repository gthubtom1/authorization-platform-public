from __future__ import annotations

import getpass
import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction
from django.utils import timezone

from authorization_platform.accounts.models import DownstreamProfile, DownstreamStatus, RegistrationSource


class Command(BaseCommand):
    help = "创建本地演示管理员和下游账号；密码只从安全输入或环境变量读取。已存在的用户名一律失败退出，绝不改角色。"

    def add_arguments(self, parser) -> None:
        parser.add_argument("--admin-username", default="admin")
        parser.add_argument("--downstream-username", default="demo_downstream")
        parser.add_argument(
            "--reset-passwords",
            action="store_true",
            help="无效果：已存在用户名会失败退出，新建账号始终写入本次密码。",
        )

    def handle(self, *args, **options):
        if getattr(settings, "APP_ENV", "") == "production":
            raise CommandError("production 拒绝 seed_demo，禁止创建演示超管或下游。")
        admin_username = options["admin_username"]
        downstream_username = options["downstream_username"]
        admin_password = os.getenv("DEMO_ADMIN_PASSWORD")
        downstream_password = os.getenv("DEMO_DOWNSTREAM_PASSWORD")
        admin_password = admin_password or self._prompt_password("管理员密码")
        downstream_password = downstream_password or self._prompt_password("下游密码")

        if len(admin_password) < 10 or len(downstream_password) < 10:
            raise CommandError("演示密码至少 10 位；命令不会输出密码内容。")

        try:
            with transaction.atomic():
                self._reject_existing_usernames(admin_username, downstream_username)
                admin = self._create_user(
                    admin_username,
                    admin_password,
                    is_staff=True,
                    is_superuser=True,
                    group_name="platform_admin",
                )
                downstream = self._create_user(
                    downstream_username,
                    downstream_password,
                    is_staff=False,
                    is_superuser=False,
                    group_name="downstream",
                )
                profile, _ = DownstreamProfile.objects.get_or_create(
                    user=downstream,
                    defaults={
                        "status": DownstreamStatus.ACTIVE,
                        "registration_source": RegistrationSource.DIRECT,
                        "created_by": admin,
                        "registered_at": timezone.now(),
                    },
                )
                if profile.status != DownstreamStatus.ACTIVE or not downstream.is_active:
                    profile.status = DownstreamStatus.ACTIVE
                    profile.closed_at = None
                    profile.closed_by = None
                    profile.closed_reason = ""
                    profile.session_version += 1
                    profile.save(update_fields=("status", "closed_at", "closed_by", "closed_reason", "session_version", "updated_at"))
                    downstream.is_active = True
                    downstream.save(update_fields=("is_active",))
        except IntegrityError as exc:
            raise CommandError("用户名已存在，拒绝改角色。命令未改任何账号。") from exc

        self.stdout.write(self.style.SUCCESS("演示数据已准备完成。"))
        self.stdout.write(f"管理员账号：{admin.username}")
        self.stdout.write(f"下游账号：{downstream.username}")

    def _prompt_password(self, label: str) -> str:
        return getpass.getpass(f"请输入{label}（不会显示）：")

    def _reject_existing_usernames(self, admin_username: str, downstream_username: str) -> None:
        if admin_username == downstream_username:
            raise CommandError("管理员与下游不能使用同一用户名；命令未改任何账号。")
        user_model = get_user_model()
        existing = list(
            user_model.objects.filter(username__in=(admin_username, downstream_username)).values_list("username", flat=True)
        )
        if existing:
            names = "、".join(sorted(existing))
            raise CommandError(f"用户名已存在，拒绝改角色：{names}。命令未改任何账号。")

    def _create_user(self, username: str, password: str, *, is_staff: bool, is_superuser: bool, group_name: str):
        user_model = get_user_model()
        user = user_model.objects.create(
            username=username,
            is_active=True,
            is_staff=is_staff,
            is_superuser=is_superuser,
        )
        user.set_password(password)
        user.save(update_fields=("password",))
        group, _ = Group.objects.get_or_create(name=group_name)
        user.groups.add(group)
        return user
