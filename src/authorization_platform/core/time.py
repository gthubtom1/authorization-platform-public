"""Time primitives shared by future authorization services and tests.

The application stores and compares UTC instants. Beijing time is a presentation
concern only. Keeping this boundary in one small module makes the future service
logic testable without changing the machine clock.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol
from zoneinfo import ZoneInfo


UTC = timezone.utc
BEIJING = ZoneInfo("Asia/Shanghai")
_DURATION_MULTIPLIERS = {"second": 1, "seconds": 1, "秒": 1, "minute": 60, "minutes": 60, "分钟": 60, "hour": 3600, "hours": 3600, "小时": 3600, "day": 86400, "days": 86400, "天": 86400}


class Clock(Protocol):
    def now(self) -> datetime:
        """Return an aware UTC datetime."""


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True)
class FixedClock:
    value: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", as_utc(self.value))

    def now(self) -> datetime:
        return self.value


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC)


def to_beijing(value: datetime) -> datetime:
    return as_utc(value).astimezone(BEIJING)


def format_beijing_wall_clock(value: datetime | None) -> str:
    if value is None:
        return ""
    return to_beijing(value).strftime("%Y-%m-%d %H:%M:%S")


def iso_z(value: datetime) -> str:
    return as_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_duration(value: int, unit: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("duration value must be a positive integer")
    if not isinstance(unit, str):
        raise ValueError("duration unit must be text")
    multiplier = _DURATION_MULTIPLIERS.get(unit.strip().lower())
    if multiplier is None:
        raise ValueError(f"unsupported duration unit: {unit}")
    return value * multiplier


def calculate_expiry(started_at: datetime, duration_seconds: int) -> datetime:
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int) or duration_seconds <= 0:
        raise ValueError("duration_seconds must be a positive integer")
    return as_utc(started_at) + timedelta(seconds=duration_seconds)


def is_expired(expires_at: datetime, *, clock: Clock | None = None, now: datetime | None = None) -> bool:
    current = as_utc(now) if now is not None else as_utc((clock or SystemClock()).now())
    return current >= as_utc(expires_at)
