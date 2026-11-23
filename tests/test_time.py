from __future__ import annotations

from datetime import datetime, timezone

from django.test import SimpleTestCase

from authorization_platform.core.time import (
    BEIJING,
    FixedClock,
    calculate_expiry,
    format_beijing_wall_clock,
    is_expired,
    iso_z,
    normalize_duration,
    to_beijing,
)


class TimeBoundaryTests(SimpleTestCase):
    def test_duration_units_are_normalized_to_integer_seconds(self):
        self.assertEqual(normalize_duration(1, "分钟"), 60)
        self.assertEqual(normalize_duration(1, "hour"), 3600)
        self.assertEqual(normalize_duration(1, "天"), 86400)

    def test_invalid_duration_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_duration(0, "分钟")
        with self.assertRaises(ValueError):
            normalize_duration(1, "weeks")

    def test_expiry_is_exclusive_at_the_boundary(self):
        start = datetime(2026, 8, 19, 0, 0, tzinfo=timezone.utc)
        expiry = calculate_expiry(start, 60)
        self.assertFalse(is_expired(expiry, clock=FixedClock(start)))
        self.assertTrue(is_expired(expiry, clock=FixedClock(expiry)))

    def test_beijing_is_presentation_only_and_api_time_is_utc(self):
        value = datetime(2026, 8, 19, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(to_beijing(value).tzinfo, BEIJING)
        self.assertEqual(to_beijing(value).hour, 8)
        self.assertEqual(iso_z(value), "2026-08-19T00:00:00Z")

    def test_beijing_wall_clock_uses_next_calendar_day_across_utc_evening(self):
        value = datetime(2026, 9, 5, 16, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(format_beijing_wall_clock(value), "2026-09-06 00:00:00")
        self.assertEqual(format_beijing_wall_clock(None), "")
        self.assertNotEqual(value.strftime("%Y-%m-%d %H:%M:%S"), format_beijing_wall_clock(value))
