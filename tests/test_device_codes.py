from __future__ import annotations

from django.test import SimpleTestCase

from authorization_platform.licensing.device_codes import compact_device_code


class DeviceCodeTests(SimpleTestCase):
    def test_hash_fingerprint_becomes_stable_grouped_code(self):
        installation_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        code = compact_device_code(installation_id)
        self.assertIsNotNone(code)
        self.assertRegex(code, r"^GS-(?:[A-F0-9]{4}-){4}[A-F0-9]{4}$")
        self.assertEqual(code, compact_device_code(installation_id))
        self.assertNotIn(installation_id, code)

    def test_existing_codes_and_opaque_ids_remain_compatible(self):
        self.assertEqual(
            compact_device_code("gs-65fb-f502-b439-270c"),
            "GS-65FB-F502-B439-270C",
        )
        self.assertEqual(compact_device_code("install-a"), "install-a")
        self.assertIsNone(compact_device_code(None))
