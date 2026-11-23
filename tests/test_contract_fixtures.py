from __future__ import annotations

import json
from pathlib import Path

from django.test import SimpleTestCase

from authorization_platform.licensing.authorization import (
    AuthorizationOperationError,
    canonicalize_jcs,
    device_proof_message,
    validate_authorization_response_shape,
    validate_device_scope,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "authorization_v1"
LOCAL_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "authorization_a_core_v1"
DEVICE_PROOF_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "device_proof_v1"
SCHEMA_DIR = Path(__file__).parent.parent / "protocol"


class AuthorizationV1FixtureTests(SimpleTestCase):
    def _load(self, name: str) -> dict:
        with (FIXTURE_DIR / name).open(encoding="utf-8") as handle:
            return json.load(handle)

    def test_all_fixtures_are_valid_json(self):
        files = sorted(FIXTURE_DIR.glob("*.json"))
        self.assertGreaterEqual(len(files), 10)
        for path in files:
            with self.subTest(path=path.name):
                self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)

    def test_device_proof_contract_fixture_matches_platform_canonical_bytes(self):
        fixture = json.loads((DEVICE_PROOF_FIXTURE_DIR / "activate.json").read_text(encoding="utf-8"))
        signed = {key: fixture[key] for key in (
            "action", "request_id", "authorization_id", "software_id", "profile_id",
            "client_id", "contract_version", "target", "arch", "channel",
            "installation_id", "device_public_key", "nonce",
        )}
        message = device_proof_message(signed)
        self.assertEqual(message.decode("utf-8"), fixture["expected_canonical_json"])
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(32))
        signature = private_key.sign(message)
        private_key.public_key().verify(signature, canonicalize_jcs(signed | {"domain": "authorization-platform.device-proof.v1"}))

    def test_positive_decisions_have_frozen_identity_time_and_integrity(self):
        required = {
            "schema_version",
            "request_id",
            "software_id",
            "profile_id",
            "client_id",
            "contract_version",
            "authorization_id",
            "authorization_revision",
            "device_scope",
            "decision",
            "issued_at",
            "expires_at",
            "server_time",
            "cache_until",
            "next_verify_at",
            "grace_until",
            "config_version",
            "support",
            "announcement",
            "modules",
            "integrity",
        }
        for name in ("active.json", "grace.json", "expired.json", "revoked.json", "blocked.json", "not_modified.json"):
            with self.subTest(name=name):
                fixture = self._load(name)
                self.assertTrue(required.issubset(fixture))
                validate_authorization_response_shape(fixture)
                self.assertEqual(fixture["schema_version"], "authorization.v1")
                self.assertEqual(fixture["contract_version"], "authorization.v1")
                self.assertEqual(fixture["target"], "windows")
                self.assertEqual(fixture["arch"], "x64")
                self.assertEqual(fixture["channel"], "stable")
                self.assertEqual(set(fixture["device_scope"]), {"scope", "device_id", "installation_id"})
                self.assertEqual(fixture["device_scope"]["scope"], "current_device")
                self.assertEqual(fixture["integrity"]["algorithm"], "ed25519")
                self.assertEqual(fixture["integrity"]["canonicalization"], "JCS-RFC8785")
                self.assertEqual(set(fixture["modules"]), {"contact", "notice", "purchase", "qr", "update"})
                self.assertEqual(fixture["modules"]["contact"], fixture["support"])
                self.assertEqual(fixture["modules"]["notice"], fixture["announcement"])

                for field in ("issued_at", "expires_at", "server_time"):
                    value = fixture[field]
                    self.assertIs(type(value), int)
                    self.assertGreaterEqual(value, -(2**63))
                    self.assertLessEqual(value, 2**63 - 1)

                self.assertLessEqual(fixture["issued_at"], fixture["server_time"])
                if fixture["decision"] == "expired":
                    self.assertGreaterEqual(fixture["server_time"], fixture["expires_at"])
                else:
                    self.assertLess(fixture["server_time"], fixture["expires_at"])

                for field in ("cache_until", "next_verify_at", "grace_until"):
                    value = fixture[field]
                    self.assertIs(type(value), int)
                    self.assertGreaterEqual(value, -(2**63))
                    self.assertLessEqual(value, 2**63 - 1)

                if fixture["decision"] == "grace":
                    self.assertIs(type(fixture["grace_until"]), int)
                    self.assertLess(fixture["server_time"], fixture["grace_until"])

                self.assertLessEqual(fixture["cache_until"], fixture["expires_at"])
                self.assertLessEqual(fixture["next_verify_at"], fixture["expires_at"])

    def test_risk_blocked_is_a_structured_error_not_an_authorization_envelope(self):
        fixture = self._load("risk-blocked-error.json")
        self.assertEqual(fixture["error"]["code"], "RISK_BLOCKED")
        self.assertFalse(fixture["error"]["retryable"])
        self.assertEqual(fixture["transport"]["http_status"], 403)
        self.assertEqual(fixture["transport"]["cache_control"], "no-store")
        self.assertNotIn("decision", fixture)
        self.assertNotIn("integrity", fixture)

    def test_unbound_compatibility_fixture_is_central_shape_only(self):
        fixture = self._load("unbound.json")
        validate_authorization_response_shape(fixture)
        self.assertEqual(fixture["decision"], "unbound")
        self.assertNotEqual(fixture["decision"], "active")
        self.assertEqual(fixture["cache_until"], fixture["server_time"])
        self.assertEqual(fixture["next_verify_at"], fixture["server_time"])
        self.assertEqual(fixture["state_code"], "unbound")
        self.assertEqual(fixture["binding_state"], "unbound")
        self.assertIsNotNone(fixture["device_scope"]["device_id"])
        self.assertIsNotNone(fixture["device_scope"]["installation_id"])

    def test_local_envelope_fixture_keeps_a_to_core_trust_boundary(self):
        fixture = json.loads((LOCAL_FIXTURE_DIR / "active.json").read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema_version"], "authorization-a-core.v1")
        self.assertEqual(fixture["local_contract_version"], "authorization-a-core.v1")
        self.assertEqual(fixture["integrity"]["origin"], "authorization-a")
        self.assertEqual(fixture["integrity"]["audience"], "authorization-a-core")
        self.assertEqual(fixture["integrity"]["algorithm"], "ed25519")
        self.assertEqual(fixture["integrity"]["canonicalization"], "JCS-RFC8785")
        self.assertIn("support", fixture)
        self.assertIn("announcement", fixture)
        validate_device_scope(fixture["device_scope"])
        self.assertIn("modules", fixture)
        self.assertIsNone(fixture["modules"]["contact"])
        self.assertIsNone(fixture["support"])
        self.assertIsNone(fixture["announcement"])

    def test_device_proof_inputs_do_not_cross_into_success_envelopes(self):
        request_only = {
            "device_public_key",
            "device_proof",
            "client_version",
            "nonce",
            "installation_id",
        }
        success_paths = [
            *sorted(FIXTURE_DIR.glob("active.json")),
            *sorted(FIXTURE_DIR.glob("grace.json")),
            *sorted(FIXTURE_DIR.glob("expired.json")),
            *sorted(FIXTURE_DIR.glob("revoked.json")),
            *sorted(FIXTURE_DIR.glob("not_modified.json")),
            LOCAL_FIXTURE_DIR / "active.json",
            LOCAL_FIXTURE_DIR / "expired.json",
        ]
        for path in success_paths:
            with self.subTest(path=path):
                fixture = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(request_only.isdisjoint(fixture))
                self.assertIsInstance(fixture["device_scope"], dict)
                self.assertEqual(fixture["device_scope"]["scope"], "current_device")
                self.assertIn("installation_id", fixture["device_scope"])

    def test_device_scope_shape_fixture_fails_closed(self):
        cases = json.loads((FIXTURE_DIR / "device_scope-shapes.json").read_text(encoding="utf-8"))
        validate_device_scope(cases["valid"])
        for name in (
            "string",
            "missing_installation_id",
            "extra_field",
            "wrong_scope",
            "wrong_device_id_type",
            "too_long_installation_id",
        ):
            with self.subTest(name=name), self.assertRaises(AuthorizationOperationError) as raised:
                validate_device_scope(cases[name])
            self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

    def test_active_response_cannot_use_null_device_scope(self):
        fixture = self._load("active.json")
        fixture["device_scope"] = {
            "scope": "current_device",
            "device_id": None,
            "installation_id": None,
        }
        with self.assertRaises(AuthorizationOperationError) as raised:
            validate_authorization_response_shape(fixture)
        self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

    def test_live_decisions_cannot_cross_expiry_or_split_cache_window(self):
        for name in ("active.json", "grace.json", "not_modified.json"):
            with self.subTest(name=name):
                fixture = self._load(name)
                fixture["server_time"] = fixture["expires_at"]
                with self.assertRaises(AuthorizationOperationError) as raised:
                    validate_authorization_response_shape(fixture)
                self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

        fixture = self._load("active.json")
        fixture["next_verify_at"] = fixture["cache_until"] + 1
        with self.assertRaises(AuthorizationOperationError) as raised:
            validate_authorization_response_shape(fixture)
        self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

    def test_only_declared_extensions_namespace_accepts_top_level_extension_data(self):
        fixture = self._load("active.json")
        fixture["extensions"] = {"com.example.test": {"display_hint": "optional"}}
        validate_authorization_response_shape(fixture)

        fixture["product_secret"] = "must-not-become-an-authorization-claim"
        with self.assertRaises(AuthorizationOperationError) as raised:
            validate_authorization_response_shape(fixture)
        self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

        fixture = self._load("active.json")
        fixture["capabilities"] = []
        with self.assertRaises(AuthorizationOperationError) as raised:
            validate_authorization_response_shape(fixture)
        self.assertEqual(raised.exception.code, "RESPONSE_SCHEMA_INVALID")

    def test_a_core_time_contract_declares_int64_and_non_negative_v1_domain(self):
        central_schema = json.loads((SCHEMA_DIR / "authorization.v1.schema.json").read_text(encoding="utf-8"))
        central_epoch = central_schema["$defs"]["epochSeconds"]
        self.assertEqual(central_epoch["minimum"], -(2**63))
        self.assertEqual(central_epoch["maximum"], 2**63 - 1)

        schema = json.loads((SCHEMA_DIR / "authorization-a-core.v1.schema.json").read_text(encoding="utf-8"))
        epoch = schema["$defs"]["epochSeconds"]
        self.assertEqual(epoch["minimum"], 0)
        self.assertEqual(epoch["maximum"], 2**63 - 1)
        for field in ("issued_at", "expires_at", "server_time", "cache_until", "next_verify_at", "grace_until"):
            self.assertEqual(schema["properties"][field]["$ref"], "#/$defs/epochSeconds")

    def test_local_negative_fixtures_are_structured_and_non_retryable(self):
        for name in ("cross-scope.json", "signature-invalid.json"):
            with self.subTest(name=name):
                fixture = json.loads((LOCAL_FIXTURE_DIR / name).read_text(encoding="utf-8"))
                self.assertEqual(fixture["error"]["retryable"], False)

    def test_protocol_schemas_are_valid_json_and_keep_frozen_versions(self):
        central = json.loads((SCHEMA_DIR / "authorization.v1.schema.json").read_text(encoding="utf-8"))
        local = json.loads((SCHEMA_DIR / "authorization-a-core.v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(central["$id"], "authorization.v1")
        self.assertEqual(local["$id"], "authorization-a-core.v1")
        self.assertEqual(central["properties"]["integrity"]["$ref"], "#/$defs/integrity")
        self.assertEqual(central["properties"]["device_scope"]["$ref"], "#/$defs/deviceScope")
        self.assertEqual(local["properties"]["device_scope"]["$ref"], "#/$defs/deviceScope")
        self.assertEqual(central["$defs"]["deviceScope"], local["$defs"]["deviceScope"])
        self.assertEqual(local["properties"]["integrity"]["properties"]["origin"]["const"], "authorization-a")
        self.assertEqual(local["properties"]["integrity"]["properties"]["audience"]["const"], "authorization-a-core")
        for field in ("cache_until", "next_verify_at", "grace_until"):
            self.assertIn(field, local["required"])
        for field in ("support", "announcement", "modules"):
            self.assertIn(field, central["required"])
            self.assertIn(field, local["required"])
        self.assertFalse(central["additionalProperties"])
        self.assertFalse(local["additionalProperties"])
        self.assertEqual(central["properties"]["extensions"]["type"], "object")
        self.assertEqual(local["properties"]["extensions"]["type"], "object")

    def test_negative_fixtures_use_stable_non_retryable_codes(self):
        expected = {
            "missing-required-field.json": "MISSING_REQUIRED_FIELD",
            "signature-invalid.json": "SIGNATURE_INVALID",
            "unknown-key.json": "KEY_UNKNOWN",
            "cross-scope.json": "DEVICE_SCOPE_MISMATCH",
            "time-rollback.json": "TIME_ROLLBACK_DETECTED",
            "old-contract.json": "CONTRACT_VERSION_UNSUPPORTED",
            "response-schema-invalid.json": "RESPONSE_SCHEMA_INVALID",
            "risk-blocked-error.json": "RISK_BLOCKED",
        }
        for name, code in expected.items():
            with self.subTest(name=name):
                error = self._load(name)["error"]
                self.assertEqual(error["code"], code)
                self.assertFalse(error["retryable"])
                if "server_time" in error:
                    self.assertIs(type(error["server_time"]), int)
                    self.assertGreaterEqual(error["server_time"], -(2**63))
                    self.assertLessEqual(error["server_time"], 2**63 - 1)
