from __future__ import annotations

import hashlib
import base64
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import resolve
from django.core.cache import cache
from django.test import Client
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(settings.BASE_DIR)


def load_tool(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


intake = load_tool("client_intake", ROOT / "scripts/client-handoff/prepare-config.py")


class HandoffBundleIntegrityTests(SimpleTestCase):
    def test_packaged_files_hashes_sources_and_clean_boundary(self):
        bundle = ROOT / "软件授权接入包"
        manifest = json.loads((bundle / "交付清单.json").read_text(encoding="utf-8"))
        listed = set(manifest["files"]) | {"交付清单.json"}
        actual = {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}
        self.assertEqual(actual, listed)
        self.assertFalse(manifest["runtime_connected"])
        excluded = {".git", "target", "product-state", "incoming", "node_modules", "__pycache__", "灾备钥匙包"}
        for name, entry in manifest["files"].items():
            with self.subTest(file=name):
                path = bundle / name
                self.assertFalse(set(path.relative_to(bundle).parts) & excluded)
                self.assertFalse(path.is_symlink())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
                if isinstance(entry["origin"], dict):
                    self.assertEqual(entry["sha256"], entry["origin"]["sha256"])
        for source, digest in manifest["platform_sources"].items():
            self.assertEqual(hashlib.sha256((ROOT / source).read_text(encoding="utf-8").encode("utf-8")).hexdigest(), digest)
        self.assertEqual((bundle / "工具/prepare-config.py").read_bytes(), (ROOT / "scripts/client-handoff/prepare-config.py").read_bytes())
        self.assertEqual((bundle / "平台公开资料/09-给软件项目AI的接入指令.md").read_text(encoding="utf-8"), (ROOT / "接入说明/09-给软件项目AI的接入指令.md").read_text(encoding="utf-8"))
        for name in intake.CONTRACTS:
            self.assertEqual((bundle / "平台公开资料/protocol" / name).read_text(encoding="utf-8"), (ROOT / "protocol" / name).read_text(encoding="utf-8"))
        self.assertFalse(list(bundle.rglob("register-platform.ps1")))
        self.assertFalse(list(bundle.rglob("*-integration.json")))
        self.assertTrue((bundle / "授权启动器模板/src/lib.rs").is_file())
        self.assertTrue((bundle / "授权启动器模板/Cargo.lock").is_file())

    def test_generated_index_matches_actual_routes_fields_schemas_and_every_feature(self):
        from authorization_platform.licensing.authorization import AUTHORIZATION_REQUEST_COMMON_FIELDS
        bundle = ROOT / "软件授权接入包"
        index = json.loads((bundle / "平台公开资料/接口字段索引.json").read_text(encoding="utf-8"))
        self.assertEqual(set(index["request_common_allowed"]), set(AUTHORIZATION_REQUEST_COMMON_FIELDS))
        expected = {"activate", "verify", "deactivate", "launch_ticket", "consume_launch_ticket", "releases", "download"}
        self.assertEqual(set(index["endpoints"]), expected)
        for name, endpoint in index["endpoints"].items():
            path = endpoint["path"].format(software_id="wire-tool", profile_id="stable", release_id="11111111-1111-4111-8111-111111111111")
            callback = resolve(path)
            self.assertTrue(callback.view_name.startswith(("licensing:", "releases:")))
            if endpoint["method"] == "POST":
                required = endpoint["request_required_for_new_client"]
                self.assertIn("device_proof", required)
                self.assertNotIn("action", required)
                self.assertEqual("license_key" in required, name == "activate")
                self.assertEqual("ticket_id" in required, name == "consume_launch_ticket")
        self.assertEqual(len(index["platform_feature_names"]), 28)
        for kind, filename in (("authorization", "authorization.v1.schema.json"), ("local_authorization", "authorization-a-core.v1.schema.json")):
            schema = json.loads((ROOT / "protocol" / filename).read_text(encoding="utf-8"))
            self.assertEqual(index["response_contracts"][kind]["required"], schema["required"])
            self.assertEqual(set(index["response_contracts"][kind]["allowed"]), set(schema["properties"]))
        self.assertEqual(set(index["device_proof"]["message"]["action_values"]), {"activate", "verify", "deactivate", "launch-ticket", "ticket-consume"})
        self.assertNotIn("manifest", index["endpoints"])

    def test_current_overlays_and_mandatory_adaptation_requirements_survive_rebuild(self):
        bundle = ROOT / "软件授权接入包"
        builder = load_tool("client_bundle_builder", ROOT / "scripts/build-client-handoff.py")
        guide = (bundle / "授权启动器模板/AI-HANDOFF.md").read_text(encoding="utf-8")
        self.assertIn("模板兼容差异.md", guide)
        self.assertIn("profile-default", guide)
        self.assertIn("NEXT_ACTION不能覆盖", guide)
        differences = (bundle / "平台公开资料/模板兼容差异.md").read_text(encoding="utf-8")
        for finding in ("B1", "B2", "B3", "B4", "B6", "B7", "C1", "C2", "C3"):
            self.assertIn(finding, differences)
        ticket = (bundle / "授权启动器模板/protocol/launch-ticket.v1.md").read_text(encoding="utf-8")
        self.assertNotIn("换新 `nonce` 重试", ticket)
        self.assertNotIn("失败不阻断已开的核心", ticket)
        self.assertNotIn("只带 `ticket_id` 与 `server_time`", ticket)
        self.assertIn('"decision": "consumed"', ticket)
        self.assertEqual((bundle / "授权启动器模板/protocol/device-proof.v1.json").read_bytes(), (ROOT / "protocol/device-proof.v1.json").read_bytes())
        schema = json.loads((bundle / "授权启动器模板/protocol/authorization-a-ui.v1.schema.json").read_text(encoding="utf-8"))
        self.assertIn("notice", schema["properties"]["enabled_modules"]["items"]["enum"])
        api = (bundle / "平台公开资料/客户端API合同.md").read_text(encoding="utf-8")
        self.assertNotIn("/manifest?", api)
        self.assertNotIn("tests/fixtures/", api)
        self.assertIn("/releases/?", api)
        self.assertIn("release=null", api)
        self.assertEqual(builder.source_contract_index(), json.loads((bundle / "平台公开资料/接口字段索引.json").read_text(encoding="utf-8")))


@override_settings(AUTHORIZATION_PUBLIC_BASE_URL="https://platform.example.test")
class ClientHandoffTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_superuser(username="handoff-admin", password="Isolated-password-123"))
        created = self.client.post("/api/v1/manage/catalog/", json.dumps({"name": "本地交接测试"}), content_type="application/json", HTTP_IDEMPOTENCY_KEY="handoff-create")
        self.assertEqual(created.status_code, 201, created.content)
        self.identity = created.json()["software"]["software_id"]
        exported = self.client.get(f"/api/v1/manage/catalog/software/{self.identity}/integration-config/")
        self.assertEqual(exported.status_code, 200)
        self.raw = exported.content
        self.config = json.loads(self.raw)
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.template = self.folder / "模板"
        self.template.mkdir()
        (self.template / "src").mkdir()
        (self.template / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        (self.template / "HANDOFF-COPY.json").write_text('{}', encoding="utf-8")
        self.source = self.folder / "配置-integration.json"
        self.source.write_bytes(self.raw)

    def save(self, config):
        self.source.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

    def test_real_export_checks_without_writes_and_prepares_exact_identity_and_contracts(self):
        before = set(self.template.rglob("*"))
        result = intake.prepare(self.source, self.template)
        self.assertEqual(result["mode"], "check-only")
        self.assertFalse(result["runtime_connected"])
        self.assertEqual(set(self.template.rglob("*")), before)
        prepared = intake.prepare(self.source, self.template, write=True)
        dest = Path(prepared["output"])
        binding = json.loads((dest / "platform-binding.json").read_text(encoding="utf-8"))
        self.assertEqual(binding["software"], self.config["software"])
        self.assertEqual(binding["platform"], self.config["platform"])
        self.assertEqual(binding["api"], self.config["api"])
        self.assertIsNone(binding["current_client_version"])
        self.assertEqual(binding["status"], "PARTIAL")
        self.assertEqual((dest / "source-integration.json").read_bytes(), self.raw)
        self.assertEqual(binding["source_sha256"], hashlib.sha256(self.raw).hexdigest())
        for name in intake.CONTRACTS:
            self.assertEqual(json.loads((dest / name).read_text(encoding="utf-8")), self.config["contracts"][name])
        self.assertEqual((dest / "AI-HANDOFF.md").read_text(encoding="utf-8"), self.config["ai_handoff"])
        self.assertEqual((dest / "launch-ticket.md").read_text(encoding="utf-8"), self.config["launch_ticket_contract"])
        self.assertFalse((self.template / "product-state").exists())

    def test_repeated_and_changed_binding_never_overwrite_existing_work(self):
        dest = Path(intake.prepare(self.source, self.template, write=True)["output"])
        (dest / "README.md").write_text("product work", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "already prepared"):
            intake.prepare(self.source, self.template, write=True)
        changed = json.loads(self.raw)
        changed["software"]["name"] = "changed"
        self.save(changed)
        with self.assertRaisesRegex(ValueError, "differs"):
            intake.prepare(self.source, self.template, write=True)
        self.assertEqual((dest / "README.md").read_text(encoding="utf-8"), "product work")
        self.assertEqual((dest / "source-integration.json").read_bytes(), self.raw)

    def test_wrong_schema_key_core_identity_and_external_api_fail_before_writing(self):
        mutations = (
            lambda data: data.update(schema="software-bind.v1"),
            lambda data: data["platform"].update(authorization_public_key="bad"),
            lambda data: data["core"].update(talks_to_platform=True),
            lambda data: data["software"].update(profile_id="../other"),
            lambda data: data["software"].update(software_id="another-software"),
            lambda data: data["api"].update(verify="https://attacker.example/verify"),
            lambda data: data.update(admin_password="must-not-copy"),
            lambda data: data["platform"].update(private_key="must-not-copy"),
            lambda data: data["platform"].update(algorithm="Ed25519"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = json.loads(self.raw)
                mutate(data)
                self.save(data)
                with self.assertRaises(ValueError):
                    intake.prepare(self.source, self.template, write=True)
                self.assertFalse((self.template / "平台接入配置").exists())
                self.assertFalse(list(self.template.glob(".binding-*")))

    def test_duplicate_keys_and_incomplete_export_fail_closed(self):
        self.source.write_text('{"schema":"software-bind.v2","schema":"software-bind.v1"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            intake.prepare(self.source, self.template, write=True)
        data = json.loads(self.raw)
        del data["contracts"][intake.CONTRACTS[0]]
        self.save(data)
        with self.assertRaises(ValueError):
            intake.prepare(self.source, self.template, write=True)

    def test_http_needs_explicit_local_mode_and_never_allows_remote_http(self):
        data = json.loads(self.raw)
        data["platform"]["base_url"] = "http://127.0.0.1:8123"
        self.save(data)
        with self.assertRaises(ValueError):
            intake.prepare(self.source, self.template)
        self.assertEqual(intake.prepare(self.source, self.template, allow_local_http=True)["mode"], "check-only")
        data["platform"]["base_url"] = "http://platform.example.test"
        self.save(data)
        with self.assertRaises(ValueError):
            intake.prepare(self.source, self.template, allow_local_http=True)

    def test_minimum_version_can_be_empty_but_is_never_inferred_as_current(self):
        self.config["software"]["minimum_client_version"] = ""
        self.save(self.config)
        output = Path(intake.prepare(self.source, self.template, write=True)["output"])
        binding = json.loads((output / "platform-binding.json").read_text(encoding="utf-8"))
        self.assertEqual(binding["software"]["minimum_client_version"], "")
        self.assertIsNone(binding["current_client_version"])

    def test_unmarked_template_master_is_not_initialized(self):
        (self.template / "HANDOFF-COPY.json").unlink()
        with self.assertRaisesRegex(ValueError, "copy marker"):
            intake.prepare(self.source, self.template, write=True)
        self.assertFalse((self.template / "平台接入配置").exists())

    def test_delivered_cli_handles_unicode_paths_and_does_not_print_bad_config(self):
        script = ROOT / "软件授权接入包/工具/prepare-config.py"
        command = [sys.executable, str(script), str(self.source), "--template-root", str(self.template), "--prepare"]
        result = subprocess.run(command, capture_output=True, encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["mode"], "prepared")
        self.source.write_text('{"admin_password":"secret-must-not-print"}', encoding="utf-8")
        denied = subprocess.run(command, capture_output=True, encoding="utf-8")
        self.assertEqual(denied.returncode, 1)
        self.assertNotIn("secret-must-not-print", denied.stdout + denied.stderr)

    def test_real_saved_legacy_client_and_minimum_version_are_preserved(self):
        from authorization_platform.catalog.models import SoftwareProfile
        profile = SoftwareProfile.objects.get(software_id=self.identity)
        profile.client_id = "vendor/client"
        profile.minimum_client_version = "1.2"
        profile.save(update_fields=("client_id", "minimum_client_version"))
        exported = self.client.get(f"/api/v1/manage/catalog/software/{self.identity}/integration-config/")
        self.assertEqual(exported.status_code, 200)
        self.source.write_bytes(exported.content)
        output = Path(intake.prepare(self.source, self.template, write=True)["output"])
        binding = json.loads((output / "platform-binding.json").read_text(encoding="utf-8"))
        self.assertEqual(binding["software"]["client_id"], "vendor/client")
        self.assertEqual(binding["software"]["minimum_client_version"], "1.2")
        self.assertIsNone(binding["current_client_version"])

    def test_dotted_identity_is_routable_without_rewriting(self):
        for field in ("software_id", "profile_id"):
            with self.subTest(field=field):
                data = deepcopy(self.config)
                data["software"][field] = "tool.v1"
                software = data["software"]
                data["api"]["releases"] = f'/api/v1/public/software/{software["software_id"]}/profiles/{software["profile_id"]}/releases/'
                self.save(data)
                result = intake.prepare(self.source, self.template)
                self.assertEqual(result["status"], "PARTIAL")
                self.assertFalse(any("UPDATE_ROUTE_ID_UNSUPPORTED" in item for item in result["warnings"]))
                self.assertEqual(resolve(data["api"]["releases"]).view_name, "releases:public_registry")
                parsed, _ = intake.load_config(self.source)
                self.assertEqual(parsed["software"][field], "tool.v1")


    def test_copied_tool_ignores_software_protocol_directory(self):
        import shutil
        project = self.folder / 'existing-software'
        package = project / '软件授权接入包'
        tool = package / '工具/prepare-config.py'
        tool.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / '软件授权接入包/工具/prepare-config.py', tool)
        contracts = package / '平台公开资料/protocol'
        shutil.copytree(ROOT / 'protocol', contracts)
        (project / 'protocol').mkdir()
        (project / 'protocol/business.json').write_text('{}')
        args = [sys.executable,str(tool),str(self.source),'--template-root',str(self.template)]
        result = subprocess.run(args,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        contracts.rename(package / 'retired-contracts')
        for name in intake.CONTRACTS:
            shutil.copyfile(ROOT / 'protocol' / name,project / 'protocol' / name)
        refused = subprocess.run(args,capture_output=True,text=True)
        self.assertNotEqual(refused.returncode,0)


class PublicWireIndexTests(TestCase):
    """Send index-shaped requests through the real local HTTP handlers and verify signatures."""

    def setUp(self):
        from tests.test_launch_ticket import LaunchTicketTests
        cache.clear()
        # Reuse only isolated business fixture construction, not the protocol request builder.
        self.reference = LaunchTicketTests("test_issue_happy_path_and_signature_verifies_with_platform_pubkey")
        self.reference.setUp()
        self.index = json.loads((ROOT / "软件授权接入包/平台公开资料/接口字段索引.json").read_text(encoding="utf-8"))
        self.device_key = Ed25519PrivateKey.generate()
        self.device_public_key = base64.urlsafe_b64encode(self.device_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode().rstrip("=")

    def send(self, endpoint, number, **extra):
        ref = self.reference
        payload = {
            "request_id": f"index-{number}", "idempotency_key": f"index-{number}",
            "software_id": ref.software.software_id, "profile_id": ref.profile.profile_id,
            "client_id": ref.profile.client_id, "contract_version": "authorization.v1",
            "target": ref.profile.target, "arch": ref.profile.arch, "channel": ref.profile.channel,
            "installation_id": "wire-hardware-identity", "device_public_key": self.device_public_key,
            "client_version": "1.0.0", "nonce": f"fresh-index-nonce-{number}", **extra,
        }
        proof_spec = self.index["device_proof"]
        message = {key: "" for key in proof_spec["message"]["object_fields"]}
        message.update({key: payload[key] for key in message if key in payload})
        message["domain"] = proof_spec["domain"]
        message["action"] = self.index["endpoints"][endpoint]["proof_action"]
        # Proof fields are strings/ASCII keys: sorted compact JSON is equivalent here.
        proof_bytes = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload["device_proof"] = base64.urlsafe_b64encode(self.device_key.sign(proof_bytes)).decode().rstrip("=")
        self.assertEqual(set(payload) - {"known_authorization_revision", "known_config_version"}, set(self.index["endpoints"][endpoint]["request_required_for_new_client"]))
        response = Client().post(self.index["endpoints"][endpoint]["path"], json.dumps(payload), content_type="application/json", HTTP_X_REQUEST_ID=payload["request_id"], HTTP_IDEMPOTENCY_KEY=payload["idempotency_key"], REMOTE_ADDR="192.0.2.199")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_five_post_actions_exact_shapes_proof_signatures_and_new_heartbeat_metadata(self):
        from authorization_platform.core.time import FixedClock
        from authorization_platform.licensing.authorization import verify_authorization_response, authorization_signing_public_key
        from tests.test_launch_ticket import _verify_ticket_signature
        with patch("authorization_platform.licensing.authorization.SystemClock", return_value=FixedClock(self.reference.now)):
            active = self.send("activate", 1, license_key=self.reference.license_key)
            self.assertTrue(set(self.index["response_contracts"]["authorization"]["required"]) <= set(active))
            trusted_keys = {active["integrity"]["key_id"]: authorization_signing_public_key()}
            verify_authorization_response(active, trusted_keys)
            verified = self.send("verify", 2, authorization_id=active["authorization_id"], known_authorization_revision=active["authorization_revision"], known_config_version=active["config_version"])
            self.assertEqual(verified["decision"], "not_modified")
            self.assertNotEqual(verified["request_id"], active["request_id"])
            self.assertEqual(verified["authorization_revision"], active["authorization_revision"])
            verify_authorization_response(verified, trusted_keys)
            issued = self.send("launch_ticket", 3, authorization_id=active["authorization_id"])
            _verify_ticket_signature(issued)
            self.assertLessEqual(issued["ticket"]["expires_at"], active["expires_at"])
            consumed = self.send("consume_launch_ticket", 4, authorization_id=active["authorization_id"], ticket_id=issued["ticket"]["ticket_id"])
            self.assertEqual(set(consumed), set(self.index["response_contracts"]["consumed"]["required"]))
            self.assertNotIn("integrity", consumed)
            unbound = self.send("deactivate", 5, authorization_id=active["authorization_id"])
            self.assertEqual(unbound["decision"], "unbound")
            verify_authorization_response(unbound, trusted_keys)

    def test_update_index_response_null_external_and_wrong_version_parameter(self):
        ref = self.reference
        endpoint = self.index["endpoints"]["releases"]
        path = endpoint["path"].format(software_id=ref.software.software_id, profile_id=ref.profile.profile_id)
        query = {"client_id": ref.profile.client_id, "target": ref.profile.target, "arch": ref.profile.arch, "channel": ref.profile.channel, "version": "1.0.0"}
        empty = Client().get(path, query)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(set(empty.json()), set(self.index["response_contracts"]["releases"]["required"]))
        self.assertIsNone(empty.json()["release"])
        self.client.force_login(ref.admin)
        published = self.client.post("/api/v1/manage/releases/external/", json.dumps({"software_id": ref.software.software_id, "profile_id": ref.profile.profile_id, "version": "1.2.4", "external_download_url": "https://example.test/wire-download", "notes": "本地字段核对"}), content_type="application/json", HTTP_IDEMPOTENCY_KEY="wire-release")
        self.assertEqual(published.status_code, 201, published.content)
        updated = Client().get(path, query).json()
        self.assertTrue(updated["has_update"])
        self.assertEqual(updated["release"]["version"], "1.2.4")
        self.assertEqual(updated["release"]["update_open_url"], "https://example.test/wire-download")
        self.assertNotIn("update_open_url", updated)
        self.assertTrue(set(updated["release"]) <= set(self.index["response_contracts"]["releases"]["release_fields"]) | {"update_open_url", "download_url"})
        query["client_version"] = query.pop("version")
        missing_version = Client().get(path, query)
        self.assertEqual(missing_version.status_code,400)
        self.assertEqual(missing_version.json()['error']['code'],'INVALID_VERSION')
