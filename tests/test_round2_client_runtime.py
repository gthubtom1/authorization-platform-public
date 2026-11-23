"""Round 2 real executable/socket/WebView/core regressions, public fixture only.

Set FINAL_CLIENT_EXE to this checkout's source build. No platform or DB needed.
Evidence is retained under ROUND2_RUNTIME_EVIDENCE_DIR (default TEMP below).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from django.conf import settings
from django.test import SimpleTestCase
from authorization_platform.licensing.authorization import validate_authorization_response_shape

ROOT = Path(settings.BASE_DIR)
TEMPLATE = ROOT / "软件授权接入包/授权启动器模板"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([42]) * 32)
IDENTITY = dict(software_id="software-a", profile_id="stable", client_id="software-a-windows", target="windows", arch="x64", channel="stable")
BASE = 1800000000


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def jcs(value):
    # Deliberately bounded fixture: ASCII member names and integral values.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def signed(value):
    value["integrity"] = dict(algorithm="ed25519", key_id="round2-test", canonicalization="JCS-RFC8785")
    if value["decision"] == "issued":
        value["integrity"].update(origin="authorization-platform", audience="software-a-core")
    value["integrity"]["signature"] = b64(KEY.sign(jcs(value)))
    return value


class Round2ClientRuntimeTests(SimpleTestCase):
    def setUp(self):
        executable = os.environ.get("FINAL_CLIENT_EXE", "")
        self.assertTrue(Path(executable).is_file(), "FINAL_CLIENT_EXE must be this checkout's built launcher")
        self.exe = Path(executable).resolve()
        self.out = Path(os.environ.get("ROUND2_RUNTIME_EVIDENCE_DIR", ROOT / "TEMP/writer2runtime/evidence")) / self._testMethodName
        self.out.mkdir(parents=True, exist_ok=True)
        self.mode = "normal"
        self.interval, self.expiry, self.issue_time, self.consume_time = 60, BASE + 3600, None, None
        self.verify_delay, self.consume_delay = 0, 0
        self.activation_phase, self.clock_origin, self.ordinary_time = None, None, None
        self.saved_responses = {}
        self.started = time.monotonic()
        self.started_wall = time.time()
        self.calls, self.observations, self.errors, self.children = [], [], [], []
        self.schema = json.loads((TEMPLATE / "src/current_contracts/authorization.v1.schema.json").read_text())
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    action = self.path.rsplit("/", 1)[-1]
                    action = {"consume": "ticket-consume"}.get(action, action)
                    proof = dict(domain="authorization-platform.device-proof.v1", action=action, authorization_id="")
                    proof.update({k: req[k] for k in ["request_id", "authorization_id", *IDENTITY, "contract_version", "installation_id", "device_public_key", "nonce"] if k in req})
                    Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(req["device_public_key"] + "==")).verify(base64.urlsafe_b64decode(req["device_proof"] + "=="), jcs(proof))
                    assert self.headers["X-Request-Id"] == req["request_id"]
                    assert self.headers["Idempotency-Key"] == req["idempotency_key"]
                    entry = dict(action=action, at=time.monotonic() - owner.started, body=req, proof_valid=True)
                    owner.calls.append(entry)
                    mode = owner.mode
                    if action == "launch-ticket" and mode == "ticket-offline":
                        self.close_connection = True
                        return
                    if action == "launch-ticket" and mode == "ticket-429":
                        self.send_response(429); self.send_header("Retry-After", "120"); self.send_header("Content-Length", "0"); self.end_headers()
                        return
                    if action == "verify":
                        if mode == "offline":
                            self.close_connection = True
                            return
                        if mode == "timeout":
                            time.sleep(4)
                            self.close_connection = True
                            return
                        if mode in ("429", "500"):
                            self.send_response(int(mode)); self.send_header("Retry-After", "120"); self.send_header("Content-Length", "0"); self.end_headers()
                            return
                        time.sleep(owner.verify_delay)
                    if action == "ticket-consume":
                        if mode == "consume-429":
                            self.send_response(429); self.send_header("Retry-After", "120"); self.send_header("Content-Length", "0"); self.end_headers()
                            return
                        time.sleep(owner.consume_delay)
                    # Anchor an explicit server-second phase at activation so
                    # core tests cover the rounding boundary independent of
                    # WebView startup speed. The client remains the real EXE.
                    if action == "activate" and owner.activation_phase is not None:
                        owner.clock_origin = time.monotonic() - owner.activation_phase
                        entry["server_second_phase"] = owner.activation_phase
                    origin = owner.clock_origin if owner.clock_origin is not None else owner.started
                    now = BASE + int(time.monotonic() - origin)
                    status = 200
                    if action == "activate" and req["license_key"] == "WRONG-LOCAL-CARD":
                        status = 403
                        value = dict(error=dict(code="LICENSE_NOT_FOUND", request_id=req["request_id"], message="Local fixture invalid card", retryable=False))
                    elif action == "launch-ticket":
                        now = owner.issue_time if owner.issue_time is not None else now
                        value = signed(dict(schema_version="authorization.v1", contract_version="authorization.v1", request_id=req["request_id"], **IDENTITY,
                            authorization_id="round2-auth", authorization_revision=1, decision="issued", server_time=now,
                            ticket=dict(ticket_id="38adef26-5af6-411d-964f-665622415b39", software_id="software-a", profile_id="stable", client_id="software-a-windows", installation_id="round2-install",
                                issued_at=now, not_before=now, expires_at=min(owner.expiry, now + 180), audience="software-a-core")))
                        if mode == "bad-issued":
                            value["ticket"]["installation_id"] = "wrong-installation"
                            value = signed(value)
                        elif mode == "bad-signature":
                            value["server_time"] += 1
                    elif action == "ticket-consume":
                        now = owner.consume_time if owner.consume_time is not None else now
                        value = dict(schema_version="authorization.v1", contract_version="authorization.v1", request_id=req["request_id"], software_id="software-a", profile_id="stable", authorization_id="round2-auth", decision="consumed", server_time=now,
                            ticket_id="wrong-ticket" if mode == "bad-consumed" else req["ticket_id"])
                    else:
                        if owner.ordinary_time is not None:
                            now = owner.ordinary_time
                        value = json.loads((ROOT / "tests/fixtures/authorization_v1/active.json").read_text())
                        value.update(request_id=req["request_id"], authorization_id="round2-auth", authorization_revision=1, issued_at=BASE, server_time=now, expires_at=owner.expiry,
                            grace_until=owner.expiry, cache_until=min(owner.expiry, now + owner.interval), next_verify_at=min(owner.expiry, now + owner.interval))
                        value["device_scope"]["installation_id"] = "round2-install"
                        if action == "verify":
                            value["decision"] = "revoked" if mode == "revoked" else "expired" if now >= owner.expiry else "not_modified"
                        value = signed(value)
                        if action == "verify" and mode == "replay-success":
                            value = owner.saved_responses[req["request_id"]]
                        validate_authorization_response_shape(value)
                    entry.update(response=value, status=status, replied_at=time.monotonic() - owner.started)
                    if action == "verify" and mode == "lost-success":
                        owner.saved_responses[req["request_id"]] = value
                        entry["response_lost"] = True
                        self.close_connection = True
                        return
                    raw = json.dumps(value).encode()
                    self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as error:
                    owner.errors.append(repr(error))
                    self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.cleanup)
        binding = self.out / "binding"
        binding.mkdir(exist_ok=True)
        source = dict(schema="software-bind.v2", platform=dict(base_url=f"http://127.0.0.1:{self.server.server_port}", contract_version="authorization.v1", algorithm="ed25519", canonicalization="JCS-RFC8785", encoding="base64url-no-padding",
            authorization_public_key_id="round2-test", authorization_public_key=b64(KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))),
            software=dict(**IDENTITY, name="Runtime acceptance", minimum_client_version="1.0.0", capabilities=[]),
            api={name: "/api/v1/public/licenses/" + suffix for name, suffix in [("activate", "activate"), ("verify", "verify"), ("deactivate", "deactivate"), ("launch_ticket", "launch-ticket"), ("consume_launch_ticket", "launch-ticket/consume")]},
            authorization_a=dict(copy_from_master=True, local_contract_version="authorization-a-core.v1", local_bind_policy="127.0.0.1-only"), core=dict(talks_to_platform=False, talks_to_local_a_only=True), response_contracts={},
            contracts={name: json.loads((TEMPLATE / "src/current_contracts" / name).read_text()) for name in ["authorization.v1.schema.json", "authorization-a-core.v1.schema.json", "device-proof.v1.json"]})
        raw = json.dumps(source).encode()
        (binding / "source-integration.json").write_bytes(raw)
        prepared = {k: source[k] for k in ["platform", "software", "api", "authorization_a", "core", "response_contracts"]}
        prepared.update(schema="authorization-a-platform-binding.v1", environment="local", source_sha256=hashlib.sha256(raw).hexdigest())
        (binding / "platform-binding.json").write_text(json.dumps(prepared))
        for name, value in source["contracts"].items():
            (binding / name).write_text(json.dumps(value))
        loaders = list(self.exe.parent.glob("build/webview2-com-sys-*/out/x64/WebView2Loader.dll"))
        self.env = {**os.environ, "PATH": os.pathsep.join([*(str(p.parent) for p in loaders), os.environ["PATH"]])}
        self.argv = [str(self.exe), "--binding", str(binding), "--version", "1.0.0", "--installation", "round2-install", "--device-key", str(self.out / "device.dpapi")]

    def cleanup(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=8)
        self.server.shutdown(); self.server.server_close()
        (self.out / "evidence.json").write_text(json.dumps(dict(executable=str(self.exe), sha256=hashlib.sha256(self.exe.read_bytes()).hexdigest(), calls=self.calls, observations=self.observations, fixture_errors=self.errors), ensure_ascii=False, indent=2), encoding="utf-8")
        self.assertEqual(self.errors, [])

    def start(self):
        self.process = subprocess.Popen([*self.argv, "--acceptance-stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", env=self.env, creationflags=subprocess.CREATE_NO_WINDOW)
        self.children.append(self.process)

    def command(self, **command):
        self.process.stdin.write(json.dumps(command) + "\n"); self.process.stdin.flush()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(1) as pool:
            reply = pool.submit(self.process.stdout.readline)
            try:
                line = reply.result(timeout=12)
            except TimeoutError:
                self.process.kill()
                self.fail("Real launcher control channel timed out")
        self.assertTrue(line, "Launcher exited before reply")
        value = json.loads(line)
        self.observations.append(dict(command=command, result=value))
        return value

    def activate(self):
        value = self.command(type="activate", credential="VALID-LOCAL-CARD")
        self.assertTrue(value["ok"], value)
        return value

    def local(self):
        value = self.command(op="local")
        document = json.loads(json.dumps(value["local"]))
        signature = document["integrity"].pop("signature")
        Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(value["public_key"] + "==")).verify(base64.urlsafe_b64decode(signature + "=="), jcs(document))
        return value["local"]

    def local_socket(self, opened=None):
        from urllib.parse import urlsplit
        if opened is None:
            endpoint = self.command(op="local_endpoint")
            address = urlsplit(endpoint["address"])
            conn = http.client.HTTPConnection(address.hostname, address.port, timeout=4)
            body = {k: IDENTITY[k] for k in ("software_id", "profile_id", "client_id")}
            body.update(client_version="1.0.0", nonce="round2-local-unique-session-nonce")
            conn.request("POST", "/local/v1/session/open", json.dumps(body), {"Authorization": "Bearer " + endpoint["bootstrap"]})
            response = conn.getresponse(); self.assertEqual(response.status, 200)
            result = json.loads(response.read()); conn.close()
            return endpoint, result["session_token"]
        endpoint, token = opened
        address = urlsplit(endpoint["address"])
        conn = http.client.HTTPConnection(address.hostname, address.port, timeout=4)
        conn.request("GET", "/local/v1/session/state", headers={"Authorization": "Bearer " + token})
        response = conn.getresponse(); self.assertEqual(response.status, 200)
        value = json.loads(response.read()); conn.close()
        document = json.loads(json.dumps(value)); signature = document["integrity"].pop("signature")
        Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(endpoint["public_key"] + "==")).verify(base64.urlsafe_b64decode(signature + "=="), jcs(document))
        self.observations.append(dict(local_socket=value, signature_valid=True))
        return value

    def webview(self, script, core=None, timeout=25):
        path = self.out / "probe.js"; path.write_text(script, encoding="utf-8")
        receipt = self.out / "receipt.json"
        receipt.unlink(missing_ok=True)
        args = ["--acceptance-webview", str(path)] if core is None else ["--core", str(core), "--acceptance-core", str(path)]
        child = subprocess.Popen([*self.argv, *args, "--receipt", str(receipt)], env=self.env, creationflags=subprocess.CREATE_NO_WINDOW)
        self.children.append(child)
        child.wait(timeout=timeout)
        self.assertEqual(child.returncode, 0, receipt.read_text(encoding="utf-8") if receipt.exists() else "no receipt")
        self.assertTrue(receipt.exists(), "Missing real WebView receipt")
        return json.loads(receipt.read_text(encoding="utf-8"))

    def test_wrong_card_page_can_explicitly_activate_corrected_card(self):
        observed = self.webview("""(() => {
          const submit=()=>document.getElementById('activationForm').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
          const card=document.getElementById('credential'); card.value='WRONG-LOCAL-CARD';submit();
          let rejected=null;
          const poll=setInterval(()=>{
            const state=document.querySelector('.shell').dataset.state;
            if(state==='unavailable' && !rejected){
              rejected={disabled:document.getElementById('activateButton').disabled,message:document.getElementById('feedbackMessage').textContent};
              card.value='VALID-LOCAL-CARD';submit();
              setTimeout(()=>window.ipc.postMessage(JSON.stringify({type:'acceptance_result',dom:{rejected,state:document.querySelector('.shell').dataset.state}})),1200);
              clearInterval(poll);
            }
          },30);
        })();""")
        self.assertFalse(observed["dom"]["rejected"]["disabled"], observed)
        self.assertIn("LICENSE_NOT_FOUND", observed["dom"]["rejected"]["message"])
        self.assertEqual(observed["dom"]["state"], "active", observed)
        self.assertEqual([v["body"]["license_key"] for v in self.calls if v["action"] == "activate"], ["WRONG-LOCAL-CARD", "VALID-LOCAL-CARD"])

    def test_wrong_card_host_does_not_allow_retry_or_revive_terminal_session(self):
        self.start()
        wrong = self.command(type="activate", credential="WRONG-LOCAL-CARD")
        self.assertFalse(wrong["ok"])
        self.assertEqual(wrong["render"]["snapshot"]["state"]["intents"], ["activate"])
        count = len(self.calls)
        self.assertFalse(self.command(type="intent", name="retry")["ok"])
        self.assertEqual(len(self.calls), count)
        self.activate(); self.mode = "revoked"
        self.assertTrue(self.command(op="verify")["ok"])
        self.mode = "normal"
        self.assertFalse(self.command(type="intent", name="retry")["ok"])
        self.assertNotEqual(self.local()["decision"], "active")

    def test_consumed_time_advances_signed_local_envelope_and_exclusive_expiry(self):
        self.interval = 60; self.expiry = BASE + 60
        self.issue_time = self.consume_time = BASE + 59
        self.start(); self.activate()
        opened = self.local_socket()
        self.assertTrue(self.command(type="intent", name="request_launch")["ok"])
        time.sleep(1.3)
        local = self.local_socket(opened)
        self.assertGreaterEqual(local["server_time"], self.expiry, local)
        self.assertEqual(local["decision"], "blocked", local)
        self.assertFalse(self.command(op="snapshot")["timing"]["usable"])

    def test_consumed_at_exclusive_expiry_cannot_grant_or_leave_active_envelope(self):
        self.expiry = BASE + 60; self.issue_time = BASE + 59; self.consume_time = BASE + 60
        self.start(); self.activate()
        rejected = self.command(type="intent", name="request_launch")
        self.assertFalse(rejected["ok"]); self.assertIsNone(rejected["permit"])
        self.assertEqual(self.local()["decision"], "blocked")

    def test_issued_alone_advances_time_even_if_consume_is_rate_limited(self):
        self.issue_time = BASE + 59; self.expiry = BASE + 60; self.mode = "consume-429"
        self.start(); self.activate()
        self.assertFalse(self.command(type="intent", name="request_launch")["ok"])
        self.assertGreaterEqual(self.local()["server_time"], BASE + 59)
        time.sleep(1.3)
        self.assertEqual(self.local()["decision"], "blocked")

    def test_consumed_newer_than_issued_and_old_verify_cannot_reset_highwater(self):
        self.issue_time = BASE + 20; self.consume_time = BASE + 50
        self.start(); self.activate()
        self.assertTrue(self.command(type="intent", name="request_launch")["ok"])
        self.assertGreaterEqual(self.local()["server_time"], BASE + 50)
        self.assertFalse(self.command(op="verify")["ok"])
        self.assertGreaterEqual(self.local()["server_time"], BASE + 50)

    def test_successful_ticket_cannot_extend_original_online_success_window(self):
        self.interval = 4; self.issue_time = self.consume_time = BASE + 3
        self.start(); self.activate()
        self.assertTrue(self.command(type="intent", name="request_launch")["ok"])
        self.assertGreaterEqual(self.local()["server_time"], BASE + 3)
        time.sleep(1.3)
        self.assertEqual(self.local()["decision"], "blocked")

    def test_invalid_tickets_do_not_advance_time_or_grant_permit(self):
        self.issue_time = BASE + 59
        self.start()
        for mode in ("bad-issued", "bad-signature"):
            with self.subTest(mode=mode):
                self.activate(); self.mode = mode
                rejected = self.command(type="intent", name="request_launch")
                self.assertFalse(rejected["ok"]); self.assertIsNone(rejected["permit"])
                self.assertLess(self.local()["server_time"], BASE + 10)
                self.mode = "normal"
        self.issue_time = None; self.consume_time = BASE + 59; self.mode = "bad-consumed"
        self.activate()
        rejected = self.command(type="intent", name="request_launch")
        self.assertFalse(rejected["ok"]); self.assertIsNone(rejected["permit"])
        self.assertLess(self.local()["server_time"], BASE + 10)

    def test_ticket_offline_then_429_retries_original_request_without_time_or_window_extension(self):
        self.interval = 4; self.issue_time = BASE + 59
        self.start(); self.activate(); self.mode = "ticket-offline"
        rejected = self.command(type="intent", name="request_launch")
        self.assertFalse(rejected["ok"]); self.assertIsNone(rejected["permit"])
        original = self.calls[-1]["body"]
        self.mode = "ticket-429"
        rejected = self.command(type="intent", name="retry")
        self.assertFalse(rejected["ok"]); self.assertIsNone(rejected["permit"])
        self.assertEqual(self.calls[-1]["body"], original)
        self.assertLess(self.local()["server_time"], BASE + 10)
        time.sleep(4.1)
        self.assertEqual(self.local()["decision"], "blocked")

    def core_probe(self, run_seconds=12, interval=4):
        self.interval = interval
        source = self.out / "ProbeCore.cs"; core = self.out / "ProbeCore.exe"
        source.write_text('using System;using System.IO;using System.Threading;class ProbeCore{static void Main(){var p=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"core-alive.log");for(int i=0;i<'+str(run_seconds*10)+';i++){File.AppendAllText(p,DateTime.UtcNow.ToString("O")+" "+System.Diagnostics.Process.GetCurrentProcess().Id+Environment.NewLine);Thread.Sleep(100);}File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"core-completed"),"completed");}}')
        for name in ("core-alive.log", "core-completed"):
            (self.out / name).unlink(missing_ok=True)
        subprocess.run(["C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe", "/nologo", "/target:winexe", f"/out:{core}", str(source)], check=True, capture_output=True)
        self.webview("""(() => {
          document.getElementById('credential').value='VALID-LOCAL-CARD';
          document.getElementById('activationForm').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
          setTimeout(()=>window.ipc.postMessage(JSON.stringify({type:'acceptance_result',dom:{state:document.querySelector('.shell').dataset.state}})),WAIT);
        })();""".replace("WAIT", str((run_seconds + 2) * 1000)), core=core, timeout=run_seconds + 15)
        lines = (self.out / "core-alive.log").read_text().splitlines()
        from datetime import datetime
        first = datetime.fromisoformat(lines[0].split()[0]); last = datetime.fromisoformat(lines[-1].split()[0])
        elapsed = (last - first).total_seconds()
        # Observe OS process exit as well as logs. Only this run's owned core
        # PID is eligible for cleanup on a failed assertion.
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        handle = kernel.OpenProcess(0x1001, False, int(lines[0].split()[1]))
        running = False
        if handle:
            code = ctypes.c_ulong()
            self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(code)))
            running = code.value == 259
            if running:
                kernel.TerminateProcess(handle, 1)
            kernel.CloseHandle(handle)
        activation = next(v for v in self.calls if v["action"] == "activate")
        original_deadline = activation["at"] + min(activation["response"]["expires_at"], activation["response"]["next_verify_at"]) - activation["response"]["server_time"]
        self.observations.append(dict(core_pid=lines[0].split()[1], ticks=len(lines), alive_seconds=elapsed, completed=(self.out / "core-completed").exists(), os_process_stopped=not running,
            original_deadline=original_deadline, last_tick_at=last.timestamp() - self.started_wall))
        self.assertFalse(running, self.observations)
        return elapsed

    def test_core_survives_two_zero_grace_heartbeats_with_800ms_success(self):
        self.verify_delay = .8
        elapsed = self.core_probe()
        self.assertTrue((self.out / "core-completed").exists(), self.observations)
        self.assertGreater(elapsed, 11)
        self.assertGreaterEqual(len([v for v in self.calls if v["action"] == "verify"]), 2)

    def test_core_survives_one_second_policy_with_100ms_success(self):
        self.verify_delay = .1
        elapsed = self.core_probe(4, interval=1)
        self.assertTrue((self.out / "core-completed").exists(), self.observations)
        self.assertGreater(elapsed, 3.5)
        self.assertGreaterEqual(len([v for v in self.calls if v["action"] == "verify"]), 3)

    def test_same_second_fresh_verify_replaces_budget_without_resetting_card_time(self):
        self.interval = 1; self.ordinary_time = BASE
        self.start(); self.activate()
        opened = self.local_socket()
        activation_at = self.calls[-1]["at"]
        for _ in range(3):
            time.sleep(.24)
            self.assertTrue(self.command(op="verify")["ok"])
        verified = [v for v in self.calls if v["action"] == "verify"]
        self.assertEqual(len({v["body"]["request_id"] for v in verified}), 3)
        self.assertEqual(len({v["body"]["nonce"] for v in verified}), 3)
        self.assertEqual({v["response"]["server_time"] for v in verified}, {BASE})
        # Past the original success deadline, within the newest fresh request's
        # budget. A local socket envelope and page snapshot must agree.
        time.sleep(max(0, self.started + activation_at + 1.12 - time.monotonic()))
        state = self.command(op="snapshot")
        self.assertTrue(state["timing"]["usable"], state)
        local = self.local_socket(opened)
        self.assertEqual(local["decision"], "active", local)
        self.assertGreaterEqual(local["server_time"], BASE + 1)
        self.assertEqual(state["timing"]["response"]["server_time"], BASE)
        self.assertEqual(state["timing"]["response"]["decision"], "not_modified")
        for call in [v for v in self.calls if "response" in v]:
            document = json.loads(json.dumps(call["response"]))
            signature = document["integrity"].pop("signature")
            KEY.public_key().verify(base64.urlsafe_b64decode(signature + "=="), jcs(document))
        time.sleep(1.05)
        self.assertFalse(self.command(op="snapshot")["timing"]["usable"])
        self.assertEqual(self.local_socket(opened)["decision"], "blocked")

    def test_delayed_ordinary_success_cannot_buy_window_at_receive_time(self):
        self.interval = 1; self.ordinary_time = BASE
        self.start(); self.activate(); opened = self.local_socket(); self.verify_delay = 1.15
        self.command(op="verify")
        self.assertFalse(self.command(op="snapshot")["timing"]["usable"])
        self.assertEqual(self.local_socket(opened)["decision"], "blocked")
        self.assertFalse(self.command(type="intent", name="request_launch")["ok"])

    def test_lost_ordinary_success_replay_keeps_first_request_anchor(self):
        self.interval = 1; self.ordinary_time = BASE
        self.start(); self.activate(); self.mode = "lost-success"
        self.assertFalse(self.command(op="verify")["ok"])
        original = self.calls[-1]
        time.sleep(1.15); self.mode = "replay-success"
        self.command(type="intent", name="retry")
        replay = self.calls[-1]
        self.assertEqual(replay["body"], original["body"])
        self.assertEqual(replay["response"], original["response"])
        self.assertFalse(self.command(op="snapshot")["timing"]["usable"])
        self.assertEqual(self.local()["decision"], "blocked")
        self.assertFalse(self.command(type="intent", name="request_launch")["ok"])

    def test_failures_after_fresh_same_second_success_do_not_extend_its_budget(self):
        self.interval = 1; self.ordinary_time = BASE
        for mode in ("offline", "429", "timeout", "500"):
            with self.subTest(mode=mode):
                self.mode = "normal"
                self.start(); self.activate()
                opened = self.local_socket()
                for _ in range(2):
                    time.sleep(.24)
                    self.assertTrue(self.command(op="verify")["ok"])
                success = self.calls[-1]
                self.mode = mode
                self.assertFalse(self.command(op="verify")["ok"])
                time.sleep(max(0, self.started + success["at"] + 1.12 - time.monotonic()))
                state = self.command(op="snapshot")
                self.assertFalse(state["timing"]["usable"], state)
                self.assertEqual(state["render"]["snapshot"]["state"]["authorization"], "unavailable")
                self.assertEqual(self.local_socket(opened)["decision"], "blocked")
                self.assertFalse(self.command(type="intent", name="request_launch")["ok"])

    def test_fresh_same_second_verifies_still_stop_at_exclusive_card_expiry(self):
        self.interval = 1; self.ordinary_time = BASE; self.expiry = BASE + 2
        self.start(); self.activate()
        for _ in range(4):
            time.sleep(.3)
            self.assertTrue(self.command(op="verify")["ok"])
        time.sleep(.9)
        state = self.command(op="snapshot")
        self.assertFalse(state["timing"]["usable"], state)
        self.assertGreaterEqual(state["timing"]["trusted_time"], self.expiry)
        self.assertEqual(self.local()["decision"], "blocked")

    def test_equal_ticket_time_preserves_fresh_budget_without_replacing_it(self):
        self.interval = 1; self.ordinary_time = BASE
        self.issue_time = self.consume_time = BASE
        self.start(); self.activate()
        activation_at = self.calls[-1]["at"]
        for _ in range(2):
            time.sleep(.24)
            self.assertTrue(self.command(op="verify")["ok"])
        success_at = self.calls[-1]["at"]
        time.sleep(.2)
        issued = self.command(type="intent", name="request_launch")
        self.assertTrue(issued["ok"], issued)
        self.assertIsNotNone(issued["permit"])
        time.sleep(max(0, self.started + activation_at + 1.12 - time.monotonic()))
        self.assertTrue(self.command(op="snapshot")["timing"]["usable"])
        time.sleep(max(0, self.started + success_at + 1.12 - time.monotonic()))
        self.assertFalse(self.command(op="snapshot")["timing"]["usable"])
        self.assertEqual(self.local()["decision"], "blocked")

    def test_core_seven_seconds_one_second_policy_phase_early(self):
        self.activation_phase = .05; self.verify_delay = .1
        elapsed = self.core_probe(7, interval=1)
        self.assertTrue((self.out / "core-completed").exists(), self.observations)
        self.assertGreater(elapsed, 6.5)
        self.assert_fresh_same_second_core_flow()

    def test_core_seven_seconds_one_second_policy_phase_late(self):
        self.activation_phase = .7; self.verify_delay = .1
        elapsed = self.core_probe(7, interval=1)
        self.assertTrue((self.out / "core-completed").exists(), self.observations)
        self.assertGreater(elapsed, 6.5)
        self.assert_fresh_same_second_core_flow()

    def assert_fresh_same_second_core_flow(self):
        verifies = [v for v in self.calls if v["action"] == "verify"]
        self.assertGreaterEqual(len(verifies), 8)
        self.assertEqual(len({v["body"]["request_id"] for v in verifies}), len(verifies))
        self.assertEqual(len({v["body"]["nonce"] for v in verifies}), len(verifies))
        last_tick_at = self.observations[-1]["last_tick_at"]
        self.assertTrue(any(a["response"]["server_time"] == b["response"]["server_time"] and b["replied_at"] < last_tick_at for a, b in zip(verifies, verifies[1:])), verifies)
        for call in verifies:
            self.assertEqual(call["status"], 200)
            document = json.loads(json.dumps(call["response"]))
            signature = document["integrity"].pop("signature")
            KEY.public_key().verify(base64.urlsafe_b64decode(signature + "=="), jcs(document))

    def test_core_offline_stops_at_original_success_deadline(self):
        self.mode = "offline"
        elapsed = self.core_probe(6)
        self.assertGreater(elapsed, 3); self.assertLess(elapsed, 4.8)
        self.assertAlmostEqual(self.observations[-1]["last_tick_at"], self.observations[-1]["original_deadline"], delta=.5)
        self.assertFalse((self.out / "core-completed").exists())

    def test_core_429_stops_at_original_success_deadline(self):
        self.mode = "429"
        elapsed = self.core_probe(6)
        self.assertGreater(elapsed, 3); self.assertLess(elapsed, 4.8)
        self.assertAlmostEqual(self.observations[-1]["last_tick_at"], self.observations[-1]["original_deadline"], delta=.5)
        self.assertFalse((self.out / "core-completed").exists())

    def test_core_timeout_stops_while_network_still_holds_host_lock(self):
        self.mode = "timeout"
        elapsed = self.core_probe(6)
        self.assertGreater(elapsed, 3); self.assertLess(elapsed, 4.8)
        self.assertAlmostEqual(self.observations[-1]["last_tick_at"], self.observations[-1]["original_deadline"], delta=.5)
        self.assertFalse((self.out / "core-completed").exists())

    def test_core_short_card_stops_at_exclusive_expiry(self):
        self.expiry = BASE + 3
        elapsed = self.core_probe(5)
        self.assertGreater(elapsed, 2); self.assertLess(elapsed, 3.7)
        self.assertAlmostEqual(self.observations[-1]["last_tick_at"], self.observations[-1]["original_deadline"], delta=.5)
        self.assertFalse((self.out / "core-completed").exists())

    def test_core_ticket_time_shrinks_watch_deadline_while_verify_is_blocked(self):
        self.expiry = BASE + 60; self.issue_time = BASE + 50; self.consume_time = BASE + 55
        self.mode = "timeout"
        elapsed = self.core_probe(7, interval=60)
        self.assertGreater(elapsed, 4)
        self.assertLess(elapsed, 5.7)
        self.assertFalse((self.out / "core-completed").exists())
