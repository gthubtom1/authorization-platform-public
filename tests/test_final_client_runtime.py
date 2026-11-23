"""Socket-to-Django acceptance for the executable's real DesktopHost path.

Build a-template-webview-ui with GNU, then set FINAL_CLIENT_EXE to that executable.
No Python Client substitutes for the Rust client's authorization HTTP calls.
"""
from __future__ import annotations

import importlib.util
import json
import os
import base64
import http.client
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, SimpleTestCase, LiveServerTestCase, override_settings
from django.core.cache import cache
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(settings.BASE_DIR)
spec = importlib.util.spec_from_file_location("final_intake", ROOT / "scripts/client-handoff/prepare-config.py")
intake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intake)


@override_settings(AUTHORIZATION_PUBLIC_BASE_URL="https://platform.example.test")
class FinalIntakeRegressionTests(TestCase):
    def test_corrupt_embedded_contract_is_rejected_before_preparing(self):
        self.client.force_login(get_user_model().objects.create_superuser(username="final-intake", password="Local-only-password123"))
        created = self.client.post("/api/v1/manage/catalog/", json.dumps({"name":"Final runtime"}), content_type="application/json", HTTP_IDEMPOTENCY_KEY="final-intake")
        identity = created.json()["software"]["software_id"]
        downloaded = self.client.get(f"/api/v1/manage/catalog/software/{identity}/integration-config/")
        self.assertEqual(downloaded.status_code, 200, downloaded.content)
        exported = downloaded.json()
        with TemporaryDirectory() as folder:
            source = Path(folder) / "input.json"
            for filename in intake.CONTRACTS:
                corrupted = json.loads(json.dumps(exported))
                corrupted["contracts"][filename] = {"wrong":"nonempty"}
                source.write_text(json.dumps(corrupted), encoding="utf-8")
                with self.subTest(contract=filename), self.assertRaises(ValueError):
                    intake.load_config(source)


class FinalBundleSourceTests(SimpleTestCase):
    def test_rebuild_preserves_the_platform_maintained_desktop_path(self):
        spec=importlib.util.spec_from_file_location("final_bundle_builder",ROOT/"scripts/build-client-handoff.py")
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        source=ROOT/"软件授权接入包/授权启动器模板"
        self.assertEqual(builder.DEFAULT_TEMPLATE,source)
        with TemporaryDirectory() as folder:
            output=Path(folder)/"rebuilt"
            builder.build(builder.DEFAULT_TEMPLATE,output)
            for relative in ("src/current_runtime.rs","src/bin/a-template-webview-ui.rs","src/webview_renderer.rs","ui/authorization-a-shell.js","Cargo.toml","Cargo.lock","tests/final_runtime.rs"):
                self.assertEqual((output/"授权启动器模板"/relative).read_bytes(),(source/relative).read_bytes(),relative)
            self.assertEqual((output/"工具/prepare-config.py").read_bytes(),(ROOT/"scripts/client-handoff/prepare-config.py").read_bytes())
            self.assertTrue(json.loads((output/"交付清单.json").read_text(encoding="utf-8"))["generic_runtime_implemented"])
            old_source=Path(folder)/"retired-master";old_source.mkdir()
            with self.assertRaisesRegex(ValueError,"current runtime"):
                builder.build(old_source,Path(folder)/"must-not-exist")


class FinalDesktopSocketTests(LiveServerTestCase):
    """Every license request is sent by the actual desktop executable."""
    def setUp(self):
        from tests.test_launch_ticket import LaunchTicketTests
        cache.clear()
        self.ref = LaunchTicketTests("test_issue_happy_path_and_signature_verifies_with_platform_pubkey")
        self.ref.setUp()
        self.now = self.ref.now
        self.clock = patch("authorization_platform.licensing.authorization.SystemClock")
        clock_type = self.clock.start()
        clock_type.return_value.now.side_effect = lambda: self.now
        self.addCleanup(self.clock.stop)
        self.mode = "normal"
        self.calls = []
        self.decisions = []
        owner = self
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                data = json.loads(body)
                owner.calls.append((self.path, data, self.headers.get("X-Request-Id"), self.headers.get("Idempotency-Key")))
                if owner.mode == "offline":
                    self.close_connection = True
                    return
                if owner.mode == "429":
                    self.send_response(429); self.send_header("Retry-After", "120"); self.send_header("Content-Length", "0"); self.end_headers(); return
                # Windows localhost may first try an unbound IPv6 endpoint for
                # two seconds. The isolated live server is IPv4 loopback.
                conn = http.client.HTTPConnection("127.0.0.1", owner.server_thread.port, timeout=5)
                conn.request("POST", self.path, body, {"Content-Type":"application/json", "X-Request-Id":data["request_id"], "Idempotency-Key":data["idempotency_key"]})
                response = conn.getresponse(); raw = response.read(); status = response.status
                if status == 200:
                    owner.decisions.append(json.loads(raw).get("decision"))
                if owner.mode == "tamper":
                    payload = json.loads(raw); payload["extensions"] = {"changed":"未经签名"}; raw = json.dumps(payload).encode()
                if owner.mode == "bad-consumed" and self.path.endswith("/consume"):
                    payload = json.loads(raw); payload["ticket_id"] = "wrong-ticket"; raw = json.dumps(payload).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
                conn.close()
        self.proxy = ThreadingHTTPServer(("127.0.0.1",0),Proxy)
        self.proxy.daemon_threads = False
        self.thread = threading.Thread(target=self.proxy.serve_forever,daemon=True); self.thread.start()
        self.addCleanup(self.proxy.server_close); self.addCleanup(self.proxy.shutdown)
        self.override = override_settings(AUTHORIZATION_PUBLIC_BASE_URL=f"http://127.0.0.1:{self.proxy.server_port}", APP_ENV="local")
        self.override.enable(); self.addCleanup(self.override.disable)
        self.client.force_login(self.ref.admin)
        exported = self.client.get(f"/api/v1/manage/catalog/software/{self.ref.software.software_id}/integration-config/")
        self.assertEqual(exported.status_code,200,exported.content)
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup); folder = Path(self.temp.name)
        self.template = folder / "template"; self.template.mkdir(); (self.template/"src").mkdir()
        (self.template/"Cargo.toml").write_text("[package]\n")
        (self.template/"HANDOFF-COPY.json").write_text("{}")
        self.source = folder/"source.json"; self.source.write_bytes(exported.content)
        prepared = intake.prepare(self.source,self.template,allow_local_http=True,write=True)
        executable = os.environ.get("FINAL_CLIENT_EXE", str(ROOT/"TEMP/target/debug/a-template-webview-ui.exe"))
        self.assertTrue(Path(executable).is_file(), "Build the desktop binary and set FINAL_CLIENT_EXE; this test must not skip")
        loaders=list(Path(executable).parent.glob("build/webview2-com-sys-*/out/x64/WebView2Loader.dll"))
        child_env={**os.environ,"PATH":os.pathsep.join([*(str(p.parent) for p in loaders),os.environ["PATH"]])}
        self.child_env=child_env
        self.argv=[executable,"--binding",prepared["output"],"--version","1.0.0","--installation","final-stable-hardware","--device-key",str(folder/"device.dpapi")]
        self.process = subprocess.Popen([*self.argv,"--acceptance-stdio"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",env=child_env)
        self.addCleanup(self.stop)
        self.assertTrue(self.command(op="snapshot")["ok"])

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)

    def command(self, **value):
        self.process.stdin.write(json.dumps(value)+"\n"); self.process.stdin.flush()
        # Bound waits so a broken desktop channel fails instead of hanging CI.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(self.process.stdout.readline)
            try: line = future.result(timeout=12)
            except TimeoutError:
                self.process.kill(); self.fail("Desktop state channel timed out")
        self.assertTrue(line, "Desktop exited before replying: "+str(self.process.poll()))
        return json.loads(line)

    def activate(self):
        result=self.command(type="activate",credential=self.ref.license_key)
        self.assertTrue(result["ok"],result)
        self.assertEqual(result["render"]["snapshot"]["state"]["authorization"],"active",result)
        return result

    def assert_local_signature(self, payload, public_key):
        from authorization_platform.licensing.authorization import canonicalize_jcs
        value=json.loads(json.dumps(payload)); sig=value["integrity"].pop("signature")
        Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(public_key+"==")).verify(base64.urlsafe_b64decode(sig+"=="),canonicalize_jcs(value))

    def test_five_real_socket_actions_renewal_notmodified_local_channel_and_permit(self):
        from datetime import timedelta
        from authorization_platform.licensing.admin import extend_authorization
        from authorization_platform.licensing.models import LicenseInstance, LaunchTicket
        from authorization_platform.licensing.authorization import device_proof_message
        active=self.activate()
        self.assertEqual(active["render"]["profile"]["enabled_modules"],[])
        verified=self.command(op="verify"); self.assertTrue(verified["ok"],verified)
        self.assertEqual(self.decisions[-1],"not_modified")
        instance=LicenseInstance.objects.get(license_card=self.ref.card)
        self.now += timedelta(seconds=2)
        extend_authorization(actor=self.ref.admin,authorization_id=instance.authorization_id,added_seconds=3600,reason="Isolated runtime renewal",now=self.now)
        renewed=self.command(op="verify"); self.assertTrue(renewed["ok"],renewed)
        self.assertGreater(renewed["render"]["snapshot"]["expires_at"],active["render"]["snapshot"]["expires_at"])
        local=self.command(op="local");self.assert_local_signature(local["local"],local["public_key"])
        self.assertEqual(local["local"]["schema_version"],"authorization-a-core.v1")
        launch=self.command(type="intent",name="request_launch");self.assertTrue(launch["ok"],launch)
        self.assertIsNotNone(launch["permit"])
        self.assertTrue(LaunchTicket.objects.get(ticket_id=launch["permit"]["ticket_id"]).consumed_at)
        self.assertFalse(self.command(type="intent",name="request_launch")["ok"])
        endpoint=self.command(op="local_endpoint")
        from urllib.parse import urlsplit
        url=urlsplit(endpoint["address"])
        conn=http.client.HTTPConnection(url.hostname,url.port,timeout=3)
        scope=json.loads(self.source.read_text(encoding="utf-8"))["software"]
        request={k:scope[k] for k in ("software_id","profile_id","client_id")}
        request.update(client_version="1.0.0",nonce="local-random-unique-nonce")
        conn.request("POST","/local/v1/session/open",json.dumps(request),{"Authorization":"Bearer "+endpoint["bootstrap"]})
        opened=conn.getresponse();self.assertEqual(opened.status,200);opened=json.loads(opened.read())
        self.assert_local_signature(opened["response"],endpoint["public_key"])
        conn.close();conn=http.client.HTTPConnection(url.hostname,url.port,timeout=3)
        conn.request("GET","/local/v1/session/state",headers={"Authorization":"Bearer "+opened["session_token"]})
        state=conn.getresponse();self.assertEqual(state.status,200);state=json.loads(state.read());self.assert_local_signature(state,endpoint["public_key"]);conn.close()
        deactivated=self.command(op="deactivate");self.assertTrue(deactivated["ok"],deactivated)
        self.assertNotIn("request_launch",deactivated["render"]["snapshot"]["state"]["intents"])
        actions={"activate":"activate","verify":"verify","deactivate":"deactivate","launch-ticket":"launch-ticket","consume":"ticket-consume"}
        self.assertEqual({path.split('/')[-1] for path,_,_,_ in self.calls},set(actions))
        for path,body,request_id,key in self.calls:
            self.assertEqual(body["request_id"],request_id);self.assertEqual(body["idempotency_key"],key)
            self.assertNotIn("identity",body);self.assertNotIn("action",body)
            public=Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(body["device_public_key"]+"=="))
            public.verify(base64.urlsafe_b64decode(body["device_proof"]+"=="),device_proof_message({**body,"action":actions[path.split('/')[-1]]}))

    def test_real_network_and_429_do_not_extend_online_window_and_retry_is_identical(self):
        # Short, real signed success window; only this isolated fixture is edited.
        from authorization_platform.catalog.services import create_policy_version
        from authorization_platform.catalog.models import PolicyStatus
        create_policy_version(actor=self.ref.admin,software_id=self.ref.software.software_id,profile_id=self.ref.profile.profile_id,version="short-heartbeat",verify_interval_seconds=2,status=PolicyStatus.ACTIVE)
        self.activate();self.mode="offline"
        failed=self.command(op="verify");self.assertFalse(failed["ok"])
        original=self.calls[-1]
        self.mode="429"
        throttled=self.command(type="intent",name="retry");self.assertFalse(throttled["ok"])
        self.assertEqual(self.calls[-1],original)
        time.sleep(2.2)
        closed=self.command(op="snapshot")
        self.assertNotIn("request_launch",closed["render"]["snapshot"]["state"]["intents"])
        self.assertNotEqual(closed["render"]["snapshot"]["state"]["authorization"],"active")
        self.assertIsNone(self.command(type="intent",name="request_launch")["permit"])

    def test_tampered_signed_response_and_wrong_consumed_scope_never_grant(self):
        self.mode="tamper"
        denied=self.command(type="activate",credential=self.ref.license_key)
        self.assertFalse(denied["ok"]);self.assertIsNone(denied["permit"])
        self.mode="normal";self.activate()
        self.mode="bad-consumed"
        denied=self.command(type="intent",name="request_launch")
        self.assertFalse(denied["ok"]);self.assertIsNone(denied["permit"])

    def test_hidden_real_webview_form_dynamic_snapshot_and_terminal_intent_gate(self):
        from authorization_platform.catalog.services import create_policy_version
        from authorization_platform.catalog.models import PolicyStatus
        from authorization_platform.licensing.models import LicenseInstance, LaunchTicket
        from authorization_platform.licensing.admin import revoke_authorization, extend_authorization
        create_policy_version(actor=self.ref.admin,software_id=self.ref.software.software_id,profile_id=self.ref.profile.profile_id,version="webview-heartbeat",verify_interval_seconds=2,status=PolicyStatus.ACTIVE)
        folder=Path(self.temp.name);script=folder/"probe.js";receipt=folder/"receipt.json"
        script.write_text("""(() => {
          const stages=[];
          const expiryMessages=[];
          const errors=[];
          addEventListener('error',event=>errors.push(String(event.message)));
          setTimeout(()=>window.ipc.postMessage(JSON.stringify({type:'acceptance_result',dom:{stages,errors,
            current:document.querySelector('.shell').dataset.state,feedback:document.getElementById('feedbackMessage').textContent,
            apply:typeof window.authorizationAApplySnapshot}})),15000);
          document.getElementById('credential').value=CREDENTIAL;
          document.getElementById('activationForm').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
          const timer=setInterval(() => {
            const state=document.querySelector('.shell').dataset.state;
            const message=document.getElementById('feedbackMessage').textContent;
            if (state==='active' && !expiryMessages.includes(message)) expiryMessages.push(message);
            if (!stages.includes(state)) stages.push(state);
            if (stages.includes('active') && state==='blocked') {
              clearInterval(timer);
              window.ipc.postMessage(JSON.stringify({type:'acceptance_result',dom:{stages,state,expiryMessages,
                supportHidden:document.getElementById('supportLinks').hidden,
                savedCard:(()=>{try{return localStorage.getItem('a.saved_card')}catch(e){return null}})(),
                credential:document.getElementById('credential').value,
                disabled:document.getElementById('activateButton').disabled}}));
            }
          },50);
        })();""".replace("CREDENTIAL",json.dumps(self.ref.license_key)),encoding="utf-8")
        probe=subprocess.Popen([*self.argv,"--acceptance-webview",str(script),"--receipt",str(receipt)],env=self.child_env,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline=time.monotonic()+40
            while time.monotonic()<deadline and not LaunchTicket.objects.filter(consumed_at__isnull=False).exists():
                if probe.poll() is not None: break
                time.sleep(.1)
            host_receipt=receipt.with_suffix(".host.json")
            self.assertTrue(LaunchTicket.objects.filter(consumed_at__isnull=False).exists(),"Actual embedded form failed to reach consumed; calls="+str([path for path,_,_,_ in self.calls])+" exit="+str(probe.poll())+" receipt="+(receipt.read_text(encoding="utf-8") if receipt.exists() else "missing")+" host="+(host_receipt.read_text(encoding="utf-8") if host_receipt.exists() else "missing"))
            instance=LicenseInstance.objects.get(license_card=self.ref.card)
            extend_authorization(actor=self.ref.admin,authorization_id=instance.authorization_id,added_seconds=3600,reason="Live WebView renewal",now=self.now)
            revision_deadline=time.monotonic()+8
            revision=0
            while time.monotonic()<revision_deadline:
                if host_receipt.exists():
                    try: revision=json.loads(host_receipt.read_text(encoding="utf-8"))["render"]["snapshot"]["authorization_revision"]
                    except (ValueError,KeyError): revision=0
                    if revision>=2:break
                time.sleep(.1)
            self.assertGreaterEqual(revision,2,"Live WebView never consumed renewal")
            time.sleep(.15)
            revoke_authorization(actor=self.ref.admin,authorization_id=instance.authorization_id,reason="Isolated live WebView revocation",request_id="final-webview-revoke")
            probe.wait(timeout=12)
            self.assertTrue(receipt.is_file(),"No dynamic WebView receipt")
            observed=json.loads(receipt.read_text(encoding="utf-8"))
            self.assertIn("active",observed["dom"]["stages"])
            self.assertEqual(observed["dom"]["state"],"blocked")
            self.assertTrue(observed["dom"]["supportHidden"])
            self.assertIsNone(observed["dom"]["savedCard"])
            self.assertEqual(observed["dom"]["credential"],"")
            self.assertGreaterEqual(len(observed["dom"]["expiryMessages"]),2,"Renewal failed to update visible expiry")
            self.assertNotIn("request_launch",observed["host"]["snapshot"]["state"]["intents"])
            evidence=ROOT/"TEMP/final-webview-receipt.json"; evidence.write_text(json.dumps(observed,ensure_ascii=False,indent=2),encoding="utf-8")
        finally:
            if probe.poll() is None:probe.kill();probe.wait(timeout=5)

    @override_settings(PUBLIC_LICENSE_RATE_LIMIT=5000)
    def test_1030_real_socket_notmodified_heartbeats_do_not_exhaust_session(self):
        from datetime import timedelta
        self.activate()
        for count in range(1030):
            self.now += timedelta(seconds=1)
            result=self.command(op="verify")
            self.assertTrue(result["ok"],(count,result))
            self.assertEqual(result["render"]["snapshot"]["state"]["authorization"],"active",(count,result))
        self.assertEqual(self.decisions.count("not_modified"),1030)
