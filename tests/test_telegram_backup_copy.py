"""第三份异地副本：把已加密的备份推到 Telegram 私有频道。

这些是**行为测试**：本地起一个假的 Telegram API（真的走 curl、真的发 multipart、真的解析
JSON），把脚本真跑一遍，看它到底做了什么、失败时会不会连累备份。
不用 curl 打桩——桩文件在 Windows 上不可靠，而真 curl + 真 HTTP 能验到更多。
"""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "backup" / "telegram_backup_copy.sh"
RUNNER = ROOT / "deploy" / "backup" / "backup_runner.sh"


def _git_bash() -> str:
    candidates = []
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    candidates.extend(
        [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise AssertionError("Git Bash is required to run the backup copy script")


def _bash_path(path: Path) -> str:
    """Git Bash 的工具用 POSIX 路径；原生 Windows 程序（curl）用 C:/... 形式。"""
    resolved = Path(path).resolve()
    if os.name != "nt":
        return str(resolved)
    text = resolved.as_posix()
    if len(text) >= 2 and text[1] == ":":
        return f"/{text[0].lower()}{text[2:]}"
    return text


def _native_path(path: Path) -> str:
    return str(Path(path).resolve()).replace("\\", "/")


class _FakeTelegram:
    """只实现脚本用到的两个端点：sendDocument / deleteMessage。"""

    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []
        handler = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # 静音
                pass

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                if "multipart/form-data" in (self.headers.get("Content-Type") or ""):
                    fields = handler._multipart(body, self.headers.get("Content-Type", ""))
                else:
                    fields = parse_qs(body.decode("utf-8", "replace"))
                handler.calls.append({"path": self.path, "fields": fields, "raw": body})
                if "sendDocument" in self.path:
                    payload = {"ok": handler.ok, "result": {"message_id": 4242}}
                else:
                    payload = {"ok": handler.ok, "result": True}
                out = json.dumps(payload, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @staticmethod
    def _multipart(body: bytes, content_type: str) -> dict:
        fields = {}
        for chunk in body.split(b"--"):
            if b"Content-Disposition" not in chunk:
                continue
            head, _, value = chunk.partition(b"\r\n\r\n")
            name = None
            for part in head.split(b"\r\n"):
                if b'name="' in part:
                    name = part.split(b'name="', 1)[1].split(b'"', 1)[0].decode()
            if name:
                fields[name] = value.rsplit(b"\r\n", 1)[0].decode("utf-8", "replace")
        return fields

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"


class TelegramBackupCopyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.keys = self.tmp / "keys"
        self.keys.mkdir()
        self.log = self.tmp / "backup.log"
        self.index = self.tmp / "telegram-backup-index.txt"
        self.dump = self.tmp / "authorization-platform-enc-20260927-000000.dump.enc"
        self.dump.write_bytes(b"Salted__" + b"\x00" * 4096)

    def _run(self, *args, dump=None, api="http://127.0.0.1:1"):
        env = dict(os.environ)
        env["PATH"] = "/usr/bin:/bin:/mingw64/bin:" + env.get("PATH", "")
        env["BACKUP_ROOT"] = _bash_path(self.tmp)
        env["BACKUP_KEYS_DIR"] = _bash_path(self.keys)
        env["BACKUP_LOG_FILE"] = _bash_path(self.log)
        env["TELEGRAM_BACKUP_INDEX"] = _bash_path(self.index)
        env["TELEGRAM_API"] = api
        # curl 是原生 Windows 程序，必须拿到 C:/... 形式的路径
        target = _native_path(Path(dump)) if dump is not None else _native_path(self.dump)
        return subprocess.run(
            [_git_bash(), _bash_path(SCRIPT), target, *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
        )

    def _set_credentials(self, token="123:ABC", channel="-100999"):
        (self.keys / "telegram-backup-bot-token.txt").write_text(token + "\n", encoding="utf-8")
        (self.keys / "telegram-backup-channel-id.txt").write_text(channel + "\n", encoding="utf-8")

    def _log(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace") if self.log.exists() else ""

    def test_a_good_dump_is_uploaded_and_remembered(self):
        self._set_credentials()
        with _FakeTelegram(ok=True) as api:
            result = self._run(api=api.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(api.calls), 1, api.calls)
            call = api.calls[0]
            self.assertIn("/bot123:ABC/sendDocument", call["path"])
            self.assertEqual(call["fields"].get("chat_id"), "-100999")
            self.assertIn(self.dump.name, str(call["fields"]))
            self.assertIn("4242", self.index.read_text(encoding="utf-8"))
            self.assertIn("uploaded", self._log())

    def test_missing_credentials_send_nothing_and_still_exit_zero(self):
        with _FakeTelegram(ok=True) as api:
            result = self._run(api=api.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(api.calls, [])
            self.assertIn("credentials missing", self._log())

    def test_the_disabled_marker_skips_everything(self):
        self._set_credentials()
        (self.keys / "telegram-backup-disabled").write_text("off\n", encoding="utf-8")
        with _FakeTelegram(ok=True) as api:
            result = self._run(api=api.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(api.calls, [])
            self.assertIn("disabled by marker", self._log())

    def test_a_dump_over_the_bot_limit_is_not_uploaded(self):
        self._set_credentials()
        big = self.tmp / "big.enc"
        with big.open("wb") as handle:
            handle.truncate(51 * 1024 * 1024)
        with _FakeTelegram(ok=True) as api:
            result = self._run(dump=str(big), api=api.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(api.calls, [])
            self.assertIn("50MB bot limit", self._log())
        big.unlink(missing_ok=True)

    def test_older_copies_are_pruned_to_the_keep_count(self):
        self._set_credentials()
        self.index.write_text("\n".join(str(i) for i in range(100, 108)) + "\n", encoding="utf-8")
        with _FakeTelegram(ok=True) as api:
            result = self._run("3", api=api.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            deletes = [c for c in api.calls if "deleteMessage" in c["path"]]
            uploads = [c for c in api.calls if "sendDocument" in c["path"]]
            self.assertEqual(len(uploads), 1, api.calls)
            self.assertEqual(len(deletes), 6, [c["fields"] for c in deletes])
            kept = self.index.read_text(encoding="utf-8").split()
            self.assertEqual(len(kept), 3)
            self.assertEqual(kept[-1], "4242")

    def test_a_rejected_send_never_fails_the_backup(self):
        self._set_credentials()
        with _FakeTelegram(ok=False) as api:
            result = self._run(api=api.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("send failed (ignored)", self._log())
            recorded = self.index.read_text(encoding="utf-8").split() if self.index.exists() else []
            self.assertEqual(recorded, [])

    def test_the_script_never_reads_a_passphrase_or_uploads_a_plaintext_dump(self):
        source = SCRIPT.read_text(encoding="utf-8")
        # 说明文字里可以提到"用哪个口令文件解开"，但代码不能去读口令、更不能传明文 dump
        code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("#"))
        caption = [line for line in code.splitlines() if line.strip().startswith("caption=")]
        body = "\n".join(line for line in code.splitlines() if line not in caption)
        self.assertNotIn("-pass file:", body)
        self.assertNotIn("cat ", body)
        self.assertNotIn(".plain", body)

    def test_the_runner_only_pushes_a_verified_full_backup(self):
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn('if [ "$RUN_TYPE" = "full" ] && [ "$DUMP_PROOF_FAILED" -eq 0 ]', runner)
        self.assertIn("telegram_backup_copy.sh", runner)
        # 上传失败绝不能连累备份成败
        marker = '"${TELEGRAM_COPY_SCRIPT}" "${DUMP_DIR}/${DUMP_NAME}" "${TELEGRAM_BACKUP_KEEP:-7}" || true'
        self.assertIn(marker, runner)
