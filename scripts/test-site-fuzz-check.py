"""Bounded malformed-input fuzz against the TEST station public API.

Only the test cluster (https://retired.example.com). Low volume (~40 requests),
sequential with small pauses. PASS = every response is a structured 4xx
(or 429/405); any HTTP 500 or transport break is a FAIL with nonzero exit.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "https://retired.example.com"
FAILURES: list[str] = []


def send(action: str, body, headers=None) -> tuple[int, dict]:
    if isinstance(body, bytes):
        raw = body
    elif isinstance(body, str):
        raw = body.encode("utf-8")
    else:
        raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE}/api/v1/public/licenses/{action}",
        data=raw,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except Exception:
            return exc.code, {}
    except Exception as exc:  # noqa: BLE001
        return 0, {"transport_error": str(exc)}


def check(name: str, action: str, body, headers=None) -> None:
    status, _ = send(action, body, headers)
    if status == 500 or status == 0:
        FAILURES.append(f"{name}: status={status}")
        print(f"FAIL {name}: status={status}", flush=True)
    elif status in (400, 401, 403, 404, 405, 409, 429):
        print(f"ok   {name}: status={status}", flush=True)
    else:
        FAILURES.append(f"{name}: unexpected status={status}")
        print(f"FAIL {name}: unexpected status={status}", flush=True)
    time.sleep(0.4)


def main() -> int:
    cases = [
        ("empty-object", "activate", {}),
        ("empty-body", "activate", ""),
        ("null-bytes", "activate", b"\x00\x01\x02"),
        ("not-json", "activate", "{oops"),
        ("array-body", "activate", [1, 2, 3]),
        ("wrong-types", "activate", {"request_id": 12345, "nonce": ["x"], "software_id": None}),
        ("oversize-string", "activate", {"request_id": "r", "license_key": "K" * 20000}),
        ("unknown-fields", "activate", {"request_id": "r1", "zzz_unknown": "x" * 500}),
        ("bad-uuid", "verify", {"request_id": "r2", "authorization_id": "not-a-uuid"}),
        ("sql-inject", "activate", {"request_id": "' OR 1=1--", "license_key": "' OR '1'='1"}),
        ("xss-probe", "activate", {"request_id": "<script>alert(1)</script>", "installation_id": "<img src=x>"}),
        ("path-traversal", "activate", {"request_id": "../../etc/passwd", "client_version": "..\\..\\win"}),
        ("negative-amount", "activate", {"request_id": "r3", "quantity": -5}),
        ("float-nonce", "activate", {"request_id": "r4", "nonce": 3.14}),
        ("bool-body", "activate", True),
        ("huge-nesting", "activate", {"request_id": "r5", "a": {"b": {"c": {"d": [1] * 5000}}}}),
        ("missing-ct", "verify", {"request_id": "r6"}),
        ("deactivate-empty", "deactivate", {}),
        ("deactivate-types", "deactivate", {"request_id": 0, "authorization_id": 0}),
        ("unicode-flood", "activate", {"request_id": "r7", "installation_id": "设" * 3000}),
    ]
    for name, action, body in cases:
        if name == "missing-ct":
            req = urllib.request.Request(
                f"{BASE}/api/v1/public/licenses/{action}",
                data=json.dumps(body).encode("utf-8"),
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            except Exception:
                status = 0
            if status in (400, 403, 404, 405, 415, 429):
                print(f"ok   {name}: status={status}", flush=True)
            else:
                FAILURES.append(f"{name}: status={status}")
                print(f"FAIL {name}: status={status}", flush=True)
            time.sleep(0.4)
            continue
        check(name, action, body)
    print(f"done: {len(cases)} cases, failures={len(FAILURES)}", flush=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
