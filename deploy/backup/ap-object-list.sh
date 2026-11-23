#!/bin/bash
set -euo pipefail
python3 - <<'PY'
import json
import subprocess
import sys

inner = r'''
set -e
if [ -n "${MINIO_ROOT_USER_FILE:-}" ] && [ -s "$MINIO_ROOT_USER_FILE" ] && [ -n "${MINIO_ROOT_PASSWORD_FILE:-}" ] && [ -s "$MINIO_ROOT_PASSWORD_FILE" ]; then
  USER=$(cat "$MINIO_ROOT_USER_FILE")
  PASS=$(cat "$MINIO_ROOT_PASSWORD_FILE")
elif [ -n "${MINIO_ACCESS_KEY_FILE:-}" ] && [ -s "$MINIO_ACCESS_KEY_FILE" ] && [ -n "${MINIO_SECRET_KEY_FILE:-}" ] && [ -s "$MINIO_SECRET_KEY_FILE" ]; then
  USER=$(cat "$MINIO_ACCESS_KEY_FILE")
  PASS=$(cat "$MINIO_SECRET_KEY_FILE")
elif [ -n "${MINIO_ROOT_USER:-}" ] && [ -n "${MINIO_ROOT_PASSWORD:-}" ]; then
  USER="$MINIO_ROOT_USER"
  PASS="$MINIO_ROOT_PASSWORD"
else
  exit 2
fi
mc alias set --insecure localprobe https://127.0.0.1:9000 "$USER" "$PASS" >/dev/null
export MC_INSECURE=1
# pgBackRest 仓库在 backup-primary；应用对象也可能在 authorization-platform。
for bucket in authorization-platform-backup-primary authorization-platform; do
  mc ls --insecure --recursive --json "localprobe/${bucket}" || true
done
'''

proc = subprocess.run(
    ["docker", "exec", "authorization-platform-candidate-object-store-1", "sh", "-c", inner],
    capture_output=True,
    text=True,
)
keys = []
seen = set()
for line in (proc.stdout or "").splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        continue
    key = payload.get("key") or payload.get("Key")
    if isinstance(key, str) and key.strip() and key not in seen:
        seen.add(key)
        keys.append(key.strip())
if proc.returncode not in (0, None) and not keys:
    sys.exit(1)
if not keys:
    sys.exit(1)
print(json.dumps(keys, ensure_ascii=False))
sys.exit(0)
PY
