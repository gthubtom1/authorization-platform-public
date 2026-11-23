#!/usr/bin/env bash
# 密钥/配置加密打包 → GitHub 私有库（SECURITY: 暂存目录在随机独占目录，权限 700，不在 git 工作区）
set -euo pipefail

BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
LOG=${BACKUP_LOG_FILE:-${BACKUP_ROOT}/backup.log}
KEYS=${BACKUP_KEYS_DIR:-${BACKUP_ROOT}/keys}
GH_TOKEN_FILE=${KEYS}/github-token.txt
SECRETS_PASS=${KEYS}/secrets-bundle-pass.txt
PYTHON_BIN=${PYTHON_BIN:-python3}
GH_REPO=${BACKUP_GITHUB_REPO:-gthubtom1/authorization-platform-backup}
POLICY_MANAGE=${AUTHORIZATION_PLATFORM_MANAGE:-}

mkdir -p "$(dirname "$LOG")" "$KEYS"
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$LOG"; }

if [ -z "$POLICY_MANAGE" ]; then
  for candidate in \
    /srv/authorization-platform/manage.py \
    /opt/authorization-platform-candidate-clean-rc8-staging/manage.py
  do
    if [ -f "$candidate" ]; then POLICY_MANAGE="$candidate"; break; fi
  done
fi
if [ ! -f "${POLICY_MANAGE:-}" ]; then
  log "manage.py missing"
  exit 1
fi
APP_ROOT=$(dirname "$POLICY_MANAGE")
DEPLOY="${APP_ROOT}/deploy"
if [ ! -d "${APP_ROOT}/src" ]; then
  log "app source missing"
  exit 1
fi
if [ ! -f "${DEPLOY}/production.env" ]; then
  log "production.env missing"
  exit 1
fi
if [ ! -s "$GH_TOKEN_FILE" ]; then
  log "github token missing or empty"
  exit 1
fi
if [ ! -s "$SECRETS_PASS" ]; then
  log "secrets bundle pass missing"
  exit 1
fi

POLICY_GH_REPO=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --github-repo)
if [ -n "$POLICY_GH_REPO" ]; then
  GH_REPO="$POLICY_GH_REPO"
fi
GH_WORK=${BACKUP_GITHUB_WORK_DIR:-${BACKUP_ROOT}/github-sync}
TS=$(date -u +%Y%m%d-%H%M%S)
NAME=secrets-bundle-${TS}.tar.enc
OUT_DIR=${GH_WORK}/secrets

umask 077
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/auth-secrets.XXXXXXXXXX")
chmod 700 "$STAGE"

cleanup() {
  if [ -n "${STAGE:-}" ] && [ -d "$STAGE" ]; then
    rm -rf "$STAGE"
  fi
  rm -f "${ASKPASS:-}" "${TOKEN_TMP:-}"
}
trap cleanup EXIT INT TERM

mkdir -p "$STAGE/raw" "$OUT_DIR"
chmod 700 "$OUT_DIR"

# 1) 收集原始文件
cd "$STAGE/raw" || exit 1
cp "$DEPLOY/production.env" production.env
cp "$DEPLOY/postgres.env" postgres.env 2>/dev/null || true
cp "$DEPLOY/object-store.env" object-store.env 2>/dev/null || true
cp "$DEPLOY/object-store-init.env" object-store-init.env 2>/dev/null || true
cp "$DEPLOY/pgbackrest/pgbackrest.conf" pgbackrest.conf 2>/dev/null || true
cp "$DEPLOY/pgbackrest/ca.crt" minio-ca.crt 2>/dev/null || true
cp -r /opt/authorization-platform-release-keys . 2>/dev/null || true
cp -r /opt/authorization-platform-backup-runner runner-scripts 2>/dev/null || true
if [ -d /etc/letsencrypt/live/retired.example.com ]; then
  mkdir -p tls-iqd && cp /etc/letsencrypt/live/retired.example.com/* tls-iqd/ 2>/dev/null || true
fi
cp "$DEPLOY/docker-compose.production.yml" docker-compose.production.yml 2>/dev/null || true
find . -type f | sort > filelist.txt

# 2) 打包 + 加密（在安全临时目录完成，绝不写进 git 工作区）
tar -czf "$STAGE/bundle.tar.gz" -C "$STAGE/raw" .
openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in "$STAGE/bundle.tar.gz" -out "$OUT_DIR/$NAME" \
  -pass file:"$SECRETS_PASS" 2>>"$LOG"
rm -rf "$STAGE"
SHA=$(sha256sum "$OUT_DIR/$NAME" | cut -d' ' -f1)

# 3) 清单
cat > "$GH_WORK/secrets-bundle-manifest.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bundle": "secrets/$NAME",
  "sha256": "$SHA",
  "encryption": "aes-256-cbc-pbkdf2",
  "contains": "production.env, postgres.env, object-store envs, pgbackrest.conf, minio-ca, release keys, runner scripts, TLS certs, compose",
  "pass_location_vps": "BACKUP_KEYS_DIR/secrets-bundle-pass.txt (600)",
  "pass_location_local": "部署与恢复/灾备钥匙包",
  "note": "明文密钥不上传；仅加密包。"
}
EOF

# 4) push（只 push 加密产物；.gitignore 兜底保护）
cd "$GH_WORK"
cat > .gitignore <<'GITEOF'
secrets/raw/
code-stage/
*.tar.gz
dumps/*.plain
secrets/*.plain
GITEOF
git add -- secrets/*.tar.enc secrets-bundle-manifest.json .gitignore
if ! git -c user.name="authorization-backup-bot" -c user.email="backup@localhost" \
  commit -m "secrets bundle ${TS}" >/dev/null 2>&1; then
  log "secrets commit failed"
  exit 1
fi
TOKEN=$(cat "$GH_TOKEN_FILE")
ASKPASS=$(mktemp)
TOKEN_TMP=$(mktemp)
chmod 600 "$TOKEN_TMP"
printf '%s' "$TOKEN" > "$TOKEN_TMP"
chmod 700 "$ASKPASS"
printf '#!/bin/sh\ncat "%s"\n' "$TOKEN_TMP" > "$ASKPASS"
trap cleanup EXIT INT TERM
if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" git push "https://github.com/${GH_REPO}.git" main >>"$LOG" 2>&1; then
  log "secrets push failed"
  exit 1
fi
log "secrets bundle pushed: ${NAME} sha=${SHA:0:16}"
exit 0
