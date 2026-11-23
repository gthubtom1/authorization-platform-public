#!/usr/bin/env bash
# 线上代码快照 → 加密 → GitHub 私有库（SECURITY: 暂存目录在随机独占目录，权限 700）
set -euo pipefail

BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
LOG=${BACKUP_LOG_FILE:-${BACKUP_ROOT}/backup.log}
KEYS=${BACKUP_KEYS_DIR:-${BACKUP_ROOT}/keys}
GH_TOKEN_FILE=${KEYS}/github-token.txt
SECRETS_PASS=${KEYS}/secrets-bundle-pass.txt
PYTHON_BIN=${PYTHON_BIN:-python3}
GH_REPO=${BACKUP_GITHUB_REPO:-gthubtom1/authorization-platform-backup}
POLICY_MANAGE=${AUTHORIZATION_PLATFORM_MANAGE:-}

mkdir -p "$(dirname "$LOG")"
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
CODE_DIR=$(dirname "$POLICY_MANAGE")
if [ ! -d "${CODE_DIR}/src" ]; then
  log "app source missing"
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
NAME=code-${TS}.tar.enc
OUT_DIR=${GH_WORK}/code

umask 077
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/auth-code.XXXXXXXXXX")
chmod 700 "$STAGE"

cleanup() {
  if [ -n "${STAGE:-}" ] && [ -d "$STAGE" ]; then
    rm -rf "$STAGE"
  fi
  rm -f "${ASKPASS:-}" "${TOKEN_TMP:-}"
}
trap cleanup EXIT INT TERM

mkdir -p "$STAGE" "$OUT_DIR"
chmod 700 "$OUT_DIR"

tar -czf "$STAGE/code.tar.gz" \
  --exclude=".git" \
  --exclude="output" \
  --exclude="*.log" \
  --exclude="*/production.env" \
  --exclude="*/postgres.env" \
  --exclude="*/object-store*.env" \
  --exclude="*/pgbackrest/pgbackrest.conf" \
  --exclude="*.tar.gz" \
  -C "$CODE_DIR" . 2>>"$LOG" || { log "code tar failed"; exit 1; }

openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in "$STAGE/code.tar.gz" -out "$OUT_DIR/$NAME" \
  -pass file:"$SECRETS_PASS" 2>>"$LOG"
rm -rf "$STAGE"
SHA=$(sha256sum "$OUT_DIR/$NAME" | cut -d' ' -f1)

cat > "$GH_WORK/code-manifest.json" <<EOF
{
  "schema_version": 1,
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bundle": "code/$NAME",
  "sha256": "$SHA",
  "encryption": "aes-256-cbc-pbkdf2",
  "source": "$CODE_DIR (production candidate snapshot, no git)",
  "contains": "authorization-platform candidate source (src/tests/deploy/docs/protocol/scripts), sensitive env excluded (see secrets bundle)",
  "recover_to": "re-copy into the current app root after decrypt+unpack"
}
EOF

cd "$GH_WORK"
git add -- code/*.tar.enc code-manifest.json
if ! git -c user.name="authorization-backup-bot" -c user.email="backup@localhost" \
  commit -m "code snapshot ${TS}" >/dev/null 2>&1; then
  log "code commit failed"
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
  log "code push failed"
  exit 1
fi
log "code snapshot pushed: ${NAME} sha=${SHA:0:16}"
exit 0
