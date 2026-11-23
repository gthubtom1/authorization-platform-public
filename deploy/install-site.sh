#!/usr/bin/env bash
# 授权平台主机完整接线（只准用这一份）。在 VPS 上以 root 运行。
# 第一次装和以后更新代码，都跑这一条。幂等：可重复执行。
# 不准打开备份总开关；只允许启用策略巡检 timer，旧 full/diff 直接日历 timer 禁止。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

INSTALL_ROOT=${INSTALL_ROOT:-/opt/authorization-platform}
COMPOSE_PROJECT=${COMPOSE_PROJECT:-authorization-platform-candidate}
APP_CONTAINER=${APP_CONTAINER:-${COMPOSE_PROJECT}-app-1}
DB_CONTAINER=${DB_CONTAINER:-${COMPOSE_PROJECT}-db-1}
BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
BACKUP_DUMP_PASS_FILE=${BACKUP_ROOT}/host-secrets/github-dump-pass.txt
AUTH_DOMAIN=${AUTH_DOMAIN:?Set AUTH_DOMAIN to the confirmed site domain before installation or verification}
KEYS_SRC=${KEYS_SRC:-/opt/authorization-platform-backup-keys}
ADMIN_PASS_FILE=${ADMIN_PASS_FILE:-/opt/authorization-platform-admin-password.txt}
VERIFY_ONLY=${VERIFY_ONLY:-0}
NGINX_SITE=/etc/nginx/sites-available/authorization-platform-${AUTH_DOMAIN}.conf
NGINX_TEMPLATE="$INSTALL_ROOT/deploy/nginx/authorization-platform.conf.example"
COMPOSE_FILE="$INSTALL_ROOT/deploy/docker-compose.production.yml"
ENV_PRODUCTION="$INSTALL_ROOT/deploy/production.env"
ENV_COMPOSE="$INSTALL_ROOT/deploy/compose.env"

if [ ! -f "$INSTALL_ROOT/manage.py" ] || [ ! -d "$INSTALL_ROOT/deploy/backup" ]; then
  echo "INSTALL_ROOT is not a complete platform tree: $INSTALL_ROOT" >&2
  exit 1
fi

validate_install_config() {
  case "$BACKUP_ROOT" in
    ''|[!/]*)
      echo "BACKUP_ROOT must be an absolute path" >&2
      exit 1
      ;;
  esac
  case "$BACKUP_ROOT" in
    *[[:space:]]*)
      echo "BACKUP_ROOT must not contain whitespace" >&2
      exit 1
      ;;
  esac
  case "$BACKUP_ROOT" in
    *"/.."*|*"/."*)
      echo "BACKUP_ROOT must not contain . or .. path segments: $BACKUP_ROOT" >&2
      exit 1
      ;;
  esac
  local normalized_backup_root
  normalized_backup_root=$(realpath -m "$BACKUP_ROOT" 2>/dev/null || echo "$BACKUP_ROOT")
  case "$normalized_backup_root" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      echo "BACKUP_ROOT cannot be a system root directory: $BACKUP_ROOT" >&2
      exit 1
      ;;
    /bin/*|/boot/*|/dev/*|/etc/*|/proc/*|/sys/*|/sbin/*)
      echo "BACKUP_ROOT cannot be inside a critical system directory: $BACKUP_ROOT" >&2
      exit 1
      ;;
  esac
}

compose() {
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_COMPOSE" -p "$COMPOSE_PROJECT" "$@"
}

compose_exec() {
  compose exec -T app "$@"
}

strip_crlf() {
  find "$INSTALL_ROOT/deploy/backup" -type f -name '*.sh' -exec sed -i 's/\r$//' {} +
  find "$INSTALL_ROOT/deploy/backup" -type f -name '*.sh' -exec chmod 700 {} +
  sed -i 's/\r$//' "$INSTALL_ROOT/deploy/install-site.sh" "$INSTALL_ROOT/deploy/backup/maintenance.sh" 2>/dev/null || true
}

require_host_tools() {
  local missing=0
  local tool
  for tool in docker nginx certbot openssl python3 git curl ss flock logrotate; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "host tool missing: $tool" >&2
      missing=1
    fi
  done
  if ! docker compose version >/dev/null 2>&1; then
    echo "host tool missing: docker compose" >&2
    missing=1
  fi
  if [ "$missing" -ne 0 ]; then
    exit 1
  fi
}

install_host_packages() {
  export DEBIAN_FRONTEND=noninteractive
  local need=()
  command -v docker >/dev/null 2>&1 || need+=(docker.io)
  command -v nginx >/dev/null 2>&1 || need+=(nginx)
  command -v certbot >/dev/null 2>&1 || need+=(certbot)
  command -v openssl >/dev/null 2>&1 || need+=(openssl)
  command -v python3 >/dev/null 2>&1 || need+=(python3)
  command -v git >/dev/null 2>&1 || need+=(git)
  command -v curl >/dev/null 2>&1 || need+=(curl)
  command -v logrotate >/dev/null 2>&1 || need+=(logrotate)
  if ! docker compose version >/dev/null 2>&1; then
    need+=(docker-compose-v2)
  fi
  if ! python3 -c "import certbot_nginx" >/dev/null 2>&1; then
    need+=(python3-certbot-nginx)
  fi
  if [ "${#need[@]}" -gt 0 ]; then
    apt-get update -qq
    apt-get install -y --no-install-recommends "${need[@]}" ca-certificates
  fi
  systemctl enable --now docker.service >/dev/null 2>&1 || true
}

ensure_object_store_tls() {
  local dir="$INSTALL_ROOT/deploy/object-store-tls"
  mkdir -p "$dir"
  if [ -s "$dir/ca.crt" ] && [ -s "$dir/public.crt" ] && [ -s "$dir/private.key" ]; then
    return 0
  fi
  echo "object-store-tls missing; generating internal MinIO certificates (not platform card keys)"
  local work ca_key
  work=$(mktemp -d)
  ca_key=/opt/authorization-platform-object-store-ca.key
  openssl genrsa -out "$ca_key" 4096
  chmod 600 "$ca_key"
  openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days 3650 \
    -subj "/CN=authorization-platform-minio-ca" -out "$dir/ca.crt"
  openssl genrsa -out "$dir/private.key" 2048
  chmod 600 "$dir/private.key"
  openssl req -new -key "$dir/private.key" -subj "/CN=object-store" -out "$work/server.csr"
  printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:object-store,DNS:localhost\n' > "$work/ext.cnf"
  echo 1000 > "$work/ca.srl"
  openssl x509 -req -in "$work/server.csr" -CA "$dir/ca.crt" -CAkey "$ca_key" \
    -CAserial "$work/ca.srl" -out "$dir/public.crt" -days 3650 -sha256 -extfile "$work/ext.cnf"
  chmod 644 "$dir/ca.crt" "$dir/public.crt"
  rm -rf "$work"
}

unpack_key_bundle_if_needed() {
  if [ -f "$ENV_PRODUCTION" ] && [ -f "$INSTALL_ROOT/deploy/postgres.env" ]; then
    return 0
  fi
  local bundle pass dest raw tar_ok
  bundle=$(find "$INSTALL_ROOT/部署与恢复/灾备钥匙包" -name '当前站点环境变量-*.tar.enc' 2>/dev/null | head -n 1 || true)
  pass="$INSTALL_ROOT/部署与恢复/灾备钥匙包/01-备份口令/secrets-bundle-pass.txt"
  if [ -z "$bundle" ] || [ ! -s "$pass" ]; then
    echo "deploy/*.env missing. Put the five env files in deploy/, or copy 灾备钥匙包 into 部署与恢复/. This script will not generate platform keys." >&2
    exit 1
  fi
  dest=$(mktemp -d)
  raw=$(mktemp)
  umask 077
  if ! openssl enc -d -aes-256-cbc -pbkdf2 -in "$bundle" -pass file:"$pass" -out "$raw"; then
    rm -rf "$dest" "$raw"
    echo "failed to decrypt key bundle" >&2
    exit 1
  fi
  if gzip -t "$raw" 2>/dev/null; then
    tar_ok=0
    tar -xzf "$raw" -C "$dest" && tar_ok=1
  else
    tar_ok=0
    tar -xf "$raw" -C "$dest" && tar_ok=1
  fi
  rm -f "$raw"
  if [ "$tar_ok" -ne 1 ]; then
    rm -rf "$dest"
    echo "failed to unpack key bundle" >&2
    exit 1
  fi
  local name
  for name in production.env postgres.env object-store.env object-store-init.env compose.env; do
    if [ ! -f "$dest/$name" ]; then
      rm -rf "$dest"
      echo "key bundle did not contain $name" >&2
      exit 1
    fi
    install -m 600 "$dest/$name" "$INSTALL_ROOT/deploy/$name"
  done
  rm -rf "$dest"
  echo "key bundle unpacked into deploy/"
}

ensure_public_certificate() {
  if [ -f "/etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem" ]; then
    return 0
  fi
  echo "issuing Let's Encrypt certificate for ${AUTH_DOMAIN}"
  local extra=(--non-interactive --agree-tos --keep-until-expiring -d "$AUTH_DOMAIN")
  if [ -n "${CERTBOT_EMAIL:-}" ]; then
    extra+=(--email "$CERTBOT_EMAIL")
  else
    extra+=(--register-unsafely-without-email)
  fi
  if systemctl is-active nginx.service >/dev/null 2>&1 && python3 -c "import certbot_nginx" >/dev/null 2>&1; then
    certbot certonly --nginx "${extra[@]}"
  else
    systemctl stop nginx.service >/dev/null 2>&1 || true
    certbot certonly --standalone "${extra[@]}"
    systemctl start nginx.service >/dev/null 2>&1 || true
  fi
  if [ ! -f "/etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem" ]; then
    echo "certbot did not produce /etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem" >&2
    exit 1
  fi
}

ensure_env_kv() {
  local file="$1" key="$2" value="$3"
  if [ ! -f "$file" ]; then
    echo "missing env file: $file" >&2
    exit 1
  fi
  python3 - "$file" "$key" "$value" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
lines = path.read_text(encoding="utf-8").splitlines()
out = []
seen = False
for line in lines:
    if line.startswith(key + "="):
        if not seen:
            out.append(f"{key}={value}")
            seen = True
        continue
    out.append(line)
if not seen:
    if out and out[-1] != "":
        out.append("")
    out.append(f"{key}={value}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
}

ensure_auth_domain_in_env() {
  local file="$ENV_PRODUCTION"
  local origin="https://${AUTH_DOMAIN}"
  if [ ! -f "$file" ]; then
    echo "missing env file: $file" >&2
    exit 1
  fi
  python3 - "$file" "$AUTH_DOMAIN" "$origin" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
domain = sys.argv[2]
origin = sys.argv[3]
lines = path.read_text(encoding="utf-8").splitlines()
changed = False

def upsert(key: str, extra: str) -> None:
    global changed
    for index, line in enumerate(lines):
        if line.startswith(key + "="):
            parts = [item.strip() for item in line.split("=", 1)[1].split(",") if item.strip()]
            if extra not in parts:
                parts.append(extra)
                lines[index] = key + "=" + ",".join(parts)
                changed = True
            return
    lines.append(f"{key}={extra}")
    changed = True

upsert("ALLOWED_HOSTS", domain)
upsert("CSRF_TRUSTED_ORIGINS", origin)
if changed:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

require_runtime_files() {
  local f
  for f in \
    "$ENV_PRODUCTION" \
    "$ENV_COMPOSE" \
    "$INSTALL_ROOT/deploy/postgres.env" \
    "$INSTALL_ROOT/deploy/object-store.env" \
    "$INSTALL_ROOT/deploy/object-store-init.env" \
    "$INSTALL_ROOT/deploy/object-store-tls/ca.crt" \
    "$INSTALL_ROOT/deploy/object-store-tls/public.crt" \
    "$INSTALL_ROOT/deploy/object-store-tls/private.key" \
    "$INSTALL_ROOT/scripts/backup_proof_generator.py" \
    "$INSTALL_ROOT/scripts/backup_evidence_collector.py" \
    "$INSTALL_ROOT/scripts/backup_mark_success.py" \
    "$INSTALL_ROOT/docs/ui-preview/manage-login.html"
  do
    if [ ! -e "$f" ]; then
      echo "missing runtime file: $f" >&2
      exit 1
    fi
  done
  if grep -q 'replace-with' "$ENV_PRODUCTION"; then
    echo "production.env still has replace-with; inject the locked key bundle" >&2
    exit 1
  fi
  # 模板是唯一事实源。旧实现只在文件不存在时复制一次，于是模板里的任何改动
  # （例如给 app 服务加 healthcheck）永远落不到站上——2026-09-27 那次部署就是这样：
  # 站上跑的还是几个月前那份 compose，app 容器没有 healthcheck。现在每次装机都从
  # 模板刷新，旧文件留一份带时间戳的 .bak 以便回退。
  if [ -f "$COMPOSE_FILE" ] && ! cmp -s "$INSTALL_ROOT/deploy/docker-compose.production.yml.example" "$COMPOSE_FILE"; then
    cp -a "$COMPOSE_FILE" "${COMPOSE_FILE}.bak.$(date -u +%Y%m%d-%H%M%S)"
    echo "compose: refreshed from template (previous copy kept as .bak)"
  fi
  cp "$INSTALL_ROOT/deploy/docker-compose.production.yml.example" "$COMPOSE_FILE"
  if grep -q '^APP_HOST_PORT=' "$ENV_COMPOSE" && ! grep -q '^APP_HOST_PORT=18002$' "$ENV_COMPOSE"; then
    echo "compose.env APP_HOST_PORT must be 18002" >&2
    exit 1
  fi
  ensure_env_kv "$ENV_COMPOSE" APP_HOST_PORT 18002
  # Compose interpolation needs the host-side source path. The app receives
  # the fixed container path from docker-compose.production.yml.example.
  ensure_env_kv "$ENV_COMPOSE" BACKUP_ROOT "$BACKUP_ROOT"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_ROOT "$BACKUP_ROOT"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_DOWNLOAD_DIR "$BACKUP_ROOT/downloads"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_KEYS_DIR "$BACKUP_ROOT/keys"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_LOG_FILE "$BACKUP_ROOT/backup.log"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_STATUS_FILE "$BACKUP_ROOT/backup-status.json"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_SCHEDULE_STAMP_DIR "$BACKUP_ROOT/backup-stamps"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_DUMP_PASS_FILE "$BACKUP_DUMP_PASS_FILE"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_PROOF_FILE "$BACKUP_ROOT/backup-proof.json"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_PROOF_GENERATOR "$INSTALL_ROOT/scripts/backup_proof_generator.py"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_EVIDENCE_COLLECTOR "$INSTALL_ROOT/scripts/backup_evidence_collector.py"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_MIGRATION_GRAPH_FILE "$BACKUP_ROOT/migration-graph.json"
  local deployed_commit
  deployed_commit=$(git -C "$INSTALL_ROOT" rev-parse HEAD 2>/dev/null || true)
  if [ -z "$deployed_commit" ]; then
    deployed_commit=$(awk -F= '$1 == "BACKUP_CANDIDATE_COMMIT" { print substr($0, index($0, "=") + 1); exit }' "$ENV_PRODUCTION" | tr -d '\r')
  fi
  case "$deployed_commit" in
    ''|replace-with-*|unknown)
      echo "BACKUP_CANDIDATE_COMMIT must be injected for a non-git candidate tree" >&2
      exit 1
      ;;
  esac
  # A git commit alone is not the deployed version: the tree may have
  # uncommitted edits, in which case the recorded commit points at bytes that
  # were never deployed.  Mark it dirty and record a content fingerprint of the
  # code that actually runs, so backup/restore audit can tell the two apart.
  #
  # This is an audit annotation only: it must never abort an install, so the
  # whole computation is wrapped to tolerate failure under `set -euo pipefail`.
  local tree_sha dirty_marker
  tree_sha=""
  if tree_sha=$(cd "$INSTALL_ROOT" && find src deploy manage.py requirements.lock -type f \
      ! -name '*.pyc' ! -path '*__pycache__*' -print0 \
      | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}') 2>/dev/null; then
    :
  else
    tree_sha=""
  fi
  case "$tree_sha" in
    ''|*[!0-9a-f]*) tree_sha="unknown" ;;
  esac
  if [ -n "$(git -C "$INSTALL_ROOT" status --porcelain 2>/dev/null || true)" ]; then
    dirty_marker="-dirty"
  else
    dirty_marker=""
  fi
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_CANDIDATE_COMMIT "${deployed_commit}${dirty_marker}"
  ensure_env_kv "$ENV_PRODUCTION" BACKUP_CANDIDATE_TREE_SHA256 "$tree_sha"
  echo "deployed-version: ${deployed_commit}${dirty_marker} tree-sha256=${tree_sha}"
  ensure_env_kv "$ENV_PRODUCTION" AUTHORIZATION_PLATFORM_MANAGE "$INSTALL_ROOT/manage.py"
  chmod 700 "$INSTALL_ROOT/deploy/install-site.sh" 2>/dev/null || true
}

enable_boot_services() {
  systemctl enable --now docker.service
  systemctl enable --now nginx.service
  systemctl enable --now certbot.timer
}

start_stack() {
  compose up -d --build
  local i status code
  for i in $(seq 1 90); do
    status=$(docker inspect -f '{{.State.Status}}' "$APP_CONTAINER" 2>/dev/null || true)
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: ${AUTH_DOMAIN}" http://127.0.0.1:18002/healthz/ || true)
    if [ "$status" = "running" ] && { [ "$code" = "200" ] || [ "$code" = "301" ]; }; then
      return 0
    fi
    sleep 2
  done
  echo "app container did not become ready on 127.0.0.1:18002: status=${status:-down} healthz=${code:-none}" >&2
  exit 1
}

install_python_bridge() {
  cat > /usr/local/sbin/ap-py.sh <<'EOS'
#!/bin/bash
set -euo pipefail
if [ "${1:-}" = "-c" ]; then
  exec python3 "$@"
fi
case "${1:-}" in
  *manage.py)
    shift
    : "${AUTHORIZATION_PLATFORM_COMPOSE_FILE:?AUTHORIZATION_PLATFORM_COMPOSE_FILE is required}"
    : "${AUTHORIZATION_PLATFORM_COMPOSE_ENV_FILE:?AUTHORIZATION_PLATFORM_COMPOSE_ENV_FILE is required}"
    : "${AUTHORIZATION_PLATFORM_COMPOSE_PROJECT:?AUTHORIZATION_PLATFORM_COMPOSE_PROJECT is required}"
    exec docker compose \
      -f "$AUTHORIZATION_PLATFORM_COMPOSE_FILE" \
      --env-file "$AUTHORIZATION_PLATFORM_COMPOSE_ENV_FILE" \
      -p "$AUTHORIZATION_PLATFORM_COMPOSE_PROJECT" \
      exec -T app python manage.py "$@"
    ;;
esac
exec python3 "$@"
EOS
  chmod 700 /usr/local/sbin/ap-py.sh
}

install_backup_environment() {
  cat > /usr/local/sbin/ap-backup-env.sh <<EOS
#!/bin/bash
set -euo pipefail
if [ ! -f "${ENV_PRODUCTION}" ]; then
  echo "production.env missing: ${ENV_PRODUCTION}" >&2
  exit 1
fi
set -a
. "${ENV_PRODUCTION}"
set +a
export PYTHON_BIN=/usr/local/sbin/ap-py.sh
export AUTHORIZATION_PLATFORM_MANAGE="${INSTALL_ROOT}/manage.py"
export AUTHORIZATION_PLATFORM_DB_CONTAINER="${DB_CONTAINER}"
export AUTHORIZATION_PLATFORM_COMPOSE_FILE="${COMPOSE_FILE}"
export AUTHORIZATION_PLATFORM_COMPOSE_ENV_FILE="${ENV_COMPOSE}"
export AUTHORIZATION_PLATFORM_COMPOSE_PROJECT="${COMPOSE_PROJECT}"
export BACKUP_PROOF_GENERATOR="${INSTALL_ROOT}/scripts/backup_proof_generator.py"
export BACKUP_EVIDENCE_COLLECTOR="${INSTALL_ROOT}/scripts/backup_evidence_collector.py"
export BACKUP_RUNNER_SH="${INSTALL_ROOT}/deploy/backup/backup_runner.sh"
export BACKUP_FULL_RUNNER_SH="${INSTALL_ROOT}/deploy/backup/backup-full.sh"
export BACKUP_DIFF_RUNNER_SH="${INSTALL_ROOT}/deploy/backup/backup-diff.sh"
export BACKUP_INCLUDE_SECRETS_CODE=0
export BACKUP_KEYS_DIR="${BACKUP_ROOT}/keys"
export BACKUP_DOWNLOAD_DIR="${BACKUP_ROOT}/downloads"
export BACKUP_PROOF_FILE="${BACKUP_ROOT}/backup-proof.json"
export BACKUP_MIGRATION_GRAPH_FILE="${BACKUP_ROOT}/migration-graph.json"
export BACKUP_DUMP_PASS_FILE="${BACKUP_DUMP_PASS_FILE}"
if [ -z "\${BACKUP_CANDIDATE_COMMIT:-}" ]; then
  BACKUP_CANDIDATE_COMMIT=\$(git -C "${INSTALL_ROOT}" rev-parse HEAD 2>/dev/null || true)
fi
export BACKUP_CANDIDATE_COMMIT
export BACKUP_KEY_VERSIONS=license-card:v2,quota-card:v2
export BACKUP_OBJECT_STORAGE_LIST="${INSTALL_ROOT}/deploy/backup/ap-object-list.sh"
export BACKUP_ROOT="${BACKUP_ROOT}"
export BACKUP_LOG_FILE="${BACKUP_ROOT}/backup.log"
export BACKUP_SCHEDULE_STAMP_DIR="${BACKUP_ROOT}/backup-stamps"
export BACKUP_GITHUB_WORK_DIR="${BACKUP_ROOT}/github-sync"
export BACKUP_STATUS_FILE="${BACKUP_ROOT}/backup-status.json"
EOS
  chmod 700 /usr/local/sbin/ap-backup-env.sh
}

install_decide() {
  install_backup_environment
  cat > /usr/local/sbin/ap-backup-full-decide.sh <<EOS
#!/bin/bash
set -euo pipefail
source /usr/local/sbin/ap-backup-env.sh
umask 077
exec /usr/local/sbin/ap-backup-dispatch.sh
EOS
  chmod 700 /usr/local/sbin/ap-backup-full-decide.sh

  cat > /usr/local/sbin/ap-backup-schedule.sh <<EOS
#!/bin/bash
set -euo pipefail
source /usr/local/sbin/ap-backup-env.sh
exec "\$PYTHON_BIN" "\$AUTHORIZATION_PLATFORM_MANAGE" backup_policy --schedule
EOS
  chmod 700 /usr/local/sbin/ap-backup-schedule.sh

  cat > /usr/local/sbin/ap-backup-dispatch.sh <<EOS
#!/bin/bash
set -euo pipefail
source /usr/local/sbin/ap-backup-env.sh
exec /bin/bash "${INSTALL_ROOT}/deploy/backup/backup-dispatch.sh" "\$@"
EOS
  chmod 700 /usr/local/sbin/ap-backup-dispatch.sh
}

install_backup_systemd() {
  install -m 700 "${INSTALL_ROOT}/deploy/backup/backup_alert.sh" /usr/local/sbin/authorization-platform-backup-alert
  cat > /etc/systemd/system/authorization-platform-backup-failure.service <<EOS
[Unit]
Description=Record Authorization Platform backup failure for external alerting

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
EnvironmentFile=${ENV_PRODUCTION}
Environment=BACKUP_KEYS_DIR=${BACKUP_ROOT}/keys
Environment=BACKUP_DUMP_PASS_FILE=${BACKUP_DUMP_PASS_FILE}
Environment=BACKUP_STATUS_FILE=${BACKUP_ROOT}/backup-status.json
ExecStart=/usr/bin/python3 ${INSTALL_ROOT}/scripts/backup_health.py record-failure --status-file ${BACKUP_ROOT}/backup-status.json --reason-code backup_service_failed
ExecStartPost=/usr/bin/python3 ${INSTALL_ROOT}/scripts/backup_failure_alert.py --status-file ${BACKUP_ROOT}/backup-status.json --handler /usr/local/sbin/authorization-platform-backup-alert --reason-code backup_service_failed
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=${BACKUP_ROOT}
EOS
  cat > /etc/systemd/system/authorization-platform-backup-full.service <<EOS
[Unit]
Description=Authorization Platform change-triggered backup
Wants=network-online.target docker.service
After=network-online.target docker.service
OnFailure=authorization-platform-backup-failure.service

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
TimeoutStartSec=7200
EnvironmentFile=${ENV_PRODUCTION}
Environment=BACKUP_DUMP_PASS_FILE=${BACKUP_DUMP_PASS_FILE}
ExecStart=/usr/local/sbin/ap-backup-dispatch.sh
ExecStartPost=-/usr/bin/python3 ${INSTALL_ROOT}/scripts/backup_mark_success.py --status-file ${BACKUP_ROOT}/backup-status.json --proof-file ${BACKUP_ROOT}/backup-proof.json --run-id-file ${BACKUP_ROOT}/current-run-id --skip-sentinel ${BACKUP_ROOT}/backup-stamps/last-exec-skipped

[Install]
WantedBy=multi-user.target
EOS

  cat > /etc/systemd/system/authorization-platform-backup-schedule.service <<EOS
[Unit]
Description=Schedule Authorization Platform backups from the saved policy
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
TimeoutStartSec=300
ExecStart=/usr/local/sbin/ap-backup-schedule.sh

[Install]
WantedBy=multi-user.target
EOS

  cat > /etc/systemd/system/authorization-platform-backup-schedule.timer <<'EOS'
[Unit]
Description=Poll Authorization Platform backup schedule every fifteen minutes

[Timer]
OnCalendar=*-*-* *:0/15:00 Asia/Shanghai
AccuracySec=1min
Persistent=true
Unit=authorization-platform-backup-schedule.service

[Install]
WantedBy=timers.target
EOS

  cat > /etc/systemd/system/authorization-platform-backup-full.path <<EOS
[Unit]
Description=Start backup when the app marks a ledger change

[Path]
PathExists=${BACKUP_ROOT}/queue/need-run
PathModified=${BACKUP_ROOT}/queue/need-run
Unit=authorization-platform-backup-full.service

[Install]
WantedBy=multi-user.target
EOS

  mkdir -p /etc/systemd/system/authorization-platform-backup-full.service.d
  rm -f /etc/systemd/system/authorization-platform-backup-full.service.d/decide.conf
  systemctl daemon-reload
  systemctl disable --now authorization-platform-backup-full.timer authorization-platform-backup-diff.timer authorization-platform-backup.timer authorization-platform-backup.service authorization-platform-backup-diff.service authorization-platform-backup-schedule.timer authorization-platform-backup-schedule.service >/dev/null 2>&1 || true
}

activate_backup_triggers() {
  systemctl daemon-reload
  systemctl enable --now authorization-platform-backup-full.path
  systemctl enable --now authorization-platform-backup-schedule.timer
}

install_maintenance() {
  touch /var/log/authorization-platform-maintenance.log
  chmod 640 /var/log/authorization-platform-maintenance.log
  cat > /etc/systemd/system/authorization-platform-maintenance.service <<EOS
[Unit]
Description=Authorization Platform hourly session cleanup
After=docker.service

[Service]
Type=oneshot
Environment=AUTHORIZATION_PLATFORM_APP_CONTAINER=${APP_CONTAINER}
Environment=AUTHORIZATION_PLATFORM_DB_CONTAINER=${DB_CONTAINER}
Environment=BACKUP_LOG_FILE=${BACKUP_ROOT}/backup.log
ExecStart=/bin/bash ${INSTALL_ROOT}/deploy/backup/maintenance.sh
EOS
  cat > /etc/systemd/system/authorization-platform-maintenance.timer <<'EOS'
[Unit]
Description=Hourly Authorization Platform maintenance

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=10m
Unit=authorization-platform-maintenance.service

[Install]
WantedBy=timers.target
EOS
  systemctl daemon-reload
  systemctl enable --now authorization-platform-maintenance.timer
}

install_app_guard() {
  command -v docker >/dev/null 2>&1 || { echo 'host tool missing: docker' >&2; exit 1; }
  cat > /etc/systemd/system/authorization-platform-app-guard.service <<EOS
[Unit]
Description=Authorization Platform app container guard (reconcile running state, restart a wedged app)
Wants=docker.service network-online.target
After=docker.service network-online.target

[Service]
Type=oneshot
Environment=APP_GUARD_COMPOSE_FILE=${INSTALL_ROOT}/deploy/docker-compose.production.yml
Environment=APP_GUARD_ENV_FILE=${INSTALL_ROOT}/deploy/compose.env
Environment=APP_GUARD_PROJECT=${COMPOSE_PROJECT}
Environment=APP_GUARD_SERVICE=app
ExecStart=/usr/bin/env bash ${INSTALL_ROOT}/deploy/backup/app_guard.sh
EOS
  cat > /etc/systemd/system/authorization-platform-app-guard.timer <<'EOS'
[Unit]
Description=Reconcile Authorization Platform app container every 90 seconds

[Timer]
OnBootSec=2min
OnUnitActiveSec=90s
Unit=authorization-platform-app-guard.service

[Install]
WantedBy=timers.target
EOS
  systemctl daemon-reload
  systemctl enable --now authorization-platform-app-guard.timer
}

# logrotate 的退出码会把"环境问题"混进来：Ubuntu 的 /var/log 是 world-writable 的
# sticky 目录，没有 su 时它会对 /var/log 下的文件报权限告警并返回非 0——那是环境，
# 不是这份配置能不能解析。所以这里只把真正的解析错误当失败，否则会把一次完全正确的
# 装机挡下来。
logrotate_stanza_parses() {
  local target="$1" output
  output=$(logrotate --debug "$target" 2>&1 || true)
  if printf '%s' "$output" | grep -qE 'lines must begin with|found error in|unknown option|bad rotation count|duplicate log entry'; then
    return 1
  fi
  return 0
}

install_logrotate() {
  local template="$INSTALL_ROOT/deploy/logrotate/authorization-platform.example"
  if [ ! -f "$template" ]; then
    echo "logrotate template missing: $template" >&2
    exit 1
  fi
  # A CRLF copy of this stanza makes logrotate parse every directive as a
  # malformed keyword, so the whole nightly rotation aborts.  That happened in
  # production on 2026-09-25 and the old verify only grepped for a filename, so
  # it reported "logrotate: ok" while logrotate.service failed every night.
  if LC_ALL=C grep -q $'\r' "$template"; then
    echo "logrotate template must be LF-only (found a CR byte): $template" >&2
    exit 1
  fi
  install -m 644 "$template" /etc/logrotate.d/authorization-platform
  if ! logrotate_stanza_parses /etc/logrotate.d/authorization-platform; then
    echo "logrotate cannot parse the stanza just installed; refusing to continue" >&2
    logrotate --debug /etc/logrotate.d/authorization-platform || true
    exit 1
  fi
}

install_nginx() {
  if [ ! -f "$NGINX_TEMPLATE" ]; then
    echo "nginx template missing: $NGINX_TEMPLATE" >&2
    exit 1
  fi
  if [ ! -f "/etc/letsencrypt/live/${AUTH_DOMAIN}/fullchain.pem" ]; then
    echo "TLS cert missing for ${AUTH_DOMAIN} after ensure_public_certificate" >&2
    exit 1
  fi
  local tmp
  tmp=$(mktemp)
  sed -e "s|__AUTH_DOMAIN__|${AUTH_DOMAIN}|g" \
      -e "s|__UI_ROOT__|${INSTALL_ROOT}/docs/ui-preview|g" \
      -e "s|127.0.0.1:8000|127.0.0.1:18002|g" \
      "$NGINX_TEMPLATE" > "$tmp"
  sed -i 's/\r$//' "$tmp"
  if ! grep -q 'client_max_body_size 120m' "$tmp"; then
    echo "nginx template missing client_max_body_size 120m" >&2
    rm -f "$tmp"
    exit 1
  fi
  if ! grep -q "server_name ${AUTH_DOMAIN};" "$tmp"; then
    echo "nginx template did not bind ${AUTH_DOMAIN}" >&2
    rm -f "$tmp"
    exit 1
  fi
  install -m 644 "$tmp" "$NGINX_SITE"
  rm -f "$tmp"
  ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/authorization-platform-${AUTH_DOMAIN}.conf
  nginx -t
  nginx -s reload
}

prepare_backup_dirs() {
  mkdir -p "$BACKUP_ROOT/queue" "$BACKUP_ROOT/downloads" "$BACKUP_ROOT/backup-stamps" "$BACKUP_ROOT/github-sync" "$BACKUP_ROOT/evidence" "$BACKUP_ROOT/keys" "$(dirname "$BACKUP_DUMP_PASS_FILE")"
  chown -R root:10001 "$BACKUP_ROOT/keys"
  chown root:10001 "$BACKUP_ROOT" "$BACKUP_ROOT/downloads" "$BACKUP_ROOT/queue"
  chown root:10001 "$BACKUP_ROOT/backup-stamps"
  chown root:root "$(dirname "$BACKUP_DUMP_PASS_FILE")"
  chmod 750 "$BACKUP_ROOT"
  chmod 770 "$BACKUP_ROOT/downloads" "$BACKUP_ROOT/queue" "$BACKUP_ROOT/keys"
  chmod 750 "$BACKUP_ROOT/backup-stamps"
  chmod 700 "$BACKUP_ROOT/github-sync"
  chmod 700 "$(dirname "$BACKUP_DUMP_PASS_FILE")"
  find "$BACKUP_ROOT/keys" -type f -exec chmod 660 {} + 2>/dev/null || true
  find "$BACKUP_ROOT/keys" -type f -exec chown root:10001 {} + 2>/dev/null || true
  local pass_src=""
  local candidate
  for candidate in \
    "$KEYS_SRC/github-dump-pass.txt" \
    "$INSTALL_ROOT/部署与恢复/灾备钥匙包/01-备份口令/github-dump-pass.txt"
  do
    if [ -s "$candidate" ]; then
      pass_src=$candidate
      break
    fi
  done
  if [ -n "$pass_src" ]; then
    install -m 600 -o root -g root "$pass_src" "$BACKUP_DUMP_PASS_FILE"
  fi
  if [ ! -s "$BACKUP_DUMP_PASS_FILE" ]; then
    echo "dump pass missing or empty: github-dump-pass.txt must be injected before starting services" >&2
    exit 1
  fi
}

run_migrations() {
  compose_exec python manage.py migrate --noinput
  compose_exec python manage.py createcachetable
}

write_migration_graph() {
  local plan_temporary graph_temporary
  plan_temporary=$(mktemp "$BACKUP_ROOT/.migration-plan.XXXXXX")
  graph_temporary=$(mktemp "$BACKUP_ROOT/.migration-graph.XXXXXX")
  if ! compose_exec python manage.py showmigrations --plan > "$plan_temporary"; then
    rm -f -- "$plan_temporary" "$graph_temporary"
    echo "could not write migration graph" >&2
    exit 1
  fi
  if [ ! -s "$plan_temporary" ]; then
    rm -f -- "$plan_temporary" "$graph_temporary"
    echo "migration graph is empty" >&2
    exit 1
  fi
  if ! python3 - "$plan_temporary" "$graph_temporary" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

plan_path = Path(sys.argv[1])
graph_path = Path(sys.argv[2])
lines = [line.rstrip() for line in plan_path.read_text(encoding="utf-8").splitlines() if line.strip()]
if not lines:
    raise SystemExit("migration graph is empty")
graph_path.write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "migration_plan": lines,
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY
  then
    rm -f -- "$plan_temporary" "$graph_temporary"
    echo "could not serialize migration graph" >&2
    exit 1
  fi
  rm -f -- "$plan_temporary"
  chown root:10001 "$graph_temporary"
  chmod 640 "$graph_temporary"
  mv -f -- "$graph_temporary" "$BACKUP_ROOT/migration-graph.json"
}

ensure_admin() {
  local count
  count=$(compose_exec python manage.py shell -c "from django.contrib.auth import get_user_model; print('ADMIN_COUNT='+str(get_user_model().objects.filter(is_superuser=True).count()))" | grep '^ADMIN_COUNT=' | tail -n 1 | cut -d= -f2)
  if [ "${count:-0}" = "0" ]; then
    local pass
    pass=$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)
    umask 077
    printf 'username admin\npassword %s\nchange-after-login yes\n' "$pass" > "$ADMIN_PASS_FILE"
    chmod 600 "$ADMIN_PASS_FILE"
    compose exec -T \
      -e DJANGO_SUPERUSER_USERNAME=admin \
      -e DJANGO_SUPERUSER_EMAIL="admin@${AUTH_DOMAIN}" \
      -e DJANGO_SUPERUSER_PASSWORD="$pass" \
      app python manage.py createsuperuser --noinput --email "admin@${AUTH_DOMAIN}"
    echo 'admin: created'
  else
    echo 'admin: exists'
  fi
  compose_exec python manage.py shell -c "
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
g, _ = Group.objects.get_or_create(name='platform_admin')
u = get_user_model().objects.filter(is_superuser=True).order_by('id').first()
if u is None:
    raise SystemExit('no superuser after ensure_admin')
u.groups.add(g)
print('admin_group_ok')
"
}

align_policy_for_docker() {
  # 这套 Docker 部署没有 pgBackRest：deploy/pgbackrest/ 不在仓库里，compose 用的
  # 是原版 postgres:17-alpine，不带该二进制。database_enabled 留着 True 的话，
  # deploy/backup/backup-full.sh 会去执行 pgbackrest 并失败，所以必须强制关掉。
  #
  # 但它以前是**静默**的：主人在页面上勾上开关，下次更新就被无声改回去，页面上只
  # 显示"已关闭"，不提示是装脚本关的。保留这个行为，但必须出声。
  local output
  output=$(compose_exec python manage.py shell -c "
from authorization_platform.backup_control.models import BackupPolicy
p, created = BackupPolicy.objects.get_or_create(key='default')
if p.database_enabled:
    p.database_enabled = False
    p.save()
    print('policy-database-enabled-reset-by-installer')
print('created', created)
print('enabled', p.enabled)
print('schedule_enabled', p.schedule_enabled)
print('database_enabled', p.database_enabled)
print('github_enabled', p.github_enabled)
")
  printf '%s\n' "$output"
  if printf '%s' "$output" | grep -q 'policy-database-enabled-reset-by-installer'; then
    echo 'WARNING: 备份策略的「PostgreSQL 双仓库」开关被装机脚本关掉了（这套部署没有 pgBackRest 仓库）。管理端页面上看不到这个原因。' >&2
  fi
}

verify_site() {
  local fail=0
  echo '=== verify-site ==='
  local u
  for u in docker.service nginx.service certbot.timer authorization-platform-backup-full.path authorization-platform-backup-schedule.timer authorization-platform-maintenance.timer authorization-platform-app-guard.timer; do
    if systemctl is-enabled "$u" >/dev/null 2>&1; then
      echo "$u: enabled"
    else
      echo "$u: NOT_ENABLED"
      fail=1
    fi
    if systemctl is-active "$u" >/dev/null 2>&1; then
      echo "$u: active"
    else
      echo "$u: NOT_ACTIVE"
      fail=1
    fi
  done
  local old_timer
  for old_timer in authorization-platform-backup-full.timer authorization-platform-backup-diff.timer; do
    if systemctl is-enabled "$old_timer" >/dev/null 2>&1 || systemctl is-active "$old_timer" >/dev/null 2>&1; then
      echo "$old_timer: ENABLED_OR_ACTIVE_BUT_MUST_STAY_DISABLED"
      fail=1
    else
      echo "$old_timer: disabled"
    fi
  done
  if [ -x /usr/local/sbin/ap-py.sh ] \
    && [ -x /usr/local/sbin/ap-backup-full-decide.sh ] \
    && [ -x /usr/local/sbin/ap-backup-dispatch.sh ] \
    && [ -x /usr/local/sbin/ap-backup-schedule.sh ]; then
    echo 'host-scripts: ok'
  else
    echo 'host-scripts: MISSING'
    fail=1
  fi
  if grep -q $'\r' "$INSTALL_ROOT/deploy/backup/backup-full.sh" >/dev/null 2>&1; then
    echo 'backup-full.sh: CRLF'
    fail=1
  else
    echo 'backup-full.sh: lf'
  fi
  if [ -x "$INSTALL_ROOT/deploy/backup/ap-object-list.sh" ]; then
    echo 'ap-object-list: executable'
  else
    echo 'ap-object-list: NOT_EXECUTABLE'
    fail=1
  fi
  if find "$INSTALL_ROOT/deploy/backup" -type f -name '*.sh' ! -perm 700 | grep -q .; then
    echo 'backup-scripts: NOT_ALL_700'
    fail=1
  else
    echo 'backup-scripts: 700'
  fi
  if grep -q 'datetime.now(timezone.utc)' "$INSTALL_ROOT/deploy/backup/backup-host-lib.sh" \
    && grep -q 'STAMP_DIR/last-\$RUN_TYPE' "$INSTALL_ROOT/deploy/backup/backup-host-lib.sh" \
    && ! grep -q -- '--mark-schedule' "$INSTALL_ROOT/deploy/backup/backup-host-lib.sh"; then
    stamp_probe=$(mktemp -d /tmp/ap-stamp-write-probe.XXXXXX)
    if python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())' > "$stamp_probe/last-full" \
      && [ -s "$stamp_probe/last-full" ]; then
      echo 'stamp-write: host'
    else
      echo 'stamp-write: HOST_PYTHON_FAILED'
      fail=1
    fi
    rm -rf "$stamp_probe"
  else
    echo 'stamp-write: DOCKER_OR_MISSING'
    fail=1
  fi
  local stamp_mode stamp_owner
  stamp_mode=$(stat -c '%a' "$BACKUP_ROOT/backup-stamps" 2>/dev/null || true)
  stamp_owner=$(stat -c '%u:%g' "$BACKUP_ROOT/backup-stamps" 2>/dev/null || true)
  if [ "$stamp_mode" = "750" ] && [ "$stamp_owner" = "0:10001" ]; then
    echo 'stamp-dir: root-write-app-read'
  else
    echo "stamp-dir: WRONG_PERMISSIONS mode=${stamp_mode:-missing} owner=${stamp_owner:-missing}"
    fail=1
  fi
  systemctl reset-failed authorization-platform-backup-full.service >/dev/null 2>&1 || true
  if grep -q '^APP_HOST_PORT=18002$' "$ENV_COMPOSE"; then
    echo 'APP_HOST_PORT: 18002'
  else
    echo 'APP_HOST_PORT: NOT_18002'
    fail=1
  fi
  if grep -q 'replace-with' "$ENV_PRODUCTION"; then
    echo 'production.env: HAS_REPLACE_WITH'
    fail=1
  else
    echo 'production.env: ok'
  fi
  if grep -q "^BACKUP_ROOT=${BACKUP_ROOT}$" "$ENV_PRODUCTION" && grep -q "^BACKUP_DOWNLOAD_DIR=${BACKUP_ROOT}/downloads$" "$ENV_PRODUCTION"; then
    echo 'BACKUP_ROOT: ok'
  else
    echo 'BACKUP_ROOT: MISSING_OR_WRONG'
    fail=1
  fi
  if grep -q "$AUTH_DOMAIN" "$ENV_PRODUCTION"; then
    echo 'ALLOWED_HOSTS: domain present'
  else
    echo 'ALLOWED_HOSTS: DOMAIN_MISSING'
    fail=1
  fi
  for f in ca.crt public.crt private.key; do
    if [ -s "$INSTALL_ROOT/deploy/object-store-tls/$f" ]; then
      echo "tls/$f: ok"
    else
      echo "tls/$f: MISSING"
      fail=1
    fi
  done
  local dump_pass_mode dump_pass_owner
  dump_pass_mode=$(stat -c '%a' "$BACKUP_DUMP_PASS_FILE" 2>/dev/null || true)
  dump_pass_owner=$(stat -c '%u:%g' "$BACKUP_DUMP_PASS_FILE" 2>/dev/null || true)
  if [ -s "$BACKUP_DUMP_PASS_FILE" ] && [ ! -L "$BACKUP_DUMP_PASS_FILE" ] && [ "$dump_pass_mode" = "600" ] && [ "$dump_pass_owner" = "0:0" ]; then
    echo 'dump_pass: ok'
  else
    echo 'dump_pass: MISSING'
    fail=1
  fi
  if [ -s "$BACKUP_ROOT/migration-graph.json" ] && [ ! -L "$BACKUP_ROOT/migration-graph.json" ]; then
    echo 'migration-graph: ok'
  else
    echo 'migration-graph: MISSING'
    fail=1
  fi
  # Presence is not evidence: the previous check only grepped for a filename and
  # passed a stanza that logrotate could not parse.  Require a clean parse --
  # but only a real parse error counts (see logrotate_stanza_parses).
  if [ -s /etc/logrotate.d/authorization-platform ] &&
     ! LC_ALL=C grep -q $'\r' /etc/logrotate.d/authorization-platform &&
     logrotate_stanza_parses /etc/logrotate.d/authorization-platform; then
    echo 'logrotate: ok'
  else
    echo 'logrotate: MISSING_OR_UNPARSEABLE'
    fail=1
  fi
  if grep -q 'client_max_body_size 120m' "$NGINX_SITE" && grep -q 'proxy_read_timeout 600s' "$NGINX_SITE"; then
    echo 'nginx-upload: ok'
  else
    echo 'nginx-upload: MISSING_LIMITS'
    fail=1
  fi
  if ss -lnt | grep -q '127.0.0.1:18002'; then
    echo 'bind: 127.0.0.1:18002'
  else
    echo 'bind: 18002_NOT_LOOPBACK'
    fail=1
  fi
  if docker inspect "$APP_CONTAINER" >/dev/null 2>&1; then
    local restore
    restore=$(docker exec "$APP_CONTAINER" pg_restore --version || true)
    echo "pg_restore: $restore"
    echo "$restore" | grep -q '17' || { echo 'pg_restore: NOT_17'; fail=1; }
  else
    echo 'app container: DOWN'
    fail=1
  fi
  local root_code health_code login_code manage_code down_code css_code session_code activate_code
  root_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/" -H "Host: $AUTH_DOMAIN" || true)
  health_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/healthz/" -H "Host: $AUTH_DOMAIN" || true)
  login_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/manage-login.html" -H "Host: $AUTH_DOMAIN" || true)
  manage_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/manage.html" -H "Host: $AUTH_DOMAIN" || true)
  down_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/downstream-login.html" -H "Host: $AUTH_DOMAIN" || true)
  css_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/preview.css" -H "Host: $AUTH_DOMAIN" || true)
  session_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/api/v1/session/" -H "Host: $AUTH_DOMAIN" || true)
  activate_code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/api/v1/public/licenses/activate" -H "Host: $AUTH_DOMAIN" || true)
  echo "root:$root_code healthz:$health_code login:$login_code manage:$manage_code downstream:$down_code css:$css_code session:$session_code activate:$activate_code"
  [ "$root_code" = 404 ] || { echo 'root: NOT_404'; fail=1; }
  [ "$health_code" = 200 ] || { echo 'healthz: NOT_200'; fail=1; }
  [ "$login_code" = 200 ] || { echo 'login: NOT_200'; fail=1; }
  [ "$manage_code" = 200 ] || { echo 'manage: NOT_200'; fail=1; }
  [ "$down_code" = 200 ] || { echo 'downstream: NOT_200'; fail=1; }
  [ "$css_code" = 200 ] || { echo 'css: NOT_200'; fail=1; }
  [ "$session_code" = 200 ] || { echo 'session: NOT_200'; fail=1; }
  [ "$activate_code" = 405 ] || { echo 'activate: NOT_405'; fail=1; }
  if curl -sk "https://127.0.0.1/" -H "Host: $AUTH_DOMAIN" | grep -q 'manage-login'; then
    echo 'root-404: LEAKS_MANAGE_LOGIN'
    fail=1
  else
    echo 'root-404: no manage-login'
  fi
  if crontab -l 2>/dev/null | grep -E 'backup-full\.sh|backup-diff\.sh' >/dev/null; then
    echo 'crontab: LEFTOVER_BACKUP_JOB'
    fail=1
  else
    echo 'crontab: no leftover backup job'
  fi
  if docker inspect "$APP_CONTAINER" >/dev/null 2>&1; then
    local admin_count cache_table enabled
    admin_count=$(compose_exec python manage.py shell -c "from django.contrib.auth import get_user_model; print('ADMIN_COUNT='+str(get_user_model().objects.filter(is_superuser=True).count()))" | grep '^ADMIN_COUNT=' | tail -n 1 | cut -d= -f2)
    cache_table=$(compose_exec python manage.py shell -c "from django.db import connection; print('CACHE_TABLE='+str('django_cache' in connection.introspection.table_names()))" | grep '^CACHE_TABLE=' | tail -n 1 | cut -d= -f2)
    enabled=$(compose_exec python manage.py shell -c "from authorization_platform.backup_control.models import BackupPolicy; p=BackupPolicy.objects.filter(key='default').first(); print('POLICY_ENABLED='+str(bool(p and p.enabled)))" | grep '^POLICY_ENABLED=' | tail -n 1 | cut -d= -f2)
    [ "$admin_count" != "0" ] || { echo 'admin: MISSING'; fail=1; }
    [ "$cache_table" = "True" ] || { echo 'cache_table: MISSING'; fail=1; }
    echo "admin_count:$admin_count cache_table:$cache_table backup_enabled:$enabled"
  fi
  if [ "$fail" -ne 0 ]; then
    echo 'VERIFY_FAIL'
    return 1
  fi
  echo 'VERIFY_OK'
}

if [ "$VERIFY_ONLY" = 1 ]; then
  validate_install_config
  verify_site
  exit $?
fi

strip_crlf
validate_install_config
install_host_packages
require_host_tools
unpack_key_bundle_if_needed
ensure_auth_domain_in_env
ensure_object_store_tls
require_runtime_files
enable_boot_services
prepare_backup_dirs
install_python_bridge
install_decide
install_backup_systemd
install_maintenance
install_app_guard
install_logrotate
ensure_public_certificate
install_nginx
systemctl stop authorization-platform-app-guard.timer >/dev/null 2>&1 || true
start_stack
run_migrations
write_migration_graph
ensure_admin
align_policy_for_docker
systemctl enable --now authorization-platform-app-guard.timer >/dev/null 2>&1 || true
activate_backup_triggers
verify_site
