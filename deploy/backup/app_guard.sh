#!/usr/bin/env bash
# 应用容器守卫。
#
# 旧行为只有一个 `docker compose up -d app`：容器不在就拉起来，容器在就什么
# 都不做。结果是 gunicorn 假死（进程活着，但每个请求都 500 或超时）永远不会被
# 发现 —— restart: unless-stopped 只对进程退出有反应。
#
# 两条不能违反的约束：
#  1) 迁移窗口不是故障。/healthz/ 在有未应用迁移时返回 503，而 install-site.sh
#     是先起容器再跑迁移，所以那一段必然红。此时绝不重启，否则会变成
#     "迁移中 → 503 → 重启 → 迁移再失败" 的循环。
#  2) 重启必须有节制。连续失败时每 90 秒重启一次只会让站点更坏。
set -euo pipefail

COMPOSE_FILE=${APP_GUARD_COMPOSE_FILE:-}
ENV_FILE=${APP_GUARD_ENV_FILE:-}
PROJECT=${APP_GUARD_PROJECT:-}
SERVICE=${APP_GUARD_SERVICE:-app}
LOG=${APP_GUARD_LOG:-/var/log/authorization-platform-app-guard.log}
STATE_FILE=${APP_GUARD_STATE_FILE:-/var/lib/authorization-platform-backup/app-guard.state}
COOLDOWN_SECONDS=${APP_GUARD_RESTART_COOLDOWN_SECONDS:-600}
HEALTH_URL=${APP_GUARD_HEALTH_URL:-http://127.0.0.1:8000/healthz/}

if [ -z "$COMPOSE_FILE" ] || [ -z "$PROJECT" ]; then
  echo "APP_GUARD_COMPOSE_FILE and APP_GUARD_PROJECT are required" >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >>"$LOG"; }

DOCKER_COMPOSE_ARGS=(compose -f "$COMPOSE_FILE")
if [ -n "$ENV_FILE" ]; then
  DOCKER_COMPOSE_ARGS+=(--env-file "$ENV_FILE")
fi
DOCKER_COMPOSE_ARGS+=(-p "$PROJECT")
compose() { docker "${DOCKER_COMPOSE_ARGS[@]}" "$@"; }

# `--no-deps` 是刻意的：没有它，每 90 秒的这次对账会把 app 的依赖也一起"起来"，
# 其中 object-store-init 是一次性任务容器 —— 于是每 90 秒重建一个 minio/mc 容器
# 跑一遍建桶，单核机器上白掉一次 CPU 和网络（2026-10-02 实测每轮 11~13 秒）。
# 依赖服务本来就常驻，真缺了由 install-site.sh 负责，不归这个守卫管。
if ! compose up -d --no-deps "$SERVICE" >>"$LOG" 2>&1; then
  log "compose up failed; leaving the running state untouched"
  exit 1
fi

container=$(compose ps -q "$SERVICE" 2>/dev/null | head -1)
if [ -z "$container" ]; then
  log "no container id for service=${SERVICE} after up"
  exit 0
fi

health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null || echo "unknown")
log "service=${SERVICE} container=${container} health=${health}"

if [ "$health" != "unhealthy" ]; then
  # 恢复正常：清掉节流窗口，下一次真坏时不用再等。
  printf '0\n' >"$STATE_FILE" 2>/dev/null || true
  exit 0
fi

payload=$(docker exec "$container" python -c "import os, sys, urllib.request as u
host = (os.environ.get('HEALTHCHECK_HOST') or (os.environ.get('ALLOWED_HOSTS') or '').split(',')[0]).strip()
request = u.Request('${HEALTH_URL}', headers={'Host': host, 'X-Forwarded-Proto': 'https'})
try:
    sys.stdout.write(u.urlopen(request, timeout=4).read().decode())
except Exception as exc:
    body = getattr(exc, 'read', None)
    sys.stdout.write(body().decode() if body else repr(exc))" 2>/dev/null || true)
log "healthz payload: ${payload:0:400}"

# 读不出探针结论时**不重启**。盲目重启只会每 10 分钟把好端端的容器掀一次，
# 那比"容器红着但进程还在服务"坏得多。
case "$payload" in
  *'"status"'*) ;;
  *)
    log "cannot read the probe verdict (Host header or probe problem); not restarting"
    exit 0
    ;;
esac

case "$payload" in
  *migrations_pending*)
    log "unhealthy but migrations are pending; not restarting (deploy window)"
    exit 0
    ;;
esac

now=$(date -u +%s)
last=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
case "$last" in ''|*[!0-9]*) last=0 ;; esac
elapsed=$((now - last))
if [ "$elapsed" -lt "$COOLDOWN_SECONDS" ]; then
  log "restart suppressed by cooldown (${elapsed}s < ${COOLDOWN_SECONDS}s)"
  exit 0
fi

printf '%s\n' "$now" >"$STATE_FILE"
log "restarting unhealthy container"
if compose restart "$SERVICE" >>"$LOG" 2>&1; then
  log "restart issued"
else
  log "restart failed"
fi
exit 0
