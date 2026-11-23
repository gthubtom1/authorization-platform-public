#!/usr/bin/env bash
# 维护：Django session 清理 + 磁盘/备份健康盯盘
#
# 退出码是有意义的：0 = 全部正常，1 = 发现需要人处理的问题（备份被判失败、
# 或磁盘余量进入 critical）。旧版本无论发现什么都在最后一行 log 之后返回 0，
# 于是"每小时健康检查"从来没有判决能力。
set -euo pipefail
LOG=${BACKUP_MAINTENANCE_LOG_FILE:-/var/log/authorization-platform-maintenance.log}
STATUS_FILE=${BACKUP_STATUS_FILE:-/var/lib/authorization-platform-backup/backup-status.json}
LAST_LOG=${BACKUP_LOG_FILE:-/var/lib/authorization-platform-backup/backup.log}
APP_CONTAINER=${AUTHORIZATION_PLATFORM_APP_CONTAINER:-}
DB_CONTAINER=${AUTHORIZATION_PLATFORM_DB_CONTAINER:-}
if [ -z "$APP_CONTAINER" ] || [ -z "$DB_CONTAINER" ]; then
  echo "AUTHORIZATION_PLATFORM_APP_CONTAINER and AUTHORIZATION_PLATFORM_DB_CONTAINER are required; refusing hardcoded container names" >&2
  exit 1
fi

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$LOG"; }

# 1) Session 清理 + 授权请求记录（幂等台账）的保留期清理。
#    清理失败只记日志，绝不让维护任务失败——它每小时跑一次，一次偶发失败不该
#    把整台机器标成异常。
log "clearsessions start"
docker exec "$APP_CONTAINER" python manage.py clearsessions >>"$LOG" 2>&1 || log "clearsessions failed"
if docker exec "$APP_CONTAINER" python manage.py prune_authorization_records --apply >>"$LOG" 2>&1; then
  log "request record prune ok"
else
  log "request record prune failed (see lines above)"
fi

# 2b) 把备份健康标记与数据库里的真实运行记录对齐。
#这套部署没有 pgBackRest，所以 mark_success 永远拿不到证明，健康标记会长期停在
# failure，管理端就一直显示"备份失败"。数据库里的运行记录才是这里的事实源：
# 最新一次确实 succeeded 就对齐成成功，并写明 proof_mode=dump_only（不伪造证明）。
# 最新一次是失败时**什么都不做**——失败路径自己会写标记。
# 必须以 root 在容器里跑：健康标记与它的锁文件归 root（宿主机 0077 umask 写的），
# 容器默认 uid 10001 打不开那个锁；而且宿主的 python3 没有 Django，镜像只 COPY
# manage.py 与 src/，所以只能在容器里执行。
if docker exec -u root "$APP_CONTAINER" python manage.py backup_status_reconcile --status-file "$STATUS_FILE" >>"$LOG" 2>&1; then
  log "backup status reconciled from run records"
else
  log "backup status reconcile failed (see lines above)"
fi

FAILED=0

# 2) 磁盘盯盘（阈值：≥85% warning，≥92% critical）
DISK_PCT=$(df -h / | awk "NR==2 {gsub(/%/,\"\",\$5); print \$5}")
log "disk usage: ${DISK_PCT}%"
if [ "${DISK_PCT:-0}" -ge 92 ]; then
  log "CRITICAL disk usage ${DISK_PCT}%"
  FAILED=1
elif [ "${DISK_PCT:-0}" -ge 85 ]; then
  log "WARNING disk usage ${DISK_PCT}%"
fi

# 3) 备份健康盯盘
#
# 旧实现数的是 "backup runner complete"（backup_runner.sh 无条件打印，成功失败
# 都打），失败计数 grep 的是 "backup failed" —— 那个小写字符串在整个 backup
# 目录里根本不存在。结果是一条全失败站点上每小时输出 "ok=N failed=0"。
#
# 现在两件事都要真的判定：日志里的失败行用真实存在的 pattern，程序写下的状态
# 文件用字段读。
RUNS_COMPLETED=0
RUNS_FAILED=0
if [ -f "$LAST_LOG" ]; then
  RUNS_COMPLETED=$(grep -c "backup runner complete" "$LAST_LOG" || true)
  # 这些 pattern 才是脚本真的打出来的：backup-full.sh / backup-diff.sh 用大写
  # FAILED，仓库失败用 "backup repoN failed"，推送失败用 "github push failed"，
  # 新增的 dump 不可用用 "encrypted dump unusable"。
  RUNS_FAILED=$(grep -ciE "backup FAILED|backup repo[0-9]+ failed|github push failed|encrypted dump unusable" "$LAST_LOG" || true)
fi
log "backup runs: completed=${RUNS_COMPLETED} failed=${RUNS_FAILED}"
if [ "${RUNS_FAILED:-0}" -gt 0 ]; then
  log "WARNING backup log contains ${RUNS_FAILED} failure line(s)"
  FAILED=1
fi

STATUS_RESULT="absent"
STATUS_FAILURE_CODE="none"
STATUS_LAST_SUCCESS="unknown"
if [ -f "$STATUS_FILE" ]; then
  # 刻意只用 sed/grep：这个脚本在主机上跑，不能假设有 python3。而且状态文件是
  # 扁平 JSON，字段名固定，够用。
  STATUS_RESULT=$(sed -n 's/.*"last_result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STATUS_FILE" | head -1)
  STATUS_FAILURE_CODE=$(sed -n 's/.*"last_failure_code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STATUS_FILE" | head -1)
  if grep -q '"last_success_at_utc"[[:space:]]*:[[:space:]]*null' "$STATUS_FILE"; then
    STATUS_LAST_SUCCESS="never"
  else
    STATUS_LAST_SUCCESS=$(sed -n 's/.*"last_success_at_utc"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STATUS_FILE" | head -1)
  fi
  [ -n "$STATUS_RESULT" ] || STATUS_RESULT="unreadable"
  [ -n "$STATUS_FAILURE_CODE" ] || STATUS_FAILURE_CODE="none"
  [ -n "$STATUS_LAST_SUCCESS" ] || STATUS_LAST_SUCCESS="unreadable"
fi
log "backup status: result=${STATUS_RESULT} failure_code=${STATUS_FAILURE_CODE} last_success=${STATUS_LAST_SUCCESS}"
if [ "$STATUS_RESULT" != "success" ]; then
  log "CRITICAL backup status result=${STATUS_RESULT} (expected success)"
  FAILED=1
fi
if [ "$STATUS_LAST_SUCCESS" = "never" ]; then
  log "CRITICAL backup status has never recorded a success"
  FAILED=1
fi

if [ "$FAILED" -eq 0 ]; then
  log "maintenance complete"
else
  log "maintenance complete with findings (see lines above)"
fi
exit "$FAILED"
