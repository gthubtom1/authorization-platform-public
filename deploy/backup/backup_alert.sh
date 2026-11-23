#!/usr/bin/env bash
# 备份失败告警 bridge：把脱敏的失败事件转发到 Telegram 机器人。
#
# 三条铁律，任何改动都不能破坏：
#  1) 永远返回 0。这个脚本是备份 unit 的 ExecStartPost、也是 notify_failure 的下游，
#     告警通道坏了绝不能反过来把备份判成失败。
#  2) 令牌只从 root 600 的文件读，绝不出现在命令行、绝不进日志。
#  3) 缺令牌 / 没装 curl / 网络不通 → 记一行本地日志就返回。curl 固定 --max-time，
#     不会挂住备份。
#
# 另外：最短发送间隔由 BACKUP_ALERT_MIN_INTERVAL_SECONDS 限住。备份失败时
# systemd.path 会每 2.5 分钟重新触发一轮，没有这个闸会一直打手机。
set -uo pipefail

payload=$(cat 2>/dev/null || true)
KEYS_DIR=${BACKUP_KEYS_DIR:-}
LOG=${BACKUP_ALERT_LOG:-/var/lib/authorization-platform-backup/alert.log}
STATE=${BACKUP_ALERT_STATE_FILE:-/var/lib/authorization-platform-backup/alert.state}
MIN_INTERVAL=${BACKUP_ALERT_MIN_INTERVAL_SECONDS:-900}
TELEGRAM_API=${BACKUP_TELEGRAM_API:-https://api.telegram.org}

note() {
  mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >>"$LOG" 2>/dev/null || true
}

if [ -z "$KEYS_DIR" ]; then
  note "alert: BACKUP_KEYS_DIR not set; nothing sent"
  exit 0
fi

token_file="${KEYS_DIR}/telegram-bot-token.txt"
chat_file="${KEYS_DIR}/telegram-chat-id.txt"
if [ ! -s "$token_file" ] || [ ! -s "$chat_file" ]; then
  note "alert: telegram credentials missing under keys/; nothing sent"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  note "alert: curl missing; nothing sent"
  exit 0
fi

now=$(date -u +%s)
last=$(cat "$STATE" 2>/dev/null || echo 0)
case "$last" in ''|*[!0-9]*) last=0 ;; esac
if [ "$((now - last))" -lt "$MIN_INTERVAL" ]; then
  note "alert: suppressed by the ${MIN_INTERVAL}s window"
  exit 0
fi
printf '%s\n' "$now" >"$STATE" 2>/dev/null || true

token=$(tr -d '\r\n' <"$token_file" 2>/dev/null || true)
chat=$(tr -d '\r\n' <"$chat_file" 2>/dev/null || true)
if [ -z "$token" ] || [ -z "$chat" ]; then
  note "alert: telegram credentials unreadable; nothing sent"
  exit 0
fi

reason=$(printf '%s' "$payload" | sed -n 's/.*"reason_code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
[ -n "$reason" ] || reason="backup_failure"
text="授权平台备份失败
reason=${reason}
主机: $(hostname 2>/dev/null || echo unknown)
时间: $(date -u +%Y-%m-%dT%H:%M:%SZ)
详情: ${payload:0:200}"

curl -sS --fail --max-time 10 --retry 0 \
  --data-urlencode "chat_id=${chat}" \
  --data-urlencode "text=${text}" \
  "${TELEGRAM_API}/bot${token}/sendMessage" >>"$LOG" 2>&1 || note "alert: telegram send failed (ignored)"

exit 0
