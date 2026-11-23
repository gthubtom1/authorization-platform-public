#!/usr/bin/env bash
# 把一份**已经加密好的**备份上传到 Telegram 私有频道，作为第三份异地副本。
#
# 规矩（和告警桥一样）：
#   - **永远 exit 0**。上传失败绝不能把备份判成失败——它只是个额外的副本。
#   - 只传**已经加密**的 .enc 文件，绝不传明文 dump、绝不传任何口令。
#   - 缺凭据、文件太大、没装 curl：只记一行日志然后安静退出。
#
# 需要两个文件（缺就跳过，不报警）：
#   keys/telegram-backup-bot-token.txt     独立机器人的令牌
#   keys/telegram-backup-channel-id.txt    私有频道的 chat id（形如 -1001234567890）
# 想临时关掉：放一个 keys/telegram-backup-disabled 标记文件。
#
# 用法: telegram_backup_copy.sh <加密后的.enc文件> [保留份数，默认 7]

set -uo pipefail

DUMP_FILE=${1:-}
KEEP=${2:-7}
BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
KEYS_DIR=${BACKUP_KEYS_DIR:-${BACKUP_ROOT}/keys}
LOG=${BACKUP_LOG_FILE:-${BACKUP_ROOT}/backup.log}
STATE=${TELEGRAM_BACKUP_INDEX:-${BACKUP_ROOT}/telegram-backup-index.txt}
API=${TELEGRAM_API:-https://api.telegram.org}
TOKEN_FILE="${KEYS_DIR}/telegram-backup-bot-token.txt"
CHANNEL_FILE="${KEYS_DIR}/telegram-backup-channel-id.txt"
MAX_BYTES=$((50 * 1024 * 1024))   # Bot API 的 sendDocument 上限 50MB

note() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >>"$LOG" 2>/dev/null || true; }

if [ -z "$DUMP_FILE" ] || [ ! -f "$DUMP_FILE" ]; then
  note "telegram backup copy: no dump file given; skipped"
  exit 0
fi
if [ -f "${KEYS_DIR}/telegram-backup-disabled" ]; then
  note "telegram backup copy: disabled by marker; skipped"
  exit 0
fi
if [ ! -s "$TOKEN_FILE" ] || [ ! -s "$CHANNEL_FILE" ]; then
  note "telegram backup copy: credentials missing under keys/; nothing sent"
  exit 0
fi
command -v curl >/dev/null 2>&1 || { note "telegram backup copy: curl missing; skipped"; exit 0; }

token=$(head -n1 "$TOKEN_FILE" | tr -d '\r\n')
chat=$(head -n1 "$CHANNEL_FILE" | tr -d '\r\n')
if [ -z "$token" ] || [ -z "$chat" ]; then
  note "telegram backup copy: credentials unreadable; nothing sent"
  exit 0
fi

size=$(stat -c%s "$DUMP_FILE" 2>/dev/null || echo 0)
if [ "$size" -gt "$MAX_BYTES" ]; then
  note "telegram backup copy: dump is ${size} bytes, over the 50MB bot limit; skipped"
  exit 0
fi

name=$(basename "$DUMP_FILE")
caption="授权平台备份 ${name} | 生成时间 $(date -u +%Y-%m-%dT%H:%M:%SZ) | 大小 $((size / 1024))KB | 用灾备钥匙包里的 github-dump-pass.txt 解开"

# 上传（-F 是 multipart，Telegram 只收这种方式）
response=$(curl -sS --max-time 900 \
  -F "chat_id=${chat}" \
  -F "document=@${DUMP_FILE};filename=${name}" \
  -F "caption=${caption}" \
  "${API}/bot${token}/sendDocument" 2>&1)

# Telegram 真实回话是 {"ok":true,...}（没有空格），但别把格式当契约：
# 允许 "ok" 与冒号之间有空格，免得对方哪天改了序列化风格就误判成失败。
if ! printf '%s' "$response" | grep -qE '"ok"[[:space:]]*:[[:space:]]*true'; then
  # 失败只记日志，不影响备份本身
  note "telegram backup copy: send failed (ignored): $(printf '%s' "$response" | head -c 160)"
  exit 0
fi

message_id=$(printf '%s' "$response" | tr -d ' \n' | sed -n 's/.*"message_id":\([0-9]\{1,\}\).*/\1/p' | head -1)
[ -n "$message_id" ] || { note "telegram backup copy: sent but no message_id parsed; nothing to prune"; exit 0; }

# 记下这条消息的编号，供以后清理旧的
umask 077
touch "$STATE"
grep -v -x "$message_id" "$STATE" >"${STATE}.tmp" 2>/dev/null || true
mv -f "${STATE}.tmp" "$STATE"
echo "$message_id" >>"$STATE"

# 只保留最近 KEEP 条：更早的删掉，免得频道无限堆积
total=$(wc -l <"$STATE" 2>/dev/null || echo 0)
if [ "$total" -gt "$KEEP" ]; then
  drop=$((total - KEEP))
  head -n "$drop" "$STATE" | while read -r old; do
    [ -n "$old" ] || continue
    curl -sS --max-time 30 -X POST \
      -d "chat_id=${chat}" -d "message_id=${old}" \
      "${API}/bot${token}/deleteMessage" >/dev/null 2>&1 || true
  done
  tail -n "$KEEP" "$STATE" >"${STATE}.tmp" 2>/dev/null || true
  mv -f "${STATE}.tmp" "$STATE"
  note "telegram backup copy: pruned ${drop} older message(s), kept ${KEEP}"
fi

note "telegram backup copy: uploaded ${name} (${size} bytes) as message ${message_id}"
exit 0
