#!/usr/bin/env bash
# 每日完整备份（双仓库 repo1=MinIO-S3 + repo2=本地卷）
# 页面保存的开关/时间由本脚本在巡检时真正执行；立即备份排队也在这里消费。
set -euo pipefail

RUN_TYPE=full
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=backup-host-lib.sh
source "$SCRIPT_DIR/backup-host-lib.sh"

prepare_backup_host
trap on_backup_exit EXIT
decide_with_retry
  if [ "${DECISION_SKIPPED:-0}" = 1 ]; then
    exit 0
  fi
sync_github_gate

{
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] full backup start reason=${REASON}"
  FAILED=""
  if [ "$DB_STATE" = "enabled" ]; then
    FULL_RETENTION=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --full-retention)
    ARCHIVE_RETENTION=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --archive-retention)
    for REPO in 1 2; do
      if ! docker exec -u postgres "$DB_CONTAINER" pgbackrest --stanza="$STANZA" --type=full \
        --repo=$REPO --repo${REPO}-retention-full="$FULL_RETENTION" --repo${REPO}-retention-archive="$ARCHIVE_RETENTION" --log-level-console=info backup 2>>"$LOG"; then
        echo "[full backup repo$REPO failed]"
        FAILED="backup_repo${REPO}_failed"
      fi
    done
  fi
  if [ ! -f "$RUNNER" ]; then
    echo "[backup runner missing]"
    FAILED="${FAILED:+$FAILED,}backup_runner_missing"
  elif ! bash "$RUNNER" --type=full --proof-file="$PROOF_FILE" >>"$LOG" 2>&1; then
    GH_STATE=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --github-check 2>/dev/null || echo "disabled")
    if [ "$GH_STATE" = "enabled" ]; then
      FAILED="${FAILED:+$FAILED,}github_sync_failed"
    else
      FAILED="${FAILED:+$FAILED,}database_dump_failed"
    fi
  fi
  if [ -z "$FAILED" ] && ! upload_latest_enc_if_needed >>"$LOG" 2>&1; then
    FAILED="${FAILED:+$FAILED,}encrypted_copy_failed"
  fi
  GH_STATE=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --github-check)
  if [ -z "$FAILED" ] && [ "${BACKUP_INCLUDE_SECRETS_CODE:-0}" = "1" ] && [ "$GH_STATE" = "enabled" ]; then
    SECRETS_RUNNER="${BACKUP_SECRETS_RUNNER:-$SCRIPT_DIR/secrets_runner.sh}"
    CODE_RUNNER="${BACKUP_CODE_RUNNER:-$SCRIPT_DIR/code_runner.sh}"
    if [ -f "$SECRETS_RUNNER" ] && ! bash "$SECRETS_RUNNER" >>"$LOG" 2>&1; then
      FAILED="${FAILED:+$FAILED,}secrets_sync_failed"
    fi
    if [ -f "$CODE_RUNNER" ] && ! bash "$CODE_RUNNER" >>"$LOG" 2>&1; then
      FAILED="${FAILED:+$FAILED,}code_sync_failed"
    fi
  fi
  if [ -n "$FAILED" ]; then
    echo "[full backup FAILED: $FAILED]"
    finish_pending failed "$FAILED"
    notify_failure "$FAILED"
    exit 1
  fi
  if ! mark_schedule_or_fail; then
    echo "[full backup FAILED: schedule_stamp_failed]"
    finish_pending failed "schedule_stamp_failed"
    notify_failure "schedule_stamp_failed"
    exit 1
  fi
  GH_STATE=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --github-check 2>/dev/null || echo "disabled")
  if [ "$GH_STATE" = "enabled" ]; then
    finish_pending succeeded "全量备份已完成（已保存本机并同步至 GitHub）。"
  else
    finish_pending succeeded "全量备份已完成（已保存本机）。"
  fi
  echo "[done]"
} >>"$LOG" 2>&1
exit 0
