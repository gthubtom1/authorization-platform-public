#!/usr/bin/env bash
# Shared by backup-full.sh and backup-diff.sh. Caller must set RUN_TYPE.
# Page policy is executed here: pending claim, log/stamp paths,
# and fail-closed completion. Backup copies go to this host and optional GitHub.

: "${RUN_TYPE:?RUN_TYPE must be set to full or diff}"

BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
POLICY_MANAGE=${AUTHORIZATION_PLATFORM_MANAGE:-}
if [ -z "$POLICY_MANAGE" ]; then
  for candidate in \
    /srv/authorization-platform/manage.py \
    /opt/authorization-platform-candidate-clean-rc8-staging/manage.py
  do
    if [ -f "$candidate" ]; then POLICY_MANAGE="$candidate"; break; fi
  done
fi
if [ ! -f "$POLICY_MANAGE" ]; then
  echo "manage.py missing; refusing backup policy defaults" >&2
  exit 1
fi

PYTHON_BIN=${PYTHON_BIN:-python3}
HOST_PYTHON_BIN=${BACKUP_HOST_PYTHON:-python3}
SCRIPT_DIR=${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
RUNNER="${BACKUP_RUNNER_SH:-$SCRIPT_DIR/backup_runner.sh}"
PROOF_FILE=${BACKUP_PROOF_FILE:-${BACKUP_ROOT}/backup-proof.json}
DOWNLOAD_DIR=${BACKUP_DOWNLOAD_DIR:-${BACKUP_ROOT}/downloads}
KEYS=${BACKUP_KEYS_DIR:-${BACKUP_ROOT}/keys}
GH_TOKEN_FILE=${KEYS}/github-token.txt
LOG=${BACKUP_LOG_FILE:-${BACKUP_ROOT}/backup.log}
LOCK_FILE=${BACKUP_LOCK_FILE:-${BACKUP_ROOT}/backup.lock}
STAMP_DIR=${BACKUP_SCHEDULE_STAMP_DIR:-${BACKUP_ROOT}/backup-stamps}
SKIP_SENTINEL=${BACKUP_SKIP_SENTINEL:-$STAMP_DIR/last-exec-skipped}
DB_CONTAINER=${AUTHORIZATION_PLATFORM_DB_CONTAINER:-}
if [ -z "$DB_CONTAINER" ]; then
  echo "AUTHORIZATION_PLATFORM_DB_CONTAINER is required; refusing dump of an unknown database container" >&2
  exit 1
fi
STANZA=${BACKUP_STANZA:-authorization-platform}
case "$DB_CONTAINER" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "AUTHORIZATION_PLATFORM_DB_CONTAINER contains unsupported characters" >&2
    exit 1
    ;;
esac
case "$STANZA" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "BACKUP_STANZA contains unsupported characters" >&2
    exit 1
    ;;
esac
ALERT="${BACKUP_ALERT_HANDLER:-$SCRIPT_DIR/backup_alert.sh}"
PENDING_FINISHED=0
PENDING_ID=""
ATTEMPT_TOKEN=""
HEARTBEAT_PID=""
DB_STATE=disabled
NETDISK=disabled
REASON=""
SCHEDULED_FOR=""
DECISION_SKIPPED=0
DECISION_RETRY_MAX=${BACKUP_DECISION_RETRY_MAX:-5}
DECISION_RETRY_DELAY_SECONDS=${BACKUP_DECISION_RETRY_DELAY_SECONDS:-30}
case "$DECISION_RETRY_MAX" in
  ''|*[!0-9]*) DECISION_RETRY_MAX=5 ;;
esac
case "$DECISION_RETRY_DELAY_SECONDS" in
  ''|*[!0-9]*) DECISION_RETRY_DELAY_SECONDS=30 ;;
esac

json_get() {
  printf '%s' "$1" | "$PYTHON_BIN" -c "import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ''))" "$2"
}

as_enabled() {
  case "$1" in
    True|true|enabled|1) echo enabled ;;
    *) echo disabled ;;
  esac
}

backup_trigger_path() {
  printf '%s/queue/need-run' "$BACKUP_ROOT"
}

write_backup_trigger() {
  local trigger
  trigger=$(backup_trigger_path)
  if ! mkdir -p "$(dirname "$trigger")" || ! printf '1\n' > "$trigger"; then
    echo "cannot restore backup trigger $trigger" >&2
    return 1
  fi
}

retry_backup_trigger() {
  # Rewriting the marker gives systemd.path a new event after a failed decision.
  write_backup_trigger
}

validate_decision() {
  printf '%s' "$1" | "$PYTHON_BIN" -c '
import json
import sys
import uuid
from datetime import datetime

run_type = sys.argv[1]
try:
    decision = json.load(sys.stdin)
except Exception as exc:
    print(f"backup policy decision is not valid JSON: {type(exc).__name__}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(decision, dict):
    print("backup policy decision must be a JSON object", file=sys.stderr)
    raise SystemExit(1)

required = {
    "execute",
    "reason",
    "backup_type",
    "pending_id",
    "attempt_token",
    "scheduled_for_utc",
    "github_enabled",
    "database_enabled",
    "cleanup_enabled",
    "schedule_enabled",
    "netdisk",
    "github_repository",
    "secret_values_exposed",
}
missing = sorted(required - decision.keys())
if missing:
    print("backup policy decision is missing required fields", file=sys.stderr)
    raise SystemExit(1)

for key in (
    "execute",
    "github_enabled",
    "database_enabled",
    "cleanup_enabled",
    "schedule_enabled",
    "secret_values_exposed",
):
    if type(decision[key]) is not bool:
        print(f"backup policy decision field {key} must be boolean", file=sys.stderr)
        raise SystemExit(1)

for key in ("reason", "backup_type", "pending_id", "attempt_token", "scheduled_for_utc", "netdisk", "github_repository"):
    if not isinstance(decision[key], str):
        print(f"backup policy decision field {key} must be a string", file=sys.stderr)
        raise SystemExit(1)

if decision["scheduled_for_utc"]:
    try:
        scheduled_for = datetime.fromisoformat(decision["scheduled_for_utc"])
    except ValueError:
        print("backup policy scheduled_for_utc is not an ISO timestamp", file=sys.stderr)
        raise SystemExit(1)
    if scheduled_for.tzinfo is None:
        print("backup policy scheduled_for_utc must include a timezone", file=sys.stderr)
        raise SystemExit(1)
    if run_type != "full":
        print("only full backups may carry scheduled_for_utc", file=sys.stderr)
        raise SystemExit(1)

if decision["secret_values_exposed"] is not False:
    print("backup policy decision cannot expose secret values", file=sys.stderr)
    raise SystemExit(1)
if decision["backup_type"] != run_type:
    print("backup policy decision type does not match the host runner", file=sys.stderr)
    raise SystemExit(1)
if decision["netdisk"] != "disabled":
    print("backup policy decision cannot enable a removed netdisk destination", file=sys.stderr)
    raise SystemExit(1)

if decision["execute"]:
    if decision["reason"] != "pending" or not decision["pending_id"]:
        print("executing a backup requires reason=pending and pending_id", file=sys.stderr)
        raise SystemExit(1)
    if not decision["attempt_token"] or decision["attempt_token"].strip() != decision["attempt_token"]:
        print("executing a backup requires an attempt_token", file=sys.stderr)
        raise SystemExit(1)
    if decision["pending_id"].strip() != decision["pending_id"]:
        print("backup policy pending_id cannot contain surrounding whitespace", file=sys.stderr)
        raise SystemExit(1)
    try:
        uuid.UUID(decision["pending_id"])
    except (ValueError, AttributeError):
        print("backup policy pending_id is not a UUID", file=sys.stderr)
        raise SystemExit(1)
else:
    if decision["reason"] not in {"not_due", "disabled", "idle"} or decision["pending_id"] or decision["attempt_token"]:
        print("a skipped backup has an inconsistent reason or pending_id", file=sys.stderr)
        raise SystemExit(1)
' "$RUN_TYPE"
}

prepare_backup_host() {
  mkdir -p "$BACKUP_ROOT" "$KEYS" "$DOWNLOAD_DIR" "$STAMP_DIR" "$BACKUP_ROOT/queue" "$(dirname "$LOG")"
  if ! chown root:10001 "$BACKUP_ROOT" "$DOWNLOAD_DIR" "$KEYS" "$BACKUP_ROOT/queue" "$STAMP_DIR"; then
    echo "cannot set backup directory ownership" >&2
    exit 1
  fi
  if ! chmod 750 "$BACKUP_ROOT" || ! chmod 770 "$DOWNLOAD_DIR" "$KEYS" "$BACKUP_ROOT/queue" || ! chmod 750 "$STAMP_DIR"; then
    echo "cannot set backup directory permissions" >&2
    exit 1
  fi
  if ! touch "$LOG"; then
    echo "cannot write backup log $LOG" >&2
    exit 1
  fi
  exec 9>"$LOCK_FILE"
  if ! flock -w 7200 9; then
    echo "another backup is running; refusing to overlap" >&2
    exit 1
  fi
}

consume_backup_trigger() {
  local trigger pending_type
  trigger=$(backup_trigger_path)
  if ! rm -f -- "$trigger"; then
    echo "cannot consume backup trigger; keeping queue wakeup" >&2
    return 1
  fi
  # The database is the source of truth for a trigger written during this run.
  if ! pending_type=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --pending-run); then
    echo "cannot verify pending backup after consuming trigger" >&2
    write_backup_trigger
    return 1
  fi
  case "$pending_type" in
    ""|none)
      return 0
      ;;
    full|diff)
      write_backup_trigger
      ;;
    *)
      echo "unknown pending backup type; keeping queue wakeup" >&2
      write_backup_trigger
      return 1
      ;;
  esac
}

sync_github_gate() {
  if "$PYTHON_BIN" "$POLICY_MANAGE" backup_policy \
    --write-github-token "$GH_TOKEN_FILE" >/dev/null; then
    return 0
  fi
  GH_STATE=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --github-check)
  if [ "$GH_STATE" = "enabled" ] && [ -s "$GH_TOKEN_FILE" ]; then
    echo "[github token already on disk; django write skipped]" >>"$LOG"
    return 0
  fi
  if [ "$GH_STATE" != "enabled" ]; then
    echo "[github gate write skipped]" >>"$LOG"
    return 0
  fi
  echo "cannot write github token" >&2
  exit 1
}

notify_failure() {
  local reason="$1"
  if [ ! -f "$ALERT" ]; then
    return 0
  fi
  echo "{\"schema_version\":1,\"event\":\"authorization_platform_backup_failure\",\"occurred_at_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"reason_code\":\"$reason\",\"last_result\":\"failed\",\"secret_values_exposed\":false}" \
    | BACKUP_KEYS_DIR="$KEYS" bash "$ALERT" || true
}

finish_pending() {
  local result="$1"
  local message="$2"
  if [ -n "${PENDING_ID:-}" ]; then
    "$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --complete-run "$PENDING_ID" --attempt-token "$ATTEMPT_TOKEN" --result "$result" --message "$message" >/dev/null
    PENDING_FINISHED=1
  fi
}

start_backup_heartbeat() {
  if [ -z "${PENDING_ID:-}" ] || [ -z "${ATTEMPT_TOKEN:-}" ]; then
    return 0
  fi
  local interval=${BACKUP_HEARTBEAT_INTERVAL_SECONDS:-60}
  case "$interval" in
    ''|*[!0-9]*|0) interval=60 ;;
  esac
  (
    while sleep "$interval"; do
      if ! "$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --heartbeat-run "$PENDING_ID" --attempt-token "$ATTEMPT_TOKEN" >/dev/null; then
        echo "backup lease heartbeat failed" >&2
        exit 1
      fi
    done
  ) >>"$LOG" 2>&1 &
  HEARTBEAT_PID=$!
}

stop_backup_heartbeat() {
  if [ -n "${HEARTBEAT_PID:-}" ]; then
    kill "$HEARTBEAT_PID" 2>/dev/null || true
    wait "$HEARTBEAT_PID" 2>/dev/null || true
    HEARTBEAT_PID=""
  fi
}

on_backup_exit() {
  stop_backup_heartbeat
  if [ -n "${PENDING_ID:-}" ] && [ "${PENDING_FINISHED:-0}" != 1 ]; then
    "$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --complete-run "$PENDING_ID" --attempt-token "$ATTEMPT_TOKEN" --result failed --message "backup_script_aborted" >/dev/null || true
  fi
}

decide_or_exit() {
  local decision execute
  DECISION_SKIPPED=0
  if ! decision=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --decide --type="$RUN_TYPE"); then
    echo "backup policy decision failed; keeping queue wakeup" >&2
    retry_backup_trigger || true
    return 1
  fi
  if ! validate_decision "$decision"; then
    echo "backup policy decision is invalid; keeping queue wakeup" >&2
    retry_backup_trigger || true
    return 1
  fi
  EXECUTE=$(json_get "$decision" execute)
  REASON=$(json_get "$decision" reason)
  PENDING_ID=$(json_get "$decision" pending_id)
  ATTEMPT_TOKEN=$(json_get "$decision" attempt_token)
  SCHEDULED_FOR=$(json_get "$decision" scheduled_for_utc)
  DB_STATE=$(as_enabled "$(json_get "$decision" database_enabled)")
  NETDISK=$(json_get "$decision" netdisk)
  if [ -z "$NETDISK" ]; then NETDISK=disabled; fi
  execute=$(as_enabled "$EXECUTE")
  if [ "$execute" != "enabled" ]; then
    printf 'skipped\n' > "$SKIP_SENTINEL"
    if ! consume_backup_trigger; then
      return 1
    fi
    DECISION_SKIPPED=1
    return 0
  fi
  if ! consume_backup_trigger; then
    return 1
  fi
  rm -f "$SKIP_SENTINEL"
  start_backup_heartbeat
}

decide_with_retry() {
  local status attempt=0
  while true; do
    decide_or_exit && return 0
    status=$?
    # A successful decision already moved a row to RUNNING. Retrying the
    # decision could turn that claimed work into an idle skip and lose it.
    if [ -n "${PENDING_ID:-}" ]; then
      return "$status"
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$DECISION_RETRY_MAX" ] || [ ! -e "$(backup_trigger_path)" ]; then
      return "$status"
    fi
    sleep "$DECISION_RETRY_DELAY_SECONDS"
  done
}

upload_latest_enc_if_needed() {
  return 0
}

mark_schedule_or_fail() {
  # The host root writes the stamp; the app uid only needs group read access.
  mkdir -p "$STAMP_DIR"
  local target temporary
  target="$STAMP_DIR/last-$RUN_TYPE"
  temporary=$(mktemp "$STAMP_DIR/.last-$RUN_TYPE.XXXXXX") || return 1
  if [ "$RUN_TYPE" = "full" ] && [ -n "${SCHEDULED_FOR:-}" ]; then
    if ! "$HOST_PYTHON_BIN" - "$SCHEDULED_FOR" > "$temporary" <<'PY'
import sys
from datetime import datetime, timezone

moment = datetime.fromisoformat(sys.argv[1])
if moment.tzinfo is None:
    raise SystemExit(1)
print("schedule-slot-v1:" + moment.astimezone(timezone.utc).isoformat())
PY
    then
      rm -f -- "$temporary"
      return 1
    fi
  elif [ "$RUN_TYPE" = "full" ]; then
    # Manual and change-triggered full runs have no schedule slot. Keep their
    # completion time in the legacy/plain format so they cannot claim one.
    # Never replace an existing scheduled slot with that plain timestamp.
    if [ -f "$STAMP_DIR/last-$RUN_TYPE" ] \
      && [ ! -L "$STAMP_DIR/last-$RUN_TYPE" ] \
      && grep -q '^schedule-slot-v1:' "$STAMP_DIR/last-$RUN_TYPE"; then
      rm -f -- "$temporary"
      return 0
    elif ! "$HOST_PYTHON_BIN" -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())' > "$temporary"; then
      rm -f -- "$temporary"
      return 1
    fi
  elif ! "$HOST_PYTHON_BIN" -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())' > "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! chown root:10001 "$temporary" || ! chmod 640 "$temporary" || ! mv -f -- "$temporary" "$target"; then
    rm -f -- "$temporary"
    return 1
  fi
}
