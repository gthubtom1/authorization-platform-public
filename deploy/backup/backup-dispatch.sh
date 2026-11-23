#!/usr/bin/env bash
# Select the runner from the database queue. The caller must run as root.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
POLICY_MANAGE=${AUTHORIZATION_PLATFORM_MANAGE:-}
BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
TRIGGER_PATH=${BACKUP_TRIGGER_PATH:-$BACKUP_ROOT/queue/need-run}
FULL_RUNNER=${BACKUP_FULL_RUNNER_SH:-$SCRIPT_DIR/backup-full.sh}
DIFF_RUNNER=${BACKUP_DIFF_RUNNER_SH:-$SCRIPT_DIR/backup-diff.sh}

if [ -z "$POLICY_MANAGE" ] || [ ! -f "$POLICY_MANAGE" ]; then
  echo "manage.py missing; refusing backup dispatch" >&2
  exit 1
fi

restore_dispatch_trigger() {
  if ! mkdir -p "$(dirname "$TRIGGER_PATH")" || ! printf '1\n' > "$TRIGGER_PATH"; then
    echo "cannot restore backup trigger $TRIGGER_PATH" >&2
    return 1
  fi
}

if ! pending_type=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --pending-run); then
  echo "cannot read pending backup type; keeping queue wakeup" >&2
  restore_dispatch_trigger || true
  exit 1
fi

case "$pending_type" in
  full)
    exec /bin/bash "$FULL_RUNNER"
    ;;
  diff)
    exec /bin/bash "$DIFF_RUNNER"
    ;;
  none|"")
    # A concurrent runner may have claimed the row between the path event and
    # this lookup. Let the full runner consume the stale wakeup safely.
    exec /bin/bash "$FULL_RUNNER"
    ;;
  *)
    echo "unknown pending backup type: $pending_type; keeping queue wakeup" >&2
    restore_dispatch_trigger || true
    exit 1
    ;;
esac
