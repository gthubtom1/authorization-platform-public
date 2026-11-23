#!/usr/bin/env bash
# 授权平台备份 runner（VPS 侧）
# 职责：pgBackRest 完整备份 → 加密 dump → GitHub 私有库同步 → 健康 marker
# 口令/令牌只从 root 600 文件读取，不回显、不写日志。
set -euo pipefail

RUN_TYPE="full"
PROOF_FILE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --type=*) RUN_TYPE="${1#*=}" ;;
    --type) shift; RUN_TYPE="${1:-}" ;;
    --proof-file=*) PROOF_FILE="${1#*=}" ;;
    --proof-file) shift; PROOF_FILE="${1:-}" ;;
    *) echo "unsupported argument: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$RUN_TYPE" != "full" ] && [ "$RUN_TYPE" != "diff" ]; then
  echo "backup type must be full or diff" >&2
  exit 2
fi
if [ -z "$PROOF_FILE" ] || [[ "$PROOF_FILE" != /* ]]; then
  echo "absolute --proof-file is required; refusing unproven backup" >&2
  exit 2
fi

BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
RUN_ID_FILE=${BACKUP_RUN_ID_FILE:-${BACKUP_ROOT}/current-run-id}
LOG=${BACKUP_LOG_FILE:-${BACKUP_ROOT}/backup.log}
STANZA=${BACKUP_STANZA:-authorization-platform}
DB_CONTAINER=${AUTHORIZATION_PLATFORM_DB_CONTAINER:-}
if [ -z "$DB_CONTAINER" ]; then
  echo "AUTHORIZATION_PLATFORM_DB_CONTAINER is required; refusing dump of an unknown database container" >&2
  exit 1
fi
PYTHON_BIN=${PYTHON_BIN:-python3}
DB_NAME=${DATABASE_NAME:-authorization_platform}
DB_USER=${DATABASE_USER:-authorization_platform}
case "$DB_CONTAINER" in
  ''|*[!A-Za-z0-9_.-]*) echo "AUTHORIZATION_PLATFORM_DB_CONTAINER contains unsupported characters" >&2; exit 1 ;;
esac
case "$STANZA" in
  ''|*[!A-Za-z0-9_.-]*) echo "BACKUP_STANZA contains unsupported characters" >&2; exit 1 ;;
esac
case "$DB_NAME" in
  ''|[!A-Za-z_]*|*[!A-Za-z0-9_]*) echo "DATABASE_NAME must be a simple PostgreSQL identifier" >&2; exit 1 ;;
esac
case "$DB_USER" in
  ''|[!A-Za-z_]*|*[!A-Za-z0-9_]*) echo "DATABASE_USER must be a simple PostgreSQL identifier" >&2; exit 1 ;;
esac
KEYS=${BACKUP_KEYS_DIR:-${BACKUP_ROOT}/keys}
GH_TOKEN_FILE=${KEYS}/github-token.txt
GH_DUMP_PASS=${BACKUP_DUMP_PASS_FILE:-${BACKUP_ROOT}/host-secrets/github-dump-pass.txt}
if [ -L "$GH_DUMP_PASS" ] || [ ! -f "$GH_DUMP_PASS" ] || [ ! -s "$GH_DUMP_PASS" ]; then
  echo "github dump pass missing or empty" >&2
  exit 1
fi
GH_REPO=${BACKUP_GITHUB_REPO:-gthubtom1/authorization-platform-backup}
GH_WORK=${BACKUP_GITHUB_WORK_DIR:-${BACKUP_ROOT}/github-sync}
GH_BRANCH=main
TS=$(date -u +%Y%m%d-%H%M%S)
DUMP_NAME=authorization-platform-enc-${TS}.dump.enc
DUMP_DIR=${GH_WORK}/dumps
DOWNLOAD_DIR=${BACKUP_DOWNLOAD_DIR:-${BACKUP_ROOT}/downloads}
EVIDENCE_DIR=${BACKUP_EVIDENCE_DIR:-${BACKUP_ROOT}/evidence/${TS}}
MIGRATION_GRAPH_FILE=${BACKUP_MIGRATION_GRAPH_FILE:-}
CANDIDATE_COMMIT=${BACKUP_CANDIDATE_COMMIT:-}
KEY_VERSIONS=${BACKUP_KEY_VERSIONS:-}

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$LOG"; }

POLICY_MANAGE=${AUTHORIZATION_PLATFORM_MANAGE:-}
if [ -z "$POLICY_MANAGE" ]; then
  for candidate in \
    /srv/authorization-platform/manage.py \
    /opt/authorization-platform-candidate-clean-rc8-staging/manage.py
  do
    if [ -f "$candidate" ]; then POLICY_MANAGE="$candidate"; break; fi
  done
fi
mkdir -p "$BACKUP_ROOT" "$(dirname "$LOG")"
if [ ! -f "$POLICY_MANAGE" ]; then log "manage.py missing; refusing backup policy defaults"; exit 1; fi
if [ -z "${BACKUP_PROOF_GENERATOR:-}" ]; then
  log "BACKUP_PROOF_GENERATOR missing; refusing to start dump"
  exit 1
fi
if [ ! -e "$BACKUP_PROOF_GENERATOR" ]; then
  log "BACKUP_PROOF_GENERATOR is not a file"
  exit 1
fi
if [ -z "${BACKUP_EVIDENCE_COLLECTOR:-}" ] || [ ! -e "$BACKUP_EVIDENCE_COLLECTOR" ]; then
  log "BACKUP_EVIDENCE_COLLECTOR missing; refusing to start dump"
  exit 1
fi
if [ -z "${BACKUP_MIGRATION_GRAPH_FILE:-}" ] || [ ! -f "${BACKUP_MIGRATION_GRAPH_FILE:-}" ] || [ -L "${BACKUP_MIGRATION_GRAPH_FILE:-}" ] || [ -z "${BACKUP_CANDIDATE_COMMIT:-}" ] || [ "${BACKUP_CANDIDATE_COMMIT}" = "unknown" ] || [ -z "${BACKUP_KEY_VERSIONS:-}" ]; then
  log "proof binding inputs missing"
  exit 1
fi
MIGRATION_GRAPH_FILE=${BACKUP_MIGRATION_GRAPH_FILE}
CANDIDATE_COMMIT=${BACKUP_CANDIDATE_COMMIT}
KEY_VERSIONS=${BACKUP_KEY_VERSIONS}
RETENTION_COUNT=7
RETENTION_COUNT=$($PYTHON_BIN "$POLICY_MANAGE" backup_policy --github-retention)
if [ "$RETENTION_COUNT" -gt 3 ]; then RETENTION_COUNT=3; fi
if [ "$RETENTION_COUNT" -lt 1 ]; then RETENTION_COUNT=1; fi
CLEANUP_STATE=$($PYTHON_BIN "$POLICY_MANAGE" backup_policy --cleanup-check)
GH_STATE=$($PYTHON_BIN "$POLICY_MANAGE" backup_policy --github-check)
POLICY_GH_REPO=$($PYTHON_BIN "$POLICY_MANAGE" backup_policy --github-repo)
if [ -n "$POLICY_GH_REPO" ]; then
  GH_REPO="$POLICY_GH_REPO"
fi
ASKPASS=""
TOKEN_TMP=""
github_origin_matches() {
  local current expected
  current=$(git -C "$GH_WORK" remote get-url origin 2>/dev/null || true)
  current=${current%/}
  current=${current%.git}
  expected="https://github.com/${GH_REPO}"
  [ "$current" = "$expected" ] || [ "$current" = "${expected}.git" ]
}
clone_github_worktree() {
  mkdir -p "$(dirname "$GH_WORK")"
  if [ -e "$GH_WORK" ]; then
    mv "$GH_WORK" "${GH_WORK}.pre-clone.$$"
  fi
  if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" git clone "https://github.com/${GH_REPO}.git" "$GH_WORK" >>"$LOG" 2>&1; then
    log "github clone failed"
    [ -e "${GH_WORK}.pre-clone.$$" ] && mv "${GH_WORK}.pre-clone.$$" "$GH_WORK"
    return 1
  fi
  if [ -d "${GH_WORK}.pre-clone.$$/dumps" ]; then
    mkdir -p "$GH_WORK/dumps"
    cp -a "${GH_WORK}.pre-clone.$$/dumps/." "$GH_WORK/dumps/" || true
  fi
  if [ -f "${GH_WORK}.pre-clone.$$/recovery-manifest.json" ]; then
    cp -a "${GH_WORK}.pre-clone.$$/recovery-manifest.json" "$GH_WORK/recovery-manifest.json"
  fi
  rm -rf "${GH_WORK}.pre-clone.$$"
}

mkdir -p "$BACKUP_ROOT" "$GH_WORK/dumps" "$DOWNLOAD_DIR"
# App container uid 10001 lists the dashboard and deletes extra .enc. Never chmod 700 the backup root.
chown root:10001 "$BACKUP_ROOT" "$DOWNLOAD_DIR" 2>/dev/null || true
chmod 750 "$BACKUP_ROOT" 2>/dev/null || true
chmod 770 "$DOWNLOAD_DIR" 2>/dev/null || true
chmod 700 "$GH_WORK" 2>/dev/null || true
mkdir -p "$(dirname "$LOG")"
printf '%s' "$TS" > "${RUN_ID_FILE}.tmp"
mv -f "${RUN_ID_FILE}.tmp" "$RUN_ID_FILE"
rm -f -- "$PROOF_FILE"

DOCKER_DUMP=/tmp/auth-dump-${TS}.dump
PLAIN_COPY="${DUMP_DIR}/${DUMP_NAME}.plain"
cleanup_plaintext() {
  rm -f -- "$DOCKER_DUMP" "$PLAIN_COPY" 2>/dev/null || true
  docker exec "$DB_CONTAINER" rm -f "$DOCKER_DUMP" >/dev/null 2>&1 || true
}
cleanup_all() {
  cleanup_plaintext
  rm -f -- "${ASKPASS:-}" "${TOKEN_TMP:-}" 2>/dev/null || true
}
trap cleanup_all EXIT INT TERM

# 当前最新备份标签（复核是否成功）
LAST_LABEL=$(docker exec -u postgres "$DB_CONTAINER" pgbackrest --stanza="$STANZA" info 2>/dev/null | grep -oE "[0-9]{8}-[0-9]{6}F" | head -1 || true)
log "backup label after run: ${LAST_LABEL:-none}"

# 1) 加密 dump：pg_dump custom → openssl AES-256-CBC（口令从 root 600 文件读）
#    DUMP_PROOF_FAILED 与后面 pgBackRest 的 PROOF_FAILED 是两件事：
#    加密 dump 是这套部署真正交付的产物，它坏了就是坏了，任何形态都必须失败。
DUMP_PROOF_FAILED=0
log "starting encrypted dump"
if [ ! -s "$GH_DUMP_PASS" ]; then
  echo "github dump pass missing or empty" >&2
  log "github dump pass missing or empty"
  exit 1
fi
docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" --format=custom -f "$DOCKER_DUMP"
docker cp "$DB_CONTAINER:$DOCKER_DUMP" "$PLAIN_COPY"
docker exec "$DB_CONTAINER" rm -f "$DOCKER_DUMP"

openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in "${DUMP_DIR}/${DUMP_NAME}.plain" \
  -out "${DUMP_DIR}/${DUMP_NAME}" \
  -pass file:"$GH_DUMP_PASS" 2>>"$LOG"
SHA_ENC=$(sha256sum "${DUMP_DIR}/${DUMP_NAME}" | cut -d' ' -f1)
log "encrypted dump ready: ${DUMP_NAME} sha256=${SHA_ENC:0:16}"

# 立刻验证这份 .enc 能不能用口令解开、并读回 pg_dump custom 的文件头。
# 全仓此前没有任何一处解过它——只有 sha256，而 sha256 对"口令不对""openssl
# 参数变过""文件被截断"全都无能为力。坏文件会安静躺满整个轮替窗口，然后被
# prune_dir 连同真正的好备份一起删掉。验证必须发生在 prune_dir 之前。
#
# 这里刻意**不使用管道**。`openssl … | head -c 5 | grep` 在 set -o pipefail 下是恒假的：
# head 拿够 5 字节就退出，openssl 吃到 SIGPIPE 退出 1，整条管道被判失败——好备份
# 也会被拒。2026-09-27 在测试站真跑出过一次：产物完全正常，判决却是 unusable，
# 于是每次备份都硬失败。所以改成两个不依赖管道的判断：
#   1) 文件头从**刚写出的明文 dump** 读（它本来就要被删，不额外落任何明文文件）；
#   2) 口令能不能解开 .enc，用 openssl 显式 -out /dev/null 与它的退出码判断。
PGDMP_MAGIC=$(head -c 5 "${DUMP_DIR}/${DUMP_NAME}.plain" 2>/dev/null || true)
if [ "$PGDMP_MAGIC" != "PGDMP" ]; then
  log "pg_dump output does not begin with the PGDMP header"
  DUMP_PROOF_FAILED=1
fi
if openssl enc -d -aes-256-cbc -pbkdf2 \
     -in "${DUMP_DIR}/${DUMP_NAME}" \
     -out /dev/null \
     -pass file:"$GH_DUMP_PASS" >>"$LOG" 2>&1; then
  if [ "$DUMP_PROOF_FAILED" -eq 0 ]; then
    log "encrypted dump verified: decrypts with the stored passphrase to a pg_dump custom header"
  fi
else
  log "encrypted dump unusable: the stored passphrase does not decrypt it"
  DUMP_PROOF_FAILED=1
fi
rm -f "${DUMP_DIR}/${DUMP_NAME}.plain"
if [ "$DUMP_PROOF_FAILED" -ne 0 ]; then
  # A failed artifact must never replace a valid copy/manifest or enter rotation.
  # The EXIT trap also removes plaintext left by an interrupted verification.
  rm -f -- "${DUMP_DIR}/${DUMP_NAME}"
  log "encrypted dump verification failed; delivery and rotation refused"
  exit 1
fi

# 管理端下载副本：只复制已加密文件，不复制明文 dump 或恢复口令。
mkdir -p "$DOWNLOAD_DIR"
cp -- "${DUMP_DIR}/${DUMP_NAME}" "$DOWNLOAD_DIR/${DUMP_NAME}"
chown root:10001 "$DOWNLOAD_DIR/${DUMP_NAME}" 2>/dev/null || true
chmod 640 "$DOWNLOAD_DIR/${DUMP_NAME}" 2>/dev/null || true

# 2a) 第三份异地副本：把**已加密**的这份上传到 Telegram 私有频道。
#只做全量（每天一次）：增量每 2 小时一份，全传会把频道塞满。
#缺凭据/上传失败都只记一行日志，**绝不影响本次备份的成败**。
if [ "$RUN_TYPE" = "full" ] && [ "$DUMP_PROOF_FAILED" -eq 0 ]; then
  TELEGRAM_COPY_SCRIPT="$(dirname "$0")/telegram_backup_copy.sh"
  if [ -x "$TELEGRAM_COPY_SCRIPT" ]; then
    "${TELEGRAM_COPY_SCRIPT}" "${DUMP_DIR}/${DUMP_NAME}" "${TELEGRAM_BACKUP_KEEP:-7}" || true
  else
    log "telegram backup copy: script missing (${TELEGRAM_COPY_SCRIPT}); skipped"
  fi
else
  [ "$RUN_TYPE" = "full" ] && log "telegram backup copy: dump not verified; nothing uploaded"
fi

# 2) 恢复清单（脱敏，不包含口令/密钥）：schema 版本、表/角色计数、备份标签、加密摘要
DUMP_SHA=$(sha256sum "${DUMP_DIR}/${DUMP_NAME}" | cut -d' ' -f1)
cat > "${GH_WORK}/recovery-manifest.json" <<EOF
{
  "schema_version": 2,
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source": "${DB_CONTAINER}",
  "backup_label": "${LAST_LABEL}",
  "encrypted_dump": "dumps/${DUMP_NAME}",
  "encrypted_dump_sha256": "${DUMP_SHA}",
  "encryption": "aes-256-cbc-pbkdf2",
  "note": "口令在 VPS root 600 的 github-dump-pass.txt 与本机 部署与恢复/灾备钥匙包，不在本仓库。",
  "protected": "no-plaintext-dumps-env-or-secrets"
}
EOF
log "manifest written"

# 3) 循环覆盖：本机和 GitHub 工作树最多留 3 份加密包
prune_dir() {
  local dir="$1"
  find "$dir" -maxdepth 1 -type f \( -name '*.enc' -o -name '*.dump' -o -name '*.plain' \) -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr | awk -v keep="$RETENTION_COUNT" 'NR > keep {sub(/^[^ ]+ /, ""); print}' \
    | xargs -r rm -f --
}
prune_dir "$DUMP_DIR"
prune_dir "$DOWNLOAD_DIR"

# 4) GitHub 白名单推送：本机加密包已就绪即可推送。github push does not wait for proof
if [ "$GH_STATE" = "enabled" ]; then
  if [ -s "$GH_TOKEN_FILE" ]; then
    log "github token file already present; skipping django write"
  else
    $PYTHON_BIN "$POLICY_MANAGE" backup_policy --write-github-token "$GH_TOKEN_FILE"
  fi
  TOKEN_TMP=$(mktemp)
  ASKPASS=$(mktemp)
  chmod 600 "$TOKEN_TMP"
  printf '%s' "$(cat "$GH_TOKEN_FILE")" > "$TOKEN_TMP"
  chmod 700 "$ASKPASS"
  printf '#!/bin/sh\ncat "%s"\n' "$TOKEN_TMP" > "$ASKPASS"
  if [ ! -d "$GH_WORK/.git" ] || ! github_origin_matches; then
    if ! clone_github_worktree; then
      log "github clone failed after local dump; encrypted dump kept"
      exit 1
    fi
  else
    git -C "$GH_WORK" remote set-url origin "https://github.com/${GH_REPO}.git"
  fi
  cd "$GH_WORK"
  unexpected_paths=$(git status --porcelain=v1 | awk '{print $2}' | grep -vE '^(recovery-manifest\.json|dumps/|dumps/[^/]+\.enc)$' || true)
  if [ -n "$unexpected_paths" ]; then
    log "unexpected changed path in GitHub backup work tree; refusing push"
    exit 1
  fi
  shopt -s nullglob
  enc_files=(dumps/*.enc)
  shopt -u nullglob
  if [ ! -f recovery-manifest.json ]; then
    log "recovery manifest missing; refusing github push"
    exit 1
  fi
  if [ ${#enc_files[@]} -eq 0 ]; then
    log "no encrypted dumps to add; refusing github push"
    exit 1
  fi
  git add -- recovery-manifest.json "${enc_files[@]}"
  git add -u -- dumps
  if ! git -c user.name="authorization-backup-bot" -c user.email="backup@localhost" \
    commit -m "backup ${TS} label=${LAST_LABEL}" >/dev/null 2>&1; then
    log "github commit failed"
    exit 1
  fi
  if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" git fetch origin >>"$LOG" 2>&1; then
    log "github fetch failed"
    exit 1
  fi
  if git rev-parse --verify "origin/${GH_BRANCH}" >/dev/null 2>&1; then
    if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" \
      git -c user.name="authorization-backup-bot" -c user.email="backup@localhost" \
      merge -X ours --no-edit "origin/${GH_BRANCH}" >>"$LOG" 2>&1; then
      log "github merge failed"
      git merge --abort >/dev/null 2>&1 || true
      exit 1
    fi
  fi
  if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" git push "https://github.com/${GH_REPO}.git" "$GH_BRANCH" >>"$LOG" 2>&1; then
    log "github push failed"
    exit 1
  fi
  log "github push done"
  # 光删工作树里的旧 .enc 不会让仓库变小：blob 还在 git 历史里。2026-10-02 实测
  # 正式站备份库已 1.76 GB 而工作树只有 3 份约 36 MB。折叠失败不影响本次备份
  # （加密包已经推上去了），只写日志，下一轮再试。
  collapse_script="$(cd "$(dirname "$0")" && pwd)/github_collapse.sh"
  if [ -x "$collapse_script" ]; then
    if ! BACKUP_GITHUB_REPO="$GH_REPO" "$collapse_script" >>"$LOG" 2>&1; then
      log "github collapse skipped or failed; encrypted dump already pushed"
    fi
  else
    log "github collapse script missing; history retention not applied"
  fi
else
  log "github copy disabled; encrypted dump kept locally"
fi

# 5) 证明：失败不撤回已写出的本机/GitHub 副本。
# 必须用 PYTHON_BIN 跑 .py。没有 shebang 时 +x 会被当成 shell，验收脚本直接碎掉。
PROOF_FAILED=0
set +e
"$PYTHON_BIN" "$BACKUP_EVIDENCE_COLLECTOR" --type "$RUN_TYPE" --backup-run-id "$TS" --evidence-dir "$EVIDENCE_DIR" --db-container "$DB_CONTAINER" --db-name "$DB_NAME" --db-user "$DB_USER" --stanza "$STANZA" --app-manage "$POLICY_MANAGE" --dump-file "$DOWNLOAD_DIR/$DUMP_NAME" --migration-graph-file "$MIGRATION_GRAPH_FILE"
collector_rc=$?
PROOF_TMP="${PROOF_FILE}.${TS}.tmp"
rm -f -- "$PROOF_TMP"
IFS=',' read -r -a KEY_VERSION_LIST <<< "$KEY_VERSIONS"
GENERATOR_ARGS=(--type "$RUN_TYPE" --proof-file "$PROOF_TMP" --backup-run-id "$TS" --evidence-dir "$EVIDENCE_DIR" --dump-file "$DOWNLOAD_DIR/$DUMP_NAME" --migration-graph-file "$MIGRATION_GRAPH_FILE" --candidate-commit "$CANDIDATE_COMMIT")
# Optional content fingerprint of the deployed tree. A git SHA alone cannot
# identify the bytes that actually run when the tree has uncommitted edits.
if [ -n "${BACKUP_CANDIDATE_TREE_SHA256:-}" ]; then
  GENERATOR_ARGS+=(--candidate-tree-sha256 "$BACKUP_CANDIDATE_TREE_SHA256")
fi
for key_version in "${KEY_VERSION_LIST[@]}"; do GENERATOR_ARGS+=(--key-version "$key_version"); done
"$PYTHON_BIN" "$BACKUP_PROOF_GENERATOR" "${GENERATOR_ARGS[@]}"
generator_rc=$?
set -e
if [ "$collector_rc" -ne 0 ] || [ "$generator_rc" -ne 0 ]; then
  PROOF_FAILED=1
fi
if [ "$collector_rc" -eq 0 ] && [ "$generator_rc" -eq 0 ] && [ -f "$PROOF_TMP" ] && [ ! -L "$PROOF_TMP" ]; then
  if ! mv -f "$PROOF_TMP" "$PROOF_FILE"; then
    log "backup proof file missing after run"
    PROOF_FAILED=1
  fi
else
  log "proof generator did not produce a regular temporary proof"
  PROOF_FAILED=1
fi
if [ ! -f "$PROOF_FILE" ] || [ -L "$PROOF_FILE" ]; then
  log "backup proof file missing after run"
  PROOF_FAILED=1
fi
DB_STATE=$("$PYTHON_BIN" "$POLICY_MANAGE" backup_policy --database-check 2>/dev/null || echo "disabled")
if [ "$PROOF_FAILED" -eq 1 ]; then
  if [ "$DB_STATE" = "enabled" ]; then
    log "proof incomplete; encrypted dump kept"
  else
    # dump-only 形态：这套部署没有 pgBackRest，双仓与 WAL 证明天然不齐。那不是
    # 失败，但也不能什么都不说——旧实现在这里静默 exit 0，于是"证明不齐"和
    # "备份成功"在日志、systemd、数据库和页面上长得一模一样。
    log "pgBackRest proof skipped (dump-only mode: no pgBackRest repository in this deployment); the encrypted dump is the artifact of record"
  fi
fi
FAILED=0
if [ "$DUMP_PROOF_FAILED" -ne 0 ]; then
  FAILED=1
fi
if [ "$PROOF_FAILED" -ne 0 ] && [ "$DB_STATE" = "enabled" ]; then
  FAILED=1
fi
if [ "$FAILED" -ne 0 ]; then
  log "backup runner complete (failed)"
  exit 1
fi
log "backup runner complete"
exit 0
