#!/usr/bin/env bash
# GitHub 备份库历史折叠：工作树只留最新 N 份加密包，并把历史压成一个提交。
#
# 为什么需要：`backup_runner.sh` 的保留策略只删工作树里的旧 .enc，被删掉的
# blob 仍然留在 git 历史里。2026-10-02 实测正式站备份库已 1.76 GB（工作树只有
# 3 份约 36 MB），照这个速度一直堆下去，GitHub 私有库迟早放不下。
#
# 这个脚本做的两件事：
#   1) 工作树按文件名时间戳只留最新 KEEP 份（默认 3，与 backup_runner 同口径）；
#   2) 历史提交数超过 THRESHOLD（默认 6）时，用孤儿提交把历史折叠成一个提交并
#      强推（force-with-lease）。旧历史在本地留一条 pre-collapse-<ts> 分支兜底。
#
# 安全闸：工作树路径白名单、清单必须存在、最新一份必须还在、远端 sha 必须与本地
# 已知值一致（lease 失败就不推）。任何一步不满足就退出，不做任何写入。
#
# 环境变量（默认值与正式站一致）：
#   BACKUP_ROOT                       默认 /var/lib/authorization-platform-backup
#   BACKUP_GITHUB_WORK_DIR            默认 ${BACKUP_ROOT}/github-sync
#   BACKUP_KEYS_DIR                   默认 ${BACKUP_ROOT}/keys
#   BACKUP_GITHUB_REPO                默认 gthubtom1/authorization-platform-backup
#   BACKUP_GITHUB_BRANCH              默认 main
#   BACKUP_LOG_FILE                   默认 ${BACKUP_ROOT}/backup.log
#   GITHUB_COLLAPSE_KEEP              默认 3（保留份数，1..20）
#   GITHUB_COLLAPSE_COMMIT_THRESHOLD  默认 6（历史提交数超过它才折叠）
#   GITHUB_COLLAPSE_GC_TIMEOUT        默认 900（折叠后后台 gc 的最长秒数）
set -euo pipefail

KEEP=${GITHUB_COLLAPSE_KEEP:-3}
THRESHOLD=${GITHUB_COLLAPSE_COMMIT_THRESHOLD:-6}
BACKUP_ROOT=${BACKUP_ROOT:-/var/lib/authorization-platform-backup}
GH_WORK=${BACKUP_GITHUB_WORK_DIR:-${BACKUP_ROOT}/github-sync}
KEYS=${BACKUP_KEYS_DIR:-${BACKUP_ROOT}/keys}
GH_TOKEN_FILE=${KEYS}/github-token.txt
GH_REPO=${BACKUP_GITHUB_REPO:-}
GH_ORIGIN=${BACKUP_GITHUB_ORIGIN:-}
GH_BRANCH=${BACKUP_GITHUB_BRANCH:-main}
LOG=${BACKUP_LOG_FILE:-${BACKUP_ROOT}/backup.log}

case "$KEEP" in ''|*[!0-9]*) KEEP=3 ;; esac
if [ "$KEEP" -lt 1 ]; then KEEP=1; fi
if [ "$KEEP" -gt 20 ]; then KEEP=20; fi
case "$THRESHOLD" in ''|*[!0-9]*) THRESHOLD=6 ;; esac
if [ "$THRESHOLD" -lt 2 ]; then THRESHOLD=2; fi

log() { printf '[%s] github collapse: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG"; }

if [ ! -d "$GH_WORK/.git" ]; then
  log "work tree missing at ${GH_WORK}; nothing to do"
  exit 0
fi
if [ -L "$GH_TOKEN_FILE" ] || [ ! -s "$GH_TOKEN_FILE" ]; then
  log "github token missing or empty; refusing to rewrite history"
  exit 1
fi

ASKPASS=$(mktemp)
TOKEN_TMP=$(mktemp)
chmod 600 "$TOKEN_TMP"
chmod 700 "$ASKPASS"
printf '%s' "$(cat "$GH_TOKEN_FILE")" >"$TOKEN_TMP"
printf '#!/bin/sh\ncat "%s"\n' "$TOKEN_TMP" >"$ASKPASS"
cleanup() { rm -f -- "$ASKPASS" "$TOKEN_TMP" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

git_net() { GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$ASKPASS" git "$@"; }

cd "$GH_WORK"

# origin 校验：显式给了 BACKUP_GITHUB_REPO / BACKUP_GITHUB_ORIGIN 就按它比；
# 没给就从工作树现有 origin 反推（正式站实际仓库是 ...-prod，页面里配的）。
# 两种情形都必须是 github.com 的 https 地址，避免误推到一个陌生远端。
current=$(git config --get remote.origin.url 2>/dev/null || true)
if [ -z "$current" ]; then
  current=$(git remote get-url origin 2>/dev/null || true)
fi
current=${current%/}
current=${current%.git}
if [ -n "$GH_ORIGIN" ]; then
  expected=${GH_ORIGIN%/}
  expected=${expected%.git}
elif [ -n "$GH_REPO" ]; then
  expected="https://github.com/${GH_REPO}"
else
  expected="$current"
  case "$current" in
    https://github.com/*) ;;
    *) log "origin ${current} is not a github https remote; refusing"; exit 1 ;;
  esac
fi
if [ "$current" != "$expected" ] && [ "$current" != "${expected}.git" ]; then
  log "origin ${current} does not match ${expected}; refusing"
  exit 1
fi

# 白名单：恢复清单、dump 目录，以及启用代码/密钥备份时才会出现的 code/ 与
# secrets/。其余任何路径都拒绝，避免把不该进备份库的东西推上去。
unexpected=$(git status --porcelain=v1 | awk '{print $2}' | grep -vE '^(recovery-manifest\.json|dumps/|dumps/[^/]+\.enc|code/|code/[^/]+|secrets/|secrets/[^/]+)$' || true)
if [ -n "$unexpected" ]; then
  log "unexpected path in work tree (${unexpected}); refusing"
  exit 1
fi
if [ ! -f recovery-manifest.json ]; then
  log "recovery manifest missing; refusing"
  exit 1
fi

# 1) 工作树只留最新 KEEP 份：文件名是 authorization-platform-enc-YYYYMMDD-HHMMSS，
#    字典序即时间序。
shopt -s nullglob
all=(dumps/*.enc)
shopt -u nullglob
if [ "${#all[@]}" -eq 0 ]; then
  log "no encrypted dumps present; refusing"
  exit 1
fi
mapfile -t sorted < <(printf '%s\n' "${all[@]}" | LC_ALL=C sort)
total=${#sorted[@]}
newest=${sorted[$((total - 1))]}
removed=0
if [ "$total" -gt "$KEEP" ]; then
  for ((index = 0; index < total - KEEP; index++)); do
    rm -f -- "${sorted[$index]}"
    removed=$((removed + 1))
  done
fi
if [ ! -f "$newest" ]; then
  log "newest dump ${newest} vanished; refusing"
  exit 1
fi
if [ "$removed" -gt 0 ]; then
  git add -u -- dumps
  if ! git -c user.name="authorization-backup-bot" -c user.email="backup@localhost" \
    commit -m "retention: keep newest ${KEEP} dump(s)" >/dev/null 2>&1; then
    log "retention commit failed (tree already clean?)"
  fi
  log "removed ${removed} old dump(s) from the work tree"
fi

# 2) 历史折叠：提交数不超过阈值就不动，避免每两小时强推一次。
commits=$(git rev-list --count HEAD)
if [ "$commits" -le "$THRESHOLD" ]; then
  log "history has ${commits} commit(s) (<= ${THRESHOLD}); no collapse needed"
  exit 0
fi

sanity_newest=$(sha256sum "$newest" | cut -d' ' -f1)
stamp=$(date -u +%Y%m%d-%H%M%S)
# 本地兜底：折叠前的历史留一条 pre-collapse-<ts> 分支。只留最新一条，否则每折叠
# 一次本地 .git 就多背一整套旧对象（正式站 1.8 GB 量级）。想彻底释放本地空间：
#   git branch -D pre-collapse-* && git reflog expire --expire=now --all && git gc --prune=now
git branch -f "pre-collapse-${stamp}" HEAD >/dev/null 2>&1 || true
while IFS= read -r stale; do
  [ -z "$stale" ] && continue
  [ "$stale" = "pre-collapse-${stamp}" ] && continue
  git branch -D "$stale" >/dev/null 2>&1 || true
done < <(git for-each-ref --format='%(refname:short)' refs/heads 'pre-collapse-*' 2>/dev/null || true)

if ! git_net fetch origin >>"$LOG" 2>&1; then
  log "fetch failed; not collapsing"
  exit 1
fi
# --verify -q：解析失败时输出为空，避免普通 rev-parse 失败把参数原样回显成非法
# lease 值（那样强推会被 git 直接拒掉）。但"空"也可能是本地 tracking ref 缺失、
# 远端其实有分支，所以真正推之前还要用 ls-remote 现场复确认，别把 fail-closed
# 变成 fail-open。
remote_sha=$(git rev-parse --verify -q "refs/remotes/origin/${GH_BRANCH}" 2>/dev/null || true)

git checkout --orphan collapse-tmp >/dev/null 2>&1
# 折叠重建成 dumps/ + 恢复清单；工作树里若还有 code/、secrets/（启用代码/密钥
# 备份时才有），必须一并保留，否则一次折叠就把它们从历史里踢掉。
keep_paths=(dumps recovery-manifest.json)
for extra in code secrets; do
  if [ -d "$extra" ]; then keep_paths+=("$extra"); fi
done
git add -A -- "${keep_paths[@]}"
if ! git -c user.name="authorization-backup-bot" -c user.email="backup@localhost" \
  commit -m "backup: keep newest ${KEEP} dump(s), history collapsed ${stamp}" >/dev/null 2>&1; then
  log "orphan commit failed; restoring ${GH_BRANCH}"
  git checkout -f "$GH_BRANCH" >/dev/null 2>&1 || true
  exit 1
fi
if ! git branch -M collapse-tmp "$GH_BRANCH"; then
  log "branch rename failed; restoring"
  git checkout -f "$GH_BRANCH" >/dev/null 2>&1 || true
  exit 1
fi

# 折叠后必须仍带着最新那份，否则不推。
if [ ! -f "$newest" ]; then
  log "post-collapse tree lost ${newest}; not pushing"
  exit 1
fi
if [ "$(sha256sum "$newest" | cut -d' ' -f1)" != "$sanity_newest" ]; then
  log "post-collapse ${newest} changed on disk; not pushing"
  exit 1
fi

if [ -n "$remote_sha" ]; then
  if ! git_net push --force-with-lease="refs/heads/${GH_BRANCH}:${remote_sha}" \
    origin "$GH_BRANCH" >>"$LOG" 2>&1; then
    log "force push rejected (remote moved or lease stale); next run retries"
    exit 1
  fi
else
  # remote_sha 为空只有两种可能：远端确实还没有这个分支（首次推送），或本地
  # tracking ref 缺失而远端其实有（例如 remote.origin.fetch 被收窄）。后者若直接
  # 无 lease 强推就会覆盖远端，所以现场问一次再决定——不靠推测，保持 fail-closed。
  ls_rc=0
  git_net ls-remote --exit-code --heads origin "refs/heads/${GH_BRANCH}" >/dev/null 2>&1 || ls_rc=$?
  if [ "$ls_rc" -eq 0 ]; then
    log "remote ${GH_BRANCH} exists but local tracking ref missing; refusing unleased force push"
    exit 1
  fi
  if [ "$ls_rc" -ne 2 ]; then
    log "ls-remote failed (rc=${ls_rc}); not pushing"
    exit 1
  fi
  if ! git_net push --force origin "$GH_BRANCH" >>"$LOG" 2>&1; then
    log "force push failed"
    exit 1
  fi
fi

git reflog expire --expire=now --all >/dev/null 2>&1 || true
# gc 在 1~2 GB 的仓库上要十几分钟（2026-10-02 实测一次 15 分钟），同步跑会把调用
# 它的备份 runner 和远端 SSH 一起拖到工具超时。改成后台限时执行、输出进日志，
# 失败或超时都不影响本轮折叠结论；下一轮折叠前 git 自己会再排一次。
GC_TIMEOUT=${GITHUB_COLLAPSE_GC_TIMEOUT:-900}
if command -v timeout >/dev/null 2>&1; then
  nohup timeout "$GC_TIMEOUT" git gc --prune=now --quiet </dev/null >>"$LOG" 2>&1 &
else
  nohup git gc --prune=now --quiet </dev/null >>"$LOG" 2>&1 &
fi

after=$(git rev-list --count HEAD)
log "history collapsed: ${commits} -> ${after} commit(s), newest dump ${newest}, ${KEEP} kept"
exit 0
