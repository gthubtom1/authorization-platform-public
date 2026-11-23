# Runbook

换机、密钥、导入备份、**装机和更新代码**看项目根 `部署与恢复/`（步骤只准 `08-完整部署SOP.md`）。接授权页 A 看 `接入说明/`。下面只写本机怎么跑、怎么测。

## Environments

本地开发与隔离验收在本项目进行；现行平台部署事实看STATUS，实际服务器操作只看根部署目录。旧测试服务器已过期，不能作为本地脚本的默认联调目标。

当前本地切片使用 Python 3.12、Django 5.2.17、Psycopg 3.2.13 和 cryptography 50.0.0。SQLite 是第一次本地启动的默认数据库；PostgreSQL 17 已安装并运行，但本机认证凭据尚未纳入项目，不能猜测或自动修改。**本机 PostgreSQL 服务存在或正在运行，不等于它是已批准的验收环境。**

## 冻结 8124 静态预览与 8123 本地同源网关

五个前端页面仍来自冻结的 `docs/ui-preview/`。只想检查方案 A 空态视觉原型时，单独启动静态服务器：

```powershell
python -m http.server 8124 --bind 127.0.0.1 --directory .\docs\ui-preview
```

以 `http://127.0.0.1:8124/` 为静态预览基址，按后缀访问冻结页面；静态页面没有数据库或账号，只用于空态/结构/视觉检查，不执行真实业务写入。真实本地页面接线使用 8123 同源网关：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1
```

该命令让 Django 监听内部 `127.0.0.1:8000`，让 8123 网关提供冻结页面并把 `/api/`、`/healthz/` 转发到 Django。浏览器、Cookie、CSRF 和真实 API 验收统一使用 8123；8000 只用于内部诊断，不是用户入口。

真实 B2.2 目录验收：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\frozen-8123-acceptance.ps1
```

本地用户入口是8123的冻结页面与同源API，内部8000仅诊断。旧Django业务页面返回410，不能作为兼容入口恢复；后续改动继续使用现行五页面，不新增8143。

运行三档真实浏览器验收并保留截图：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/ui-preview-acceptance.ps1 -KeepArtifacts
```

## Documentation Check

运行：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-docs.ps1`

该检查只验证文档存在、关键链接/术语和功能 ID 格式，不代替业务测试。

## Start And Stop

### Start

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1
```

浏览器打开 `http://127.0.0.1:8123/manage-login.html` 或 `http://127.0.0.1:8123/downstream-login.html`。内部 Django 健康检查为 `http://127.0.0.1:8000/healthz/`，同源浏览器健康检查为 `http://127.0.0.1:8123/healthz/`。

### Demo data

```powershell
$env:DEMO_ADMIN_PASSWORD = "至少 10 位的本地密码"
$env:DEMO_DOWNSTREAM_PASSWORD = "至少 10 位的本地密码"
& .\.venv\Scripts\python.exe .\manage.py seed_demo
```

命令只输出账号名，不输出密码。没有环境变量时会隐藏输入密码。管理员名或下游名已在库里时命令失败退出，不会改已有账号的角色或密码。

### PR-02 local flow

1. 运行 `seed_demo` 后打开 `http://127.0.0.1:8123/manage-login.html`，使用管理员账号进入 `manage.html`；下游账号从 `http://127.0.0.1:8123/downstream-login.html` 进入 `downstream.html`。
2. 在“生成邀请码”页面输入数量；结果按单码列表交付，不提供批次页或批次号，历史记录默认只显示 UUID。
3. 需要重新交付时，在历史记录中使用受权限保护的 POST 查看动作；完整码显示、复制、下载不写“谁看过”查看审计，仍需 `no-store`、限速和脱敏。
4. 不再允许注册时，在同一列表点击“作废”；作废必须带 CSRF，且邀请码不能恢复。
5. 管理员可以直建下游。新下游使用 `http://127.0.0.1:8123/downstream-register.html` 注册，再从 `downstream-login.html` 进入自己的工作台；登录和注册请求由同源 `/api/v1/` 服务处理。
6. 归档下游后，其旧会话在下一次受保护请求时失效；活跃账号不能直接删除，归档后删除会保留脱敏墓碑。

PR-02 的账号、邀请码和审计迁移由 `run-local.ps1` 自动执行。手工检查迁移状态可以运行：

```powershell
& .\.venv\Scripts\python.exe .\manage.py showmigrations accounts audit
& .\.venv\Scripts\python.exe .\manage.py makemigrations --check --dry-run
```

`accounts.0002_invitationcode_public_id` 采用“允许空值 → 为历史行回填 UUID → 检查空值/重复 → 收紧为非空唯一”的顺序。历史迁移的本地验证不代表可逆；若已有外部链接或审计引用了公开 UUID，不要用反向迁移当生产回滚方案，应先备份并按恢复流程处理。生产迁移还需要单独演练备份、失败重试和 PostgreSQL 锁行为。

### B3.1 quota flow（当前本地切片）

1. 管理员在冻结的 `manage.html` 额度区块保存购买链接，并按数量发行不预绑下游的额度兑换码；不能创建新的 Django 页面或 8143。
2. 退出管理员后，使用冻结的 `downstream.html` 额度区块查看余额和流水；旧 Django `/downstream/credits/` 页面已退役，不作为用户入口。
3. 下游输入管理员交付的完整额度码并点击“兑换额度”。成功后页面显示前后余额，流水列出北京时间、金额和前后余额；实际兑换下游由服务端当前会话确定。
4. 再次提交同一额度码必须失败或稳定重放，余额和流水只能增加一次。购买链接的同一幂等键同内容稳定重放、同键不同内容冲突，旧键迟到重试不能覆盖当前配置。

### B6 版本、统计和受控存储（当前本地候选）

定向回归：

```powershell
& .\.venv\Scripts\python.exe .\manage.py test tests.test_releases tests.test_analytics tests.test_storage_cleanup --verbosity 2
node --check docs/ui-preview/preview.js
git diff --check
```

当前 API 入口为：版本管理 `/api/v1/manage/releases/`、公共版本 registry/download `/api/v1/public/software/{software_id}/profiles/{profile_id}/releases/`、统计 `/api/v1/manage/analytics/summary/` 与 `/api/v1/downstream/analytics/summary/`、清理 `/api/v1/manage/storage/cleanup/`。版本包必须包含唯一 `client-release.v1` Manifest；生产 Manifest 必须提供签名覆盖的 `payload_sha256`，平台另行保存完整包 SHA-256，`declared` 签名只适合开发候选，生产必须绑定 Key ID 并使用有效公钥。清理删除前重新核对路径、普通文件、大小和已记录哈希，篡改或符号链接跳过。

容量验收使用 `deploy/capacity-thresholds.json` 和 `scripts/capacity_threshold_acceptance.py`：每个目标 200 请求/20 并发、p95 不超过 1000ms、0 个传输错误、0 个 429 且全部返回预期 200。SkinForge registry 目标必须带 `client_id`、`target`、`arch`、`channel` 四个身份参数。该阈值是当前候选上线门，不是最大容量或压力测试；超过阈值必须保留失败证据并停止切流。

静态 8124 预览只保留页面结构、表头、筛选、分页、空态和交互骨架，不携带任何软件、下游、套餐、卡密、额度、设备、版本或审计演示记录；静态保存/生成/清理动作不得合成业务对象或调用 API。发布候选前必须运行 `python scripts/check_ui_preview.py`，并用 `python scripts/release_candidate_acceptance.py --candidate-archive <候选归档>` 扫描归档内的 `docs/ui-preview/`。静态预览不能单独当作真实 API、数据库、权限或文件系统证据；真实 8123 验收通过 `run-local.ps1` 启动 Django 与同源网关后，以管理员/下游会话观察页面从 API 返回的状态。不得把静态空态骨架或本地内部标记写成平台事实。
5. 额度列表、流水和发行结果按单码展示；一次生成多张是允许的，但不提供批次页、批次号、批次列、批次筛选、按批次交付或“回收本批”。

历史 PR-04 中关于“预绑指定下游”的内容仅作历史参考，不是当前 B3.1 合同。当前 SQLite 测试覆盖模型约束、顺序状态机、幂等、回滚、权限和财务历史保留；`select_for_update()` 行锁、跨 Worker 幂等和同卡/同账户并发仍需在隔离 PostgreSQL 测试库中验证。

### PostgreSQL 并发验证（隔离候选已验证，正式生产拓扑仍待验证）

运行前必须由项目负责人确认目标是可丢弃的隔离验收数据库和专用测试角色。以下变量只能通过当前进程的安全注入方式提供，不能把真实密码写入仓库、`.env.example`、文档或共享命令记录，也不能根据默认值猜测：

```text
DATABASE_ENGINE=postgresql
DATABASE_HOST=<confirmed-isolated-host>
DATABASE_PORT=<confirmed-port>
DATABASE_NAME=<confirmed-isolated-database>
DATABASE_USER=<confirmed-test-role>
DATABASE_PASSWORD=<provided-secret>
```

推荐使用 fail-closed runner（密码仍只注入当前 PowerShell 进程，不要写入命令、文档或日志）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\postgresql-concurrency-acceptance.ps1 `
  -ConfirmIsolatedTarget `
  -ApprovedHost "<confirmed-isolated-host>" `
  -ApprovedServerAddress "<confirmed-server-address>" `
  -ApprovedPort <confirmed-port> `
  -ApprovedDatabase "<confirmed-isolated-database>" `
  -ApprovedUser "<confirmed-test-role>"
```

runner 会先执行不连接数据库的配置预检，再比较当前进程的 `DATABASE_HOST`、`DATABASE_PORT`、`DATABASE_NAME`、`DATABASE_USER` 与批准参数；只有完全一致后才核对 Git HEAD、当前分支和干净工作树，再允许目标库只读连接。之后依次执行目标/维护库身份核对和维护库 `CREATEDB` 权限核对。runner 为每次运行生成唯一的测试库名，并通过维护库的原子 `CREATE DATABASE` 预留它，随后用临时 Django settings 和 `--keepdb` 运行测试；测试结束、失败或超时后在 `finally` 中执行 `DROP DATABASE ... WITH (FORCE)`，再核对测试库不存在。配置不一致、Git 证据失败或任一资源清理无法证明成功时不会进入/不会通过测试。测试结果必须按当前选择的专项实际收集数记录，`skipped=0`、失败0、错误0；不能沿用旧固定测试数量，并且 stdout、stderr、身份摘要、Git 状态、清理结果、退出码和 commit 会保存到被 Git 忽略的 `output/postgresql-concurrency/<unique-run>/` 目录。

runner 的 `-ApprovedServerAddress` 应填写只读身份查询返回的实际 `inet_server_addr()`，不能用未经确认的默认值。当前本地 runner 只接受 `localhost`/`127.0.0.1`/`::1` 的 loopback 目标，并且只允许 `-MaintenanceDatabase postgres`，以避免 Django no-DB 连接回退到未批准维护库；远程 PostgreSQL 需要单独的 TLS/证书和目标绑定合同。runner 会拒绝维护库不可达或角色没有 `CREATEDB` 的情况，唯一测试库的预留由数据库原子创建操作决定，不使用“先查询不存在、再创建”的竞态窗口。每个子进程默认最多运行 900 秒，可用 `-ProcessTimeoutSeconds` 在 1 至 3600 秒内调整；超时会终止并核对整个进程树，输出管道排空也有界，任一项无法证明成功则以失败退出。`-OutputDirectory` 只能指向 `output\postgresql-concurrency\` 下尚不存在的新目录，默认目录包含毫秒时间和随机 ID，不会覆盖旧证据。该 runner 只创建并清理自己生成的唯一测试库，不会自动删除其他旧数据库，也不会连接未批准的目标。

如需单独诊断，仍可先运行以下两个命令；目标未确认时不要运行 `-CheckConnection`，它们不替代 runner 的批准目标、维护库和零 skip 门禁：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\preflight-postgresql.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\preflight-postgresql.ps1 -CheckConnection
```

`-CheckConnection` 只执行目标库只读查询，不等于并发测试通过；Django 测试会在 runner 预留的唯一测试库中创建/写入，runner 负责结束后的删除和残留核对。批准的隔离 PostgreSQL runner 已实际运行 18 项、18 项通过、0 skip，覆盖撤销/阻断↔`verify`、重复激活、绑定重试和相关账本竞态；生产数据库的规格、连接池、故障注入和容量仍未验证。直接运行 `scripts/test.ps1` 或 `manage.py test` 仍不能代替 runner。

### Test

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1
```

停止本地开发服务器使用运行窗口中的 `Ctrl+C`。当前 F-018/F-019/F-020 的冻结 8123 版本/统计/清理页面验收已完成；候选 VPS 已有正式域名/TLS、隔离 PostgreSQL 备份恢复、两个进程共享限流、对象存储 CRUD、应用回滚演练和 200/20 有界容量证据。证书/密钥轮换、生产更新包下载/验签/安装、异地备份/PITR/RPO/RTO、告警和 A-core 强绑定仍未验证。B3.1 额度 API/服务、F-018/F-019/F-020 平台 API/服务及其本地真实 8123 页面接线已接通，但不等于生产证据。

### B7.2 本地候选验收

以下命令只作用于本地候选或由脚本创建的 loopback 隔离资源，不会部署、连接未知生产系统或读取真实密钥：

```powershell
& .\.venv\Scripts\python.exe scripts\release_candidate_acceptance.py --root . --nginx-config deploy\nginx\authorization-platform.conf.example --source-only
& .\.venv\Scripts\python.exe manage.py test tests.test_release_candidate tests.test_object_storage tests.test_settings --verbosity 2
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\isolated-postgresql-backup-restore-acceptance.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\local-capacity-acceptance.ps1 -Requests 40 -Concurrency 4
```

验收夹具会把安全 JSON 证据写入被忽略的 `output/` 子目录；随机测试密码、对象存储 secret 和真实生产值不写入产物。`release_candidate_acceptance.py` 在没有生产环境变量时应诚实返回 `blocked`，这表示未连接真实生产设施，不是测试失败。

隔离 PostgreSQL 演练还会运行 `shared_rate_limit_probe.py`，并在同一运行目录生成 `shared-worker-rate-limit.json`：正控为两个进程共享同一限流身份且只有一次允许，负控为两个不同身份均允许。旧的 `shared_worker_probe.py` 直接测 `DatabaseCache.incr`，因 Django DatabaseCache 的实现不是原子自增，不作为 B7.2 发布证据。


## 本机隔离恢复与证据

使用 `scripts/isolated-postgresql-backup-restore-acceptance.ps1`，先读取脚本参数和目标约束；只对经确认的可丢弃隔离资源运行，不能将正式数据库传给测试runner。环境只支持local/test/production，test/production需要真实注入的相应设置，不能用不存在的staging绕过启动门。

本地 `recovery_inventory` 核对卡密密文/HMAC、状态、设备绑定、逐账户流水链和余额、软件/Profile、策略及审计。源与恢复数据库身份必须不同；同库自比、文件头可读或只列目录均不算恢复成功。应用checkpoint回滚工具和迁移分流脚本是本地候选工具，不是正式站自动回滚系统。

## 本地检查

```powershell
& .\.venv\Scripts\python.exe .\manage.py check
& .\.venv\Scripts\python.exe .\manage.py makemigrations --check --dry-run
& .\.venv\Scripts\python.exe .\manage.py test tests
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-docs.ps1
```

SQLite跳过不算PostgreSQL验证；静态预览不算真实API，平台测试不算模板/核心验收。实际命令、数量、退出码和未验证项落入当前回执与STATUS，不预填PASSED。

备份、导入、生产环境注入、装机、更新和回退统一从 [根部署入口](../部署与恢复/00-先读我.md) 进入；这里只保留本机运行与验证，不再复制服务器操作流程。
