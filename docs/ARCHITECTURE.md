# 当前架构边界

下一场先读仓库根 `README.md` 现行方案和 `docs/STATUS.md`。下面长文里的 pgBackRest / 双仓 WAL 是旧候选，**不是**还欠的部署步骤。

## 新软件接入创建与交付（2026-11-16）

管理端同源 POST catalog → software-create 命名空间的持久创建幂等记录 → 事务创建 Software/Profile/Policy（Plan 可选）。自动身份只在事务回调内产生；同键在缓存清空后仍重放原响应。

管理员按软件/Profile GET integration-config → catalog/integration.py 读取已保存身份、现行签发公钥、09 指令、protocol 三份原文与 API 合同票据节 → software-bind.v2 附件。镜像显式包含这些公开交付材料，缺失拒绝导出。导出不包含凭据/卡、不改变经营范围或接通状态；授权模板副本与核心适配仍在软件项目。

平台维护的通用启动器源码位于 `软件授权接入包/授权启动器模板/`。现行桌面入口经 `Binding::load → DesktopHost → WebViewRenderer::run_live` 消费准备后的下载配置，使用当前五动作请求、设备证明及钉住的Ed25519公钥；完整JSON通过Schema/JCS验签后才能进入会话。授权到期、最近成功窗口和重试时刻分开，心跳/续期同步页面及本地A-core；只有签发票据验签与真实核销成功后产生一次启动许可。设备私钥由Windows DPAPI保护，卡密不进浏览器存储。旧参考模块保留独立回归，不承担现行桌面授权。

本机通道只监听回环随机端口，核心通过启动环境中的短期凭据建立会话并验证独立签名信封。通用启动器可以启动明确配置的核心进程并在授权失效时停止它；具体软件仍须实现稳定硬件身份、逐功能门、直开拒绝和进程树处理。通用网络/WebView验收不等于任何软件已经完成保护。包重建默认取受Git跟踪的包内维护源，拒绝用缺少现行运行时的外部旧母版覆盖；构建不复制仓库、凭据或编译产物。

## 当前状态

本文保存目标架构和当前实现边界；PR-01 只落地工程基础，PR-02 完成账号切片，PR-03 已落地软件目录/经营范围/套餐快照模型与服务，B2.1 补充冻结 8123 使用的 catalog JSON API 和 `preview.js` 接线，B2.2 增加本地 8123 同源静态/API 网关并完成目录浏览器验收，B3.1-S1 补充通用额度兑换码、额度读写 API、购买链接持久化和不可变生命周期守卫，PR-04/PR-05 已落地额度/授权卡密服务层，PR-07/PR-07.x 已落地平台侧在线激活/验证/解绑、授权实例、设备证明、设备绑定、`authorization.v1` 签名响应和 `device_scope` 合同门禁；B7.1 已把生产共享缓存、独立哈希密钥、HTTPS/HSTS、数据库和可信代理配置改为显式环境合同；B7.2 已加入生产配置 fail-closed、反向代理/Worker 模板、provider-neutral 对象存储边界、隔离 PostgreSQL 备份恢复、跨进程共享缓存、应用回滚和容量验收夹具；F-018 版本发布、F-019 受控存储清理和 F-020 真实统计已接入 Django/API、冻结 `preview.js`。现行更新：版本号 + `has_update`；默认网盘；本站 ZIP 谁都能下，生产不得再强制卡密下载。现行备份：本机 `.enc` + 可选 GitHub，不是备份网盘。签名强制仍 fail closed。

当前Django提供JSON API、业务服务与管理命令，Psycopg连接PostgreSQL；冻结HTML/JS是产品前端。开发由8123同源网关转发内部Django8000；正式环境由Nginx提供相同页面后缀及API，容器内Gunicorn监听0.0.0.0:8000，仅宿主127.0.0.1:18002可达。Django模板不作为第二套产品页面，DRF/HTMX也不是现有实现依赖。现有密钥、HTTPS/CSRF、DatabaseCache和可信代理启动门继续有效。

详细字段和状态规则见 `docs/DOMAIN-RULES.md`；公共客户端接口见 `docs/API-CONTRACT.md`；安全约束见 `docs/SECURITY-BASELINE.md`。

## 本轮安全与运营实现边界

票据签发/核销（含幂等重放）先在既有卡→实例→设备→绑定锁序中检查当前事实；只有正常新请求消费nonce，重试不重复消费。原票TTL不延长且上限为授权到期。

限流保留固定窗口和原限额：DatabaseCache对既有序列化value及expires执行有界CAS，唯一插入冲突隔离在保存点中后重读；缓存清理沿用后端能力。LocMem整次操作用本地锁（仍非生产共享后端）。Redis代号计数用原子存在检查+递增，Memcached用原生递增；allow/blocked/reset共享代号和截止时间。未知后端、写失败或竞争耗尽拒绝放行。Redis/Memcached运行证据和PG多进程证据按STATUS实际结果记录，不由代码推定通过。登录NFKC规范化和来源预算在API/保留HTML入口共用；注册来源预算独立于邀请码。

软件状态复用历史命名PlanCreateOperation的software-status:{软件ID}命名空间保存持久幂等事实，与状态及原因审计同事务。重新上架不自动恢复下游经营范围。参数页面区分提交结果未知、提交成功与随后目录刷新失败；同一未知提交在本页重开弹窗仍复用原body/key。

## B2.1 目录 API 边界

冻结 `manage.html` 的 catalog 创建、**同一软件新增多个套餐**、套餐修订、经营范围 API 与 `downstream.html` 的目录读取 API，都经过会话角色、CSRF、幂等和事务服务；Software/Profile/Policy/Plan/PlanSnapshot/DownstreamSoftware 由服务端维护。新增套餐和套餐修订都产生独立的不可变快照；新增套餐的 `PlanCreateOperation` 与 Plan/快照在同一事务内提交，缓存只做读优化，页面隐藏字段不能决定下游归属；发卡、额度和授权 A 不由 catalog API 伪造。详细动作见 `docs/API-CONTRACT.md`。

Profile配置与下游渠道保存使用持久 `ConfigurationOperation`，由操作者行锁串行化首次请求，目标、原请求体哈希、响应与业务/审计同事务提交。旧键重放只返回原结果，不覆盖后来保存的配置；同键换内容或目标拒绝。审计归属投影按当前查看者计算，共享物理设备不会带出另一家下游的授权或账号。

## B2.2 本地同源网关边界

```text
浏览器
  │ 仅访问 http://127.0.0.1:8123/（正式环境替换为域名）
  ▼
scripts/static_proxy.py
  ├─ 冻结 docs/ui-preview/ 五个页面和静态资源
  └─ /api/、/healthz/ ──► 内部 Django 127.0.0.1:8000
                              │ 会话、CSRF、角色、服务和数据库
                              ▼
                           SQLite（本地）/ PostgreSQL（目标部署）
```

该网关是本地开发和验收工具，不是生产部署配置；它只转发固定的 `/api`、`/healthz` 上游路径，并在上游不可用时返回结构化 502。8123 页面、Cookie 和 CSRF 是同源验收边界；直接访问 8000 只能用于诊断，不能作为用户入口，也不引入 8143。

## B7.2 生产候选运行边界

生产候选由部署模板、应用环境合同和本地验收夹具组成：Nginx 模板终止 TLS、强制 HTTPS/HSTS，只提供冻结五页面、`/api/` 和 `/healthz/`；应用只经宿主回环端口暴露，Gunicorn至少两个Worker。生产设置拒绝 LocMemCache、非 PostgreSQL、单 Worker、复用密钥、缺签名公钥、HTTP 对象 endpoint 和 local object storage；`LocalObjectStore` 只服务本地候选，`S3ObjectStore` 通过 AWS Signature V4 + CA 校验连接 HTTPS S3 兼容 provider，下载前按对象元数据和内容复核大小/SHA-256。备份恢复、共享 DatabaseCache、应用哈希指针回滚、迁移分流和容量脚本均已有隔离证据，但当前域名/证书、反代和安装接线已有本次部署核对；目标对象存储权限、异地恢复、RPO/RTO和规模容量须分别保留证据缺口，不能由安装成功推定。

## B3.1 额度 API 边界（S1/S2）

```text
冻结 8123 manage.html#credits
  ├─ GET  /api/v1/manage/credits/
  ├─ POST /api/v1/manage/credits/settings/
  ├─ POST /api/v1/manage/credits/cards/
  └─ POST /api/v1/manage/credits/cards/{public_id}/revoke/
        │ 管理员角色、CSRF、幂等、单码读侧分页
        ▼
Credits services → QuotaCard / QuotaCardBatch(仅内部) / QuotaAccount / QuotaLedgerEntry / QuotaPlatformSettings / QuotaPurchaseUrlOperation
        ▲
冻结 8123 downstream.html#ledger
  ├─ GET  /api/v1/downstream/credits/
  └─ POST /api/v1/downstream/credits/
        │ active 下游会话推导账户；卡码、流水、余额、状态同一事务
        ▼
匿名五页面中的购买链接
  └─ GET /api/v1/public/quota-settings/
```

B3.1 的 `QuotaCardBatch` 仍是数据库内部事务/幂等分组，API 和 `preview.js` 不把它转化为批次 Tab、批次列、URL、文件名或交付维度。额度码发行不接受目标下游；兑换服务从当前 active 下游会话确定 `redeemed_by`，并保存 IP 摘要。余额只由不可变流水服务改变，账户余额是可重建缓存。批准隔离 PostgreSQL 并发和 B7.2 共享 DatabaseCache 已有证据；当前生产反向代理已按部署记录核对；目标容量仍未验证。

B3.1-S2 的购买链接更新在同一事务内锁定平台设置行，并由 `QuotaPurchaseUrlOperation(actor, idempotency_key, request_hash, purchase_url)` 保存原始结果。操作表的管理员+键唯一约束提供持久化重放和冲突边界；旧键重试只读取历史结果，不改写当前链接。设置表的旧 `last_*` 字段仅用于兼容读取。

## B5 授权与设备风险 API 边界

```text
冻结 8123 manage.html#risk
  └─ GET  /api/v1/manage/authorizations/
       └─ POST /api/v1/manage/authorizations/{authorization_id}/devices/{device_id}/reset/
       └─ POST /api/v1/manage/authorizations/{authorization_id}/devices/{device_id}/block/
       └─ POST /api/v1/manage/authorizations/{authorization_id}/devices/{device_id}/unblock/
       └─ POST /api/v1/manage/authorizations/{authorization_id}/revoke/
             │ 管理员会话、CSRF、原因、AuthorizationAdminOperation 幂等事实
             ▼
 licensing admin services
   LicenseCard → LicenseInstance → Device → DeviceBinding 锁顺序
             │ 状态、revision、失败/成功审计同事务
             ▼
   SQLite（当前本地）/ PostgreSQL（部署目标）
```

下游设备读侧独立使用 `/api/v1/downstream/devices/`，服务端从当前会话推导 `current_downstream_public_id`，只返回该下游自己卡密对应的明文设备 ID/IP 行；下游重置使用短期 `device_action_ref` 和独立幂等事实，只解除目标授权的当前绑定，不提供管理员级设备封禁、解封或授权撤销。

## B6 版本、统计与受控存储边界

```text
冻结 8123 manage.html
  ├─ GET/POST /api/v1/manage/releases/
  ├─ POST /api/v1/manage/releases/{release_id}/publish/
  ├─ POST /api/v1/manage/releases/{release_id}/withdraw/
  ├─ GET /api/v1/manage/analytics/summary/
  └─ GET/POST /api/v1/manage/storage/cleanup/
冻结 8123 manage.html / downstream.html 总览
  └─ GET /api/v1/downstream/analytics/summary/
        │ 服务端管理员/下游权限、幂等、审计、Manifest/包路径校验
        ▼
Releases / Analytics / Storage Cleanup
        ├─ Release + ReleaseOperation（版本事实与不可变操作）
        ├─ 真实卡密/授权/审计/额度流水只读统计
        └─ 受控文件根目录（撤回包、tmp、exports、logs）
```

版本上传先落入受控临时文件，服务端重新计算大小与完整包 SHA-256，再读取唯一 `client-release.v1` Manifest 并校验 Software/Profile/平台/架构/通道。生产 Manifest 的 `payload_sha256` 按 ZIP 内除 Manifest 外的确定性内容计算并纳入签名，避免把完整 ZIP 哈希写回包内形成自引用循环。发布状态与签名状态分开：`declared` 是上传方声明，只有配置公钥和登记的 Key ID 验证通过才是 `verified`；生产强制拒绝未验证签名。公共 registry/download 只允许 active/testing 软件与 Profile、verified 签名和仍匹配大小/完整包哈希的对象，并在每次下载前重新解析路径、拒绝越界和符号链接。授权 A 负责下载后的验签、安装和客户端回滚，中央平台不执行安装。

统计不建立可漂移的数字快照：按已激活卡密的套餐额度成本、授权实例、审计和额度流水现算。查询服务显式使用 `ZoneInfo("Asia/Shanghai")` 计算今日/月和趋势边界；下游范围从会话推导，筛选参数不能扩权；无数据返回真实空状态。

存储清理通过数据库锁和持久化幂等操作记录串行化；只处理超过保留期且仍位于允许根目录的撤回包、临时导出和日志文件。删除前重新检查普通文件、符号链接、路径、大小和已记录包哈希，篡改或竞态变化跳过。审计、额度流水、卡密、授权实例、设备和账号不在清理范围。无论发布包 provider 是 local 还是 S3，应用卷上的 `tmp/`、`exports/`、`logs/` 都必须继续扫描；远程 provider 只额外负责远程撤回包和 pending 对象。
反向说明：授权请求记录（`AuthorizationRequestRecord`，幂等台账）**由另一个具名定时作业按自己的保留期清理**（`manage.py prune_authorization_records`，默认 30 天，由小时维护任务调用），与上面的文件清理完全分离。它的模型层 `delete()` 守卫仍然拒绝普通删除，只有那一个具名出口能删。授权随机值（nonce）与审计**永不在清理范围**：nonce 是重放阻断的原语（设备证明可被管理员关掉，此时它是唯一防线），审计受 `adr/0011` 与多份合同保护。

备份运行与证明分层：deploy/backup中的当前Docker runner生成独立完整加密dump，本机保存并可选推送GitHub；health识别dump_only并提示严格proof未齐。严格proof工具仍校验版本、dump/迁移/对象/恢复清单及证据哈希，不等于现场已部署双仓/WAL/PITR。settings仍调用旧validate_backup_environment检查pgbackrest/双仓/WAL等环境声明；保留这些兼容设置不能当成设施验收，也不在本次清文档时放宽该门。对象清单必须来自实际对象存储，隔离恢复须核对业务inventory；同库自比或旧时间戳不算恢复证明。实际操作只写根部署目录。

定时备份的实际调用链是：每 15 分钟的 `authorization-platform-backup-schedule.timer` 调用 `manage.py backup_policy --schedule`，按 `enabled`、`schedule_enabled`、北京时间全量时刻和增量间隔至多创建一条 `PENDING`，全量优先；定时全量记录对应的 `scheduled_for` 槽位，主机成功 stamp 绑定该槽位，因此跨北京时间午夜完成不会占用下一日的 full 槽位；创建后写 `need-run`。`need-run` 只是 systemd.path 唤醒信号，数据库队列是事实源；dispatcher 按队列中的 `full` / `diff` 选择 runner，数据库查询失败或未知类型时返回失败并重写 `need-run`，旧的 full/diff 日历 timer 禁止启用。stamp 由主机 root 写入、应用容器只读。

## 推荐形态

单体 Web 应用，内部按领域模块拆分：

```text
浏览器
    │
8123 同源网关：静态管理端/下游端（已冻结）+ /api/ 代理
    │ 内部 8000
当前正式域名的受控反向代理
现行冻结HTML/JS + Django同源API
              │
        Application Services
              │
 ┌────────────┼────────────────────┐
 Catalog   Credits        Licensing / Profiles
 Accounts  Audit          Devices / Risk
 Releases  Channel        Policy / Capability
                         平台侧 Adapter Registry
              │
          PostgreSQL

每个软件的分发目录（独立维护）
授权 A：授权页 / Launcher / 平台 API 客户端 / 本地缓存 / 本地桥接
              │ HTTPS → 中央平台；loopback API → 核心 EXE
            核心 EXE
```

第一版不拆微服务。异步任务只有在批量生成、统计或文件处理确实需要时再加入。

## 三层部署边界

```text
中央授权平台
  多软件、多下游、卡密、授权、更新、公告、联系方式
             │ HTTPS（中央平台不主动连接客户端）
             ▼
授权 A（每个软件独立一套）
  授权页 + Launcher + PlatformClient + Cache + LocalBroker
             │ 本机稳定合同：/local/v1（默认只绑定 127.0.0.1）
             ▼
核心 EXE
  产品 UI、业务功能和受保护功能门
```

三层的职责必须保持单向：

| 层 | 负责 | 明确不负责 |
|---|---|---|
| 中央授权平台 | 保存授权事实；解析软件、Profile、卡密、设备、下游归属；下发类型化配置、联系方式、公告和更新元数据 | 不识别或控制某个 EXE 的 UI；不直接连接核心 EXE；不下发任意脚本 |
| 授权 A | 展示授权/购买/联系方式页面；调用中央 API；校验和缓存结果；向核心提供本地合同；默认询问版本并打开网盘，按所选通道处理更新 | 不拥有管理员权限；不伪造授权事实；不把其他软件或客户的缓存交给当前核心 |
| 核心 EXE | 运行产品功能和 UI；按本地合同启用/锁定受保护功能；展示授权 A 提供的类型化结果 | 不直连中央平台；不保存平台主密钥；不决定到期、下游归属、撤销或更新可信性 |

### 允许和禁止的连接

- 允许：授权 A → 中央平台 `/api/v1/`，使用 HTTPS 和公共客户端合同。
- 允许：核心 EXE → 同一软件的授权 A `/local/v1`，使用本机稳定合同。
- 禁止：核心 EXE → 中央平台；中央平台 → 核心 EXE；软件 A 的授权 A → 软件 B 的核心或缓存。
- 授权 A 默认只监听 `127.0.0.1`，使用短期、软件和会话范围内的本地令牌；不能把本地桥接端口暴露到公网。
- 本地响应只允许版本化 JSON、状态、时间、能力、配置和更新元数据，不允许平台或授权 A 下发任意可执行脚本、命令或 DLL 路径。

平台公共 API 的调用者是授权 A；“客户端 API”在本文和合同中若未特别说明，指授权 A 代表核心调用。核心侧完整本地合同见 `docs/CLIENT-INTEGRATION-HANDOFF.md` 和 `docs/API-CONTRACT.md`。

## 领域边界

- `Catalog`：软件、Profile、套餐、软件状态和发布状态。
- `Policy`：版本化通用授权策略、策略快照和生效规则。
- `Capability`：类型化软件能力、套餐能力值和客户端公开能力。
- `Adapter Registry`：`generic-online-v1` 与少量版本化软件适配器；不执行数据库中的脚本。
- `Authorization A`：不属于中央平台领域表；它是每个软件分发目录内独立维护的授权页、Launcher、平台 API 客户端、本地桥接和缓存组合。平台只登记其 Profile/合同版本，不把某个产品的 A 代码复制进中央核心。
- `Accounts`：Django User 凭据、管理员/下游角色、DownstreamProfile、邀请码内部生成分组/单码、会话、归档和脱敏墓碑。
- `Credits`：额度卡、额度兑换、额度流水、余额汇总。
- `Licensing`：授权卡密内部生成分组、授权卡密、套餐快照引用和后续授权实例；PR-05 负责生成和归属，PR-06 负责未激活卡密回收和原始额度返还，不提前改变授权事实。内部生成分组不属于用户页面领域。
- `Devices`：设备、设备密钥、设备绑定、解绑历史。
- `Risk`：限流、异常事件、封禁和解禁。
- `Releases`：版本、安装包元数据、校验值和发布状态。
- `Channel`：二维码、联系方式、发卡网安全链接。
- `Audit`：业务和安全审计事件。

## 状态边界

### 授权卡密

```text
generated → unused → activated → expired
              │          │
              ├→ reclaimed  └→ revoked / disabled
              └→ revoked / disabled
```

`reclaimed` 是终态，不能回到 `unused`。回收必须在卡密状态、原始下游和额度账本同一外层事务中完成。

### 额度卡

```text
issued → redeemed
   └→ revoked
```

兑换必须是一次性原子操作。

### 下游

```text
active → suspended → closed
                       └──────────────┘
```

是否允许从 `closed` 恢复必须由管理员明确操作并写入审计。

## 核心数据关系

```text
Software 1—N SoftwareProfile 1—N PolicyVersion
SoftwareProfile 1—N CapabilityDefinition
Software 1—N Plan 1—N PlanSnapshot
Downstream N—N Software
PlanSnapshot 1—N LicenseCardBatch 1—N LicenseCard
LicenseCard 1—1 LicenseInstance
LicenseInstance 1—N DeviceBinding
Device 1—N DeviceKey
Device 1—N DeviceBinding
Downstream 1—N QuotaLedger
LicenseCard 1—N AuditLog
```

每个业务表都必须保留软件、Profile 和下游归属所需的可校验关系。服务端不能只依赖客户端传来的 ID；跨软件查询必须由当前会话和 DownstreamSoftware 关系推导。

## 软件隔离数据流

```text
授权 A 的远程请求
  → software_id + profile_id + client_id + target/arch/channel
  → Profile Registry
  → PolicyVersion + PlanSnapshot + CapabilityDefinition
  → generic-online-v1 或平台侧注册表适配器
  → 通用授权决定
  → authorization.v1 签名响应 + 下游配置解析 + 审计
  → 授权 A 校验并按范围缓存
  → /local/v1 本地合同
  → 核心 EXE
```

新软件默认只新增数据和测试夹具，不改通用授权服务。真正的特殊行为必须进入独立适配器，并只能返回标准授权决定；适配器不能扣额度、改变卡密状态或直接写审计。

PR-07 的通用平台运行时入口为 `/api/v1/public/licenses/activate`、`verify` 和 `deactivate`。所有动作严格校验 Profile 七元身份，使用 `LicenseCard → LicenseInstance → Device/DeviceKey/DeviceBinding` 关系和不可变套餐/策略快照；A 验证中央签名后必须独立签发 `authorization-a-core.v1`，平台不会把 A 或核心的专属路由写入自身。

### 配置、联系方式和更新的所有权

- 中央平台按 `SoftwareProfile` 默认 → 当前真实 `DownstreamSoftware` 配置 → `LicenseInstance.configuration_override` 的顺序解析公告、更新元数据和类型化客户端配置。渠道通知 `support.purchase_url` / `qq` / `wechat` 不走 Profile 候选：只跟发卡下游在下游页保存的购买 URL 和联系方式；没填就给客户端空。客户端不能提交 `downstream_id` 来选择这些值。下游配置由 `configuration_enabled` 控制；清除授权实例覆盖后，公告回到当前实际生效层，渠道通知回到该下游已保存内容或空。
- `support`、`announcement`、`modules` 和 `config_version` 是中央响应与 A-core 本地响应共享的产品中立配置语义：`modules.contact`/`notice` 分别镜像支持/公告，未实现模块保持空值；`config_version` 只表示配置缓存版本，不替代授权 `authorization_revision`。
- Profile、下游软件配置和授权实例覆盖各自拥有版本粒度；更新配置或清除覆盖必须使旧配置缓存不能继续作为当前结果。授权 A 只缓存当前 `software_id + profile_id + authorization_id + device_scope + config_version` 范围内的结果。缓存不是授权事实源，不能在服务端已经返回撤销、封禁或过期后继续放行。
- 核心 EXE 只读授权 A 的本地响应；它不保存跨产品缓存，也不接收平台主密钥。空联系方式或购买链接必须用空值表达，授权 A/核心页面隐藏对应区域，不显示假占位数据。
- 更新和公告也沿同一条路径传递：平台 → 授权 A → 核心。核心只接收类型化状态和说明；默认由A/软件打开网盘；明确选用本站包/自更新通道时，下载、哈希/签名校验、安装和回滚才按该产品独立合同实现。

## 授权 API 原则

- 通过 HTTPS 访问。
- 首次激活在线完成。
- 授权 A 提交卡密、固定的软件标识、设备公钥/设备证明和客户端版本；最终客户在授权 A 页面输入卡密，核心 EXE 不收集或转发平台卡密。
- 服务端重新判断卡密、软件、套餐、下游状态、设备限制、期限和风控。
- 服务端返回短期授权结果；必要时使用标准签名库签名。
- 不把管理员密钥、数据库密钥或对称主密钥放入客户端。
- API 请求需要限速、请求 ID、幂等处理和安全审计。
- 客户端身份必须同时包含 `software_id`、`profile_id`、`client_id`、`contract_version`、`target`、`arch` 和 `channel`；服务端严格匹配 Profile，禁止用相近标识兜底。
- 响应可以携带类型化 `capabilities`、`entitlements`、`policy_version`、`adapter_version` 和 `config_version`，客户端不能把未知字段解释成可执行指令。
- 设备风险阻断返回普通 `RISK_BLOCKED` 错误；只有授权实例自身的 `blocked` 状态才通过签名 `decision=blocked` 信封表达，二者不能互换。
- 新建默认产生可供接入的 `active` 软件/Profile；客户端首轮验证仍使用隔离夹具，`active` 不代表客户端已接通；需特殊分阶段登记时可显式使用 `draft/testing`。

授权 A 到核心的本地合同必须独立版本化。默认使用本机 loopback HTTP/JSON（`/local/v1`）；产品确有必要时可以换成 Windows Named Pipe，但不得改变中央平台合同或把平台连接下沉到核心。任何传输方式都必须绑定软件、Profile、客户端版本和本地会话，并在失败时让核心锁定受保护功能。

## 备份部署路径

`install-site.sh` 会按自定义 `BACKUP_ROOT` 同步主机环境路径，把当前 Git commit 写入
`BACKUP_CANDIDATE_COMMIT`，并在迁移后原子生成 `migration-graph.json`；dump 口令位于
应用不可写的 `BACKUP_ROOT/host-secrets/`。旧 full/diff 日历 timer 只作为退役识别材料，
实际运行必须通过策略巡检、`need-run` path 和 dispatcher。

## 时间边界

- 应用服务统一通过可注入的时钟入口取得当前时间，默认返回带时区的 UTC；业务层不直接调用无时区本地时间。
- PostgreSQL 和 API 保存/传输 UTC 时间瞬间；管理端、报表和统计边界转换为 `Asia/Shanghai`。VPS 系统时区只属于部署环境，不是产品配置。
- 授权到期比较由服务端完成，`authorization.v1` 的 `issued_at`、`expires_at`、`server_time` 等时间字段在线统一使用有符号 64 位 Unix epoch seconds；客户端本机时间和客户端提交的到期字段不可信。客户端只使用服务端返回的时间和单调计时辅助显示，验证/心跳和重启后的授权门仍以服务端结果为准。A 发现已接受时间回退时必须返回 `TIME_ROLLBACK_DETECTED` 并 fail closed；展示和自然日仍统一使用 `Asia/Shanghai`。
- `cache_until`/`next_verify_at` 对 active、grace 和 not_modified 统一计算为 `min(expires_at, server_time + verify_interval_seconds)`；它们只决定启动器何时再问，不是核心到期。`grace_until` 不能延长排他的 `expires_at`，A/core 到期必须 fail closed。挤机 / 解绑 / 撤销 / 阻断靠下一次 `verify` 硬结果，不靠本地倒计时。
- 公共 `verify` 先判定再限流：`DEVICE_NOT_BOUND`、撤销、阻断、到期、设备密钥无效不得先变成 `RATE_LIMITED`。默认间隔 60 秒；已售卡下次 `verify` 读当前 ACTIVE 策略间隔。
- 测试套餐复用普通套餐与授权状态机；1 分钟测试卡只是 `duration_seconds=60`、`test_only=true` 的数据配置，不引入测试专用核心分支。

## 数据一致性原则

- 额度流水是事实源，余额是可重建汇总。
- 生成卡密、扣除额度和写入批次必须在同一事务中完成。
- 授权卡密批次和每张卡都引用生成时选定的同一个 `PlanSnapshot`；套餐修订只创建新快照，不能改写旧快照或策略版本。
- 发卡服务先按当前下游会话锁定下游、套餐和经营范围，再在外层事务中调用 `credits.services.debit_quota`；非零成本不允许直接写余额，零成本测试套餐不伪造零额流水。
- 卡密明文只在生成结果或受保护的 POST 查看动作中解密；数据库只保存 HMAC 查询值和密文，生成碰撞通过 savepoint 重试，超过上限整体回滚。
- 回收卡密和返还额度必须在同一事务中完成。
- 每个可能重试的写操作都需要幂等键。
- 审计记录和额度流水不物理删除；业务对象先归档再删除，并保留最小脱敏墓碑或可追责引用。
- Credits 的余额字段只是可重建缓存；额度卡发行、兑换、人工充值和授权卡密扣除必须通过事务服务写入不可变流水，不能直接改余额。
- Credits 的卡密查询使用受保护哈希，明文只保留加密密文；重复发行、兑换和充值请求由数据库幂等键与请求指纹约束。
- Profile、策略、能力定义和适配器登记也遵守版本化、幂等和发布状态规则；失败不能留下半发布配置。

## PR-02 账号与租户边界

账号、会话、邀请码、下游状态和墓碑由 Accounts 服务维护；密码、角色、CSRF、会话版本、邀请码消费和下游归属均由服务端 API/事务决定，不能依赖 8123 前端隐藏控件或客户端租户 ID。注册按“锁邀请码→校验→建 User/Profile→消费邀请码”执行，失败和并发重试不得留下半成品；字段细节见 `docs/DOMAIN-RULES.md`。
