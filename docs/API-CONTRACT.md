# API 合同

## 新软件自助接入（2026-11-16，取代手工登记回填）

- `POST /api/v1/manage/catalog/` 保持管理员会话、CSRF、`Idempotency-Key`；最少请求为 `{"name":"软件名称"}`。服务端在持久幂等事务内生成稳定 `sw-<UUID>` 软件 ID、默认 `stable` Profile、由软件 ID 和 target 派生的 client_id、`policy-1` 与 `generic-online-v1`。默认 Windows/x64/stable、设备 1、验证 60 秒、断网宽限 0、允许满员挤机、每日换机 5。已有显式 ID 和完整套餐请求兼容。
- 未传套餐字段则只创建软件/Profile/策略，响应 `plan=null`、`snapshot=null`。`create_plan=true` 时必须完整验证套餐；`false` 时禁止夹带套餐字段；旧请求省略开关但含套餐字段仍按完整套餐创建。失败全部回滚；同键同体在缓存清空后仍返回原 ID，同键异体 409。软件名称可重名，身份不可因名称变化而重建。
- `GET /api/v1/manage/catalog/software/{software_id}/integration-config/?profile_id={profile_id}`：管理员下载 `software-bind.v2` JSON，附件名只由软件/Profile 的稳定标识生成；`Cache-Control: no-store`。单 Profile 可省略参数；多 Profile 省略则 400 `PROFILE_REQUIRED`，不得默选其它身份。软件或 Profile 非 active/testing 拒绝，未登记 404；公钥或交付资料不可用 503，不生成空配置。
- JSON 包含已保存的软件名称/身份、平台地址、公共合同与本地合同版本、目标系统/架构/通道、从现行签发私钥派生的验签**公钥**及 key_id、声明式能力、随包的 AI 接入说明、三份公共协议原文和本文件一次性启动票据节原文（launch_ticket_contract；response_contracts 区分普通授权/票据响应）。导出使用已配置的 `AUTHORIZATION_PUBLIC_BASE_URL`，未配置时使用受信请求来源；生产必须 HTTPS，本地 loopback 才允许 HTTP。不接受客户端提交的软件身份、公钥、策略或地址覆盖。
- 导出不包含管理/下游凭据、私钥、卡密、设备身份或授权放行结果；不生成密钥、不发卡、不建下游、不改经营范围、不自动更新客户端信任根。成功写 `software.integration_config.export` 审计，仅记录软件/Profile、格式和 key_id。
- 配置是软件侧 AI 的接入材料，不是授权凭证。AI 在软件项目使用模板副本实现 A 和核心功能门；模板母版仍只读。配置中的策略不作为永久授权依据；运行时以服务端签名结果为准。软件当前版本由该软件构建填写，不能使用平台最低版本或最新发行号冒充。

本文定义第一版客户端公共授权 API、授权 A 到核心 EXE 的本地合同、冻结 8123 页面使用的同源管理/下游 JSON API 和业务服务动作。管理/下游 API 只服务五个冻结页面，不创建第二套页面或 8143 入口。

## 两段接口和调用方

```text
授权 A（本软件专属的授权页 / Launcher / LocalBroker）
        │ HTTPS，调用中央平台 /api/v1/
        ▼
中央授权平台（唯一授权事实源）
        ▲
        │ 本机 /local/v1，只有同一软件的核心 EXE 调用
        │
核心 EXE
```

### 平台 API 的调用者：授权 A

- `/api/v1/` 公共授权 API 由授权 A 调用；核心 EXE 不保存中央平台地址、不直连中央平台，也不转发最终客户的卡密到中央平台。
- 授权 A 使用固定的 `software_id`、`profile_id`、`client_id`、`contract_version`、`target`、`arch` 和 `channel`，这些身份来自产品登记和构建配置，不由页面输入。
- 最终客户在授权 A 页面输入卡密。服务端根据卡密、授权实例和下游软件关系解析真实下游归属，客户端不能提交 `downstream_id` 来选择联系方式、购买链接或其他配置。
- 返回的联系方式、购买链接、公告、更新和能力都是类型化数据；没有配置时返回 `null` 或空数组，授权 A 和核心页面隐藏对应区域。

### 核心 API 的调用者：本地授权 A

- 核心 EXE 只调用同一软件授权 A 的 `/local/v1`，不需要中央平台账号或平台密钥。
- 默认传输是仅绑定 `127.0.0.1` 的 loopback HTTP/JSON；授权 A 启动核心时传递一次性、本地会话范围的连接信息。产品确有必要时可使用 Windows Named Pipe，但合同语义不变。
- 本地合同与平台合同独立版本化，例如平台 `authorization.v1`、本地 `authorization-a-core.v1`。两者不能通过“兼容猜测”互相降级。
- 授权 A 失去平台确认、收到撤销/过期或本地会话失效时，核心必须锁定受保护功能；缓存只用于短暂可用性，不能覆盖安全撤销。

## 通用规则

- 前缀：`/api/v1/`
- 传输：HTTPS + JSON UTF-8。
- 每次请求带 `X-Request-Id`。会创建、消费、发行或回收业务事实的请求必须带 `Idempotency-Key`；登录、注册入口校验、退出和会话刷新使用服务端会话/状态机幂等语义，不把重复登录或登出当作重复业务事实。
- 客户端不能提交或覆盖服务端状态字段。
- 错误响应不暴露卡密是否存在、数据库信息或内部堆栈。
- 授权 A 的身份由 `software_id`、`profile_id`、`client_id`、`contract_version`、`target`、`arch` 和 `channel` 共同组成；服务端必须与登记的 SoftwareProfile 完全匹配。
- 软件差异优先通过类型化 `capabilities` / `entitlements` 表达；不接受数据库中的任意脚本、任意未登记能力或客户端自行决定的授权规则。只有 Profile 中登记且标记为公开、仍处于 active 的能力键可以进入中央响应；内部能力可以保留在服务端快照中，但不得发送给授权 A 或核心。
- 每个软件和 Profile 都有独立的配置哈希、策略版本和审计上下文，响应不能跨软件复用。
- A 层本地缓存至少按 `software_id`、`profile_id`、`authorization_id`、设备范围和 `config_version` 隔离；缓存键不能使用明文卡密，也不能跨软件、跨客户或跨 Profile 复用。

### 配置响应字段与版本语义

公告、更新元数据和类型化客户端配置沿三层链路解析：`SoftwareProfile` 提供默认值，当前真实下游的 `DownstreamSoftware` 在 `configuration_enabled=true` 时覆盖默认值，非空的 `LicenseInstance.configuration_override` 再覆盖前两层。渠道通知 `support.purchase_url` / `qq` / `wechat` **不走 Profile 候选**：只跟发卡下游在下游页保存的内容（`configuration_enabled=true`）；没填就给客户端空（三个键都空时 `support` 为 `null`，不要写「无」）；授权实例覆盖非空时仍可改这一张卡。客户端不能提交下游 ID 选择配置；服务端只使用授权实例的真实 `current_downstream_public_id`、软件和 Profile 归属。

完整授权响应和 A-core 本地响应使用同一组配置语义：

```json
{
  "config_version": "cfg-opaque-version",
  "support": {"purchase_url": null, "qq": "support-id", "wechat": null},
  "announcement": {"title": "公告标题", "body": null},
  "modules": {
    "contact": {"purchase_url": null, "qq": "support-id", "wechat": null},
    "notice": {"title": "公告标题", "body": null},
    "purchase": null,
    "qr": null,
    "update": null
  }
}
```

`support` 在三个字段都为空时为 `null`；`announcement` 只有公告已启用且标题或正文至少一个非空时才返回对象，空成员为 `null`。`modules` 始终使用固定键集合 `contact`、`notice`、`purchase`、`qr`、`update`；当前配置切片要求 `contact` 等于 `support`、`notice` 等于 `announcement`，其余模块保持 `null`，后续模块必须另行冻结类型化字段。两份 v1 Schema 都把 `support`、`announcement` 和 `modules` 列为正向 envelope 必填字段，并限制这三个对象的键集合。`config_version` 是非空不透明字符串：Profile、下游配置和授权实例覆盖各自只推进自己的版本；清除覆盖后返回当前实际生效层的版本。配置版本变化只触发配置缓存刷新，不改变授权期限或授权 revision。

## `authorization.v1` 冻结信封（PR-07 已落地平台纵向切片）

PR-05 冻结两层接入都要遵守的通用字段，PR-07 在平台侧落地激活、验证、解绑、设备证明、一次性 nonce、真实 Ed25519 响应签名和 `generic-online-v1` 服务路径。该合同不包含任何具体产品、核心 EXE 或授权 A 的专属路由。

### 身份与版本字段

请求必须提交登记身份上下文；成功或结构化响应必须返回当前身份和非空的服务端 `authorization_revision`/`config_version`。首次激活请求还没有版本条件，可以省略已知版本条件；验证、Manifest 和版本检查请求可携带 `known_authorization_revision`/`known_config_version` 作为条件字段。服务端不得从相近标识猜测或降级。

`device_scope` 在本 v1 中是“服务端确认后的响应 claim”，不是客户端请求的替代字段。PR-07 的请求 DTO 使用顶层 `installation_id`，再结合设备公钥、设备证明和 nonce 完成服务端校验；平台据此生成响应中的结构化 `device_scope`。A/core 只能消费这个响应 claim，不能把它降级成字符串，也不能用请求中的设备范围选择其他设备或授权。若未来需要客户端提交结构化 `device_scope`，必须作为独立请求 DTO/兼容切片冻结字段映射和 fixture；当前 v1 不做字符串/对象猜测兼容：

| 字段 | 类型 | 规则 |
|---|---|---|
| `software_id` | string | 服务端登记的软件稳定 ID |
| `profile_id` | string | 软件内 Profile ID |
| `client_id` | string | Profile 登记的客户端身份 |
| `contract_version` | string | 固定为 `authorization.v1` 或明确兼容版本 |
| `target` / `arch` / `channel` | string | 必须与 Profile 完全匹配 |
| `request_id` | string | 调用方生成的追踪 ID；服务端响应原样关联但不当作授权事实 |
| `device_scope` | object（响应） | 当前设备/安装范围；服务端确认后返回，不能跨设备复用；当前 v1 请求不接受此字段作为输入 |
| `installation_id` | string（请求） | 授权 A 必须提交稳定主板/硬件指纹；软件重装、清安装目录不得换值，同一台交同一指纹；必须被设备证明绑定；仅以服务端确认后的 `device_scope.installation_id` 回显 |
| `device_code` | 管理端/下游读侧字段 | 由服务端从已保存的 `installation_id` 稳定派生的人工核对码，只用于显示、复制、客服查找和后台搜索；不进入 `authorization.v1`、设备证明、票据或核心授权事实 |
| `device_public_key` | string（请求） | Ed25519 设备公钥；仅用于证明和设备密钥登记，不进入中央成功响应或 `authorization-a-core.v1` |
| `device_proof` | string（请求） | 绑定动作、身份、公钥、安装标识和 nonce 的设备证明；不进入中央成功响应或 `authorization-a-core.v1` |
| `client_version` | string（请求） | 客户端版本；仅用于 Profile/策略检查和平台记录，不进入中央成功响应或 `authorization-a-core.v1` |
| `nonce` | string（请求） | 一次性随机值；服务端仅保存哈希并消费，不进入任何成功 envelope |
| `authorization_revision` | integer | 响应中的服务端单调版本，必填且大于 0；状态或归属变化时递增 |
| `config_version` | string | 响应中的配置/渠道/公告/更新版本，必填且非空；不参与有效期计算 |
| `known_authorization_revision` | integer/null | 请求中的可选已知授权版本条件；不替代响应 `authorization_revision` |
| `known_config_version` | string/null | 请求中的可选已知配置版本条件；不替代响应 `config_version` |

最小身份对象为：

```json
{
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable"
}
```

`device_scope` 只能表达服务端确认的范围，例如：

```json
{
  "scope": "current_device",
  "device_id": "device-server-id",
  "installation_id": "installation-id"
}
```

`device_scope` 的 v1 结构是固定的：三个键均必填且不得增加其他键；`scope` 只能是 `"current_device"`；`device_id` 为服务端设备 ID（`string`，最长 64 字符）或 `null`；`installation_id` 为服务端确认的稳定主板/硬件指纹（`string`，最长 128 字符）或 `null`。管理端和下游读侧另返回 `device_code`：当前 64 位十六进制指纹按 SHA-256 派生 80 位并格式化为 `GS-XXXX-XXXX-XXXX-XXXX-XXXX`；已有 `GS-` 短码或其他短 opaque 标识保持兼容。这个字段不属于 v1 `device_scope`，不得加入签名授权响应。只有没有完成当前设备确认的结构化拒绝响应才允许两个 ID 为 `null`；成功的设备授权响应必须返回已确认的范围。字符串长度限制按 Unicode 字符计，空字符串不接受。

客户端提交的硬件指纹、设备 ID 或下游 ID 都不是授权事实；它们必须经过设备证明和服务端关系校验。指纹是 `installation_id` 的取值来源，重装不得换值，仍须 `device_proof`，不能单靠裸指纹放行。

因此，A→平台的当前通用映射固定为：请求提交顶层 `installation_id`、`device_public_key`、`device_proof`、`client_version`、`nonce`；中央 `authorization.v1` 成功响应返回结构化 `device_scope`，但不回显前述四个证明/运行时字段。A 验证中央响应后重新签发的 `authorization-a-core.v1` 也不携带这些请求字段；唯一可传递的安装信息是服务端确认后的 `device_scope.installation_id`。`authorization_id` 在 activate 请求中由平台创建、在 verify/deactivate 请求中作为目标实例提交，并在成功响应中返回。

两份 v1 Schema 都只允许已声明的顶层字段；未来扩展必须放入签名覆盖的 `extensions` 对象。未知扩展内容可以按调用方策略忽略，但未声明的顶层字段必须 fail closed，不能被当作授权事实。`capabilities`、`modules`、联系方式、公告和更新仍属于 manifest/profile/config/revision 绑定数据，不能成为第二授权权威。

### 时间字段（线协议冻结）

`authorization.v1` 的时间字段统一使用 JSON 整数，类型为有符号 64 位 Unix epoch seconds：

| 字段 | JSON 类型 | 规则 |
|---|---|---|
| `issued_at`、`expires_at`、`server_time` | integer | Unix epoch 秒，UTC 绝对时间，不能带小数、不能使用毫秒、不能传 ISO 字符串 |
| `cache_until`、`next_verify_at`、`grace_until` | integer | 同上；`authorization.v1` 成功或结构化状态响应必须返回，不能以缺省代替版本失效语义 |

epoch seconds 是线上的绝对时间，不携带时区后缀；数据库仍保存同一个 UTC 时间瞬间。所有语言必须按有符号 `int64` 解析和序列化，不能把秒误当成毫秒或依赖本机时区。签名规范化前后必须保持整数表示，不能在 A 或核心中改写成浮点数/字符串。

业务和展示语义分开：授权比较以 UTC 绝对时间为事实，后台、报表、日志和自然日边界统一转换为 `Asia/Shanghai`（北京时间）。VPS 的系统时区不能改变授权结果。

### 决策、时间和条件刷新

标准响应使用 `decision` 表达授权结果：`active`、`grace`、`expired`、`revoked`、`blocked`、`not_modified` 或 `unbound`。`decision=blocked` 只表示中央已判定授权实例本身进入 `blocked` 状态，例如卡密/实例被禁用或时间回拨后的实例阻断；此时可以返回带签名的 `authorization.v1` 状态信封。它不等同于设备风险错误 `RISK_BLOCKED`。`not_modified` 只用于调用方带来的 `known_authorization_revision` 与 `known_config_version` 均仍然匹配、且当前授权没有安全失效的条件请求；撤销、封禁和过期不能用 `not_modified` 隐藏。

当 `Device.risk_state=blocked` 时，平台返回 HTTP 403 的普通结构化错误，不伪装成完整 `authorization.v1`：

```json
{
  "error": {
    "code": "RISK_BLOCKED",
    "message": "当前设备已被阻断。",
    "request_id": "req_123",
    "retryable": false
  }
}
```

该错误响应必须使用 `Cache-Control: no-store` 和 `Pragma: no-cache`；A 收到后立即失效当前设备范围缓存并传递锁定结果，不能把旧的 `active` 缓存重新包装成 allow。

成功或结构化状态响应至少包含：

```json
{
  "schema_version": "authorization.v1",
  "request_id": "req_123",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "authorization_id": "auth-server-id",
  "authorization_revision": 17,
  "device_scope": {
    "scope": "current_device",
    "device_id": "device-server-id",
    "installation_id": "installation-id"
  },
  "decision": "active",
  "issued_at": 1787097600,
  "expires_at": 1789689600,
  "server_time": 1787097600,
  "config_version": "cfg-17"
}
```

示例中的 `1787097600` 是 `2026-08-19T00:00:00Z`。`server_time` 是服务端事实源，客户端本机时间、时区、手工 `expires_at`、旧缓存时间和时间回拨都不能改变 `decision`。

### 完整性字段和密钥轮换

`authorization.v1` 平台响应必须包含响应签名：

```json
{
  "integrity": {
    "algorithm": "ed25519",
    "key_id": "platform-2026-01",
    "canonicalization": "JCS-RFC8785",
    "signature": "base64url-signature"
  }
}
```

签名覆盖去除 `integrity.signature` 后的完整规范化响应，不覆盖传输层外壳。平台实现只接受精确小写 `ed25519` 和 `JCS-RFC8785`；未知算法、未知 key、规范化失败、响应形状不符合合同或签名不匹配必须 fail closed，不能退回哈希、明文或“暂时信任”。响应形状失败使用不可重试的 `RESPONSE_SCHEMA_INVALID`；请求层字段不能通过签名进入成功 envelope。生产密钥由环境/受管密钥服务注入；本地测试可使用明确的开发回退，不能带入生产。密钥轮换允许新旧 key 在明确重叠窗口内同时验证，窗口结束后旧 key 立即视为未知；轮换、撤销和失败都必须可审计。

授权 A 的平台验签公钥不通过匿名 Manifest、`activate` 响应或任何公共 key/JWKS 路由自举。新接入默认由平台管理员下载对应软件的software-bind.v2，将其中实际公钥和key_id受控交给模板副本；独立诊断时仍可使用受控会话读取 `GET /api/v1/manage/authorization-signing-key/`，响应固定为 `key_id`、`public_key`、`algorithm=ed25519`、`encoding=base64url-no-padding` 和 `canonicalization=JCS-RFC8785`；它从当前签发私钥派生公钥，绝不返回私钥、种子、环境变量或密钥托管引用。响应使用 `Cache-Control: no-store`，成功读取写审计但审计不记录公钥值。管理员将该公开值经受控客户端配置交接给对应授权 A；客户端遇到未知 `key_id` 必须 fail closed，不能自动从公共网络替换信任根。

这组完整性字段属于中央平台签发的 `authorization.v1`。本地 `authorization-a-core.v1` 是另一份独立合同：A 在验证中央响应后重新封装并用 A 自己的签发密钥签名，`origin=authorization-a`、`audience=authorization-a-core` 固定写入其 `response.integrity` 并纳入同一签名输入；平台密钥不下发给核心 EXE。

### 模块归属绑定

`support`（购买 URL 和联系方式文本）、`purchase`（购买入口）、`qr`、`announcement`（公告）和 `update`（更新元数据）都由中央平台根据卡密/授权实例真实归属解析。`support` 只跟发卡下游在下游页填的内容，不回退 Profile。每个模块只能出现在同一响应的 `software_id + profile_id + authorization_id + device_scope + authorization_revision + config_version` 范围内；A 不得用请求参数选择其他下游，也不能跨模块或跨软件复用缓存。

更新模块只能传类型化元数据：`release_id`、`version`、`size`、`sha256`、`signature`、`min_core_version` 和受控下载地址。平台/A 不下发脚本、命令、任意 DLL 路径或动态代码；核心只消费 A 已验证的状态。

缺省模块返回 `null` 或空数组，A 和核心隐藏对应 UI。修改联系方式、公告或更新后必须产生新的 `config_version`；授权撤销、封禁、过期或 Profile 归档必须使对应缓存按 `authorization_revision`/`config_version` 失效。只有当前实际生效层发生变化才改变当前响应版本；被授权实例覆盖遮蔽的低层变化在清除覆盖后才进入响应。

### 稳定错误和重试

错误仍使用统一结构：

```json
{
  "error": {
    "code": "PROFILE_MISMATCH",
    "message": "客户端身份与软件 Profile 不匹配。",
    "request_id": "req_123",
    "retryable": false
  }
}
```

v1 预留稳定错误码如下：

| 错误码 | `retryable` | 语义 |
|---|---:|---|
| `INVALID_REQUEST` / `MISSING_REQUIRED_FIELD` | false | 缺字段、类型或格式错误 |
| `METHOD_NOT_ALLOWED` | false | 公共授权接口只接受 POST |
| `UNAUTHORIZED` / `FORBIDDEN` | false | 调用方身份或权限失败 |
| `SOFTWARE_MISMATCH` / `PROFILE_MISMATCH` / `CONTRACT_VERSION_UNSUPPORTED` | false | 软件、Profile 或合同不匹配 |
| `LICENSE_NOT_FOUND` / `LICENSE_NOT_ACTIVE` | false | 卡密或授权实例不能进入当前动作 |
| `LICENSE_EXPIRED` / `LICENSE_REVOKED` / `LICENSE_BLOCKED` | false | 服务端已判定授权卡密或授权实例失效 |
| `DEVICE_SCOPE_MISMATCH` / `DEVICE_NOT_BOUND` / `DEVICE_KEY_INVALID` / `DEVICE_KEY_MISMATCH` / `DEVICE_PROOF_REQUIRED` / `DEVICE_PROOF_INVALID` / `REPLAY_DETECTED` | false | 设备范围、密钥、证明或一次性随机值失败 |
| `SIGNATURE_INVALID` / `KEY_UNKNOWN` / `ALGORITHM_UNSUPPORTED` / `CANONICALIZATION_UNSUPPORTED` / `RESPONSE_SCHEMA_INVALID` | false | 完整性或响应合同形状校验失败，必须锁定 |
| `TIME_ROLLBACK_DETECTED` / `TIME_SKEW` | false | 服务端/A 检测到可信时间回退或不可信时间，必须锁定；不得自动重试 |
| `VERSION_BLOCKED` / `RISK_BLOCKED` / `ADAPTER_UNSUPPORTED` / `PROFILE_NOT_ACTIVE` | false | 运营、Profile 或适配器策略拒绝 |
| `DEVICE_LIMIT_REACHED` / `DEVICE_SWITCH_LIMIT_REACHED` | false | 同时在线已满且现行不允许顶绑用 `DEVICE_LIMIT_REACHED`；允许顶绑但当日北京自然日 N 用尽用 `DEVICE_SWITCH_LIMIT_REACHED` |
| `RATE_LIMITED` / `SERVICE_TEMPORARILY_UNAVAILABLE` | true | 可按 `Retry-After` 重试，不能改变授权事实。`RATE_LIMITED` 不得覆盖硬失败：`DEVICE_NOT_BOUND`、撤销、阻断、卡已到期、设备密钥无效等必须返回原错误码，不能先 429 |
| `IDEMPOTENCY_CONFLICT` | false | 同一键对应不同请求体，或历史放行结果已因授权事实变化失效 |
| `INTERNAL_ERROR` | true | 未知服务端错误；不得暴露堆栈 |

`not_modified` 是正常响应决策，不是错误码。A 只能对 `retryable=true` 重试；任何重试都必须携带同一 `request_id`/幂等语义，不能通过换软件、Profile、设备或时间参数绕过拒绝。同一幂等键对应的历史放行结果若因撤销、阻断、过期、解绑或配置/授权 revision 变化而失效，平台返回不可重试的 `IDEMPOTENCY_CONFLICT`，绝不重新发送旧的 `active` 签名响应；调用方必须生成新的请求标识并重新走当前事实判断。

### 冻结夹具

PR-05/PR-07 的中央合同夹具位于 `tests/fixtures/authorization_v1/`；A→核心的产品无关本地合同夹具位于 `tests/fixtures/authorization_a_core_v1/`，Schema 位于 `protocol/`。两者都是联调输入，平台不把某个产品路由写进合同：

所有正向中央和 A-core envelope fixture 都包含 `support`、`announcement`、固定五键 `modules` 和 `config_version`；`modules.contact`/`notice` 分别镜像支持/公告，空值使用 `null`。`tests.test_contract_fixtures` 会校验 JSON、稳定字段集合、Schema 版本、设备范围、时间窗口和完整性边界。

| 夹具 | 期望状态 |
|---|---|
| `active.json` | `decision=active`，身份/设备/签名/版本完整 |
| `grace.json` | `decision=grace`，仍受 `grace_until` 和撤销优先级约束 |
| `expired.json` | `decision=expired`，服务端时间达到排他 `expires_at` |
| `revoked.json` | `decision=revoked`，安全撤销不能被缓存宽限覆盖 |
| `blocked.json` | `decision=blocked`，授权实例自身阻断时使用签名状态信封；不等同于设备 `RISK_BLOCKED` |
| `not_modified.json` | 条件版本匹配时的正常无变更响应 |
| `missing-required-field.json` | 缺 `software_id`/`profile_id` 等必填字段，返回 `MISSING_REQUIRED_FIELD` |
| `signature-invalid.json` | 签名不匹配，返回 `SIGNATURE_INVALID` 并 fail closed |
| `response-schema-invalid.json` | 已签名响应的字段/类型/设备范围形状不符合合同，返回 `RESPONSE_SCHEMA_INVALID` 并 fail closed |
| `unknown-key.json` | `key_id` 未登记，返回 `KEY_UNKNOWN` 并 fail closed |
| `cross-scope.json` | 软件/Profile/设备范围不一致，返回 `PROFILE_MISMATCH` 或 `DEVICE_SCOPE_MISMATCH` |
| `time-rollback.json` | 服务端/A 检测到旧响应、服务端时间或本机墙钟回退，返回 `TIME_ROLLBACK_DETECTED` 并 fail closed |
| `risk-blocked-error.json` | 设备风险阻断返回普通 `RISK_BLOCKED` 错误、403 和 `no-store`，不包含 `decision`/`integrity` 授权信封 |
| `unbound.json` | 中央解绑形状 `decision=unbound` + `state_code=unbound`；A 必须映射为 A-core `AUTH_INVALID` deny，不得转成 active allow |
| `old-contract.json` | 旧合同版本，返回 `CONTRACT_VERSION_UNSUPPORTED` |

本地夹具至少固定 `local_contract_version=authorization-a-core.v1`、`origin=authorization-a`、`audience=authorization-a-core`、精确小写 `ed25519` 和 `JCS-RFC8785`。中央签名只由 A 验证；A 必须用自己的受保护私钥重新签发本地 envelope，核心只信任 A 公钥。

## 时间与有效期合同

- 服务端以 UTC 绝对时间为授权事实源；所有线协议时间字段使用有符号 64 位 Unix epoch seconds，不能读取客户端提交的当前时间或到期时间。
- `authorization-a-core.v1` 的业务时间门禁额外要求所有授权时间字段满足 `0 <= timestamp <= 9223372036854775807`；负 epoch 即 `AUTH_CONTRACT_INVALID`/fail closed，不表示允许 1969 年授权。Schema 仍明确使用整数秒和 int64 上界。
- `expires_at` 是排他结束时间；对于 `active`、`grace` 和 `not_modified`，必须满足 `issued_at <= server_time < expires_at`。服务端在 `server_time >= expires_at` 时返回 `expired`；`revoked`/`blocked` 等安全失效状态优先于时间状态，不能被 grace 覆盖。
- 两套钟不准改混：`expires_at` 是卡到期，激活时写进票，启动器交给主程序本地倒计时，到点关闭。挤机 / 解绑 / 撤销 / 阻断只改平台绑定事实，旧电脑必须再调 `POST /api/v1/public/licenses/verify`，收到 `DEVICE_NOT_BOUND`（或撤销/阻断）才关。禁止把验证间隔写成核心到期倒计时，也不要把「到期也必须再问平台才关」改成唯一关门条件。
- 对仍可验证的 `active`、`grace` 和 `not_modified` 响应，`cache_until` 与 `next_verify_at` 必须按同一公式计算：`min(expires_at, server_time + verify_interval_seconds)`。这两个字段只决定启动器何时再问平台，不是主程序还能开多久。因此验证间隔即使是 6 小时，也不能让缓存或下一次验证时间越过签名的 `expires_at`。
- 正式、测试、本地新建软件的默认 `verify_interval_seconds` 是 60。`cache_until` / `next_verify_at` 读当前 ACTIVE 策略间隔，已售已激活卡下次 `verify` 也跟现行间隔。禁止按软件名写 `if godskin`。
- `grace_until` 是策略元数据，不改变排他的 `expires_at`；即使它晚于 `expires_at`，A/core 在可信 `server_time >= expires_at` 时仍必须 fail closed，不能把它解释为当前 v1 的到期后授权。若未来允许到期后的离线宽限，必须另行冻结合同版本和明确的状态语义。
- `next_verify_at`、`grace_until` 和 `cache_until` 也使用 epoch seconds。后台、导出和统计默认按 `Asia/Shanghai`（北京时间）显示和划分自然日；显示转换不改变接口和数据库中的时间瞬间，也不依赖 VPS 的系统时区。
- A 必须按 `software_id + profile_id + authorization_id + device_scope` 保存已接受的最大 `server_time`。签名响应、缓存或服务端时钟使可信时间回退时，返回不可重试的 `TIME_ROLLBACK_DETECTED` 并 fail closed；仅有 nonce/revision 重放且没有时间回退时可使用 `REPLAY_DETECTED`。
- 通用A须在成功窗口到期前安排心跳，预留网络往返时间；提前发起请求不延长原成功窗口，网络失败、429、超时或重试不能推迟原截止。已验签且身份/请求关联正确的票据签发时间，以及已验证九字段关联的核销时间，也须推进同范围可信时间高水位并收紧剩余卡期限；票据不替代普通verify成功，不购买新的在线有效窗口。A-core输出及核心看守都使用这一高水位加单调经过时间，到期仍排他。
- 通过完整签名、Schema、身份、设备和当前请求关联校验的新普通activate/verify/not_modified成功，按该逻辑请求首次尝试的单调时刻加签名窗口长度替换在线预算，即使server_time与前次同为一个整数秒。可信卡钟、高水位及已经过的小数秒不得回拨，实际放行截止取普通成功截止与卡排他到期的最早值。同请求重放、迟到、断网、429、超时或退避不得购买新窗口；票据只推进可信时间并收紧既有截止，不刷新普通成功预算。
- `TIME_ROLLBACK_DETECTED` 的签名阻断信封不能使用回退后的不可信墙钟作为时间基准；其 `server_time` 使用服务端已持久化的可信时间高水位，并保持 `issued_at <= server_time`。该信封只表达阻断诊断，不授予任何缓存或功能放行。
- 客户端必须使用响应中的服务端时间和到期时间；本机墙上时钟、客户端时区以及客户端提交的 `expires_at` 不得参与授权判定。客户端倒计时应以服务端时间加本地单调计时为展示辅助，验证/心跳仍必须回到服务端。
- 需要测试过期锁定时，管理员可以创建 `test_only` 的 1 分钟套餐（内部为 `duration_seconds=60`）。它只改变测试标识和运营提示，仍走同一套激活、验证、设备绑定、撤销和审计合同。

### PR-07 平台运行时边界

- `LicenseCard 1—1 LicenseInstance 1—N DeviceBinding`。一张卡第一次成功激活才创建唯一授权实例；同卡同设备重复请求返回幂等结果。同卡新设备在未满员时新增绑定；满员时按 Profile 当前 ACTIVE 的是否允许换机和每日换机次数决定能否顶掉最旧有效绑定。有效期、套餐和同时在线 `max_devices` 仍锁发卡快照。
- `Device` 按 `software + profile + installation_id` 的服务端 HMAC 哈希隔离；`DeviceKey` 只保存 Ed25519 公钥和 key ID，不保存私钥；设备证明签名绑定动作、request ID、完整 Profile 身份、安装 ID、公钥和 nonce。
- nonce 只保存哈希并一次性消费。相同 request/idempotency **在记录保留期内**（默认 30 天，`AUTHORIZATION_REQUEST_RECORD_RETENTION_DAYS`）返回已保存结果；超期后原结果已按保留期清理，相同 key 重新提交与"更换 request/idempotency"一样返回不可重试的 `REPLAY_DETECTED`，客户端须换新的 request_id/idempotency_key/nonce。不同请求重新使用已消费 nonce 同样返回 `REPLAY_DETECTED`。
- 激活、验证、解绑的事务锁顺序固定为“卡密 → 授权实例 → 设备 → 设备密钥 → 当前绑定”；设备上限检查在授权实例行锁内完成。SQLite 只能验证行为，PostgreSQL 行锁并发是第二阶段必做证据。
- `expires_at` 排他；`server_time >= expires_at` 立即返回 `decision=expired` 并把绑定历史标记为 `expired`。服务端或 A 检测到可信时间回退时返回 `TIME_ROLLBACK_DETECTED`，实例和当前绑定 fail closed 为 `blocked`。
- 中央平台当前实现公共 `/api/v1/public/licenses/{activate,verify,deactivate}`、`generic-online-v1`、通用管理员风险控制台（授权撤销、设备阻断/解除阻断）以及 F-018/F-019/F-020 的版本、统计和受控清理 API；F-018/F-019/F-020 的历史真实 8123 管理端/下游页面与 API 验收已通过，不覆盖之后的顶卡/额度下拉改动。候选环境已实测反向代理/TLS、PostgreSQL 并发、共享 Worker 和对象存储 CRUD；正式生产 provider/IAM、A 的持久缓存、核心本地 IPC 和 A→core 强绑定仍未完成。

## 公共客户端接口

### 激活

`POST /api/v1/public/licenses/activate`

公共授权动作按来源地址和动作限速。`activate` / `deactivate` 仍在判定前按 IP 限流；超过窗口返回 `429`、`RATE_LIMITED`、`retryable=true`、`Retry-After` 和 `no-store`。`POST /api/v1/public/licenses/verify` 必须先做授权判定：硬失败（`DEVICE_NOT_BOUND`、撤销、阻断、卡已到期、设备密钥无效等）原样返回，禁止先返回 `RATE_LIMITED`。`RATE_LIMITED` 只用于这台绑定仍有效、只是问太勤。不要关掉限流，也不要把上限改成无限。当前本地切片的默认窗口为 5 分钟/120 次，生产必须把限速后端替换为多进程共享实现。窗口是固定的：到期后该身份从 1 重新计数。生产 `DatabaseCache.incr` 不得把每次加一的 TTL 改成默认 300 秒，否则客户端还开着就会一直 429。不要改成全站一个池，也不要把加大次数当成修复。

请求字段：

```json
{
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "license_key": "user-entered-key",
  "installation_id": "client-installation-id",
  "device_public_key": "base64-public-key",
  "device_proof": "signature-over-challenge",
  "client_version": "1.2.0",
  "nonce": "random-request-value",
  "request_id": "req_123",
  "idempotency_key": "activate-unique-key"
}
```

新客户端对activate/verify/deactivate三个POST均发送X-Request-Id及Idempotency-Key，并与JSON对应字段保持一致。请求号可从头或体解析；同名值同时存在必须一致。
兼容行为：单独缺幂等键时可回退到已解析request_id；请求头和请求体均没有request_id时返回MISSING_REQUIRED_FIELD，不会为授权业务自动生成一个可用请求号。新客户端不依赖这些兼容回退。一次未知结果的网络重试复用原请求体、request_id/idempotency_key/nonce；下一次独立逻辑操作使用新标识，超期重放按现行错误合同拒绝。

服务端依次校验软件、卡密、套餐、下游账号状态、设备策略、风控和版本策略。unused 首次激活还必须存在该卡密归属下游对该软件 `status=ACTIVE` 的经营范围行；无行或 `CLOSED` 返回 `LICENSE_NOT_ACTIVE`（403），卡密保持 unused。已开通实例的同设备再激活、换机和 verify 不走该经营范围闸。成功响应至少包含：

```json
{
  "authorization_id": "server-id",
  "authorization_revision": 17,
  "device_scope": {"scope": "current_device", "device_id": "device-server-id", "installation_id": "client-installation-id"},
  "decision": "active",
  "state_code": "active",
  "status": "active",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "policy_version": "policy-3",
  "adapter_version": "generic-online-v1",
  "capabilities": {
    "core.validate": true,
    "core.switch-device": false
  },
  "entitlements": {
    "edition": "pro",
    "limit.projects": 5
  },
  "support": {
    "purchase_url": null,
    "qq": null,
    "wechat": null
  },
  "announcement": null,
  "update": null,
  "config_version": "cfg-17",
  "cache_until": 1787119200,
  "expires_at": 1789689600,
  "server_time": 1787097600,
  "next_verify_at": 1787119200,
  "grace_until": 1787184000,
  "integrity": {
    "algorithm": "ed25519",
    "key_id": "platform-2026-01",
    "canonicalization": "JCS-RFC8785",
    "signature": "base64url-signature"
  }
}
```

### 验证

`POST /api/v1/public/licenses/verify`

使用授权实例 ID、已登记的 Profile 身份、设备公钥证明、客户端版本和一次性随机值。服务端保存 nonce 哈希；同一幂等请求在记录保留期内可以重放原结果（默认 30 天，见上一节），超期后与更换 request/idempotency 重新提交一样返回 `REPLAY_DETECTED`；更换 request/idempotency 重新提交已用 nonce 返回 `REPLAY_DETECTED`。验证接口必须重新判断撤销、到期、设备和风控，不只验证客户端缓存的签名。激活、验证、解绑和换机都必须校验软件/Profile/客户端身份组合。

请求样例（不含真实卡密、私钥或签名值）：

```json
{
  "request_id": "req_verify_001",
  "idempotency_key": "verify_001",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "authorization_id": "<ACTIVATE_RESPONSE_AUTHORIZATION_ID>",
  "installation_id": "<STABLE_INSTALLATION_ID>",
  "device_public_key": "<ED25519_PUBLIC_KEY_BASE64URL>",
  "device_proof": "<NEW_ED25519_PROOF_BASE64URL>",
  "client_version": "1.0.0",
  "nonce": "<FRESH_NONCE>",
  "known_authorization_revision": 1,
  "known_config_version": "<KNOWN_CONFIG_VERSION>"
}
```

服务端到期时返回结构化的过期错误（例如 `LICENSE_EXPIRED`）和当前服务端时间；授权 A 必须把结果传给核心，核心必须锁定受保护功能，不得因把本机时间调回过去、重启或重复发送旧响应而恢复可用状态。

卡到期靠票里的 `expires_at` 本地倒计时关闭，这是对的。挤机 / 解绑 / 撤销 / 阻断不是到期：旧电脑必须再问本次接口。已被挤掉或解绑后，即使该 IP 已经触发限流，本接口仍必须返回 `DEVICE_NOT_BOUND`（或撤销/阻断），不能 429。客户端把 `RATE_LIMITED` 当可重试、不关软件；因此限流不得先于硬结果。`cache_until` / `next_verify_at` 只决定启动器何时再问，禁止写进核心到期倒计时。默认间隔 60 秒，约 1 分钟内应看得见挤机。改当前策略后，已售卡下次 `verify` 也跟现行间隔。

### 解绑

`POST /api/v1/public/licenses/deactivate`

只允许解绑当前设备的绑定。管理员强制解绑另走管理端服务动作。解绑不会删除设备、密钥或绑定历史；成功响应使用 `decision=unbound` 与 `state_code=unbound`，授权实例本身仍保留到期事实。解绑和重置设备不消耗当日换机次数；坑位空了再激活新设备不算顶绑。满员顶绑仍读 Profile 当前 ACTIVE 换机两项。`decision=unbound` 不是放行：A/core 必须把它和 `state_code=unbound`、非活动绑定或非 2xx 传输结果映射为 A-core `error.code=AUTH_INVALID`、`retryable=false` 的结构化拒绝，不能把解绑信封当成 `active` 放行核心功能。

请求样例（不含私钥或签名值）：

```json
{
  "request_id": "req_deactivate_001",
  "idempotency_key": "deactivate_001",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "authorization_id": "<ACTIVATE_RESPONSE_AUTHORIZATION_ID>",
  "installation_id": "<STABLE_INSTALLATION_ID>",
  "device_public_key": "<ED25519_PUBLIC_KEY_BASE64URL>",
  "device_proof": "<NEW_ED25519_PROOF_BASE64URL>",
  "client_version": "1.0.0",
  "nonce": "<FRESH_NONCE>"
}
```

### 一次性启动票据

签发（含同键重放）与核销均重新核对当前卡密/授权有效性、授权到期、设备风险、当前有效绑定/设备公钥及现行票据开关；历史绑定不能代替当前绑定。当前硬失败原样拒绝，不因幂等或限流恢复放行。签发同键只可返回未到期、未核销、同revision的原票据，不另发新票或延长TTL；原票失效返回明确错误。票据到期不晚于授权到期。核销同键成功回执只在票据未到期且当前授权/绑定仍有效时重放，不重复核销。


`POST /api/v1/public/licenses/launch-ticket`（签发）与
`POST /api/v1/public/licenses/launch-ticket/consume`（核销）。

覆盖层只钉平台公钥、不再信任启动器私钥的软件，每次启动先换票再拉起。
两条都是纯新增：activate/verify/deactivate 的请求、响应、签名口径一字不动，
老客户端不认识它们也能继续工作。

签发请求与 activate/verify 同风格，`device_proof` 的 proof 消息 action 固定
`launch-ticket`（字段结构不变，只换 action 值）；核销请求多一个 `ticket_id`，
proof action 固定 `ticket-consume`。`nonce`、`request_id`、`idempotency_key`
口径不变，每次新的逻辑调用换新；结果未知的网络重试复用原请求体、request_id、idempotency_key 和 nonce。CSRF 豁免，HTTPS，只接受 POST，请求体同样限 32KB。

签发前置（全满足才签，否则按码拒签，不返回 200 空票）：
已激活且未过期（仅 active/grace；过期/撤销/阻断逐条拒签）、设备证明通过且
`installation_id` 与 `device_public_key` 匹配当前有效绑定、未被挤下线、
策略开着票据开关、限流正常。

成功响应 `decision=issued`，票据含 `ticket_id`（UUID）、三段身份、
`installation_id`、`issued_at`/`not_before`/`expires_at`（Unix 秒，到期时刻取
签发时刻加现行策略 TTL 与授权到期时刻的较早值，策略默认 180 秒）、`audience={software_id}-core`；`integrity` 与
中央响应同一把私钥、同一 key_id，覆盖范围是整个响应体去掉
`integrity.signature` 这一个字段（禁止删整个 integrity 对象再签，那是另一种
字节流），JCS-RFC8785（UTF-16 码元序），签名 base64url 无填充。

签发请求样例（`device_proof` 用 action=`launch-ticket` 签，字段结构见
`protocol/device-proof.v1.json`）：

```json
{
  "request_id": "req_ticket_001",
  "idempotency_key": "ticket_001",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "authorization_id": "<ACTIVATE_RESPONSE_AUTHORIZATION_ID>",
  "installation_id": "<STABLE_INSTALLATION_ID>",
  "device_public_key": "<ED25519_PUBLIC_KEY_BASE64URL>",
  "device_proof": "<ACTION_LAUNCH_TICKET_PROOF>",
  "client_version": "1.0.0",
  "nonce": "<FRESH_NONCE>"
}
```

签发成功响应样例：

```json
{
  "schema_version": "authorization.v1",
  "contract_version": "authorization.v1",
  "request_id": "req_ticket_001",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "authorization_id": "<AUTHORIZATION_ID>",
  "authorization_revision": 3,
  "decision": "issued",
  "server_time": 1787101200,
  "ticket": {
    "ticket_id": "<UUID>",
    "software_id": "software-a",
    "profile_id": "stable",
    "client_id": "software-a-windows",
    "installation_id": "<STABLE_INSTALLATION_ID>",
    "issued_at": 1787101200,
    "not_before": 1787101200,
    "expires_at": 1787101380,
    "audience": "software-a-core"
  },
  "integrity": {
    "algorithm": "ed25519",
    "key_id": "<PLATFORM_SIGNING_KEY_ID>",
    "canonicalization": "JCS-RFC8785",
    "origin": "authorization-platform",
    "audience": "software-a-core",
    "signature": "<BASE64URL_SIGNATURE>"
  }
}
```

核销请求样例（proof action=`ticket-consume`，其余同形，`nonce` 必须换新）：

```json
{
  "request_id": "req_consume_001",
  "idempotency_key": "consume_001",
  "software_id": "software-a",
  "profile_id": "stable",
  "client_id": "software-a-windows",
  "contract_version": "authorization.v1",
  "target": "windows",
  "arch": "x64",
  "channel": "stable",
  "authorization_id": "<AUTHORIZATION_ID>",
  "ticket_id": "<TICKET_ID>",
  "installation_id": "<STABLE_INSTALLATION_ID>",
  "device_public_key": "<ED25519_PUBLIC_KEY_BASE64URL>",
  "device_proof": "<ACTION_TICKET_CONSUME_PROOF>",
  "client_version": "1.0.0",
  "nonce": "<FRESH_NONCE>"
}
```

核销成功是以下九字段顶层对象，无 `integrity` 签名体。它是 HTTPS 请求的核销确认，不替代已签名的 issued 票据，也不能套用普通 authorization.v1 响应 Schema：

```json
{
  "schema_version": "authorization.v1",
  "contract_version": "authorization.v1",
  "request_id": "req_consume_001",
  "software_id": "software-a",
  "profile_id": "stable",
  "authorization_id": "<AUTHORIZATION_ID>",
  "decision": "consumed",
  "server_time": 1787101200,
  "ticket_id": "<TICKET_ID>"
}
```

平台签名、启动器验签和核心消费必须采用一致的 JCS 字节规则，授权响应及票据时间字段禁止浮点；错误类型须失败关闭。平台已有签名回归不代表参考启动器或具体核心已完成真实实现。软件侧须保留完整响应，只去 integrity.signature 后验签，再映射本地对象，并验证类型错误和篡改反例；不得以历史对账或模拟夹具代替实际验签证据。

核销成功 `decision=consumed`；同一张票第二次核销 `TICKET_ALREADY_CONSUMED`（409），
过期 `TICKET_EXPIRED`（410），不存在 `TICKET_NOT_FOUND`（404），设备对不上
`DEVICE_SCOPE_MISMATCH`（403）。错误体沿用现有 `{error:{code,message,request_id,retryable}}`
结构。限流沿用 verify 的先判定再限流：硬失败原样返回，429 只替换本会成功的签发。

### 客户端配置

当前没有独立公共配置 Manifest GET 路由。静态软件身份、验签公钥及公开能力定义来自后台下载的 software-bind.v2；运行时公告、真实下游渠道信息、能力/权益和 config_version 来自 activate/verify/deactivate 返回的普通授权信封。deactivate 的 unbound 仅用于停用确认，不能据此放行。更新另查下一节 releases。

渠道配置由服务端按授权实例真实归属解析，不能通过查询参数传入下游 ID。公告是可选能力，不作为授权主流程；购买链接只允许安全协议。客户端只能使用自己已实现的合同和能力；未知能力安全忽略或按合同拒绝，不下载执行插件。

### 版本检查

`GET /api/v1/public/software/{software_id}/profiles/{profile_id}/releases/?client_id=software-a-windows&version=1.2.0&target=windows&arch=x64&channel=stable`

由授权 A 调用。客户端必须带当前 `version`。返回最新已发布版本、`has_update`、版本号。默认下载是 `update_open_url`（网盘）。本站 ZIP 的 `download_url` 谁都能下，不要求卡密，预备以后大流量 VPS，不得删掉上传能力。不要把卡密放进网址，不要给 `/api/` 加 CORS `*`。弹窗由各软件自己做；平台只提供「有没有新版本」。

仅当软件明确选择本站 ZIP/自更新通道时，构建产物才需要附带 `client-release.v1` manifest，至少包含版本、软件/Profile、平台、架构、通道、更新说明和签名信息。该通道的生产 Manifest 还必须包含 `payload_sha256`：它按 ZIP 内除 Manifest 外的规范化文件名、文件大小和内容计算，且必须纳入 Manifest 签名；这样可以验证包内容而不把整个 ZIP 的 SHA-256 写回 ZIP 形成自引用循环。平台在包外重新计算并保存完整 ZIP 的 `package_sha256`，下载时同时校验大小和完整包哈希；不根据旧版本机械加一。该通道发布确认后保留旧版本并记录可撤回关系，客户端负责下载、验签、安装、重启和失败回滚。默认网盘更新只查询、提示并由用户点击打开系统浏览器，不要求实现安装器。

响应是顶层对象，没有 data/response 外壳，不带授权签名，不套普通授权 Schema。`has_update` 在顶层；版本、说明和更新地址在 `release` 内：

```json
{
  "software_id": "software-a",
  "profile_id": "stable",
  "minimum_client_version": "1.0.0",
  "has_update": true,
  "release": {
    "version": "1.2.4",
    "distribution": "external_url",
    "update_open_url": "https://example.test/download",
    "package_size": 0,
    "package_sha256": ""
  },
  "generated_at": "2026-11-16T00:00:00+00:00"
}
```

此为字段层级摘录，完整公开详情还包括 release_id、software_name、software_id/profile_id、target/arch/channel、minimum_client_version、notes、manifest、package_name、external_download_url、signature、status、created_at/published_at/withdrawn_at、withdrawal_reason、archived_at/archived_from_status/archive_reason、package_available。网盘版本提供 `release.update_open_url`；可用本站包提供 `release.download_url`（相对平台路径），二者按分发渠道选择。没有可分发版本时 `release=null`；有版本但无需升级时 `has_update=false`，release 仍可存在。generated_at 和版本详情日期是 ISO 字符串，不能按授权 epoch 秒解析。

软件侧必须先取得真实三段当前构建版本，以 query `version` 提交，不能用 `client_version` 或最低支持版本代替。缺失、空白、非法或超过64字符的version返回400/INVALID_VERSION；查询失败不得解释为“已是最新版”。公共更新及下载路径支持已登记的软件/Profile稳定标识，包括点号，不通过改JSON换身份规避。

管理端版本发布 API：

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 读取版本列表 | `/api/v1/manage/releases/` · GET | 仅 `platform_admin`；可按 `software_id`、`status` 筛选，`page`/`page_size` 服务端分页（冻结页默认 10、接口最大 200）；未指定状态或 `all` 时排除已丢弃草稿和已归档版本（`status=archived` 可单独读回）；返回版本元数据、网盘地址、服务端包大小/SHA-256、签名状态、包可用性和分页元数据；不返回包内容 |
| 发布网盘地址 | `/api/v1/manage/releases/external/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、软件、版本、至少 4 字说明和 HTTP/HTTPS 网盘地址（不含账号密码），可附带 64 位十六进制 `package_sha256` 完整性校验和；直接发布，无 ZIP；同一版本号已发布或已撤回时覆盖旧记录（`replaced=true`，HTTP 200），不必先换号；公共 registry 返回 `update_open_url` 与 `package_sha256` |
| 修改网盘地址 | `/api/v1/manage/releases/{release_id}/external-url/` · POST JSON | 仅管理员；必须带 `Idempotency-Key` 和新 HTTP/HTTPS 地址，可附带 64 位十六进制 `package_sha256`（不传保留旧哈希，传空串清空）；只允许已发布的网盘版本，版本号不变；公共 registry 下次查询返回新 `update_open_url` 与 `package_sha256` |
| 上传版本草稿 | `/api/v1/manage/releases/` · POST `multipart/form-data` | 仅管理员；备用本站 ZIP 通道；必须带 `Idempotency-Key`、软件、通道和 ZIP 包；服务端重新计算大小/SHA-256，读取唯一 `client-release.v1` Manifest，校验软件/Profile/平台/架构/通道；失败不留下 Release 或上传临时文件 |
| 确认发布 | `/api/v1/manage/releases/{release_id}/publish/` · POST | 仅管理员；需要更新说明和幂等键；只允许草稿，发布操作与审计同一事务；签名 `declared` 只表示声明，生产要求 `verified` 时必须有匹配公钥 |
| 丢弃草稿 | `/api/v1/manage/releases/{release_id}/discard/` · POST | 仅管理员；必须带幂等键；只允许 `draft`；删除安装包并把状态打成 `discarded`，同一软件/Profile/平台/通道/版本号可再传；已发布/已撤回 409 `RELEASE_NOT_DRAFT` |
| 撤回版本 | `/api/v1/manage/releases/{release_id}/withdraw/` · POST | 仅管理员；需要原因和幂等键；只允许已发布版本，保留历史，不卸载已安装客户端，也不立刻删除安装包 ZIP；响应含 `registry_fallback_version`（同一软件/Profile/通道剩余已发布里版本最高者，没有则为 `null`），公共 registry 按该版本回退 |
| 删除已撤回安装包 | `/api/v1/manage/releases/{release_id}/delete-package/` · POST | 仅管理员；必须带幂等键和 `confirmed: true`；只允许 `withdrawn` 且可走存储适配器删包；状态仍是 `withdrawn`，清空 `package_path` 并写 `package_deleted_at`，版本号仍占用；已发布/草稿/已丢弃 409 `RELEASE_NOT_WITHDRAWN`；包已空同键重放 200 `repeated` |
| 归档版本 | `/api/v1/manage/releases/{release_id}/archive/` · POST JSON | 仅管理员；必须带 `Idempotency-Key` 和至少 4 字归档原因；只允许 `published` 或 `withdrawn`（草稿 409 `RELEASE_NOT_ARCHIVABLE`，请直接丢弃）；归档后状态为 `archived`，记 `archived_at`、`archived_from_status` 和原因；默认版本列表不再返回，`status=archived` 可读回；版本号仍占用，重发同号会复活该行并清掉归档标记；归档一个已发布版本时响应含 `registry_fallback_version`，公共 registry 同步回退 |
| 就地改版本号 | `/api/v1/manage/releases/{release_id}/version/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、三段数字版本号和至少 4 字改号原因；只允许已发布的网盘版本；本站 ZIP 的 Manifest 已签名，不可就地改号（409 `RELEASE_NOT_RENUMBERABLE`），须重新构建、签名并发布；已撤回或草稿也不能改号；新号不得与同软件/Profile/平台/架构/通道下另一条未丢弃版本冲突（409 `VERSION_ALREADY_EXISTS`），必须高于该范围其他已发布版本（409 `VERSION_NOT_HIGHEST`），与当前号相同返回 409 `VERSION_UNCHANGED`；同步更新记录与 Manifest 的 `version`，响应含 `previous_version`，审计含前后版本号 |

公共 registry 只接受 `active`/`testing` 软件和 Profile；归档或草稿对象即使数据库保留发布记录，也不会公开查询或下载。下载前服务端重新解析包路径，拒绝绝对/相对越界路径和任意符号链接，文件名使用安全投影；授权 A 仍负责下载后的签名验签、安装、重启和失败回滚。静态 8124 预览中的上传/发布按钮只是演示，不是 API 或数据库证据。

### 统计 API

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 管理端统计总览 | `/api/v1/manage/analytics/summary/` · GET | 仅 `platform_admin`；支持 `software_id`、`downstream_id`、`window=7d|30d|empty`；返回今日/月/累计已激活卡套餐额度成本、授权数、激活成功率、额度净消耗、风险待处理（设备 `risk_state=blocked` 加授权实例 `blocked` 冻卡）、趋势、软件拆分、可选筛选项和真实空状态；`empty` 强制 `has_data=false`，窗口落在远未来，不使用写死的 2025 年 |
| 管理端统计导出 | `/api/v1/manage/analytics/summary/export/` · GET | 仅管理员；复用 summary 筛选；CSV 读取 `revenue.today/month/total`，范围说明含 window、北京日期和时区；成功写 `analytics.export` 审计 |
| 下游统计总览 | `/api/v1/downstream/analytics/summary/` · GET | 仅当前 active 下游；支持软件和时间筛选；服务端从会话确定下游，伪造 `downstream_id` 不扩权，返回余额、已发卡、可回收和自己范围内的统计 |

统计所有日期边界显式使用 `Asia/Shanghai`，数据库时间仍按 UTC 存储；收入只汇总 `activated_at` 非空卡密的 `quota_cost`，未激活卡不计入。0 成本测试卡即使已激活也使该项为 0。管理端不筛下游时，`revenue.total/today/month` 等于各下游同一口径之和；下游接口只汇总当前会话下游。`revenue.today/month/total` 按日历日/月/累计，不跟 window 走；空窗口返回 `has_data=false`、窗口内净消耗/拆分/趋势为零或空，不使用静态演示数字，也不把日历收入改写成 0。`software_id` 筛选必须同时收窄窗口内 `quota_net_consumed`：发卡扣额只计该软件的 `LicenseCardBatch`，回收只计该软件的 `LicenseCard`；不得把别的软件的流水算进来，也不得用日历收入顶替净消耗。管理端额度账本页只展示余额和流水，不展示未接线的「本月净消耗」装饰指标。

### 审计查询与导出 API

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 管理端审计列表 | `/api/v1/manage/audit/` · GET | 仅 `platform_admin`；筛选 `from_date`/`to_date`（北京自然日）、动作、结果、操作者、来源、下游公开 ID、软件 ID；`page`/`page_size` 服务端分页，默认 50、最大 100；返回 `actor_label`/`actor_role`、`object_label`（可读下游名称）、业务对象 ID、IP 等非凭证字段明文；客户端授权事件优先以 `installation_id` 显示操作者/来源；请求摘要继续保留摘要形式，并返回 `count`/`has_next` |
| 管理端审计导出 | `/api/v1/manage/audit/export/` · GET | 仅管理员；复用同一筛选，最多 1000 条 CSV；卡密/额度码等凭证仍不写入明文，设备、IP、下游名称和业务对象 ID 按读侧权限明文导出；截断时 `X-Export-Truncated=1` 与 `X-Export-Total`；成功或筛选失败都写审计 |
| 下游操作记录 | `/api/v1/downstream/audit/` · GET | 仅当前下游会话范围；SQL 按 actor/metadata/对象归属收窄后再 `page`/`page_size` 分页；`scope=all\|mine\|client` 也是 QuerySet 过滤；返回 `actor_label`/`actor_role`、`object_label`（当前下游名称）以及对象 ID、IP 等非凭证业务字段；客户端事件的操作者/来源使用客户端 `installation_id`；卡密/额度码凭证不返回完整值；不能用查询参数扩权 |
| 下游操作导出 | `/api/v1/downstream/audit/export/` · GET | 仅当前下游；复用 `scope` 与筛选，最多 1000 条（SQL LIMIT），对象名称、对象 ID、IP 和其他非凭证业务字段明文导出，卡密/额度码凭证不返回完整值，截断头与管理端相同 |

审计列表的 `q` 搜索同时覆盖动作、对象、操作者、原因码、客户端设备码 `installation_id` 及其历史设备关联；展示层允许显示客户端设备码和下游名称，但不得把完整卡密、额度兑换码或其他凭证写入审计元数据。授权激活失败若能通过卡密摘要或授权实例安全匹配，展示对应下游名称；匹配不到时显示“未匹配下游”，不伪造归属。

### 受控存储清理 API

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 扫描清理候选 | `/api/v1/manage/storage/cleanup/` · GET | 仅 `platform_admin`；只列出超过保留期、路径在允许根目录内的撤回版本包、`storage/tmp/`、`storage/exports/` 和 `storage/logs/` 文件，返回相对路径、大小、原因、候选总量和 `truncated`；扫描窗口最多 1000 条/5GiB，超出时 `truncated=true` |
| 执行清理 | `/api/v1/manage/storage/cleanup/` · POST | 仅管理员；必须带 `Idempotency-Key`；冻结页先弹出确认再 POST，确认文案绑定本次扫描数量/大小，`truncated=true` 时必须写明 1000 条/5GiB 窗口；锁定清理状态，删除前重新检查常规文件、根目录、大小和已记录 SHA-256；篡改、符号链接、越界、消失或变化的文件跳过；超预算单文件跳过并继续；操作可重放并写审计，绝不删除审计、额度流水、卡密、授权实例、设备历史或账号 |

清理操作只清除受控残留，不等于数据库备份/恢复，也不等于生产文件系统权限或对象存储验收；这些仍由部署终审和 `RUNBOOK.md` 负责。

### 授权 A 到核心 EXE 的本地合同

默认接口为 `http://127.0.0.1:<dynamic-port>/local/v1/`，端口由授权 A 每次启动分配，不能监听公网地址。授权 A 应向核心提供以下最小动作：

| 动作 | 方向 | 结果 |
|---|---|---|
| `GET /health` | 核心 → A | 返回 `local_contract_version`、软件/Profile 身份和 A 是否已就绪 |
| `POST /session/open` | 核心 → A | 以当前客户端版本和随机值建立本地会话；不提交平台卡密或下游 ID |
| `GET /session/state` | 核心 → A | 返回 `active/expired/revoked/offline/blocked`、服务端时间、到期时间、能力、`support`、公告和更新摘要 |
| `POST /session/refresh` | 核心 → A | 请求 A 按缓存和平台策略重新验证；不能延长服务端已结束的授权 |
| `POST /session/close` | 核心 → A | 结束本地会话并清理临时连接信息，不删除平台历史 |

本地成功响应至少包含：`local_contract_version`、`software_id`、`profile_id`、`client_id`、`target`、`arch`、`channel`、`authorization_id`、`authorization_revision`、`device_scope`、`decision`/`state_code`、`server_time`、`expires_at`、`cache_until`、`next_verify_at`、`grace_until`、`capabilities`、`entitlements`、模块数据、`config_version` 和强制 `integrity`。本地 `integrity` 的 `algorithm` 固定为小写 `ed25519`，`origin` 固定为 `authorization-a`，`audience` 固定为 `authorization-a-core`，`canonicalization` 固定为 `JCS-RFC8785`；`signature` 覆盖删除自身后的完整本地 response。其中 `server_time`/`expires_at`/`cache_until`/`next_verify_at`/`grace_until` 沿用有符号 64 位 Unix epoch seconds，但 A-core v1 业务门禁要求所有授权时间为非负整数；`support`、公告和更新缺省时必须是空值而不是伪造默认内容。Schema 和通用夹具分别见 `protocol/authorization-a-core.v1.schema.json` 与 `tests/fixtures/authorization_a_core_v1/`。

本地合同只传递声明式状态和元数据，不传递脚本、命令、任意 DLL 路径或“执行这段代码”的字段。核心收到格式错误、身份不匹配、签名无效、会话失效或 A 不可用时，必须显示可理解的错误并锁定受保护功能。

## PR-02 浏览器认证与账号动作

账号JSON输入采用最大遍历深度64的迭代Unicode校验，解析器超深、孤立代理字符及格式错误统一返回`400 INVALID_REQUEST`；原32KiB请求上限保持。正常Unicode与合法代理对不因此被拒绝。

登录用户名的限流身份与认证采用同样的NFKC规范化，再去首尾空白并大小写折叠。登录在原账号来源桶之外消耗独立入口/来源总预算；注册在原邀请码来源桶之外消耗独立来源总预算，不能通过更换账号写法或邀请码重置该来源预算。共享计数原子更新，窗口固定、到期重置；缓存竞争或后端故障拒绝放行。

PR-02 的真实用户入口是冻结的 8123 静态页面；Django 只提供同源 `/api/v1/` 服务。页面文件名不是 Django 路由，不能据此创建 8143，也不能恢复旧 `/manage/invitations/` 模板页面。生产环境由同一正式域名提供静态文件和 `/api/`，开发环境由 8123 静态服务代理到内部 Django 端口；浏览器不依赖跨端口 Cookie、宽松 CORS 或跳过 CSRF。

### 页面到 API 映射

| 页面动作 | API/方法 | 规则 |
|---|---|---|
| 读取匿名/角色会话 | `/api/v1/session/` · GET | 返回 `anonymous`、`platform_admin` 或 `downstream`；会话版本不匹配、归档或暂停下游按匿名处理；同时建立 CSRF Cookie |
| 管理端登录 | `/api/v1/auth/login/` · POST | JSON `username/password/entrypoint=admin`；只接受平台管理员；成功建立 Django 会话。浏览器里已有会话时，校验通过就换成这个管理员，不要求先退出或换浏览器；校验失败保留原会话。失败统一返回 `AUTHENTICATION_FAILED`，不泄露账号存在性 |
| 下游端登录 | `/api/v1/auth/login/` · POST | JSON `username/password/entrypoint=downstream`；只接受 active 下游；成功建立 Django 会话。已登录管理员或其他下游时，校验通过就换成这个下游，不要求先退出或换浏览器；校验失败保留原会话。密码正确但账号已暂停返回 403 `ACCOUNT_SUSPENDED`「账号已暂停。」；错密、错门、归档/关闭仍 `AUTHENTICATION_FAILED`「用户名或密码不正确。」，不按暂停口吻泄露账号存在性 |
| 登出 | `/api/v1/auth/logout/` · POST | 必须带 CSRF；只清除当前会话。管理员回 `manage-login.html`，下游和匿名回 `downstream-login.html`，永不返回隐藏入口 `entry.html` |
| 自助修改密码 | `/api/v1/auth/password/change/` · POST | 管理员或 active 下游；JSON `current_password/new_password/new_password_confirm`；必须带 `Idempotency-Key`、CSRF 和密码专用限速；当前会话通过 `update_session_auth_hash` 保留，其他旧会话失效；成功响应不返回密码 |
| 下游注册 | `/api/v1/auth/register/` · POST | JSON `invitation_code/username/password/password_confirm`；失败不创建 User/Profile、不消费或改变邀请码；成功原子消费邀请码后转入 `downstream-login.html`。同一规范化用户名对已由该用户消费的同一邀请码再次提交仍 201 并转入登录，不得报「邀请码不可用」；换用户名重用已消费码仍 400、不建第二号。成功句由登录页展示，不要求 JSON 另加 `message` 字段 |
| 管理端下游列表 | `/api/v1/manage/downstreams/` · GET | 仅管理员；服务端分页（`page`/`page_size` 最大 100）返回脱敏状态和真实 `pagination.total`；可选 `status=active|suspended|closed`，未知值 `INVALID_STATUS`；不能使用客户端 `downstream_id` 扩大范围 |
| 管理员直建下游 | `/api/v1/manage/downstreams/` · POST | 仅管理员；只使用用户名和密码，忽略页面展示的非 B1 字段；必须带 `Idempotency-Key`；创建 User/Profile 与 `DownstreamAdminOperation` 同一事务提交；同键重放原始 201 响应，密码只进入服务端 HMAC |
| 下游状态 | `/api/v1/manage/downstreams/<uuid>/status/` · POST | 仅管理员；只允许 `active`/`suspended`，必须带 `Idempotency-Key`；状态变更和 `DownstreamAdminOperation` 同一事务提交；暂停下游不能登录或发起业务 |
| 下游归档 | `/api/v1/manage/downstreams/<uuid>/archive/` · POST | 仅管理员；需要原因和 `Idempotency-Key`；递增 `session_version`，立即阻止登录并使现有会话失效；同键重放不重复改变状态 |
| 管理员重置下游密码 | `/api/v1/manage/downstreams/<uuid>/password/reset/` · POST | 仅平台管理员；JSON `new_password/new_password_confirm/reason`；必须带 `Idempotency-Key`、CSRF 和密码重置限速；目标必须存在且未归档；递增目标 `session_version` 使其全部旧会话失效；原因只以长度/摘要进入审计，密码不进入响应、日志或审计 |
| 删除归档下游 | `/api/v1/manage/downstreams/<uuid>/delete/` · POST | 仅管理员；必须显式确认、填写原因并带 `Idempotency-Key`；对象已归档后才执行；保留脱敏墓碑，审计、流水和 `DownstreamAdminOperation` 不删除 |
| 查看邀请码 | `/api/v1/manage/invitations/` · GET | 仅管理员；只返回单码列表、状态、时间、最终注册用户名快照和脱敏 `masked_code`/`code_suffix`；支持当前/归档分类筛选；列表不返回完整邀请码，不能依赖客户端下游 ID |
| 邀请码精确搜索 | `/api/v1/manage/invitations/search/` · POST | 仅管理员；完整码只放 JSON 请求体，服务端按 HMAC/哈希精确匹配并返回脱敏单码，不回显明文；受限流、CSRF 和 `no-store` 保护 |
| 发行邀请码 | `/api/v1/manage/invitations/` · POST | 仅管理员；数量有上限，结果按单码交付；邀请码不绑定下游、未使用前无业务期限；必须带 `Idempotency-Key`；发行受限流，超限返回 429 `RATE_LIMITED`；冻结页在本窗未成功前钉死同一幂等键，失败再点不得换新键；`InvitationBatch` 持久化保存管理员作用域内的 `Idempotency-Key` 与请求摘要，未删除时重试从加密密文重新交付，不把明文放入缓存；批次内邀请码均已墓碑时，同键重放返回 404 `INVITATION_NOT_FOUND`，响应不含完整码，不新发一批；混合批次只交付未墓碑的码；不返回批次 UI 合同 |
| 按需交付邀请码 | `/api/v1/manage/invitations/{public_id}/reveal/` · POST | 仅管理员；受 CSRF、限流和 `Cache-Control: no-store` 保护；从加密密文重复交付同一码明文；成功显示/复制/下载不写“谁看过”审计，失败和限流保留必要审计 |
| 作废未使用邀请码 | `/api/v1/manage/invitations/{public_id}/revoke/` · POST | 仅管理员；JSON `reason`（至少 2 个字）；只接受 `issued`；作废后该码不能注册；已过期/已使用/已作废返回 `INVITATION_UNAVAILABLE` 或 `INVITATION_EXPIRED`；冻结页邀请列表提供作废入口 |
| 归档邀请码 | `/api/v1/manage/invitations/archive/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、`code_ids`（非空数组）与原因；只接受已过期/已使用/已作废的码，有效未使用码必须先 revoke；整批事务，任一目标不合法则全部回滚；同键同体重放原结果 |
| 删除已归档邀请码 | `/api/v1/manage/invitations/delete/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、`code_ids`（非空数组）与原因；只接受已归档记录；整批事务并持久幂等，保留墓碑与审计，不物理删审计 |
| 邀请码导出 | `/api/v1/manage/invitations/export/` · GET | 仅管理员；复用列表筛选，最多 1000 条 CSV；完整邀请码不写入明文，只导出脱敏码与状态/时间/最终用户名快照；截断时带 `X-Export-Truncated` 与 `X-Export-Total` |
| 管理端目录导出 | `/api/v1/manage/catalog/export/` · GET | 仅管理员；导出软件/Profile/策略/套餐目录 CSV；口径与 `/api/v1/manage/catalog/` 一致（已删套餐留墓碑，导出按当前可见口径），最多 1000 条，截断时带头部标记 |

邀请码列表每项返回 `public_id`、`status`、`created_at`、`expires_at`、`consumed_at` 和 `consumed_username`；`consumed_username` 为空表示尚未注册，完整邀请码不出现在 GET 列表或错误响应中，只在发行响应或受保护的 `reveal` 响应中交付。批次码均已墓碑后，发行同键重放与 search/reveal 一样按不存在处理，不得从保留密文再交码。有效未使用邀请码必须先撤销，已过期、已使用或已撤销邀请码可直接归档；归档记录只能通过归档分类查询，删除接口只接受已归档记录。管理端邀请码表固定显示 5 个行位，分页控件位于表格底部右侧；不得把旧 Django 模板路径当成 8123 页面入口。

旧 `/manage/login/`、`/downstream/login/`、`/downstream/register/` 等 Django 模板路径仍保留为内部兼容/历史路线，不是 8123 页面入口。旧 HTML **业务写入口**（邀请发/揭/作废、下游建/归档/删除、目录创建与配置、额度发卡/揭码/兑换、批次发卡/揭码/回收/导出、授权风险页与客户配置、版本页上传/发布/撤回、备份旧页存策略与清理）无条件返回 410，正文必须是「请从当前控制室进入。」，不再依赖 `DISABLE_LEGACY_BATCH_VIEWS`，禁止半死表单。登录 GET、注册 HTML、只读总览/列表/审计 GET、备份下载 GET 和 `/api/v1/` JSON 写仍保留。本阶段不删除这些 URL，避免把历史兼容和静态入口清理混成同一变更。

密码动作统一返回 `Cache-Control: no-store` 的结构化错误：缺少幂等键为 `400/IDEMPOTENCY_REQUIRED`，当前密码错误为 `400/CURRENT_PASSWORD_INVALID`，新密码校验或确认失败为 `400/PASSWORD_INVALID` 或 `400/PASSWORD_MISMATCH`，同键不同请求体为 `409/IDEMPOTENCY_CONFLICT`，下游已归档为 `409/DOWNSTREAM_UNAVAILABLE`，限速为 `429/RATE_LIMITED` 并带 `Retry-After`。成功结果只返回 `changed`/`reset`、账号摘要、`request_id` 和 `replayed`，不返回新密码、当前密码、原因原文或操作请求体。

下游管理员写操作统一返回 `Cache-Control: no-store`。缺少幂等键为 `400/IDEMPOTENCY_REQUIRED`；同键不同动作、目标或请求体为 `409/IDEMPOTENCY_CONFLICT`；同键已有未完成事实为可重试的 `409/ADMIN_ACTION_RETRYABLE`；归档顺序错误为 `409/ARCHIVE_REQUIRED` 或 `409/ALREADY_CLOSED`。重放返回首次保存的脱敏 JSON 和原始 HTTP 状态，不返回初始密码。

## B2.1 软件目录、套餐和经营范围 API

B2.1 的管理/下游目录 API 使用冻结页面已有的 `apiRequest()`、同源 Django 会话 Cookie、CSRF Cookie/请求头和 `X-Request-Id`。所有写操作还必须带 `Idempotency-Key`；新建软件复用持久 `PlanCreateOperation` 的software-create动作，新增/修订套餐及经营范围分别按对应持久操作表重放。Profile 配置与下游渠道配置使用持久 `ConfigurationOperation`，绑定操作者、目标和原始 JSON 请求体哈希；同键同体返回首次结果，旧请求重试不覆盖较新的配置，同键换目标或内容返回 `409 IDEMPOTENCY_CONFLICT`。配置变更、审计与操作结果在同一事务提交，通过操作者行锁串行化首次请求。其他动作按各自实现使用幂等缓存。生产共享缓存与跨Worker证据必须单独核对，不能把本地LocMemCache当作共享证据。

B2.2 的本地运行方式由 `scripts/static_proxy.py` 提供：浏览器只访问 8123，冻结静态页面和 `/api/`、`/healthz/` 由同一端口提供，网关将固定上游请求转发到内部 Django 8000。Cookie、CSRF、`X-Request-Id` 和 `Idempotency-Key` 不跨端口重建；8000 仅是内部诊断地址，不能作为用户入口或验收证据。生产仍需由正式域名的受控反向代理提供同源静态文件和 API。

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 管理端读取软件、Profile、策略、能力、套餐快照和下游范围 | `/api/v1/manage/catalog/` · GET | 仅 `platform_admin`；始终返回服务端分页（`page`/`page_size` 最大 100）和真实 `pagination.total`，以及每个软件的 `client_connection`（未登记客户端时为 `not_connected`）。冻结管理端必须翻完分页后再把目录当全集（经营范围、发版、额度调整） |
| 从软件唯一入口创建软件、Profile、策略和可选首个套餐 | `/api/v1/manage/catalog/` · POST | 仅管理员；名称为最小业务输入；外层事务创建Software/Profile/PolicyVersion，选择首个套餐时才同时创建Plan/PlanSnapshot；持久幂等，失败全部回滚；套餐时长使用 `duration_value + duration_unit`，服务端保存正整数秒；换机字段缺省为允许且每日 5 次，冻结创建页必须提交表单勾选和次数 |
| 下架/重新上架软件 | `/api/v1/manage/catalog/software/{software_id}/status/` · POST | 仅管理员；JSON的status为archived或active，与至少4字原因。下架停止新发、阻止unused首次激活、关闭经营范围，已激活verify用到过期；重新上架只恢复软件状态，下架关闭的下游经营范围需明确重新开放，不自动恢复。操作与持久幂等记录、前后状态/原因审计同事务；同键同体重放原响应，同键异体409；旧HTML入口仍410，不接受draft |
| 修订 Profile 授权参数 | `/api/v1/manage/catalog/software/{software_id}/profiles/{profile_id}/policy/revise/` · POST | 仅管理员；提交设备上限、换机、设备证明、验证间隔、断网宽限；持久化幂等键生成新的 `PolicyVersion`，旧策略归档；仍指向刚归档策略的套餐会追加新 `PlanSnapshot`，已发出卡密和历史快照不改写；下次激活换机跟新规则，下次 `verify` 跟现行间隔；有效期/套餐/`max_devices` 仍锁快照；身份字段不可修改 |
| 新增套餐 | `/api/v1/manage/catalog/plans/` · POST | 仅管理员；明确提交 `software_id`、`profile_id`、`policy_version` 和套餐字段；同一软件可重复创建多个独立 Plan，每个新 Plan 生成自己的第 1 个 `PlanSnapshot`；`PlanCreateOperation` 保存请求摘要、结果和幂等键，且与 Plan/快照同一事务提交；失败整体回滚，写操作必须带幂等键 |
| 修订套餐 | `/api/v1/manage/catalog/plans/{plan_id}/revise/` · POST | 仅管理员；锁定 Plan，更新当前值并创建递增 `PlanSnapshot`；历史快照不可改写；持久化 `PlanRevisionOperation` 记录请求哈希和脱敏响应，缓存清空后同键仍只产生一个快照；生命周期状态变化必须改用 `/status/` |
| 归档/恢复套餐 | `/api/v1/manage/catalog/plans/{plan_id}/status/` · POST | 仅管理员；JSON `status=archived|active`、`reason`；锁定 Plan，持久化 `(actor, action=status, idempotency_key, request_hash)`，写 before/after 审计；归档停止新发卡和下游目录，不改变已发出卡效力；恢复重新检查软件、Profile、策略可用性；已删除套餐不能恢复；状态变更不创建新快照 |
| 删除已归档套餐 | `/api/v1/manage/catalog/plans/{plan_id}/delete/` · POST | 仅管理员；JSON `reason`（4–255 字）与幂等键；只接受 `archived`；同一事务把该套餐全部现存卡密失效（未激活回收退额度，已激活撤销），Plan 标 `deleted` 并从管理端目录/色块/套餐管理隐藏；快照、卡密行、流水、审计留下；同键重放返回原响应，未归档返回 `PLAN_NOT_ARCHIVED`，已删除再删 `changed=false` |
| 设置下游软件经营范围 | `/api/v1/manage/catalog/access/{downstream_public_id}/` · POST | 仅管理员；服务端校验下游状态、软件状态和套餐归属；`all_plans_allowed=false` 时只接受当前软件的 active 套餐 ID；持久化 `DownstreamSoftwareOperation` 绑定幂等键、目标和请求哈希，缓存失效后重放不能改写另一组范围。关闭某软件后：该下游不能再发该软件新卡；该下游该软件 unused 卡不能首次激活（公共 activate 返回 `LICENSE_NOT_ACTIVE`）；已开通 verify 继续；unused 回收仍退额度，不要求当前范围 ACTIVE |
| 下游读取自己可见的软件和套餐 | `/api/v1/downstream/catalog/` · GET | 仅 active 下游；服务端从当前会话推导 `DownstreamProfile`，不信任客户端下游 ID；只返回 active 软件、active Profile/Plan、生效时间已到且经营范围允许的套餐 |
| 下游读取/保存渠道支持 | `/api/v1/downstream/support/{software_id}/` · GET/POST | 仅当前 active 下游且已开放该软件；POST `values` 只更新出现的 `purchase_url`/`qq`/`wechat`，缺省键保持该下游该软件当前库值，不回填 Profile；显式空串清空该字段；`clear=true` 关闭整层 |

创建软件的最小业务字段为 `name`，服务端生成稳定身份并应用预填规则；显式身份的旧请求继续兼容。首个套餐可选，选择创建时须完整提供其套餐字段；新增套餐请求的最小业务字段为 `software_id`、`profile_id`、`policy_version`、`name`、`duration_value`、`duration_unit`、`quota_cost`、`test_only`、`capability_values`；策略/设备字段若省略使用页面默认值。正式套餐（`test_only=false`）`quota_cost` 必须 ≥ 1，测试套餐仍可 0；服务端拒绝正式 0 成本，错误码 `INVALID_QUOTA_COST`。套餐修订请求至少包含 `name`、`duration_value`、`duration_unit`、`quota_cost`、`test_only` 和 `capability_values`。失败返回统一 `error.code/message/request_id/retryable`，不暴露堆栈或数据库字段。

目录API处理软件/Profile/策略、可选首个套餐、套餐修订及经营范围。真实发卡和额度由其独立业务API完成，不产生演示卡密；软件保存成功或配置下载成功不能宣称授权A/核心已经接通。

## B3.1 额度兑换码、额度流水和购买链接 API

B3.1 的用户入口仍然是冻结的 8123 五页面；不新增 HTML、Django 模板页面或 8143。内部 `QuotaCardBatch` 只用于事务和幂等，以下响应、查询参数、下载名和页面结果均不返回批次号或批次视图。

额度兑换码密文使用独立的 `QUOTA_CARD_ENCRYPTION_KEY`，每行保存 `encryption_key_version`。当前版本新发卡使用 `QUOTA_CARD_ENCRYPTION_KEY_VERSION`；旧版本只能由显式历史密钥读取。`python manage.py rotate_quota_card_keys` 默认只做解密/哈希盘点；只有明确 `--apply` 才重加密，生产还必须设置一次性 `ALLOW_QUOTA_CARD_KEY_ROTATION=1`。命令不输出明文码、密钥或数据库连接信息，迁移失败整体回滚。

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 读取额度卡购买链接 | `/api/v1/public/quota-settings/` · GET | 匿名可读；返回 `purchase_url` 或 `null`，用于下游登录、注册和工作台；不返回账户或卡密数据 |
| 管理端读取额度 | `/api/v1/manage/credits/` · GET | 仅 `platform_admin`；返回购买链接、单码额度兑换码列表、全平台流水和账户余额；`accounts[]` 含在档 ACTIVE 下游（可无 `QuotaAccount`、此时 `available_balance=0`）、已有账户的暂停/归档下游，以及墓碑账户（`status=deleted`、`username` 为空、余额原样保留）；读路径不 `get_or_create`。另给 `operating_available_balance`（仍有下游档案的账户余额合计，含暂停/归档，不含墓碑）；冻结页左侧大数字只读该字段，禁止把 `accounts[]` 全表余额加总。冻结页现调额窗仍只读该缓存里 `status=active` 的项，禁止改跟下游表当前筛选走。`scope=current|archived|all` 控制当前/归档/全部分类，`card_page`/`ledger_page` 默认 5 行服务端分页，可用 `card_page_size`/`ledger_page_size` 调整（最大 100）；列表返回脱敏 `masked_code`/`code_suffix`，不返回批次字段或列表完整码 |
| 管理员调整下游额度 | `/api/v1/manage/credits/adjust/` · POST | 仅管理员；JSON `downstream_public_id`、`adjustment_type=credit|debit`、正整数 `amount`、原因；需要 `Idempotency-Key`。`credit` 走 `credit_quota` 写入 `manual_credit` 正向流水，`debit` 走 `recover_downstream_credits` 写入 `ADMIN_ADJUSTMENT` 负向流水。余额不足拒绝且不入账；下游越权返回 403。活账户调额窗不含墓碑下游 |
| 扣回已删除下游余额 | `/api/v1/manage/credits/recover-deleted/` · POST | 仅管理员；JSON `downstream_public_id`、正整数 `amount`、原因；需要 `Idempotency-Key`。只扣墓碑账户剩余余额，不把墓碑塞进现调额窗，不改 `operating_available_balance` 口径。下游档案还在时返回 409 `DOWNSTREAM_STILL_PRESENT` |
| 保存额度卡购买链接 | `/api/v1/manage/credits/settings/` · POST | 仅管理员；JSON `purchase_url` 可为空，只接受不含账号密码的 HTTP/HTTPS 地址；需要 `Idempotency-Key`，同一管理员同一键同一内容永久重放首次结果，旧键重试不覆盖更新后的当前链接，冲突返回 `IDEMPOTENCY_CONFLICT` |
| 发行额度兑换码 | `/api/v1/manage/credits/cards/` · POST | 仅管理员；JSON `amount`、`quantity` 必须是正整数；发行不接受下游字段，完整码在本次发行结果 `items[].code` 中交付；未删除时同键重放交原码；批次码均已墓碑时同键重放返回 404 `QUOTA_CARD_NOT_FOUND`，响应不含完整码，不新发一批；混合批次只交付未墓碑的码；响应不含 `batch_id` |
| 作废未兑换单码 | `/api/v1/manage/credits/cards/{public_id}/revoke/` · POST | 仅管理员；需要原因和幂等键；只有 `issued` 可作废，`redeemed`/已作废拒绝；只改变该单码状态，不写额度流水 |
| 归档额度兑换码 | `/api/v1/manage/credits/cards/archive/` · POST | 仅管理员；需要原因和幂等键；已撤销或已兑换等终态可直接归档，有效 `issued` 必须先作废；归档后进入 `scope=archived` 分类，写审计和生命周期操作 |
| 删除归档额度兑换码 | `/api/v1/manage/credits/cards/delete/` · POST | 仅管理员；需要原因和幂等键；只接受已归档记录，删除后保留脱敏墓碑、审计、额度流水和密文（供恢复核对），完整码不再 reveal，发行同键重放亦按不存在 |
| 额度兑换码精确搜索 | `/api/v1/manage/credits/cards/search/` · POST | 仅管理员；完整码只放 JSON 请求体，服务端按 HMAC/哈希精确匹配并返回脱敏单码，不回显明文；受限流、CSRF 和 `no-store` 保护 |
| 按需交付额度兑换码 | `/api/v1/manage/credits/cards/{public_id}/reveal/` · POST | 仅管理员；受 CSRF、限流和 `Cache-Control: no-store` 保护；从加密密文重复交付同一码明文；成功显示/复制/下载不写“谁看过”审计，失败和限流保留必要审计 |
| 读取当前下游额度 | `/api/v1/downstream/credits/` · GET | 仅 active 下游；服务端从当前会话推导账户，返回余额、单页流水、北京自然日 `today_consumed`（当日扣额合计，不含入账）和购买链接，不接受下游 ID |
| 导出额度流水摘要 | `/api/v1/manage/credits/ledger/export/` · GET | 仅管理员；最多 1000 条脱敏 CSV；截断时响应头 `X-Export-Truncated=1` 与 `X-Export-Total`；成功写入审计 |
| 导出额度兑换码摘要 | `/api/v1/manage/credits/cards/export/` · GET | 仅管理员；复用当前列表的 `scope`/`status`/`amount`/`redeemed_by` 筛选；最多 1000 条脱敏 CSV，不含完整码；截断与审计同上 |
| 当前下游兑换额度卡 | `/api/v1/downstream/credits/` · POST | 仅 active 下游；JSON `card_code`，服务端从当前会话确定实际入账账户；需要 CSRF、幂等键和限流；额度卡、流水、余额和兑换状态在一个事务中改变 |

额度码列表每项返回 `public_id`、面额、状态、发行时间、实际兑换下游、兑换时间、IP 摘要和作废原因；`scope=current|archived|all` 由服务端控制归档分类，`status`、`amount`、`redeemed_by` 结构化筛选也在分页前生效；完整码不进入列表、URL、日志或隐藏 DOM。流水每项返回下游、方向、金额、操作类型、来源引用、原因、前余额、后余额和 UTC 时间。分页元数据包含 `page`、`page_size`、`total`、`total_pages`、`has_previous` 和 `has_next`。所有错误沿用统一 `error.code/message/request_id/retryable` 合同；兑换失败、限流或重复不得改变余额。

购买链接保存由持久化的 `QuotaPurchaseUrlOperation` 记录幂等事实：记录管理员身份、幂等键、请求哈希、该次请求实际返回的 `purchase_url` 和创建时间，并对 `(actor, idempotency_key)` 建立唯一约束。服务端在同一事务内锁定平台设置行；相同管理员和键的相同内容直接返回操作记录中的原始 URL，不再次写当前设置或成功审计；相同键不同内容返回 `IDEMPOTENCY_CONFLICT`；另一个管理员可以使用同名键而不共享幂等作用域。`QuotaPlatformSettings.last_idempotency_key` 和 `last_request_hash` 仅保留兼容可读性，不再作为历史幂等事实源。

## B4 授权卡密发卡、单卡监管和回收 API

B4 继续只使用冻结的 8123 五页面和同源 `/api/v1/`。任意卡券类型都允许一次生成多张；内部 `LicenseCardBatch` 只承担事务、额度扣除和幂等，不作为用户列表、筛选、URL、下载名或交付维度。用户可见列表只返回单卡脱敏摘要；完整卡密只在本次发卡结果或受保护的 POST reveal 响应中交付。批次卡均已墓碑时，发卡同键重放按不存在处理，不得从保留密文再交完整码；混合批次只交付未墓碑卡的码。

所有 8123 业务表都声明 `data-row-slots=5` 或 `data-row-slots=10`；服务端分页表也必须在真实行不足时显示剩余空白行位，分页控件不放在筛选工具栏内，统一位于表格底部并右对齐。

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 下游成本预览 | `/api/v1/downstream/licenses/preview/` · POST | 仅 active 下游；JSON `software_id`、`plan_id`、`quantity`；服务端从当前会话推导归属，返回不可篡改的短时 `preview_token`（默认 600 秒，与 `LICENSE_CARD_PREVIEW_TTL_SECONDS` 一致）、展示用 `expires_in`、单卡/总成本和生成后余额，不创建卡密或流水 |
| 下游确认批量发卡 | `/api/v1/downstream/licenses/issue/` · POST | 仅 active 下游；必须带 CSRF、`Idempotency-Key` 和匹配的 `preview_token`；服务端再次锁定下游账户、软件/套餐快照并在一个事务内扣额度、生成卡密、写审计；未删除时同键重放返回 201 并交原码；批次卡均已墓碑时同键重放返回 404 `LICENSE_CARD_NOT_FOUND`，不新发卡、不再扣额度、响应不含完整码；混合批次只交付未墓碑卡的码；管理员调用固定返回 403 |
| 下游单卡列表 | `/api/v1/downstream/licenses/cards/` · GET | 仅当前下游；按单卡服务端分页读取；默认排除 `archived`，`status=archived` 或 `scope=archived` 拒绝；支持其余 `status`、`software_id`/`software_name`、`plan_snapshot_id`/`plan_name`、`device_state=bound|unbound`、`expiry_state=not_started|started|expired`；筛选条件先在服务端生效，再计算 `pagination.total/total_pages`；响应不含 `batch_id`、内部 batch 或明文 `code`；卡密仍只返回脱敏尾号，设备 ID、IP 和其他非凭证业务字段按当前下游读侧权限明文返回 |
| 下游精确搜索 | `/api/v1/downstream/licenses/cards/search/` · POST | 完整码只放 JSON 请求体，不进入 URL；服务端按当前会话归属查找，排除归档卡，返回脱敏单卡摘要，不回显明文；归档码与不存在一样返回 `LICENSE_CARD_NOT_FOUND` |
| 下游按需交付完整码 | `/api/v1/downstream/licenses/cards/{public_id}/reveal/` · POST | 仅当前下游归属；服务端权限、限流和 CSRF 生效，成功响应 `Cache-Control: no-store`；归档卡与不存在一样返回 `LICENSE_CARD_NOT_FOUND`；成功显示不写“谁看过”审计，失败/限流保留必要审计 |
| 下游回收预览 | `/api/v1/downstream/licenses/cards/reclaim-preview/` · GET | 仅当前下游归属；接收当前列表筛选（状态强制为 `unused`；`software_name`/`plan_name` 与列表同为精确匹配），返回可回收张数、原始成本总额和冻结的 `card_ids`（仍 ≤1000），不改变数据 |
| 下游批量回收未激活卡 | `/api/v1/downstream/licenses/cards/reclaim/` · POST | 仅当前下游归属；必须提交预览锁定的 `card_ids` 和至少 4 字 `reason`，必须带 `Idempotency-Key`；禁止只传 `selection: filtered` 再按筛选活查。服务端按稳定 ID 顺序锁定，只接受 `unused`，原始成本在同一事务中返还一次，零成本不写 0 金额流水，已激活/越权/重复 ID 拒绝；预览之后新发的未激活卡不会被扫进这次确认；不要求当前经营范围 ACTIVE |
| 管理端全平台单卡列表 | `/api/v1/manage/licenses/cards/` · GET | 仅 `platform_admin`；`scope=current|archived|all` 控制当前/归档/全部分类；可按状态、软件、套餐、当前下游、设备状态、期限状态和分页查看全平台单卡，包含明文下游用户名和业务对象引用；卡密仍只返回脱敏尾号，设备 ID、IP 和其他非凭证业务字段按管理员读侧权限明文返回；筛选发生在分页前，不能从此接口发卡 |
| 归档授权卡密 | `/api/v1/manage/licenses/cards/archive/` · POST | 仅管理员；需要原因和幂等键；已过期、已回收、已撤销或其他终态可直接归档，仍有效的未使用卡必须先回收；归档后进入独立分类，保留授权/设备/审计历史 |
| 删除归档授权卡密 | `/api/v1/manage/licenses/cards/delete/` · POST | 仅管理员；需要原因和幂等键；只接受已归档记录；删除采用脱敏墓碑，保留授权实例、设备历史、审计、额度流水和密文（供恢复核对），不能再 reveal，发卡同键重放亦不得从密文交码 |
| 管理端精确搜索/按需交付 | `/api/v1/manage/licenses/cards/search/` · POST；`/api/v1/manage/licenses/cards/{public_id}/reveal/` · POST | 仅管理员；搜索请求体接收完整码，响应和列表仍脱敏；reveal 受限流、CSRF、`no-store` 和审计失败路径保护 |
| 管理端回收预览 | `/api/v1/manage/licenses/cards/reclaim-preview/` · GET | 仅管理员；接收当前列表筛选（含 `scope=current|archived|all`）并返回可回收张数、原始成本总额和冻结的 `card_ids`；归档分类没有未激活卡，预览为 0 且 `card_ids` 为空；`software_name`/`plan_name` 与列表同为精确匹配，不改变数据 |
| 管理端回收未激活卡 | `/api/v1/manage/licenses/cards/reclaim/` · POST | 仅管理员；必须提交预览或勾选锁定的 `card_ids`，以及至少 4 字 `reason` 和 `Idempotency-Key`；禁止只传 `selection: filtered` 再按筛选活查。持久化 `LicenseReclaimOperation` 记录 `(actor, idempotency_key)`、请求哈希和脱敏响应，同键不同内容返回 `IDEMPOTENCY_CONFLICT`；可回收卡的原始下游获得额度返还；不要求当前经营范围 ACTIVE |
| 导出授权卡密摘要 | `/api/v1/manage/licenses/cards/export/` · GET；`/api/v1/downstream/licenses/cards/export/` · GET | 管理员全平台或当前下游；复用当前列表筛选；最多 1000 条脱敏 CSV，不含完整码；截断时 `X-Export-Truncated=1` 与 `X-Export-Total`；成功写审计 `license_card.export` |

`filters` 只接受合同列出的 `status`、`software_id`、`software_name`、`plan_snapshot_id`、`plan_name`、管理员可用的 `downstream_public_id`、`device_state`、`expiry_state` 和管理端 `scope`；`software_name`/`plan_name` 与列表同为大小写不敏感的精确匹配，不能用包含匹配把「月卡」扩成「超级月卡」。服务端先应用卡密筛选再分页，分页元数据必须反映筛选后的集合；下游侧忽略客户端提供的归属标识。回收预览/提交仍强制状态为 `unused`，管理端归档分类的筛选回收候选为空，并在提交时服务端再次计算候选集合、归属、数量和返还金额。

`LicenseReclaimOperation` 是 API 级幂等事实，回收操作和每张卡的状态变化、额度流水、原因与成功审计位于同一个外层事务；同键竞争插入在保存点内处理，避免唯一键冲突污染事务；卡片按稳定公共 ID 顺序处理，减少重叠批量请求的死锁风险；中途任一张失败整体回滚。完整码不写入列表 DOM、查询 URL、日志、审计 metadata、回收操作响应或下载摘要。服务端错误至少覆盖 `PREVIEW_EXPIRED`、`PREVIEW_MISMATCH`、`INSUFFICIENT_QUOTA`、`CARD_NOT_RECLAIMABLE`、`NO_RECLAIMABLE_CARDS`、`RECLAIM_TOO_MANY`、`RECLAIM_INCONSISTENT`、`RATE_LIMITED` 和 `IDEMPOTENCY_CONFLICT`，沿用统一 `error.code/message/request_id/retryable` 结构。

公共verify、deactivate、启动票据签发与核销在进入数据库前校验authorization_id格式，非法UUID返回400/INVALID_REQUEST，合法但不存在保持原AUTHORIZATION_NOT_FOUND语义。票据新签发与核销使用同一可信有效时间并原子推进授权及绑定的时间高水位；15秒内漂移取高水位与当前时刻最大值，超过容差返回TIME_ROLLBACK_DETECTED，不因此另行持久封卡。有效时间必须处于not_before（含）与expires_at（不含）之间，提前核销返回TICKET_NOT_YET_VALID；原票重放不延长TTL。拒绝请求的脱敏失败审计在最外层事务回滚后保留一次。

## B5 在线授权、设备诊断和风险处置 API

B5 继续只使用冻结的 8123 五页面和同源 `/api/v1/`。公共 `activate/verify/deactivate` 仍由授权 A 调用；本节只补平台管理端的已激活授权读侧和管理员处置动作，不创建授权 A 页面、核心页面或 8143 入口。

管理端绑定与历史项的`binding_order_known`表示该事件是否拥有可靠持久顺序，为false时不得把同秒历史的展示顺序解释为真实时序；列表、详情、导出、下游读取和续期使用统一绑定事实。该字段不改变公共授权协议的整数秒时间、设备身份或卡密期限。

管理端授权项的 `time_rollback_blocked` 为服务端计算的只读布尔值，只表示该授权由服务端可信时间回拨阻断；与保留ACTIVE座位的 `card_frozen` 不同。页面据此提供“恢复时间阻断”，确认服务器时间恢复后，仍调用现有该授权设备的 `unblock/` POST（原因、CSRF、持久幂等和管理员权限不变）；后端重新验证资格。恢复不延长到期，也不解封物理风险设备。`risk_signals` 是全平台最近50条，不随本页筛选变化；只有记录的脱敏线索可展示，不能按未认证请求中的对象ID自动归罪或处罚。

所有选择操作在确认时冻结目标ID，首次提交后冻结正文和幂等键；零选择不能隐式改为筛选全量。同一次单卡处置若网络结果未知，前端保留原目标、原因和幂等键原样重试；已收到成功响应后，列表刷新失败只重读列表，不再次提交处置。`activate` 在持久化时间阻断前必须先完成当前策略的设备证明校验；无效证明不能因平台时钟回拨改变客户授权状态。有效证明遇到超过容差的真实回拨仍安全阻断。

续期、撤销授权、物理设备封禁与解封的逐项事务同时保存该项完成事实。同键重试跳过已完成项并继续未完成项，汇总保留原结果；目标授权到物理设备的映射在开始时冻结。旧版无逐项事实的空操作无法安全推断，返回可重试409并要求人工核对，不自动重复加时。响应丢失不能通过换键重做整组。

设备诊断查询支持 `q`（授权 ID、卡密对象 ID、平台设备 UUID、客户端 `installation_id` 设备码、软件、Profile、套餐、下游用户名或 IP）以及 `status`、`software_id`、`downstream_public_id`、`device_state`、`risk_state`、`expiry_state`；服务端以“每个授权实例与每个物理设备的最新绑定事实”为分页基本单位，筛选先作用于该设备行，再分页；一个授权有多台设备时允许在多个页出现，但每页真实设备行不超过 `page_size`，`pagination.total/total_pages` 按设备行计算。`device_state=bound|blocked|unbound` 只滤该行最新 `DeviceBinding.state`（`active` / `blocked` / `unbound`）：`unbound` 不是非 `active` 补集，`device_state=blocked` 也不等同 `device.risk_state`。`risk_state` 只滤设备风险；`status` 含 `blocked` 时滤授权实例状态。导出复用同一组筛选条件，最多 1000 条 CSV；卡密只保留脱敏尾号，设备 ID、IP 和其他业务引用按读侧权限明文返回；截断时 `X-Export-Truncated=1` 与 `X-Export-Total`，并写审计 `authorization.export`。设备操作使用短期加密 `device_action_ref`（Fernet，TTL 与 `AUTHORIZATION_ADMIN_ACTION_REF_TTL_SECONDS` 一致），不是展示用设备 ID，也不是可解码的 HMAC 签名票。

| 页面动作 | API/方法 | 权限和结果 |
|---|---|---|
| 下游读取自己的授权设备 | `/api/v1/downstream/devices/` · GET | 仅 active 下游；归属从当前会话推导；以每个授权设备的最新绑定事实为一行进行服务端分页、搜索，并返回 `device_code`/`installation_id`（优先展示）和 `device_uuid`/`device_id`（内部兼容）及明文 IP；不返回公钥、安装 hash、完整卡密或跨下游对象 |
| 下游重置自己的设备绑定 | `/api/v1/downstream/authorizations/{authorization_id}/devices/{device_action_ref}/reset/` · POST | 仅当前卡密归属下游；必须 CSRF、原因和持久化 `Idempotency-Key`；设备引用绑定下游+授权+设备；只解除目标授权当前 **active** 绑定，保留历史和到期时间，不提供全平台 block/unblock/revoke。非 active（含 `blocked`）幂等 200、不改库；响应 `device.binding_state` / `binding_state_label` 必须跟该行最新绑定事实走，禁止写死 `unbound` / 「已解绑」 |
| 管理端读取授权与设备风险 | `/api/v1/manage/authorizations/` · GET | 仅 `platform_admin`；支持 `q` 搜索授权 ID、卡密对象 ID、客户端设备码、平台设备 UUID、软件、Profile、套餐、下游用户名和 IP，支持 `status`（含实例 `blocked`）、`software_id`、`downstream_public_id`、`device_state`（绑定态 `bound`/`blocked`/`unbound`）、`risk_state`（仅设备风险）、`expiry_state`；服务端以每个授权设备最新绑定事实分页，筛选只返回实际命中的设备行，`items[].devices[]` 只包含当前页命中的设备；结果返回明文设备 ID、IP、业务引用和短期 `device_action_ref`，用于 CSRF 保护的重置/封禁/解封；仍不返回 installation hash、公钥、卡密密文、完整卡密或完整 request id；每个设备项保留绑定状态、风险状态、明文 IP、绑定/解绑/最近访问时间及 `binding_history[]`；列表项带该卡 `policy_version.verify_interval_seconds`，只给撤销确认写大约还能开多久，不缩短已售间隔 |
| 管理员精确重置设备绑定 | `/api/v1/manage/authorizations/{authorization_id}/devices/{device_action_ref}/reset/` · POST | 仅管理员；`device_action_ref` 必须为服务端加密短期引用，不接受原始设备 UUID；必须 CSRF、原因和 `Idempotency-Key`；只把该授权实例与该设备的当前 active binding 改为 `unbound`，不影响共享设备上的其他授权，不改授权到期、套餐快照、卡密收入或历史绑定；重置后该授权的 public `verify` 返回 `DEVICE_NOT_BOUND` |
| 管理员冻结这张卡 | `/api/v1/manage/authorizations/{authorization_id}/devices/{device_action_ref}/block/` · POST | 仅管理员；`device_action_ref` 必须为服务端加密短期引用；必须 CSRF、原因和 `Idempotency-Key`；只将目标授权实例置为blocked并递增revision，原ACTIVE绑定继续占座，不能靠换电脑激活绕过；不修改物理设备风险标记，不影响同机其他卡；卡密、实例、设备和绑定按现行锁序校验并写审计 |
| 管理员解冻本卡／恢复时间阻断 | `/api/v1/manage/authorizations/{authorization_id}/devices/{device_action_ref}/unblock/` · POST | 仅管理员；必须CSRF、原因、持久幂等和服务端加密短期设备引用。普通解冻保留原ACTIVE绑定，无需重新激活；独立时间阻断资格由服务端判定，只恢复其因时间异常阻断的绑定，仍有物理风险的设备跳过；两者均不延长到期、不解封整台设备；物理封禁／解封使用下列独立批量入口 |
| 管理员撤销授权 | `/api/v1/manage/authorizations/{authorization_id}/revoke/` · POST | 仅管理员；必须 CSRF、原因和 `Idempotency-Key`；授权实例进入 `revoked`，卡密进入 `revoked`（已回收卡除外），当前绑定失效并递增 revision；重复动作不恢复状态 |
| 续期预览 | `/api/v1/manage/authorizations/renew-preview/` · GET | 仅管理员；查询参数与授权列表一致（`status`、`software_id`、`downstream_public_id`、`expiry_state`、`q`），另加 `unit`（`hour`/`day`）和 `amount`；只返回已激活且未过期的授权（`state ∈ {active, grace}`、`server_now < expires_at`、卡密 `activated`），`expiry_state=expired` 或非活跃 `status` 一律返回空；响应含冻结的 `authorization_ids`、每条 `expires_at`/`new_expires_at`、`renewable_count` 和 `added_seconds`；超过 500 条返回 400 `RENEWAL_TOO_MANY`；此接口不写库 |
| 批量续期 | `/api/v1/manage/authorizations/renew/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、`authorization_ids`（非空数组，最多 500）、`unit`、`amount` 和 2–255 字原因；确认只接受提交的这批 ID，不按筛选条件重新活查；逐条独立事务，成功与失败分别汇报（`items`/`renewed_count` 与 `failures`/`failed_count`，失败项含稳定 `code`）；每条同时推后 `LicenseInstance.expires_at` 与 `LicenseCard.expires_at` 并递增 `authorization_revision`，客户下次 `verify` 即返回新到期时间；未激活、已过期（`AUTHORIZATION_EXPIRED`）、已撤销（`AUTHORIZATION_REVOKED`）、已阻断（`AUTHORIZATION_BLOCKED`）一律拒绝；不写额度流水、不改 `quota_cost`、不计收入；同键重放返回同一结果且不重复加时间 |
| 管理端设备总表 | `/api/v1/manage/devices/` · GET | 仅管理员；以物理设备为一行的管理读侧（与授权表互补：授权表按授权聚合、本表按设备聚合），支持 `q`（最长 128 字）与授权表同一套筛选；服务端分页，`page_size` 最大 100；返回设备明文 ID、风险状态、绑定授权数与最近活动；不返回公钥、installation hash 或卡密密文 |
| 导出授权摘要 | `/api/v1/manage/authorizations/export/` · GET | 仅管理员；复用授权列表筛选（`status`、`software_id`、`downstream_public_id`、`device_state`、`risk_state`、`expiry_state`、`q`），最多 1000 条 CSV；导出明文设备码、IP 和业务对象 ID，不导出卡密密文、公钥、installation hash 或完整 request id；截断时带 `X-Export-Truncated` 与 `X-Export-Total` |
| 批量撤销授权 | `/api/v1/manage/authorizations/bulk-revoke/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、`authorization_ids`（非空数组，去重后最多 500，超限 400 `REVOKE_TOO_MANY`）与 2–255 字原因；逐条撤销授权实例并同步撤销对应有效卡密，当前有效绑定失效并递增 revision；已撤销的记 `items[].status=already_revoked` 且不计入 `revoked_count`；逐条独立事务，成功与失败分别汇报（`revoked_count`、`failed_count`、`failures`） |
| 批量封禁设备 | `/api/v1/manage/authorizations/bulk-block/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、`authorization_ids`（非空数组，去重后最多 500，超限 400 `BLOCK_TOO_MANY`）与 2–255 字原因；批量将目标授权当前绑定的物理设备标记为 `blocked`，相关有效绑定全部阻断失效；同批命中同一设备只封一次；无活跃绑定的授权记 `DEVICE_NOT_BOUND` 跳过，不追溯历史；逐条独立事务，成功与失败分别汇报（`blocked_count`、`failed_count`、`failures`） |
| 批量解封设备 | `/api/v1/manage/authorizations/bulk-unblock/` · POST JSON | 仅管理员；必须带 `Idempotency-Key`、`authorization_ids`（非空数组，去重后最多 500，超限 400 `UNBLOCK_TOO_MANY`）与 2–255 字原因；批量将目标授权名下被封禁的物理设备移出黑名单，旧阻断座位不复活，解封后可用新卡重新激活；无被封绑定的授权记 `DEVICE_NOT_BLOCKED` 跳过；逐条独立事务，成功与失败分别汇报（`unblocked_count`、`failed_count`、`failures`） |

历史 Django 管理写入口 `/manage/authorizations/{authorization_id}/revoke/`、`/manage/authorizations/devices/{device_id}/block/` 和 `/manage/authorizations/devices/{device_id}/unblock/` 只保留 URL 名称与权限/方法兼容性，实际写请求统一返回 HTTP 410，并提示使用同源 `/api/v1/` 管理接口。它们不再调用服务层处置动作，不创建成功幂等记录、不改变授权/设备状态，也不写成功审计；未登录、越权和错误 HTTP 方法仍按认证、权限与方法门禁返回结构化拒绝。

因此，冻结 8123 页面唯一有效的管理处置入口是上表六个 `/api/v1/` POST。只有这些入口会经过 `AuthorizationAdminOperation` 的持久化幂等合同；任何保留的旧模板或旧链接都不能被当作第二个写入通道。

六个管理 POST 的持久化幂等事实均记录在不可变 `AuthorizationAdminOperation`：唯一键为 `(actor, idempotency_key)`，保存 action、授权/设备目标、规范化请求哈希和不含凭证明文值的原始响应。同一管理员、同一键、同一动作/目标/原因直接返回首次响应；同键不同内容返回 `IDEMPOTENCY_CONFLICT`；竞争插入在 savepoint 内处理，未完成操作只返回可重试的 `ADMIN_ACTION_RETRYABLE`，失败事务不留下成功操作记录。缺少幂等键返回 `IDEMPOTENCY_REQUIRED`。

管理动作审计必须保存前后状态、前后 revision（适用时）、卡密状态变化、绑定数量、操作者、原因、时间、IP 和业务目标引用；卡密/额度码只写摘要或尾号，未知对象或业务失败也写失败审计，且不写成功审计。页面动作成功后重新读取服务端列表，失败保留服务端错误并不伪造本地状态；浏览器验收还必须覆盖页面刷新、CSRF、方法错误、缺少幂等键、同键重放、同键冲突、共享设备隔离、多设备展开和下游 403。

B5 的设备对象同时返回：`device_id`/`device_uuid`（平台内部 UUID，继续用于短期加密 `device_action_ref` 的服务端解析）、`installation_id`/`device_code`（客户端设备码）和 `device_label`（列表展示值）。列表和授权卡密详情优先使用客户端设备码；旧记录没有明文设备码时回退显示平台 UUID。管理端和下游端授权卡密列表的 `q` 也覆盖关联设备码；下游结果仍先按当前会话归属过滤。

### JSON 错误和 CSRF

API 错误统一返回：

```json
{
  "error": {
    "code": "AUTHENTICATION_FAILED",
    "message": "用户名或密码不正确。",
    "request_id": "req_123",
    "retryable": false
  }
}
```

所有改变会话或业务数据的 API 都要求 Django CSRF Cookie 和 `X-CSRFToken` 请求头。错误不得包含密码、完整邀请码或完整会话值；登录和注册失败使用摘要审计。页面必须在已有错误区域显示加载、校验、权限、限流、冲突和服务不可用状态，不以静态演示成功代替真实结果。

## 服务动作与角色边界

以下动作必须通过服务层完成，页面不能直接改表：

- `create_software`
- `set_downstream_software_access`
- `create_plan_snapshot`
- `issue_quota_card_batch`
- `credit_quota`
- `redeem_quota_card`
- `debit_quota`（PR-05 生成授权卡密时调用；不允许直接改余额或流水）
- `generate_license_batch`（仅当前登录下游为自身生成；管理员不得调用）
- `reclaim_unused_licenses`
- `recover_downstream_credits`
- `activate_license`
- `bind_device`
- `revoke_authorization`
- `block_device`
- `unblock_device`
- `register_software_profile`
- `publish_policy_version`
- `register_capability_definition`
- `publish_client_manifest`

`reclaim_unused_licenses` 只能接收当前归属且仍为 `unused` 的授权卡密；服务端从卡密记录读取软件、原始下游和保存的成本，不接受客户端传入金额/来源，也不要求当前经营范围 `ACTIVE`。它按卡密级效果键创建一次 `LICENSE_CARD_RECLAIM` 正向流水，再把卡密置为不可恢复的 `reclaimed`；零成本卡只改变状态、不写 0 金额流水。`recover_downstream_credits` 是管理员专用动作，按服务端锁定的账户余额创建 `ADMIN_ADJUSTMENT` 负向流水；两者都必须使用幂等键，不能直接写余额。

每个动作都必须产生日志、返回业务结果并支持失败回滚。

## 错误格式

```json
{
  "error": {
    "code": "INSUFFICIENT_CREDITS",
    "message": "可用额度不足，请减少数量或充值。",
    "request_id": "req_123",
    "retryable": false
  }
}
```

推荐错误码：

```text
INVALID_REQUEST
UNAUTHORIZED
FORBIDDEN
RATE_LIMITED
SOFTWARE_NOT_FOUND
LICENSE_NOT_FOUND
LICENSE_NOT_ACTIVE
LICENSE_EXPIRED
LICENSE_REVOKED
DEVICE_LIMIT_REACHED
DEVICE_PROOF_INVALID
INSUFFICIENT_CREDITS
IDEMPOTENCY_CONFLICT
VERSION_BLOCKED
RISK_BLOCKED
INTERNAL_ERROR
PROFILE_MISMATCH
ADAPTER_UNSUPPORTED
CAPABILITY_NOT_REGISTERED
POLICY_VERSION_UNSUPPORTED
```

## 幂等约定

- 同一 `Idempotency-Key` + 同一身份 + 同一动作必须返回同一业务结果。
- 同一键对应不同请求体时返回 `IDEMPOTENCY_CONFLICT`。
- 历史结果若不再匹配当前授权 revision、状态、设备风险或排他到期时间，不得重放旧的放行结果；返回 `IDEMPOTENCY_CONFLICT` 并要求新的请求标识。
- 卡密回收的幂等键按卡密资源作用域解释；服务端另使用不可变的卡密级效果键，网络重试或更换请求键都不能重复返还同一张卡。
- 服务端在事务提交后保存幂等结果，网络超时重试不能重复扣款或返还。

## 认证边界

### 管理端备份中心

- `GET /api/v1/manage/backup/` 仅管理员可调用，返回当前备份策略、脱敏 marker/proof 摘要、排队记录、可下载 `.enc` 列表，以及 `restore.site_empty` / `restore.can_restore`；不返回口令、令牌、完整 dump 或明文业务数据。策略含备份总开关 `enabled`、定时开关 `schedule_enabled`、北京时间 `schedule.full_time`、`diff_interval_hours`、`github_repository`，以及 `github_token_configured`。不返回网盘预设，也不返回 `s3_*` / `webdav_*` 字段。
- `POST /api/v1/manage/backup/` 仅管理员可调用，必须带 `Idempotency-Key`。可更新备份总开关、定时备份开关、GitHub 副本（`github_repository` 为 `owner/repo`，也可粘贴 github.com 地址）、GitHub 令牌、清理开关、1--3650 保留数量、北京时间全量时刻、1--24 小时增量间隔。本机加密包是默认去向；GitHub 是额外拷贝，排队与定时共用。开启 GitHub 时必须有仓库和令牌。空的 GitHub 令牌表示保持原值。请求体若带 `netdisk_preset`、`s3_*`、`webdav_*` 等已移除网盘字段，返回 400 `INVALID_POLICY`。成功写入审计 `backup.policy.update`。
- `POST /api/v1/manage/backup/runs/` 仅管理员可调用，必须带 `Idempotency-Key`，每小时最多 5 次。请求体 `backup_type` 为 `full` 或 `diff`。总开关关闭时返回 `BACKUP_DISABLED`。成功后创建 `pending` 排队记录并审计 `backup.run.request`；已有排队中任务时返回 `BACKUP_RUN_PENDING`，但仍会在事务提交后重写 `need-run` 叫醒主机 runner；该接口不在 Web 进程执行 pgBackRest 或把加密包拷到网盘。主机 runner 通过 `backup_policy --decide` 认领排队（总开关关掉后仍认领已排队），成功或失败后回写状态。主机每 15 分钟调用 `manage.py backup_policy --schedule`：只有 `enabled=true` 且 `schedule_enabled=true` 才创建新的定时 `PENDING`；定时全量记录本次北京时间计划槽位对应的 `scheduled_for_utc`，主机成功写入的 full stamp 必须绑定该槽位；任务跨北京时间午夜完成也不得占用下一自然日的 full 槽位。已有 `PENDING` 只保持幂等并补写 `need-run`，有未超时 `running` 则等待，超过 90 分钟的 `running` 标为失败后再排队；全量和增量同时到期时全量优先。`need-run` 只是 systemd.path 唤醒信号，数据库队列才是事实源；dispatcher 按队列中的 `full` / `diff` 选择对应 runner，数据库查询失败或未知类型时返回失败并重写 `need-run`。定时巡检只评估策略和 stamp，不执行 dump；stamp 由主机 root 写入、应用容器只读。旧 `authorization-platform-backup-full.timer` / `authorization-platform-backup-diff.timer` 禁止启用，不能用它们替代策略巡检 timer。当前单体 Docker 部署下跳过外部 pgBackRest 双仓，full 与 diff runner 均执行独立完整的数据库加密导出，每次生成的 .enc 均具备单文件独立恢复能力，不依赖历史差异链。
- `POST /api/v1/manage/backup/destinations/probe/` 仅管理员可调用，每小时最多 10 次。只测已保存的 GitHub 连通，不 dump、不 PUT `.enc`、不 push、不创建排队记录。未勾选 GitHub 返回 `DESTINATION_NOT_CONFIGURED`。响应含 `ok`、`uploaded=false` 和人话 `message`。
- `GET /api/v1/manage/backup/downloads/<filename>/` 仅管理员可调用，只能下载 `BACKUP_DOWNLOAD_DIR` 目录内的普通 `.enc` 文件；拒绝越界、软链接和其他扩展名，响应 `Cache-Control: no-store`，审计只记录文件名、大小和 SHA-256 后缀。
- `POST /api/v1/manage/backup/downloads/<filename>/delete/` 仅管理员可调用，必须带 `Idempotency-Key`，请求体 `confirmed: true`。只删除 `BACKUP_DOWNLOAD_DIR` 内普通 `.enc`；拒绝越界、软链接和其他扩展名。删前按 `list_downloads()` 计数，`N = max(1, github_retention_count)`，剩余会少于 N 则 `BACKUP_RETENTION_FLOOR` 且文件仍在。成功/拒绝都审计 `backup.download.delete`（只记文件名、大小、SHA 后缀、剩余份数）。不动 pgBackRest 仓库。
- `POST /api/v1/manage/backup/restore/inspect/` 仅管理员可调用，每小时最多 10 次。上传加密 `.enc` 和备份口令（multipart，口令不入库、不审计）。服务端按 OpenSSL AES-256-CBC PBKDF2 解密，校验 `PGDMP` 魔数，并从文件名 `authorization-platform-enc-YYYYMMDD-HHMMSS.dump.enc` 解析 UTC 时间，返回北京时间。`can_restore` 仅在站点为空且当前引擎是 PostgreSQL 时为 true。站点已有软件、套餐、卡密、授权实例、额度卡、下游、邀请码、下游墓碑、额度账户或额度流水时 `can_restore=false` 且不保留上传，HTTP 仍为 200，人话为「文件和口令对，但当前有业务数据，不能导入。」；管理员、审计（含当次核对）、备份策略/排队/暂存不算非空。SQLite 空站仍可核对并保留短期 `staging_id`，但 `can_restore=false`，确认导入返回 `RESTORE_REQUIRES_POSTGRESQL`。
- `POST /api/v1/manage/backup/restore/` 仅管理员可调用，必须带 `Idempotency-Key`，每小时最多 3 次。请求体含 `staging_id`、口令、`confirmed_backup_time`（必须与刚才显示的北京时间完全一致）。恢复过程持全局互斥排他锁，并发冲突返回 `RESTORE_IN_PROGRESS`；再次确认站点仍为空后，才允许对当前 PostgreSQL 执行带 `--single-transaction` 的 `pg_restore`；SQLite 返回 `RESTORE_REQUIRES_POSTGRESQL` 且不改数据；时间不符返回 `BACKUP_TIME_MISMATCH`；非空返回 `SITE_NOT_EMPTY`。成功审计 `backup.restore.apply` 不含口令，metadata 只记 `restore_command_finished=true` 和 `inventory_compared=false`，不能写成隔离核对已通过。
- `GET /manage/backup/download/<filename>/` 是旧 Django 模板下载入口，合同与 API 下载相同，冻结管理端页面只使用 API 路径。
- 公共版本目录查询按 IP+软件/Profile 限流并返回 `Retry-After`。窗口到期后该身份从 1 重算，不得把计数续成缓存默认超时，也不得用加大次数代替。每条发布必须有版本号；客户端用 `version` 比较，`has_update` 决定是否提示。本站 ZIP 谁都能下，不要求 `X-License-Key`，生产不得再强制卡密下载。仍按 IP 限流；生产不得把 IP 限流设为 0 或负数。网盘地址优先。不要把卡密放进网址。
- 旧 `/downstream/licenses/` 批次页、批次导出、旧揭码/回收 HTML，以及旧 `/manage/` 业务写页，默认即返回 410，正文「请从当前控制室进入。」；不依赖生产开关 `DISABLE_LEGACY_BATCH_VIEWS`。当前用户流程统一使用 `/api/v1/` 与冻结 8123 页。

- 管理端和下游后台第一版使用安全会话 Cookie、CSRF 防护和权限检查。
- 授权 A 和核心都不使用管理员 Token，不嵌入数据库密钥或平台主密钥；授权 A 也不能把自己的产品配置当作中央平台事实。
- 设备密钥用于证明设备持有私钥；设备私钥只在客户端本地保存。
- 不自定义握手协议；使用成熟密码库和标准签名算法实现设备证明及服务端响应签名。

定时 full 槽位补充：只有定时 `PENDING` 携带的 `scheduled_for_utc` 才能写入供巡检去重的计划槽位 stamp；巡检按精确计划槽位去重，修改北京时间全量时刻会产生新的槽位；没有该字段的手动或变动 full 只能记录普通完成时间，不得被当作当天定时 full，也不得覆盖已完成的计划槽位。

## 版本兼容

- 公共 API 只在 `/api/v1/` 内做向后兼容修复。
- 破坏性字段变化进入 `/api/v2/`，不能静默改变 v1 行为。
- 客户端版本必须随激活和验证请求提交，服务端根据软件策略判断最低版本。
- 新增软件默认使用 `generic-online-v1`；只有公共合同不足时才增加模块或 `/api/v2/`，旧 Profile 不因新软件接入而改变。
- Profile、能力和适配器版本必须可追溯；发布后的配置通过 `config_version` 和审计记录核对，不能静默覆盖历史快照。
- 修改授权 A 到核心的本地合同时，增加新的本地合同版本或提供明确的向后兼容实现；不能因为软件 B 接入而改变软件 A 的本地响应语义。
