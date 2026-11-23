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

PR-05/PR-07 的中央合同夹具位于 `平台公开资料/fixtures/authorization_v1/`；A→核心的产品无关本地合同夹具位于 `平台公开资料/fixtures/authorization_a_core_v1/`，Schema 位于 `protocol/`。两者都是联调输入，平台不把某个产品路由写进合同：

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


### 授权 A 到核心 EXE 的本地合同

默认接口为 `http://127.0.0.1:<dynamic-port>/local/v1/`，端口由授权 A 每次启动分配，不能监听公网地址。授权 A 应向核心提供以下最小动作：

| 动作 | 方向 | 结果 |
|---|---|---|
| `GET /health` | 核心 → A | 返回 `local_contract_version`、软件/Profile 身份和 A 是否已就绪 |
| `POST /session/open` | 核心 → A | 以当前客户端版本和随机值建立本地会话；不提交平台卡密或下游 ID |
| `GET /session/state` | 核心 → A | 返回 `active/expired/revoked/offline/blocked`、服务端时间、到期时间、能力、`support`、公告和更新摘要 |
| `POST /session/refresh` | 核心 → A | 请求 A 按缓存和平台策略重新验证；不能延长服务端已结束的授权 |
| `POST /session/close` | 核心 → A | 结束本地会话并清理临时连接信息，不删除平台历史 |

本地成功响应至少包含：`local_contract_version`、`software_id`、`profile_id`、`client_id`、`target`、`arch`、`channel`、`authorization_id`、`authorization_revision`、`device_scope`、`decision`/`state_code`、`server_time`、`expires_at`、`cache_until`、`next_verify_at`、`grace_until`、`capabilities`、`entitlements`、模块数据、`config_version` 和强制 `integrity`。本地 `integrity` 的 `algorithm` 固定为小写 `ed25519`，`origin` 固定为 `authorization-a`，`audience` 固定为 `authorization-a-core`，`canonicalization` 固定为 `JCS-RFC8785`；`signature` 覆盖删除自身后的完整本地 response。其中 `server_time`/`expires_at`/`cache_until`/`next_verify_at`/`grace_until` 沿用有符号 64 位 Unix epoch seconds，但 A-core v1 业务门禁要求所有授权时间为非负整数；`support`、公告和更新缺省时必须是空值而不是伪造默认内容。Schema 和通用夹具分别见 `protocol/authorization-a-core.v1.schema.json` 与 `平台公开资料/fixtures/authorization_a_core_v1/`。

本地合同只传递声明式状态和元数据，不传递脚本、命令、任意 DLL 路径或“执行这段代码”的字段。核心收到格式错误、身份不匹配、签名无效、会话失效或 A 不可用时，必须显示可理解的错误并锁定受保护功能。


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
