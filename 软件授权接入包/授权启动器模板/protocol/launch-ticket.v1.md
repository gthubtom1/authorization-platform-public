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
