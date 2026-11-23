# ADR-0018 一次性启动票据（launch ticket）

状态：accepted（实现与专项测试已完成，代码随现行平台部署；真实客户端签发/核销不由本次平台导出检查证明）

## 背景

覆盖层主程序只肯被带合法签名信封的启动器拉起，但签名私钥随包发给客户，
拷走文件的人可以自解包提私钥、自写签名器绕过门禁。客户端不再长期持有签名
能力，改为每次启动向平台换一张短期票据，覆盖层只钉平台公钥（公开无妨）。

## 决定

1. 纯新增两个公开接口，不动现有三条链路：
   `POST /api/v1/public/licenses/launch-ticket`（签发）与
   `POST /api/v1/public/licenses/launch-ticket/consume`（核销）。
   现有 activate/verify/deactivate 的请求、响应、签名口径一字不动。
2. 签发前置与 verify 同判定顺序：profile 归属 → 设备证明
   （action 固定 `launch-ticket`，沿用现有 proof 消息字段结构）→ 设备绑定
   有效 → 风险 → 时钟回退（只拒签，不另行标记）→ 终端状态（仅 active/grace
   可签；过期/撤销/阻断逐条拒签）。硬失败原样返回，429 只替换本会成功的签发。
3. 签名复用平台私钥与 key_id（现网 `platform-prod-a4428b257c49`，测试走配置值，
   不硬编码）。覆盖范围 = 整个响应体去掉 `integrity.signature` 这一个字段，
   其余（含 integrity 内其它字段）全部参与 JCS 规范化；禁止删整个 integrity
   对象再签（客户端已验证那是另一种字节流）。
4. 票据 `audience` 按规则 `{software_id}-core` 派生，不按软件名分支；
   例如 `cs2-pro-vision` 派生 `cs2-pro-vision-core`。TTL 跟现行 ACTIVE 策略
   （默认 180 秒，策略可在 30–3600 秒内配置，建议 120–600）。
5. 核销可选但已实现：同形设备证明（action 固定 `ticket-consume`，防跨接口重放）、
   同设备、未过期、未核销过才成功；`ticket_id` 保留供以后扩展。
6. 策略维度开关：`launch_ticket_enabled=false` 的 Profile 一律拒签
   （`LAUNCH_TICKET_DISABLED`），已售卡跟现行策略（与心跳间隔热读同一口径）。

## 错误码对照（相对 CS2 需求文档的差异）

CS2 文档列的 `DEVICE_MISMATCH` 在本平台词汇里叫 `DEVICE_SCOPE_MISMATCH`，
语义相同；其余 `AUTH_INVALID` 保留给 A-core 本地信封，平台侧用
`LICENSE_*` / `DEVICE_*` / `TICKET_*` 系列。新票据码只有三个：
`TICKET_NOT_FOUND`（404）、`TICKET_ALREADY_CONSUMED`（409）、
`TICKET_EXPIRED`（410），以及开关码 `LAUNCH_TICKET_DISABLED`（403）。

## 后果

- 启动器私钥不再随包分发；覆盖层验签对象从启动器私钥换成平台公钥。
- 票据行保留作审计，不物理删除；180 秒自然过期，无需清理任务。
- 限流桶与 verify 分开（`public-license-launch-ticket` /
  `public-license-ticket-consume`），观测计数同样只记数不改返回。
