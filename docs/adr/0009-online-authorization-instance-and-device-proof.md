# ADR-0009：在线授权实例、设备证明与产品无关响应

- 状态：accepted
- 日期：2026-08-19
- 领域：授权、设备、安全、跨目录合同

## 决定

1. 一张 `LicenseCard` 只能创建一个 `LicenseInstance`；实例保存卡密生成时的 Software/Profile/PlanSnapshot/PolicyVersion 关系、完整客户端身份、有效期、状态、`authorization_revision`、`config_version` 和服务端最后可信时间。
2. `Device` 按 `software + profile + installation_id` 的服务端 HMAC 哈希隔离。`DeviceKey` 只保存 Ed25519 公钥和 key ID，不保存客户端私钥。`DeviceBinding` 追加保存绑定、解绑、阻断和过期历史，不能覆盖或删除。
3. 激活、验证、解绑都必须提交完整 Profile 七元身份、客户端版本、设备公钥、设备证明和 nonce。证明输入使用固定域分隔符，并绑定动作、request ID、授权 ID（如有）、软件/Profile 身份、安装 ID、公钥和 nonce。nonce 只保存哈希并一次性消费；相同幂等请求返回原结果，不同请求重复 nonce 返回 `REPLAY_DETECTED`。
4. 平台公共入口固定为产品无关的：
   - `POST /api/v1/public/licenses/activate`
   - `POST /api/v1/public/licenses/verify`
   - `POST /api/v1/public/licenses/deactivate`
5. 中央平台签发完整 `authorization.v1`，使用精确小写 `ed25519` + `JCS-RFC8785`。签名输入是删除 `integrity.signature` 后的完整响应。A 只验证中央事实，然后用自己的受保护私钥签发 `authorization-a-core.v1`；核心只信任 A 公钥，不持有平台密钥。平台不实现 A 的 LocalBroker 或核心 IPC。
6. 服务端以 UTC epoch seconds 判定到期，`server_time >= expires_at` 即失效。服务端或 A 发现已接受时间回退时返回 `TIME_ROLLBACK_DETECTED` 并 fail closed；北京时间只用于运营展示。
7. 事务锁顺序固定为“卡密 → 授权实例 → 设备 → 设备密钥 → 当前绑定”。设备上限检查在授权实例行锁内执行；SQLite 只作顺序行为测试，PostgreSQL 行锁并发是验收前置。

## JCS 与密钥边界

PR-07 复用已锁定的 `cryptography==50.0.0`，不新增生产依赖。平台内置的合同编码器只接受授权响应实际使用的 I-JSON 值：字符串、布尔、null、数组、对象和不超过 IEEE-754 安全范围的整数；浮点数和超范围整数 fail closed。生产签名私钥必须通过环境或受管密钥服务注入；本地缺省回退只用于测试，不能在生产配置中启用。

若后续能力需要任意 JSON 数字或跨语言 RFC 向量，必须先评估带明确许可证的 RFC 8785 实现并经过依赖审批，不能把 `json.dumps` 的未限定行为默认为通用 JCS。

## 代价和后续

- 当前 nonce 是客户端生成、由服务端一次性消费并由设备私钥证明的请求随机值；服务端挑战/预签发需要新增字段和独立兼容评审，不能在 A/core 未确认时偷偷改变 v1 请求。
- 撤销管理动作、共享限流、持久化 A 缓存、密钥轮换重叠窗口、真实 VPS、OS IPC 和 PostgreSQL 并发证据继续分别属于 PR-08 至 PR-12。
- 本决定保持中央平台通用；新增软件只登记自己的 Software/Profile/Policy/Capability 和 A，不增加产品名分支。
