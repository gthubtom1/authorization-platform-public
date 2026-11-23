# ADR-0008：每个软件通过独立授权 A 接入中央授权平台

- 状态：accepted
- 日期：2026-08-19
- 领域：客户端接入、软件隔离、授权、更新

## 背景

平台需要同时服务多个软件、多个下游和多种客户端。若核心 EXE 直接调用中央平台，新增软件就会把平台地址、授权字段、联系方式、更新逻辑和软件专属分支带进每个核心，容易造成跨软件污染、缓存串用和客户端重复改造。

用户已经确认：每个软件都有自己的“授权 A”，由授权 A 展示授权页、调用中央平台、接收下游归属配置并转给该软件核心；中央平台不直接连接核心 EXE。

## 决策

采用三层拓扑：

```text
中央授权平台
        │ HTTPS：只有对应授权 A 调用
        ▼
授权 A（每个软件独立：授权页 / Launcher / API 客户端 / 缓存 / LocalBroker）
        │ 版本化本地合同 authorization-a-core.v1
        ▼
该软件核心 EXE
```

1. 中央平台继续保存唯一授权事实：软件、Profile、卡密、授权实例、设备、下游真实归属、策略、能力、联系方式、公告和更新元数据。
2. 授权 A 是每个软件自己的客户端接入层。最终客户在 A 页面输入卡密；A 使用固定的 Profile 身份调用 `authorization.v1`，校验并缓存结果，再通过 `/local/v1` 交给核心。
3. 核心 EXE 不直连中央平台、不携带平台主密钥、不决定有效期/下游归属/撤销/更新可信性，只消费 A 的类型化本地结果。
4. 本地合同默认使用只绑定 `127.0.0.1` 的动态 loopback HTTP/JSON，使用短期本地会话令牌；产品确有必要时可使用 Windows Named Pipe，但合同语义、身份校验和 fail-closed 行为不变。
5. 平台侧 `SoftwareAdapter` 与产品侧授权 A 分开：前者只处理极少数服务端特殊语义，后者负责产品接入和本地桥接，二者都不能变成任意脚本执行器。

## 下游配置规则

- 平台根据卡密/授权实例的真实 `current_downstream_public_id` 解析购买链接、QQ、微信、公告和更新配置，绝不信任客户端提交的下游 ID。
- 公告与通用配置优先级为：`LicenseInstance.configuration_override`（非空）→ 当前真实下游的 `DownstreamSoftware` 配置（启用时）→ `SoftwareProfile` 默认值。
- 支持信息只按真实发卡下游解析，Profile支持字段不兜底；有效实例覆盖可覆盖本卡。support/公告无有效内容时返回null，隐藏对应UI。此处按ADR0011与现行API/DOMAIN合同更新原笼统层级。
- Profile与下游仅更新提交字段，省略保留本层原值，显式空串清空；clear关闭下游层。实例覆盖仍为整份替换，清除为{}。公告可回到Profile，support在无有效真实下游/实例值时为空，不能一概回退。
- A 缓存至少按 `software_id + profile_id + authorization_id + device_scope + config_version` 隔离；配置版本变化、撤销、封禁、过期或 Profile 归档时按策略刷新/失效。

## 结果

### 好处

- 新增软件主要增加自己的 A、Profile、能力和产品档案，不改旧软件核心和中央通用授权流程。
- 联系方式、公告和更新只需要平台下发一次，A 负责接收，核心只保持稳定的本地合同。
- 具体 EXE 的 UI、旧授权入口、组件和功能基线可以保存在独立产品档案，不污染公共平台文档。

### 代价和边界

- 每个软件都要维护一套 A 和本地合同测试，不能承诺“任何 EXE 自动接入”。
- 本地桥接不能阻止拥有本机控制权的人修改客户端；安全事实仍必须由中央平台决定，产品不得对“绝对防破解”作承诺。
- A 的更新、缓存和本地会话多一层故障点，因此必须有明确的过期、撤销、离线宽限和失败锁定规则。

## 验收要求

- 核心 EXE 静态和运行时不直连中央平台；只有对应 A 调用 `/api/v1/`。
- A/B 软件的 Profile、授权、缓存、联系方式、公告、更新和 LocalBroker 互相隔离。
- 空配置、`SoftwareProfile` 默认值、启用的 `DownstreamSoftware` 配置、授权实例覆盖、配置刷新、撤销失效和本机改时钟场景全部通过。
- 本地合同版本不匹配时明确阻断；平台和 A 不下发脚本、命令或任意 DLL 路径。
- 具体客户端只在用户拥有或明确获准修改的范围内接入；权限不清时停在只读盘点。

## 受影响文档

- `docs/ARCHITECTURE.md`
- `docs/SOFTWARE-ADAPTERS.md`
- `docs/CLIENT-INTEGRATION-HANDOFF.md`
- `docs/API-CONTRACT.md`
- `docs/DOMAIN-RULES.md`
- `docs/SECURITY-BASELINE.md`
- `docs/PR-PLAN.md`
- `docs/ACCEPTANCE-MATRIX.md`
