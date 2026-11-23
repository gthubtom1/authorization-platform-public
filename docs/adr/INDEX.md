# ADR 索引

| ADR | 标题 | 状态 |
|---|---|---|
| [0001](0001-monolith-online-first.md) | 单体应用和在线优先授权 | accepted |
| [0002](0002-ledger-and-license-objects.md) | 额度账本与授权对象分离 | accepted |
| [0003](0003-registry-ledger-ui.md) | Registry / Ledger Control Room UI | accepted |
| [0004](0004-software-adapter-isolation.md) | 版本化软件 Profile 与适配器隔离 | accepted |
| [0005](0005-zero-base-acceptance-and-operations.md) | 零基础操作、真实验收与凭证显示规则 | accepted |
| [0006](0006-server-time-and-short-test-cards.md) | 服务端可信时间、北京时间展示与短时测试卡 | accepted |
| [0007](0007-django-user-and-downstream-profile.md) | Django User 凭据与独立 DownstreamProfile | accepted |
| [0008](0008-product-authorization-adapter-boundary.md) | 每个软件通过独立授权 A 接入中央授权平台 | accepted |
| [0009](0009-online-authorization-instance-and-device-proof.md) | 在线授权实例、设备证明与产品无关响应 | accepted |
| [0010](0010-product-freeze-2026-08-20.md) | 2026-08-20 产品一次冻结（不代发、完整码可不记谁看过、过期邀请码不恢复；回收本批已被 ADR-0011 取代） | accepted |
| [0011](0011-single-card-archive-revenue-and-links.md) | 单卡列表、归档清理、激活收入与购买链接（批次从界面移除；D-017-02 由筛选多选回收取代） | accepted |
| [0012](0012-static-page-entry-map-and-domain-routing.md) | 8123 静态页面入口地图与未来域名后缀路由 | accepted |
| [0013](0013-frozen-8123-frontend-and-phased-backend.md) | 冻结 8123 前端并按阶段适配后端 | accepted |
| [0014](0014-backup-recovery-governance.md) | 备份证明与隔离恢复治理 | 部分取代（双仓/PITR候选被现行Docker dump方案取代，恢复原则保留） |
| [0015](0015-single-platform-key-set.md) | 全生命周期只使用一套平台密钥 | accepted |
| [0016](0016-license-renewal-and-release-housekeeping.md) | 卡密续期、版本归档与就地改版本号（取代「续费=发新卡」和禁止续期入口的旧门禁） | accepted |
| [0017](0017-anti-abuse-hardening-and-batch-operations.md) | 防脱机盗开、换机防套利、时钟容差、同机公钥自愈与批量管理 | accepted |
| [0018](0018-launch-ticket.md) | 一次性启动票据：短期单设备绑定、可核销、平台公钥验签（现有三链路不动） | accepted |
