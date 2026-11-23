# 文档地图

平台开发按 [AGENTS](../AGENTS.md) 读取 [STATUS](STATUS.md)、[PROJECT](PROJECT.md)、[FEATURES](FEATURES.md)。索引负责导航，不再用“只看前言、忽略旧正文”解释文档冲突。

## 按任务进入

- 负责人操作：[老板入口](../00-老板先看这个.md)。
- 新软件接入：[00](../接入说明/00-先读我.md) → 后台下载本软件JSON → 软件项目模板副本 → 实际验收。
- 软件AI接入指令：[09](../接入说明/09-给软件项目AI的接入指令.md)，已随JSON交付；技术责任查 [CLIENT-INTEGRATION-HANDOFF](CLIENT-INTEGRATION-HANDOFF.md)。
- 本机运行与测试：[RUNBOOK](RUNBOOK.md)。
- 部署/恢复：[部署入口](../部署与恢复/00-先读我.md)，实际步骤只有 [08](../部署与恢复/08-完整部署SOP.md)。

## 当前合同与证据

- [架构](ARCHITECTURE.md)、[领域规则](DOMAIN-RULES.md)、[API](API-CONTRACT.md)、[安全基线](SECURITY-BASELINE.md)。
- [Profile/能力/适配器](SOFTWARE-ADAPTERS.md)、[公开协议](../protocol/)、[UI设计](UI-DESIGN-SYSTEM.md)、[页面合同](UI-PREVIEW.md)、[UI参考](UI-REFERENCE.md)。
- [验收矩阵](ACCEPTANCE-MATRIX.md)说明场景与证据层，[STATUS](STATUS.md)集中记录现行验证、风险与下一步。
- [AI角色](AI-ROLES.md)、[外部研究](COMPETITOR-RESEARCH.md)、[路线图](ROADMAP.md)。

## 决策与历史

[ADR索引](adr/INDEX.md)保留有效决定和明确取代关系；[产品裁决](PR-DECISIONS.md)、[切片映射](PR-PLAN.md)用于追溯，不能自动恢复旧任务。[N7锁序复核](N7-lock-order-review.md)保留已证伪结论。已完成事故流水、重复旧计划和手填摘要已从当前树清理，历史在Git中，不作为现行操作说明。
