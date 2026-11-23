# 备份runner组件

这是实现说明，安装与更新只按 [部署与恢复/08](../../部署与恢复/08-完整部署SOP.md)，旧 `authorization-platform-backup-full.timer`、`authorization-platform-backup-diff.timer` 禁止 enable；安装器使用的是 `.path` 门铃。

## 当前运行链

管理端总开关/定时开关和计划 → 数据库PENDING队列 → 每15分钟策略巡检或变动信号 → authorization-platform-backup-full.path监听need-run → dispatcher → full/diff runner → 加密.enc → 可选GitHub副本。

当前Docker部署中full/diff都生成独立完整数据库导出，不依赖差异链，不提供PITR。dump口令来自既有权威材料；host-secrets保持主机root专用，keys目录采用安装器定义的root:10001及容器可写权限，两者不能混用。安装器不改页面总开关/定时开关，不生成第二套平台密钥。

runner校验加密导出完整性后才轮替包；本机导出结果与严格proof marker分别记录。dump_only可以记录运行成功并提示证明未齐；没有双仓/WAL/对象/恢复证据不得伪造严格proof。旧环境启动声明校验仍存在，不等于实际启用了这些设施。

GitHub推送后会自动调用历史折叠组件；页面保留值与collapse KEEP的现行差异、证据要求和维护边界只写在 [GitHub备份说明](../../部署与恢复/10-GitHub备份库.md)，这里不复制手工强推/删分支/gc步骤。

加密包不包含原密钥、网站证书或安装包对象。实际恢复使用根 [03](../../部署与恢复/03-新VPS怎么装怎么导备份.md) 的前置与隔离业务核对，不把success、文件头或可列目录当成完成恢复。定时器、dispatcher、proof工具存在也不等于长期运维或告警已实机验收。
