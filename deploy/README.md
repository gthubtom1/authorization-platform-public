# 部署组件说明

实际装机、更新和主机接线唯一入口是 [部署与恢复/08](../部署与恢复/08-完整部署SOP.md)，由08统一调用 `deploy/install-site.sh`，不按本目录组件名手工拼装。

- Dockerfile运行Django/Gunicorn，容器内监听0.0.0.0:8000，宿主仅映射127.0.0.1:18002，由正式Nginx反代。
- 冻结页面在主机docs/ui-preview，API在应用镜像；安装器同步重建应用和接线，不能只更新一边。
- Compose及.example是受审配置结构，不是新密钥生成模板。新目标注入既有一套env/平台密钥，保留现有数据与证书。
- 当前备份runner导出完整加密.enc，默认本机，可选GitHub；队列由页面策略控制，旧full/diff日历timer禁止启用。
- 旧proof/pgBackRest配置检查仍是启动声明兼容门，不能据此声称真实双仓/WAL/PITR已经部署，也不能为通过文档检查放宽安全设置。

组件技术边界见 [ARCHITECTURE](../docs/ARCHITECTURE.md)；实际部署、恢复和凭据材料由根部署目录维护。证明缺口与风险见STATUS，不再在这里复制另一套运维步骤。
