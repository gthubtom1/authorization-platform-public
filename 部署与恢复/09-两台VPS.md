# 现行服务器与退役身份

本页区分两台现行VPS与退役身份；部署前仍须只读核对现状和明确目标域名。

| 状态 | 域名 | IP | 用途 |
|---|---|---|---|
| 三站正式，已部署并迁入原业务 | auth.example.com、files.example.com、showcase.example.com | 192.0.2.10 | 授权平台、直链站、展示站；现有storage.example.com与news.example.com及其服务保留 |
| 旧授权兼容入口与迁移回退材料 | https://legacy.example.com | 192.0.2.11 | Nginx经验证HTTPS反代到新平台，保留客户端原IP；旧应用/对象服务停止，平台自动任务停用，原数据库与密钥保留，不形成双写 |
| 测试服务器已过期，禁止连接 | retired.example.com | 192.0.2.12 | 仅用于辨认旧记录，不提供SSH/发卡/恢复步骤 |

正式站代码在 `/opt/authorization-platform`，现行归档部署不含.git，Compose项目为 `authorization-platform-candidate`，应用宿主映射127.0.0.1:18002。实际源码及部署回执见 [上线记录](09-正式站上线与回退手册.md)。

直链站在 `/opt/direct-link-site`，systemd服务只监听127.0.0.1:18081；展示站在 `/opt/software-showcase`，Compose仅发布127.0.0.1:18082。三个域名分别使用有效证书，由宿主Nginx共用80/443按域名分流。网站后台登录与私有资料索引见钥匙包README、12、13、15；不要把含两个i的既有pan/toutiao域名改成新站的一个i。

维护者先读权威钥匙包README确认当前SSH与登录材料；SSH使用严格主机校验与现有ai_vps_ed25519密钥，实际位置按权威索引确认，不能用退役机器清单覆盖本表。平台管理员登录为 `/manage-login.html`，下游为 `/downstream-login.html`。

授权接入测试只用已有test_downstream_b的test_only/0成本卡，不重置test_downstream_a/test_downstream_b口令，不操作真下游。软件侧AI无需SSH或后台凭据。更新/换机步骤只看 [08](08-完整部署SOP.md)。
