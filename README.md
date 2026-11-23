# 授权系统

多软件、多下游、额度制发卡的**中央授权平台**。管理员和下游用浏览器；最终客户不登录本平台，只在各软件自己的授权页 A 输入卡密。

本目录同时维护独立直链站、展示网站和可复制授权接入包，完整入口与部署边界看 [配套项目导航](配套项目导航.md)。授权平台两个后台属于同一网站；授权启动器已包含在接入包内。

## 现行方案（2026-11-24）

平台开发读取顺序见 [AGENTS](AGENTS.md)；接软件直接从 [00](接入说明/00-先读我.md) 开始。

给新软件用的完整文件夹在 [软件授权接入包](软件授权接入包/00-先读我.md)：复制整个文件夹到软件项目，放入后台下载的本软件 JSON，再让软件侧 AI 按包内入口适配。已含干净启动器参考源码和公开接口资料；配置准备不等于真实软件已接通。

| 项 | 现在这样 |
|---|---|
| 卡密 | 激活 / 验证 / 解绑。所有软件同一套接口，禁止 `if 软件==某某` |
| 更新 | 版本号必须是 `1.2.3`。客户端带当前版本问平台；`has_update` 为真才提示。默认打开**网盘地址**。已发布版本可改地址 |
| 本站安装包 | 可上传、谁都能下，预备以后大流量 VPS。**不是**默认更新渠道。备份**不含**安装包 |
| 备份 | 整份数据库账本打成加密 `.enc`（卡密状态、额度、流水、设备绑定、发版含网盘地址、审计）。可选再拷 GitHub。不要 R2/坚果云 |
| 密钥 | 永远本地 `部署与恢复/灾备钥匙包/` 那一套 |
| 接软件 | 后台新建（常用值预填，套餐可稍后添加）→ 下载该软件的 software-bind.v2 JSON → 把 JSON 和模板副本放到软件项目 → 软件侧 AI 按内嵌协议/指令接卡密页及核心功能门 → 实际验证。入口：接入说明/00-先读我.md；不再默认让 AI 登录后台重复登记回填。正式站接入测试只用 test_downstream_b 的 test_only/0 成本卡；不改 test_downstream_a/test_downstream_b 密码、不用真下游。 |
| 测试站 | `https://retired.example.com`（测试服务器已过期，不再可用，历史记录） |

不要把旧审查、pgBackRest 双仓、持卡下载、跨域 `*` 当成还欠的活。

三个正式站均在反代美国 VPS `192.0.2.10`：授权平台 `https://auth.example.com`、独立直链站 `https://files.example.com`、展示网站 `https://showcase.example.com`。授权管理员入口为 `/manage-login.html`，下游入口为 `/downstream-login.html`；两个独立站后台为各自的 `/manage/login/`。旧 `https://legacy.example.com` 保留为同一新授权账本的兼容反代，不再运行第二套业务应用。服务器身份与回退边界见 [`部署与恢复/09-两台VPS.md`](部署与恢复/09-两台VPS.md)。香港测试站已过期，禁止连接。

## 公共授权入口（只给授权 A 调用）

五个授权POST（激活、验证、解绑、票据签发、票据核销）和更新查询、包下载共七条客户端路由，统一查 [接口字段索引](软件授权接入包/平台公开资料/接口字段索引.json)；方法、身份、字段与响应以 [API合同](docs/API-CONTRACT.md) 为准。核心EXE只调用本软件授权A的本机接口。

## 服务器安装（一台新 Ubuntu，只这一条命令）

人准备：代码放到 `/opt/authorization-platform`，把 `部署与恢复/灾备钥匙包/` 带上（或已经解开的五个 `deploy/*.env`），域名 A 记录指到这台机，安全组 22/80/443。然后以 root：

```bash
AUTH_DOMAIN=你的域名 bash /opt/authorization-platform/deploy/install-site.sh
```

结尾必须出现 `VERIFY_OK`。以后改代码再部署，还是这一条。说明只认 [`部署与恢复/08-完整部署SOP.md`](部署与恢复/08-完整部署SOP.md)。

不要 `seed_demo`，不要打开备份日历 timer，不要让脚本代开备份总开关。现有授权账号口令按钥匙包12总账查取，服务器初装口令文件不代表现行口令；两个独立站凭据见钥匙包13索引，不进源码或接入包。

## 本地开发

1. [`docs/STATUS.md`](docs/STATUS.md)
2. [`docs/INDEX.md`](docs/INDEX.md)
3. 接某个软件的授权页 A：[`接入说明/00-先读我.md`](接入说明/00-先读我.md)。先做软件项目本地验证，再用既有 `test_downstream_b` 的 `test_only` / 0 成本卡受控联调。旧测试站不可用，`test_downstream_a` 仅历史；不准用真下游发卡或重置测试账号口令。软件侧 AI 无需平台登录凭据。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1
```

浏览器打开：

- 管理端：`http://127.0.0.1:8123/manage-login.html`
- 下游端：`http://127.0.0.1:8123/downstream-login.html`

根路径 `/` 必须是 404。`127.0.0.1:8000` 只给内部诊断，不是产品入口。

演示账号用环境变量创建，不要把密码写进仓库：

```powershell
$env:DEMO_ADMIN_PASSWORD = "至少 10 位的本地密码"
$env:DEMO_DOWNSTREAM_PASSWORD = "至少 10 位的本地密码"
& .\.venv\Scripts\python.exe .\manage.py seed_demo
```

运行测试：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1
```
