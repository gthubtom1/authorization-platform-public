# 完整部署 SOP（只准按这份）

给负责人和后续 AI。**装机、更新代码、接线、核对，全部只按这份。不准另发明一套临时脚本。**

这套授权平台要长期自己跑，不只是「页面能打开」。  
仓库里的程序、Nginx、证书续期、第一位管理员、备份策略巡检、备份门铃、小时清理、日志滚动，必须同一次部署接上。只 `docker compose up` **不算部署完成**。

当前正式平台和以后新目标均走这份。密钥永远一套（`05-密钥永远一套.md`）。两台机器见 `09-两台VPS.md`。未确认不要在正式机跑安装脚本。同机其它容器（例如 sub2api、kiro）不准动。

## 这份和旁边文件的关系（防止以后的 AI 走岔）

| 要做的事 | 读哪份 | 实际动手 |
|---|---|---|
| 装机、更新代码、接线、核对 | **就读这份** | `AUTH_DOMAIN=确认过的域名 bash /opt/authorization-platform/deploy/install-site.sh` |
| 注入哪一套密钥 | `05-密钥永远一套.md` | 把钥匙包 env 放进 `deploy/`，禁止 `replace-with` |
| DNS、Let's Encrypt | `02-域名证书和端口转发.md` | 脚本缺证书时会自己签发；不要手抄 Nginx |
| 空库导入 `.enc` | `03-新VPS怎么装怎么导备份.md` | 页面导入或手工 `pg_restore` 17；在 `VERIFY_OK` 之后 |
| compose / Dockerfile 长什么样 | `deploy/` | 不是步骤。不要按 `deploy/README.md`、`deploy/backup/README.md` 去 enable 旧日历 timer 或装 pgBackRest |

`install-site.sh` 用 `deploy/nginx/authorization-platform.conf.example`，按 `AUTH_DOMAIN` 填域名。不要自己 `cp` 进 `sites-enabled` 就当部署完成。

## 跑起来一共有哪些块（缺一块就不算装完）

| 块 | 干什么 | 谁来开 |
|---|---|---|
| 宿主机工具 | `docker`、`docker compose`、`nginx`、`certbot`、`openssl`、`python3`、`git`、`curl` | 第一次装系统包。以后开备份 GitHub 拷贝需要 `git` |
| Docker 三件套 | 应用、PostgreSQL 17、MinIO | `compose up`，`restart: unless-stopped`，开机靠 `docker.service` |
| 冻结页 | 管理端 / 下游端 HTML | Nginx 读 **主机** `/opt/authorization-platform/docs/ui-preview` |
| 应用 API | 登录、发卡、activate/verify、网页导入备份 | Docker **镜像** 里的 gunicorn，只绑 `127.0.0.1:18002` |
| Nginx + 证书 | HTTPS、根路径 404、反代 `/api/` `/healthz/`、上传 `.enc` | `nginx.service` + `certbot.timer`。必须有 `client_max_body_size 120m` 和 `proxy_read_timeout 600s` |
| 第一位管理员 | 能进管理端 | `install-site.sh` 在空库创建；口令只写 root 600 文件。已有管理员不改口令 |
| 备份策略巡检 | 每 15 分钟读取页面策略，只创建到期的 `PENDING` | `authorization-platform-backup-schedule.timer` → `manage.py backup_policy --schedule`。**总开关和定时开关默认关**，人在页面打开 |
| 备份门铃 | 账本变动或定时任务排队后叫醒 runner | `authorization-platform-backup-full.path` 盯 `/var/lib/authorization-platform-backup/queue/need-run`；dispatcher 按 `full` / `diff` 分流 |
| dump 口令 | 以后打开总开关才能加密 | 从 `/opt/authorization-platform-backup-keys/github-dump-pass.txt` 拷到主机专用的 `BACKUP_ROOT/host-secrets/github-dump-pass.txt`；目录 `700`、文件 `root:root 600`，应用容器不可写 |
| 备份库历史折叠 | GitHub 备份库只留最新 3 份、历史折成单提交，避免仓库一直涨（只删工作树里的旧 `.enc` 不会让仓库变小） | `backup_runner.sh` 推送成功后**自动**调用 `deploy/backup/github_collapse.sh`，不要人手工跑。清理哪个库跟着页面填的 `owner/repo` 走。判据、巡检命令和两个"像故障其实正常"的事实见 `10-GitHub备份库.md` |
| 小时维护 | `clearsessions` | `authorization-platform-maintenance.timer` |
| 日志滚动 | Nginx 本站日志、维护日志、备份 runner 日志 | `/etc/logrotate.d/authorization-platform` |

页面静态文件和 API 不在同一个地方：换代码必须 **同时覆盖主机目录并 `compose build`**。只改其中一边，就会出现「页面新、接口旧」或反过来。  
门铃是主机 systemd 看的文件；应用容器必须能写同一个目录（`BACKUP_ROOT` / `BACKUP_DOWNLOAD_DIR` 指向 `/var/lib/authorization-platform-backup`）。

## 人在页面上才做的（安装脚本不准代劳）

总开关默认关。真正开始用备份时：

1. 打开 `manage-login.html` → 备份
2. 打开「备份总开关」
3. 若要拷到 GitHub：勾选、填 `owner/repo` 和令牌
4. 保存
5. 仅空站首次生成的初始管理员口令，由负责人首次登录后设置；已有平台更新沿用现有口令，不重置账号

登记软件、建下游、发卡，也只在页面做。不要找 AI 改 systemd。

这套 Docker 部署 **没有 pgBackRest**。备份页打开后，实际留下的是本机加密 `.enc`（可选再拷 GitHub）。不要把「证明文件 / 双仓 WAL」当成已经闭环。

## 定死的名字

| 项 | 值 |
|---|---|
| 代码目录 | `/opt/authorization-platform` |
| Compose 项目 | `authorization-platform-candidate` |
| 应用端口 | `127.0.0.1:18002`（必须和 Nginx `proxy_pass` 一致） |
| 备份目录 | `/var/lib/authorization-platform-backup` |
| 主机接线 | `AUTH_DOMAIN=auth.example.com bash /opt/authorization-platform/deploy/install-site.sh`（其它目标必须改成已确认域名） |
| 只核对 | `AUTH_DOMAIN=auth.example.com VERIFY_ONLY=1 bash /opt/authorization-platform/deploy/install-site.sh` |
| 管理员口令文件 | `/opt/authorization-platform-admin-password.txt`（仅空库第一次创建时写入） |
| 退役测试站 | 已不可用，仅在服务器表保留识别，不连接 |
| 正式站 | `auth.example.com` → `192.0.2.10`；旧legacy.example.com在原192.0.2.11只做兼容反代，原业务应用与自动任务停用 |
| 策略巡检 timer | `authorization-platform-backup-schedule.timer`，每 15 分钟，必须 enable |
| 应用守卫 timer | `authorization-platform-app-guard.timer`，每 90 秒对账一次应用容器 running 状态，死了自动 `up -d` 拉起，必须 enable；计划内停机维护前先 `systemctl stop` 它，完事再 `start` 回来（停机窗口内 `VERIFY_ONLY=1` 报红属预期，恢复后重跑全绿才算完） |
| 旧备份日历 timer | `authorization-platform-backup-full.timer` / `authorization-platform-backup-diff.timer`，**禁止 enable** |

`install-site.sh` 可重复跑。更新代码后也必须再跑，避免门铃还指着旧目录。重复跑不准打开或关闭备份总开关或定时开关；脚本会先停策略巡检 service/timer，完成应用更新和策略对齐后再启用策略巡检 timer。

Windows 拷过去的 `.sh` 可能带 CRLF，脚本每次会自己 `sed` 掉并 `chmod 700`。**不准只拷几个文件。** 任意经确认的目标都使用完整审定代码树覆盖 `/opt/authorization-platform`（不要覆盖 `deploy/*.env`、MinIO 证书、钥匙包），然后再跑这一条。页面在主机 `docs/ui-preview`，接口在 Docker 镜像里；两边不是同一份，使用上就不是镜像。

盖「今天已备份」戳记必须由**主机 root 的 python3** 写到 `backup-stamps/`；目录由 root 拥有、组 `10001` 可读（750），文件由 root 写入、组 `10001` 可读（640），应用容器不能写 stamp。`VERIFY_OK` 必须出现 `stamp-write: host`、`stamp-dir: root-write-app-read` 和 `backup-scripts: 700`。缺这些行，以后一点备份又会页面显示失败、加密文件其实已经有了。

## 第一次装（空库）

未得到负责人确认不要执行。别人、朋友、另一台自己的机器，都是这一条路。不要再找人「补装 Nginx / 补装门铃 / 再生成密钥」。

人只准备这三样：

1. Ubuntu 22.04。安全组 22/80/443。域名 A 记录已经指到这台机。系统防火墙可以关。
2. 代码放到 **`/opt/authorization-platform`**（完整树，不要带日期的新目录）。
3. 钥匙：先读钥匙包README，使用其索引确认有效的五个env放到 `deploy/`；2026-11-17现行明文快照在私有15目录，8月旧enc不能解，不依赖安装器的旧包自动解密。禁止 `replace-with`，脚本**不会**新生成卡密密钥。`AUTH_DOMAIN` 必须出现在 `production.env` 的 `ALLOWED_HOSTS` / `CSRF_TRUSTED_ORIGINS` 里。dump口令按现行索引取，保留原始换行。2026-11-17 MinIO公开仓库已无法拉取，钥匙包14目录保留原正式站导出的两镜像及校验值；全新主机先核验并导入该归档，再运行同一安装器，不能用未知镜像或新密钥替代。

然后只跑这一条（目标域名必须与DNS及受控配置一致）：

```bash
AUTH_DOMAIN=auth.example.com bash /opt/authorization-platform/deploy/install-site.sh
```

上面示例为当前正式域名；新主机改为经确认的目标域名。跑之前必须先把经确认的目标域名写进 `production.env` 的 `ALLOWED_HOSTS` / `CSRF_TRUSTED_ORIGINS`。未确认不要在年包机上执行。

这一条会自己：安装缺的系统包、缺 MinIO 内部证书就生成（不是卡密密钥）、缺网站证书就 certbot 签发、`compose up -d --build`、接 Nginx（含上传体积和超时）、migrate、`createcachetable`、没有管理员就创建、接 15 分钟备份策略巡检、接备份门铃 dispatcher、开小时维护、装应用守卫 timer、装 logrotate、核对。

**不准**在这一步打开备份总开关，**不准** `seed_demo`。  
结尾必须是 `VERIFY_OK`。没有这行，部署没完成。

管理员口令只在 `/opt/authorization-platform-admin-password.txt`（若本机已有管理员则不会改口令、也不会重写这个文件）。不要把口令写进仓库或聊天。仅空站首次生成的初始口令由负责人首次登录后设置；普通更新不重置或改现有口令。

同机其它容器（例如 sub2api、kiro）不准动。未确认不要碰年包正式机。

## 以后更新代码 / 修 bug 后再部署

不清库、不换密钥、不改备份总开关或定时开关、不动同机其它容器。

1. 用新代码覆盖 `/opt/authorization-platform`。
2. **把属主改回 root**：`chown -R root:root /opt/authorization-platform`。
   覆盖方式不同，属主结果也不同：用 tar/scp 归档覆盖会把**归档里记的属主**一起带过来，
   站上就会出现 `UNKNOWN:UNKNOWN`（Windows 上打的 tar 尤其容易这样）。后果不是"看起来不对"，
   而是 `git` 直接报 `detected dubious ownership` 罢工 → 装机脚本读不到
   `BACKUP_CANDIDATE_COMMIT`，备份的版本绑定和事后追责都断掉。
   源码Git checkout可读取HEAD；现行正式站为归档部署，没有.git，应仅将审定源码提交写入 `deploy/production.env` 的 `BACKUP_CANDIDATE_COMMIT` 元数据，安装器用该已有后备路径。制作完整代码归档时排除.git、钥匙包、真实env/证书及本地临时文件；覆盖前保留原代码与经校验的正式加密备份，覆盖后按文件哈希清单及版本元数据核对。不能为了让git命令成功而复制含敏感历史的.git。
3. **只再跑同一条** `AUTH_DOMAIN=auth.example.com bash /opt/authorization-platform/deploy/install-site.sh`（其它目标显式换成已确认域名；脚本会build并重新接线，缺AUTH_DOMAIN在修改主机前拒绝，不再默认退役域名）。
4. 必须再看到 `VERIFY_OK`。

不要另开「优化文档」文件夹。不要只覆盖主机文件却指望接口变新——脚本会 build。上次漏门铃，就是因为只 `compose up`、没跑这一条。

## 怎样才算部署完成

`VERIFY_OK` 已经查这些。人工再确认一遍也可以：

- `https://域名/healthz/` = 200
- `https://域名/` = 404，且没有 `manage-login`
- `https://域名/manage-login.html` = 200
- `GET /api/v1/session/` = 200 JSON
- `GET /api/v1/public/licenses/activate` = 405 JSON（说明公共授权接口到了应用，不是静态 404）
- 应用只听 `127.0.0.1:18002`
- 应用容器 `pg_restore --version` 是 17
- `docker` `nginx` `certbot.timer` 开机自启且当前是 active
- 备份策略巡检 **timer** 为 enabled+active；备份 **path** 为 enabled+active；旧 full/diff 备份日历 timer 为 disabled
- 备份总开关仍是关的（除非负责人已在页面打开）
- 有超级管理员；`django_cache` 表存在
- `github-dump-pass.txt` 已在 `BACKUP_ROOT/host-secrets/`（以后打开总开关才能加密 dump；目录 `700`、文件 `root:root 600`）
- Nginx 已限制 `client_max_body_size 120m`（否则管理端上传 `.enc` 会被默认 1MB 挡住）
- 小时维护 timer、logrotate 已装
- root crontab 里没有旧的 `backup-full.sh` / `backup-diff.sh`
- `stamp-write: host`（盖戳记不走容器）
- `stamp-dir: root-write-app-read`（目录 750、root:10001，文件 640）
- `keys-dir: root-write-app-rw`（`BACKUP_ROOT/keys` 属组 `root:10001`、目录 `770`、文件 `660`，应用写入凭据前执行安全 unlink，防止 Docker 容器写 GitHub/备份凭据权限死锁）
- `backup-scripts: 700`（`ap-object-list.sh` 等可执行；`github_collapse.sh` 必须在里面，缺它 GitHub 备份库会一直涨）
- Docker 模式单机备份生成独立完整 `.enc` 包；systemd 服务采用 `ExecStartPost=-...` 容错前缀，未配置 GitHub 时不误杀本地备份或误发报警。
- `BACKUP_ROOT/migration-graph.json` 是迁移完成后由 `showmigrations --plan` 原子生成的 JSON，不能用手工空文件代替。
- 自定义 `BACKUP_ROOT` 时，安装脚本会同步 `production.env` 中的 dump 口令、proof、迁移图和下载路径；备份 proof 绑定当前部署 Git commit。

机器重启后：docker 三件套、Nginx、证书续期、备份策略巡检、备份门铃、小时维护、应用守卫应自己起来。若重启后 `VERIFY_ONLY=1` 失败，部署手续不完整。

## 产品边界（不是本 SOP 漏做）

- 授权页 A / 核心 EXE 不在本仓库，要在各软件自己的项目里接。先本地验证，再用当前正式站既有test_downstream_b的test_only/0成本卡受控联调；旧测试站不可用。接入先读 `接入说明/00-先读我.md`（卡密 + 带版本号问更新 + 打开网盘）。
- 正式平台已按这份SOP迁至正式授权域名；2026-11-17迁移记录中的 `authorization_platform_historical` 仅是历史恢复库名，当前正式数据库为2026-11-23重建并经设备码迁移核对的正式库，具体名称只以目标机运行环境和私有钥匙包索引为准。旧机器只保留兼容反代与原数据回退材料，禁止恢复双写。密钥仍同一套，原已开启的备份策略保留；安装器不代开总开关。机器表见 `09-两台VPS.md`。GitHub备份库见 `10-GitHub备份库.md`。
- 任意新目标必须使用审定代码树和同一套密钥。旧测试站不再连接或覆盖；目标服务器应与已验证源码一致，实际接线只用安装器审定模板。
- 本套账本备份就是加密 `.enc`（页面打开总开关；可选 GitHub）。不要再去装 pgBackRest、也不要再把「双仓 WAL 证明」当成还欠的部署步骤。
- `.enc` 只有数据库，没有安装包对象。数据库空站不自带对象包。以后若发过安装包，换机时对象存储要另拷。
- 定档的 `404.html` 上有「前往下游登录」按钮，不是管理端地址。不要在部署时改冻结页。

以后优化或修 bug：不要另开「优化文档」文件夹。还是读这份，按上面「以后更新代码」做。

## 禁止

- 跳过 `install-site.sh`，或另写 `/tmp` 脚本
- 代码放到 `/opt/authorization-platform-日期` 却不改门铃和 Nginx `root`
- 只覆盖主机文件、不 `compose build`（API 不会更新）
- enable 旧的 full/diff 备份日历 timer（允许的周期 timer 只有策略巡检 timer 与应用守卫 timer 两项）
- `replace-with` / `openssl rand` 出第二套平台密钥
- production 跑 `seed_demo`
- 未确认就导入测试 dump、碰年包正式机、动同机其它容器
- 安装脚本代开备份总开关
