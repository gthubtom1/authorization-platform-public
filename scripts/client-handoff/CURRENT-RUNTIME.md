# 当前通用运行时与验收

平台维护的来源是本包 `授权启动器模板/`，默认构建源也是这里。`scripts/build-client-handoff.py --output 新目录` 读取受 Git 跟踪的包内源码，并按显式登记的新增源文件补入尚未提交的审查内容，记录逐文件哈希；不再默认读取外部旧母版。缺少 `src/current_runtime.rs` 的旧源会被拒绝，不复制第二套完整源码。

现有桌面入口 `src/bin/a-template-webview-ui.rs` 调用 `Binding::load → DesktopHost → WebViewRenderer::run_live`。它不是旧演示的空回调：UI提交卡密，宿主发送真实请求；完整原JSON先验签再进入会话；新的状态快照同时决定宿主可接受意图和页面状态。运行窗口标题从已校验的产品 manifest `display_name` 读取，不再固定使用模板标题；窗口图标仍来自 `授权启动器模板/ui/app-icon-32.rgba`，必须按 `产品品牌适配清单.md` 替换，并同步适配最终 EXE、安装器、快捷方式和托盘资源。旧 `authorization/platform/session/codec` 等参考实现继续独立回归，不参与正式桌面授权。

成熟依赖采用精确版本并保存 Cargo.lock：serde_json/serde、serde_jcs、ed25519-dalek、jsonschema、ureq/rustls、rand_core、sha2。没有自制签名或JSON规范化。响应只删除 `integrity.signature` 后JCS验签，保留未知扩展、Unicode键、浮点和其余完整性字段。重复键、孤立代理项、过深或过大的JSON拒绝；合法代理对、中文按字符长度接受。云端有符号int64时间可解析，本地成功信封要求非负。

先运行包内 `工具/prepare-config.py` 准备后台下载原件，再构建并运行：

```text
python 工具/prepare-config.py 放后台下载的JSON这里/实际文件名-integration.json --template-root 授权启动器模板 --prepare
cargo build --locked --manifest-path 授权启动器模板/Cargo.toml --bin a-template-webview-ui
a-template-webview-ui.exe --binding 授权启动器模板/平台接入配置 --version 1.0.0 --installation 实际稳定硬件指纹 --device-key 本用户私有目录/device.dpapi --core 原软件入口绝对路径
```

`--version` 必须替换为真实软件构建版本，不能用minimum_client_version推断。`--installation` 必须由目标软件可信的稳定硬件采集实现提供；此命令行参数是集成边界，不是已完成硬件实现的声明。平台管理端/下游读侧显示的 `device_code` 由已确认的 `installation_id` 稳定派生，仅用于客户核对、复制和搜索；它不替代 `--installation`，也不进入授权请求、设备证明、票据或核心授权事实。设备私钥在本机生成，用本用户Windows DPAPI与软件/安装范围保护；不会将卡密写入浏览器存储或明文配置。运行时缺配置、缺密钥安全存储、缺桥接时拒绝；只有显式 `?prototype=1` 页面原型允许模拟。

GNU构建需要把相同架构的WebView2Loader.dll与启动器放在一起或置于其PATH，目标机器还需要Microsoft WebView2 Runtime。GNU工具链中文路径可能需要工作区内临时ASCII路径/linker映射；这属于构建环境，不改产品源码、不安装系统组件。正式发布前仍需核对软件签名、依赖分发与实际安装路径。

五POST使用当前平铺字段和一致的body/header/request/idempotency值；proof精确覆盖device-proof.v1的五个action。结果未知重试保留原body、nonce和幂等键。首次尝试的单调时钟锚点也保留，重试成功返回旧响应不会重新购买成功有效窗口。请求失败、429及重试时间不会延长最后成功窗口。卡到期独立且排他；本v1的离线宽限时长从签名grace_until减expires_at取得，只能延长成功窗口，不能越过卡到期。

自动验证使用单调时钟提前量：签名间隔的一半与3秒取较小值，1秒窗口提前500ms，0秒成功窗口拒绝。网络回包超过剩余预算仍按原截止停用，不增加隐含宽限。签发及九字段关联核销接受的新server_time推进同范围高水位，收紧本地信封、许可与独立看守的截止；它们不购买普通verify的新成功窗口，也不修改平台签名原件。首次激活被明确拒绝后，页面使用宿主允许的新activate接受更正卡密；请求结果未知仍只能原样retry。

普通成功窗口独立于可信卡钟：新的相关activate/verify/not_modified成功按该逻辑请求首次尝试的单调时刻加签名窗口长度更新预算，同整数秒的新请求也可更新；卡钟高水位及已过小数秒不重置。相同请求的原响应迟到或重试仍用首次尝试锚点；票据相同时间不刷新窗口，新时间只减去对应时钟跳跃并收紧截止。UI、本地信封和核心看守统一取普通截止与可信卡到期的最早值。

同revision的新请求和新时间允许；not_modified消费完整签名时间并保持当前授权状态。续期允许保持issued_at、增加revision与expires_at；回退/旧重放/终态恢复拒绝。近期请求台账有界，不存在终生1024请求预算。运行中的下一次verify传递新到期/模块/UI；硬拒绝立即失效，持续断网在成功窗口结束后停用。

启动链为真实 `launch-ticket → 验签issued → ticket-consume → 关联九字段consumed → 一次LaunchPermit`。仅issued、错误ticket/身份/时刻、核销失败、窗口结束都不产生许可，桌面处理许可时再次检查当前状态和票据截止。正式运行必须提供--core，只使用本地明确配置的可执行文件，不接受平台下发命令。启动后监测单调截止，宿主授权失效时终止它启动的子进程；目标软件仍必须逐功能门检查，不能依赖外壳终止代替核心保护。

本机接口只绑定127.0.0.1随机端口。启动核心的环境提供 `AUTHORIZATION_A_LOCAL_URL`、短期 `AUTHORIZATION_A_BOOTSTRAP_TOKEN` 和 `AUTHORIZATION_A_LOCAL_PUBLIC_KEY`；这些不进入URL、日志或网页。核心以软件/Profile/client、真实client_version和一次性nonce打开会话，随后使用随机session_token访问health/state/refresh/close。A-core采用当前独立schema重新签名，origin/audience固定；核心必须钉住启动通道交付的本地公钥并验证签名/身份/时间。此通道不声称能防同用户恶意进程、伪造父进程或被修改的核心。

在平台工作区的可重复验证：

```text
cargo test --locked --manifest-path 软件授权接入包/授权启动器模板/Cargo.toml
设置 FINAL_CLIENT_EXE 为刚构建的 a-template-webview-ui.exe 绝对路径
python manage.py test tests.test_final_client_runtime --noinput
python manage.py test tests.test_round2_client_runtime --noinput
```

测试程序运行桌面EXE的显式 `--acceptance-stdio` 通道，授权HTTP仍由相同DesktopHost发出真实socket到隔离Django，不用Python Client替代客户端。另以隐藏真实WebView2加载包内页面，提交真实表单、接收新快照、自动签发核销、再撤销并核对DOM/宿主权限。`--acceptance-webview`/`--receipt`只用于本地显式验收；脚本来自测试目录，正式路径不读取远程脚本。

正常核心验收使用自有ProbeCore；显式`--acceptance-core`复用正式`--core`的路径校验、许可复查、启动回调和看守，只注入隐藏表单及回执。覆盖4秒零宽限/800ms正常回包、1秒短间隔、断网/429/超时、绝对到期、票据时间推进后验证持锁，核对实际子进程存活和退出；不是客户软件核心保护或子孙进程树认证。

2026-11-16本轮验证：165项Rust执行通过（原161项保留+新增4项），交接/平台导出/专属运行时36项执行通过、零跳过；其中连续1030次真实socket条件心跳，隐藏真实WebView表单→核销→运行中续期显示→撤销阻断通过。执行包内JS控制器的反例在旧版本实际打红，新版本通过缺桥接/原型隔离/旧明文清理/动态状态/续期/空渠道。三份损坏但非空合同的准备反例也在旧工具实际打红。

整体交付保持PARTIAL，清单runtime_connected=false表示尚无任何具体客户软件接入完成，不否定generic_runtime_implemented。仍需目标软件：稳定硬件采集与重装稳定、每个核心入口/后台任务功能门、直开核心拒绝、可信父子/本机认证、子进程树停用与真实依赖/参数、双机挤机、真机长时。releases提示/网盘下载与具体更新流程不属于此五动作宿主的已实现范围，软件项目按公开合同另接。平台真实业务数据、正式密钥与服务器不参与这些隔离验收。
