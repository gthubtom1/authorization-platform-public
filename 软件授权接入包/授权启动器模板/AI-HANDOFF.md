# 软件侧 AI 入口

先读包根 00-先读我.md，选择「放后台下载的JSON这里」唯一一份 *-integration.json，核对目标软件后读取其 ai_handoff、contracts、response_contracts、launch_ticket_contract。
开工前必须读平台公开资料/接口与能力说明.md、接口字段索引.json、模板兼容差异.md和授权启动器模板/docs/CURRENT-RUNTIME.md；不能仅按旧参考Rust源码或占位fixture推断现行协议。现行桌面入口调用current_runtime通用活路径，旧DTO/mock/codec只保留给参考回归。
平台指令唯一源为平台公开资料/09-给软件项目AI的接入指令.md；下载 JSON 内为导出时的副本。二者有协议/行为冲突时记录版本差异，不静默采用较宽松规则，也不修改 JSON 来掩盖冲突。

路径定义必须按本包层级：BundleRoot=软件授权接入包；ProgramRoot=BundleRoot 的父目录（原软件源码根）；TemplateRoot=BundleRoot/授权启动器模板；ProductRoot=TemplateRoot。不要把 BundleRoot 当作原程序根。
平台维护包内通用启动器源码，包构建默认直接读取这里，拒绝从缺少当前活路径的旧母版重建。目标软件里只改本软件副本；平台通用包不初始化成某个客户产品。保留原软件 Git 修改和基线，不动外部母版、其他软件或服务器。先完成包内 `产品品牌适配清单.md`：标题、图标、颜色、文案、安装器/快捷方式/托盘和最终 EXE 资源都必须切换为本软件身份，模板默认“软件授权”、示例名称、sample/simulation 和示例图标只能留在测试或文档边界。

第一阶段：盘点本软件框架、真实启动入口、当前构建版本、产品正式名称、窗口/任务栏/托盘标题、图标来源、品牌色和受保护功能；运行原软件测试，记录来源配置哈希、交付清单、母版版本/哈希。先完成 `产品品牌适配清单.md`，并把模板标题、图标和用户可见文案列为接入修改项。源码已就绪但还没 EXE 时先做源码接线，不要求先逆向/登记 EXE；已有真实 EXE 才可用 scripts/init-product.ps1 -InputPath 的不可变基线辅助流程。不要把模拟初始化当真实输入。
有源码、获准维护的仅EXE、只能外包启动窗口按接口与能力说明分别判断。start-here.ps1仅报告模板状态，枚举INPUT不能当软件目录盘点；init-product.ps1只保存EXE基线，默认core_path不会自动指向InputPath。两脚本均为可选辅助，其NEXT_ACTION不能覆盖本入口。原软件在ProgramRoot盘点；工作目录、依赖和运行入口另核实。
新本地product_id可取software_id；已有值保留并记录到平台身份的稳定映射，UI profile_id须对应真实profile_id，不留profile-default。绝不反改下载JSON。

第二阶段：用 Python 3 检查配置（命令从 BundleRoot 执行；文件名用下载原件真实名称）：

```text
python 工具/prepare-config.py 放后台下载的JSON这里/实际文件名-integration.json --template-root 授权启动器模板
python 工具/prepare-config.py 放后台下载的JSON这里/实际文件名-integration.json --template-root 授权启动器模板 --prepare
```

默认命令只读，--prepare 创建 TemplateRoot/平台接入配置/。重复导入拒绝覆盖，恢复现有配置继续工作。运行 a-template-webview-ui 时显式传 --binding 平台接入配置、--version 真实构建版本、--installation 本机稳定硬件指纹、--device-key 本用户安全存储路径；具体 --core 必须是软件真实入口绝对路径。工具不改 product-manifest.v1。不要运行旧 register-platform、后台登记或导出向导；本包不携带这些脚本。

第三阶段：按平台公开资料/客户端API合同.md 和 客户端接入合同.md 接线。source-integration.json 为原件，platform-binding.json 为本地准备格式；运行时消费这些真实身份/固定公钥/API，并从软件构建填写真实 current_client_version，绝不拿 minimum_client_version 代填。设备私钥在客户设备生成；平台私钥和管理员口令不得进软件。

复用现行桌面真实 HTTP、Ed25519/JCS、设备证明、冻结请求重试、DPAPI设备密钥、运行中 verify、续期传播、动态 UI 和本机认证通道；给具体核心加入每个功能门和直开保护。同步完成产品品牌适配：使用目标软件的 manifest display_name、窗口/错误/任务栏/托盘标题、图标资源、ThemeTokens、UI copy、安装器和 EXE 资源，清理模板默认值。正式入口缺配置/桥接时拒绝，不用 Mock/fixture 放行。两段合同独立；票据 issued/consumed 不套普通授权响应 Schema。旧参考协议只用于旧回归，当前活路径验证受控下载 JSON 的合同版本和完整结构；不修改下载原件。

第四阶段：按平台指令逐项验错卡、单机超过两次验证周期、短卡到期、断网、撤销/封禁、直接打开核心、续期、更新和渠道空值；同时检查窗口、错误框、任务栏、托盘、安装器、快捷方式、EXE 图标和所有用户可见文案没有模板残留。两台机器才算验证挤机。把命令、结果、品牌资源哈希和未验项写到 ProgramRoot/授权平台对接文档.md，结论用 SUPPORTED/PARTIAL/BLOCKED，不含秘密。无测试卡可完成本地工作，但不模拟真实平台验收。
