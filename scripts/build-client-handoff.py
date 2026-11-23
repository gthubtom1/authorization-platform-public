"""Build a copyable, credential-free folder from reviewed source files. No ZIP."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
BUNDLE_NAME = "软件授权接入包"
TEMPLATE_NAME = "授权启动器模板"
DEFAULT_TEMPLATE = ROOT / BUNDLE_NAME / TEMPLATE_NAME

OWNER_GUIDE = """# 软件授权接入包：从这里开始

这是开发资料文件夹。把整个「软件授权接入包」复制到已经开发好的软件项目根目录，保留文件夹结构。

1. 在授权平台管理端新建软件，设置规则，下载本软件的 `*-integration.json`。这是 JSON 数据文件。
2. 把下载原件放入本包 `放后台下载的JSON这里/`。一次只放当前软件、当前 Profile 的一个配置，不手填或修改身份和公钥。
3. 在软件项目里让 AI 读取本文件和 `01-给软件AI的提示词.txt`，再读 `平台公开资料/接口与能力说明.md`、`接口字段索引.json`、`模板兼容差异.md`。启动器源码已放在 `授权启动器模板/`，无需再找母版。
4. AI 按配置与公开合同完成真实接线、产品身份与品牌适配、核心功能门和测试，在软件项目输出《授权平台对接文档.md》。产品名称、窗口标题、图标、品牌色和用户可见文案必须替换成目标软件自己的内容，不能沿用模板默认值。你另行提供测试卡，完整卡密不放进包或文档。

以后每个软件都复制一份新的通用包，再放入该软件自己的 JSON。已经接过的软件副本独立维护；升级不能覆盖其源码、配置或产品状态。

```text
你的软件项目/                         ← 原有软件源码和构建仍在这里
└─ 软件授权接入包/
   ├─ 00-先读我.md
   ├─ 01-给软件AI的提示词.txt
   ├─ 放后台下载的JSON这里/           ← 你放本软件的下载原件
   ├─ 授权启动器模板/                ← 干净源码；AI只改本软件这一份
   ├─ 平台公开资料/                  ← 平台指令、接口、协议、夹具
   ├─ 产品品牌适配清单.md             ← 标题、图标、颜色和文案的必做检查
   ├─ 工具/prepare-config.py          ← 本地配置检查/准备，不访问后台
   └─ 交付清单.json                   ← 来源、文件哈希和能力边界
```

软件未授权时，受保护功能不可用；激活后可用；运行中按平台要求验证，到期、撤销、封禁或持续断网后停止受保护功能。后台补时间须传给运行中的软件。心跳再问时间和卡到期时间是两套钟。

当前交付的桌面入口已接入 v2 准备结果、真实 HTTP/HTTPS、成熟 Ed25519/JCS、五动作设备证明、运行中心跳、续期、启动票据核销、本地签名接口和动态 UI。窗口标题会从已校验的产品 manifest 读取；图标、EXE 资源、安装器和用户可见文案仍必须按 `产品品牌适配清单.md` 替换。使用方式见授权启动器模板/docs/CURRENT-RUNTIME.md。配置导入不代表已经授权；稳定硬件采集、具体核心功能门和双机验收仍由软件侧完成，交付整体保持 PARTIAL。

有源码时直接在源码加功能门。只有 EXE 而不能修改核心时，要报告保护缺口，不能把外层启动窗口算成完整保护。缺少 JSON、测试卡或双机条件时保留未完成项，继续能完成的本地工作。

此包不需要后台账号、平台私钥或服务器权限。后台下载配置不发卡；正式站测试套餐/发卡由平台操作者另办，按平台指令使用既有 test_downstream_b、test_only/0 成本，不改测试账号口令。
"""

AI_GUIDE = """# 软件侧 AI 入口

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
"""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_contract_index():
    """Extract public field names from code; never import settings or access credentials."""
    source = ROOT / "src/authorization_platform/licensing/authorization.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    common = None
    consumed = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "AUTHORIZATION_REQUEST_COMMON_FIELDS" for target in node.targets):
                common = sorted(ast.literal_eval(node.value.args[0]))
        if isinstance(node, ast.FunctionDef) and node.name == "consume_launch_ticket":
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "payload" for target in child.targets) and isinstance(child.value, ast.Dict):
                    consumed = [key.value for key in child.value.keys]
    if common is None or consumed is None:
        raise ValueError("Public source contract could not be extracted")
    required = [key for key in common if key not in {"known_authorization_revision", "known_config_version", "config_version"}]
    endpoints = {}
    for key, action, suffix in (
        ("activate", "activate", "activate"), ("verify", "verify", "verify"),
        ("deactivate", "deactivate", "deactivate"), ("launch_ticket", "launch-ticket", "launch-ticket"),
        ("consume_launch_ticket", "ticket-consume", "launch-ticket/consume"),
    ):
        endpoints[key] = {
            "method": "POST", "path": "/api/v1/public/licenses/" + suffix,
            "proof_action": action,
            "headers": ["Content-Type: application/json", "X-Request-Id", "Idempotency-Key"],
            "request_required_for_new_client": sorted(required + (["license_key"] if key == "activate" else ["authorization_id"]) + (["ticket_id"] if key == "consume_launch_ticket" else [])),
            "request_optional": ["known_authorization_revision", "known_config_version"],
            "compatibility_alias": {"config_version": "known_config_version; prefer known_config_version"},
            "response_kind": "consumed" if key == "consume_launch_ticket" else "issued" if key == "launch_ticket" else "authorization",
        }
    endpoints["releases"] = {
        "method": "GET", "path": "/api/v1/public/software/{software_id}/profiles/{profile_id}/releases/",
        "query_required_for_new_client": ["client_id", "target", "arch", "channel", "version"],
        "response_kind": "releases", "current_version_format": "three numeric components from real build",
    }
    endpoints["download"] = {
        "method": "GET", "path": "/api/v1/public/software/{software_id}/profiles/{profile_id}/releases/{release_id}/download/",
        "url_source": "release.download_url", "response_kind": "zip-or-error", "optional_channel": True,
    }
    auth_schema = json.loads((ROOT / "protocol/authorization.v1.schema.json").read_text(encoding="utf-8"))
    local_schema = json.loads((ROOT / "protocol/authorization-a-core.v1.schema.json").read_text(encoding="utf-8"))
    errors = {}
    for relative in ("src/authorization_platform/licensing/authorization.py", "src/authorization_platform/licensing/api.py"):
        error_tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(error_tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "AuthorizationOperationError" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                errors.setdefault(node.args[0].value, []).append({"source": relative, "line": node.lineno})
    release_tree = ast.parse((ROOT / "src/authorization_platform/releases/services.py").read_text(encoding="utf-8"))
    release_fields = []
    for node in ast.walk(release_tree):
        if isinstance(node, ast.FunctionDef) and node.name == "release_payload":
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "payload" for t in child.targets) and isinstance(child.value, ast.Dict):
                    release_fields = [key.value for key in child.value.keys]
    features = {}
    for line in (ROOT / "docs/FEATURES.md").read_text(encoding="utf-8").splitlines():
        match = re.match(r"\| (F-\d+) \| ([^|]+)\|", line)
        if match:
            features[match[1]] = match[2].strip()
    return {
        "schema": "authorization-client-reference.v1", "runtime_connected": False,
        "scope": "offline reference; fixed per-software values come only from controlled software-bind.v2",
        "endpoints": endpoints,
        "not_client_runtime": {"quota-settings": "/api/v1/public/quota-settings/", "administrator": "/api/v1/manage/", "downstream": "/api/v1/downstream/"},
        "configuration_transport": "ordinary signed authorization response; no public manifest GET",
        "request_common_allowed": common,
        "response_contracts": {
            "authorization": {"schema_file": "protocol/authorization.v1.schema.json", "required": auth_schema["required"], "allowed": list(auth_schema["properties"]), "properties": auth_schema["properties"], "definitions": auth_schema.get("$defs", {}), "signed": True},
            "local_authorization": {"schema_file": "protocol/authorization-a-core.v1.schema.json", "required": local_schema["required"], "allowed": list(local_schema["properties"]), "signed": True, "trust": "separate A-core contract, not interchangeable with cloud proof"},
            "issued": {"signed": True, "payload": "complete object including ticket and integrity; use downloaded launch_ticket_contract"},
            "consumed": {"required": consumed, "signed": False, "decision": "consumed", "not_authorization": True},
            "releases": {"required": ["software_id", "profile_id", "minimum_client_version", "has_update", "release", "generated_at"], "signed": False, "release_nullable": True, "release_fields": release_fields, "conditional_release_fields": ["update_open_url", "download_url"], "version_path": "release.version", "update_url_path": "release.update_open_url", "zip_url_path": "release.download_url", "time_format": "ISO-8601, not authorization epoch seconds"},
            "error": {"top_level": "error", "required": ["code", "message", "request_id", "retryable"], "signed": False},
        },
        "signature": {"algorithm": "ed25519", "canonicalization": "JCS-RFC8785", "remove_only": "integrity.signature", "input": "complete parsed original JSON object before DTO projection", "encoding": "base64url-no-padding", "unknown_key": "deny"},
        "device_proof": json.loads((ROOT / "protocol/device-proof.v1.json").read_text(encoding="utf-8")),
        "public_authorization_error_sources": dict(sorted(errors.items())),
        "error_policy": {"retryable_rate_limit": "bounded retry with Retry-After; never extend last valid online window", "unknown_nonretryable": "deny; do not translate all unknown codes to success", "hard_failures": ["LICENSE_REVOKED", "LICENSE_BLOCKED", "LICENSE_EXPIRED", "DEVICE_NOT_BOUND", "RISK_BLOCKED", "DEVICE_KEY_INVALID", "DEVICE_KEY_MISMATCH"]},
        "platform_feature_names": features,
        "known_limitations": ["target-specific stable hardware, core feature gates, direct-core protection and dual-machine acceptance remain PARTIAL"],
    }


def build(template_root: Path, output: Path):
    template_root = template_root.resolve(strict=True)
    if not (template_root / "src/current_runtime.rs").is_file():
        raise ValueError("Template source lacks the platform-maintained current runtime; do not rebuild from the retired external master")
    output = output.resolve()
    if output.exists():
        raise ValueError("Output already exists; preserve it and choose a new output directory")
    # Only tracked, selected source material. Never enumerate a working tree for bulk copy.
    tracked = subprocess.check_output(["git", "-C", str(template_root), "ls-files", "-z"])
    commit = subprocess.check_output(["git", "-C", str(template_root), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(template_root), "status", "--porcelain"]).strip())
    files = {}
    origins = {}
    overlays = {}

    def add(name, raw, origin):
        if name in files:
            raise ValueError("Duplicate bundle output")
        files[name] = raw.encode("utf-8") if isinstance(raw, str) else raw
        origins[name] = origin

    def overlay(name, raw, reason):
        if name in files:
            overlays[name] = {"replaces": origins[name], "reason": reason}
            del files[name]
            del origins[name]
        add(name, raw, "platform-current-contract-overlay")

    root_files = {"Cargo.toml", "Cargo.lock", ".gitignore"}
    selected = set()
    for item in tracked.decode("utf-8").split("\0"):
        if not item:
            continue
        path = Path(item)
        allowed = path.parts[0] in {"src", "tests", "fixtures", "protocol", "ui"} or item in root_files
        allowed |= path.parts[0] == "scripts" and path.name.startswith("check-") and path.suffix == ".ps1"
        allowed |= item in {"scripts/start-here.ps1", "scripts/init-product.ps1"}
        if not allowed:
            continue
        selected.add(path.as_posix())

    # Keep newly added, reviewable template sources in the handoff before they
    # are committed. This prevents the package from silently omitting a source
    # file that is already present in the maintained template directory.
    selected.update({"src/device_code.rs"})
    for item in sorted(selected):
        path = Path(item)
        source = template_root / path
        if not source.is_file() or source.is_symlink() or not source.resolve().is_relative_to(template_root):
            raise ValueError(f"Refusing missing or redirected template input: {item}")
        raw = source.read_bytes()
        add(f"{TEMPLATE_NAME}/{path.as_posix()}", raw, {"template_path": path.as_posix(), "sha256": sha(raw)})

    add("00-先读我.md", OWNER_GUIDE, "bundle-builder")
    add(".gitattributes", "# Preserve manifest byte hashes and the source snapshot's CRLF/blank EOF.\n** -text whitespace=cr-at-eol\n授权启动器模板/fixtures/profiles/*.json whitespace=cr-at-eol,-blank-at-eof\n", "bundle-builder")
    add("01-给软件AI的提示词.txt", "请在当前软件项目接入授权。先读 软件授权接入包/00-先读我.md 和 授权启动器模板/AI-HANDOFF.md，再读 放后台下载的JSON这里/ 的本软件 JSON。按内嵌指令和公开合同完成配置映射、真实联网验签、运行中心跳、核心功能门及失效停用，逐项实测并输出《授权平台对接文档.md》。只改本软件副本，不重复后台登记；缺少材料或真机条件明确记为未完成。\n", "bundle-builder")
    add("AGENTS.md", "# 交接包边界\n\n先读 00-先读我.md 与 授权启动器模板/AI-HANDOFF.md。平台仓库维护包内通用运行时；具体软件接入只在目标副本完成。配置来源以后台受控下载为准，不把模拟当真接通。不操作后台、外部母版和其他软件。\n", "bundle-builder")
    add("放后台下载的JSON这里/README.md", "# 放本软件的下载原件\n\n只放管理端为当前软件/Profile 下载的一份 `*-integration.json`。不要改名成 JS、手填身份或公钥，不放测试卡、账号、令牌和私钥。通用包此处保持空白。\n", "bundle-builder")
    importer = ROOT / "scripts/client-handoff/prepare-config.py"
    add("工具/prepare-config.py", importer.read_bytes(), "scripts/client-handoff/prepare-config.py")
    branding = ROOT / "scripts/client-handoff/PRODUCT-BRANDING-CHECKLIST.md"
    add("产品品牌适配清单.md", branding.read_bytes(), "scripts/client-handoff/PRODUCT-BRANDING-CHECKLIST.md")
    add(f"{TEMPLATE_NAME}/AI-HANDOFF.md", AI_GUIDE, "bundle-builder")
    for entry in ("README.md", "接入一步走.md", "WORK-HANDOFF.md", "OWNER-SPEECH.md"):
        add(f"{TEMPLATE_NAME}/{entry}", "# 授权启动器副本\n\n统一从 [AI-HANDOFF.md](AI-HANDOFF.md) 开始；负责人先看包根 [00](../00-先读我.md)。通用真实运行时见 [CURRENT-RUNTIME](docs/CURRENT-RUNTIME.md)，具体软件功能门/稳定硬件/双机条件仍须目标项目实测。\n", "bundle-builder")
    add(f"{TEMPLATE_NAME}/AGENTS.md", "# 本软件启动器副本\n\n先读 AI-HANDOFF.md、docs/PROJECT.md、docs/FEATURES.md、docs/STATUS.md、docs/CURRENT-RUNTIME.md。平台可维护通用运行时；具体软件在当前副本接入，不访问后台凭据、不改外部母版。现行桌面入口读取平台接入配置，旧演示不作为授权。\n", "bundle-builder")
    template_docs = {
        "PROJECT.md": "# 目标\n\n把当前软件接到统一授权平台：平台事实 → 本软件 A → 本机合同 → 核心功能门。平台软件身份来自下载 JSON；本软件构建版本来自真实源码。只在本软件副本实施。\n",
        "FEATURES.md": "# 已有能力和缺口\n\n现行 WebView2 桌面入口真实调用 current_runtime：v2映射、HTTP/HTTPS、Ed25519/JCS、五动作proof、运行中verify、续期、真核销许可、本机签名通道、动态UI。旧参考模块保留回归。具体核心功能门、稳定硬件采集、直开防护、双机条件保持 PARTIAL，见 CURRENT-RUNTIME.md。\n",
        "STATUS.md": "# 当前事实\n\n平台维护未绑定任何软件的通用源码，无 product-state、客户配置或测试卡。现行桌面入口直接读取v2准备结果并走真实平台链，通用验收见 CURRENT-RUNTIME.md。整体仍PARTIAL：具体软件功能门/稳定硬件/双机必须另验，不能继承通用测试为客户完成证据。\n",
        "ARCHITECTURE.md": "# 边界\n\n平台 HTTPS 仅由 A 调用；核心仅访问本机 A。UI 发意图，由运行时复核。平台公钥验证平台响应，本地合同独立校验会话/身份/完整性。src 内 fixture/mock 是参考测试边界，正式路径须使用真实实现。\n",
        "PLATFORM-INTEGRATION-HANDOFF.md": "# 平台接入\n\n直接读取本软件下载 JSON 和包内平台公开资料。protocol/ 为来源模板的参考合同，随来源逐字节保留；下载 JSON 的 contracts 为本次接入合同，需逐项对比代码兼容性，不能覆盖文件就算适配。操作入口为 ../AI-HANDOFF.md。\n",
        "COPY-SYNC.md": "# 同步\n\n每个软件副本独立维护。新包不能覆盖已改过的副本、平台接入配置或 product-state；按交付清单逐项比对来源和本软件改动后再同步，保留检查点并重跑受影响测试。\n",
    }
    for name, value in template_docs.items():
        add(f"{TEMPLATE_NAME}/docs/{name}", value, "bundle-builder")
    add(f"{TEMPLATE_NAME}/docs/CURRENT-RUNTIME.md", (ROOT / "scripts/client-handoff/CURRENT-RUNTIME.md").read_bytes(), "scripts/client-handoff/CURRENT-RUNTIME.md")
    add(f"{TEMPLATE_NAME}/SOURCE-COMMIT.txt", commit + "\n", "template-git-head")
    add(f"{TEMPLATE_NAME}/HANDOFF-COPY.json", json.dumps({"schema": "authorization-handoff-copy.v1", "template_source_commit": commit, "runtime_connected": False}, indent=2) + "\n", "bundle-builder")

    public = ROOT / "docs/API-CONTRACT.md"
    api = public.read_text(encoding="utf-8")
    # Client-facing sections only; omit browser/admin release operations.
    sections = [api[api.index("## 两段接口和调用方"):api.index("管理端版本发布 API：")], api[api.index("### 授权 A 到核心 EXE 的本地合同"):api.index("## PR-02 浏览器认证与账号动作")], api[api.index("## 错误格式"):api.index("## 认证边界")]]
    delivered_api = "\n".join(sections).rstrip() + "\n"
    delivered_api = delivered_api.replace("tests/fixtures/authorization_v1/", "平台公开资料/fixtures/authorization_v1/").replace("tests/fixtures/authorization_a_core_v1/", "平台公开资料/fixtures/authorization_a_core_v1/")
    add("平台公开资料/客户端API合同.md", delivered_api, "docs/API-CONTRACT.md:client-sections")
    for name in ("接口与能力说明.md", "模板兼容差异.md"):
        add("平台公开资料/" + name, (ROOT / "scripts/client-handoff" / name).read_bytes(), "scripts/client-handoff/" + name)
    add("平台公开资料/接口字段索引.json", json.dumps(source_contract_index(), ensure_ascii=False, indent=2) + "\n", "public-source-AST-and-schema")
    ticket = "### 一次性启动票据\n" + re.split(r"\n#{1,3} ", api.split("### 一次性启动票据\n", 1)[1], maxsplit=1)[0]
    overlay(f"{TEMPLATE_NAME}/protocol/launch-ticket.v1.md", ticket, "replace conflicting legacy nonce/TTL/consume instructions with current public contract")
    overlay(f"{TEMPLATE_NAME}/protocol/device-proof.v1.json", (ROOT / "protocol/device-proof.v1.json").read_bytes(), "current five proof actions including launch-ticket/ticket-consume")
    ui_name = f"{TEMPLATE_NAME}/protocol/authorization-a-ui.v1.schema.json"
    ui_schema = json.loads(files[ui_name])
    if "notice" not in ui_schema["properties"]["enabled_modules"]["items"]["enum"]:
        ui_schema["properties"]["enabled_modules"]["items"]["enum"].append("notice")
    overlay(ui_name, json.dumps(ui_schema, ensure_ascii=False, indent=2) + "\n", "accept notice alias already supported by Rust UI and tests")
    for source, name in (
        ("接入说明/09-给软件项目AI的接入指令.md", "09-给软件项目AI的接入指令.md"),
        ("docs/CLIENT-INTEGRATION-HANDOFF.md", "客户端接入合同.md"),
    ):
        content = (ROOT / source).read_text(encoding="utf-8")
        if name == "客户端接入合同.md":
            content = content[content.index("| 材料/事实 |"):]
            # Keep source names as references rather than broken repository links.
            links = {
                "API-CONTRACT.md": "客户端API合同.md",
                "../protocol/authorization.v1.schema.json": "protocol/authorization.v1.schema.json",
                "../protocol/authorization-a-core.v1.schema.json": "protocol/authorization-a-core.v1.schema.json",
                "../protocol/device-proof.v1.json": "protocol/device-proof.v1.json",
            }
            content = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", lambda match: f"[{match[1]}]({links[match[2]]})" if match[2] in links else match[1], content)
            content = "# 客户端接入合同\n\n摘取平台责任合同；包内操作入口为 [启动器 AI 入口](../授权启动器模板/AI-HANDOFF.md)。当前软件身份/协议按后台下载 JSON 核对。\n\n" + content
        add("平台公开资料/" + name, content if name == "客户端接入合同.md" else (ROOT / source).read_bytes(), source)
    for source in (ROOT / "protocol").glob("*.json"):
        if source.name in {"authorization.v1.schema.json", "authorization-a-core.v1.schema.json", "device-proof.v1.json"}:
            add("平台公开资料/protocol/" + source.name, source.read_bytes(), "protocol/" + source.name)
    for fixture_dir in ("authorization_v1", "authorization_a_core_v1"):
        for source in sorted((ROOT / "tests/fixtures" / fixture_dir).glob("*.json")):
            add("平台公开资料/fixtures/" + fixture_dir + "/" + source.name, source.read_bytes(), source.relative_to(ROOT).as_posix())
    add("平台公开资料/fixtures/README.md", "# 夹具用途\n\n各子目录 active/grace/expired/revoked/blocked/not_modified/unbound 等完整信封仅供形状测试；签名 fixture-signature 是占位，时间戳不代表当前策略间隔。risk-blocked-error 是普通error加transport说明包装，不是整个HTTP响应体；transport仅为测试元数据。其他 error-only、missing-required-field、old-contract、unknown-key、signature-invalid、cross-scope 等是故意失败输入，必须按各自测试意图拒绝，不可当正常响应照抄。time-rollback 是错误示例，不是带签名授权。真实验签必须另用受控测试私钥/平台响应，不能拿占位签名证明生产接通。\n", "bundle-builder")
    manifest = {
        "schema": "authorization-client-handoff.v1",
        "platform_source_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "platform_worktree_dirty": bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"]).strip()),
        "platform_sources_hash_format": "UTF-8 with LF newlines",
        "platform_sources": {name: sha((ROOT / name).read_text(encoding="utf-8").encode("utf-8")) for name in ("docs/API-CONTRACT.md", "docs/CLIENT-INTEGRATION-HANDOFF.md", "接入说明/09-给软件项目AI的接入指令.md")},
        "template_source": str(template_root), "template_commit": commit, "template_worktree_dirty": dirty,
        "overlays": overlays,
        "runtime_connected": False, "generic_runtime_implemented": True, "status": "PARTIAL",
        "excluded": [".git", "target", "product-state", "incoming", "credentials", "old registration/export scripts", "legacy process documents"],
        "files": {name: {"sha256": sha(raw), "size": len(raw), "origin": origins[name]} for name, raw in sorted(files.items())},
    }
    add("交付清单.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", "bundle-builder")
    output.mkdir(parents=True)
    for name, raw in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return {"output": str(output), "files": len(files), "bytes": sum(map(len, files.values())), "runtime_connected": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template-root", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--output", type=Path, default=ROOT / BUNDLE_NAME)
    args = parser.parse_args()
    print(json.dumps(build(args.template_root, args.output), ensure_ascii=False, indent=2))
