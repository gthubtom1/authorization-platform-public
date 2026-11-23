# Authorization A 页面原型

`authorization-a-shell.html` 是 `authorization-a-ui.v1` 的无依赖视觉原型。
当前默认使用 `zh-CN` 和紧凑单表面授权入口：品牌标识、可见卡密输入、一个
激活按钮、同页动态反馈、设备码和底部联系入口。激活不会切换到第二个页面；
成功状态只显示“正在进入程序”的反馈，真实运行时应在此处直接发起核心启动。
它只用于呈现和交互评审，不联网、不保存凭证、不开 IPC，也不启动核心程序。

原型覆盖通用结构：

- 单一激活入口，以及同页动态成功/失败反馈；
- 登录、检查中、授权有效、离线缓存态、过期、撤销、阻断、不可用和响应无效；
- 键盘可见焦点、窄屏单列布局和减少动画；
- 由 `enabled_modules` 控制的模块目录仍按契约过滤；主授权页只保留购买和联系支持入口，其他模块交给运行时或核心消费；
- 通过 `window.AUTHORIZATION_A_UI_PROFILE` 替换主题源色、语言和文案。

生产 renderer 必须消费已经验证的 `UiRenderSnapshot`，把按钮点击作为 intent，
并在启动核心前让 A 运行时再次检查授权。原型中的状态选择器和演示凭证框只
用于视觉 QA，不代表真实授权成功或真实模块动作；普通打开页面不会显示这些
原型工具，追加 `?prototype=1` 才会显示。

The native Windows reference can be smoke-tested with:

```text
cargo run --bin a-template-windows-renderer -- --smoke
```

手动检查窗口时省略 `--smoke`，这样会打开可输入卡密的登录态；`--active` 和
`--grace` 仅用于选择示例状态。该
参考实现面向 Windows 10 version 1607 或更高版本，使用标准 Win32 控件，
不连接授权台、不开 IPC、不启动核心、不保存凭证。正式 Windows GUI 子系统
不会附带黑色控制台窗口；开发验证仍可从终端运行命令。凭证回调收到借用的
UTF-16 切片，renderer 在回调返回后清零临时缓冲。

The Windows desktop entry point is the `wry` host:

See [CURRENT-RUNTIME](../docs/CURRENT-RUNTIME.md) for the current binding,
real software version, stable device identity, protected device-key path and
core executable parameters. The WebView entry runs the real authorization chain;
it has no sample-state or `--smoke` mode. The retired helper script was removed.
The Microsoft WebView2 Runtime is a Windows prerequisite. The separate Win32
renderer above remains a visual prototype; it cannot prove software integration.
