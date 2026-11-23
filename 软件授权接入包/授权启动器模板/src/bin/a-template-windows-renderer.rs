#![cfg_attr(windows, windows_subsystem = "windows")]

use std::env;

use authorization_a_template::{
    CompatibilityMode, LicenseState, ProductManifest, ThemeTokens, UiProfile, UiRenderSnapshot,
    UiShellModel, UiViewState, WindowsRenderer, WindowsRendererConfig,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let smoke = args.iter().any(|arg| arg == "--smoke");
    let state = if args.iter().any(|arg| arg == "--active") {
        UiViewState::from_license_state(LicenseState::Active, true)?
    } else if args.iter().any(|arg| arg == "--grace") {
        UiViewState::from_license_state(LicenseState::Grace, false)?
    } else if args.iter().any(|arg| arg == "--loading") {
        UiViewState::loading()
    } else {
        UiViewState::login()
    };

    let manifest = ProductManifest::new(
        "sample-product",
        "示例软件",
        "sample-adapter",
        "1.0.0",
        "zh-CN",
        ThemeTokens::new("#D4B45A", "#0C0B09", "#F3EEE4", "#E85A6F"),
        "core/sample.exe",
        "state/sample",
        "a-auth-sample",
        CompatibilityMode::NativeCore,
        vec![],
    );
    let profile = UiProfile::for_manifest(&manifest, "profile-default")
        .with_enabled_modules(["contact", "purchase"])
        .with_copy("app_kicker", "示例软件")
        .with_copy("subheadline", "通过后会自动打开本软件，不用再点。");
    let model = UiShellModel::new(&manifest, &profile, state)?;
    let model = if matches!(
        model.state.authorization,
        authorization_a_template::UiAuthorizationState::Active
            | authorization_a_template::UiAuthorizationState::Grace
    ) {
        model.with_device_code("DEMO-DEVICE")?
    } else {
        model
    };
    let snapshot = UiRenderSnapshot::new(model, &profile)?;
    let mut renderer = WindowsRenderer::new(
        WindowsRendererConfig {
            title: "软件授权".to_string(),
            ..WindowsRendererConfig::default()
        },
        snapshot,
    )?;

    if smoke {
        renderer.smoke_test()?;
        return Ok(());
    }

    renderer.run(|_| {}, |_| {})?;
    Ok(())
}
