use authorization_a_template::{
    CompatibilityMode, ProductManifest, ThemeTokens, UiProfile, UiRenderSnapshot, UiViewState,
    WindowsRenderer, WindowsRendererConfig, WindowsRendererError,
    WINDOWS_RENDERER_MAX_CREDENTIAL_CHARS,
};

fn snapshot() -> UiRenderSnapshot {
    let manifest = ProductManifest::new(
        "renderer-sample",
        "Renderer Sample",
        "sample-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::new("#3478F6", "#F2F2F7", "#1C1C1E", "#FF3B30"),
        "core/sample.exe",
        "state/sample",
        "a-auth-sample",
        CompatibilityMode::NativeCore,
        vec![],
    );
    let profile = UiProfile::for_manifest(&manifest, "profile-default")
        .with_copy("headline", "A native checkpoint")
        .with_copy("credential_placeholder", "Credential stays transient");
    let model =
        authorization_a_template::UiShellModel::new(&manifest, &profile, UiViewState::login())
            .unwrap();
    UiRenderSnapshot::new(model, &profile).unwrap()
}

#[test]
fn renderer_isolated_boundary_accepts_snapshot_and_config() {
    let snapshot = snapshot();
    let config = WindowsRendererConfig::default();
    assert!(config.width > config.height);
    assert_eq!(config.width, 990);
    assert_eq!(config.height, 700);
    assert_eq!(config.min_width, 806);
    assert_eq!(config.min_height, 598);
    let renderer = WindowsRenderer::new(config, snapshot).unwrap();
    assert_eq!(renderer.model().product_id, "renderer-sample");
    assert_eq!(
        renderer.snapshot().copy_text("headline"),
        Some("A native checkpoint")
    );
}

#[test]
fn renderer_rejects_invalid_config_and_model_before_win32() {
    let invalid_config = WindowsRendererConfig {
        min_width: 900,
        width: 640,
        ..WindowsRendererConfig::default()
    };
    assert!(matches!(
        WindowsRenderer::new(invalid_config, snapshot()),
        Err(WindowsRendererError::InvalidConfig(_))
    ));

    let mut invalid_snapshot = snapshot();
    invalid_snapshot.model.schema_version = "authorization-a-ui.v0".to_string();
    assert!(matches!(
        WindowsRenderer::new(WindowsRendererConfig::default(), invalid_snapshot),
        Err(WindowsRendererError::InvalidModel(_))
    ));

    let mut unsafe_text_snapshot = snapshot();
    unsafe_text_snapshot
        .copy
        .insert("headline".to_string(), "unsafe\u{0000}text".to_string());
    assert!(matches!(
        WindowsRenderer::new(WindowsRendererConfig::default(), unsafe_text_snapshot),
        Err(WindowsRendererError::InvalidModel(_))
    ));
}

#[test]
fn renderer_sample_is_a_gui_binary_without_console_logging() {
    let source = include_str!("../src/bin/a-template-windows-renderer.rs");
    assert!(source.contains("windows_subsystem = \"windows\""));
    assert!(source.contains("--loading"));
    assert!(!source.contains("println!"));
    assert!(!source.contains("eprintln!"));
}

#[test]
fn renderer_keeps_native_input_and_display_paths_bounded() {
    assert!((1..=1024).contains(&WINDOWS_RENDERER_MAX_CREDENTIAL_CHARS));
    let source = include_str!("../src/windows_renderer.rs");
    assert!(source.contains("EM_LIMITTEXT"));
    assert!(source.contains("EM_EMPTYUNDOBUFFER"));
    assert!(source.contains("WM_SYSCOLORCHANGE"));
    assert!(source.contains("WM_DPICHANGED"));
    assert!(source.contains("GetDpiForSystem"));
    assert!(source.contains("SetWindowPos"));
    assert!(source.contains("drain_renderer_exit_messages"));
    assert!(!source.contains("std::thread::spawn"));
    assert!(!source.contains("WM_TIMER"));
}

#[test]
fn renderer_smoke_check_never_shows_a_user_facing_window() {
    let source = include_str!("../src/windows_renderer.rs");
    let (_, startup) = source
        .split_once("let startup_error = unsafe")
        .expect("native startup path must remain discoverable");
    let (startup, _) = startup
        .split_once("let mut message")
        .expect("native startup path must end before the message loop");
    let visible_branch = startup
        .split_once("if !close_after_show {")
        .map(|(_, branch)| branch)
        .expect("only interactive sessions may enter the visible branch");
    assert!(visible_branch.contains("ShowWindow(hwnd, SW_SHOW);"));
    assert!(visible_branch.contains("UpdateWindow(hwnd);"));
    assert!(startup.contains("if close_after_show {"));
}

#[test]
fn accessibility_qa_only_resizes_when_explicitly_requested() {
    let source = include_str!("../scripts/check-windows-renderer-accessibility.ps1");
    assert!(source.contains("[switch]$AllowInteractiveDesktop"));
    assert!(source.contains("requires -AllowInteractiveDesktop"));
    assert!(source.contains("[switch]$IncludeResizeCheck"));
    assert!(source.contains("include_resize_check = [bool]$IncludeResizeCheck"));
    assert!(source.contains("if ($IncludeResizeCheck) {"));
    assert!(!source.contains("            520,"));
    assert!(!source.contains("            420,"));
    assert!(source.contains("$minimumWidth"));
    assert!(source.contains("$minimumHeight"));
    assert!(source.contains("$originalWidth"));
    assert!(source.contains("$originalHeight"));
    assert!(source.contains("Set-VisualCredentialForQa"));
    assert!(source.contains("RedrawWindow"));
    assert!(source.contains("Assert-ControlHasVisibleTextPixels"));

    let (_, resize_branch) = source
        .split_once("if ($IncludeResizeCheck) {")
        .expect("resize QA must have an explicit opt-in branch");
    let set_window_pos = resize_branch
        .find("SetWindowPos")
        .expect("opt-in resize QA must still exercise native resizing");
    let branch_end = resize_branch
        .find("\n    }")
        .expect("opt-in resize QA branch must be bounded");
    assert!(set_window_pos < branch_end);
}

#[test]
fn renderer_uses_a_product_neutral_visual_hierarchy_and_visible_credential() {
    let source = include_str!("../src/windows_renderer.rs");
    for marker in [
        "ID_APP_KICKER",
        "ID_HEADLINE",
        "ID_SUBHEADLINE",
        "WM_PAINT",
        "WM_DRAWITEM",
        "BS_OWNERDRAW",
        "CreateFontW",
        "draw_button",
        "RoundRect",
        "button_highlight",
        "feedback_surface",
        "ID_PURCHASE",
        "ID_CONTACT",
        "module_enabled(\"purchase\")",
    ] {
        assert!(
            source.contains(marker),
            "native renderer is missing the visual hierarchy marker: {marker}"
        );
    }
    assert!(
        !source.contains("ES_PASSWORD"),
        "the transient credential edit must remain visibly readable"
    );
    assert!(source.contains("ShowWindow(self.credential, SW_SHOW)"));
    assert!(source.contains("EnableWindow"));
    assert!(source.contains("UiViewState::loading()"));
}

#[test]
fn renderer_keeps_credential_text_readable_and_busy_primary_actions_colored() {
    let source = include_str!("../src/windows_renderer.rs");
    assert!(source.contains("font_input"));
    assert!(source.contains("create_font(-self.scale(18), FW_SEMIBOLD, \"Consolas\")"));
    assert!(source.contains("send_font(self.credential, self.font_input)"));
    assert!(!source.contains("send_font(self.credential, self.font_body)"));
    assert!(source.contains("EM_SETMARGINS"));
    assert!(source.contains("RICHEDIT50W"));
    assert!(source.contains("EM_SETBKGNDCOLOR"));
    assert!(source.contains("EM_SETCHARFORMAT"));
    assert!(source.contains("CHARFORMAT2W"));
    assert!(source.contains("metrics.credential_y + self.scale(8)"));
    assert!(source.contains("self.scale(30)"));
    assert!(source.contains("disabled && !primary"));
    assert!(source.contains("ID_ACTIVATE | ID_LAUNCH | ID_RETRY"));
}

#[test]
fn renderer_paints_feedback_text_inside_the_feedback_surface() {
    let source = include_str!("../src/windows_renderer.rs");
    assert!(source.contains("feedback_brush"));
    assert!(source.contains("control_id == ID_STATUS || control_id == ID_DETAILS"));
    assert!(source.contains("metrics.feedback_y + self.scale(12)"));
    assert!(source.contains("metrics.feedback_y + self.scale(34)"));
    assert!(source.contains("feedback_dot"));
    assert!(source.contains("let retry_y = action_y"));
    assert!(source.contains("metrics.content_width - self.scale(90)"));
}

#[test]
fn renderer_repaints_the_parent_and_children_after_resize() {
    let source = include_str!("../src/windows_renderer.rs");
    let (_, resize_handler) = source
        .split_once("WM_SIZE => {")
        .expect("resize message branch must remain discoverable");
    let (resize_handler, _) = resize_handler
        .split_once("WM_PAINT => {")
        .expect("resize message branch must end before painting");
    assert!(resize_handler.contains("(*state).layout();"));
    assert!(resize_handler.contains("(*state).invalidate_children();"));
    assert!(resize_handler.contains("InvalidateRect(hwnd, null(), 1);"));
}

#[test]
fn renderer_matches_the_reference_device_and_support_geometry() {
    let source = include_str!("../src/windows_renderer.rs");
    assert!(source.contains("let support_y = card_bottom - scale(110);"));
    assert!(source.contains("let device_summary_y = device_code_y - scale(26);"));
    assert!(source.contains(".min(scale(96))"));
    assert!(source.contains("device_code_chip"));
    assert!(source.contains("draw_brand_mark"));
    assert!(source.contains(".clamp(64, 140)"));
    assert!(source.contains("control_id == ID_APP_KICKER"));
    assert!(source.contains("control_id == ID_DEVICE_LABEL"));
    assert!(source.contains("control_id == ID_DEVICE_CODE_LABEL"));
}

#[test]
fn renderer_sample_uses_the_reference_dark_theme() {
    let source = include_str!("../src/bin/a-template-windows-renderer.rs");
    assert!(source.contains("ThemeTokens::new(\"#D4B45A\", \"#0C0B09\", \"#F3EEE4\", \"#E85A6F\")"));
}

#[test]
fn renderer_keeps_system_color_refresh_path_product_neutral() {
    let source = include_str!("../src/windows_renderer.rs");
    for marker in [
        "WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE",
        "SPI_GETHIGHCONTRAST",
        "high_contrast_enabled()",
        "GetSysColor(COLOR_WINDOW)",
        "GetSysColor(COLOR_WINDOWTEXT)",
        "refresh_colors()",
    ] {
        assert!(
            source.contains(marker),
            "native renderer is missing the system-color marker: {marker}"
        );
    }

    let (_, color_message_handler) = source
        .split_once("WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {")
        .expect("system-color message branch must remain discoverable");
    let (color_message_handler, _) = color_message_handler
        .split_once("WM_ERASEBKGND => {")
        .expect("system-color message branch must end before background erasure");
    assert!(color_message_handler.contains("(*state).refresh_colors();"));
    assert!(color_message_handler.contains("(*state).invalidate_children();"));
    assert!(color_message_handler.contains("InvalidateRect(hwnd, null(), 1);"));
}

#[cfg(not(windows))]
#[test]
fn renderer_reports_unsupported_platform_without_running_callbacks() {
    let mut renderer = WindowsRenderer::new(WindowsRendererConfig::default(), snapshot()).unwrap();
    let result = renderer.run(|_| {}, |_| {});
    assert_eq!(result, Err(WindowsRendererError::UnsupportedPlatform));
}
