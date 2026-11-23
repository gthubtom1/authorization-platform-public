use std::collections::BTreeMap;

use authorization_a_template::{
    AuthorizationErrorCode, AuthorizationModuleV1, AuthorizationResponseV1, Capability,
    CompatibilityMode, LicenseState, ProductManifest, ThemeTokens, UiAuthorizationSource,
    UiAuthorizationState, UiConnectivity, UiModuleCatalog, UiProfile, UiScreen, UiThemeTokens,
    UiViewState,
};

fn manifest() -> ProductManifest {
    ProductManifest::new(
        "sample-product",
        "Sample Product",
        "sample-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::new("#A7E8D0", "#101A24", "#EDF5F7", "#EF8888"),
        "core/sample.exe",
        "state/sample",
        "a-auth-sample",
        CompatibilityMode::LegacyAuth,
        vec![
            Capability::required("launch", "1"),
            Capability::optional("contact", "1"),
            Capability::optional("purchase", "1"),
            Capability::optional("announcement", "1"),
            Capability::optional("update", "1"),
        ],
    )
}

fn active_response() -> AuthorizationResponseV1 {
    AuthorizationResponseV1::from_json(include_str!(
        "../fixtures/authorization/active.authorization-a-core.v1.json"
    ))
    .unwrap()
}

#[test]
fn ui_profile_round_trips_and_stays_bound_to_manifest() {
    let manifest = manifest();
    let profile = UiProfile::for_manifest(&manifest, "profile-default")
        .with_copy("headline", "Access, kept in one place.")
        .with_enabled_modules(["contact", "purchase"]);

    let shell =
        authorization_a_template::UiShellModel::new(&manifest, &profile, UiViewState::login())
            .unwrap();
    let snapshot = authorization_a_template::UiRenderSnapshot::new(shell, &profile).unwrap();
    assert_eq!(
        snapshot.copy_text("headline"),
        Some("Access, kept in one place.")
    );

    let json = profile.to_json().unwrap();
    let decoded = UiProfile::from_json(&json).unwrap();
    assert_eq!(decoded, profile);
    decoded.validate_for_manifest(&manifest).unwrap();

    let other = ProductManifest::new(
        "other-product",
        "Other Product",
        "other-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        "core/other.exe",
        "state/other",
        "a-auth-other",
        CompatibilityMode::NativeCore,
        vec![Capability::required("launch", "1")],
    );
    assert!(decoded.validate_for_manifest(&other).is_err());
}

#[test]
fn ui_shell_accepts_only_a_bounded_display_device_code() {
    let manifest = manifest();
    let profile = UiProfile::for_manifest(&manifest, "profile-default");
    let shell = authorization_a_template::UiShellModel::new(
        &manifest,
        &profile,
        UiViewState::from_license_state(LicenseState::Active, true).unwrap(),
    )
    .unwrap()
    .with_device_code("  DEMO-DEVICE  ")
    .unwrap();

    assert_eq!(shell.device_code.as_deref(), Some("DEMO-DEVICE"));
    assert!(
        authorization_a_template::UiShellModel::new(&manifest, &profile, UiViewState::login(),)
            .unwrap()
            .with_device_code("\n")
            .is_err()
    );
    assert!(
        authorization_a_template::UiShellModel::new(&manifest, &profile, UiViewState::login(),)
            .unwrap()
            .with_device_code("X".repeat(65))
            .is_err()
    );
}

#[test]
fn ui_profile_rejects_unknown_copy_and_module_values() {
    let unknown_copy = r#"{
        "schema_version":"authorization-a-ui.v1",
        "product_id":"sample-product",
        "profile_id":"profile-default",
        "locale":"en-US",
        "copy":{"server_route":"do-not-render"},
        "enabled_modules":[]
    }"#;
    assert!(UiProfile::from_json(unknown_copy).is_err());

    let unknown_module = r#"{
        "schema_version":"authorization-a-ui.v1",
        "product_id":"sample-product",
        "profile_id":"profile-default",
        "locale":"en-US",
        "copy":{},
        "enabled_modules":["script"]
    }"#;
    assert!(UiProfile::from_json(unknown_module).is_err());
}

#[test]
fn ui_state_matrix_keeps_offline_source_explicit_and_fail_closed() {
    assert_eq!(UiViewState::login().screen, UiScreen::Login);
    assert_eq!(UiViewState::loading().connectivity, UiConnectivity::Loading);

    let active = UiViewState::from_license_state(LicenseState::Active, true).unwrap();
    assert_eq!(active.authorization, UiAuthorizationState::Active);
    assert_eq!(active.source, UiAuthorizationSource::Live);
    assert!(active.can_request_launch());

    let offline_grace = UiViewState::from_license_state(LicenseState::Grace, false).unwrap();
    assert_eq!(offline_grace.connectivity, UiConnectivity::Offline);
    assert_eq!(offline_grace.source, UiAuthorizationSource::Cache);
    assert!(offline_grace.is_offline());
    assert!(offline_grace.can_request_launch());

    for state in [
        LicenseState::Expired,
        LicenseState::Revoked,
        LicenseState::Blocked,
    ] {
        let view = UiViewState::from_license_state(state, true).unwrap();
        assert_eq!(view.screen, UiScreen::Error);
        assert!(!view.can_request_launch());
        if state == LicenseState::Expired {
            assert!(view
                .intents
                .iter()
                .any(|intent| matches!(intent, authorization_a_template::UiIntent::Activate)));
        }
    }

    let unavailable = UiViewState::from_license_state(LicenseState::Unavailable, true).unwrap();
    assert_eq!(unavailable.connectivity, UiConnectivity::Unavailable);
    assert!(unavailable
        .intents
        .iter()
        .any(|intent| matches!(intent, authorization_a_template::UiIntent::Retry)));
    assert!(UiViewState::from_license_state(LicenseState::NotModified, true).is_err());
    assert!(UiViewState::from_license_state_with_context(
        LicenseState::Active,
        UiConnectivity::Unavailable,
        UiAuthorizationSource::None,
    )
    .is_err());
    assert!(!UiViewState::contract_invalid().can_request_launch());
}

#[test]
fn ui_theme_rejects_css_injection_and_exposes_only_source_tokens() {
    let manifest = manifest();
    let theme = UiThemeTokens::from_manifest(&manifest).unwrap();
    let variables = theme.css_variables();
    assert_eq!(variables.get("--a-accent"), Some(&"#A7E8D0".to_string()));
    assert_eq!(variables.len(), 4);

    let unsafe_manifest = ProductManifest::new(
        "sample-product",
        "Sample Product",
        "sample-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::new(
            "red; background:url(secret)",
            "#101A24",
            "#EDF5F7",
            "#EF8888",
        ),
        "core/sample.exe",
        "state/sample",
        "a-auth-sample",
        CompatibilityMode::LegacyAuth,
        vec![Capability::required("launch", "1")],
    );
    assert!(UiThemeTokens::from_manifest(&unsafe_manifest).is_err());
}

#[test]
fn module_catalog_filters_disabled_unknown_and_non_display_fields() {
    let manifest = manifest();
    let profile = UiProfile::for_manifest(&manifest, "profile-default")
        .enable_module("contact")
        .enable_module("update");
    let mut response = active_response();
    response.capabilities.push("contact".to_string());
    response.capabilities.push("update".to_string());

    let mut contact_payload = BTreeMap::new();
    contact_payload.insert("title".to_string(), "Support".to_string());
    contact_payload.insert(
        "contact".to_string(),
        "Use the configured support channel".to_string(),
    );
    contact_payload.insert("url".to_string(), "https://example.invalid".to_string());
    contact_payload.insert("command".to_string(), "start-helper".to_string());
    response.modules.push(
        AuthorizationModuleV1::new(
            response.product_id.clone(),
            response.authorization_id.clone(),
            &response.identity,
            "contact-1",
            "contact",
            "1",
            "contact",
            response.config_version.clone(),
            response.authorization_revision,
            contact_payload,
        )
        .with_structured_device_scope(response.structured_device_scope.clone().unwrap()),
    );

    let mut unknown_payload = BTreeMap::new();
    unknown_payload.insert("title".to_string(), "Hidden".to_string());
    response.modules.push(
        AuthorizationModuleV1::new(
            response.product_id.clone(),
            response.authorization_id.clone(),
            &response.identity,
            "unknown-1",
            "custom_module",
            "1",
            "contact",
            response.config_version.clone(),
            response.authorization_revision,
            unknown_payload,
        )
        .with_structured_device_scope(response.structured_device_scope.clone().unwrap()),
    );

    let catalog = UiModuleCatalog::from_response(&response, &manifest, &profile).unwrap();
    assert_eq!(catalog.entries().len(), 1);
    assert_eq!(catalog.entries()[0].kind.as_str(), "contact");
    assert!(catalog.entries()[0].fields.contains_key("contact"));
    assert!(!catalog.entries()[0].fields.contains_key("url"));
    assert!(!catalog.entries()[0].fields.contains_key("command"));
    assert_eq!(catalog.ignored_module_ids(), &["unknown-1".to_string()]);

    let wrong_profile =
        UiProfile::for_manifest(&manifest, "other-profile").enable_module("contact");
    assert!(UiModuleCatalog::from_response(&response, &manifest, &wrong_profile).is_err());
}

#[test]
fn unbound_generic_core_projection_rejects_module_bearing_responses() {
    let mut response = AuthorizationResponseV1::from_json(include_str!(
        "../fixtures/authorization/structured.active.authorization.v1.json"
    ))
    .unwrap();
    response.capabilities.push("contact".to_string());
    response.modules.push(
        AuthorizationModuleV1::new(
            response.product_id.clone(),
            response.authorization_id.clone(),
            &response.identity,
            "contact-1",
            "contact",
            "1",
            "contact",
            response.config_version.clone(),
            response.authorization_revision,
            BTreeMap::new(),
        )
        .with_structured_device_scope(response.structured_device_scope.clone().unwrap()),
    );

    let error = response.to_core().unwrap_err();
    assert_eq!(error.code(), AuthorizationErrorCode::ResponseSchemaInvalid);
}

#[test]
fn shared_ui_defaults_to_chinese_and_the_flat_prototype_stays_local() {
    let chinese_manifest = ProductManifest::new(
        "sample-product",
        "示例程序",
        "sample-adapter",
        "1.0.0",
        "zh-CN",
        ThemeTokens::new("#3478F6", "#F2F2F7", "#1C1C1E", "#FF3B30"),
        "core/sample.exe",
        "state/sample",
        "a-auth-sample",
        CompatibilityMode::NativeCore,
        vec![Capability::required("launch", "1")],
    );
    let profile = UiProfile::for_manifest(&chinese_manifest, "profile-default");
    assert_eq!(profile.copy_text_or_default("activate"), "立即激活");
    assert_eq!(profile.copy_text_or_default("source_live"), "实时检查");
    assert_eq!(
        profile.copy_text_or_default("scope_current_device"),
        "设备状态"
    );
    let english_manifest = ProductManifest::new(
        "english-product",
        "English Product",
        "english-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        "core/english.exe",
        "state/english",
        "a-english",
        CompatibilityMode::NativeCore,
        vec![Capability::required("launch", "1")],
    );
    let english = UiProfile::for_manifest(&english_manifest, "profile-default");
    assert_eq!(english.copy_text_or_default("activate"), "Activate");

    let html = include_str!("../ui/authorization-a-shell.html");
    let css = include_str!("../ui/authorization-a-shell.css");
    let js = include_str!("../ui/authorization-a-shell.js");
    assert!(html.contains("<html lang=\"zh-CN\">"));
    assert!(html.contains("授权验证"));
    assert!(html.contains("本软件"));
    assert!(!html.contains("GodSkin"));
    assert!(html.contains("app-mark.png"));
    assert!(html.contains("type=\"text\""));
    assert!(!html.contains("type=\"password\""));
    assert!(html.contains("id=\"feedbackPanel\""));
    assert!(!html.contains("id=\"statusView\""));
    assert!(!html.contains("id=\"errorView\""));
    assert!(html.contains("id=\"deviceCode\""));
    assert!(html.contains("点击复制设备码"));
    assert!(html.contains("class=\"page-footer\""));
    assert!(css.contains(".page-footer"));
    assert!(css.contains("border-top: 1px solid var(--a-line)"));
    assert!(!html.contains("id=\"deviceStatus\""));
    assert!(!html.contains("用于授权平台核对"));
    assert!(!html.contains("验证后进入本软件"));
    assert!(!html.contains("验证后进入 GodSkin"));
    assert!(!html.contains("class=\"field-label\""));
    assert!(html.contains("id=\"purchaseLink\""));
    assert!(html.contains("id=\"contactLink\""));
    assert!(html.contains("class=\"prototype-ribbon\" role=\"note\" hidden"));
    assert!(html.contains("class=\"prototype-tools\" hidden"));
    assert!(!html.contains("Access, kept in one place."));
    assert!(css.contains("--a-accent: #d4b45a"));
    assert!(css.contains("--a-surface: #0c0b09"));
    assert!(css.contains("overflow: hidden"));
    assert!(!css.contains("min-height: 700px"));
    assert!(!css.contains("radial-gradient("));
    assert!(!css.contains("linear-gradient("));
    assert!(js.contains("locale: \"zh-CN\""));
    assert!(js.contains("source_recovery"));
    assert!(js.contains("device_mismatch"));
    assert!(js.contains("renderSupportLinks"));
    assert!(js.contains("feedbackPanel.hidden"));
    assert!(js.contains("copyDeviceCode"));
    assert!(js.contains("localStorage"));
    assert!(js.contains("get(\"prototype\") === \"1\""));
    assert!(js.contains("正在打开本软件"));
    assert!(!js.contains("GodSkin"));
    assert!(!js.contains("可以继续使用程序"));
    assert!(!js.contains("fetch("));
    assert!(!js.contains("WebSocket"));
}

#[test]
fn platform_notice_key_maps_to_announcement_card() {
    use authorization_a_template::{
        PlatformAnnouncement, PlatformModules, PlatformSupport, UiModuleKind,
    };
    assert_eq!(
        UiModuleKind::from_module_type("notice"),
        Some(UiModuleKind::Announcement)
    );
    assert_eq!(
        UiModuleKind::from_module_type("announcement"),
        Some(UiModuleKind::Announcement)
    );
    assert_eq!(UiModuleKind::Announcement.platform_key(), "notice");
    let profile = UiProfile::new("sample-product", "stable", "zh-CN")
        .with_enabled_modules(["contact", "notice", "purchase", "qr", "update"]);
    let modules = PlatformModules {
        contact: PlatformSupport {
            purchase_url: Some("https://example.invalid/buy".to_string()),
            qq: None,
            wechat: Some("helper".to_string()),
        },
        notice: PlatformAnnouncement {
            title: Some("note".to_string()),
            body: Some("hello".to_string()),
        },
        purchase_present: false,
        qr_present: false,
        update: None,
    };
    let catalog = UiModuleCatalog::from_platform_modules(&modules, &profile);
    assert_eq!(catalog.entries().len(), 2);
    assert!(catalog.entries().iter().all(
        |entry| entry.kind == UiModuleKind::Contact || entry.kind == UiModuleKind::Announcement
    ));
    let empty = PlatformModules {
        contact: PlatformSupport::default(),
        notice: PlatformAnnouncement::default(),
        purchase_present: false,
        qr_present: false,
        update: None,
    };
    assert!(UiModuleCatalog::from_platform_modules(&empty, &profile).is_empty());
}

#[test]
fn downstream_contact_text_reaches_ui_verbatim_without_additions() {
    use authorization_a_template::{PlatformAnnouncement, PlatformModules, PlatformSupport};
    // Whatever the downstream typed (even text that already looks like a
    // label) must arrive unchanged: no kind prefix, no colon, no trimming.
    let tricky = "微信：abc123 加我注明来意";
    let spaced = "  QQ 12345  ";
    let profile = UiProfile::new("sample-product", "stable", "zh-CN")
        .with_enabled_modules(["contact", "notice"]);
    let modules = PlatformModules {
        contact: PlatformSupport {
            purchase_url: None,
            qq: Some(spaced.to_string()),
            wechat: Some(tricky.to_string()),
        },
        notice: PlatformAnnouncement {
            title: None,
            body: Some(tricky.to_string()),
        },
        purchase_present: false,
        qr_present: false,
        update: None,
    };
    let catalog = UiModuleCatalog::from_platform_modules(&modules, &profile);
    let mut shown: Vec<&str> = catalog
        .entries()
        .iter()
        .flat_map(|entry| entry.fields.values().map(String::as_str))
        .collect();
    shown.sort();
    assert!(shown.contains(&tricky));
    assert!(shown.contains(&spaced));
    for text in shown {
        assert!(!text.starts_with("公告："));
        assert!(!text.starts_with("联系："));
    }
}
