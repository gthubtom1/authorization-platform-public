use std::collections::BTreeMap;
use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationSnapshot, Capability, CompatibilityMode, LegacyAuthAdapter, LicenseState,
    ModuleEnvelope, ProductManifest, ProductRegistry, SimulatedLegacyAuthAdapter, ThemeTokens,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ProductRegistry::new();

    let skin_manifest = ProductManifest::new(
        "sample-product-a",
        "示例软件A",
        "sample-legacy-bridge-a",
        "1.0.0",
        "zh-CN",
        ThemeTokens::new("#7C3AED", "#111827", "#F9FAFB", "#F43F5E"),
        PathBuf::from("core/sample-a.exe"),
        PathBuf::from("state/sample-a"),
        "a-auth-sample-a",
        CompatibilityMode::LegacyAuth,
        vec![
            Capability::required("launch", "1"),
            Capability::optional("updates", "1"),
        ],
    )
    .with_category("design")
    .with_protocol_parameter("legacy_api", "authorization.v1")
    .with_protocol_parameter("channel", "stable");

    let media_manifest = ProductManifest::new(
        "sample-product-b",
        "示例软件B",
        "sample-legacy-bridge-b",
        "2.1.0",
        "en-US",
        ThemeTokens::new("#0EA5E9", "#0F172A", "#E0F2FE", "#FB7185"),
        PathBuf::from("core/sample-b.exe"),
        PathBuf::from("state/sample-b"),
        "a-auth-sample-b",
        CompatibilityMode::LegacyAuth,
        vec![
            Capability::required("launch", "1"),
            Capability::required("notices", "2"),
        ],
    )
    .with_category("media")
    .with_protocol_parameter("legacy_api", "authorization.v2")
    .with_protocol_parameter("channel", "beta");

    registry.register(skin_manifest.clone())?;
    registry.register(media_manifest.clone())?;

    let mut updates = BTreeMap::new();
    updates.insert("channel".to_string(), "stable".to_string());
    updates.insert("version".to_string(), "2026.08".to_string());
    let skin_module = ModuleEnvelope::new(
        "sample-product-a",
        "update-metadata",
        "1.0.0",
        "updates",
        updates,
    );
    let skin_snapshot = AuthorizationSnapshot::new(
        "sample-product-a",
        "snapshot-sample-a-001",
        "customer-sample-a-001",
        "device-sample-a-001",
        LicenseState::Active,
        1_755_000_000,
        None,
        vec!["launch".to_string(), "updates".to_string()],
        vec![skin_module],
    );

    let media_snapshot = AuthorizationSnapshot::new(
        "sample-product-b",
        "snapshot-sample-b-001",
        "customer-sample-b-001",
        "device-sample-b-001",
        LicenseState::Grace,
        1_755_000_000,
        None,
        vec!["launch".to_string(), "notices".to_string()],
        Vec::new(),
    );

    let skin_adapter = SimulatedLegacyAuthAdapter::new(
        "sample-legacy-bridge-a",
        "1.0.0",
        "legacy.authorization.v1",
    );
    let media_adapter = SimulatedLegacyAuthAdapter::new(
        "sample-legacy-bridge-b",
        "2.1.0",
        "legacy.authorization.v2",
    );
    let skin_result = skin_adapter.adapt(&skin_manifest, &skin_snapshot)?;
    let media_result = media_adapter.adapt(&media_manifest, &media_snapshot)?;

    println!("a-core.v1 simulation; authorization-a-core.v1 formal contract available");
    println!("registered products: {}", registry.len());
    println!(
        "{}: category={}, locale={}, state_root={}, ipc={}, granted={}, real_exe_verified={}",
        skin_manifest.product_id,
        skin_manifest.category,
        skin_manifest.locale,
        skin_manifest.state_root.display(),
        skin_manifest.ipc_name,
        skin_result.granted,
        skin_result.real_exe_compatibility_verified()
    );
    println!(
        "{}: category={}, locale={}, state_root={}, ipc={}, granted={}, state={}",
        media_manifest.product_id,
        media_manifest.category,
        media_manifest.locale,
        media_manifest.state_root.display(),
        media_manifest.ipc_name,
        media_result.granted,
        media_result.license_state.as_str()
    );
    println!(
        "raw credential exposed: {}",
        skin_result.exposes_raw_credential()
    );
    Ok(())
}
