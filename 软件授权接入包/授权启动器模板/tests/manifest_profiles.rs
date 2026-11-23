use std::fs;
use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationSnapshot, Capability, CompatibilityMode, ContractError, LicenseState,
    ProductManifest, ProductProfileStore, ProductRegistry, ProfileStoreError, ThemeTokens,
    MAX_PROFILE_BYTES,
};

fn manifest(
    product_id: &str,
    category: &str,
    locale: &str,
    state_root: &str,
    ipc_name: &str,
) -> ProductManifest {
    ProductManifest::new(
        product_id,
        product_id,
        format!("{product_id}-adapter"),
        "1.0.0",
        locale,
        ThemeTokens::neutral(),
        PathBuf::from(format!("core/{product_id}.exe")),
        PathBuf::from(state_root),
        ipc_name,
        CompatibilityMode::LegacyAuth,
        vec![Capability::required("launch", "1")],
    )
    .with_category(category)
    .with_protocol_parameter("legacy_api", format!("{product_id}.v1"))
}

#[test]
fn two_products_keep_protocol_and_runtime_identity_separate() {
    let skin = manifest(
        "skin-studio",
        "design",
        "zh-CN",
        "state/skin-studio",
        "a-skin",
    );
    let media = manifest(
        "media-tool",
        "media",
        "en-US",
        "state/media-tool",
        "a-media",
    );

    assert_ne!(skin.category, media.category);
    assert_ne!(skin.locale, media.locale);
    assert_ne!(skin.protocol_parameters, media.protocol_parameters);

    let mut registry = ProductRegistry::new();
    registry.register(skin).unwrap();
    registry.register(media).unwrap();
    assert_eq!(registry.len(), 2);
}

#[test]
fn registry_rejects_duplicate_product_state_and_ipc_identity() {
    let first = manifest("skin-studio", "design", "zh-CN", "state/shared", "a-shared");
    let same_product = manifest("skin-studio", "other", "en-US", "state/other", "a-other");
    let same_state = manifest("media-tool", "media", "en-US", "state/shared", "a-media");
    let same_ipc = manifest(
        "report-tool",
        "reports",
        "en-US",
        "state/reports",
        "a-shared",
    );

    let mut registry = ProductRegistry::new();
    registry.register(first).unwrap();

    assert!(matches!(
        registry.register(same_product),
        Err(ContractError::DuplicateProductId(_))
    ));
    assert!(matches!(
        registry.register(same_state),
        Err(ContractError::DuplicateStateRoot { .. })
    ));
    assert!(matches!(
        registry.register(same_ipc),
        Err(ContractError::DuplicateIpcName { .. })
    ));
}

#[test]
fn manifest_validation_rejects_unsafe_or_incomplete_values() {
    let invalid = ProductManifest::new(
        "Bad Product",
        "",
        "adapter",
        "1.0.0",
        "not a locale",
        ThemeTokens::new("", "#fff", "#111", "#f00"),
        PathBuf::from("..\\core.exe"),
        PathBuf::from("state/bad"),
        "bad ipc",
        CompatibilityMode::LegacyAuth,
        Vec::new(),
    );

    assert!(invalid.validate().is_err());
}

#[test]
fn snapshot_is_bound_to_the_manifest_product() {
    let skin = manifest("skin-studio", "design", "zh-CN", "state/skin", "a-skin");
    let media = manifest("media-tool", "media", "en-US", "state/media", "a-media");
    let snapshot = AuthorizationSnapshot::new(
        "skin-studio",
        "snapshot-1",
        "subject-1",
        "device-1",
        LicenseState::Active,
        1,
        None,
        vec!["launch".to_string()],
        Vec::new(),
    );

    assert!(snapshot.validate_for(&skin).is_ok());
    assert!(matches!(
        snapshot.validate_for(&media),
        Err(ContractError::ProductMismatch { .. })
    ));
}

#[test]
fn persisted_profiles_use_the_same_validation_and_registry_path() {
    let store =
        ProductProfileStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"));
    let skin = store
        .load_manifest("profiles/sample-product-a.json")
        .unwrap();
    let media = store
        .load_manifest("profiles/sample-product-b.json")
        .unwrap();
    let registry = store
        .load_registry([
            "profiles/sample-product-a.json",
            "profiles/sample-product-b.json",
        ])
        .unwrap();

    assert_eq!(skin.product_id, "sample-product-a");
    assert_eq!(media.product_id, "sample-product-b");
    assert_eq!(registry.len(), 2);
    assert_ne!(skin.state_root, media.state_root);
    assert_ne!(skin.ipc_name, media.ipc_name);
}

#[test]
fn malformed_and_cross_product_profiles_fail_closed() {
    let store =
        ProductProfileStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"));

    assert!(matches!(
        store.load_manifest("profiles/malformed.json"),
        Err(ProfileStoreError::Contract(ContractError::InvalidManifest(
            _
        )))
    ));
    assert!(matches!(
        store.load_manifest_for("profiles/sample-product-b.json", "sample-product-a"),
        Err(ProfileStoreError::Contract(
            ContractError::ProductMismatch { .. }
        ))
    ));
    assert!(matches!(
        store.load_manifest("../Cargo.toml"),
        Err(ProfileStoreError::InvalidPath(_))
    ));
}

#[test]
fn manifest_json_round_trip_is_deterministic_and_validated() {
    let original = manifest(
        "round-trip",
        "tools",
        "en-US",
        "state/round-trip",
        "a-round-trip",
    );
    let json = original.to_json().unwrap();
    let decoded = ProductManifest::from_json(&json).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(decoded.to_json().unwrap(), json);
}

#[test]
fn unknown_or_duplicate_json_fields_are_rejected() {
    let unknown = r#"{
      "schema_version":"product-manifest.v1",
      "product_id":"skin-studio",
      "unexpected":true
    }"#;
    let duplicate = r#"{
      "schema_version":"product-manifest.v1",
      "schema_version":"product-manifest.v1"
    }"#;

    assert!(ProductManifest::from_json(unknown).is_err());
    assert!(ProductManifest::from_json(duplicate).is_err());
}

#[test]
fn profile_store_rejects_oversized_files_before_parsing() {
    let root = std::env::temp_dir().join(format!(
        "authorization-a-template-profile-limit-{}",
        std::process::id()
    ));
    assert!(!root.exists(), "test directory unexpectedly already exists");
    fs::create_dir_all(&root).unwrap();
    let profile_path = root.join("oversized.json");
    fs::write(&profile_path, vec![b' '; MAX_PROFILE_BYTES + 1]).unwrap();

    let result = ProductProfileStore::new(&root).load_manifest("oversized.json");
    assert!(matches!(
        result,
        Err(ProfileStoreError::ProfileTooLarge { .. })
    ));

    fs::remove_file(profile_path).unwrap();
    fs::remove_dir(root).unwrap();
}
