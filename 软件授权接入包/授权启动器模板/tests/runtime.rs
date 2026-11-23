use std::path::PathBuf;

use authorization_a_template::runtime as runtime_module;
use authorization_a_template::{
    AdapterRegistry, AuthorizationSnapshot, Capability, CompatibilityMode, EnvironmentCatalog,
    EnvironmentKind, EnvironmentProfile, LicenseState, ProductManifest, RetryClass, RetryDecision,
    RetryPolicy, RuntimeError, SimulatedLegacyAuthAdapter, ThemeTokens,
};

fn manifest(product_id: &str, adapter_id: &str, adapter_version: &str) -> ProductManifest {
    ProductManifest::new(
        product_id,
        format!("{product_id} display"),
        adapter_id,
        adapter_version,
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from(format!("core/{product_id}.exe")),
        PathBuf::from(format!("state/{product_id}")),
        format!("a-auth-{product_id}"),
        CompatibilityMode::LegacyAuth,
        vec![Capability::required("launch", "1")],
    )
}

fn snapshot(product_id: &str) -> AuthorizationSnapshot {
    AuthorizationSnapshot::new(
        product_id,
        format!("snapshot-{product_id}"),
        format!("subject-{product_id}"),
        format!("device-{product_id}"),
        LicenseState::Active,
        1_755_000_000,
        None,
        vec!["launch".to_string()],
        Vec::new(),
    )
}

#[test]
fn environment_profiles_are_versioned_and_switch_by_configuration() {
    let test = EnvironmentProfile::test("test-local", "http://127.0.0.1:8789");
    let production = EnvironmentProfile::production("prod", "https://license.example.invalid/v1");
    assert_eq!(test.kind, EnvironmentKind::Test);
    assert_eq!(production.kind, EnvironmentKind::Production);
    assert_eq!(runtime_module::EnvironmentKind::Test, EnvironmentKind::Test);
    assert_eq!(
        runtime_module::EnvironmentProfile::test("module-path", "http://127.0.0.1"),
        EnvironmentProfile::test("module-path", "http://127.0.0.1")
    );
    test.validate().unwrap();
    production.validate().unwrap();

    let mut catalog = EnvironmentCatalog::new();
    catalog.register(test.clone()).unwrap();
    catalog.register(production.clone()).unwrap();
    assert_eq!(catalog.len(), 2);
    assert_eq!(catalog.require("prod").unwrap(), &production);
    assert_eq!(catalog.require("test-local").unwrap(), &test);
}

#[test]
fn environment_validation_rejects_production_http_and_embedded_credentials() {
    let http_production = EnvironmentProfile::production("prod", "http://license.example.invalid");
    assert!(matches!(
        http_production.validate(),
        Err(RuntimeError::InvalidEnvironment(_))
    ));

    let credential_endpoint = EnvironmentProfile::test(
        "test-local",
        "https://license.example.invalid/auth?token=should-not-be-here",
    );
    assert!(matches!(
        credential_endpoint.validate(),
        Err(RuntimeError::InvalidEnvironment(_))
    ));

    let malformed_endpoint = EnvironmentProfile::test("test-local", "https://");
    assert!(matches!(
        malformed_endpoint.validate(),
        Err(RuntimeError::InvalidEnvironment(_))
    ));

    let userinfo_endpoint =
        EnvironmentProfile::test("test-local", "https://user:pass@example.invalid");
    assert!(matches!(
        userinfo_endpoint.validate(),
        Err(RuntimeError::InvalidEnvironment(_))
    ));
}

#[test]
fn retry_policy_is_bounded_and_does_not_retry_permanent_failures() {
    let policy = RetryPolicy {
        max_attempts: 3,
        initial_backoff_ms: 100,
        max_backoff_ms: 250,
    };
    assert_eq!(
        policy.decision(0, RetryClass::Transient),
        RetryDecision::Retry {
            next_attempt: 1,
            backoff_ms: 100
        }
    );
    assert_eq!(
        policy.decision(1, RetryClass::Transient),
        RetryDecision::Retry {
            next_attempt: 2,
            backoff_ms: 200
        }
    );
    assert_eq!(
        policy.decision(2, RetryClass::Transient),
        RetryDecision::Unavailable
    );
    assert_eq!(
        policy.decision(0, RetryClass::Permanent),
        RetryDecision::Stop
    );
    assert!(policy.validate().is_ok());
}

#[test]
fn adapter_registry_resolves_by_version_without_product_branches() {
    let skin_manifest = manifest("skin-studio", "skin-bridge", "1.0.0");
    let media_manifest = manifest("media-tool", "media-bridge", "2.1.0");
    let mut registry = AdapterRegistry::new();
    registry
        .register(SimulatedLegacyAuthAdapter::new(
            "skin-bridge",
            "1.0.0",
            "legacy.authorization.v1",
        ))
        .unwrap();
    registry
        .register(SimulatedLegacyAuthAdapter::new(
            "media-bridge",
            "2.1.0",
            "legacy.authorization.v2",
        ))
        .unwrap();

    assert_eq!(registry.len(), 2);
    assert!(registry.contains("skin-bridge", "1.0.0"));
    assert!(registry.contains("media-bridge", "2.1.0"));
    assert_eq!(
        registry
            .adapt(&skin_manifest, &snapshot("skin-studio"))
            .unwrap()
            .legacy_protocol,
        "legacy.authorization.v1"
    );
    assert_eq!(
        registry
            .adapt(&media_manifest, &snapshot("media-tool"))
            .unwrap()
            .legacy_protocol,
        "legacy.authorization.v2"
    );
}

#[test]
fn adapter_registry_rejects_duplicate_and_missing_identities() {
    let adapter =
        SimulatedLegacyAuthAdapter::new("skin-bridge", "1.0.0", "legacy.authorization.v1");
    let mut registry = AdapterRegistry::new();
    registry.register(adapter.clone()).unwrap();
    assert!(matches!(
        registry.register(adapter),
        Err(RuntimeError::DuplicateAdapter { .. })
    ));

    let missing = manifest("skin-studio", "unknown-bridge", "1.0.0");
    assert!(matches!(
        registry.resolve(&missing),
        Err(RuntimeError::AdapterNotFound { .. })
    ));
}

#[test]
fn default_environment_is_online_only_with_zero_offline_grace() {
    // Platform default: offline_grace_seconds = 0. A wider grace is an
    // explicit per-product choice via with_cache_policy, never the default.
    let profile = EnvironmentProfile::production("prod", "https://license.example.invalid/v1");
    assert_eq!(profile.offline_grace_secs, 0);
    let widened = EnvironmentProfile::production("prod", "https://license.example.invalid/v1")
        .with_cache_policy(15 * 60, 5 * 60);
    assert_eq!(widened.offline_grace_secs, 5 * 60);
}
