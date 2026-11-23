use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationSnapshot, Capability, CompatibilityMode, CompatibilityVerification, ContractError,
    LegacyAuthAdapter, LicenseState, ProductManifest, SimulatedLegacyAuthAdapter, ThemeTokens,
};

fn manifest() -> ProductManifest {
    ProductManifest::new(
        "skin-studio",
        "Skin Studio",
        "skin-legacy-bridge",
        "1.0.0",
        "zh-CN",
        ThemeTokens::neutral(),
        PathBuf::from("core/skin.exe"),
        PathBuf::from("state/skin"),
        "a-skin",
        CompatibilityMode::LegacyAuth,
        vec![Capability::required("launch", "1")],
    )
    .with_category("design")
}

fn snapshot(state: LicenseState) -> AuthorizationSnapshot {
    AuthorizationSnapshot::new(
        "skin-studio",
        "snapshot-1",
        "subject-1",
        "device-1",
        state,
        1,
        None,
        vec!["launch".to_string()],
        Vec::new(),
    )
}

#[test]
fn active_and_grace_states_create_simulated_legacy_grants() {
    let manifest = manifest();
    let adapter =
        SimulatedLegacyAuthAdapter::new("skin-legacy-bridge", "1.0.0", "legacy.authorization.v1");

    for state in [LicenseState::Active, LicenseState::Grace] {
        let result = adapter.adapt(&manifest, &snapshot(state)).unwrap();
        assert!(result.granted);
        assert_eq!(result.license_state, state);
        assert_eq!(
            result.compatibility,
            CompatibilityVerification::RealExeUnverified
        );
        assert!(!result.real_exe_compatibility_verified());
        assert!(!result.exposes_raw_credential());
        assert!(result
            .legacy_parameters
            .get("authorization_handle")
            .is_some_and(|value| value.starts_with("simulated-grant-")));
    }
}

#[test]
fn rejected_states_never_reach_the_legacy_contract() {
    let manifest = manifest();
    let adapter =
        SimulatedLegacyAuthAdapter::new("skin-legacy-bridge", "1.0.0", "legacy.authorization.v1");

    for state in [
        LicenseState::Expired,
        LicenseState::Revoked,
        LicenseState::Unavailable,
    ] {
        assert!(matches!(
            adapter.adapt(&manifest, &snapshot(state)),
            Err(ContractError::AuthorizationRejected { .. })
        ));
    }
}

#[test]
fn simulated_result_does_not_copy_a_raw_card_key() {
    let manifest = manifest();
    let adapter =
        SimulatedLegacyAuthAdapter::new("skin-legacy-bridge", "1.0.0", "legacy.authorization.v1");
    let mut snapshot = snapshot(LicenseState::Active);
    snapshot.subject_id = "CARD-DO-NOT-FORWARD".to_string();

    let result = adapter.adapt(&manifest, &snapshot).unwrap();
    let debug = format!("{result:?}");
    assert!(!debug.contains("CARD-DO-NOT-FORWARD"));
    assert!(!result.exposes_raw_credential());
}

#[test]
fn adapter_identity_is_product_specific() {
    let manifest = manifest();
    let wrong_adapter =
        SimulatedLegacyAuthAdapter::new("other-legacy-bridge", "1.0.0", "legacy.authorization.v1");

    assert!(matches!(
        wrong_adapter.adapt(&manifest, &snapshot(LicenseState::Active)),
        Err(ContractError::AdapterMismatch { .. })
    ));
}
