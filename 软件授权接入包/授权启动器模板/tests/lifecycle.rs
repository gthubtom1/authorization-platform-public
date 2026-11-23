use std::path::PathBuf;

use authorization_a_template::{
    AdapterRegistry, AuthorizationSnapshot, Capability, CloudError, CompatibilityMode,
    ContractError, DeviceBinding, LicenseState, LifecycleError, LifecycleStateMachine,
    MockCloudClient, ProductManifest, SimulatedLegacyAuthAdapter, SnapshotApplyOutcome,
    ThemeTokens,
};

fn manifest(product_id: &str) -> ProductManifest {
    ProductManifest::new(
        product_id,
        format!("{product_id} display"),
        format!("{product_id}-adapter"),
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from(format!("core/{product_id}.exe")),
        PathBuf::from(format!("state/{product_id}")),
        format!("a-auth-{product_id}"),
        CompatibilityMode::LegacyAuth,
        vec![Capability::required("launch", "1")],
    )
}

fn snapshot(
    product_id: &str,
    snapshot_id: &str,
    subject_id: &str,
    device_id: &str,
    state: LicenseState,
    issued_at: u64,
) -> AuthorizationSnapshot {
    AuthorizationSnapshot::new(
        product_id,
        snapshot_id,
        subject_id,
        device_id,
        state,
        issued_at,
        None,
        vec!["launch".to_string()],
        Vec::new(),
    )
}

#[test]
fn lifecycle_states_have_explicit_launch_behavior() {
    for (state, launchable) in [
        (LicenseState::Active, true),
        (LicenseState::Grace, true),
        (LicenseState::Expired, false),
        (LicenseState::Revoked, false),
        (LicenseState::Unavailable, false),
    ] {
        let product = manifest("skin-studio");
        let mut machine = LifecycleStateMachine::new(product, "device-1").unwrap();
        machine
            .apply_snapshot(snapshot(
                "skin-studio",
                state.as_str(),
                "subject-1",
                "device-1",
                state,
                10,
            ))
            .unwrap();

        assert_eq!(machine.state(), state);
        assert_eq!(machine.can_launch_at(10), launchable);
    }
}

#[test]
fn cloud_sync_is_scoped_to_product_subject_and_device() {
    let mut cloud = MockCloudClient::new();
    cloud
        .set_snapshot(snapshot(
            "skin-studio",
            "skin-1",
            "subject-1",
            "device-1",
            LicenseState::Active,
            10,
        ))
        .unwrap();
    cloud
        .set_snapshot(snapshot(
            "media-tool",
            "media-1",
            "subject-1",
            "device-1",
            LicenseState::Grace,
            10,
        ))
        .unwrap();

    let mut skin = LifecycleStateMachine::new(manifest("skin-studio"), "device-1").unwrap();
    let mut media = LifecycleStateMachine::new(manifest("media-tool"), "device-1").unwrap();
    skin.synchronize(&mut cloud, "subject-1").unwrap();
    media.synchronize(&mut cloud, "subject-1").unwrap();

    assert_eq!(skin.state(), LicenseState::Active);
    assert_eq!(media.state(), LicenseState::Grace);
    assert_ne!(
        skin.snapshot().unwrap().product_id,
        media.snapshot().unwrap().product_id
    );

    let mut wrong_device = LifecycleStateMachine::new(manifest("skin-studio"), "device-2").unwrap();
    assert!(matches!(
        wrong_device.synchronize(&mut cloud, "subject-1"),
        Err(LifecycleError::Cloud(CloudError::Unavailable))
    ));
    assert_eq!(wrong_device.state(), LicenseState::Unavailable);
}

#[test]
fn same_snapshot_is_idempotent_and_older_snapshot_is_rejected() {
    let product = manifest("skin-studio");
    let mut machine = LifecycleStateMachine::new(product, "device-1").unwrap();
    let current = snapshot(
        "skin-studio",
        "snapshot-2",
        "subject-1",
        "device-1",
        LicenseState::Active,
        20,
    );

    assert_eq!(
        machine.apply_snapshot(current.clone()).unwrap(),
        SnapshotApplyOutcome::Applied
    );
    assert_eq!(
        machine.apply_snapshot(current).unwrap(),
        SnapshotApplyOutcome::Idempotent
    );

    let older = snapshot(
        "skin-studio",
        "snapshot-1",
        "subject-1",
        "device-1",
        LicenseState::Grace,
        19,
    );
    assert!(matches!(
        machine.apply_snapshot(older),
        Err(LifecycleError::StaleSnapshot { .. })
    ));

    let conflicting = snapshot(
        "skin-studio",
        "snapshot-2",
        "subject-1",
        "device-1",
        LicenseState::Revoked,
        20,
    );
    assert!(matches!(
        machine.apply_snapshot(conflicting),
        Err(LifecycleError::SnapshotConflict { .. })
    ));
}

#[test]
fn device_and_product_mismatches_fail_closed() {
    let mut machine = LifecycleStateMachine::new(manifest("skin-studio"), "device-1").unwrap();
    assert!(matches!(
        machine.apply_snapshot(snapshot(
            "skin-studio",
            "snapshot-1",
            "subject-1",
            "device-2",
            LicenseState::Active,
            1,
        )),
        Err(LifecycleError::DeviceMismatch { .. })
    ));
    assert!(matches!(
        machine.apply_snapshot(snapshot(
            "media-tool",
            "snapshot-2",
            "subject-1",
            "device-1",
            LicenseState::Active,
            2,
        )),
        Err(LifecycleError::ProductMismatch { .. })
    ));

    let binding = DeviceBinding::new("skin-studio", "device-1").unwrap();
    assert!(binding.validate_device("device-1").is_ok());
    assert!(binding.validate_device("device-2").is_err());
}

#[test]
fn expiry_is_evaluated_without_mutating_the_cloud_snapshot() {
    let product = manifest("skin-studio");
    let mut machine = LifecycleStateMachine::new(product, "device-1").unwrap();
    let mut current = snapshot(
        "skin-studio",
        "snapshot-expiring",
        "subject-1",
        "device-1",
        LicenseState::Active,
        10,
    );
    current.expires_at = Some(20);
    machine.apply_snapshot(current).unwrap();

    assert_eq!(machine.state_at(19), LicenseState::Active);
    assert_eq!(machine.state_at(20), LicenseState::Expired);
    assert!(!machine.can_launch_at(20));
    assert_eq!(
        machine.snapshot().unwrap().license_state,
        LicenseState::Active
    );
}

#[test]
fn unavailable_cloud_response_changes_runtime_state_and_is_recoverable() {
    let mut cloud = MockCloudClient::new();
    cloud
        .set_snapshot(snapshot(
            "skin-studio",
            "snapshot-1",
            "subject-1",
            "device-1",
            LicenseState::Active,
            1,
        ))
        .unwrap();
    let mut machine = LifecycleStateMachine::new(manifest("skin-studio"), "device-1").unwrap();
    machine.synchronize(&mut cloud, "subject-1").unwrap();

    cloud
        .set_unavailable("skin-studio", "subject-1", "device-1")
        .unwrap();
    assert!(matches!(
        machine.synchronize(&mut cloud, "subject-1"),
        Err(LifecycleError::Cloud(CloudError::Unavailable))
    ));
    assert_eq!(machine.state(), LicenseState::Unavailable);

    cloud
        .set_snapshot(snapshot(
            "skin-studio",
            "snapshot-2",
            "subject-1",
            "device-1",
            LicenseState::Grace,
            2,
        ))
        .unwrap();
    machine.synchronize(&mut cloud, "subject-1").unwrap();
    assert_eq!(machine.state(), LicenseState::Grace);
}

#[test]
fn lifecycle_controls_legacy_handoff_and_blocks_expired_active_snapshots() {
    let mut registry = AdapterRegistry::new();
    registry
        .register(SimulatedLegacyAuthAdapter::new(
            "skin-studio-adapter",
            "1.0.0",
            "legacy.authorization.v1",
        ))
        .unwrap();
    let product = manifest("skin-studio");
    let mut machine = LifecycleStateMachine::new(product, "device-1").unwrap();

    let mut active = snapshot(
        "skin-studio",
        "snapshot-active",
        "subject-1",
        "device-1",
        LicenseState::Active,
        10,
    );
    active.expires_at = Some(20);
    machine.apply_snapshot(active).unwrap();
    assert!(machine.adapt_with_registry(&registry, 19).unwrap().granted);
    assert!(matches!(
        machine.adapt_with_registry(&registry, 20),
        Err(LifecycleError::Contract(
            ContractError::AuthorizationRejected {
                state: LicenseState::Expired,
                ..
            }
        ))
    ));

    machine
        .apply_snapshot(snapshot(
            "skin-studio",
            "snapshot-revoked",
            "subject-1",
            "device-1",
            LicenseState::Revoked,
            21,
        ))
        .unwrap();
    assert!(matches!(
        machine.adapt_with_registry(&registry, 21),
        Err(LifecycleError::Contract(
            ContractError::AuthorizationRejected {
                state: LicenseState::Revoked,
                ..
            }
        ))
    ));
}

#[test]
fn revoked_state_requires_explicit_reauthorization_before_new_grant() {
    let mut machine = LifecycleStateMachine::new(manifest("skin-studio"), "device-1").unwrap();
    machine
        .apply_snapshot(snapshot(
            "skin-studio",
            "snapshot-revoked",
            "subject-1",
            "device-1",
            LicenseState::Revoked,
            10,
        ))
        .unwrap();

    let new_grant = snapshot(
        "skin-studio",
        "snapshot-new-grant",
        "subject-1",
        "device-1",
        LicenseState::Active,
        11,
    );
    assert!(matches!(
        machine.apply_snapshot(new_grant.clone()),
        Err(LifecycleError::InvalidTransition {
            from: LicenseState::Revoked,
            to: LicenseState::Active,
        })
    ));

    machine.begin_reauthorization().unwrap();
    assert_eq!(machine.state(), LicenseState::Unavailable);
    assert_eq!(
        machine.apply_snapshot(new_grant).unwrap(),
        SnapshotApplyOutcome::Applied
    );
    assert_eq!(machine.state(), LicenseState::Active);
}

#[test]
fn invalid_cloud_snapshots_do_not_cross_the_contract_boundary() {
    let product = manifest("skin-studio");
    let mut machine = LifecycleStateMachine::new(product, "device-1").unwrap();
    let mut invalid = snapshot(
        "skin-studio",
        "snapshot-invalid",
        "subject-1",
        "device-1",
        LicenseState::Active,
        1,
    );
    invalid.capabilities.push("unknown".to_string());
    assert!(matches!(
        machine.apply_snapshot(invalid),
        Err(LifecycleError::Contract(
            ContractError::CapabilityNotDeclared(_)
        ))
    ));
}

#[test]
fn required_capabilities_must_be_granted_before_handoff() {
    let product = manifest("skin-studio");
    let mut machine = LifecycleStateMachine::new(product, "device-1").unwrap();
    let snapshot = AuthorizationSnapshot::new(
        "skin-studio",
        "snapshot-without-launch",
        "subject-1",
        "device-1",
        LicenseState::Active,
        1,
        None,
        Vec::new(),
        Vec::new(),
    );

    assert!(matches!(
        machine.apply_snapshot(snapshot),
        Err(LifecycleError::Contract(
            ContractError::RequiredCapabilityMissing(capability)
        )) if capability == "launch"
    ));
    assert_eq!(machine.state(), LicenseState::Unavailable);
}
