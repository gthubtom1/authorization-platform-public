#[cfg(windows)]
use authorization_a_template::WindowsCredentialVault;
use authorization_a_template::{
    AuthorizationBinding, AuthorizationIdentity, AuthorizationResponseV1, CompatibilityMode,
    CredentialRecovery, CredentialRecoveryState, CredentialVault, CredentialVaultAddress,
    CredentialVaultScope, IntegrityProof, LicenseState, MemoryCredentialVault,
    MockIntegrityVerifier, ProductManifest, SecretValue, ThemeTokens, UnsupportedCredentialVault,
    VerifiedCredentialRecord,
};
use std::path::PathBuf;

fn manifest() -> ProductManifest {
    ProductManifest::new(
        "product-a",
        "Product A",
        "adapter-generic",
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from("core/product-a.exe"),
        PathBuf::from("state/product-a"),
        "a-auth-product-a",
        CompatibilityMode::LegacyAuth,
        vec![authorization_a_template::Capability::required(
            "launch", "1",
        )],
    )
}

fn binding() -> AuthorizationBinding {
    AuthorizationBinding::new(
        "product-a",
        AuthorizationIdentity::new(
            "software-generic",
            "profile-default",
            "client-1",
            "current_device",
            "device-1",
        ),
    )
}

fn verified_response(
    decision: LicenseState,
) -> (
    AuthorizationResponseV1,
    MockIntegrityVerifier,
    ProductManifest,
    AuthorizationBinding,
) {
    let product_manifest = manifest();
    let product_binding = binding();
    let request = authorization_a_template::AuthorizationRequestV1::new(
        "request-1",
        &product_binding,
        "config-7",
        None,
    )
    .with_target_arch_channel("windows", "x86_64", "stable");
    let response = AuthorizationResponseV1::new_cloud(
        &request,
        "authorization-1",
        "snapshot-1",
        decision,
        7,
        100,
        7,
        Some(200),
        Some(160),
        Some(160),
        Some(180),
        IntegrityProof::new("ed25519", "a-key-1", "JCS-RFC8785", "a-signature-1")
            .with_origin_audience("authorization-a", "authorization-a-core"),
        vec!["launch".to_string()],
        Vec::new(),
    )
    .with_structured_device_scope(
        authorization_a_template::StructuredDeviceScopeV1::current_device(
            "device-1",
            Some("installation-1"),
        ),
    )
    .to_core()
    .expect("fixture response converts to the local contract");
    let mut verifier = MockIntegrityVerifier::new();
    verifier
        .allow(&response.integrity, response.canonical_payload())
        .expect("fixture response is registered");
    (response, verifier, product_manifest, product_binding)
}

#[test]
fn recovery_round_trip_is_os_vault_shaped_and_never_authorizes_by_presence() {
    let (response, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let verified = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &response,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-only-in-secure-storage",
        Some("device-token-1"),
    )
    .expect("active verified response creates a recovery record");
    let address = verified.record().scope.address.clone();
    let vault = MemoryCredentialVault::default();
    let recovery = CredentialRecovery::new(vault.clone());

    assert_eq!(
        recovery.startup(&address).unwrap(),
        CredentialRecoveryState::LoginRequired
    );
    recovery.save_verified(&address, &verified).unwrap();
    let state = recovery.startup(&address).unwrap();
    let CredentialRecoveryState::VerifyCachedCredential(cached) = state else {
        panic!("saved credential should be offered only for server verification");
    };
    cached.with_request_material(|scope, credential, device_token| {
        assert_eq!(scope, &verified.record().scope);
        assert_eq!(
            credential.with_bytes(|bytes| bytes.to_vec()),
            b"license-key-only-in-secure-storage"
        );
        assert_eq!(
            device_token
                .expect("device token is cached")
                .with_bytes(|bytes| bytes.to_vec()),
            b"device-token-1"
        );
    });
    assert!(cached.is_within_recorded_expiry(150));
    assert!(!cached.is_within_recorded_expiry(200));
    let debug = format!("{cached:?}");
    assert!(!debug.contains("license-key-only-in-secure-storage"));
    assert!(!debug.contains("device-token-1"));

    recovery.clear(&address).unwrap();
    assert_eq!(
        recovery.startup(&address).unwrap(),
        CredentialRecoveryState::LoginRequired
    );
}

#[test]
fn vault_scope_contains_server_binding_and_config_version_but_no_ip_claim() {
    let (response, _, _, _) = verified_response(LicenseState::Active);
    let scope = CredentialVaultScope::from_response("test-local", &response).unwrap();
    assert_eq!(scope.authorization_id, "authorization-1");
    assert_eq!(scope.device_scope, "current_device");
    assert_eq!(scope.device_id, "device-1");
    assert_eq!(scope.installation_id, "installation-1");
    assert_eq!(scope.config_version, "config-7");
    assert!(!response.to_json().contains("\"ip_address\""));
    assert!(!response.to_json().contains("\"client_ip\""));
    let request = authorization_a_template::AuthorizationRequestV1::new(
        "request-1",
        &binding(),
        "config-7",
        None,
    );
    assert!(!request.to_json().contains("\"ip_address\""));
    assert!(!request.to_json().contains("\"client_ip\""));

    let mut changed = response.clone();
    changed.config_version = "config-8".to_string();
    assert!(!scope
        .matches_response("test-local", &changed)
        .expect("changed response remains structurally readable"));
}

#[test]
fn different_client_or_environment_cannot_reuse_a_cached_record() {
    let (response, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let verified = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &response,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-1",
        None,
    )
    .unwrap();
    let address = verified.record().scope.address.clone();
    let vault = MemoryCredentialVault::default();
    vault.save(&address, &verified).unwrap();

    let other_client = CredentialVaultAddress::new(
        "test-local",
        "product-a",
        "software-generic",
        "profile-default",
        "client-2",
    );
    assert_eq!(vault.load(&other_client).unwrap(), None);
    let other_environment = CredentialVaultAddress::new(
        "production",
        "product-a",
        "software-generic",
        "profile-default",
        "client-1",
    );
    assert_eq!(vault.load(&other_environment).unwrap(), None);
}

#[test]
fn complete_scope_is_part_of_the_storage_key_and_records_do_not_overwrite() {
    let (response, mut verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let first = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &response,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-1",
        None,
    )
    .unwrap();

    let mut second_response = response.clone();
    second_response.authorization_id = "authorization-2".to_string();
    second_response.authorization_revision = 8;
    verifier
        .allow(
            &second_response.integrity,
            second_response.canonical_payload(),
        )
        .unwrap();
    let second = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &second_response,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-2",
        None,
    )
    .unwrap();

    let address = first.record().scope.address.clone();
    let vault = MemoryCredentialVault::default();
    vault.save(&address, &first).unwrap();
    vault.save(&address, &second).unwrap();

    let first_loaded = vault
        .load_for_scope(&first.record().scope)
        .unwrap()
        .expect("first scoped record must remain addressable");
    let second_loaded = vault
        .load_for_scope(&second.record().scope)
        .unwrap()
        .expect("second scoped record must remain addressable");
    assert_eq!(
        first_loaded.credential().with_bytes(|bytes| bytes.to_vec()),
        b"license-key-1"
    );
    assert_eq!(
        second_loaded
            .credential()
            .with_bytes(|bytes| bytes.to_vec()),
        b"license-key-2"
    );
}

#[test]
fn cached_startup_material_must_be_freshly_verified_before_resaving() {
    let (response, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let verified = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &response,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-verify-again",
        None,
    )
    .unwrap();
    let address = verified.record().scope.address.clone();
    let vault = MemoryCredentialVault::default();
    let recovery = CredentialRecovery::new(vault.clone());
    recovery.save_verified(&address, &verified).unwrap();

    let CredentialRecoveryState::VerifyCachedCredential(pending) =
        recovery.startup(&address).unwrap()
    else {
        panic!("the saved record must enter the verify-only startup state");
    };
    let refreshed = recovery
        .verify_cached_response(
            pending,
            "test-local",
            &response,
            &product_manifest,
            &product_binding,
            &verifier,
        )
        .unwrap();
    assert_eq!(refreshed.record().scope, verified.record().scope);
    recovery.save_verified(&address, &refreshed).unwrap();
}

#[test]
fn cached_credential_accepts_a_new_server_config_version() {
    let (response, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let verified = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &response,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-survives-config-refresh",
        None,
    )
    .unwrap();
    let address = verified.record().scope.address.clone();
    let vault = MemoryCredentialVault::default();
    let recovery = CredentialRecovery::new(vault.clone());
    recovery.save_verified(&address, &verified).unwrap();
    let CredentialRecoveryState::VerifyCachedCredential(pending) =
        recovery.startup(&address).unwrap()
    else {
        panic!("the saved record must enter verify-only recovery");
    };

    let mut refreshed_response = response;
    refreshed_response.request_id = "request-config-8".to_string();
    refreshed_response.snapshot_id = "snapshot-config-8".to_string();
    refreshed_response.config_version = "config-8".to_string();
    refreshed_response.authorization_revision += 1;
    refreshed_response.server_time += 1;
    let mut refreshed_verifier = MockIntegrityVerifier::new();
    refreshed_verifier
        .allow(
            &refreshed_response.integrity,
            refreshed_response.canonical_payload(),
        )
        .unwrap();

    let refreshed = recovery
        .verify_cached_response(
            pending,
            "test-local",
            &refreshed_response,
            &product_manifest,
            &product_binding,
            &refreshed_verifier,
        )
        .expect("a signed config refresh must not require retyping the credential");
    assert_eq!(refreshed.record().scope.config_version, "config-8");
    refreshed
        .record()
        .credential()
        .with_text(|credential| assert_eq!(credential, "license-key-survives-config-refresh"));
}

#[test]
fn non_launchable_or_unconfirmed_responses_cannot_create_recovery_records() {
    let (revoked, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Revoked);
    assert!(VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &revoked,
        &product_manifest,
        &product_binding,
        &verifier,
        "license-key-1",
        None,
    )
    .is_err());

    let (active, _verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let mut unconfirmed = active.clone();
    unconfirmed.structured_device_scope = None;
    let mut unconfirmed_verifier = MockIntegrityVerifier::new();
    unconfirmed_verifier
        .allow(&unconfirmed.integrity, unconfirmed.canonical_payload())
        .unwrap();
    assert!(VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &unconfirmed,
        &product_manifest,
        &product_binding,
        &unconfirmed_verifier,
        "license-key-1",
        None,
    )
    .is_err());
    let (active, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let mut different_device = active.clone();
    different_device.identity.device_id = "device-2".to_string();
    let mut different_device_verifier = MockIntegrityVerifier::new();
    different_device_verifier
        .allow(
            &different_device.integrity,
            different_device.canonical_payload(),
        )
        .unwrap();
    assert!(VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &different_device,
        &product_manifest,
        &product_binding,
        &different_device_verifier,
        "license-key-1",
        None,
    )
    .is_err());
    let _ = verifier;
}

#[test]
fn secure_storage_unavailable_does_not_fallback_to_plaintext() {
    let address = CredentialVaultAddress::new(
        "test-local",
        "product-a",
        "software-generic",
        "profile-default",
        "client-1",
    );
    assert_eq!(
        UnsupportedCredentialVault.load(&address),
        Err(authorization_a_template::CredentialVaultError::SecureStorageUnavailable)
    );
    assert!(SecretValue::from_text("line\nfeed").is_err());
}

#[cfg(windows)]
#[test]
fn windows_credential_manager_round_trip_is_cleaned_up() {
    let (response, verifier, product_manifest, product_binding) =
        verified_response(LicenseState::Active);
    let verified = VerifiedCredentialRecord::from_verified_response(
        "test-local",
        &response,
        &product_manifest,
        &product_binding,
        &verifier,
        "credential-vault-integration-test",
        Some("device-token-integration-test"),
    )
    .unwrap();
    let address = verified.record().scope.address.clone();
    let vault = WindowsCredentialVault::new();
    vault.clear(&address).unwrap();
    struct Cleanup {
        vault: WindowsCredentialVault,
        address: CredentialVaultAddress,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.vault.clear(&self.address);
        }
    }
    let _cleanup = Cleanup {
        vault,
        address: address.clone(),
    };

    vault.save(&address, &verified).unwrap();
    let loaded = vault
        .load(&address)
        .unwrap()
        .expect("Credential Manager should return the saved record");
    assert_eq!(loaded.scope, verified.record().scope);
    assert_eq!(
        loaded.credential().len(),
        verified.record().credential().len()
    );
    assert_eq!(
        loaded.device_token().map(SecretValue::len),
        Some("device-token-integration-test".len())
    );
}
