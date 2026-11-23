use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use authorization_a_template::{
    AuthorizationBinding, AuthorizationCache, AuthorizationCacheStore, AuthorizationIdentity,
    AuthorizationResponseV1, CacheApplyOutcome, CompatibilityMode, EnvironmentProfile,
    IntegrityProof, LicenseState, MockIntegrityVerifier, OfflineLeaseDecision, OfflineLeasePolicy,
    ProductManifest, RuntimePinClaim, RuntimeRollbackPin, RuntimeRollbackPinStore,
    RuntimeStateError, ThemeTokens, AUTHORIZATION_A_CORE_CONTRACT_VERSION,
};

static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

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
        vec![authorization_a_template::Capability::required(
            "launch", "1",
        )],
    )
}

fn binding(product_id: &str, client_id: &str) -> AuthorizationBinding {
    AuthorizationBinding::new(
        product_id,
        AuthorizationIdentity::new(
            "software-generic",
            "profile-default",
            client_id,
            "current_device",
            "device-1",
        ),
    )
}

fn response(
    binding: &AuthorizationBinding,
    request_id: &str,
    server_time: u64,
    decision: LicenseState,
) -> (AuthorizationResponseV1, MockIntegrityVerifier) {
    let request = authorization_a_template::AuthorizationRequestV1::new(
        request_id, binding, "config-7", None,
    )
    .with_target_arch_channel("windows", "x86_64", "stable");
    let mut response = AuthorizationResponseV1::new_cloud(
        &request,
        "authorization-1",
        "snapshot-1",
        decision,
        7,
        server_time,
        100,
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
    .expect("cloud fixture converts to the local contract");
    response.state_code = match decision {
        LicenseState::Active => "AUTH_ACTIVE",
        LicenseState::Grace => "AUTH_GRACE",
        LicenseState::Expired => "AUTH_EXPIRED",
        LicenseState::Revoked => "AUTH_REVOKED",
        LicenseState::Blocked => "AUTH_BLOCKED",
        LicenseState::NotModified => "AUTH_NOT_MODIFIED",
        LicenseState::Unavailable => "AUTH_UNAVAILABLE",
    }
    .to_string();
    let mut verifier = MockIntegrityVerifier::new();
    verifier
        .allow(&response.integrity, response.canonical_payload())
        .expect("fixture response is registered");
    (response, verifier)
}

fn fresh_root(label: &str) -> PathBuf {
    let id = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "authorization-a-template-{label}-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("temporary test root is writable");
    root
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_not_modified_requires_and_preserves_a_launchable_record() {
    let product_manifest = manifest("product-a");
    let product_binding = binding("product-a", "client-1");
    let (active, mut verifier) = response(
        &product_binding,
        "request-active",
        100,
        LicenseState::Active,
    );
    let (not_modified, _) = response(
        &product_binding,
        "request-refresh",
        120,
        LicenseState::NotModified,
    );
    verifier
        .allow(&active.integrity, active.canonical_payload())
        .unwrap();
    let mut cache = AuthorizationCache::new();
    assert_eq!(
        cache
            .apply(
                active.clone(),
                &product_manifest,
                &product_binding,
                &verifier
            )
            .unwrap(),
        CacheApplyOutcome::Stored
    );
    verifier
        .allow(&not_modified.integrity, not_modified.canonical_payload())
        .unwrap();
    assert_eq!(
        cache
            .apply(not_modified, &product_manifest, &product_binding, &verifier)
            .unwrap(),
        CacheApplyOutcome::NotModified
    );
    let key = authorization_a_template::AuthorizationCacheKey::from_response(&active);
    let cached = cache.get(&key).expect("active response remains cached");
    assert_eq!(cached.decision, LicenseState::Active);
    assert_eq!(cached.request_id, "request-active");
    assert_eq!(cache.last_seen_server_time_for(&product_binding), Some(120));

    let (orphan, verifier) = response(
        &product_binding,
        "request-orphan",
        120,
        LicenseState::NotModified,
    );
    let mut empty_cache = AuthorizationCache::new();
    assert!(matches!(
        empty_cache.apply(orphan, &product_manifest, &product_binding, &verifier),
        Err(authorization_a_template::AuthorizationError::InvalidRequest(_))
    ));
}

#[test]
fn durable_cache_restores_scope_idempotency_and_highwater() {
    let root = fresh_root("cache");
    let product_manifest = manifest("product-a");
    let product_binding = binding("product-a", "client-1");
    let (active, mut verifier) = response(&product_binding, "request-1", 100, LicenseState::Active);
    let store = AuthorizationCacheStore::for_environment(
        &root,
        "test-local",
        &product_manifest,
        &product_binding,
    )
    .unwrap();
    let mut cache = AuthorizationCache::new();
    cache
        .apply(
            active.clone(),
            &product_manifest,
            &product_binding,
            &verifier,
        )
        .unwrap();
    store
        .save(&cache, &product_manifest, &product_binding, &verifier)
        .unwrap();

    let mut reopened = store
        .load(&product_manifest, &product_binding, &verifier)
        .unwrap()
        .expect("saved cache reloads");
    assert_eq!(
        reopened.last_seen_server_time_for(&product_binding),
        Some(100)
    );
    assert_eq!(
        reopened
            .apply(
                active.clone(),
                &product_manifest,
                &product_binding,
                &verifier
            )
            .unwrap(),
        CacheApplyOutcome::Idempotent
    );

    let mut conflict = active;
    conflict.snapshot_id = "snapshot-conflict".to_string();
    verifier
        .allow(&conflict.integrity, conflict.canonical_payload())
        .unwrap();
    assert!(matches!(
        reopened.apply(conflict, &product_manifest, &product_binding, &verifier),
        Err(authorization_a_template::AuthorizationError::RequestConflict { .. })
    ));

    let other_binding = binding("product-a", "client-2");
    let other_store = AuthorizationCacheStore::for_environment(
        &root,
        "test-local",
        &product_manifest,
        &other_binding,
    )
    .unwrap();
    assert!(matches!(
        other_store.load(&product_manifest, &other_binding, &verifier),
        Err(RuntimeStateError::ScopeMismatch { .. })
    ));
    let production_store = AuthorizationCacheStore::for_environment(
        &root,
        "production",
        &product_manifest,
        &product_binding,
    )
    .unwrap();
    assert_eq!(
        production_store
            .load(&product_manifest, &product_binding, &verifier)
            .unwrap(),
        None
    );
    cleanup(&root);
}

#[test]
fn durable_cache_rejects_request_only_fields_in_persisted_idempotency_payload() {
    let root = fresh_root("request-only");
    let product_manifest = manifest("product-a");
    let product_binding = binding("product-a", "client-1");
    let (active, verifier) = response(&product_binding, "request-1", 100, LicenseState::Active);
    let store = AuthorizationCacheStore::for_environment(
        &root,
        "test-local",
        &product_manifest,
        &product_binding,
    )
    .unwrap();
    let mut cache = AuthorizationCache::new();
    cache
        .apply(active, &product_manifest, &product_binding, &verifier)
        .unwrap();
    store
        .save(&cache, &product_manifest, &product_binding, &verifier)
        .unwrap();
    let valid = fs::read_to_string(store.path()).unwrap();
    let poisoned = valid.replace(
        "\\\"request_id\\\"",
        "\\\"nonce\\\":\\\"nonce-sentinel\\\",\\\"request_id\\\"",
    );
    assert_ne!(poisoned, valid);
    fs::write(store.path(), poisoned).unwrap();
    assert!(matches!(
        store.load(&product_manifest, &product_binding, &verifier),
        Err(RuntimeStateError::Corrupt(_))
    ));
    cleanup(&root);
}

#[test]
fn durable_cache_rejects_corrupt_or_temporary_state() {
    let root = fresh_root("corrupt");
    let product_manifest = manifest("product-a");
    let product_binding = binding("product-a", "client-1");
    let (active, verifier) = response(&product_binding, "request-1", 100, LicenseState::Active);
    let store = AuthorizationCacheStore::for_environment(
        &root,
        "test-local",
        &product_manifest,
        &product_binding,
    )
    .unwrap();
    let mut cache = AuthorizationCache::new();
    cache
        .apply(active, &product_manifest, &product_binding, &verifier)
        .unwrap();
    store
        .save(&cache, &product_manifest, &product_binding, &verifier)
        .unwrap();
    let valid = fs::read_to_string(store.path()).unwrap();

    fs::write(store.path(), &valid[..valid.len() - 1]).unwrap();
    assert!(matches!(
        store.load(&product_manifest, &product_binding, &verifier),
        Err(RuntimeStateError::Corrupt(_))
    ));

    let unknown_field = format!("{},\"unknown\":1}}", &valid[..valid.len() - 1]);
    fs::write(store.path(), unknown_field).unwrap();
    assert!(matches!(
        store.load(&product_manifest, &product_binding, &verifier),
        Err(RuntimeStateError::Corrupt(_))
    ));

    fs::remove_file(store.path()).unwrap();
    let temporary = store.path().with_file_name(format!(
        ".{}.tmp-test",
        store.path().file_name().unwrap().to_string_lossy()
    ));
    fs::write(&temporary, valid).unwrap();
    assert_eq!(
        store
            .load(&product_manifest, &product_binding, &verifier)
            .unwrap(),
        None
    );
    let mut reserved_manifest = product_manifest.clone();
    reserved_manifest.state_root = PathBuf::from("state/CON");
    assert!(matches!(
        AuthorizationCacheStore::for_environment(
            &root,
            "test-local",
            &reserved_manifest,
            &product_binding,
        ),
        Err(RuntimeStateError::InvalidState(_))
    ));
    cleanup(&root);
}

#[test]
fn offline_lease_uses_server_time_and_cannot_override_expiry_or_rollback() {
    let product_manifest = manifest("product-a");
    let product_binding = binding("product-a", "client-1");
    let (active, _) = response(&product_binding, "request-1", 100, LicenseState::Active);
    let policy = OfflineLeasePolicy::from_environment(
        &EnvironmentProfile::test("test-local", "http://127.0.0.1:8789").with_cache_policy(60, 20),
    );
    assert_eq!(
        policy.evaluate(&active, 100, 150).unwrap(),
        OfflineLeaseDecision::Active
    );
    assert_eq!(
        policy.evaluate(&active, 100, 170).unwrap(),
        OfflineLeaseDecision::Grace
    );
    assert_eq!(
        policy.evaluate(&active, 100, 180).unwrap(),
        OfflineLeaseDecision::RejectExpired
    );
    assert!(matches!(
        policy.evaluate(&active, 100, 99),
        Err(RuntimeStateError::TimeRollback { .. })
    ));

    let mut expires_early = active;
    expires_early.expires_at = Some(165);
    assert_eq!(
        policy.evaluate(&expires_early, 100, 170).unwrap(),
        OfflineLeaseDecision::RejectExpired
    );
    let _ = product_manifest;
}

#[test]
fn rollback_pin_persists_claims_and_never_rolls_back_from_revocation() {
    let root = fresh_root("pin");
    let product_manifest = manifest("product-a");
    let product_binding = binding("product-a", "client-1");
    let store = RuntimeRollbackPinStore::for_environment(
        &root,
        "test-local",
        &product_manifest,
        &product_binding,
    )
    .unwrap();
    let first = RuntimePinClaim::new(
        "release-a",
        AUTHORIZATION_A_CORE_CONTRACT_VERSION,
        7,
        100,
        LicenseState::Active,
        "hash-a",
    )
    .unwrap();
    let second = RuntimePinClaim::new(
        "release-b",
        AUTHORIZATION_A_CORE_CONTRACT_VERSION,
        8,
        120,
        LicenseState::Active,
        "hash-b",
    )
    .unwrap();
    let mut pin = RuntimeRollbackPin::new(first).unwrap();
    pin.advance(second).unwrap();
    store.save(&pin).unwrap();
    assert_eq!(store.load().unwrap(), Some(pin.clone()));
    pin.rollback().unwrap();
    assert_eq!(pin.current.artifact, "release-a");

    let same_revision_different_claim = RuntimePinClaim::new(
        "release-same-revision",
        AUTHORIZATION_A_CORE_CONTRACT_VERSION,
        8,
        140,
        LicenseState::Active,
        "hash-other",
    )
    .unwrap();
    assert!(matches!(
        pin.advance(same_revision_different_claim),
        Err(RuntimeStateError::InvalidState(_))
    ));
    let lower_revision = RuntimePinClaim::new(
        "release-old",
        AUTHORIZATION_A_CORE_CONTRACT_VERSION,
        7,
        150,
        LicenseState::Active,
        "hash-a",
    )
    .unwrap();
    assert!(matches!(
        pin.advance(lower_revision),
        Err(RuntimeStateError::InvalidState(_))
    ));

    let revoked = RuntimePinClaim::new(
        "release-revoked",
        AUTHORIZATION_A_CORE_CONTRACT_VERSION,
        9,
        130,
        LicenseState::Revoked,
        "hash-revoked",
    )
    .unwrap();
    pin.advance(revoked).unwrap();
    assert!(matches!(
        pin.rollback(),
        Err(RuntimeStateError::InvalidState(_))
    ));

    let other_binding = binding("product-a", "client-2");
    let other_store = RuntimeRollbackPinStore::for_environment(
        &root,
        "test-local",
        &product_manifest,
        &other_binding,
    )
    .unwrap();
    assert!(matches!(
        other_store.load(),
        Err(RuntimeStateError::ScopeMismatch { .. })
    ));
    cleanup(&root);
}
