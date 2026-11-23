use std::collections::BTreeMap;
use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationBinding, AuthorizationCache, AuthorizationCacheKey, AuthorizationError,
    AuthorizationErrorCode, AuthorizationErrorResponseV1, AuthorizationIdentity,
    AuthorizationModuleV1, AuthorizationRequestV1, AuthorizationResponseV1, CacheApplyOutcome,
    CompatibilityMode, IntegrityError, IntegrityProof, IntegritySigner, IntegrityVerifier,
    LicenseState, LifecycleError, LifecycleStateMachine, LocalTransportFrame, MockIntegritySigner,
    MockIntegrityVerifier, ProductManifest, ServerTimeWatermark, StructuredDeviceScopeV1,
    ThemeTokens, TransportError, LOCAL_FRAME_HEADER_BYTES,
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
        vec![
            authorization_a_template::Capability::required("launch", "1"),
            authorization_a_template::Capability::optional("updates", "1"),
        ],
    )
}

fn make_binding(product_id: &str, client_id: &str) -> AuthorizationBinding {
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

fn cloud_request(binding: &AuthorizationBinding) -> AuthorizationRequestV1 {
    AuthorizationRequestV1::new("request-1", binding, "config-7", None)
        .with_target_arch_channel("windows", "x86_64", "stable")
        .with_platform_credentials(
            "A".repeat(43),
            Some("A".repeat(86)),
            "installation-1",
            "1.0.0",
            "nonce-12345678",
        )
}

fn cloud_response(binding: &AuthorizationBinding) -> AuthorizationResponseV1 {
    let request = cloud_request(binding);
    AuthorizationResponseV1::new_cloud(
        &request,
        "authorization-1",
        "snapshot-1",
        LicenseState::Active,
        7,
        1_755_000_100,
        1_755_000_000,
        Some(1_755_000_200),
        Some(1_755_000_180),
        Some(1_755_000_180),
        Some(1_755_000_200),
        IntegrityProof::new(
            "ed25519",
            "platform-key-1",
            "JCS-RFC8785",
            "platform-signature-1",
        )
        .with_origin_audience("authorization-platform", "authorization-a"),
        vec!["launch".to_string()],
        Vec::new(),
    )
    .with_structured_device_scope(StructuredDeviceScopeV1::current_device(
        "device-1",
        Some("installation-1"),
    ))
}

fn verified_response(
    binding: &AuthorizationBinding,
    verifier: &mut MockIntegrityVerifier,
) -> AuthorizationResponseV1 {
    let cloud = cloud_response(binding);
    verifier
        .allow(&cloud.integrity, cloud.canonical_payload())
        .unwrap();
    let signer = MockIntegritySigner::new("a-key-1", "a-signature-1");
    let product_manifest = manifest(&binding.product_id);
    let response = cloud
        .to_core_with_signer_for(
            &cloud_request(binding),
            &product_manifest,
            binding,
            verifier,
            &signer,
        )
        .unwrap();
    verifier
        .allow(&response.integrity, response.canonical_payload())
        .unwrap();
    response
}

#[test]
fn cloud_to_core_migration_preserves_authority_claims() {
    let binding = make_binding("skin-studio", "client-1");
    let cloud = cloud_response(&binding);
    let request = cloud_request(&binding);
    let mut central_verifier = MockIntegrityVerifier::new();
    central_verifier
        .allow(&cloud.integrity, cloud.canonical_payload())
        .unwrap();
    let signer = MockIntegritySigner::new("a-key-migration", "a-signature-migration");
    let product_manifest = manifest(&binding.product_id);
    cloud.validate_for_request(&request).unwrap();

    let core = cloud
        .clone()
        .to_core_with_signer_for(
            &request,
            &product_manifest,
            &binding,
            &central_verifier,
            &signer,
        )
        .unwrap();
    assert_eq!(cloud.request_id, core.request_id);
    assert_eq!(cloud.identity, core.identity);
    assert_eq!(cloud.authorization_revision, core.authorization_revision);
    assert_eq!(cloud.config_version, core.config_version);
    assert_eq!(cloud.decision, core.decision);
    assert_eq!(cloud.issued_at, core.issued_at);
    assert_eq!(cloud.expires_at, core.expires_at);
    assert_eq!(cloud.server_time, core.server_time);
    assert_ne!(cloud.integrity, core.integrity);
    assert_eq!(core.integrity.algorithm, "ed25519");
    assert_eq!(core.integrity.canonicalization, "JCS-RFC8785");
    assert_eq!(core.integrity.origin, "authorization-a");
    assert_eq!(core.integrity.audience, "authorization-a-core");
    assert_eq!(core.protocol, "authorization-a-core.v1");
    assert_eq!(core.schema_version, "authorization-a-core.v1");
    assert_eq!(core.contract_version, "authorization-a-core.v1");
}

#[test]
fn local_signer_covers_the_complete_core_response() {
    let binding = make_binding("skin-studio", "client-1");
    let cloud = cloud_response(&binding);
    let mut central_verifier = MockIntegrityVerifier::new();
    central_verifier
        .allow(&cloud.integrity, cloud.canonical_payload())
        .unwrap();
    let signer = MockIntegritySigner::new("a-key-complete", "a-signature-complete");
    let product_manifest = manifest(&binding.product_id);
    let core = cloud
        .to_core_with_signer_for(
            &cloud_request(&binding),
            &product_manifest,
            &binding,
            &central_verifier,
            &signer,
        )
        .unwrap();

    signer
        .verify(&core.integrity, &core.canonical_payload())
        .unwrap();
    let mut tampered = core;
    tampered.channel = "beta".to_string();
    assert!(matches!(
        signer.verify(&tampered.integrity, &tampered.canonical_payload()),
        Err(IntegrityError::InvalidSignature)
    ));
}

#[test]
fn missing_binding_or_integrity_fields_fail_closed() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let mut verifier = MockIntegrityVerifier::new();
    let mut response = verified_response(&binding, &mut verifier);

    response.identity.profile_id.clear();
    assert!(matches!(
        response.validate_for_binding(&manifest, &binding),
        Err(AuthorizationError::InvalidRequest(_))
    ));

    let mut response = verified_response(&binding, &mut verifier);
    response.integrity.signature.clear();
    assert!(matches!(
        response.verify(&verifier),
        Err(AuthorizationError::Integrity(IntegrityError::Missing))
    ));
}

#[test]
fn platform_runtime_fields_and_new_decisions_are_explicit() {
    let binding = make_binding("skin-studio", "client-1");
    let request = AuthorizationRequestV1::new("request-fields", &binding, "config-7", None);
    assert!(matches!(
        request.validate(),
        Err(AuthorizationError::InvalidRequest(_))
    ));

    for (state, state_code) in [
        (LicenseState::Blocked, "AUTH_BLOCKED"),
        (LicenseState::NotModified, "AUTH_NOT_MODIFIED"),
    ] {
        assert_eq!(
            state.as_str(),
            state_code
                .strip_prefix("AUTH_")
                .unwrap()
                .to_ascii_lowercase()
        );
        assert!(!state.allows_launch());
    }

    let production_shape = IntegrityProof::new(
        "ed25519",
        "platform-key-1",
        "JCS-RFC8785",
        "base64url-signature",
    )
    .with_origin_audience("authorization-a", "authorization-a-core");
    production_shape.validate_for_core_contract().unwrap();

    let mut uppercase_algorithm = production_shape.clone();
    uppercase_algorithm.algorithm = "Ed25519".to_string();
    assert!(matches!(
        uppercase_algorithm.validate_for_cloud_contract(),
        Err(IntegrityError::UnsupportedAlgorithm(value)) if value == "Ed25519"
    ));
}

#[test]
fn integrity_verifier_rejects_unknown_key_and_tampered_claims() {
    let binding = make_binding("skin-studio", "client-1");
    let mut verifier = MockIntegrityVerifier::new();
    let response = verified_response(&binding, &mut verifier);
    response.verify(&verifier).unwrap();

    let mut tampered = response.clone();
    tampered.decision = LicenseState::Revoked;
    assert!(matches!(
        tampered.verify(&verifier),
        Err(AuthorizationError::Integrity(
            IntegrityError::InvalidSignature
        ))
    ));

    let mut unknown_key = response;
    unknown_key.integrity.key_id = "rotated-key-not-loaded".to_string();
    assert!(matches!(
        unknown_key.verify(&verifier),
        Err(AuthorizationError::Integrity(IntegrityError::UnknownKey(_)))
    ));
}

#[test]
fn server_time_watermark_rejects_rollback_and_keeps_highwater() {
    let mut watermark = ServerTimeWatermark::default();
    watermark.observe(100).unwrap();
    assert!(matches!(
        watermark.observe(99),
        Err(AuthorizationError::ServerTimeRollback {
            last_seen: 100,
            received: 99
        })
    ));
    assert_eq!(watermark.last_seen_server_time(), Some(100));
    assert_eq!(
        AuthorizationErrorCode::ServerTimeRollback.as_str(),
        "TIME_ROLLBACK_DETECTED"
    );
    assert!(!AuthorizationErrorCode::ServerTimeRollback.retryable());
    assert!(AuthorizationErrorCode::Unavailable.retryable());
}

#[test]
fn stable_error_response_keeps_retry_semantics_and_integrity() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let error = AuthorizationErrorResponseV1::new_core(
        "request-error",
        &binding,
        AuthorizationErrorCode::Unavailable,
        100,
        IntegrityProof::new("ed25519", "a-key-error", "JCS-RFC8785", "a-signature-error")
            .with_origin_audience("authorization-a", "authorization-a-core"),
    );
    let mut verifier = MockIntegrityVerifier::new();
    verifier
        .allow(&error.integrity, error.canonical_payload())
        .unwrap();
    error.validate_for_binding(&manifest, &binding).unwrap();
    error.verify(&verifier).unwrap();

    let mut inconsistent = error;
    inconsistent.retryable = false;
    assert!(matches!(
        inconsistent.validate_for_binding(&manifest, &binding),
        Err(AuthorizationError::InvalidRequest(_))
    ));
}

#[test]
fn lifecycle_accepts_only_bound_verified_core_response_and_resists_local_time_rollback() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let mut verifier = MockIntegrityVerifier::new();
    let response = verified_response(&binding, &mut verifier);
    let mut machine = LifecycleStateMachine::new(manifest, "device-1").unwrap();

    machine
        .apply_authorization_response(response.clone(), &binding, &verifier)
        .unwrap();
    assert_eq!(machine.state(), LicenseState::Active);
    assert_eq!(machine.server_time_highwater(), Some(1_755_000_100));

    let mut rollback = response;
    rollback.request_id = "request-2".to_string();
    rollback.authorization_revision = 8;
    rollback.server_time = 1_755_000_099;
    let mut rollback_verifier = MockIntegrityVerifier::new();
    rollback_verifier
        .allow(&rollback.integrity, rollback.canonical_payload())
        .unwrap();
    assert!(matches!(
        machine.apply_authorization_response(rollback, &binding, &rollback_verifier),
        Err(LifecycleError::Authorization(
            AuthorizationError::ServerTimeRollback { .. }
        ))
    ));
    assert_eq!(machine.state(), LicenseState::Active);

    assert_eq!(machine.state_at(1), LicenseState::Active);
    assert_eq!(machine.state_at(1_755_000_200), LicenseState::Expired);
    assert_eq!(machine.state_at(1), LicenseState::Expired);
}

#[test]
fn lifecycle_rejects_formal_request_replay_conflict_and_revision_rollback() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let mut verifier = MockIntegrityVerifier::new();
    let response = verified_response(&binding, &mut verifier);
    let mut machine = LifecycleStateMachine::new(manifest, "device-1").unwrap();
    machine
        .apply_authorization_response(response.clone(), &binding, &verifier)
        .unwrap();

    let mut conflict = response.clone();
    conflict.snapshot_id = "snapshot-conflict".to_string();
    let mut conflict_verifier = MockIntegrityVerifier::new();
    conflict_verifier
        .allow(&conflict.integrity, conflict.canonical_payload())
        .unwrap();
    assert!(matches!(
        machine.apply_authorization_response(conflict, &binding, &conflict_verifier),
        Err(LifecycleError::Authorization(
            AuthorizationError::RequestConflict { .. }
        ))
    ));

    let mut stale = response;
    stale.request_id = "request-stale".to_string();
    stale.snapshot_id = "snapshot-stale".to_string();
    stale.authorization_revision = 6;
    stale.server_time += 1;
    let mut stale_verifier = MockIntegrityVerifier::new();
    stale_verifier
        .allow(&stale.integrity, stale.canonical_payload())
        .unwrap();
    assert!(matches!(
        machine.apply_authorization_response(stale, &binding, &stale_verifier),
        Err(LifecycleError::Authorization(
            AuthorizationError::StaleRevision { .. }
        ))
    ));
}

#[test]
fn cache_is_scoped_and_request_idempotency_is_strict() {
    let binding = make_binding("skin-studio", "client-1");
    let skin_manifest = manifest("skin-studio");
    let mut verifier = MockIntegrityVerifier::new();
    let response = verified_response(&binding, &mut verifier);
    let mut cache = AuthorizationCache::new();

    assert_eq!(
        cache
            .apply(response.clone(), &skin_manifest, &binding, &verifier)
            .unwrap(),
        CacheApplyOutcome::Stored
    );
    assert_eq!(
        cache
            .apply(response.clone(), &skin_manifest, &binding, &verifier)
            .unwrap(),
        CacheApplyOutcome::Idempotent
    );
    assert_eq!(
        cache.last_seen_server_time_for(&binding),
        Some(1_755_000_100)
    );

    let mut conflict = response.clone();
    conflict.decision = LicenseState::Revoked;
    conflict.state_code = "AUTH_REVOKED".to_string();
    let mut conflict_verifier = MockIntegrityVerifier::new();
    conflict_verifier
        .allow(&conflict.integrity, conflict.canonical_payload())
        .unwrap();
    assert!(matches!(
        cache.apply(conflict, &skin_manifest, &binding, &conflict_verifier),
        Err(AuthorizationError::RequestConflict { .. })
    ));

    let other_binding = make_binding("skin-studio", "client-2");
    let mut other_response = verified_response(&other_binding, &mut verifier);
    other_response.request_id = "request-other".to_string();
    let mut other_verifier = MockIntegrityVerifier::new();
    other_verifier
        .allow(
            &other_response.integrity,
            other_response.canonical_payload(),
        )
        .unwrap();
    assert!(cache
        .apply(
            other_response,
            &skin_manifest,
            &other_binding,
            &other_verifier
        )
        .is_ok());

    let mut same_request_other_authorization = response.clone();
    same_request_other_authorization.authorization_id = "authorization-2".to_string();
    let mut same_scope_verifier = MockIntegrityVerifier::new();
    same_scope_verifier
        .allow(
            &same_request_other_authorization.integrity,
            same_request_other_authorization.canonical_payload(),
        )
        .unwrap();
    assert!(cache
        .apply(
            same_request_other_authorization,
            &skin_manifest,
            &binding,
            &same_scope_verifier,
        )
        .is_ok());

    let other_product = make_binding("media-tool", "client-1");
    let mut other_product_response = verified_response(&other_product, &mut verifier);
    other_product_response.request_id = "request-other-product".to_string();
    let mut other_product_verifier = MockIntegrityVerifier::new();
    other_product_verifier
        .allow(
            &other_product_response.integrity,
            other_product_response.canonical_payload(),
        )
        .unwrap();
    assert!(cache
        .apply(
            other_product_response,
            &manifest("media-tool"),
            &other_product,
            &other_product_verifier,
        )
        .is_ok());
}

#[test]
fn response_may_advance_config_version_but_not_modified_may_not() {
    let binding = make_binding("skin-studio", "client-1");
    let request = cloud_request(&binding);
    let mut refreshed = cloud_response(&binding);
    refreshed.config_version = "config-8".to_string();
    assert!(refreshed.validate_for_request(&request).is_ok());

    refreshed.decision = LicenseState::NotModified;
    refreshed.state_code = "AUTH_NOT_MODIFIED".to_string();
    assert!(matches!(
        refreshed.validate_for_request(&request),
        Err(AuthorizationError::BindingMismatch { field, .. }) if field == "config_version"
    ));
}

#[test]
fn config_version_respects_the_public_64_byte_contract() {
    let binding = make_binding("skin-studio", "client-1");
    let mut request = cloud_request(&binding);
    request.config_version = "v".repeat(65);
    assert!(request.validate().is_err());

    let mut response = cloud_response(&binding);
    response.config_version = "v".repeat(65);
    assert!(response.validate_for_platform_response().is_err());

    for schema in [
        include_str!("../protocol/authorization.v1.schema.json"),
        include_str!("../protocol/authorization-a-core.v1.schema.json"),
    ] {
        let declarations: Vec<_> = schema
            .lines()
            .filter(|line| line.contains("\"config_version\": {"))
            .collect();
        assert!(!declarations.is_empty());
        assert!(declarations
            .iter()
            .all(|line| line.contains("\"maxLength\": 64")));
    }
}

#[test]
fn cache_replaces_old_config_and_keeps_revision_floor_across_versions() {
    let binding = make_binding("skin-studio", "client-1");
    let product_manifest = manifest("skin-studio");
    let mut first_verifier = MockIntegrityVerifier::new();
    let first = verified_response(&binding, &mut first_verifier);
    let old_key = AuthorizationCacheKey::from_response(&first);
    let mut cache = AuthorizationCache::new();
    cache
        .apply(first.clone(), &product_manifest, &binding, &first_verifier)
        .unwrap();

    let mut revoked = first.clone();
    revoked.request_id = "request-config-8-revoked".to_string();
    revoked.snapshot_id = "snapshot-config-8-revoked".to_string();
    revoked.config_version = "config-8".to_string();
    revoked.authorization_revision = first.authorization_revision + 1;
    revoked.server_time = first.server_time + 1;
    revoked.decision = LicenseState::Revoked;
    revoked.state_code = "AUTH_REVOKED".to_string();
    let new_key = AuthorizationCacheKey::from_response(&revoked);
    let mut revoked_verifier = MockIntegrityVerifier::new();
    revoked_verifier
        .allow(&revoked.integrity, revoked.canonical_payload())
        .unwrap();
    cache
        .apply(revoked, &product_manifest, &binding, &revoked_verifier)
        .unwrap();

    assert!(cache.get(&old_key).is_none());
    assert_eq!(
        cache.get(&new_key).map(|response| response.decision),
        Some(LicenseState::Revoked)
    );

    let mut stale = first;
    stale.request_id = "request-stale-old-config".to_string();
    stale.snapshot_id = "snapshot-stale-old-config".to_string();
    stale.server_time += 2;
    let mut stale_verifier = MockIntegrityVerifier::new();
    stale_verifier
        .allow(&stale.integrity, stale.canonical_payload())
        .unwrap();
    assert!(matches!(
        cache.apply(stale, &product_manifest, &binding, &stale_verifier),
        Err(AuthorizationError::StaleRevision { .. })
    ));
}

#[test]
fn modules_carry_full_scope_and_updates_require_trust_metadata() {
    let binding = make_binding("skin-studio", "client-1");
    let request = AuthorizationRequestV1::new("request-module", &binding, "config-7", None)
        .with_target_arch_channel("windows", "x86_64", "stable")
        .with_platform_credentials(
            "A".repeat(43),
            Some("A".repeat(86)),
            "installation-1",
            "1.0.0",
            "nonce-module-123",
        );
    let mut payload = BTreeMap::new();
    payload.insert("artifact_sha256".to_string(), "a".repeat(64));
    payload.insert("artifact_size".to_string(), "123".to_string());
    payload.insert(
        "artifact_signature".to_string(),
        "signed-artifact".to_string(),
    );
    payload.insert("min_core_version".to_string(), "1.0.0".to_string());
    payload.insert("channel".to_string(), "stable".to_string());
    let module = AuthorizationModuleV1::new(
        "skin-studio",
        "authorization-module",
        &binding.identity,
        "update-1",
        "update",
        "1.0.0",
        "updates",
        "config-7",
        7,
        payload,
    )
    .with_structured_device_scope(StructuredDeviceScopeV1::current_device(
        "device-1",
        Some("installation-1"),
    ));
    let cloud = AuthorizationResponseV1::new_cloud(
        &request,
        "authorization-module",
        "snapshot-module",
        LicenseState::Active,
        7,
        100,
        90,
        Some(200),
        Some(180),
        Some(180),
        Some(200),
        IntegrityProof::new(
            "ed25519",
            "platform-key-module",
            "JCS-RFC8785",
            "platform-signature-module",
        )
        .with_origin_audience("authorization-platform", "authorization-a"),
        vec!["launch".to_string(), "updates".to_string()],
        vec![module],
    )
    .with_structured_device_scope(StructuredDeviceScopeV1::current_device(
        "device-1",
        Some("installation-1"),
    ));
    let mut central_verifier = MockIntegrityVerifier::new();
    central_verifier
        .allow(&cloud.integrity, cloud.canonical_payload())
        .unwrap();
    let signer = MockIntegritySigner::new("a-key-module", "a-signature-module");
    let product_manifest = manifest("skin-studio");
    let response = cloud
        .to_core_with_signer_for(
            &request,
            &product_manifest,
            &binding,
            &central_verifier,
            &signer,
        )
        .unwrap();
    response
        .validate_for_manifest(&manifest("skin-studio"))
        .unwrap();

    let mut raw_credential = response.clone();
    raw_credential.modules[0]
        .payload
        .insert("raw_card_key".to_string(), "card-secret".to_string());
    assert!(matches!(
        raw_credential.validate_for_manifest(&manifest("skin-studio")),
        Err(AuthorizationError::InvalidRequest(message)) if message.contains("raw credentials")
    ));

    let mut mismatched = response.clone();
    mismatched.modules[0].profile_id = "other-profile".to_string();
    assert!(matches!(
        mismatched.validate_for_manifest(&manifest("skin-studio")),
        Err(AuthorizationError::BindingMismatch { .. })
    ));
}

#[test]
fn formal_transport_round_trip_is_explicit_and_legacy_path_remains_available() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let mut verifier = MockIntegrityVerifier::new();
    let response = verified_response(&binding, &mut verifier);
    let expected_frame = LocalTransportFrame::from_authorization(response.clone());
    let bytes = LocalTransportFrame::encode_verified_authorization_for(
        response, &manifest, &binding, &verifier,
    )
    .unwrap();
    let decoded = LocalTransportFrame::decode_verified_authorization_for(
        &bytes, &manifest, &binding, &verifier,
    )
    .unwrap();
    assert_eq!(decoded, expected_frame);
    assert_eq!(decoded.protocol, "authorization-a-core.v1");
}

#[test]
fn formal_error_transport_round_trip_uses_final_error_contract() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let error = AuthorizationErrorResponseV1::new_core_with_message(
        "request-error-frame",
        &binding,
        AuthorizationErrorCode::ServiceTemporarilyUnavailable,
        "central authorization service is temporarily unavailable",
        1_755_000_100,
        IntegrityProof::new(
            "ed25519",
            "a-key-error-frame",
            "JCS-RFC8785",
            "a-signature-error-frame",
        )
        .with_origin_audience("authorization-a", "authorization-a-core"),
    );
    let mut verifier = MockIntegrityVerifier::new();
    verifier
        .allow(&error.integrity, error.canonical_payload())
        .unwrap();

    let bytes = LocalTransportFrame::encode_verified_error_for(
        error.clone(),
        &manifest,
        &binding,
        &verifier,
    )
    .unwrap();
    let payload = String::from_utf8(bytes[LOCAL_FRAME_HEADER_BYTES..].to_vec()).unwrap();
    assert!(payload.contains("authorization_error"));
    assert!(payload.contains("SERVICE_TEMPORARILY_UNAVAILABLE"));
    assert!(!payload.contains("not_modified"));

    let decoded =
        LocalTransportFrame::decode_verified_error_for(&bytes, &manifest, &binding, &verifier)
            .unwrap();
    assert_eq!(decoded.protocol, "authorization-a-core.v1");
    assert!(matches!(
        decoded.message,
        authorization_a_template::CoreMessage::Error(_)
    ));
}

#[test]
fn secure_formal_encoder_rejects_unverified_fixture_proof() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let response = cloud_response(&binding).to_core().unwrap();
    let verifier = MockIntegrityVerifier::new();
    assert!(matches!(
        LocalTransportFrame::encode_verified_authorization_for(
            response, &manifest, &binding, &verifier,
        ),
        Err(TransportError::Contract(
            authorization_a_template::ContractError::InvalidSnapshot(_)
        ))
    ));
}

#[test]
fn formal_transport_rejects_missing_required_binding_field() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let mut verifier = MockIntegrityVerifier::new();
    let response = verified_response(&binding, &mut verifier);
    let frame = LocalTransportFrame::from_authorization(response);
    let bytes = frame.encode_authorization_for(&manifest).unwrap();
    let payload = String::from_utf8(bytes[LOCAL_FRAME_HEADER_BYTES..].to_vec()).unwrap();
    let payload = payload.replace("\"profile_id\":\"profile-default\",", "");
    let mut malformed = Vec::with_capacity(LOCAL_FRAME_HEADER_BYTES + payload.len());
    malformed.extend_from_slice(b"ACV1");
    malformed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    malformed.extend_from_slice(payload.as_bytes());

    assert!(matches!(
        LocalTransportFrame::decode_authorization_for(&malformed, &manifest),
        Err(TransportError::MalformedPayload(_))
    ));
}

#[test]
fn auth_invalid_is_local_only_and_non_retryable() {
    let core_schema = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/protocol/authorization-a-core.v1.error.schema.json"
    ));
    let cloud_schema = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/protocol/authorization.v1.schema.json"
    ));
    assert!(core_schema.contains("\"AUTH_INVALID\""));
    assert!(!cloud_schema.contains("\"AUTH_INVALID\""));
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/auth-invalid.authorization-a-core.v1.error.json"
    ));
    let fixture_error = AuthorizationErrorResponseV1::from_json(fixture).unwrap();
    assert_eq!(fixture_error.error_code, "AUTH_INVALID");
    assert!(!fixture_error.retryable);

    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let signer = MockIntegritySigner::new("a-key-auth-invalid", "a-signature-auth-invalid");
    let error = AuthorizationErrorResponseV1::new_core_from_platform_error(
        "request-conflict",
        &binding,
        "IDEMPOTENCY_CONFLICT",
        1_755_000_100,
        signer.integrity_template(),
    )
    .sign_for_core(&manifest, &binding, &signer)
    .unwrap();

    assert_eq!(error.error_code, "AUTH_INVALID");
    assert_eq!(error.message, "AUTH_INVALID");
    assert!(!error.retryable);
    assert_eq!(error.request_id, "request-conflict");
    error.verify(&signer).unwrap();
    assert!(AuthorizationErrorCode::from_str("AUTH_INVALID").is_some());
    assert!(!AuthorizationErrorCode::AuthInvalid.retryable());
}

#[test]
fn unbound_deactivate_response_is_restricted_and_signed_as_deny() {
    let binding = make_binding("skin-studio", "client-1");
    let manifest = manifest("skin-studio");
    let mut request = cloud_request(&binding);
    request.operation = "deactivate".to_string();
    let mut central = cloud_response(&binding);
    central.request_id = request.request_id.clone();
    central.state_code = "unbound".to_string();

    let mut central_verifier = MockIntegrityVerifier::new();
    central_verifier
        .allow(&central.integrity, central.canonical_payload())
        .unwrap();
    let signer = MockIntegritySigner::new("a-key-unbound", "a-signature-unbound");

    let ordinary_path = central.validate_for_platform_response().unwrap_err();
    assert_eq!(ordinary_path.code().as_str(), "RESPONSE_SCHEMA_INVALID");

    let denial = AuthorizationResponseV1::from_platform_unbound_deactivate_json(
        &central.to_json(),
        &request,
        &manifest,
        &binding,
        200,
        &central_verifier,
        &signer,
    )
    .unwrap();
    assert_eq!(denial.error_code, "AUTH_INVALID");
    assert!(!denial.retryable);
    assert_eq!(denial.request_id, request.request_id);
    denial.verify(&signer).unwrap();

    let http_error = AuthorizationResponseV1::from_platform_unbound_deactivate_json(
        &central.to_json(),
        &request,
        &manifest,
        &binding,
        403,
        &central_verifier,
        &signer,
    )
    .unwrap_err();
    assert!(matches!(
        http_error,
        AuthorizationError::InvalidRequest(message)
            if message.contains("successful HTTP status")
    ));

    let mut wrong_method = request.clone();
    wrong_method.operation = "activate".to_string();
    let mut central_for_wrong_method = cloud_response(&binding);
    central_for_wrong_method.request_id = wrong_method.request_id.clone();
    central_for_wrong_method.state_code = "unbound".to_string();
    let error = central_for_wrong_method
        .to_core_auth_invalid_for_unbound(
            &wrong_method,
            &manifest,
            &binding,
            200,
            &central_verifier,
            &signer,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        AuthorizationError::InvalidRequest(message)
            if message.contains("deactivate compatibility")
    ));
}

#[test]
fn final_error_codes_are_wire_stable_and_retry_only_transient() {
    for code in [
        "AUTH_INVALID",
        "INVALID_REQUEST",
        "RESPONSE_SCHEMA_INVALID",
        "MISSING_REQUIRED_FIELD",
        "UNAUTHORIZED",
        "FORBIDDEN",
        "SOFTWARE_MISMATCH",
        "PROFILE_MISMATCH",
        "CONTRACT_VERSION_UNSUPPORTED",
        "LICENSE_NOT_FOUND",
        "LICENSE_NOT_ACTIVE",
        "LICENSE_EXPIRED",
        "AUTHORIZATION_REVOKED",
        "AUTHORIZATION_BLOCKED",
        "DEVICE_SCOPE_MISMATCH",
        "DEVICE_NOT_BOUND",
        "DEVICE_LIMIT_REACHED",
        "DEVICE_PROOF_REQUIRED",
        "DEVICE_PROOF_INVALID",
        "REPLAY_DETECTED",
        "SIGNATURE_INVALID",
        "KEY_UNKNOWN",
        "TIME_ROLLBACK_DETECTED",
        "TIME_SKEW",
        "VERSION_BLOCKED",
        "RISK_BLOCKED",
        "ADAPTER_UNSUPPORTED",
        "RATE_LIMITED",
        "SERVICE_TEMPORARILY_UNAVAILABLE",
        "IDEMPOTENCY_CONFLICT",
        "INTERNAL_ERROR",
    ] {
        let parsed = AuthorizationErrorCode::from_str(code).expect("final code must parse");
        assert_eq!(parsed.as_str(), code);
        assert_eq!(
            parsed.retryable(),
            matches!(
                code,
                "RATE_LIMITED" | "SERVICE_TEMPORARILY_UNAVAILABLE" | "INTERNAL_ERROR"
            )
        );
    }
    assert!(AuthorizationErrorCode::from_str("AUTH_SERVER_TIME_ROLLBACK").is_none());
}
