use std::collections::BTreeMap;
use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationBinding, AuthorizationIdentity, AuthorizationModuleV1, AuthorizationRequestV1,
    AuthorizationResponseV1, Capability, CompatibilityMode, DeviceScopeV1, IntegrityProof,
    LicenseState, ProductManifest, StructuredDeviceScopeV1, ThemeTokens,
};

const DEVICE_PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DEVICE_PROOF: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn request() -> AuthorizationRequestV1 {
    let binding = AuthorizationBinding::new(
        "sample-product",
        AuthorizationIdentity::new(
            "software-generic",
            "profile-default",
            "fixture-client-1",
            "current_device",
            DEVICE_ID,
        ),
    );
    AuthorizationRequestV1::new("fixture-request-platform-1", &binding, "config-7", None)
        .with_target_arch_channel("windows", "x86_64", "stable")
        .with_platform_credentials(
            DEVICE_PUBLIC_KEY,
            Some(DEVICE_PROOF),
            "installation-1",
            "1.0.0",
            "nonce-12345678",
        )
}

#[test]
fn platform_request_fixture_round_trips_and_validates_at_boundary() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/platform-request.authorization.v1.json"
    ));
    let request = AuthorizationRequestV1::from_json(fixture).unwrap();
    request
        .validate_for_platform_with_proof_required(true)
        .unwrap();
    let encoded = request.to_json();
    let decoded = AuthorizationRequestV1::from_json(&encoded).unwrap();
    assert_eq!(decoded, request);
    assert!(encoded.contains("\"device_public_key\""));
    assert!(encoded.contains("\"device_proof\""));
}

#[test]
fn request_credentials_enforce_decoded_lengths_and_nonce_policy() {
    let mut invalid_key = request();
    invalid_key
        .validate_for_platform_with_proof_required(true)
        .unwrap();

    invalid_key.device_public_key = "A=".to_string();
    assert!(invalid_key.validate_for_platform().is_err());

    let mut proof_optional = request();
    proof_optional.device_proof = Some("A".repeat(86));
    proof_optional.validate_for_platform().unwrap();
    assert!(proof_optional
        .validate_for_platform_with_proof_required(true)
        .is_ok());

    let mut missing_proof = request();
    missing_proof.device_proof = None;
    let proof_error = missing_proof
        .validate_for_platform_with_proof_required(true)
        .unwrap_err();
    assert_eq!(proof_error.code().as_str(), "DEVICE_PROOF_REQUIRED");
    assert!(!proof_error.code().retryable());

    let mut short_nonce = request();
    short_nonce.nonce = "short".to_string();
    assert!(short_nonce.validate_for_platform().is_err());

    let mut long_installation = request();
    long_installation.installation_id = "x".repeat(129);
    assert!(long_installation.validate_for_platform().is_err());

    let mut long_client_version = request();
    long_client_version.client_version = "x".repeat(65);
    assert!(long_client_version.validate_for_platform().is_err());
}

#[test]
fn structured_device_scope_is_exact_and_preserved_through_core() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/structured.active.authorization.v1.json"
    ));
    let cloud = AuthorizationResponseV1::from_json(fixture).unwrap();
    cloud.validate_for_platform_response().unwrap();
    let scope = cloud.structured_device_scope.as_ref().unwrap();
    assert_eq!(scope.scope, "current_device");
    assert_eq!(scope.device_id.as_deref(), Some(DEVICE_ID));
    assert_eq!(scope.installation_id.as_deref(), Some("installation-1"));
    assert!(cloud.to_json().contains("\"device_scope\":{\"device_id\""));

    let core = cloud.clone().to_core().unwrap();
    assert_eq!(core.structured_device_scope, cloud.structured_device_scope);
    let core_json = core.to_json();
    assert!(core_json.contains("\"installation_id\":\"installation-1\""));
    assert!(core_json.contains("\"scope\":\"current_device\""));
}

#[test]
fn structured_scope_rejects_unconfirmed_and_unknown_shapes() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/invalid.unconfirmed-device-scope.authorization.v1.json"
    ));
    let error = AuthorizationResponseV1::from_platform_json(fixture).unwrap_err();
    assert_eq!(error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
    assert!(!error.code().retryable());

    let scope = StructuredDeviceScopeV1::current_device(DEVICE_ID, Some("installation-1"));
    let malformed = scope.to_json().replace(
        "\"scope\":\"current_device\"",
        "\"extra\":\"x\",\"scope\":\"current_device\"",
    );
    assert!(StructuredDeviceScopeV1::from_json(&malformed).is_err());

    assert!(matches!(
        DeviceScopeV1::from_json("\"current_device\"").unwrap(),
        DeviceScopeV1::Legacy(value) if value == "current_device"
    ));
}

#[test]
fn unconfirmed_rejection_keeps_both_scope_claims_null() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/invalid.unconfirmed-device-scope.authorization.v1.json"
    ));
    let refusal = fixture
        .replace("\"decision\": \"active\"", "\"decision\": \"blocked\"")
        .replace(
            "\"state_code\": \"AUTH_ACTIVE\"",
            "\"state_code\": \"AUTH_BLOCKED\"",
        )
        .replace(
            "\"installation_id\": \"installation-1\"",
            "\"installation_id\": null",
        );
    let response = AuthorizationResponseV1::from_platform_json(&refusal).unwrap();
    let scope = response.structured_device_scope.as_ref().unwrap();
    assert_eq!(scope.device_id, None);
    assert_eq!(scope.installation_id, None);
    assert_eq!(response.decision, LicenseState::Blocked);
}

#[test]
fn refusal_response_rejects_partial_scope_claims() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/invalid.unconfirmed-device-scope.authorization.v1.json"
    ));
    let partial = fixture.replace(
        "\"installation_id\": null",
        "\"installation_id\": \"installation-1\"",
    );
    let partial = partial
        .replace("\"decision\": \"active\"", "\"decision\": \"blocked\"")
        .replace(
            "\"state_code\": \"AUTH_ACTIVE\"",
            "\"state_code\": \"AUTH_BLOCKED\"",
        );
    let error = AuthorizationResponseV1::from_platform_json(&partial).unwrap_err();
    assert_eq!(error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
}

#[test]
fn platform_response_requires_both_confirmed_scope_claims_for_launchable_states() {
    let request = request();
    let response = AuthorizationResponseV1::new_cloud(
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
    .with_structured_device_scope(StructuredDeviceScopeV1::new(
        "current_device",
        None::<String>,
        None::<String>,
    ));

    let error = response.validate_for_platform_response().unwrap_err();
    assert_eq!(error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
    assert!(!error.code().retryable());
}

#[test]
fn structured_scope_claims_use_frozen_lengths() {
    let too_long_device_id =
        StructuredDeviceScopeV1::current_device("d".repeat(65), Some("installation-1"));
    assert!(too_long_device_id.validate().is_err());

    let too_long_scope =
        StructuredDeviceScopeV1::new("s".repeat(33), Some(DEVICE_ID), Some("installation-1"));
    assert!(too_long_scope.validate().is_err());
}

#[test]
fn platform_response_shape_gate_rejects_leaks_and_invalid_time() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/structured.active.authorization.v1.json"
    ));
    let leaked = fixture.replace(
        "\"capabilities\": [\"launch\"]",
        "\"nonce\": \"nonce-sentinel\", \"capabilities\": [\"launch\"]",
    );
    let leaked_error = AuthorizationResponseV1::from_platform_json(&leaked).unwrap_err();
    assert_eq!(leaked_error.code().as_str(), "RESPONSE_SCHEMA_INVALID");

    let expired_at_server =
        fixture.replace("\"server_time\": 1755000100", "\"server_time\": 1755000200");
    let time_error = AuthorizationResponseV1::from_platform_json(&expired_at_server).unwrap_err();
    assert_eq!(time_error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
    assert!(!time_error.code().retryable());
}

#[test]
fn platform_response_schedule_and_expiry_gates_are_fail_closed() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/structured.active.authorization.v1.json"
    ));

    let mismatched_schedule = fixture.replace(
        "\"next_verify_at\": 1755000180",
        "\"next_verify_at\": 1755000120",
    );
    let schedule_error =
        AuthorizationResponseV1::from_platform_json(&mismatched_schedule).unwrap_err();
    assert_eq!(schedule_error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
    assert!(!schedule_error.code().retryable());

    let cache_beyond_expiry =
        fixture.replace("\"cache_until\": 1755000180", "\"cache_until\": 1755000201");
    let cache_beyond_expiry = cache_beyond_expiry.replace(
        "\"next_verify_at\": 1755000180",
        "\"next_verify_at\": 1755000201",
    );
    let cache_error =
        AuthorizationResponseV1::from_platform_json(&cache_beyond_expiry).unwrap_err();
    assert_eq!(cache_error.code().as_str(), "RESPONSE_SCHEMA_INVALID");

    let expired_before_expiry = fixture
        .replace("\"decision\": \"active\"", "\"decision\": \"expired\"")
        .replace(
            "\"state_code\": \"AUTH_ACTIVE\"",
            "\"state_code\": \"AUTH_EXPIRED\"",
        );
    let expired_error =
        AuthorizationResponseV1::from_platform_json(&expired_before_expiry).unwrap_err();
    assert_eq!(expired_error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
}

#[test]
fn central_unbound_fixture_is_not_an_a_core_state() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/unbound.deactivate.authorization.v1.json"
    ));
    let mut request = request();
    request.operation = "deactivate".to_string();
    let binding = AuthorizationBinding::new(request.product_id.clone(), request.identity.clone());
    let manifest = ProductManifest::new(
        "sample-product",
        "Sample Product",
        "sample-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from("core/sample.exe"),
        PathBuf::from("state/sample"),
        "a-auth-sample",
        CompatibilityMode::NativeCore,
        vec![Capability::required("launch", "1")],
    );
    let central = AuthorizationResponseV1::from_json(fixture).unwrap();
    let mut verifier = authorization_a_template::MockIntegrityVerifier::new();
    verifier
        .allow(&central.integrity, central.canonical_payload())
        .unwrap();
    let signer = authorization_a_template::MockIntegritySigner::new(
        "fixture-a-key-unbound",
        "fixture-a-signature-unbound",
    );
    let denial = AuthorizationResponseV1::from_platform_unbound_deactivate_json(
        fixture, &request, &manifest, &binding, 200, &verifier, &signer,
    )
    .unwrap();
    assert_eq!(denial.error_code, "AUTH_INVALID");
    assert!(!denial.retryable);

    let core_schema = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/protocol/authorization-a-core.v1.schema.json"
    ));
    assert!(!core_schema.contains("\"unbound\""));
}

#[test]
fn core_temporal_gate_rejects_cache_beyond_expiry() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/authorization/structured.active.authorization.v1.json"
    ));
    let central = AuthorizationResponseV1::from_platform_json(fixture).unwrap();
    let mut core = central.to_core().unwrap();
    core.integrity = IntegrityProof::new(
        "ed25519",
        "fixture-a-key",
        "JCS-RFC8785",
        "fixture-a-signature",
    )
    .with_origin_audience("authorization-a", "authorization-a-core");
    core.cache_until = Some(1_755_000_201);
    core.next_verify_at = Some(1_755_000_201);

    let request = request();
    let binding = AuthorizationBinding::new(request.product_id.clone(), request.identity.clone());
    let manifest = ProductManifest::new(
        "sample-product",
        "Sample Product",
        "sample-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from("core/sample.exe"),
        PathBuf::from("state/sample"),
        "a-auth-sample",
        CompatibilityMode::NativeCore,
        vec![Capability::required("launch", "1")],
    );
    let error = core.validate_for_binding(&manifest, &binding).unwrap_err();
    assert_eq!(error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
    assert!(!error.code().retryable());
}

#[test]
fn structured_platform_handoff_rejects_request_only_module_keys() {
    let request = request();
    let scope = StructuredDeviceScopeV1::current_device(DEVICE_ID, Some("installation-1"));
    let mut payload = BTreeMap::new();
    payload.insert("device_proof".to_string(), "proof-sentinel".to_string());
    let module = AuthorizationModuleV1::new(
        "sample-product",
        "authorization-1",
        &request.identity,
        "module-1",
        "notice",
        "1.0.0",
        "launch",
        "config-7",
        7,
        payload,
    )
    .with_structured_device_scope(scope.clone());
    let response = AuthorizationResponseV1::new_cloud(
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
        vec![module],
    )
    .with_structured_device_scope(scope);

    let error = response.to_core().unwrap_err();
    assert_eq!(error.code().as_str(), "RESPONSE_SCHEMA_INVALID");
}

#[test]
fn request_only_credentials_never_enter_core_json() {
    let request = request();
    request
        .validate_for_platform_with_proof_required(true)
        .unwrap();
    let response = AuthorizationResponseV1::new_cloud(
        &request,
        "authorization-1",
        "snapshot-1",
        authorization_a_template::LicenseState::Active,
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
        DEVICE_ID,
        Some("installation-1"),
    ));
    let core = response.to_core().unwrap();
    let core_json = core.to_json();
    let canonical = core.canonical_payload();
    for value in [DEVICE_PUBLIC_KEY, DEVICE_PROOF, "1.0.0", "nonce-12345678"] {
        assert!(
            !core_json.contains(value),
            "raw request value leaked: {value}"
        );
        assert!(
            !canonical.contains(value),
            "raw request value signed into core: {value}"
        );
    }
    assert_eq!(core_json.matches("\"installation_id\"").count(), 1);
    assert_eq!(canonical.matches("\"installation_id\"").count(), 1);
    for field in [
        "device_public_key",
        "device_proof",
        "client_version",
        "nonce",
    ] {
        assert!(
            !core_json.contains(field),
            "request-only field leaked: {field}"
        );
        assert!(
            !canonical.contains(field),
            "request-only field signed into core: {field}"
        );
    }
}

#[test]
fn request_only_fields_are_rejected_from_module_and_legacy_parameter_maps() {
    let request = request();
    let scope = StructuredDeviceScopeV1::current_device(DEVICE_ID, Some("installation-1"));
    let mut payload = BTreeMap::new();
    payload.insert("device_proof".to_string(), "proof-sentinel".to_string());
    let module = AuthorizationModuleV1::new(
        "sample-product",
        "authorization-1",
        &request.identity,
        "module-1",
        "notice",
        "1.0.0",
        "launch",
        "config-7",
        7,
        payload,
    )
    .with_structured_device_scope(scope.clone());
    let response = AuthorizationResponseV1::new_cloud(
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
        vec![module],
    )
    .with_structured_device_scope(scope);
    let manifest = ProductManifest::new(
        "sample-product",
        "Sample Product",
        "sample-adapter",
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from("core/sample.exe"),
        PathBuf::from("state/sample"),
        "a-auth-sample",
        CompatibilityMode::NativeCore,
        vec![Capability::required("launch", "1")],
    );
    assert!(matches!(
        response.validate_for_manifest(&manifest),
        Err(authorization_a_template::AuthorizationError::InvalidRequest(message))
            if message.contains("raw credentials")
    ));

    let manifest_with_nonce = manifest.with_protocol_parameter("nonce", "nonce-sentinel");
    assert!(manifest_with_nonce.validate().is_err());
}
