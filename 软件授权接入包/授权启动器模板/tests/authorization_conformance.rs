use std::path::PathBuf;
use std::process::Command;

use authorization_a_template::{
    AuthorizationBinding, AuthorizationIdentity, AuthorizationRequestV1, AuthorizationResponseV1,
    Capability, CompatibilityMode, CoreMessage, IntegrityError, IntegrityProof, IntegrityVerifier,
    LicenseState, LocalTransportFrame, MockIntegritySigner, MockIntegrityVerifier, ProductManifest,
    StructuredDeviceScopeV1, ThemeTokens,
};

const FIXTURE_TIME: u64 = 1_755_000_000;

fn manifest() -> ProductManifest {
    ProductManifest::new(
        "fixture-product",
        "Fixture Product",
        "fixture-adapter",
        "1.0.0",
        "zh-CN",
        ThemeTokens::neutral(),
        PathBuf::from("core/fixture.exe"),
        PathBuf::from("state/fixture"),
        "fixture-a-core",
        CompatibilityMode::LegacyAuth,
        vec![Capability::required("launch", "1")],
    )
}

fn binding() -> AuthorizationBinding {
    AuthorizationBinding::new(
        "fixture-product",
        AuthorizationIdentity::new(
            "fixture-software",
            "fixture-profile",
            "fixture-client",
            "current_device",
            "server-device",
        ),
    )
}

fn request(binding: &AuthorizationBinding) -> AuthorizationRequestV1 {
    AuthorizationRequestV1::new("fixture-request", binding, "fixture-config", None)
        .with_target_arch_channel("windows", "x86_64", "stable")
        .with_platform_credentials(
            "A".repeat(43),
            Some("A".repeat(86)),
            "fixture-installation",
            "1.0.0",
            "fixture-nonce-1234",
        )
}

fn central_response(request: &AuthorizationRequestV1) -> AuthorizationResponseV1 {
    AuthorizationResponseV1::new_cloud(
        request,
        "fixture-authorization",
        "fixture-snapshot",
        LicenseState::Active,
        7,
        FIXTURE_TIME + 100,
        FIXTURE_TIME,
        Some(FIXTURE_TIME + 200),
        Some(FIXTURE_TIME + 120),
        Some(FIXTURE_TIME + 120),
        Some(FIXTURE_TIME + 200),
        IntegrityProof::new(
            "ed25519",
            "fixture-platform-key",
            "JCS-RFC8785",
            "fixture-platform-signature",
        )
        .with_origin_audience("authorization-platform", "authorization-a"),
        vec!["launch".to_string()],
        Vec::new(),
    )
    .with_structured_device_scope(StructuredDeviceScopeV1::current_device(
        "server-device",
        Some("fixture-installation"),
    ))
}

fn signed_core() -> (
    ProductManifest,
    AuthorizationBinding,
    AuthorizationRequestV1,
    MockIntegritySigner,
    AuthorizationResponseV1,
) {
    let product_manifest = manifest();
    let product_binding = binding();
    let platform_request = request(&product_binding);
    let central = central_response(&platform_request);
    let parsed = AuthorizationResponseV1::from_platform_json(&central.to_json()).unwrap();
    let mut verifier = MockIntegrityVerifier::new();
    verifier
        .allow(&parsed.integrity, parsed.canonical_payload())
        .unwrap();
    let signer = MockIntegritySigner::new("fixture-a-key", "fixture-a-signature");
    let core = parsed
        .to_core_with_signer_for(
            &platform_request,
            &product_manifest,
            &product_binding,
            &verifier,
            &signer,
        )
        .unwrap();
    (
        product_manifest,
        product_binding,
        platform_request,
        signer,
        core,
    )
}

#[test]
fn generic_conformance_rebuilds_and_round_trips_signed_a_core_envelope() {
    let (product_manifest, product_binding, platform_request, signer, core) = signed_core();

    assert_eq!(core.protocol, "authorization-a-core.v1");
    assert_eq!(core.schema_version, "authorization-a-core.v1");
    assert_eq!(core.contract_version, "authorization-a-core.v1");
    assert_eq!(core.integrity.origin, "authorization-a");
    assert_eq!(core.integrity.audience, "authorization-a-core");
    assert_eq!(core.integrity.algorithm, "ed25519");
    assert_eq!(core.integrity.canonicalization, "JCS-RFC8785");
    assert!(core
        .structured_device_scope
        .as_ref()
        .is_some_and(|scope| scope.device_id.as_deref() == Some("server-device")
            && scope.installation_id.as_deref() == Some("fixture-installation")));

    let request_wire = platform_request.to_json();
    for field in [
        "device_public_key",
        "device_proof",
        "client_version",
        "nonce",
    ] {
        assert!(request_wire.contains(&format!("\"{field}\"")));
    }
    let core_wire = core.to_json();
    for field in [
        "device_public_key",
        "device_proof",
        "client_version",
        "nonce",
    ] {
        assert!(!core_wire.contains(&format!("\"{field}\"")));
    }
    let canonical = core.canonical_payload();
    assert!(canonical.contains("\"origin\":\"authorization-a\""));
    assert!(canonical.contains("\"audience\":\"authorization-a-core\""));
    assert!(!canonical.contains("\"signature\""));
    signer
        .verify(&core.integrity, &canonical)
        .expect("A signer verifies the complete canonical response");

    let frame = LocalTransportFrame::encode_verified_authorization_for(
        core.clone(),
        &product_manifest,
        &product_binding,
        &signer,
    )
    .unwrap();
    let decoded = LocalTransportFrame::decode_verified_authorization_for(
        &frame,
        &product_manifest,
        &product_binding,
        &signer,
    )
    .unwrap();
    match decoded.message {
        CoreMessage::Authorization(response) => assert_eq!(response, core),
        other => panic!("unexpected conformance message: {other:?}"),
    }
}

#[test]
fn generic_conformance_rejects_tampered_authority_claims() {
    let (_, _, _, signer, core) = signed_core();
    let mutators: [fn(&mut AuthorizationResponseV1); 4] = [
        |response| response.request_id = "other-request".into(),
        |response| response.authorization_revision += 1,
        |response| response.decision = LicenseState::Grace,
        |response| response.server_time += 1,
    ];
    for mutate in mutators {
        let mut tampered = core.clone();
        mutate(&mut tampered);
        assert!(matches!(
            signer.verify(&tampered.integrity, &tampered.canonical_payload()),
            Err(IntegrityError::InvalidSignature)
        ));
    }
}

#[test]
fn conformance_command_returns_redacted_pass_summary() {
    let output = Command::new(env!("CARGO_BIN_EXE_a-template-core-conformance"))
        .output()
        .expect("conformance binary should be built for integration tests");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("authorization-a-core.v1 conformance: PASS"));
    assert!(stdout.contains("fixture-only mock signer/verifier"));
    for sensitive in [
        "fixture-platform-key",
        "fixture-platform-signature",
        "fixture-a-key",
        "fixture-a-signature",
        "device_public_key",
        "device_proof",
        "fixture-nonce-1234",
    ] {
        assert!(!stdout.contains(sensitive), "stdout leaked {sensitive}");
    }
}
