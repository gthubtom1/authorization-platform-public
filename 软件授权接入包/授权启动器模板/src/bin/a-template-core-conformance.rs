//! Offline conformance walkthrough for the generic central-to-core boundary.
//!
//! This binary intentionally uses only fixture verifier/signer seams. It is a
//! developer check, not a licensing service, launcher, IPC endpoint, or
//! production cryptographic implementation.

use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationBinding, AuthorizationIdentity, AuthorizationRequestV1, AuthorizationResponseV1,
    Capability, CompatibilityMode, CoreMessage, IntegrityProof, LicenseState, LocalTransportFrame,
    MockIntegritySigner, MockIntegrityVerifier, ProductManifest, StructuredDeviceScopeV1,
    ThemeTokens,
};

const FIXTURE_TIME: u64 = 1_755_000_000;

fn fixture_manifest() -> ProductManifest {
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

fn fixture_binding() -> AuthorizationBinding {
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

fn fixture_request(binding: &AuthorizationBinding) -> AuthorizationRequestV1 {
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

fn fixture_cloud_response(request: &AuthorizationRequestV1) -> AuthorizationResponseV1 {
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

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().nth(1).is_some() {
        return Err("this offline conformance check accepts no arguments".into());
    }

    let manifest = fixture_manifest();
    let binding = fixture_binding();
    let request = fixture_request(&binding);
    request.validate_for_platform_with_proof_required(true)?;

    let central = fixture_cloud_response(&request);
    let central_wire = central.to_json();
    let parsed_central = AuthorizationResponseV1::from_platform_json(&central_wire)?;
    let mut central_verifier = MockIntegrityVerifier::new();
    central_verifier.allow(
        &parsed_central.integrity,
        parsed_central.canonical_payload(),
    )?;

    let local_signer = MockIntegritySigner::new("fixture-a-key", "fixture-a-signature");
    let core = parsed_central.to_core_with_signer_for(
        &request,
        &manifest,
        &binding,
        &central_verifier,
        &local_signer,
    )?;
    core.verify_for_core(&manifest, &binding, &local_signer)?;

    ensure(
        core.protocol == "authorization-a-core.v1"
            && core.schema_version == "authorization-a-core.v1"
            && core.contract_version == "authorization-a-core.v1",
        "local envelope protocol contract is not authorization-a-core.v1",
    )?;
    ensure(
        core.integrity.origin == "authorization-a"
            && core.integrity.audience == "authorization-a-core"
            && core.integrity.algorithm == "ed25519"
            && core.integrity.canonicalization == "JCS-RFC8785",
        "local envelope integrity boundary is invalid",
    )?;
    ensure(
        core.structured_device_scope.as_ref().is_some_and(|scope| {
            scope.scope == "current_device"
                && scope.device_id.as_deref() == Some("server-device")
                && scope.installation_id.as_deref() == Some("fixture-installation")
        }),
        "server-confirmed device_scope was not preserved",
    )?;

    let core_wire = core.to_json();
    for field in [
        "device_public_key",
        "device_proof",
        "client_version",
        "nonce",
    ] {
        ensure(
            !core_wire.contains(&format!("\"{field}\"")),
            "request-only credential leaked into the A-core envelope",
        )?;
    }
    let canonical = core.canonical_payload();
    ensure(
        canonical.contains("\"origin\":\"authorization-a\"")
            && canonical.contains("\"audience\":\"authorization-a-core\"")
            && !canonical.contains("\"signature\""),
        "canonical payload does not cover the complete response without signature",
    )?;

    let frame = LocalTransportFrame::encode_verified_authorization_for(
        core.clone(),
        &manifest,
        &binding,
        &local_signer,
    )?;
    let decoded = LocalTransportFrame::decode_verified_authorization_for(
        &frame,
        &manifest,
        &binding,
        &local_signer,
    )?;
    let decoded_core = match decoded.message {
        CoreMessage::Authorization(response) => response,
        _ => return Err("conformance frame did not contain authorization response".into()),
    };
    ensure(
        decoded_core == core,
        "ACV1 encode/decode changed the signed A-core envelope",
    )?;

    println!("authorization-a-core.v1 conformance: PASS");
    println!("boundary: central response verified; A response re-signed; core response verified");
    println!("claim: active / current_device / paired server-confirmed device scope");
    println!(
        "transport: ACV1 frame encoded and decoded ({} bytes)",
        frame.len()
    );
    println!("request-only: platform credentials absent from the local envelope");
    println!("crypto: fixture-only mock signer/verifier; production Ed25519/JCS remains external");
    Ok(())
}
