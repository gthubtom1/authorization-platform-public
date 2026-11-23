//! Live-platform-shape parsing, driven by the synced fixtures.
//! Source: `fixtures/authorization_v1/*`, `fixtures/authorization_a_core_v1/*`
//! (copied 2026-10-01, see `protocol/SYNC-20251001.md`).

use authorization_a_template::{
    parse_platform_envelope, AuthorizationError, PlatformDecision, PlatformEnvelope,
};

fn load(name: &str) -> String {
    std::fs::read_to_string(format!("fixtures/authorization_v1/{name}"))
        .expect("synced platform fixture must exist")
}

fn must_response(name: &str) -> authorization_a_template::PlatformResponse {
    match parse_platform_envelope(&load(name)) {
        Ok(PlatformEnvelope::Response(response)) => response,
        other => panic!("{name} must parse as a platform response, got {other:?}"),
    }
}

fn must_schema_invalid(payload: &str) {
    match parse_platform_envelope(payload) {
        Err(AuthorizationError::ResponseSchemaInvalid(_)) => {}
        other => panic!(
            "malformed platform payload must collapse to RESPONSE_SCHEMA_INVALID, got {other:?}"
        ),
    }
}

#[test]
fn active_fixture_parses_with_revision_and_times() {
    let response = must_response("active.json");
    assert_eq!(response.decision, PlatformDecision::Active);
    assert!(!response.decision.must_stop_core());
    assert_eq!(response.authorization_revision, 17);
    assert_eq!(response.software_id, "software-a");
    assert_eq!(response.profile_id, "stable");
    assert_eq!(response.config_version, "cfg-17");
    assert!(response.cache_until <= response.expires_at);
    assert!(response.next_verify_at <= response.expires_at);
    assert_eq!(response.integrity.key_id, "fixture-key-1");
    assert!(response.support.is_empty());
    assert!(response.announcement.is_empty());
    assert!(!response.modules.purchase_present);
    assert!(!response.modules.qr_present);
    assert!(response.modules.update.is_none());
    assert!(response.device_scope.device_id.as_deref() == Some("device-a"));
    assert!(response.device_scope.installation_id.as_deref() == Some("install-a"));
}

#[test]
fn lifecycle_decisions_map_and_stop_rules() {
    for (name, decision, must_stop) in [
        ("grace.json", PlatformDecision::Grace, false),
        ("expired.json", PlatformDecision::Expired, true),
        ("revoked.json", PlatformDecision::Revoked, true),
        ("blocked.json", PlatformDecision::Blocked, true),
        ("unbound.json", PlatformDecision::Unbound, true),
    ] {
        let response = must_response(name);
        assert_eq!(response.decision, decision, "{name}");
        assert_eq!(response.decision.must_stop_core(), must_stop, "{name}");
    }
}

#[test]
fn not_modified_is_a_normal_decision_that_keeps_running() {
    let response = must_response("not_modified.json");
    assert_eq!(response.decision, PlatformDecision::NotModified);
    assert!(!response.decision.must_stop_core());
    assert_eq!(response.authorization_revision, 17);
}

#[test]
fn risk_blocked_error_envelope_parses() {
    match parse_platform_envelope(&load("risk-blocked-error.json")) {
        Ok(PlatformEnvelope::Error(error)) => {
            assert_eq!(error.code, "RISK_BLOCKED");
            assert!(!error.retryable);
            assert_eq!(error.http_status, Some(403));
        }
        other => panic!("risk fixture must parse as error envelope, got {other:?}"),
    }
}

#[test]
fn old_template_shape_is_rejected() {
    // Old envelope keys must not pass as platform responses.
    must_schema_invalid(
        r#"{"protocol":"authorization.v1","schema_version":"authorization.v1","contract_version":"authorization.v1","request_id":"r","product_id":"p","software_id":"s","profile_id":"stable","client_id":"c","device_scope":{"scope":"current_device","device_id":"d","installation_id":"i"},"device_id":"d","authorization_id":"a","target":"windows","arch":"x64","channel":"stable","authorization_revision":1,"config_version":"c","snapshot_id":"s","decision":"active","state_code":"AUTH_ACTIVE","issued_at":1,"expires_at":2,"server_time":1,"cache_until":2,"next_verify_at":2,"grace_until":2,"integrity":{"algorithm":"ed25519","key_id":"k","canonicalization":"JCS-RFC8785","signature":"s","origin":"o","audience":"a"},"capabilities":[],"modules":[]}"#,
    );
}

#[test]
fn request_only_credentials_are_rejected() {
    let mut payload = load("active.json");
    payload = payload.replace(
        "\"integrity\":",
        "\"device_proof\": \"AAAAAAAA\", \"integrity\":",
    );
    must_schema_invalid(&payload);
}

#[test]
fn central_integrity_with_origin_audience_is_rejected() {
    let payload = load("active.json").replace(
        "\"signature\": \"fixture-signature\"",
        "\"signature\": \"fixture-signature\", \"origin\": \"x\", \"audience\": \"y\"",
    );
    must_schema_invalid(&payload);
}

#[test]
fn reask_times_beyond_expiry_are_rejected() {
    let payload =
        load("active.json").replace("\"cache_until\": 1787122800", "\"cache_until\": 1789689601");
    must_schema_invalid(&payload);
}

#[test]
fn unknown_module_key_is_rejected() {
    let payload = load("active.json").replace("\"qr\": null", "\"qr\": null, \"extra\": null");
    must_schema_invalid(&payload);
}

#[test]
fn support_announcement_update_content_parses() {
    let payload = load("active.json")
        .replace("\"support\": null", "\"support\": {\"purchase_url\": \"https://example.invalid/buy\", \"qq\": null, \"wechat\": \"helper\"}")
        .replace("\"announcement\": null", "\"announcement\": {\"title\": \"note\", \"body\": \"hello\"}")
        .replace("\"update\": null", "\"update\": {\"version\": \"1.2.4\", \"update_open_url\": \"https://example.invalid/dl\", \"has_update\": true}");
    let response = match parse_platform_envelope(&payload) {
        Ok(PlatformEnvelope::Response(response)) => response,
        other => panic!("content fixture must parse, got {other:?}"),
    };
    assert!(!response.support.is_empty());
    assert_eq!(
        response.support.purchase_url.as_deref(),
        Some("https://example.invalid/buy")
    );
    assert_eq!(response.support.wechat.as_deref(), Some("helper"));
    assert!(!response.announcement.is_empty());
    let update = response.modules.update.expect("update must be present");
    assert_eq!(update.version.as_deref(), Some("1.2.4"));
    assert_eq!(
        update.open_url.as_deref(),
        Some("https://example.invalid/dl")
    );
    assert_eq!(update.has_update, Some(true));
}

#[test]
fn a_core_fixtures_share_the_fixed_module_shape() {
    for name in ["active.json", "expired.json"] {
        let payload = std::fs::read_to_string(format!("fixtures/authorization_a_core_v1/{name}"))
            .expect("synced a-core fixture must exist");
        // a-core envelopes are consumed by the local contract path; here we
        // only pin the shared fixed-key modules object both sides agree on.
        assert!(payload.contains("\"notice\""), "{name}");
    }
}

#[test]
fn missing_display_blocks_default_to_empty() {
    // Platform deviation pin: the platform's own blocked.json fixture omits
    // top-level announcement even though its schema marks it required.
    // Absence defaults to empty; malformed presence still fails closed.
    let response = must_response("blocked.json");
    assert_eq!(response.decision, PlatformDecision::Blocked);
    assert!(response.announcement.is_empty());
    assert_eq!(response.error_code.as_deref(), Some("LICENSE_BLOCKED"));
}

fn ticket_payload() -> String {
    r#"{"schema_version":"authorization.v1","contract_version":"authorization.v1","request_id":"ticket-1","software_id":"ticket-tool","profile_id":"stable","client_id":"ticket-tool-windows","target":"windows","arch":"x64","channel":"stable","authorization_id":"auth-1","authorization_revision":3,"decision":"issued","server_time":1787101200,"ticket":{"ticket_id":"11111111-2222-3333-4444-555555555555","software_id":"ticket-tool","profile_id":"stable","client_id":"ticket-tool-windows","installation_id":"install-a","issued_at":1787101200,"not_before":1787101200,"expires_at":1787101380,"audience":"ticket-tool-core"},"integrity":{"algorithm":"ed25519","key_id":"k1","canonicalization":"JCS-RFC8785","origin":"authorization-platform","audience":"ticket-tool-core","signature":"sig"}}"#.to_string()
}

#[test]
fn ticket_issue_parses_with_audience_and_lifetime() {
    use authorization_a_template::{parse_ticket_response, TicketDecision};
    let response = parse_ticket_response(&ticket_payload()).expect("ticket must parse");
    assert_eq!(response.decision, TicketDecision::Issued);
    assert_eq!(response.ticket.audience, "ticket-tool-core");
    assert_eq!(response.ticket.expires_at - response.ticket.issued_at, 180);
    assert_eq!(response.integrity_key_id, "k1");
}

#[test]
fn ticket_wrong_audience_or_lifetime_fails_closed() {
    use authorization_a_template::parse_ticket_response;
    let bad_audience = ticket_payload().replace("ticket-tool-core", "other-core");
    assert!(parse_ticket_response(&bad_audience).is_err());
    let bad_integrity_audience = ticket_payload().replace(
        "\"audience\":\"ticket-tool-core\",\"signature\"",
        "\"audience\":\"other-core\",\"signature\"",
    );
    assert!(parse_ticket_response(&bad_integrity_audience).is_err());
    let missing_origin = ticket_payload().replace("\"origin\":\"authorization-platform\",", "");
    assert!(parse_ticket_response(&missing_origin).is_err());
    let body_mismatch = ticket_payload().replace(
        "\"ticket\":{\"ticket_id\":\"11111111-2222-3333-4444-555555555555\",\"software_id\":\"ticket-tool\"",
        "\"ticket\":{\"ticket_id\":\"11111111-2222-3333-4444-555555555555\",\"software_id\":\"other-tool\"",
    );
    assert!(parse_ticket_response(&body_mismatch).is_err());
    let zero_lifetime =
        ticket_payload().replace("\"expires_at\":1787101380", "\"expires_at\":1787101200");
    assert!(parse_ticket_response(&zero_lifetime).is_err());
    let inverted =
        ticket_payload().replace("\"not_before\":1787101200", "\"not_before\":1787101400");
    assert!(parse_ticket_response(&inverted).is_err());
}

#[test]
fn ticket_error_envelope_refuses_with_code() {
    use authorization_a_template::parse_ticket_response;
    let error =
        r#"{"error":{"code":"LICENSE_REVOKED","message":"x","request_id":"r","retryable":false}}"#;
    let result = parse_ticket_response(error).expect_err("must refuse");
    assert!(format!("{result:?}").contains("LICENSE_REVOKED"));
}

#[test]
fn ticket_wallet_single_use_expiry_and_device() {
    use authorization_a_template::{parse_ticket_response, TicketWallet};
    let response = parse_ticket_response(&ticket_payload()).expect("ticket must parse");
    let mut wallet = TicketWallet::default();
    wallet.store(response.ticket.clone(), 1787101200);
    // Wrong device first: must fail without consuming.
    assert!(wallet
        .take_for_launch("ticket-tool", "install-b", 1787101200)
        .is_err());
    // Expired: must fail without consuming.
    assert!(wallet
        .take_for_launch("ticket-tool", "install-a", 1787101380)
        .is_err());
    // Correct launch consumes exactly once.
    let taken = wallet
        .take_for_launch("ticket-tool", "install-a", 1787101200)
        .expect("first launch must succeed");
    assert_eq!(taken.ticket_id, "11111111-2222-3333-4444-555555555555");
    assert!(wallet
        .take_for_launch("ticket-tool", "install-a", 1787101200)
        .is_err());
}

#[test]
fn ticket_wallet_never_overwrites_live_ticket_with_older() {
    use authorization_a_template::{parse_ticket_response, TicketWallet};
    let response = parse_ticket_response(&ticket_payload()).expect("ticket must parse");
    let mut wallet = TicketWallet::default();
    wallet.store(response.ticket.clone(), 1787101200);
    // An older ticket must not displace the live one.
    let mut older = response.ticket.clone();
    older.expires_at = 1787101300;
    wallet.store(older, 1787101200);
    let taken = wallet
        .take_for_launch("ticket-tool", "install-a", 1787101200)
        .expect("live ticket must survive");
    assert_eq!(taken.expires_at, 1787101380);
}

fn ticket_params() -> authorization_a_template::TicketRequestParams {
    use authorization_a_template::{TicketRequestAction, TicketRequestParams};
    TicketRequestParams {
        action: TicketRequestAction::Issue,
        request_id: "req-1".to_string(),
        idempotency_key: None,
        software_id: "ticket-tool".to_string(),
        profile_id: "stable".to_string(),
        client_id: "ticket-tool-windows".to_string(),
        target: "windows".to_string(),
        arch: "x64".to_string(),
        channel: "stable".to_string(),
        authorization_id: "auth-1".to_string(),
        installation_id: "install-a".to_string(),
        device_public_key: "QUJD".to_string(),
        client_version: "1.0.0".to_string(),
        nonce: "nonce-12345678".to_string(),
        ticket_id: None,
    }
}

#[test]
fn ticket_request_builds_issue_shape_without_proof() {
    use authorization_a_template::build_ticket_request;
    let json = build_ticket_request(&ticket_params()).expect("valid params must build");
    assert!(json.contains("\"contract_version\":\"authorization.v1\""));
    assert!(!json.contains("device_proof"));
    assert!(!json.contains("ticket_id"));
}

#[test]
fn ticket_request_rejects_bad_shapes() {
    use authorization_a_template::{build_ticket_request, TicketRequestAction};
    // Short nonce.
    let mut params = ticket_params();
    params.nonce = "short".to_string();
    assert!(build_ticket_request(&params).is_err());
    // Consume without ticket_id.
    let mut params = ticket_params();
    params.action = TicketRequestAction::Consume;
    assert!(build_ticket_request(&params).is_err());
    // Issue must not carry ticket_id.
    let mut params = ticket_params();
    params.ticket_id = Some("11111111-2222-3333-4444-555555555555".to_string());
    assert!(build_ticket_request(&params).is_err());
    // Consume with ticket_id builds and names the endpoint.
    let mut params = ticket_params();
    params.action = TicketRequestAction::Consume;
    params.ticket_id = Some("11111111-2222-3333-4444-555555555555".to_string());
    let json = build_ticket_request(&params).expect("consume must build");
    assert!(json.contains("\"ticket_id\":\"11111111-2222-3333-4444-555555555555\""));
    assert_eq!(
        TicketRequestAction::Consume.path(),
        "/api/v1/public/licenses/launch-ticket/consume"
    );
    assert_eq!(
        TicketRequestAction::Issue.path(),
        "/api/v1/public/licenses/launch-ticket"
    );
}

#[test]
fn ticket_request_idempotency_defaults_to_request_id() {
    use authorization_a_template::build_ticket_request;
    let json = build_ticket_request(&ticket_params()).expect("must build");
    assert!(json.contains("\"idempotency_key\":\"req-1\""));
    let mut params = ticket_params();
    params.idempotency_key = Some("custom-key-9".to_string());
    let json = build_ticket_request(&params).expect("must build");
    assert!(json.contains("\"idempotency_key\":\"custom-key-9\""));
}
