//! Regressions exercise the same host used by the desktop executable.
use authorization_a_template::current_runtime::{parse_json, verify_signed, LiveSession, VerifiedDocument};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn signed(mut value: Value) -> Value {
    let key = SigningKey::from_bytes(&[42; 32]);
    value["integrity"] = json!({"algorithm":"ed25519","key_id":"test",
        "canonicalization":"JCS-RFC8785"});
    let bytes = serde_jcs::to_vec(&value).unwrap();
    value["integrity"]["signature"] = URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()).into();
    value
}
fn response(request: &str, revision: u64, now: i64, expiry: i64, decision: &str) -> VerifiedDocument {
    let value = signed(json!({"request_id":request,"authorization_id":"auth", "authorization_revision":revision,
        "config_version":"cfg", "issued_at":10,"server_time":now,"expires_at":expiry,
        "cache_until":now+60,"next_verify_at":now+60,"grace_until":expiry,
        "decision":decision,"device_scope":{"scope":"current_device","device_id":"dev","installation_id":"install"}}));
    verify_signed(&value, "test", &SigningKey::from_bytes(&[42;32]).verifying_key()).unwrap()
}

#[test]
fn complete_original_object_is_verified_before_projection() {
    let key = SigningKey::from_bytes(&[42;32]);
    let v = signed(json!({"extensions":{"\u{10000}":1,"\u{e000}":1.25,"中文":"😀"},"server_time":-1}));
    assert!(verify_signed(&v, "test", &key.verifying_key()).is_ok());
    let mut tampered = v.clone(); tampered["extensions"]["中文"] = "changed".into();
    assert!(verify_signed(&tampered, "test", &key.verifying_key()).is_err());
    assert!(verify_signed(&v, "other", &key.verifying_key()).is_err());
    let parsed = parse_json(br#"{"x":"\ud83d\ude00","n":-9223372036854775808}"#).unwrap();
    assert_eq!(parsed["x"], "😀");
    assert!(parse_json(br#"{"x":1,"x":2}"#).is_err());
    assert!(parse_json(br#"{"x":{"a":1,"a":2}}"#).is_err());
    assert!(parse_json(br#"{"x":"\ud800"}"#).is_err());
    assert!(parse_json(&vec![b' '; 2_000_001]).is_err());
    assert!(parse_json(format!("{}0{}", "[".repeat(40), "]".repeat(40)).as_bytes()).is_err());
}

#[test]
fn heartbeat_not_modified_renewal_and_more_than_1024_requests() {
    let anchor = Instant::now();
    let mut session = LiveSession::default();
    for i in 0..1100 {
        let decision = if i == 0 { "active" } else { "not_modified" };
        session.accept(response(&format!("r{i}"), 1, 100+i, 10000, decision), anchor+Duration::from_secs(i as u64)).unwrap();
    }
    session.accept(response("renew", 2, 1200, 20000, "active"), anchor+Duration::from_secs(1100)).unwrap();
    assert_eq!(session.response().unwrap()["issued_at"], 10);
    assert_eq!(session.response().unwrap()["expires_at"], 20000);
    assert!(session.accept(response("old",1,1201,10000,"active"), anchor+Duration::from_secs(1101)).is_err());
    session.accept(response("revoke",3,1202,20000,"revoked"), anchor+Duration::from_secs(1102)).unwrap();
    assert!(session.accept(response("restore",4,1203,20000,"active"), anchor+Duration::from_secs(1103)).is_err());
}

#[test]
fn network_and_rate_limit_retry_never_extend_success_deadline() {
    let anchor = Instant::now(); let mut session = LiveSession::default();
    session.accept(response("a",1,100,10000,"active"), anchor).unwrap();
    for n in [10, 30, 59, 60, 100] {
        session.retry_after(anchor+Duration::from_secs(n), Duration::from_secs(120));
        assert_eq!(session.usable(anchor+Duration::from_secs(n)), n < 60);
    }
}

#[test]
fn zero_grace_refresh_is_due_before_deadline_and_failures_keep_the_original_deadline() {
    let anchor=Instant::now();let mut session=LiveSession::default();
    let mut value=signed(json!({"request_id":"short","authorization_id":"auth","authorization_revision":1,
        "config_version":"cfg","issued_at":10,"server_time":100,"expires_at":10000,
        "cache_until":104,"next_verify_at":104,"grace_until":10000,"decision":"active"}));
    let key=SigningKey::from_bytes(&[42;32]).verifying_key();
    session.accept(verify_signed(&value,"test",&key).unwrap(),anchor).unwrap();
    assert!(!session.due(anchor+Duration::from_secs(1)));
    assert!(session.due(anchor+Duration::from_secs(2)),"normal refresh must have room for 800ms RTT and the worker interval");
    let deadline=session.deadline().unwrap();
    session.retry_after(anchor+Duration::from_secs(2),Duration::from_secs(120));
    assert_eq!(session.deadline(),Some(deadline));
    assert!(session.usable(anchor+Duration::from_millis(3999)));
    assert!(!session.usable(anchor+Duration::from_secs(4)));
    value["request_id"]="next".into();value["server_time"]=102.into();value["cache_until"]=106.into();value["next_verify_at"]=106.into();
    session.accept(verify_signed(&signed(value),"test",&key).unwrap(),anchor+Duration::from_secs(2)).unwrap();
    assert!(session.usable(anchor+Duration::from_secs(4)));
}

#[test]
fn original_signed_notmodified_is_retained_and_equal_time_does_not_reset_fractional_clock() {
    let anchor=Instant::now();let mut session=LiveSession::default();
    session.accept(response("initial",1,100,10000,"active"),anchor).unwrap();
    session.accept(response("same-second",1,100,10000,"not_modified"),anchor+Duration::from_millis(800)).unwrap();
    assert_eq!(session.trusted_time(anchor+Duration::from_secs(1)),Some(101));
    let original=session.response().unwrap();
    assert_eq!(original["decision"],"not_modified");
    assert_eq!(original["request_id"],"same-second");
    assert_eq!(original["server_time"],100);
    assert_eq!(original["next_verify_at"],160);
    assert!(verify_signed(original,"test",&SigningKey::from_bytes(&[42;32]).verifying_key()).is_ok());
}

#[test]
fn fresh_same_second_success_replaces_online_budget_but_replay_does_not() {
    let anchor=Instant::now();let mut session=LiveSession::default();
    session.accept(response("initial",1,100,10000,"active"),anchor).unwrap();
    let first=session.deadline().unwrap();
    session.accept(response("fresh",1,100,10000,"not_modified"),anchor+Duration::from_millis(800)).unwrap();
    assert_eq!(session.deadline(),Some(first+Duration::from_millis(800)));
    assert!(session.usable(first+Duration::from_millis(799)));
    assert!(!session.usable(first+Duration::from_millis(800)));
    assert!(session.accept(response("fresh",1,100,10000,"not_modified"),anchor+Duration::from_millis(900)).is_err());
    assert_eq!(session.deadline(),Some(first+Duration::from_millis(800)));
    assert_eq!(session.trusted_time(anchor+Duration::from_secs(1)),Some(101));
}

#[test]
fn fresh_same_second_success_cannot_move_card_expiry_or_erase_fractional_time() {
    let anchor=Instant::now();let mut session=LiveSession::default();
    let key=SigningKey::from_bytes(&[42;32]).verifying_key();
    let mut value=json!({"request_id":"initial","authorization_id":"auth","authorization_revision":1,
        "config_version":"cfg","issued_at":10,"server_time":100,"expires_at":101,
        "cache_until":101,"next_verify_at":101,"grace_until":101,"decision":"active"});
    session.accept(verify_signed(&signed(value.clone()),"test",&key).unwrap(),anchor).unwrap();
    value["request_id"]="fresh".into();value["decision"]="not_modified".into();
    session.accept(verify_signed(&signed(value),"test",&key).unwrap(),anchor+Duration::from_millis(800)).unwrap();
    assert_eq!(session.deadline(),Some(anchor+Duration::from_secs(1)));
    assert!(session.usable(anchor+Duration::from_millis(999)));
    assert!(!session.usable(anchor+Duration::from_secs(1)));
    assert_eq!(session.trusted_time(anchor+Duration::from_secs(1)),Some(101));
}

#[test]
fn same_second_one_second_refresh_uses_each_fresh_request_anchor_and_failures_do_not_move_it() {
    let anchor=Instant::now();let mut session=LiveSession::default();
    let key=SigningKey::from_bytes(&[42;32]).verifying_key();
    let mut value=json!({"request_id":"initial","authorization_id":"auth","authorization_revision":1,
        "config_version":"cfg","issued_at":10,"server_time":100,"expires_at":10000,
        "cache_until":101,"next_verify_at":101,"grace_until":10000,"decision":"active"});
    session.accept(verify_signed(&signed(value.clone()),"test",&key).unwrap(),anchor).unwrap();
    for (id,millis) in [("fresh1",400),("fresh2",800)] {
        value["request_id"]=id.into();value["decision"]="not_modified".into();
        session.accept(verify_signed(&signed(value.clone()),"test",&key).unwrap(),anchor+Duration::from_millis(millis)).unwrap();
    }
    assert!(!session.due(anchor+Duration::from_millis(1299)));
    assert!(session.due(anchor+Duration::from_millis(1300)));
    let deadline=Some(anchor+Duration::from_millis(1800));
    assert_eq!(session.deadline(),deadline);
    session.retry_after(anchor+Duration::from_millis(1300),Duration::from_secs(120));
    assert_eq!(session.deadline(),deadline);
    assert!(session.usable(anchor+Duration::from_millis(1799)));
    assert!(!session.usable(anchor+Duration::from_millis(1800)));
    assert_eq!(session.trusted_time(anchor+Duration::from_millis(1800)),Some(101));
}

#[test]
fn precise_refresh_one_second_window_starts_before_exclusive_deadline() {
    let anchor=Instant::now();let mut session=LiveSession::default();
    let key=SigningKey::from_bytes(&[42;32]).verifying_key();
    let value=signed(json!({"request_id":"one-second","authorization_id":"auth","authorization_revision":1,
        "config_version":"cfg","issued_at":10,"server_time":100,"expires_at":10000,
        "cache_until":101,"next_verify_at":101,"grace_until":10000,"decision":"active"}));
    session.accept(verify_signed(&value,"test",&key).unwrap(),anchor).unwrap();
    let deadline=session.deadline();
    assert!(!session.due(anchor+Duration::from_millis(499)));
    assert!(session.due(anchor+Duration::from_millis(500)),"integer rounding must not discard the one-second window's refresh lead");
    assert_eq!(session.trusted_time(anchor+Duration::from_millis(500)),Some(100));
    session.retry_after(anchor+Duration::from_millis(500),Duration::from_secs(120));
    assert_eq!(session.deadline(),deadline);
    assert!(session.usable(anchor+Duration::from_millis(999)));
    assert!(!session.usable(anchor+Duration::from_secs(1)));
}

#[test]
fn precise_refresh_zero_second_window_is_rejected_instead_of_granted() {
    let mut session=LiveSession::default();let anchor=Instant::now();
    let value=signed(json!({"request_id":"zero-window","authorization_id":"auth","authorization_revision":1,
        "config_version":"cfg","issued_at":10,"server_time":100,"expires_at":10000,
        "cache_until":100,"next_verify_at":100,"grace_until":10000,"decision":"active"}));
    let key=SigningKey::from_bytes(&[42;32]).verifying_key();
    assert_eq!(session.accept(verify_signed(&value,"test",&key).unwrap(),anchor).unwrap_err(),"Empty online success window");
    assert!(!session.usable(anchor));assert!(session.deadline().is_none());
}

#[test]
fn current_schema_counts_unicode_characters_and_local_epochs_are_nonnegative() {
    use authorization_a_template::current_runtime::{AUTH_SCHEMA, LOCAL_SCHEMA};
    let mut value:Value=serde_json::from_str(include_str!("../../平台公开资料/fixtures/authorization_v1/active.json")).unwrap();
    value["support"]=json!({"purchase_url":null,"qq":null,"wechat":"中".repeat(64)});
    value["modules"]["contact"]=value["support"].clone();
    value["issued_at"]=(-1).into();
    let value=signed(value);
    let platform_schema:Value=serde_json::from_str(AUTH_SCHEMA).unwrap();
    let local_schema:Value=serde_json::from_str(LOCAL_SCHEMA).unwrap();
    let platform=jsonschema::validator_for(&platform_schema).unwrap();
    let local=jsonschema::validator_for(&local_schema).unwrap();
    assert!(platform.is_valid(&value));
    assert!(verify_signed(&value,"test",&SigningKey::from_bytes(&[42;32]).verifying_key()).is_ok());
    let mut too_long=value.clone();too_long["support"]["wechat"]="中".repeat(65).into();
    assert!(!platform.is_valid(&too_long));
    let mut envelope=value;
    envelope["schema_version"]="authorization-a-core.v1".into();
    envelope["contract_version"]="authorization-a-core.v1".into();
    envelope["local_contract_version"]="authorization-a-core.v1".into();
    envelope["integrity"]["origin"]="authorization-a".into();
    envelope["integrity"]["audience"]="authorization-a-core".into();
    assert!(!local.is_valid(&envelope));
    envelope["issued_at"]=0.into();assert!(local.is_valid(&envelope));
}
