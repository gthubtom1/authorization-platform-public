use authorization_a_template::{
    classify_platform_code, classify_platform_code_str, classify_session_denial,
    core_handoff_until, core_lease_from_grant, is_verify_interval_injected_as_core_expiry,
    run_session_matrix, run_two_device_same_card, AuthorizationErrorCode, AuthorizationSession,
    CachedLicenseRecord, CorePresence, LicensePlatform, PlatformGrant, PlatformOperation,
    PlatformOutcome, SessionDenialClass, SessionScenario, SharedCardCloud,
    AUTHORIZATION_SESSION_VERSION,
};

const NOW: u64 = 1_800_000_000;
const CARD_TTL: u64 = 30 * 24 * 60 * 60;
const VERIFY_EVERY: u64 = 60;

#[test]
fn session_version_voids_window_handoff() {
    assert_eq!(AUTHORIZATION_SESSION_VERSION, "authorization-a-session.v2");
}

#[test]
fn device_not_bound_is_hard_stop_rate_limit_is_retry() {
    assert_eq!(
        classify_platform_code(AuthorizationErrorCode::DeviceNotBound),
        SessionDenialClass::BindingLost
    );
    assert_eq!(
        classify_platform_code_str("DEVICE_NOT_BOUND"),
        SessionDenialClass::BindingLost
    );
    assert!(SessionDenialClass::BindingLost.must_stop_running_core());
    assert!(!SessionDenialClass::TransientNetwork.must_stop_running_core());
    assert_eq!(
        classify_platform_code(AuthorizationErrorCode::RateLimited),
        SessionDenialClass::TransientNetwork
    );
    assert_eq!(
        classify_session_denial(
            Some(PlatformOperation::Verify),
            AuthorizationErrorCode::AuthInvalid
        ),
        SessionDenialClass::BindingLost
    );
    assert_eq!(
        classify_session_denial(
            Some(PlatformOperation::Activate),
            AuthorizationErrorCode::AuthInvalid
        ),
        SessionDenialClass::Invalid
    );
}

#[test]
fn core_handoff_is_card_expiry_not_verify_interval() {
    let grant = PlatformGrant {
        authorization_id: "auth-1".to_string(),
        device_id: "device-old".to_string(),
        authorization_revision: 1,
        card_expires_at: NOW + CARD_TTL,
        cache_until: NOW + VERIFY_EVERY,
        next_verify_at: NOW + VERIFY_EVERY,
        server_time: NOW,
    };
    let lease = core_lease_from_grant(&grant).unwrap();
    assert_eq!(lease.core_expires_at, NOW + CARD_TTL);
    assert_eq!(lease.card_expires_at, NOW + CARD_TTL);
    assert_eq!(lease.next_verify_at, NOW + VERIFY_EVERY);
    assert_ne!(lease.core_expires_at, lease.next_verify_at);
    assert_eq!(core_handoff_until(&grant).unwrap(), grant.card_expires_at);
    assert_ne!(core_handoff_until(&grant).unwrap(), grant.cache_until);
    assert!(!is_verify_interval_injected_as_core_expiry(
        core_handoff_until(&grant).unwrap(),
        &grant
    ));
    assert!(is_verify_interval_injected_as_core_expiry(
        grant.cache_until,
        &grant
    ));
}

#[test]
fn activate_injects_card_expiry_and_schedules_verify() {
    let mut cloud = SharedCardCloud::new(1, true).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    let report = session.activate(&mut cloud, NOW);
    assert_eq!(report.core, CorePresence::Running);
    let lease = report.lease.expect("activate must produce a core lease");
    assert_eq!(lease.core_expires_at, NOW + CARD_TTL);
    assert_eq!(lease.next_verify_at, NOW + VERIFY_EVERY);
    assert_ne!(lease.core_expires_at, lease.next_verify_at);
}

#[test]
fn single_machine_stays_open_after_verify_window() {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    let report = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(report.core, CorePresence::Running);
    assert!(report.verify_calls >= 1);
    let lease = report.lease.expect("verify must keep the card expiry");
    assert_eq!(lease.core_expires_at, NOW + CARD_TTL);
    assert_eq!(lease.next_verify_at, NOW + VERIFY_EVERY + VERIFY_EVERY);
    assert_ne!(lease.core_expires_at, lease.next_verify_at);
    assert!(report.denial.is_none());
}

#[test]
fn single_machine_transient_verify_failure_does_not_stop_core() {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    cloud.set_unavailable(true);
    let report = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(report.core, CorePresence::Running);
    let lease = report.lease.expect("transient failure must keep the card");
    assert_eq!(lease.core_expires_at, NOW + CARD_TTL);
    assert_ne!(report.denial, Some(SessionDenialClass::BindingLost));
}

#[test]
fn single_machine_rate_limit_retries_and_does_not_stop_core() {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    cloud.set_rate_limited(true);
    let report = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(report.core, CorePresence::Running);
    assert_eq!(lease_core_expiry(&report), NOW + CARD_TTL);
}

#[test]
fn startup_cache_must_verify_and_cannot_open_core_from_card_expiry_alone() {
    let mut cloud = SharedCardCloud::new(1, true);
    assert!(matches!(
        cloud.activate("device-old", NOW),
        PlatformOutcome::Grant(_)
    ));
    assert!(matches!(
        cloud.activate("device-new", NOW),
        PlatformOutcome::Grant(_)
    ));
    let mut session = AuthorizationSession::with_cache(
        "device-old",
        CachedLicenseRecord {
            authorization_id: "auth-shared-card".to_string(),
            device_id: "device-old".to_string(),
            card_expires_at: Some(NOW + CARD_TTL),
            cache_until: None,
            next_verify_at: None,
            server_time: Some(NOW),
        },
    );
    let report = session.recover(&mut cloud, NOW);
    assert_eq!(report.core, CorePresence::Stopped);
    assert_eq!(report.denial, Some(SessionDenialClass::BindingLost));
    assert!(report.verify_calls >= 1);
}

#[test]
fn startup_with_valid_binding_verifies_and_keeps_card_expiry() {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    assert!(matches!(
        cloud.activate("device-old", NOW),
        PlatformOutcome::Grant(_)
    ));
    let mut session = AuthorizationSession::with_cache(
        "device-old",
        CachedLicenseRecord {
            authorization_id: "auth-shared-card".to_string(),
            device_id: "device-old".to_string(),
            card_expires_at: Some(NOW + CARD_TTL),
            cache_until: None,
            next_verify_at: None,
            server_time: Some(NOW),
        },
    );
    let report = session.recover(&mut cloud, NOW);
    assert_eq!(report.core, CorePresence::Running);
    assert!(report.verify_calls >= 1);
    let lease = report.lease.expect("fresh verify must keep card expiry");
    assert_eq!(lease.core_expires_at, NOW + CARD_TTL);
    assert_ne!(lease.core_expires_at, lease.next_verify_at);
}

#[test]
fn two_devices_same_card_displace_stops_the_old_core() {
    let report = run_two_device_same_card(true, NOW);
    assert_eq!(report.new_core, CorePresence::Running);
    assert_eq!(report.old_core, CorePresence::Stopped);
    assert_eq!(report.old_denial, Some(SessionDenialClass::BindingLost));
    assert!(
        report.old_verify_calls >= 1,
        "old machine must verify after being displaced"
    );
}

#[test]
fn two_devices_same_card_without_displace_blocks_the_new_machine() {
    let report = run_two_device_same_card(false, NOW);
    assert_eq!(report.old_core, CorePresence::Running);
    assert_eq!(report.new_core, CorePresence::Stopped);
    assert_eq!(
        report.new_denial,
        Some(SessionDenialClass::DeviceLimitReached)
    );
}

#[test]
fn session_matrix_puts_single_machine_first() {
    assert_eq!(
        SessionScenario::ALL[0],
        SessionScenario::SingleMachineStaysOpenAfterVerify
    );
    let reports = run_session_matrix(NOW);
    for report in reports {
        assert!(
            report.passed,
            "{} failed: {}",
            report.scenario.as_str(),
            report.detail
        );
    }
}

fn lease_core_expiry(report: &authorization_a_template::SessionReport) -> u64 {
    report
        .lease
        .as_ref()
        .expect("running core must keep a card expiry")
        .core_expires_at
}

#[test]
fn hard_unbound_beats_rate_limit_on_verify() {
    // Platform rule: judge first, limit second. A displaced machine must
    // see DEVICE_NOT_BOUND even while the rate bucket is exhausted.
    let mut cloud = SharedCardCloud::new(1, true).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    let mut newer = AuthorizationSession::new("device-new");
    newer.activate(&mut cloud, NOW);
    cloud.set_rate_limited(true);
    let report = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(report.core, CorePresence::Stopped);
    assert_eq!(report.denial, Some(SessionDenialClass::BindingLost));
}

#[test]
fn device_limit_beats_rate_limit_on_activate() {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut first = AuthorizationSession::new("device-old");
    first.activate(&mut cloud, NOW);
    cloud.set_rate_limited(true);
    let mut second = AuthorizationSession::new("device-new");
    let report = second.activate(&mut cloud, NOW);
    assert_eq!(report.core, CorePresence::Stopped);
    assert_eq!(report.denial, Some(SessionDenialClass::DeviceLimitReached));
}

#[test]
fn bound_machine_rate_limit_still_retries_without_stopping() {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    cloud.set_rate_limited(true);
    let report = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(report.core, CorePresence::Running);
    assert_eq!(lease_core_expiry(&report), NOW + CARD_TTL);
}

struct NotModifiedAfterFirst {
    grant: PlatformGrant,
}

impl LicensePlatform for NotModifiedAfterFirst {
    fn activate(&mut self, _device_id: &str, _now: u64) -> PlatformOutcome {
        PlatformOutcome::Grant(self.grant.clone())
    }

    fn verify(&mut self, _device_id: &str, _authorization_id: &str, _now: u64) -> PlatformOutcome {
        PlatformOutcome::NotModified
    }
}

#[test]
fn not_modified_keeps_running_on_existing_lease() {
    let cloud_grant = PlatformGrant {
        authorization_id: "auth-1".to_string(),
        device_id: "device-old".to_string(),
        authorization_revision: 3,
        card_expires_at: NOW + CARD_TTL,
        cache_until: NOW + VERIFY_EVERY,
        next_verify_at: NOW + VERIFY_EVERY,
        server_time: NOW,
    };
    let mut cloud = NotModifiedAfterFirst { grant: cloud_grant };
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    let report = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(report.core, CorePresence::Running);
    assert_eq!(lease_core_expiry(&report), NOW + CARD_TTL);
    assert!(report.denial.is_none());
}

#[test]
fn renewal_pushes_expiry_while_running_without_restart() {
    // Platform renewal: admin extends an active authorization; the next
    // verify returns a longer expires_at plus a bumped revision, and the
    // running core must adopt it without restart or re-activation.
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    let first = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(first.core, CorePresence::Running);
    assert_eq!(lease_core_expiry(&first), NOW + CARD_TTL);
    cloud.renew_card(86_400);
    let second = session.tick(&mut cloud, NOW + VERIFY_EVERY + VERIFY_EVERY);
    assert_eq!(second.core, CorePresence::Running);
    assert_eq!(lease_core_expiry(&second), NOW + CARD_TTL + 86_400);
    assert!(second.denial.is_none());
}

#[test]
fn launch_sequence_verify_then_ticket_then_single_core_start() {
    use authorization_a_template::{PlatformTicket, TicketWallet};
    // Full launch order: verify active -> take ticket for this device ->
    // exactly one core start -> second start refused without a new ticket.
    let mut cloud = SharedCardCloud::new(1, false).with_windows(VERIFY_EVERY, CARD_TTL);
    let mut session = AuthorizationSession::new("device-old");
    session.activate(&mut cloud, NOW);
    let running = session.tick(&mut cloud, NOW + VERIFY_EVERY);
    assert_eq!(running.core, CorePresence::Running);
    let mut wallet = TicketWallet::default();
    wallet.store(
        PlatformTicket {
            ticket_id: "11111111-2222-3333-4444-555555555555".to_string(),
            software_id: "sample-product".to_string(),
            profile_id: "stable".to_string(),
            client_id: "sample-product-windows".to_string(),
            installation_id: "device-old".to_string(),
            issued_at: NOW,
            not_before: NOW,
            expires_at: NOW + 180,
            audience: "sample-product-core".to_string(),
        },
        NOW,
    );
    let taken = wallet
        .take_for_launch("sample-product", "device-old", NOW)
        .expect("bound device launches once");
    assert_eq!(taken.audience, "sample-product-core");
    assert!(session.report().core == CorePresence::Running);
    assert!(wallet
        .take_for_launch("sample-product", "device-old", NOW)
        .is_err());
}
