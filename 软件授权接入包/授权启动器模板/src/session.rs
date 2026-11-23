//! Product-neutral authorization session.
//!
//! v1 injected `cache_until` into the core. That is void: a copy would close
//! itself when the verify interval elapsed. v2 keeps two clocks apart:
//! the launcher asks `verify` at `next_verify_at`; the core / title bar still
//! use the card `expires_at`. Hard errors stop the core. Transient failures
//! retry and leave it running.

use std::collections::BTreeMap;
use std::fmt;

use super::authorization::AuthorizationErrorCode;

pub const AUTHORIZATION_SESSION_VERSION: &str = "authorization-a-session.v2";
pub const SESSION_SIMULATION_VERSION: &str = "a-template-session-simulation.v2";

const DEFAULT_VERIFY_WINDOW_SECS: u64 = 60;
const DEFAULT_CARD_TTL_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformOperation {
    Activate,
    Verify,
}

impl PlatformOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Verify => "verify",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDenialClass {
    BindingLost,
    DeviceLimitReached,
    TransientNetwork,
    Expired,
    Revoked,
    Blocked,
    Invalid,
}

impl SessionDenialClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BindingLost => "binding_lost",
            Self::DeviceLimitReached => "device_limit_reached",
            Self::TransientNetwork => "transient_network",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Blocked => "blocked",
            Self::Invalid => "invalid",
        }
    }

    pub const fn is_offline_grace(self) -> bool {
        matches!(self, Self::TransientNetwork)
    }

    pub const fn must_stop_running_core(self) -> bool {
        !matches!(self, Self::TransientNetwork)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorePresence {
    Stopped,
    Running,
}

impl CorePresence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreLease {
    pub core_expires_at: u64,
    pub next_verify_at: u64,
    pub card_expires_at: u64,
    pub server_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedLicenseRecord {
    pub authorization_id: String,
    pub device_id: String,
    pub card_expires_at: Option<u64>,
    pub cache_until: Option<u64>,
    pub next_verify_at: Option<u64>,
    pub server_time: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformGrant {
    pub authorization_id: String,
    pub device_id: String,
    /// Platform `authorization_revision`. Renewal pushes expiry AND bumps
    /// this number; the launcher must accept a longer expiry while running.
    pub authorization_revision: u64,
    pub card_expires_at: u64,
    pub cache_until: u64,
    pub next_verify_at: u64,
    pub server_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformOutcome {
    Grant(PlatformGrant),
    /// Platform `not_modified`: nothing changed, keep running on the
    /// existing lease. Never an error, never a stop.
    NotModified,
    Denied {
        code: AuthorizationErrorCode,
    },
    Unavailable,
}

pub trait LicensePlatform {
    fn activate(&mut self, device_id: &str, now: u64) -> PlatformOutcome;
    fn verify(&mut self, device_id: &str, authorization_id: &str, now: u64) -> PlatformOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    pub core: CorePresence,
    pub lease: Option<CoreLease>,
    pub last_operation: Option<PlatformOperation>,
    pub denial: Option<SessionDenialClass>,
    pub verify_calls: u32,
    pub activate_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    InvalidGrant(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrant(message) => write!(f, "invalid authorization grant: {message}"),
        }
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug, Clone)]
pub struct AuthorizationSession {
    device_id: String,
    cache: Option<CachedLicenseRecord>,
    core: CorePresence,
    lease: Option<CoreLease>,
    denial: Option<SessionDenialClass>,
    verify_calls: u32,
    activate_calls: u32,
    last_operation: Option<PlatformOperation>,
}

impl AuthorizationSession {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            cache: None,
            core: CorePresence::Stopped,
            lease: None,
            denial: None,
            verify_calls: 0,
            activate_calls: 0,
            last_operation: None,
        }
    }

    pub fn with_cache(device_id: impl Into<String>, cache: CachedLicenseRecord) -> Self {
        let mut session = Self::new(device_id);
        session.cache = Some(cache);
        session
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn report(&self) -> SessionReport {
        SessionReport {
            core: self.core,
            lease: self.lease.clone(),
            last_operation: self.last_operation,
            denial: self.denial,
            verify_calls: self.verify_calls,
            activate_calls: self.activate_calls,
        }
    }

    pub fn recover<P: LicensePlatform>(&mut self, platform: &mut P, now: u64) -> SessionReport {
        let Some(cache) = self.cache.clone() else {
            self.core = CorePresence::Stopped;
            return self.report();
        };
        if cache.authorization_id.is_empty() {
            self.stop(SessionDenialClass::Invalid);
            return self.report();
        }
        self.verify_calls = self.verify_calls.saturating_add(1);
        self.last_operation = Some(PlatformOperation::Verify);
        let outcome = platform.verify(&self.device_id, &cache.authorization_id, now);
        self.apply_outcome(outcome, now);
        self.report()
    }

    pub fn activate<P: LicensePlatform>(&mut self, platform: &mut P, now: u64) -> SessionReport {
        self.activate_calls = self.activate_calls.saturating_add(1);
        self.last_operation = Some(PlatformOperation::Activate);
        let outcome = platform.activate(&self.device_id, now);
        self.apply_outcome(outcome, now);
        self.report()
    }

    pub fn tick<P: LicensePlatform>(&mut self, platform: &mut P, now: u64) -> SessionReport {
        if self.core != CorePresence::Running {
            return self.report();
        }
        if self
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.core_expires_at)
        {
            self.stop(SessionDenialClass::Expired);
            return self.report();
        }
        let due = self
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.next_verify_at);
        if !due {
            return self.report();
        }
        let Some(authorization_id) = self
            .cache
            .as_ref()
            .map(|cache| cache.authorization_id.clone())
            .filter(|authorization_id| !authorization_id.is_empty())
        else {
            self.stop(SessionDenialClass::Invalid);
            return self.report();
        };
        self.verify_calls = self.verify_calls.saturating_add(1);
        self.last_operation = Some(PlatformOperation::Verify);
        let outcome = platform.verify(&self.device_id, &authorization_id, now);
        self.apply_outcome(outcome, now);
        self.report()
    }

    fn apply_outcome(&mut self, outcome: PlatformOutcome, now: u64) {
        match outcome {
            PlatformOutcome::Grant(grant) => match core_lease_from_grant(&grant) {
                Ok(lease) => {
                    self.cache = Some(cache_from_grant(&grant));
                    self.core = CorePresence::Running;
                    self.lease = Some(lease);
                    self.denial = None;
                }
                Err(_) => self.stop(SessionDenialClass::Invalid),
            },
            PlatformOutcome::Denied { code } => {
                self.apply_denial(classify_session_denial(self.last_operation, code), now);
            }
            PlatformOutcome::NotModified => {
                // Nothing changed on the platform: keep running on the
                // existing lease when the core is already open. A stopped
                // core must NOT open from not_modified alone.
                if self.core == CorePresence::Running {
                    self.denial = None;
                }
            }
            PlatformOutcome::Unavailable => {
                self.apply_denial(SessionDenialClass::TransientNetwork, now);
            }
        }
    }

    fn apply_denial(&mut self, class: SessionDenialClass, now: u64) {
        if self.core == CorePresence::Running
            && !class.must_stop_running_core()
            && self
                .lease
                .as_ref()
                .is_some_and(|lease| now < lease.core_expires_at)
        {
            if let Some(lease) = self.lease.as_mut() {
                lease.next_verify_at = now.saturating_add(DEFAULT_VERIFY_WINDOW_SECS);
            }
            self.denial = Some(class);
            return;
        }
        self.stop(class);
    }

    fn stop(&mut self, denial: SessionDenialClass) {
        self.core = CorePresence::Stopped;
        self.denial = Some(denial);
        if matches!(
            denial,
            SessionDenialClass::BindingLost
                | SessionDenialClass::Revoked
                | SessionDenialClass::Blocked
                | SessionDenialClass::Expired
        ) {
            self.lease = None;
            self.cache = None;
        }
    }
}

pub fn classify_platform_code(code: AuthorizationErrorCode) -> SessionDenialClass {
    classify_platform_code_str(code.as_str())
}

pub fn classify_platform_code_str(code: &str) -> SessionDenialClass {
    match code {
        "DEVICE_NOT_BOUND" | "UNBOUND" => SessionDenialClass::BindingLost,
        "DEVICE_LIMIT_REACHED" => SessionDenialClass::DeviceLimitReached,
        "SERVICE_TEMPORARILY_UNAVAILABLE" | "RATE_LIMITED" => SessionDenialClass::TransientNetwork,
        "LICENSE_EXPIRED" => SessionDenialClass::Expired,
        "AUTHORIZATION_REVOKED" => SessionDenialClass::Revoked,
        "AUTHORIZATION_BLOCKED" => SessionDenialClass::Blocked,
        _ => SessionDenialClass::Invalid,
    }
}

pub fn classify_session_denial(
    operation: Option<PlatformOperation>,
    code: AuthorizationErrorCode,
) -> SessionDenialClass {
    if operation == Some(PlatformOperation::Verify)
        && matches!(
            code,
            AuthorizationErrorCode::DeviceNotBound | AuthorizationErrorCode::AuthInvalid
        )
    {
        return SessionDenialClass::BindingLost;
    }
    classify_platform_code(code)
}

/// The only expiry a copy may inject into the core or title bar.
pub fn core_handoff_until(grant: &PlatformGrant) -> Result<u64, SessionError> {
    Ok(core_lease_from_grant(grant)?.core_expires_at)
}

pub fn is_verify_interval_injected_as_core_expiry(injected: u64, grant: &PlatformGrant) -> bool {
    injected == grant.cache_until && grant.cache_until != grant.card_expires_at
}

pub fn core_lease_from_grant(grant: &PlatformGrant) -> Result<CoreLease, SessionError> {
    if grant.cache_until != grant.next_verify_at {
        return Err(SessionError::InvalidGrant(
            "cache_until and next_verify_at must be equal".to_string(),
        ));
    }
    if grant.cache_until > grant.card_expires_at {
        return Err(SessionError::InvalidGrant(
            "cache_until cannot exceed expires_at".to_string(),
        ));
    }
    if grant.server_time >= grant.card_expires_at {
        return Err(SessionError::InvalidGrant(
            "card expiry must be later than server_time".to_string(),
        ));
    }
    if grant.server_time >= grant.next_verify_at {
        return Err(SessionError::InvalidGrant(
            "next_verify_at must be later than server_time".to_string(),
        ));
    }
    Ok(CoreLease {
        core_expires_at: grant.card_expires_at,
        next_verify_at: grant.next_verify_at,
        card_expires_at: grant.card_expires_at,
        server_time: grant.server_time,
    })
}

fn cache_from_grant(grant: &PlatformGrant) -> CachedLicenseRecord {
    CachedLicenseRecord {
        authorization_id: grant.authorization_id.clone(),
        device_id: grant.device_id.clone(),
        card_expires_at: Some(grant.card_expires_at),
        cache_until: Some(grant.cache_until),
        next_verify_at: Some(grant.next_verify_at),
        server_time: Some(grant.server_time),
    }
}

#[derive(Debug, Clone)]
struct BoundDevice {
    authorization_id: String,
    active: bool,
}

/// Deterministic one-card cloud. The short verify window is only a schedule,
/// never the core countdown.
#[derive(Debug, Clone)]
pub struct SharedCardCloud {
    max_devices: u32,
    displace: bool,
    verify_window_secs: u64,
    card_ttl_secs: u64,
    authorization_id: String,
    authorization_revision: u64,
    card_expires_at: Option<u64>,
    bindings: BTreeMap<String, BoundDevice>,
    unavailable: bool,
    rate_limited: bool,
}

impl SharedCardCloud {
    pub fn new(max_devices: u32, displace: bool) -> Self {
        Self {
            max_devices,
            displace,
            verify_window_secs: DEFAULT_VERIFY_WINDOW_SECS,
            card_ttl_secs: DEFAULT_CARD_TTL_SECS,
            authorization_id: "auth-shared-card".to_string(),
            authorization_revision: 1,
            card_expires_at: None,
            bindings: BTreeMap::new(),
            unavailable: false,
            rate_limited: false,
        }
    }

    pub fn with_windows(mut self, verify_window_secs: u64, card_ttl_secs: u64) -> Self {
        self.verify_window_secs = verify_window_secs;
        self.card_ttl_secs = card_ttl_secs;
        self
    }

    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.unavailable = unavailable;
    }

    pub fn set_rate_limited(&mut self, rate_limited: bool) {
        self.rate_limited = rate_limited;
    }

    /// Platform renewal: push the card expiry and bump the revision.
    /// Mirrors the platform "extend authorization" behavior.
    pub fn renew_card(&mut self, extra_secs: u64) {
        if let Some(expiry) = self.card_expires_at.as_mut() {
            *expiry = expiry.saturating_add(extra_secs);
        }
        self.authorization_revision = self.authorization_revision.saturating_add(1);
    }

    fn grant_for(&mut self, device_id: &str, now: u64) -> PlatformGrant {
        let card_expires_at = *self
            .card_expires_at
            .get_or_insert_with(|| now.saturating_add(self.card_ttl_secs));
        PlatformGrant {
            authorization_id: self.authorization_id.clone(),
            device_id: device_id.to_string(),
            authorization_revision: self.authorization_revision,
            card_expires_at,
            cache_until: now.saturating_add(self.verify_window_secs),
            next_verify_at: now.saturating_add(self.verify_window_secs),
            server_time: now,
        }
    }

    fn active_count(&self) -> u32 {
        self.bindings
            .values()
            .filter(|binding| binding.active)
            .count() as u32
    }
}

impl LicensePlatform for SharedCardCloud {
    /// Judge first, limit second: hard failures (unbound / full / revoked
    /// class) are never covered by RATE_LIMITED, mirroring the platform.
    /// `unavailable` (no transport at all) still short-circuits first.
    fn activate(&mut self, device_id: &str, now: u64) -> PlatformOutcome {
        if self.unavailable {
            return PlatformOutcome::Unavailable;
        }
        if !self
            .bindings
            .get(device_id)
            .is_some_and(|binding| binding.active)
            && self.active_count() >= self.max_devices
            && !self.displace
        {
            return PlatformOutcome::Denied {
                code: AuthorizationErrorCode::DeviceLimitReached,
            };
        }
        if self.rate_limited {
            return PlatformOutcome::Denied {
                code: AuthorizationErrorCode::RateLimited,
            };
        }
        if self
            .bindings
            .get(device_id)
            .is_some_and(|binding| binding.active)
        {
            return PlatformOutcome::Grant(self.grant_for(device_id, now));
        }
        if self.active_count() >= self.max_devices {
            for binding in self.bindings.values_mut() {
                binding.active = false;
            }
        }
        self.bindings.insert(
            device_id.to_string(),
            BoundDevice {
                authorization_id: self.authorization_id.clone(),
                active: true,
            },
        );
        PlatformOutcome::Grant(self.grant_for(device_id, now))
    }

    fn verify(&mut self, device_id: &str, authorization_id: &str, now: u64) -> PlatformOutcome {
        if self.unavailable {
            return PlatformOutcome::Unavailable;
        }
        match self.bindings.get(device_id) {
            Some(binding) if binding.active && binding.authorization_id == authorization_id => {
                if self.rate_limited {
                    return PlatformOutcome::Denied {
                        code: AuthorizationErrorCode::RateLimited,
                    };
                }
                PlatformOutcome::Grant(self.grant_for(device_id, now))
            }
            _ => PlatformOutcome::Denied {
                code: AuthorizationErrorCode::DeviceNotBound,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoDeviceReport {
    pub displace: bool,
    pub old_core: CorePresence,
    pub old_denial: Option<SessionDenialClass>,
    pub old_verify_calls: u32,
    pub new_core: CorePresence,
    pub new_denial: Option<SessionDenialClass>,
}

pub fn run_two_device_same_card(displace: bool, now: u64) -> TwoDeviceReport {
    let mut cloud = SharedCardCloud::new(1, displace).with_windows(60, DEFAULT_CARD_TTL_SECS);
    let mut old_device = AuthorizationSession::new("device-old");
    let mut new_device = AuthorizationSession::new("device-new");
    old_device.activate(&mut cloud, now);
    new_device.activate(&mut cloud, now.saturating_add(5));
    old_device.tick(&mut cloud, now.saturating_add(60));
    TwoDeviceReport {
        displace,
        old_core: old_device.report().core,
        old_denial: old_device.report().denial,
        old_verify_calls: old_device.report().verify_calls,
        new_core: new_device.report().core,
        new_denial: new_device.report().denial,
    }
}

pub fn run_single_machine_stays_open(now: u64) -> SessionReport {
    let mut cloud = SharedCardCloud::new(1, false).with_windows(60, DEFAULT_CARD_TTL_SECS);
    let mut session = AuthorizationSession::new("device-only");
    session.activate(&mut cloud, now);
    session.tick(&mut cloud, now.saturating_add(60))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionScenario {
    SingleMachineStaysOpenAfterVerify,
    SingleMachineTransientVerifyKeepsCore,
    CoreHandoffIsCardExpiry,
    TwoDeviceDisplaceStopsOld,
    TwoDeviceNoDisplaceBlocksNew,
    StartupCacheRequiresVerify,
    DeviceNotBoundNotOfflineGrace,
    BindingLostThenOfflineDoesNotRevive,
}

impl SessionScenario {
    pub const ALL: &'static [Self] = &[
        Self::SingleMachineStaysOpenAfterVerify,
        Self::SingleMachineTransientVerifyKeepsCore,
        Self::CoreHandoffIsCardExpiry,
        Self::TwoDeviceDisplaceStopsOld,
        Self::TwoDeviceNoDisplaceBlocksNew,
        Self::StartupCacheRequiresVerify,
        Self::DeviceNotBoundNotOfflineGrace,
        Self::BindingLostThenOfflineDoesNotRevive,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleMachineStaysOpenAfterVerify => "single-machine-stays-open-after-verify",
            Self::SingleMachineTransientVerifyKeepsCore => {
                "single-machine-transient-verify-keeps-core"
            }
            Self::CoreHandoffIsCardExpiry => "core-handoff-is-card-expiry",
            Self::TwoDeviceDisplaceStopsOld => "two-device-displace-stops-old",
            Self::TwoDeviceNoDisplaceBlocksNew => "two-device-no-displace-blocks-new",
            Self::StartupCacheRequiresVerify => "startup-cache-requires-verify",
            Self::DeviceNotBoundNotOfflineGrace => "device-not-bound-not-offline-grace",
            Self::BindingLostThenOfflineDoesNotRevive => {
                "binding-lost-then-offline-does-not-revive"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionScenarioReport {
    pub scenario: SessionScenario,
    pub passed: bool,
    pub detail: String,
}

pub fn run_session_scenario(scenario: SessionScenario, now: u64) -> SessionScenarioReport {
    match scenario {
        SessionScenario::SingleMachineStaysOpenAfterVerify => {
            let report = run_single_machine_stays_open(now);
            let passed = report.core == CorePresence::Running
                && report.verify_calls >= 1
                && report.lease.as_ref().is_some_and(|lease| {
                    lease.core_expires_at == now.saturating_add(DEFAULT_CARD_TTL_SECS)
                        && lease.core_expires_at != lease.next_verify_at
                });
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "core={} verify={} core_expires={} next_verify={}",
                    report.core.as_str(),
                    report.verify_calls,
                    report
                        .lease
                        .as_ref()
                        .map(|lease| lease.core_expires_at.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    report
                        .lease
                        .as_ref()
                        .map(|lease| lease.next_verify_at.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                ),
            }
        }
        SessionScenario::SingleMachineTransientVerifyKeepsCore => {
            let mut cloud = SharedCardCloud::new(1, false).with_windows(60, DEFAULT_CARD_TTL_SECS);
            let mut session = AuthorizationSession::new("device-only");
            session.activate(&mut cloud, now);
            cloud.set_unavailable(true);
            let report = session.tick(&mut cloud, now.saturating_add(60));
            let passed = report.core == CorePresence::Running
                && report.lease.as_ref().is_some_and(|lease| {
                    lease.core_expires_at == now.saturating_add(DEFAULT_CARD_TTL_SECS)
                });
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "core={} denial={} core_expires={}",
                    report.core.as_str(),
                    report
                        .denial
                        .map(SessionDenialClass::as_str)
                        .unwrap_or("none"),
                    report
                        .lease
                        .as_ref()
                        .map(|lease| lease.core_expires_at.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                ),
            }
        }
        SessionScenario::CoreHandoffIsCardExpiry => {
            let grant = PlatformGrant {
                authorization_id: "auth-1".to_string(),
                device_id: "device-only".to_string(),
                authorization_revision: 1,
                card_expires_at: now.saturating_add(DEFAULT_CARD_TTL_SECS),
                cache_until: now.saturating_add(60),
                next_verify_at: now.saturating_add(60),
                server_time: now,
            };
            let injected = core_handoff_until(&grant).ok();
            let passed = injected == Some(grant.card_expires_at)
                && !is_verify_interval_injected_as_core_expiry(
                    injected.unwrap_or_default(),
                    &grant,
                );
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "injected={} card={} verify_at={}",
                    injected
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    grant.card_expires_at,
                    grant.next_verify_at
                ),
            }
        }
        SessionScenario::TwoDeviceDisplaceStopsOld => {
            let report = run_two_device_same_card(true, now);
            let passed = report.old_core == CorePresence::Stopped
                && report.old_denial == Some(SessionDenialClass::BindingLost)
                && report.old_verify_calls >= 1
                && report.new_core == CorePresence::Running;
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "old_core={} old_denial={} old_verify={} new_core={}",
                    report.old_core.as_str(),
                    report
                        .old_denial
                        .map(SessionDenialClass::as_str)
                        .unwrap_or("none"),
                    report.old_verify_calls,
                    report.new_core.as_str()
                ),
            }
        }
        SessionScenario::TwoDeviceNoDisplaceBlocksNew => {
            let report = run_two_device_same_card(false, now);
            let passed = report.old_core == CorePresence::Running
                && report.new_core == CorePresence::Stopped
                && report.new_denial == Some(SessionDenialClass::DeviceLimitReached);
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "old_core={} new_core={} new_denial={}",
                    report.old_core.as_str(),
                    report.new_core.as_str(),
                    report
                        .new_denial
                        .map(SessionDenialClass::as_str)
                        .unwrap_or("none")
                ),
            }
        }
        SessionScenario::StartupCacheRequiresVerify => {
            let mut cloud = SharedCardCloud::new(1, true);
            cloud.activate("device-old", now);
            cloud.activate("device-new", now);
            let mut session = AuthorizationSession::with_cache(
                "device-old",
                CachedLicenseRecord {
                    authorization_id: "auth-shared-card".to_string(),
                    device_id: "device-old".to_string(),
                    card_expires_at: Some(now.saturating_add(DEFAULT_CARD_TTL_SECS)),
                    cache_until: None,
                    next_verify_at: None,
                    server_time: Some(now),
                },
            );
            let report = session.recover(&mut cloud, now);
            let passed = report.core == CorePresence::Stopped
                && report.denial == Some(SessionDenialClass::BindingLost)
                && report.verify_calls >= 1;
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "core={} denial={} verify={}",
                    report.core.as_str(),
                    report
                        .denial
                        .map(SessionDenialClass::as_str)
                        .unwrap_or("none"),
                    report.verify_calls
                ),
            }
        }
        SessionScenario::DeviceNotBoundNotOfflineGrace => {
            let mut cloud = SharedCardCloud::new(1, true).with_windows(60, DEFAULT_CARD_TTL_SECS);
            let mut old_device = AuthorizationSession::new("device-old");
            let mut new_device = AuthorizationSession::new("device-new");
            old_device.activate(&mut cloud, now);
            new_device.activate(&mut cloud, now.saturating_add(5));
            let report = old_device.tick(&mut cloud, now.saturating_add(60));
            let passed = report.core == CorePresence::Stopped
                && report.denial == Some(SessionDenialClass::BindingLost)
                && report
                    .denial
                    .is_some_and(|denial| denial.must_stop_running_core())
                && report.verify_calls >= 1;
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "core={} denial={} verify={}",
                    report.core.as_str(),
                    report
                        .denial
                        .map(SessionDenialClass::as_str)
                        .unwrap_or("none"),
                    report.verify_calls
                ),
            }
        }
        SessionScenario::BindingLostThenOfflineDoesNotRevive => {
            let mut cloud = SharedCardCloud::new(1, true).with_windows(60, DEFAULT_CARD_TTL_SECS);
            let mut old_device = AuthorizationSession::new("device-old");
            let mut new_device = AuthorizationSession::new("device-new");
            old_device.activate(&mut cloud, now);
            new_device.activate(&mut cloud, now.saturating_add(5));
            old_device.tick(&mut cloud, now.saturating_add(60));
            cloud.set_unavailable(true);
            let report = old_device.recover(&mut cloud, now.saturating_add(61));
            let passed = report.core == CorePresence::Stopped
                && report.denial == Some(SessionDenialClass::BindingLost);
            SessionScenarioReport {
                scenario,
                passed,
                detail: format!(
                    "core={} denial={}",
                    report.core.as_str(),
                    report
                        .denial
                        .map(SessionDenialClass::as_str)
                        .unwrap_or("none")
                ),
            }
        }
    }
}

pub fn run_session_matrix(now: u64) -> Vec<SessionScenarioReport> {
    SessionScenario::ALL
        .iter()
        .copied()
        .map(|scenario| run_session_scenario(scenario, now))
        .collect()
}
