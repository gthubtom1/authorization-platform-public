//! Product-neutral local simulation of the launcher boundary.
//!
//! This module is deliberately not a real platform client or process
//! supervisor. It proves that a product profile can drive the existing
//! lifecycle, UI snapshot, adapter and launch-gate contracts before a real
//! platform or EXE is available.

use std::fmt;

use super::{
    AdapterRegistry, AuthorizationSnapshot, CompatibilityMode, LicenseState, LifecycleError,
    LifecycleStateMachine, MockCloudClient, ProductManifest, SimulatedLegacyAuthAdapter,
    ThemeTokens, UiError, UiProfile, UiRenderSnapshot, UiShellModel, UiViewState,
};

pub const TEMPLATE_SIMULATION_VERSION: &str = "a-template-simulation.v2";
const SIMULATION_SUBJECT_ID: &str = "simulation-subject";
const SIMULATION_DEVICE_ID: &str = "simulation-device";
const SIMULATION_ISSUED_AT: u64 = 1_800_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationScenario {
    Active,
    Grace,
    Expired,
    Revoked,
    Unavailable,
    DeviceMismatch,
    CoreMissing,
    CoreStartFailed,
}

impl SimulationScenario {
    pub const ALL: &'static [Self] = &[
        Self::Active,
        Self::Grace,
        Self::Expired,
        Self::Revoked,
        Self::Unavailable,
        Self::DeviceMismatch,
        Self::CoreMissing,
        Self::CoreStartFailed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Unavailable => "unavailable",
            Self::DeviceMismatch => "device-mismatch",
            Self::CoreMissing => "core-missing",
            Self::CoreStartFailed => "core-start-failed",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "active" => Self::Active,
            "grace" => Self::Grace,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            "unavailable" => Self::Unavailable,
            "device-mismatch" => Self::DeviceMismatch,
            "core-missing" => Self::CoreMissing,
            "core-start-failed" => Self::CoreStartFailed,
            _ => return None,
        })
    }

    const fn expected_cloud_snapshot(self) -> bool {
        !matches!(self, Self::Unavailable | Self::DeviceMismatch)
    }

    const fn snapshot_state(self) -> LicenseState {
        match self {
            Self::Active | Self::CoreMissing | Self::CoreStartFailed => LicenseState::Active,
            Self::Grace => LicenseState::Grace,
            Self::Expired => LicenseState::Active,
            Self::Revoked => LicenseState::Revoked,
            Self::Unavailable | Self::DeviceMismatch => LicenseState::Active,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationCoreOutcome {
    NotAttempted,
    Started,
    BlockedByAuthorization,
    Missing,
    StartFailed,
}

impl SimulationCoreOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Started => "started",
            Self::BlockedByAuthorization => "blocked_by_authorization",
            Self::Missing => "missing",
            Self::StartFailed => "start_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationReport {
    pub scenario: SimulationScenario,
    pub lifecycle_state: LicenseState,
    pub ui_state: UiViewState,
    pub launch_requested: bool,
    pub adapter_granted: bool,
    pub core_outcome: SimulationCoreOutcome,
    pub idempotent_replay: bool,
    pub raw_credential_exposed: bool,
    pub boundary_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationError {
    InvalidSetup(String),
}

impl fmt::Display for SimulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSetup(message) => write!(f, "invalid simulation setup: {message}"),
        }
    }
}

impl std::error::Error for SimulationError {}

/// Run one deterministic scenario through cloud, lifecycle, UI and adapter
/// boundaries. Expected failure paths are returned as a report so the CLI can
/// show the complete result matrix instead of treating them as test crashes.
pub fn run_simulation(
    manifest: ProductManifest,
    profile: UiProfile,
    scenario: SimulationScenario,
    now: u64,
) -> Result<SimulationReport, SimulationError> {
    manifest
        .validate()
        .map_err(|error| SimulationError::InvalidSetup(error.to_string()))?;
    profile
        .validate_for_manifest(&manifest)
        .map_err(ui_setup_error)?;

    let mut lifecycle = LifecycleStateMachine::new(manifest.clone(), SIMULATION_DEVICE_ID)
        .map_err(lifecycle_setup_error)?;
    let mut cloud = MockCloudClient::new();
    let mut boundary_error = None;
    let mut idempotent_replay = false;

    let mut snapshot = AuthorizationSnapshot::new(
        &manifest.product_id,
        format!("simulation-{}", scenario.as_str()),
        SIMULATION_SUBJECT_ID,
        SIMULATION_DEVICE_ID,
        scenario.snapshot_state(),
        SIMULATION_ISSUED_AT,
        None,
        manifest
            .capabilities
            .iter()
            .map(|capability| capability.id.clone())
            .collect(),
        Vec::new(),
    );
    if scenario == SimulationScenario::Expired {
        snapshot.expires_at = Some(now);
    }
    if scenario == SimulationScenario::DeviceMismatch {
        snapshot.device_id = "different-device".to_string();
    }

    if scenario == SimulationScenario::Unavailable {
        cloud
            .set_unavailable(
                &manifest.product_id,
                SIMULATION_SUBJECT_ID,
                SIMULATION_DEVICE_ID,
            )
            .map_err(|error| SimulationError::InvalidSetup(error.to_string()))?;
        let result = lifecycle.synchronize(&mut cloud, SIMULATION_SUBJECT_ID);
        record_expected_sync_failure(result, &mut boundary_error)?;
    } else if scenario == SimulationScenario::DeviceMismatch {
        let result = lifecycle.apply_snapshot(snapshot);
        record_expected_sync_failure(result, &mut boundary_error)?;
    } else {
        cloud
            .set_snapshot(snapshot)
            .map_err(|error| SimulationError::InvalidSetup(error.to_string()))?;
        lifecycle
            .synchronize(&mut cloud, SIMULATION_SUBJECT_ID)
            .map_err(lifecycle_setup_error)?;

        if scenario.expected_cloud_snapshot() {
            idempotent_replay = matches!(
                lifecycle
                    .synchronize(&mut cloud, SIMULATION_SUBJECT_ID)
                    .map_err(lifecycle_setup_error)?,
                super::SnapshotApplyOutcome::Idempotent
            );
        }
    }

    let lifecycle_state = lifecycle.state_at(now);
    let online = !matches!(
        scenario,
        SimulationScenario::Unavailable | SimulationScenario::DeviceMismatch
    );
    let ui_state =
        UiViewState::from_license_state(lifecycle_state, online).map_err(ui_setup_error)?;
    let model = UiShellModel::new(&manifest, &profile, ui_state.clone()).map_err(ui_setup_error)?;
    let _render_snapshot = UiRenderSnapshot::new(model, &profile).map_err(ui_setup_error)?;

    let launch_requested = ui_state.can_request_launch();
    let mut adapter_granted = false;
    let mut raw_credential_exposed = false;
    let mut core_outcome = SimulationCoreOutcome::NotAttempted;

    if !launch_requested && boundary_error.is_none() {
        set_boundary_error(
            &mut boundary_error,
            format!(
                "launch denied by lifecycle state: {}",
                lifecycle_state.as_str()
            ),
        );
    }

    if launch_requested {
        let mut adapters = AdapterRegistry::new();
        adapters
            .register(SimulatedLegacyAuthAdapter::new(
                &manifest.adapter_id,
                &manifest.adapter_version,
                "simulated.core.authorization.v1",
            ))
            .map_err(|error| SimulationError::InvalidSetup(error.to_string()))?;

        match lifecycle.adapt_with_registry(&adapters, now) {
            Ok(handoff) => {
                adapter_granted = handoff.granted;
                raw_credential_exposed = handoff.exposes_raw_credential();
                core_outcome = match scenario {
                    SimulationScenario::CoreMissing => SimulationCoreOutcome::Missing,
                    SimulationScenario::CoreStartFailed => SimulationCoreOutcome::StartFailed,
                    _ => SimulationCoreOutcome::Started,
                };
            }
            Err(error) => {
                set_boundary_error(&mut boundary_error, error.to_string());
                core_outcome = SimulationCoreOutcome::BlockedByAuthorization;
            }
        }
    }

    Ok(SimulationReport {
        scenario,
        lifecycle_state,
        ui_state,
        launch_requested,
        adapter_granted,
        core_outcome,
        idempotent_replay,
        raw_credential_exposed,
        boundary_error,
    })
}

/// The default manifest used by the CLI is intentionally a sample input. Real
/// products supply their own manifest through the product initialization flow.
pub fn sample_manifest() -> ProductManifest {
    ProductManifest::new(
        "simulation-product",
        "Authorization A simulation",
        "simulation-adapter",
        "0.1.0",
        "zh-CN",
        ThemeTokens::neutral(),
        "core/simulation.exe",
        "product-state/runtime",
        "a-auth-simulation-product",
        CompatibilityMode::NativeCore,
        vec![
            super::Capability::required("launch", "1"),
            super::Capability::optional("contact", "1"),
            super::Capability::optional("purchase", "1"),
        ],
    )
    .with_category("template")
}

pub fn sample_profile(manifest: &ProductManifest) -> UiProfile {
    UiProfile::for_manifest(manifest, "profile-default")
        .with_enabled_modules(["contact", "purchase"])
}

fn record_expected_sync_failure(
    result: Result<super::SnapshotApplyOutcome, LifecycleError>,
    boundary_error: &mut Option<String>,
) -> Result<(), SimulationError> {
    match result {
        Ok(_) => Err(SimulationError::InvalidSetup(
            "failure scenario unexpectedly synchronized".to_string(),
        )),
        Err(error) => {
            set_boundary_error(boundary_error, error.to_string());
            Ok(())
        }
    }
}

fn set_boundary_error(boundary_error: &mut Option<String>, message: String) {
    if boundary_error.is_none() {
        *boundary_error = Some(message);
    }
}

fn lifecycle_setup_error(error: LifecycleError) -> SimulationError {
    SimulationError::InvalidSetup(error.to_string())
}

fn ui_setup_error(error: UiError) -> SimulationError {
    SimulationError::InvalidSetup(error.to_string())
}
