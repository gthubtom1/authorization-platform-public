//! Product-neutral authorization lifecycle and mock cloud boundary.
//!
//! This module deliberately keeps the cloud seam synchronous and in-memory. It
//! validates the same product snapshot contract used by the local transport,
//! binds a session to one product and one explicit device identity, and applies
//! snapshots monotonically. It does not discover hardware, persist a cache,
//! open IPC, or connect to a real authorization platform.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

use super::{
    validate_identifier, validate_opaque_identifier, AdapterRegistry, AuthorizationBinding,
    AuthorizationError, AuthorizationResponseV1, AuthorizationSnapshot, ContractError,
    IntegrityVerifier, LegacyAuthResult, LicenseState, ProductManifest, RuntimeError,
    AUTHORIZATION_CLOUD_PROTOCOL_VERSION, MAX_REQUEST_IDEMPOTENCY_RECORDS,
};

pub const A_LIFECYCLE_VERSION: &str = "a-lifecycle.v1";

/// The lifecycle uses the contract's state vocabulary so adapters cannot
/// accidentally invent a second license authority.
pub type LifecycleState = LicenseState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudError {
    InvalidRequest(String),
    Unavailable,
    ProtocolMismatch { expected: String, actual: String },
    Contract(ContractError),
}

impl fmt::Display for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(f, "invalid authorization request: {message}"),
            Self::Unavailable => write!(f, "authorization cloud is unavailable"),
            Self::ProtocolMismatch { expected, actual } => write!(
                f,
                "authorization cloud protocol mismatch: expected {expected}, received {actual}"
            ),
            Self::Contract(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CloudError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::InvalidRequest(_) | Self::Unavailable | Self::ProtocolMismatch { .. } => None,
        }
    }
}

impl From<ContractError> for CloudError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub protocol: String,
    pub product_id: String,
    pub subject_id: String,
    pub device_id: String,
}

impl AuthorizationRequest {
    pub fn new(
        product_id: impl Into<String>,
        subject_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Self {
        Self {
            protocol: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
            product_id: product_id.into(),
            subject_id: subject_id.into(),
            device_id: device_id.into(),
        }
    }

    pub fn validate(&self) -> Result<(), CloudError> {
        if self.protocol != AUTHORIZATION_CLOUD_PROTOCOL_VERSION {
            return Err(CloudError::ProtocolMismatch {
                expected: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
                actual: self.protocol.clone(),
            });
        }
        validate_identifier(&self.product_id, "request.product_id", false)
            .map_err(CloudError::InvalidRequest)?;
        validate_opaque_identifier(&self.subject_id, "request.subject_id")
            .map_err(CloudError::InvalidRequest)?;
        validate_opaque_identifier(&self.device_id, "request.device_id")
            .map_err(CloudError::InvalidRequest)?;
        Ok(())
    }
}

/// A caller-supplied, product-scoped device identity.
///
/// This type intentionally does not claim hardware attestation. The identity is
/// validated and compared consistently; cryptographic device proofs are now a
/// required branch (see request validation with proof required), not a later
/// slice. OS discovery remains outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBinding {
    product_id: String,
    device_id: String,
}

impl DeviceBinding {
    pub fn new(
        product_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        let product_id = product_id.into();
        let device_id = device_id.into();
        validate_identifier(&product_id, "binding.product_id", false)
            .map_err(LifecycleError::InvalidIdentity)?;
        validate_opaque_identifier(&device_id, "binding.device_id")
            .map_err(LifecycleError::InvalidIdentity)?;
        Ok(Self {
            product_id,
            device_id,
        })
    }

    pub fn product_id(&self) -> &str {
        &self.product_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn validate_product(&self, product_id: &str) -> Result<(), LifecycleError> {
        if self.product_id != product_id {
            return Err(LifecycleError::ProductMismatch {
                expected: self.product_id.clone(),
                actual: product_id.to_string(),
            });
        }
        Ok(())
    }

    pub fn validate_device(&self, device_id: &str) -> Result<(), LifecycleError> {
        if self.device_id != device_id {
            return Err(LifecycleError::DeviceMismatch {
                expected: self.device_id.clone(),
                actual: device_id.to_string(),
            });
        }
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: &AuthorizationSnapshot) -> Result<(), LifecycleError> {
        self.validate_product(&snapshot.product_id)?;
        self.validate_device(&snapshot.device_id)
    }
}

pub trait CloudClient {
    fn fetch_snapshot(
        &mut self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationSnapshot, CloudError>;
}

pub use CloudClient as AuthorizationCloudClient;

#[derive(Debug, Clone, PartialEq, Eq)]
enum MockCloudResponse {
    Snapshot(AuthorizationSnapshot),
    Unavailable,
}

type MockCloudKey = (String, String, String);

/// Deterministic in-memory cloud seam for two-profile and lifecycle tests.
#[derive(Debug, Clone, Default)]
pub struct MockCloudClient {
    responses: BTreeMap<MockCloudKey, MockCloudResponse>,
}

impl MockCloudClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_snapshot(&mut self, snapshot: AuthorizationSnapshot) -> Result<(), CloudError> {
        validate_cloud_snapshot_identity(&snapshot)?;
        let key = cloud_key(
            &snapshot.product_id,
            &snapshot.subject_id,
            &snapshot.device_id,
        );
        self.responses
            .insert(key, MockCloudResponse::Snapshot(snapshot));
        Ok(())
    }

    pub fn set_unavailable(
        &mut self,
        product_id: impl Into<String>,
        subject_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<(), CloudError> {
        let request = AuthorizationRequest::new(product_id, subject_id, device_id);
        request.validate()?;
        let key = cloud_key(&request.product_id, &request.subject_id, &request.device_id);
        self.responses.insert(key, MockCloudResponse::Unavailable);
        Ok(())
    }

    pub fn clear(
        &mut self,
        product_id: impl Into<String>,
        subject_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<(), CloudError> {
        let request = AuthorizationRequest::new(product_id, subject_id, device_id);
        request.validate()?;
        self.responses.remove(&cloud_key(
            &request.product_id,
            &request.subject_id,
            &request.device_id,
        ));
        Ok(())
    }
}

impl CloudClient for MockCloudClient {
    fn fetch_snapshot(
        &mut self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationSnapshot, CloudError> {
        request.validate()?;
        match self.responses.get(&cloud_key(
            &request.product_id,
            &request.subject_id,
            &request.device_id,
        )) {
            Some(MockCloudResponse::Snapshot(snapshot)) => Ok(snapshot.clone()),
            Some(MockCloudResponse::Unavailable) | None => Err(CloudError::Unavailable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotApplyOutcome {
    Applied,
    Idempotent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    InvalidIdentity(String),
    ProductMismatch {
        expected: String,
        actual: String,
    },
    SubjectMismatch {
        expected: String,
        actual: String,
    },
    DeviceMismatch {
        expected: String,
        actual: String,
    },
    StaleSnapshot {
        current_snapshot_id: String,
        current_issued_at: u64,
        received_snapshot_id: String,
        received_issued_at: u64,
    },
    SnapshotConflict {
        snapshot_id: String,
    },
    InvalidTransition {
        from: LicenseState,
        to: LicenseState,
    },
    Contract(ContractError),
    Cloud(CloudError),
    Runtime(RuntimeError),
    Authorization(AuthorizationError),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(message) => write!(f, "invalid lifecycle identity: {message}"),
            Self::ProductMismatch { expected, actual } => {
                write!(f, "lifecycle product mismatch: expected {expected}, received {actual}")
            }
            Self::SubjectMismatch { expected, actual } => {
                write!(f, "lifecycle subject mismatch: expected {expected}, received {actual}")
            }
            Self::DeviceMismatch { expected, actual } => {
                write!(f, "lifecycle device mismatch: expected {expected}, received {actual}")
            }
            Self::StaleSnapshot {
                current_snapshot_id,
                current_issued_at,
                received_snapshot_id,
                received_issued_at,
            } => write!(
                f,
                "stale authorization snapshot: current {current_snapshot_id}@{current_issued_at}, received {received_snapshot_id}@{received_issued_at}"
            ),
            Self::SnapshotConflict { snapshot_id } => {
                write!(f, "authorization snapshot is not idempotent: {snapshot_id}")
            }
            Self::InvalidTransition { from, to } => write!(
                f,
                "authorization lifecycle transition is not allowed: {} -> {}",
                from.as_str(),
                to.as_str()
            ),
            Self::Contract(error) => error.fmt(f),
            Self::Cloud(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::Authorization(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for LifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Cloud(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Authorization(error) => Some(error),
            Self::InvalidIdentity(_)
            | Self::ProductMismatch { .. }
            | Self::SubjectMismatch { .. }
            | Self::DeviceMismatch { .. }
            | Self::StaleSnapshot { .. }
            | Self::SnapshotConflict { .. }
            | Self::InvalidTransition { .. } => None,
        }
    }
}

impl From<ContractError> for LifecycleError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<CloudError> for LifecycleError {
    fn from(error: CloudError) -> Self {
        Self::Cloud(error)
    }
}

impl From<RuntimeError> for LifecycleError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<AuthorizationError> for LifecycleError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleStateMachine {
    manifest: ProductManifest,
    device_binding: DeviceBinding,
    subject_id: Option<String>,
    snapshot: Option<AuthorizationSnapshot>,
    state: LifecycleState,
    reauthorization_armed: bool,
    server_time_highwater: Cell<Option<u64>>,
    evaluation_time_highwater: Cell<Option<u64>>,
    formal_requests: BTreeMap<String, String>,
    formal_revision: Option<u64>,
    formal_authority_payload: Option<String>,
}

impl LifecycleStateMachine {
    pub fn new(
        manifest: ProductManifest,
        device_id: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        manifest.validate().map_err(LifecycleError::Contract)?;
        let device_binding = DeviceBinding::new(&manifest.product_id, device_id)?;
        Ok(Self {
            manifest,
            device_binding,
            subject_id: None,
            snapshot: None,
            state: LicenseState::Unavailable,
            reauthorization_armed: false,
            server_time_highwater: Cell::new(None),
            evaluation_time_highwater: Cell::new(None),
            formal_requests: BTreeMap::new(),
            formal_revision: None,
            formal_authority_payload: None,
        })
    }

    pub fn manifest(&self) -> &ProductManifest {
        &self.manifest
    }

    pub fn device_binding(&self) -> &DeviceBinding {
        &self.device_binding
    }

    pub fn subject_id(&self) -> Option<&str> {
        self.subject_id.as_deref()
    }

    pub fn snapshot(&self) -> Option<&AuthorizationSnapshot> {
        self.snapshot.as_ref()
    }

    pub fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn server_time_highwater(&self) -> Option<u64> {
        self.server_time_highwater.get()
    }

    pub fn state_at(&self, now: u64) -> LifecycleState {
        let effective_now = self.monotonic_time_for_evaluation(now);
        if matches!(self.state, LicenseState::Active | LicenseState::Grace)
            && self
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.expires_at)
                .is_some_and(|expires_at| effective_now >= expires_at)
        {
            LicenseState::Expired
        } else {
            self.state
        }
    }

    pub fn can_launch_at(&self, now: u64) -> bool {
        self.state_at(now).allows_launch()
    }

    pub fn adapt_with_registry(
        &self,
        registry: &AdapterRegistry,
        now: u64,
    ) -> Result<LegacyAuthResult, LifecycleError> {
        let snapshot = self.snapshot.as_ref().ok_or_else(|| {
            LifecycleError::Contract(ContractError::AuthorizationRejected {
                product_id: self.manifest.product_id.clone(),
                state: self.state,
            })
        })?;
        let state = self.state_at(now);
        if !state.allows_launch() {
            return Err(LifecycleError::Contract(
                ContractError::AuthorizationRejected {
                    product_id: self.manifest.product_id.clone(),
                    state,
                },
            ));
        }
        registry
            .adapt(&self.manifest, snapshot)
            .map_err(LifecycleError::Runtime)
    }

    /// Applies a response that has crossed the formal A -> core contract.
    /// The response must already carry all product/profile/client/device
    /// bindings. A verifies the proof and records the server-time high-water
    /// mark before the legacy-compatible snapshot handoff is attempted.
    pub fn apply_authorization_response<V: IntegrityVerifier>(
        &mut self,
        response: AuthorizationResponseV1,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<SnapshotApplyOutcome, LifecycleError> {
        response.validate_for_binding(&self.manifest, binding)?;
        response.validate_for_manifest(&self.manifest)?;
        response.verify(verifier)?;
        self.observe_server_time(response.server_time)?;
        let request_fingerprint = response.canonical_payload();
        if let Some(previous) = self.formal_requests.get(&response.request_id) {
            if previous != &request_fingerprint {
                return Err(AuthorizationError::RequestConflict {
                    request_id: response.request_id,
                }
                .into());
            }
        }
        let authority_payload = response.authority_payload();
        if let Some(current_revision) = self.formal_revision {
            if response.authorization_revision < current_revision {
                return Err(AuthorizationError::StaleRevision {
                    current: current_revision,
                    received: response.authorization_revision,
                }
                .into());
            }
            if response.authorization_revision == current_revision
                && self.formal_authority_payload.as_deref() != Some(authority_payload.as_str())
            {
                return Err(AuthorizationError::RequestConflict {
                    request_id: response.request_id,
                }
                .into());
            }
        }
        if !self.formal_requests.contains_key(&response.request_id)
            && self.formal_requests.len() >= MAX_REQUEST_IDEMPOTENCY_RECORDS
        {
            return Err(AuthorizationError::InvalidRequest(
                "formal request idempotency journal reached its bound".to_string(),
            )
            .into());
        }
        let snapshot = response.to_snapshot(&self.manifest)?;
        let outcome = self.apply_snapshot(snapshot)?;
        self.formal_requests
            .insert(response.request_id, request_fingerprint);
        self.formal_revision = Some(
            self.formal_revision
                .unwrap_or_default()
                .max(response.authorization_revision),
        );
        self.formal_authority_payload = Some(authority_payload);
        Ok(outcome)
    }

    pub fn mark_unavailable(&mut self) {
        self.state = LicenseState::Unavailable;
    }

    /// A revoked grant cannot silently become active. The caller must make an
    /// explicit reauthorization decision before accepting a newer grant.
    pub fn begin_reauthorization(&mut self) -> Result<(), LifecycleError> {
        if self.state != LicenseState::Revoked
            || self
                .snapshot
                .as_ref()
                .is_none_or(|snapshot| snapshot.license_state != LicenseState::Revoked)
        {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: LicenseState::Unavailable,
            });
        }
        self.reauthorization_armed = true;
        self.state = LicenseState::Unavailable;
        Ok(())
    }

    pub fn apply_snapshot(
        &mut self,
        snapshot: AuthorizationSnapshot,
    ) -> Result<SnapshotApplyOutcome, LifecycleError> {
        self.device_binding.validate_product(&snapshot.product_id)?;
        snapshot.validate_for(&self.manifest)?;
        self.device_binding.validate_snapshot(&snapshot)?;

        if let Some(expected_subject_id) = self.subject_id.as_deref() {
            if expected_subject_id != snapshot.subject_id {
                return Err(LifecycleError::SubjectMismatch {
                    expected: expected_subject_id.to_string(),
                    actual: snapshot.subject_id,
                });
            }
        }

        if let Some(current) = self.snapshot.as_ref() {
            if current.snapshot_id == snapshot.snapshot_id {
                if current == &snapshot {
                    self.state = snapshot.license_state;
                    self.reauthorization_armed = false;
                    self.observe_issued_at(snapshot.issued_at);
                    return Ok(SnapshotApplyOutcome::Idempotent);
                }
                return Err(LifecycleError::SnapshotConflict {
                    snapshot_id: snapshot.snapshot_id,
                });
            }

            if snapshot.issued_at <= current.issued_at {
                return Err(LifecycleError::StaleSnapshot {
                    current_snapshot_id: current.snapshot_id.clone(),
                    current_issued_at: current.issued_at,
                    received_snapshot_id: snapshot.snapshot_id,
                    received_issued_at: snapshot.issued_at,
                });
            }

            if !transition_allowed(
                current.license_state,
                snapshot.license_state,
                self.reauthorization_armed,
            ) {
                return Err(LifecycleError::InvalidTransition {
                    from: current.license_state,
                    to: snapshot.license_state,
                });
            }
        }

        self.subject_id = Some(snapshot.subject_id.clone());
        self.state = snapshot.license_state;
        self.snapshot = Some(snapshot);
        self.reauthorization_armed = false;
        self.observe_issued_at(
            self.snapshot
                .as_ref()
                .expect("snapshot was just stored")
                .issued_at,
        );
        Ok(SnapshotApplyOutcome::Applied)
    }

    pub fn synchronize<C: AuthorizationCloudClient>(
        &mut self,
        cloud: &mut C,
        subject_id: impl Into<String>,
    ) -> Result<SnapshotApplyOutcome, LifecycleError> {
        let subject_id = subject_id.into();
        if let Some(expected_subject_id) = self.subject_id.as_deref() {
            if expected_subject_id != subject_id {
                return Err(LifecycleError::SubjectMismatch {
                    expected: expected_subject_id.to_string(),
                    actual: subject_id,
                });
            }
        }

        let request = AuthorizationRequest::new(
            &self.manifest.product_id,
            subject_id,
            self.device_binding.device_id(),
        );
        match cloud.fetch_snapshot(&request) {
            Ok(snapshot) => self.apply_snapshot(snapshot),
            Err(CloudError::Unavailable) => {
                self.mark_unavailable();
                Err(LifecycleError::Cloud(CloudError::Unavailable))
            }
            Err(error) => Err(LifecycleError::Cloud(error)),
        }
    }

    fn observe_issued_at(&self, issued_at: u64) {
        let current = self.evaluation_time_highwater.get().unwrap_or_default();
        self.evaluation_time_highwater
            .set(Some(current.max(issued_at)));
    }

    fn observe_server_time(&self, server_time: u64) -> Result<(), LifecycleError> {
        if let Some(last_seen) = self.server_time_highwater.get() {
            if server_time < last_seen {
                return Err(LifecycleError::Authorization(
                    AuthorizationError::ServerTimeRollback {
                        last_seen,
                        received: server_time,
                    },
                ));
            }
        }
        self.server_time_highwater.set(Some(
            self.server_time_highwater
                .get()
                .unwrap_or_default()
                .max(server_time),
        ));
        Ok(())
    }

    fn monotonic_time_for_evaluation(&self, now: u64) -> u64 {
        let effective = self
            .server_time_highwater
            .get()
            .unwrap_or_default()
            .max(self.evaluation_time_highwater.get().unwrap_or_default())
            .max(now);
        self.evaluation_time_highwater.set(Some(
            self.evaluation_time_highwater
                .get()
                .unwrap_or_default()
                .max(effective),
        ));
        effective
    }
}

fn cloud_key(product_id: &str, subject_id: &str, device_id: &str) -> MockCloudKey {
    (
        product_id.to_string(),
        subject_id.to_string(),
        device_id.to_string(),
    )
}

fn transition_allowed(from: LicenseState, to: LicenseState, reauthorization_armed: bool) -> bool {
    if from != LicenseState::Revoked {
        return true;
    }
    reauthorization_armed || matches!(to, LicenseState::Revoked | LicenseState::Unavailable)
}

fn validate_cloud_snapshot_identity(snapshot: &AuthorizationSnapshot) -> Result<(), CloudError> {
    validate_identifier(&snapshot.product_id, "snapshot.product_id", false)
        .map_err(CloudError::InvalidRequest)?;
    validate_opaque_identifier(&snapshot.snapshot_id, "snapshot.snapshot_id")
        .map_err(CloudError::InvalidRequest)?;
    validate_opaque_identifier(&snapshot.subject_id, "snapshot.subject_id")
        .map_err(CloudError::InvalidRequest)?;
    validate_opaque_identifier(&snapshot.device_id, "snapshot.device_id")
        .map_err(CloudError::InvalidRequest)?;
    Ok(())
}
