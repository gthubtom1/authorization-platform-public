//! Product-scoped durable runtime state.
//!
//! This module persists only already-validated A-local authorization
//! responses and runtime pins. It never creates authorization facts, stores
//! central credentials, contacts the VPS, or decides validity from the local
//! wall clock. Corrupt, mismatched, stale, or unverifiable state is rejected.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use super::authorization::{
    authorization_from_json_value, authorization_to_json_value, AuthorizationBinding,
    AuthorizationCache, AuthorizationCacheKey, AuthorizationCacheRequestRecord,
    AuthorizationCacheWatermark, AuthorizationIdentity, AuthorizationResponseV1, IntegrityVerifier,
    AUTHORIZATION_A_CORE_CONTRACT_VERSION, MAX_REQUEST_IDEMPOTENCY_RECORDS,
};
use super::codec::{
    ensure_known_fields, json_array, json_object, json_required, json_required_string,
    serialize_json, JsonParser, JsonValue,
};
use super::contract::contains_request_only_field;
use super::profile::ProductManifest;
use super::runtime::{EnvironmentProfile, MAX_CACHE_TTL_SECS, MAX_OFFLINE_GRACE_SECS};
use super::{validate_identifier, validate_short_text, AuthorizationError, LicenseState};

pub const AUTHORIZATION_CACHE_STATE_VERSION: &str = "authorization-a-cache.v1";
pub const RUNTIME_ROLLBACK_PIN_STATE_VERSION: &str = "authorization-a-runtime-pin.v1";
pub const AUTHORIZATION_CACHE_FILE_NAME: &str = "authorization-cache.v1.json";
pub const RUNTIME_ROLLBACK_PIN_FILE_NAME: &str = "authorization-a-runtime-pin.v1.json";
pub const MAX_PERSISTED_CACHE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PERSISTED_RESPONSES: usize = 64;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);
static STATE_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuntimeStateScope {
    pub environment_id: String,
    pub product_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub device_scope: String,
    pub device_id: String,
}

impl RuntimeStateScope {
    pub fn from_binding(environment_id: impl Into<String>, binding: &AuthorizationBinding) -> Self {
        Self {
            environment_id: environment_id.into(),
            product_id: binding.product_id.clone(),
            software_id: binding.identity.software_id.clone(),
            profile_id: binding.identity.profile_id.clone(),
            client_id: binding.identity.client_id.clone(),
            device_scope: binding.identity.device_scope.clone(),
            device_id: binding.identity.device_id.clone(),
        }
    }

    fn from_response(environment_id: &str, response: &AuthorizationResponseV1) -> Self {
        Self {
            environment_id: environment_id.to_string(),
            product_id: response.product_id.clone(),
            software_id: response.identity.software_id.clone(),
            profile_id: response.identity.profile_id.clone(),
            client_id: response.identity.client_id.clone(),
            device_scope: response.identity.device_scope.clone(),
            device_id: response.identity.device_id.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeStateError> {
        validate_identifier(&self.environment_id, "state.scope.environment_id", false)
            .map_err(RuntimeStateError::InvalidState)?;
        validate_runtime_path_segment(&self.environment_id)?;
        validate_identifier(&self.product_id, "state.scope.product_id", false)
            .map_err(RuntimeStateError::InvalidState)?;
        AuthorizationIdentity::new(
            &self.software_id,
            &self.profile_id,
            &self.client_id,
            &self.device_scope,
            &self.device_id,
        )
        .validate()
        .map_err(RuntimeStateError::Authorization)
    }

    fn to_json_value(&self) -> JsonValue {
        let mut object = BTreeMap::new();
        object.insert(
            "environment_id".to_string(),
            JsonValue::String(self.environment_id.clone()),
        );
        object.insert(
            "client_id".to_string(),
            JsonValue::String(self.client_id.clone()),
        );
        object.insert(
            "device_id".to_string(),
            JsonValue::String(self.device_id.clone()),
        );
        object.insert(
            "device_scope".to_string(),
            JsonValue::String(self.device_scope.clone()),
        );
        object.insert(
            "product_id".to_string(),
            JsonValue::String(self.product_id.clone()),
        );
        object.insert(
            "profile_id".to_string(),
            JsonValue::String(self.profile_id.clone()),
        );
        object.insert(
            "software_id".to_string(),
            JsonValue::String(self.software_id.clone()),
        );
        JsonValue::Object(object)
    }
}

#[derive(Debug)]
pub enum RuntimeStateError {
    InvalidState(String),
    Corrupt(String),
    ScopeMismatch {
        expected: RuntimeStateScope,
        actual: RuntimeStateScope,
    },
    TooLarge {
        path: PathBuf,
        max_bytes: usize,
    },
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Authorization(AuthorizationError),
    TimeRollback {
        last_seen: u64,
        received: u64,
    },
}

impl fmt::Display for RuntimeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(message) => write!(f, "invalid runtime state: {message}"),
            Self::Corrupt(message) => write!(f, "corrupt runtime state: {message}"),
            Self::ScopeMismatch { expected, actual } => write!(
                f,
                "runtime state scope mismatch: expected {expected:?}, received {actual:?}"
            ),
            Self::TooLarge { path, max_bytes } => write!(
                f,
                "runtime state {} exceeds the {max_bytes}-byte limit",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(
                    f,
                    "cannot access runtime state {}: {source}",
                    path.display()
                )
            }
            Self::Authorization(error) => error.fmt(f),
            Self::TimeRollback {
                last_seen,
                received,
            } => write!(
                f,
                "runtime server time moved backwards: last {last_seen}, received {received}"
            ),
        }
    }
}

impl std::error::Error for RuntimeStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Authorization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AuthorizationError> for RuntimeStateError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCacheStore {
    path: PathBuf,
    scope: RuntimeStateScope,
}

impl AuthorizationCacheStore {
    pub fn for_environment(
        base_dir: impl AsRef<Path>,
        environment_id: impl Into<String>,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
    ) -> Result<Self, RuntimeStateError> {
        manifest
            .validate()
            .map_err(|error| RuntimeStateError::InvalidState(error.to_string()))?;
        binding.validate_for(manifest)?;
        let scope = RuntimeStateScope::from_binding(environment_id, binding);
        scope.validate()?;
        validate_runtime_relative_path(&manifest.state_root)?;
        let state_root = base_dir.as_ref().join(&manifest.state_root);
        validate_state_path(&state_root)?;
        Ok(Self {
            path: state_root
                .join(&scope.environment_id)
                .join(AUTHORIZATION_CACHE_FILE_NAME),
            scope,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load<V: IntegrityVerifier>(
        &self,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<Option<AuthorizationCache>, RuntimeStateError> {
        self.validate_context(manifest, binding)?;
        if !state_file_present(&self.path)? {
            return Ok(None);
        }
        let input = read_state_file(&self.path)?;
        let (scope, responses, request_records, watermarks) = parse_cache_state(&input)?;
        self.ensure_scope(scope)?;

        let mut cache = AuthorizationCache::new();
        for response in responses {
            if response.decision == LicenseState::NotModified {
                return Err(RuntimeStateError::Corrupt(
                    "not_modified cannot be persisted as an authorization record".to_string(),
                ));
            }
            cache
                .apply(response, manifest, binding, verifier)
                .map_err(RuntimeStateError::Authorization)?;
        }
        cache
            .restore_persistence_metadata(request_records, watermarks, binding)
            .map_err(RuntimeStateError::Authorization)?;
        Ok(Some(cache))
    }

    pub fn save<V: IntegrityVerifier>(
        &self,
        cache: &AuthorizationCache,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<(), RuntimeStateError> {
        self.validate_context(manifest, binding)?;
        let responses = cache.responses().collect::<Vec<_>>();
        if responses.len() > MAX_PERSISTED_RESPONSES {
            return Err(RuntimeStateError::InvalidState(format!(
                "authorization cache cannot persist more than {MAX_PERSISTED_RESPONSES} responses"
            )));
        }

        let mut response_values = Vec::with_capacity(responses.len());
        for response in responses {
            if response.decision == LicenseState::NotModified {
                return Err(RuntimeStateError::InvalidState(
                    "not_modified cannot be persisted as an authorization record".to_string(),
                ));
            }
            let actual_scope =
                RuntimeStateScope::from_response(&self.scope.environment_id, response);
            self.ensure_scope(actual_scope)?;
            response
                .verify_for_core(manifest, binding, verifier)
                .map_err(RuntimeStateError::Authorization)?;
            response_values.push(authorization_to_json_value(response));
        }

        let request_records = cache.persistence_request_records();
        let watermarks = cache.persistence_watermarks();
        let request_record_values = request_records
            .iter()
            .map(request_record_to_json_value)
            .collect::<Vec<_>>();
        let watermark_values = watermarks
            .iter()
            .map(watermark_to_json_value)
            .collect::<Vec<_>>();

        let mut object = BTreeMap::new();
        object.insert("responses".to_string(), JsonValue::Array(response_values));
        object.insert(
            "request_records".to_string(),
            JsonValue::Array(request_record_values),
        );
        object.insert(
            "schema_version".to_string(),
            JsonValue::String(AUTHORIZATION_CACHE_STATE_VERSION.to_string()),
        );
        object.insert("scope".to_string(), self.scope.to_json_value());
        object.insert("watermarks".to_string(), JsonValue::Array(watermark_values));
        write_state_file(
            &self.path,
            serialize_json(&JsonValue::Object(object)).as_bytes(),
        )
    }

    fn validate_context(
        &self,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
    ) -> Result<(), RuntimeStateError> {
        manifest
            .validate()
            .map_err(|error| RuntimeStateError::InvalidState(error.to_string()))?;
        binding.validate_for(manifest)?;
        self.ensure_scope(RuntimeStateScope::from_binding(
            &self.scope.environment_id,
            binding,
        ))
    }

    fn ensure_scope(&self, actual: RuntimeStateScope) -> Result<(), RuntimeStateError> {
        actual.validate()?;
        if actual != self.scope {
            return Err(RuntimeStateError::ScopeMismatch {
                expected: self.scope.clone(),
                actual,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineLeasePolicy {
    pub cache_ttl_secs: u64,
    pub offline_grace_secs: u64,
}

impl OfflineLeasePolicy {
    pub const fn new(cache_ttl_secs: u64, offline_grace_secs: u64) -> Self {
        Self {
            cache_ttl_secs,
            offline_grace_secs,
        }
    }

    pub const fn from_environment(profile: &EnvironmentProfile) -> Self {
        Self::new(profile.cache_ttl_secs, profile.offline_grace_secs)
    }

    pub fn validate(&self) -> Result<(), RuntimeStateError> {
        if self.cache_ttl_secs > MAX_CACHE_TTL_SECS {
            return Err(RuntimeStateError::InvalidState(format!(
                "cache_ttl_secs cannot exceed {MAX_CACHE_TTL_SECS}"
            )));
        }
        if self.offline_grace_secs > MAX_OFFLINE_GRACE_SECS {
            return Err(RuntimeStateError::InvalidState(format!(
                "offline_grace_secs cannot exceed {MAX_OFFLINE_GRACE_SECS}"
            )));
        }
        Ok(())
    }

    pub fn evaluate(
        &self,
        response: &AuthorizationResponseV1,
        last_seen_server_time: u64,
        server_time: u64,
    ) -> Result<OfflineLeaseDecision, RuntimeStateError> {
        self.validate()?;
        if server_time < last_seen_server_time {
            return Err(RuntimeStateError::TimeRollback {
                last_seen: last_seen_server_time,
                received: server_time,
            });
        }
        if server_time < response.server_time {
            return Err(RuntimeStateError::TimeRollback {
                last_seen: response.server_time,
                received: server_time,
            });
        }

        let decision = match response.decision {
            LicenseState::Active | LicenseState::Grace => response.decision,
            LicenseState::Expired => return Ok(OfflineLeaseDecision::RejectExpired),
            LicenseState::Revoked => return Ok(OfflineLeaseDecision::RejectRevoked),
            LicenseState::Blocked => return Ok(OfflineLeaseDecision::RejectBlocked),
            LicenseState::NotModified | LicenseState::Unavailable => {
                return Ok(OfflineLeaseDecision::RejectUnavailable)
            }
        };

        if response
            .expires_at
            .is_some_and(|expires_at| server_time >= expires_at)
        {
            return Ok(OfflineLeaseDecision::RejectExpired);
        }

        let cache_until = response.cache_until.ok_or_else(|| {
            RuntimeStateError::InvalidState(
                "offline evaluation requires the server cache_until lease".to_string(),
            )
        })?;
        let cache_cap = response.server_time.saturating_add(self.cache_ttl_secs);
        let cache_deadline = cache_until.min(cache_cap);
        let grace_until = response.grace_until.ok_or_else(|| {
            RuntimeStateError::InvalidState(
                "offline evaluation requires the server grace_until lease".to_string(),
            )
        })?;
        let grace_cap = response
            .server_time
            .saturating_add(self.cache_ttl_secs)
            .saturating_add(self.offline_grace_secs);
        let grace_deadline = grace_until.min(grace_cap);

        if decision == LicenseState::Active && server_time < cache_deadline {
            return Ok(OfflineLeaseDecision::Active);
        }
        if server_time < grace_deadline {
            return Ok(OfflineLeaseDecision::Grace);
        }
        Ok(OfflineLeaseDecision::RejectExpired)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineLeaseDecision {
    Active,
    Grace,
    RejectExpired,
    RejectRevoked,
    RejectBlocked,
    RejectUnavailable,
}

impl OfflineLeaseDecision {
    pub const fn allows_launch(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePinClaim {
    pub artifact: String,
    pub contract_version: String,
    pub authorization_revision: u64,
    pub server_time: u64,
    pub decision: LicenseState,
    pub authority_payload_hash: String,
    pub revoked_or_blocked: bool,
}

impl RuntimePinClaim {
    pub fn new(
        artifact: impl Into<String>,
        contract_version: impl Into<String>,
        authorization_revision: u64,
        server_time: u64,
        decision: LicenseState,
        authority_payload_hash: impl Into<String>,
    ) -> Result<Self, RuntimeStateError> {
        let claim = Self {
            artifact: artifact.into(),
            contract_version: contract_version.into(),
            authorization_revision,
            server_time,
            decision,
            authority_payload_hash: authority_payload_hash.into(),
            revoked_or_blocked: matches!(decision, LicenseState::Revoked | LicenseState::Blocked),
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn validate(&self) -> Result<(), RuntimeStateError> {
        validate_short_text(&self.artifact, "runtime_pin.artifact")
            .map_err(RuntimeStateError::InvalidState)?;
        if self.contract_version != AUTHORIZATION_A_CORE_CONTRACT_VERSION {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin contract_version must be authorization-a-core.v1".to_string(),
            ));
        }
        if self.authorization_revision == 0 {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin authorization_revision must be greater than zero".to_string(),
            ));
        }
        if !matches!(
            self.decision,
            LicenseState::Active
                | LicenseState::Grace
                | LicenseState::Expired
                | LicenseState::Revoked
                | LicenseState::Blocked
        ) {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin decision is not a stable authorization state".to_string(),
            ));
        }
        if self.revoked_or_blocked
            != matches!(self.decision, LicenseState::Revoked | LicenseState::Blocked)
        {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin revoked_or_blocked does not match decision".to_string(),
            ));
        }
        validate_short_text(
            &self.authority_payload_hash,
            "runtime_pin.authority_payload_hash",
        )
        .map_err(RuntimeStateError::InvalidState)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRollbackPin {
    pub schema_version: String,
    pub current: RuntimePinClaim,
    pub previous: Option<RuntimePinClaim>,
    pub generation: u64,
    pub authorization_revision_floor: u64,
    pub server_time_highwater: u64,
}

impl RuntimeRollbackPin {
    pub fn new(current: RuntimePinClaim) -> Result<Self, RuntimeStateError> {
        let authorization_revision_floor = current.authorization_revision;
        let server_time_highwater = current.server_time;
        let pin = Self {
            schema_version: RUNTIME_ROLLBACK_PIN_STATE_VERSION.to_string(),
            current,
            previous: None,
            generation: 0,
            authorization_revision_floor,
            server_time_highwater,
        };
        pin.validate()?;
        Ok(pin)
    }

    pub fn validate(&self) -> Result<(), RuntimeStateError> {
        if self.schema_version != RUNTIME_ROLLBACK_PIN_STATE_VERSION {
            return Err(RuntimeStateError::InvalidState(format!(
                "runtime pin schema_version must be {RUNTIME_ROLLBACK_PIN_STATE_VERSION}"
            )));
        }
        self.current.validate()?;
        if self.authorization_revision_floor < self.current.authorization_revision {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin authorization revision floor is below current claim".to_string(),
            ));
        }
        if self.server_time_highwater < self.current.server_time {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin server-time high-water is below current claim".to_string(),
            ));
        }
        if let Some(previous) = &self.previous {
            previous.validate()?;
            if previous.artifact == self.current.artifact {
                return Err(RuntimeStateError::InvalidState(
                    "runtime pin current and previous artifacts must differ".to_string(),
                ));
            }
            if self.authorization_revision_floor < previous.authorization_revision {
                return Err(RuntimeStateError::InvalidState(
                    "runtime pin authorization revision floor is below previous claim".to_string(),
                ));
            }
            if self.server_time_highwater < previous.server_time {
                return Err(RuntimeStateError::InvalidState(
                    "runtime pin server-time high-water is below previous claim".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn advance(&mut self, next: RuntimePinClaim) -> Result<(), RuntimeStateError> {
        next.validate()?;
        if next.artifact == self.current.artifact {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin already points to this artifact".to_string(),
            ));
        }
        if next.authorization_revision < self.authorization_revision_floor {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin candidate authorization revision is below the persisted floor"
                    .to_string(),
            ));
        }
        if next.server_time < self.server_time_highwater {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin candidate server time is below the persisted high-water mark"
                    .to_string(),
            ));
        }
        let same_floor_claim = (self.current.authorization_revision
            == self.authorization_revision_floor
            && self.current.authority_payload_hash == next.authority_payload_hash)
            || self.previous.as_ref().is_some_and(|previous| {
                previous.authorization_revision == self.authorization_revision_floor
                    && previous.authority_payload_hash == next.authority_payload_hash
            });
        if next.authorization_revision == self.authorization_revision_floor && !same_floor_claim {
            return Err(RuntimeStateError::InvalidState(
                "runtime pin candidate changes authority payload at the same revision".to_string(),
            ));
        }
        let current = std::mem::replace(&mut self.current, next);
        self.previous = Some(current);
        self.generation = self.generation.saturating_add(1);
        self.authorization_revision_floor = self
            .authorization_revision_floor
            .max(self.current.authorization_revision);
        self.server_time_highwater = self.server_time_highwater.max(self.current.server_time);
        self.validate()
    }

    pub fn rollback(&mut self) -> Result<(), RuntimeStateError> {
        if self.current.revoked_or_blocked {
            return Err(RuntimeStateError::InvalidState(
                "a revoked or blocked pin cannot be cleared by local rollback".to_string(),
            ));
        }
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| previous.revoked_or_blocked)
        {
            return Err(RuntimeStateError::InvalidState(
                "a local rollback cannot restore a revoked or blocked previous pin".to_string(),
            ));
        }
        let previous = self.previous.take().ok_or_else(|| {
            RuntimeStateError::InvalidState("runtime pin has no previous artifact".to_string())
        })?;
        let current = std::mem::replace(&mut self.current, previous);
        self.previous = Some(current);
        self.generation = self.generation.saturating_add(1);
        self.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRollbackPinStore {
    path: PathBuf,
    scope: RuntimeStateScope,
}

impl RuntimeRollbackPinStore {
    pub fn for_environment(
        base_dir: impl AsRef<Path>,
        environment_id: impl Into<String>,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
    ) -> Result<Self, RuntimeStateError> {
        manifest
            .validate()
            .map_err(|error| RuntimeStateError::InvalidState(error.to_string()))?;
        binding.validate_for(manifest)?;
        let scope = RuntimeStateScope::from_binding(environment_id, binding);
        scope.validate()?;
        validate_runtime_relative_path(&manifest.state_root)?;
        let state_root = base_dir.as_ref().join(&manifest.state_root);
        validate_state_path(&state_root)?;
        Ok(Self {
            path: state_root
                .join(&scope.environment_id)
                .join(RUNTIME_ROLLBACK_PIN_FILE_NAME),
            scope,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<RuntimeRollbackPin>, RuntimeStateError> {
        if !state_file_present(&self.path)? {
            return Ok(None);
        }
        let input = read_state_file(&self.path)?;
        let (scope, pin) = parse_pin_state(&input)?;
        if scope != self.scope {
            return Err(RuntimeStateError::ScopeMismatch {
                expected: self.scope.clone(),
                actual: scope,
            });
        }
        Ok(Some(pin))
    }

    pub fn save(&self, pin: &RuntimeRollbackPin) -> Result<(), RuntimeStateError> {
        pin.validate()?;
        let mut object = BTreeMap::new();
        object.insert("current".to_string(), pin_claim_to_json_value(&pin.current));
        object.insert("generation".to_string(), JsonValue::Number(pin.generation));
        object.insert(
            "authorization_revision_floor".to_string(),
            JsonValue::Number(pin.authorization_revision_floor),
        );
        object.insert(
            "previous".to_string(),
            pin.previous
                .as_ref()
                .map_or(JsonValue::Null, pin_claim_to_json_value),
        );
        object.insert(
            "schema_version".to_string(),
            JsonValue::String(pin.schema_version.clone()),
        );
        object.insert(
            "server_time_highwater".to_string(),
            JsonValue::Number(pin.server_time_highwater),
        );
        object.insert("scope".to_string(), self.scope.to_json_value());
        write_state_file(
            &self.path,
            serialize_json(&JsonValue::Object(object)).as_bytes(),
        )
    }
}

fn parse_cache_state(
    input: &str,
) -> Result<
    (
        RuntimeStateScope,
        Vec<AuthorizationResponseV1>,
        Vec<AuthorizationCacheRequestRecord>,
        Vec<AuthorizationCacheWatermark>,
    ),
    RuntimeStateError,
> {
    let value = JsonParser::new(input)
        .parse()
        .map_err(RuntimeStateError::Corrupt)?;
    let object = json_object(&value, "authorization cache state")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &[
            "schema_version",
            "scope",
            "responses",
            "request_records",
            "watermarks",
        ],
        "authorization cache state",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let schema_version = json_required_string(
        object,
        "schema_version",
        "authorization cache state.schema_version",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    if schema_version != AUTHORIZATION_CACHE_STATE_VERSION {
        return Err(RuntimeStateError::Corrupt(format!(
            "unsupported authorization cache schema_version: {schema_version}"
        )));
    }
    let scope = parse_scope(
        json_required(object, "scope", "authorization cache state.scope")
            .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
    )?;
    let values = json_array(
        json_required(object, "responses", "authorization cache state.responses")
            .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
        "authorization cache state.responses",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    if values.len() > MAX_PERSISTED_RESPONSES {
        return Err(RuntimeStateError::Corrupt(format!(
            "authorization cache contains more than {MAX_PERSISTED_RESPONSES} responses"
        )));
    }
    let responses = values
        .iter()
        .cloned()
        .map(authorization_from_json_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(RuntimeStateError::Corrupt)?;
    let request_values = json_array(
        json_required(
            object,
            "request_records",
            "authorization cache state.request_records",
        )
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
        "authorization cache state.request_records",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    if request_values.len() > MAX_REQUEST_IDEMPOTENCY_RECORDS {
        return Err(RuntimeStateError::Corrupt(format!(
            "authorization cache contains more than {MAX_REQUEST_IDEMPOTENCY_RECORDS} request records"
        )));
    }
    let request_records = request_values
        .iter()
        .map(request_record_from_json_value)
        .collect::<Result<Vec<_>, _>>()?;
    let watermark_values = json_array(
        json_required(object, "watermarks", "authorization cache state.watermarks")
            .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
        "authorization cache state.watermarks",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    if watermark_values.len() > MAX_PERSISTED_RESPONSES {
        return Err(RuntimeStateError::Corrupt(format!(
            "authorization cache contains more than {MAX_PERSISTED_RESPONSES} watermarks"
        )));
    }
    let watermarks = watermark_values
        .iter()
        .map(watermark_from_json_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((scope, responses, request_records, watermarks))
}

fn parse_pin_state(
    input: &str,
) -> Result<(RuntimeStateScope, RuntimeRollbackPin), RuntimeStateError> {
    let value = JsonParser::new(input)
        .parse()
        .map_err(RuntimeStateError::Corrupt)?;
    let object = json_object(&value, "runtime rollback pin state")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &[
            "authorization_revision_floor",
            "schema_version",
            "scope",
            "current",
            "previous",
            "generation",
            "server_time_highwater",
        ],
        "runtime rollback pin state",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let schema_version = json_required_string(
        object,
        "schema_version",
        "runtime rollback pin state.schema_version",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    if schema_version != RUNTIME_ROLLBACK_PIN_STATE_VERSION {
        return Err(RuntimeStateError::Corrupt(format!(
            "unsupported runtime pin schema_version: {schema_version}"
        )));
    }
    let scope = parse_scope(
        json_required(object, "scope", "runtime rollback pin state.scope")
            .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
    )?;
    let current = pin_claim_from_json_value(
        json_required(object, "current", "runtime_pin.current")
            .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
    )?;
    let previous = match json_required(object, "previous", "runtime_pin.previous")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Null => None,
        value => Some(pin_claim_from_json_value(value)?),
    };
    let generation = match json_required(object, "generation", "runtime_pin.generation")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Number(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "runtime_pin.generation must be an unsigned integer".to_string(),
            ))
        }
    };
    let authorization_revision_floor = match json_required(
        object,
        "authorization_revision_floor",
        "runtime_pin.authorization_revision_floor",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Number(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "runtime pin authorization_revision_floor must be an unsigned integer".to_string(),
            ))
        }
    };
    let server_time_highwater = match json_required(
        object,
        "server_time_highwater",
        "runtime_pin.server_time_highwater",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Number(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "runtime pin server_time_highwater must be an unsigned integer".to_string(),
            ))
        }
    };
    let pin = RuntimeRollbackPin {
        schema_version: schema_version.to_string(),
        current,
        previous,
        generation,
        authorization_revision_floor,
        server_time_highwater,
    };
    pin.validate()?;
    Ok((scope, pin))
}

fn parse_scope(value: &JsonValue) -> Result<RuntimeStateScope, RuntimeStateError> {
    let object = json_object(value, "runtime state scope")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &[
            "environment_id",
            "product_id",
            "software_id",
            "profile_id",
            "client_id",
            "device_scope",
            "device_id",
        ],
        "runtime state scope",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let scope = RuntimeStateScope {
        environment_id: required_scope_text(object, "environment_id")?,
        product_id: required_scope_text(object, "product_id")?,
        software_id: required_scope_text(object, "software_id")?,
        profile_id: required_scope_text(object, "profile_id")?,
        client_id: required_scope_text(object, "client_id")?,
        device_scope: required_scope_text(object, "device_scope")?,
        device_id: required_scope_text(object, "device_id")?,
    };
    scope.validate()?;
    Ok(scope)
}

fn cache_key_to_json_value(key: &AuthorizationCacheKey) -> JsonValue {
    let mut object = BTreeMap::new();
    for (field, value) in [
        ("arch", &key.arch),
        ("authorization_id", &key.authorization_id),
        ("channel", &key.channel),
        ("client_id", &key.client_id),
        ("config_version", &key.config_version),
        ("contract_version", &key.contract_version),
        ("device_id", &key.device_id),
        ("device_scope", &key.device_scope),
        ("product_id", &key.product_id),
        ("profile_id", &key.profile_id),
        ("software_id", &key.software_id),
        ("target", &key.target),
    ] {
        object.insert(field.to_string(), JsonValue::String(value.clone()));
    }
    JsonValue::Object(object)
}

fn cache_key_from_json_value(
    value: &JsonValue,
) -> Result<AuthorizationCacheKey, RuntimeStateError> {
    let object = json_object(value, "authorization cache key")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &[
            "arch",
            "authorization_id",
            "channel",
            "client_id",
            "config_version",
            "contract_version",
            "device_id",
            "device_scope",
            "product_id",
            "profile_id",
            "software_id",
            "target",
        ],
        "authorization cache key",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let key = AuthorizationCacheKey {
        arch: required_scope_text(object, "arch")?,
        authorization_id: required_scope_text(object, "authorization_id")?,
        channel: required_scope_text(object, "channel")?,
        client_id: required_scope_text(object, "client_id")?,
        config_version: required_scope_text(object, "config_version")?,
        contract_version: required_scope_text(object, "contract_version")?,
        device_id: required_scope_text(object, "device_id")?,
        device_scope: required_scope_text(object, "device_scope")?,
        product_id: required_scope_text(object, "product_id")?,
        profile_id: required_scope_text(object, "profile_id")?,
        software_id: required_scope_text(object, "software_id")?,
        target: required_scope_text(object, "target")?,
    };
    key.validate()
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    Ok(key)
}

fn request_record_to_json_value(record: &AuthorizationCacheRequestRecord) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "canonical_payload".to_string(),
        JsonValue::String(record.canonical_payload.clone()),
    );
    object.insert("key".to_string(), cache_key_to_json_value(&record.key));
    object.insert(
        "request_id".to_string(),
        JsonValue::String(record.request_id.clone()),
    );
    JsonValue::Object(object)
}

fn request_record_from_json_value(
    value: &JsonValue,
) -> Result<AuthorizationCacheRequestRecord, RuntimeStateError> {
    let object = json_object(value, "authorization cache request record")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &["canonical_payload", "key", "request_id"],
        "authorization cache request record",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let canonical_payload = required_scope_text(object, "canonical_payload")?;
    if let Some(field) = contains_request_only_field(&canonical_payload) {
        return Err(RuntimeStateError::Corrupt(format!(
            "authorization cache request canonical payload contains request-only field {field}"
        )));
    }
    Ok(AuthorizationCacheRequestRecord {
        canonical_payload,
        key: cache_key_from_json_value(
            json_required(object, "key", "authorization cache request record.key")
                .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
        )?,
        request_id: required_scope_text(object, "request_id")?,
    })
}

fn watermark_to_json_value(watermark: &AuthorizationCacheWatermark) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert("key".to_string(), cache_key_to_json_value(&watermark.key));
    object.insert(
        "server_time".to_string(),
        JsonValue::Number(watermark.server_time),
    );
    JsonValue::Object(object)
}

fn watermark_from_json_value(
    value: &JsonValue,
) -> Result<AuthorizationCacheWatermark, RuntimeStateError> {
    let object = json_object(value, "authorization cache watermark")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &["key", "server_time"],
        "authorization cache watermark",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let server_time = match json_required(object, "server_time", "cache watermark.server_time")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Number(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "cache watermark.server_time must be an unsigned integer".to_string(),
            ))
        }
    };
    Ok(AuthorizationCacheWatermark {
        key: cache_key_from_json_value(
            json_required(object, "key", "cache watermark.key")
                .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?,
        )?,
        server_time,
    })
}

fn pin_claim_to_json_value(claim: &RuntimePinClaim) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "artifact".to_string(),
        JsonValue::String(claim.artifact.clone()),
    );
    object.insert(
        "authority_payload_hash".to_string(),
        JsonValue::String(claim.authority_payload_hash.clone()),
    );
    object.insert(
        "authorization_revision".to_string(),
        JsonValue::Number(claim.authorization_revision),
    );
    object.insert(
        "contract_version".to_string(),
        JsonValue::String(claim.contract_version.clone()),
    );
    object.insert(
        "decision".to_string(),
        JsonValue::String(claim.decision.as_str().to_string()),
    );
    object.insert(
        "revoked_or_blocked".to_string(),
        JsonValue::Bool(claim.revoked_or_blocked),
    );
    object.insert(
        "server_time".to_string(),
        JsonValue::Number(claim.server_time),
    );
    JsonValue::Object(object)
}

fn pin_claim_from_json_value(value: &JsonValue) -> Result<RuntimePinClaim, RuntimeStateError> {
    let object = json_object(value, "runtime pin claim")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    ensure_known_fields(
        object,
        &[
            "artifact",
            "authority_payload_hash",
            "authorization_revision",
            "contract_version",
            "decision",
            "revoked_or_blocked",
            "server_time",
        ],
        "runtime pin claim",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?;
    let decision = LicenseState::from_str(&required_scope_text(object, "decision")?)
        .ok_or_else(|| RuntimeStateError::Corrupt("runtime pin decision is unknown".to_string()))?;
    let authorization_revision = match json_required(
        object,
        "authorization_revision",
        "runtime pin authorization_revision",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Number(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "runtime pin authorization_revision must be an unsigned integer".to_string(),
            ))
        }
    };
    let server_time = match json_required(object, "server_time", "runtime pin server_time")
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Number(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "runtime pin server_time must be an unsigned integer".to_string(),
            ))
        }
    };
    let revoked_or_blocked = match json_required(
        object,
        "revoked_or_blocked",
        "runtime pin revoked_or_blocked",
    )
    .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))?
    {
        JsonValue::Bool(value) => *value,
        _ => {
            return Err(RuntimeStateError::Corrupt(
                "runtime pin revoked_or_blocked must be boolean".to_string(),
            ))
        }
    };
    let claim = RuntimePinClaim {
        artifact: required_scope_text(object, "artifact")?,
        contract_version: required_scope_text(object, "contract_version")?,
        authorization_revision,
        server_time,
        decision,
        authority_payload_hash: required_scope_text(object, "authority_payload_hash")?,
        revoked_or_blocked,
    };
    claim.validate()?;
    Ok(claim)
}

fn required_scope_text(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<String, RuntimeStateError> {
    json_required_string(object, key, &format!("runtime state scope.{key}"))
        .map(str::to_string)
        .map_err(|error| RuntimeStateError::Corrupt(error.to_string()))
}

fn validate_runtime_path_segment(value: &str) -> Result<(), RuntimeStateError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.ends_with('.')
        || value.ends_with(' ')
        || value
            .chars()
            .any(|character| matches!(character, ':' | '/' | '\\'))
    {
        return Err(RuntimeStateError::InvalidState(format!(
            "runtime state path segment is unsafe: {value:?}"
        )));
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        return Err(RuntimeStateError::InvalidState(format!(
            "runtime state path segment is a reserved Windows device name: {value:?}"
        )));
    }
    Ok(())
}

fn validate_runtime_relative_path(path: &Path) -> Result<(), RuntimeStateError> {
    if path.is_absolute() {
        return Err(RuntimeStateError::InvalidState(
            "runtime state root must be relative".to_string(),
        ));
    }
    for component in path.components() {
        if let std::path::Component::Normal(value) = component {
            let value = value.to_str().ok_or_else(|| {
                RuntimeStateError::InvalidState(
                    "runtime state root must be valid UTF-8 on this reference path".to_string(),
                )
            })?;
            validate_runtime_path_segment(value)?;
        }
    }
    Ok(())
}

fn validate_state_path(path: &Path) -> Result<(), RuntimeStateError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(RuntimeStateError::InvalidState(format!(
                        "runtime state path contains a symlink/reparse component: {}",
                        current.display()
                    )));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(RuntimeStateError::InvalidState(format!(
                            "runtime state path contains a reparse component: {}",
                            current.display()
                        )));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(RuntimeStateError::Io {
                    path: current,
                    source,
                })
            }
        }
    }
    Ok(())
}

fn read_state_file(path: &Path) -> Result<String, RuntimeStateError> {
    if let Some(parent) = path.parent() {
        validate_state_path(parent)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| RuntimeStateError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(RuntimeStateError::Corrupt(format!(
            "runtime state path is a symlink: {}",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(RuntimeStateError::Corrupt(format!(
            "runtime state path is not a file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_PERSISTED_CACHE_BYTES as u64 {
        return Err(RuntimeStateError::TooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_PERSISTED_CACHE_BYTES,
        });
    }
    let mut file = File::open(path).map_err(|source| RuntimeStateError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut input = String::new();
    Read::by_ref(&mut file)
        .take((MAX_PERSISTED_CACHE_BYTES + 1) as u64)
        .read_to_string(&mut input)
        .map_err(|source| RuntimeStateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if input.len() > MAX_PERSISTED_CACHE_BYTES {
        return Err(RuntimeStateError::TooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_PERSISTED_CACHE_BYTES,
        });
    }
    Ok(input)
}

fn state_file_present(path: &Path) -> Result<bool, RuntimeStateError> {
    if let Some(parent) = path.parent() {
        validate_state_path(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(RuntimeStateError::Corrupt(format!(
                    "runtime state path is a symlink: {}",
                    path.display()
                )));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(RuntimeStateError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_state_file(path: &Path, contents: &[u8]) -> Result<(), RuntimeStateError> {
    if contents.len() > MAX_PERSISTED_CACHE_BYTES {
        return Err(RuntimeStateError::TooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_PERSISTED_CACHE_BYTES,
        });
    }
    let parent = path.parent().ok_or_else(|| {
        RuntimeStateError::InvalidState(format!(
            "runtime state path has no parent: {}",
            path.display()
        ))
    })?;
    let _write_guard = STATE_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| {
            RuntimeStateError::InvalidState("runtime state writer lock is poisoned".to_string())
        })?;
    validate_state_path(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(RuntimeStateError::InvalidState(format!(
                "runtime state target is a symlink: {}",
                path.display()
            )));
        }
    }
    fs::create_dir_all(parent).map_err(|source| RuntimeStateError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    validate_state_path(parent)?;

    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            RuntimeStateError::InvalidState(format!(
                "runtime state path has an invalid file name: {}",
                path.display()
            ))
        })?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        counter
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| RuntimeStateError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(contents)
            .and_then(|_| file.sync_all())
            .map_err(|source| RuntimeStateError::Io {
                path: temporary.clone(),
                source,
            })?;
        drop(file);
        replace_file(&temporary, path).map_err(|source| RuntimeStateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        sync_directory(parent).map_err(|source| RuntimeStateError::Io {
            path: parent.to_path_buf(),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let from = from
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let success = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x9) };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}
