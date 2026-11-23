//! Product-neutral runtime policy seams.
//!
//! This module intentionally contains configuration and registry policy only.
//! It does not perform network I/O, open an OS IPC endpoint, start a process, or
//! store credentials. The cloud client, lifecycle state machine and platform
//! process supervision can build on these seams in later slices.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::{
    validate_identifier, validate_short_text, AuthorizationSnapshot, ContractError,
    LegacyAuthAdapter, LegacyAuthResult, ProductManifest,
};

pub const A_ENVIRONMENT_VERSION: &str = "a-environment.v1";
pub const MAX_ENVIRONMENT_PROFILES: usize = 32;
pub const MAX_RETRY_ATTEMPTS: u32 = 8;
pub const MAX_INITIAL_BACKOFF_MS: u64 = 60_000;
pub const MAX_BACKOFF_MS: u64 = 300_000;
pub const MAX_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
pub const MAX_OFFLINE_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentKind {
    Test,
    Production,
}

impl EnvironmentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Production => "production",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "test" => Some(Self::Test),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    Transient,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    Retry { next_attempt: u32, backoff_ms: u64 },
    Stop,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl RetryPolicy {
    pub const fn conservative() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 250,
            max_backoff_ms: 5_000,
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeError> {
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&self.max_attempts) {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "retry.max_attempts must be between 1 and {MAX_RETRY_ATTEMPTS}"
            )));
        }
        if self.initial_backoff_ms == 0 || self.initial_backoff_ms > MAX_INITIAL_BACKOFF_MS {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "retry.initial_backoff_ms must be between 1 and {MAX_INITIAL_BACKOFF_MS}"
            )));
        }
        if self.max_backoff_ms < self.initial_backoff_ms || self.max_backoff_ms > MAX_BACKOFF_MS {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "retry.max_backoff_ms must be between initial_backoff_ms and {MAX_BACKOFF_MS}"
            )));
        }
        Ok(())
    }

    pub fn decision(&self, attempt: u32, failure: RetryClass) -> RetryDecision {
        if failure == RetryClass::Permanent {
            return RetryDecision::Stop;
        }
        if attempt.saturating_add(1) >= self.max_attempts {
            return RetryDecision::Unavailable;
        }

        let exponent = attempt.min(31);
        let multiplier = 1_u64 << exponent;
        RetryDecision::Retry {
            next_attempt: attempt + 1,
            backoff_ms: self
                .initial_backoff_ms
                .saturating_mul(multiplier)
                .min(self.max_backoff_ms),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentProfile {
    pub schema_version: String,
    pub environment_id: String,
    pub kind: EnvironmentKind,
    pub endpoint: String,
    pub request_timeout_ms: u64,
    pub retry: RetryPolicy,
    pub cache_ttl_secs: u64,
    pub offline_grace_secs: u64,
}

impl EnvironmentProfile {
    pub fn new(
        environment_id: impl Into<String>,
        kind: EnvironmentKind,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: A_ENVIRONMENT_VERSION.to_string(),
            environment_id: environment_id.into(),
            kind,
            endpoint: endpoint.into(),
            request_timeout_ms: 15_000,
            retry: RetryPolicy::conservative(),
            cache_ttl_secs: 15 * 60,
            // Platform default is offline_grace_seconds = 0 (online-only):
            // once heartbeats fail past the verify window the launcher must
            // stop the core. A wider grace is an explicit per-product choice
            // via with_cache_policy, never the default.
            offline_grace_secs: 0,
        }
    }

    pub fn test(environment_id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self::new(environment_id, EnvironmentKind::Test, endpoint)
    }

    pub fn production(environment_id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self::new(environment_id, EnvironmentKind::Production, endpoint)
    }

    pub fn with_request_timeout_ms(mut self, request_timeout_ms: u64) -> Self {
        self.request_timeout_ms = request_timeout_ms;
        self
    }

    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub fn with_cache_policy(mut self, cache_ttl_secs: u64, offline_grace_secs: u64) -> Self {
        self.cache_ttl_secs = cache_ttl_secs;
        self.offline_grace_secs = offline_grace_secs;
        self
    }

    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema_version != A_ENVIRONMENT_VERSION {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "schema_version must be {A_ENVIRONMENT_VERSION}"
            )));
        }
        validate_identifier(&self.environment_id, "environment_id", false)
            .map_err(RuntimeError::InvalidEnvironment)?;
        validate_short_text(&self.endpoint, "endpoint")
            .map_err(RuntimeError::InvalidEnvironment)?;
        if self.endpoint.chars().any(char::is_whitespace) {
            return Err(RuntimeError::InvalidEnvironment(
                "endpoint must not contain whitespace".to_string(),
            ));
        }

        let endpoint = self.endpoint.to_ascii_lowercase();
        let valid_scheme = match self.kind {
            EnvironmentKind::Test => {
                endpoint.starts_with("http://") || endpoint.starts_with("https://")
            }
            EnvironmentKind::Production => endpoint.starts_with("https://"),
        };
        if !valid_scheme {
            return Err(RuntimeError::InvalidEnvironment(
                "endpoint must use https for production and http(s) for test".to_string(),
            ));
        }
        let authority = endpoint
            .split_once("://")
            .and_then(|(_, remainder)| remainder.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if authority.is_empty() || authority.starts_with(':') || endpoint.contains('@') {
            return Err(RuntimeError::InvalidEnvironment(
                "endpoint must contain a host and must not contain user credentials".to_string(),
            ));
        }
        for marker in [
            "token=",
            "secret=",
            "password=",
            "api_key=",
            "apikey=",
            "authorization=",
        ] {
            if endpoint.contains(marker) {
                return Err(RuntimeError::InvalidEnvironment(
                    "endpoint must not contain credential query parameters".to_string(),
                ));
            }
        }

        if !(1..=120_000).contains(&self.request_timeout_ms) {
            return Err(RuntimeError::InvalidEnvironment(
                "request_timeout_ms must be between 1 and 120000".to_string(),
            ));
        }
        self.retry.validate()?;
        if self.cache_ttl_secs > MAX_CACHE_TTL_SECS {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "cache_ttl_secs cannot exceed {MAX_CACHE_TTL_SECS}"
            )));
        }
        if self.offline_grace_secs > MAX_OFFLINE_GRACE_SECS {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "offline_grace_secs cannot exceed {MAX_OFFLINE_GRACE_SECS}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnvironmentCatalog {
    profiles: BTreeMap<String, EnvironmentProfile>,
}

impl EnvironmentCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, profile: EnvironmentProfile) -> Result<(), RuntimeError> {
        profile.validate()?;
        let environment_id = profile.environment_id.clone();
        if self.profiles.contains_key(&environment_id) {
            return Err(RuntimeError::DuplicateEnvironment(environment_id));
        }
        if self.profiles.len() >= MAX_ENVIRONMENT_PROFILES {
            return Err(RuntimeError::InvalidEnvironment(format!(
                "environment catalog cannot contain more than {MAX_ENVIRONMENT_PROFILES} profiles"
            )));
        }
        self.profiles.insert(environment_id, profile);
        Ok(())
    }

    pub fn get(&self, environment_id: &str) -> Option<&EnvironmentProfile> {
        self.profiles.get(environment_id)
    }

    pub fn require(&self, environment_id: &str) -> Result<&EnvironmentProfile, RuntimeError> {
        self.get(environment_id)
            .ok_or_else(|| RuntimeError::EnvironmentNotFound(environment_id.to_string()))
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn profiles(&self) -> impl Iterator<Item = &EnvironmentProfile> {
        self.profiles.values()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    InvalidEnvironment(String),
    DuplicateEnvironment(String),
    EnvironmentNotFound(String),
    InvalidAdapterIdentity(String),
    DuplicateAdapter {
        adapter_id: String,
        adapter_version: String,
    },
    AdapterNotFound {
        adapter_id: String,
        adapter_version: String,
    },
    Contract(ContractError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvironment(message) => {
                write!(f, "invalid environment profile: {message}")
            }
            Self::DuplicateEnvironment(environment_id) => {
                write!(f, "environment is already registered: {environment_id}")
            }
            Self::EnvironmentNotFound(environment_id) => {
                write!(f, "environment is not registered: {environment_id}")
            }
            Self::InvalidAdapterIdentity(message) => {
                write!(f, "invalid adapter identity: {message}")
            }
            Self::DuplicateAdapter {
                adapter_id,
                adapter_version,
            } => write!(
                f,
                "adapter is already registered: {adapter_id}@{adapter_version}"
            ),
            Self::AdapterNotFound {
                adapter_id,
                adapter_version,
            } => write!(
                f,
                "adapter is not registered: {adapter_id}@{adapter_version}"
            ),
            Self::Contract(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for RuntimeError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Clone, Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<(String, String), Arc<dyn LegacyAuthAdapter>>,
}

impl fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("adapter_count", &self.adapters.len())
            .field("identities", &self.adapters.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<A>(&mut self, adapter: A) -> Result<(), RuntimeError>
    where
        A: LegacyAuthAdapter + 'static,
    {
        self.register_arc(Arc::new(adapter))
    }

    pub fn register_arc(
        &mut self,
        adapter: Arc<dyn LegacyAuthAdapter>,
    ) -> Result<(), RuntimeError> {
        let adapter_id = adapter.adapter_id().to_string();
        let adapter_version = adapter.adapter_version().to_string();
        validate_identifier(&adapter_id, "adapter_id", false)
            .map_err(RuntimeError::InvalidAdapterIdentity)?;
        validate_short_text(&adapter_version, "adapter_version")
            .map_err(RuntimeError::InvalidAdapterIdentity)?;
        let key = (adapter_id.clone(), adapter_version.clone());
        if self.adapters.contains_key(&key) {
            return Err(RuntimeError::DuplicateAdapter {
                adapter_id,
                adapter_version,
            });
        }
        self.adapters.insert(key, adapter);
        Ok(())
    }

    pub fn get(
        &self,
        adapter_id: &str,
        adapter_version: &str,
    ) -> Option<Arc<dyn LegacyAuthAdapter>> {
        self.adapters
            .get(&(adapter_id.to_string(), adapter_version.to_string()))
            .cloned()
    }

    pub fn resolve(
        &self,
        manifest: &ProductManifest,
    ) -> Result<Arc<dyn LegacyAuthAdapter>, RuntimeError> {
        self.get(&manifest.adapter_id, &manifest.adapter_version)
            .ok_or_else(|| RuntimeError::AdapterNotFound {
                adapter_id: manifest.adapter_id.clone(),
                adapter_version: manifest.adapter_version.clone(),
            })
    }

    pub fn adapt(
        &self,
        manifest: &ProductManifest,
        snapshot: &AuthorizationSnapshot,
    ) -> Result<LegacyAuthResult, RuntimeError> {
        snapshot.validate_for(manifest)?;
        self.resolve(manifest)?
            .adapt(manifest, snapshot)
            .map_err(RuntimeError::Contract)
    }

    pub fn contains(&self, adapter_id: &str, adapter_version: &str) -> bool {
        self.adapters
            .contains_key(&(adapter_id.to_string(), adapter_version.to_string()))
    }

    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}
