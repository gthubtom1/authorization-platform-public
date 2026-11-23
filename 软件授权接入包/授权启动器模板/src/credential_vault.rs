//! Product-neutral credential recovery and OS-protected local storage.
//!
//! The vault stores a credential only as an encrypted OS credential. A vault
//! record is a recovery input, not an authorization decision: the caller must
//! verify the server response and its device scope again on every startup.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::authorization::{
    validate_config_version, AuthorizationBinding, AuthorizationResponseV1, IntegrityVerifier,
};
use crate::contract::{validate_identifier, validate_opaque_identifier};
use crate::{LicenseState, ProductManifest};

pub const CREDENTIAL_VAULT_PROTOCOL_VERSION: &str = "authorization-a-credential.v1";
/// Windows defines CRED_MAX_CREDENTIAL_BLOB_SIZE as 5 * 512 bytes.
pub const CREDENTIAL_VAULT_MAX_RECORD_BYTES: usize = 5 * 512;
pub const CREDENTIAL_VAULT_MAX_SECRET_BYTES: usize = 1024;
pub const CREDENTIAL_VAULT_MAX_DEVICE_TOKEN_BYTES: usize = 1536;

const RECORD_MAGIC: &[u8] = b"AUTH-A-CREDENTIAL-V1\0";
const CREDENTIAL_MANAGER_NOT_FOUND: u32 = 1168;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVaultError {
    InvalidScope(String),
    InvalidRecord(String),
    ScopeMismatch { expected: String, actual: String },
    SecureStorageUnavailable,
    Storage { operation: &'static str, code: u32 },
}

impl fmt::Display for CredentialVaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScope(message) => write!(f, "invalid credential vault scope: {message}"),
            Self::InvalidRecord(message) => write!(f, "invalid credential vault record: {message}"),
            Self::ScopeMismatch { expected, actual } => write!(
                f,
                "credential vault scope mismatch: expected {expected}, received {actual}"
            ),
            Self::SecureStorageUnavailable => write!(
                f,
                "the current platform has no configured secure credential storage"
            ),
            Self::Storage { operation, code } => {
                write!(
                    f,
                    "secure credential storage operation {operation} failed ({code})"
                )
            }
        }
    }
}

impl std::error::Error for CredentialVaultError {}

/// A short-lived secret kept out of Debug output and zeroed when dropped.
///
/// Zeroing process memory cannot protect a compromised process, but it avoids
/// leaving the value in an ordinary heap allocation after the recovery flow.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn from_text(value: &str) -> Result<Self, CredentialVaultError> {
        if value.is_empty() {
            return Err(CredentialVaultError::InvalidRecord(
                "secret must not be empty".to_string(),
            ));
        }
        if value.len() > CREDENTIAL_VAULT_MAX_SECRET_BYTES {
            return Err(CredentialVaultError::InvalidRecord(
                "secret exceeds the bounded storage limit".to_string(),
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(CredentialVaultError::InvalidRecord(
                "secret contains a control character".to_string(),
            ));
        }
        Ok(Self(value.as_bytes().to_vec()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Access the value only for the immediate request that needs it.
    pub fn with_bytes<R>(&self, callback: impl FnOnce(&[u8]) -> R) -> R {
        callback(&self.0)
    }

    pub fn with_text<R>(&self, callback: impl FnOnce(&str) -> R) -> R {
        let text =
            std::str::from_utf8(&self.0).expect("SecretValue constructors must preserve UTF-8");
        callback(text)
    }

    fn from_bytes(
        bytes: ZeroizingBytes,
        max_bytes: usize,
        field: &'static str,
    ) -> Result<Self, CredentialVaultError> {
        if bytes.is_empty() {
            return Err(CredentialVaultError::InvalidRecord(format!(
                "{field} must not be empty"
            )));
        }
        if bytes.len() > max_bytes {
            return Err(CredentialVaultError::InvalidRecord(format!(
                "{field} exceeds the bounded storage limit"
            )));
        }
        let text = std::str::from_utf8(bytes.as_slice()).map_err(|_| {
            CredentialVaultError::InvalidRecord(format!("{field} is not valid UTF-8"))
        })?;
        if text.chars().any(char::is_control) {
            return Err(CredentialVaultError::InvalidRecord(format!(
                "{field} contains a control character"
            )));
        }
        Ok(Self(bytes.into_vec()))
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretValue")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

/// An owned byte buffer used while encoding or decoding a record that contains
/// a secret. It prevents temporary serialized records from being left as
/// ordinary heap allocations after a failed decode or storage operation.
struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn push(&mut self, byte: u8) {
        self.0.push(byte);
    }

    fn into_vec(self) -> Vec<u8> {
        let mut this = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut this.0)
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: every pointer comes from a live, uniquely borrowed byte and
        // remains valid for the duration of the volatile write.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialVaultAddress {
    pub environment_id: String,
    pub product_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
}

impl CredentialVaultAddress {
    pub fn new(
        environment_id: impl Into<String>,
        product_id: impl Into<String>,
        software_id: impl Into<String>,
        profile_id: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            environment_id: environment_id.into(),
            product_id: product_id.into(),
            software_id: software_id.into(),
            profile_id: profile_id.into(),
            client_id: client_id.into(),
        }
    }

    pub fn validate(&self) -> Result<(), CredentialVaultError> {
        validate_identifier(&self.environment_id, "vault.environment_id", false)
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_identifier(&self.product_id, "vault.product_id", false)
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_identifier(&self.software_id, "vault.software_id", false)
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_identifier(&self.profile_id, "vault.profile_id", false)
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_opaque_identifier(&self.client_id, "vault.client_id")
            .map_err(CredentialVaultError::InvalidScope)?;
        if self.storage_target_name().len() > 2048 {
            return Err(CredentialVaultError::InvalidScope(
                "vault target name is too long".to_string(),
            ));
        }
        Ok(())
    }

    /// The target is a deterministic, non-secret base prefix. Full scope
    /// records append a scope digest so different authorizations never share
    /// one Credential Manager slot.
    pub fn storage_target_name(&self) -> String {
        let material = [
            self.environment_id.as_str(),
            self.product_id.as_str(),
            self.software_id.as_str(),
            self.profile_id.as_str(),
            self.client_id.as_str(),
        ]
        .join("\0");
        format!(
            "AuthorizationA/{CREDENTIAL_VAULT_PROTOCOL_VERSION}/{}",
            hex_encode(material.as_bytes())
        )
    }

    fn display_scope(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.environment_id, self.product_id, self.software_id, self.profile_id, self.client_id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialVaultScope {
    pub address: CredentialVaultAddress,
    pub authorization_id: String,
    pub device_scope: String,
    pub device_id: String,
    pub installation_id: String,
    pub config_version: String,
}

impl CredentialVaultScope {
    pub fn new(
        address: CredentialVaultAddress,
        authorization_id: impl Into<String>,
        device_scope: impl Into<String>,
        device_id: impl Into<String>,
        installation_id: impl Into<String>,
        config_version: impl Into<String>,
    ) -> Self {
        Self {
            address,
            authorization_id: authorization_id.into(),
            device_scope: device_scope.into(),
            device_id: device_id.into(),
            installation_id: installation_id.into(),
            config_version: config_version.into(),
        }
    }

    pub fn from_response(
        environment_id: impl Into<String>,
        response: &AuthorizationResponseV1,
    ) -> Result<Self, CredentialVaultError> {
        let environment_id = environment_id.into();
        let structured_scope = response.structured_device_scope.as_ref().ok_or_else(|| {
            CredentialVaultError::InvalidRecord(
                "server response has no structured device binding".to_string(),
            )
        })?;
        structured_scope.validate_for_authorization().map_err(|_| {
            CredentialVaultError::InvalidRecord(
                "server device binding is not confirmed".to_string(),
            )
        })?;
        let device_id = structured_scope.device_id.clone().ok_or_else(|| {
            CredentialVaultError::InvalidRecord(
                "server device binding has no device id".to_string(),
            )
        })?;
        let installation_id = structured_scope.installation_id.clone().ok_or_else(|| {
            CredentialVaultError::InvalidRecord(
                "server device binding has no installation id".to_string(),
            )
        })?;
        if response.identity.device_scope != structured_scope.scope
            || response.identity.device_id != device_id
        {
            return Err(CredentialVaultError::InvalidRecord(
                "server device binding does not match the response identity".to_string(),
            ));
        }
        let scope = Self::new(
            CredentialVaultAddress::new(
                environment_id,
                response.product_id.clone(),
                response.identity.software_id.clone(),
                response.identity.profile_id.clone(),
                response.identity.client_id.clone(),
            ),
            response.authorization_id.clone(),
            structured_scope.scope.clone(),
            device_id,
            installation_id,
            response.config_version.clone(),
        );
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), CredentialVaultError> {
        self.address.validate()?;
        validate_opaque_identifier(&self.authorization_id, "vault.authorization_id")
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_opaque_identifier(&self.device_scope, "vault.device_scope")
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_opaque_identifier(&self.device_id, "vault.device_id")
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_opaque_identifier(&self.installation_id, "vault.installation_id")
            .map_err(CredentialVaultError::InvalidScope)?;
        validate_config_version(&self.config_version, "vault.config_version")
            .map_err(CredentialVaultError::InvalidScope)?;
        if self.storage_target_name().len() > 2048 {
            return Err(CredentialVaultError::InvalidScope(
                "vault target name is too long".to_string(),
            ));
        }
        Ok(())
    }

    /// The actual storage key includes the authorization instance, device and
    /// configuration scope. The scope is also retained in the protected blob
    /// and checked after reading to detect tampering or stale records.
    pub fn storage_target_name(&self) -> String {
        let material = [
            self.authorization_id.as_str(),
            self.device_scope.as_str(),
            self.device_id.as_str(),
            self.installation_id.as_str(),
            self.config_version.as_str(),
        ]
        .join("\0");
        format!(
            "{}/{}",
            self.address.storage_target_name(),
            hex_encode(material.as_bytes())
        )
    }

    pub fn matches_response(
        &self,
        environment_id: impl Into<String>,
        response: &AuthorizationResponseV1,
    ) -> Result<bool, CredentialVaultError> {
        Ok(self == &Self::from_response(environment_id, response)?)
    }

    fn same_authorization_scope(&self, other: &Self) -> bool {
        self.address == other.address
            && self.authorization_id == other.authorization_id
            && self.device_scope == other.device_scope
            && self.device_id == other.device_id
            && self.installation_id == other.installation_id
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CachedCredential {
    pub scope: CredentialVaultScope,
    credential: SecretValue,
    device_token: Option<SecretValue>,
    pub authorization_revision: u64,
    pub server_time: u64,
    pub expires_at: Option<u64>,
}

impl fmt::Debug for CachedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedCredential")
            .field("scope", &self.scope)
            .field("credential", &self.credential)
            .field(
                "device_token",
                &self.device_token.as_ref().map(SecretValue::len),
            )
            .field("authorization_revision", &self.authorization_revision)
            .field("server_time", &self.server_time)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CachedCredential {
    pub fn new(
        scope: CredentialVaultScope,
        credential: SecretValue,
        device_token: Option<SecretValue>,
        authorization_revision: u64,
        server_time: u64,
        expires_at: Option<u64>,
    ) -> Result<Self, CredentialVaultError> {
        let record = Self {
            scope,
            credential,
            device_token,
            authorization_revision,
            server_time,
            expires_at,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn new_text(
        scope: CredentialVaultScope,
        credential: &str,
        device_token: Option<&str>,
        authorization_revision: u64,
        server_time: u64,
        expires_at: Option<u64>,
    ) -> Result<Self, CredentialVaultError> {
        let token = device_token.map(SecretValue::from_text).transpose()?;
        Self::new(
            scope,
            SecretValue::from_text(credential)?,
            token,
            authorization_revision,
            server_time,
            expires_at,
        )
    }

    pub fn credential(&self) -> &SecretValue {
        &self.credential
    }

    pub fn device_token(&self) -> Option<&SecretValue> {
        self.device_token.as_ref()
    }

    /// This is only a timestamp comparison. It never grants access by itself;
    /// the runtime must still verify the server response or its signed lease.
    pub fn is_within_recorded_expiry(&self, server_time: u64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| server_time < expires_at)
    }

    fn validate(&self) -> Result<(), CredentialVaultError> {
        self.scope.validate()?;
        if self.credential.is_empty() {
            return Err(CredentialVaultError::InvalidRecord(
                "credential must not be empty".to_string(),
            ));
        }
        if let Some(token) = &self.device_token {
            if token.is_empty() || token.len() > CREDENTIAL_VAULT_MAX_DEVICE_TOKEN_BYTES {
                return Err(CredentialVaultError::InvalidRecord(
                    "device token is outside the bounded storage limit".to_string(),
                ));
            }
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at < self.server_time)
        {
            return Err(CredentialVaultError::InvalidRecord(
                "record expiry precedes its server issue time".to_string(),
            ));
        }
        Ok(())
    }
}

/// A marker created only after the response has passed A's binding, manifest,
/// state and integrity checks. The vault still does not turn this into a
/// launch grant; it only allows the runtime to persist the recovery material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCredentialRecord(CachedCredential);

impl VerifiedCredentialRecord {
    pub fn from_verified_response<V: IntegrityVerifier>(
        environment_id: impl Into<String>,
        response: &AuthorizationResponseV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
        credential: &str,
        device_token: Option<&str>,
    ) -> Result<Self, CredentialVaultError> {
        response
            .validate_for_binding(manifest, binding)
            .map_err(|_| {
                CredentialVaultError::InvalidRecord(
                    "authorization response failed binding validation".to_string(),
                )
            })?;
        response.validate_for_manifest(manifest).map_err(|_| {
            CredentialVaultError::InvalidRecord(
                "authorization response failed manifest validation".to_string(),
            )
        })?;
        response.verify(verifier).map_err(|_| {
            CredentialVaultError::InvalidRecord(
                "authorization response integrity verification failed".to_string(),
            )
        })?;
        if !matches!(
            response.decision,
            LicenseState::Active | LicenseState::Grace
        ) {
            return Err(CredentialVaultError::InvalidRecord(
                "only active or grace responses may create a recovery record".to_string(),
            ));
        }
        let scope = CredentialVaultScope::from_response(environment_id, response)?;
        CachedCredential::new_text(
            scope,
            credential,
            device_token,
            response.authorization_revision,
            response.server_time,
            response.expires_at,
        )
        .map(Self)
    }

    pub fn record(&self) -> &CachedCredential {
        &self.0
    }
}

/// A cached record that has been loaded for a fresh server verification.
///
/// The raw credential is deliberately not exposed as a field or getter. A
/// transport adapter can borrow request material for one request, then must
/// consume this value through the verify_cached_response method before it can
/// obtain a newly verified recovery record.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingCachedCredential(CachedCredential);

impl fmt::Debug for PendingCachedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingCachedCredential")
            .field("scope", &self.0.scope)
            .field("authorization_revision", &self.0.authorization_revision)
            .field("server_time", &self.0.server_time)
            .field("expires_at", &self.0.expires_at)
            .finish()
    }
}

impl PendingCachedCredential {
    pub fn scope(&self) -> &CredentialVaultScope {
        &self.0.scope
    }

    pub fn authorization_revision(&self) -> u64 {
        self.0.authorization_revision
    }

    pub fn server_time(&self) -> u64 {
        self.0.server_time
    }

    pub fn is_within_recorded_expiry(&self, server_time: u64) -> bool {
        self.0.is_within_recorded_expiry(server_time)
    }

    /// Borrow request material only while constructing the fresh verify
    /// request. This callback does not confer authorization.
    pub fn with_request_material<R>(
        &self,
        callback: impl FnOnce(&CredentialVaultScope, &SecretValue, Option<&SecretValue>) -> R,
    ) -> R {
        callback(
            &self.0.scope,
            &self.0.credential,
            self.0.device_token.as_ref(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRecoveryState {
    LoginRequired,
    VerifyCachedCredential(PendingCachedCredential),
}

pub trait CredentialVault: Send + Sync {
    fn load(
        &self,
        address: &CredentialVaultAddress,
    ) -> Result<Option<CachedCredential>, CredentialVaultError>;

    fn load_for_scope(
        &self,
        scope: &CredentialVaultScope,
    ) -> Result<Option<CachedCredential>, CredentialVaultError>;

    fn save(
        &self,
        address: &CredentialVaultAddress,
        record: &VerifiedCredentialRecord,
    ) -> Result<(), CredentialVaultError>;

    fn clear(&self, address: &CredentialVaultAddress) -> Result<(), CredentialVaultError>;
}

/// Startup integration for a launcher or runtime. It deliberately stops at
/// `VerifyCachedCredential`; the caller must send a fresh verify request and
/// apply the existing signed response/cache lease rules before launching.
#[derive(Debug, Clone)]
pub struct CredentialRecovery<V> {
    vault: V,
}

impl<V: CredentialVault> CredentialRecovery<V> {
    pub fn new(vault: V) -> Self {
        Self { vault }
    }

    pub fn startup(
        &self,
        address: &CredentialVaultAddress,
    ) -> Result<CredentialRecoveryState, CredentialVaultError> {
        match self.vault.load(address) {
            Ok(Some(record)) => Ok(CredentialRecoveryState::VerifyCachedCredential(
                PendingCachedCredential(record),
            )),
            Ok(None) | Err(CredentialVaultError::SecureStorageUnavailable) => {
                Ok(CredentialRecoveryState::LoginRequired)
            }
            Err(CredentialVaultError::InvalidRecord(_))
            | Err(CredentialVaultError::ScopeMismatch { .. })
            | Err(CredentialVaultError::Storage { .. }) => {
                Ok(CredentialRecoveryState::LoginRequired)
            }
            Err(error) => Err(error),
        }
    }

    /// Convert a startup cache candidate into a new verified record only after
    /// a fresh signed response has passed the same binding and manifest checks
    /// as first activation. The response must not move backwards in revision
    /// or scope.
    pub fn verify_cached_response<I: IntegrityVerifier>(
        &self,
        pending: PendingCachedCredential,
        environment_id: impl Into<String>,
        response: &AuthorizationResponseV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &I,
    ) -> Result<VerifiedCredentialRecord, CredentialVaultError> {
        let environment_id = environment_id.into();
        let expected_scope = pending.0.scope.clone();
        let verified = pending.0.credential.with_text(|credential| {
            if let Some(token) = pending.0.device_token.as_ref() {
                token.with_text(|device_token| {
                    VerifiedCredentialRecord::from_verified_response(
                        environment_id,
                        response,
                        manifest,
                        binding,
                        verifier,
                        credential,
                        Some(device_token),
                    )
                })
            } else {
                VerifiedCredentialRecord::from_verified_response(
                    environment_id,
                    response,
                    manifest,
                    binding,
                    verifier,
                    credential,
                    None,
                )
            }
        })?;
        if !verified
            .record()
            .scope
            .same_authorization_scope(&expected_scope)
        {
            return Err(CredentialVaultError::ScopeMismatch {
                expected: expected_scope.address.display_scope(),
                actual: verified.record().scope.address.display_scope(),
            });
        }
        if response.authorization_revision < pending.0.authorization_revision {
            return Err(CredentialVaultError::InvalidRecord(
                "fresh authorization response is older than the cached revision".to_string(),
            ));
        }
        Ok(verified)
    }

    pub fn save_verified(
        &self,
        address: &CredentialVaultAddress,
        record: &VerifiedCredentialRecord,
    ) -> Result<(), CredentialVaultError> {
        self.vault.save(address, record)
    }

    pub fn clear(&self, address: &CredentialVaultAddress) -> Result<(), CredentialVaultError> {
        self.vault.clear(address)
    }
}

/// In-memory test double only. Production code should use
/// [`default_credential_vault`] and fail closed when the platform has no OS
/// secure store.
#[derive(Clone, Default)]
pub struct MemoryCredentialVault {
    entries: Arc<Mutex<BTreeMap<String, ZeroizingBytes>>>,
}

impl fmt::Debug for MemoryCredentialVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self
            .entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0);
        f.debug_struct("MemoryCredentialVault")
            .field("stored_entries", &count)
            .finish()
    }
}

impl CredentialVault for MemoryCredentialVault {
    fn load(
        &self,
        address: &CredentialVaultAddress,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        address.validate()?;
        let prefix = format!("{}/", address.storage_target_name());
        let entries = self
            .entries
            .lock()
            .map_err(|_| CredentialVaultError::Storage {
                operation: "memory_lock",
                code: 0,
            })?;
        let mut selected = None;
        for (key, bytes) in entries.iter() {
            if !key.starts_with(&prefix) {
                continue;
            }
            let record = decode_record(bytes.as_slice())?;
            if record.scope.address != *address {
                return Err(CredentialVaultError::ScopeMismatch {
                    expected: address.display_scope(),
                    actual: record.scope.address.display_scope(),
                });
            }
            if selected
                .as_ref()
                .is_none_or(|current: &CachedCredential| is_newer_record(&record, current))
            {
                selected = Some(record);
            }
        }
        Ok(selected)
    }

    fn load_for_scope(
        &self,
        scope: &CredentialVaultScope,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        scope.validate()?;
        let key = scope.storage_target_name();
        let entries = self
            .entries
            .lock()
            .map_err(|_| CredentialVaultError::Storage {
                operation: "memory_lock",
                code: 0,
            })?;
        let Some(bytes) = entries.get(&key) else {
            return Ok(None);
        };
        let record = decode_record(bytes.as_slice())?;
        if record.scope != *scope {
            return Err(CredentialVaultError::ScopeMismatch {
                expected: scope.address.display_scope(),
                actual: record.scope.address.display_scope(),
            });
        }
        Ok(Some(record))
    }

    fn save(
        &self,
        address: &CredentialVaultAddress,
        record: &VerifiedCredentialRecord,
    ) -> Result<(), CredentialVaultError> {
        address.validate()?;
        if record.0.scope.address != *address {
            return Err(CredentialVaultError::ScopeMismatch {
                expected: address.display_scope(),
                actual: record.0.scope.address.display_scope(),
            });
        }
        record.0.scope.validate()?;
        let bytes = encode_record(&record.0)?;
        self.entries
            .lock()
            .map_err(|_| CredentialVaultError::Storage {
                operation: "memory_lock",
                code: 0,
            })?
            .insert(record.0.scope.storage_target_name(), bytes);
        Ok(())
    }

    fn clear(&self, address: &CredentialVaultAddress) -> Result<(), CredentialVaultError> {
        address.validate()?;
        let prefix = format!("{}/", address.storage_target_name());
        self.entries
            .lock()
            .map_err(|_| CredentialVaultError::Storage {
                operation: "memory_lock",
                code: 0,
            })?
            .retain(|key, _| !key.starts_with(&prefix));
        Ok(())
    }
}

fn is_newer_record(candidate: &CachedCredential, current: &CachedCredential) -> bool {
    (candidate.server_time, candidate.authorization_revision)
        > (current.server_time, current.authorization_revision)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedCredentialVault;

impl CredentialVault for UnsupportedCredentialVault {
    fn load(
        &self,
        _address: &CredentialVaultAddress,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        Err(CredentialVaultError::SecureStorageUnavailable)
    }

    fn load_for_scope(
        &self,
        _scope: &CredentialVaultScope,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        Err(CredentialVaultError::SecureStorageUnavailable)
    }

    fn save(
        &self,
        _address: &CredentialVaultAddress,
        _record: &VerifiedCredentialRecord,
    ) -> Result<(), CredentialVaultError> {
        Err(CredentialVaultError::SecureStorageUnavailable)
    }

    fn clear(&self, _address: &CredentialVaultAddress) -> Result<(), CredentialVaultError> {
        Err(CredentialVaultError::SecureStorageUnavailable)
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsCredentialVault;

#[cfg(windows)]
impl WindowsCredentialVault {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(windows)]
impl CredentialVault for WindowsCredentialVault {
    fn load(
        &self,
        address: &CredentialVaultAddress,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        address.validate()?;
        windows::read(address)
    }

    fn load_for_scope(
        &self,
        scope: &CredentialVaultScope,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        scope.validate()?;
        windows::read_scope(scope)
    }

    fn save(
        &self,
        address: &CredentialVaultAddress,
        record: &VerifiedCredentialRecord,
    ) -> Result<(), CredentialVaultError> {
        address.validate()?;
        windows::write(address, &record.0)
    }

    fn clear(&self, address: &CredentialVaultAddress) -> Result<(), CredentialVaultError> {
        address.validate()?;
        windows::delete(address)
    }
}

pub fn default_credential_vault() -> Box<dyn CredentialVault> {
    #[cfg(windows)]
    {
        Box::new(WindowsCredentialVault::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedCredentialVault)
    }
}

fn encode_record(record: &CachedCredential) -> Result<ZeroizingBytes, CredentialVaultError> {
    record.validate()?;
    let mut output = ZeroizingBytes::with_capacity(1024);
    output.extend_from_slice(RECORD_MAGIC);
    write_text(&mut output, &record.scope.address.environment_id)?;
    write_text(&mut output, &record.scope.address.product_id)?;
    write_text(&mut output, &record.scope.address.software_id)?;
    write_text(&mut output, &record.scope.address.profile_id)?;
    write_text(&mut output, &record.scope.address.client_id)?;
    write_text(&mut output, &record.scope.authorization_id)?;
    write_text(&mut output, &record.scope.device_scope)?;
    write_text(&mut output, &record.scope.device_id)?;
    write_text(&mut output, &record.scope.installation_id)?;
    write_text(&mut output, &record.scope.config_version)?;
    record
        .credential
        .with_bytes(|bytes| write_bytes(&mut output, bytes))?;
    match &record.device_token {
        Some(token) => {
            output.push(1);
            token.with_bytes(|bytes| write_bytes(&mut output, bytes))?;
        }
        None => output.push(0),
    }
    output.extend_from_slice(&record.authorization_revision.to_le_bytes());
    output.extend_from_slice(&record.server_time.to_le_bytes());
    match record.expires_at {
        Some(expires_at) => {
            output.push(1);
            output.extend_from_slice(&expires_at.to_le_bytes());
        }
        None => output.push(0),
    }
    if output.len() > CREDENTIAL_VAULT_MAX_RECORD_BYTES {
        return Err(CredentialVaultError::InvalidRecord(
            "encoded record exceeds the bounded storage limit".to_string(),
        ));
    }
    Ok(output)
}

fn decode_record(input: &[u8]) -> Result<CachedCredential, CredentialVaultError> {
    if input.len() > CREDENTIAL_VAULT_MAX_RECORD_BYTES {
        return Err(CredentialVaultError::InvalidRecord(
            "encoded record exceeds the bounded storage limit".to_string(),
        ));
    }
    let mut cursor = Cursor::new(input);
    if cursor.read_exact(RECORD_MAGIC)? != RECORD_MAGIC {
        return Err(CredentialVaultError::InvalidRecord(
            "record magic or version is invalid".to_string(),
        ));
    }
    let environment_id = cursor.read_text("environment_id")?;
    let product_id = cursor.read_text("product_id")?;
    let software_id = cursor.read_text("software_id")?;
    let profile_id = cursor.read_text("profile_id")?;
    let client_id = cursor.read_text("client_id")?;
    let authorization_id = cursor.read_text("authorization_id")?;
    let device_scope = cursor.read_text("device_scope")?;
    let device_id = cursor.read_text("device_id")?;
    let installation_id = cursor.read_text("installation_id")?;
    let config_version = cursor.read_text("config_version")?;
    let credential = SecretValue::from_bytes(
        cursor.read_sensitive_bytes(CREDENTIAL_VAULT_MAX_SECRET_BYTES, "credential")?,
        CREDENTIAL_VAULT_MAX_SECRET_BYTES,
        "credential",
    )?;
    let device_token = match cursor.read_u8("device_token flag")? {
        0 => None,
        1 => Some(SecretValue::from_bytes(
            cursor.read_sensitive_bytes(CREDENTIAL_VAULT_MAX_DEVICE_TOKEN_BYTES, "device_token")?,
            CREDENTIAL_VAULT_MAX_DEVICE_TOKEN_BYTES,
            "device_token",
        )?),
        _ => {
            return Err(CredentialVaultError::InvalidRecord(
                "device token flag is invalid".to_string(),
            ));
        }
    };
    let authorization_revision = cursor.read_u64("authorization_revision")?;
    let server_time = cursor.read_u64("server_time")?;
    let expires_at = match cursor.read_u8("expiry flag")? {
        0 => None,
        1 => Some(cursor.read_u64("expires_at")?),
        _ => {
            return Err(CredentialVaultError::InvalidRecord(
                "expiry flag is invalid".to_string(),
            ));
        }
    };
    if !cursor.is_empty() {
        return Err(CredentialVaultError::InvalidRecord(
            "record contains trailing bytes".to_string(),
        ));
    }
    CachedCredential::new(
        CredentialVaultScope::new(
            CredentialVaultAddress::new(
                environment_id,
                product_id,
                software_id,
                profile_id,
                client_id,
            ),
            authorization_id,
            device_scope,
            device_id,
            installation_id,
            config_version,
        ),
        credential,
        device_token,
        authorization_revision,
        server_time,
        expires_at,
    )
}

fn write_text(output: &mut ZeroizingBytes, value: &str) -> Result<(), CredentialVaultError> {
    write_bytes(output, value.as_bytes())
}

fn write_bytes(output: &mut ZeroizingBytes, bytes: &[u8]) -> Result<(), CredentialVaultError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| CredentialVaultError::InvalidRecord("record field is too long".to_string()))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_exact(&mut self, expected: &[u8]) -> Result<Vec<u8>, CredentialVaultError> {
        let bytes = self.read_raw(expected.len(), "record header")?;
        Ok(bytes.to_vec())
    }

    fn read_bytes(
        &mut self,
        max_bytes: usize,
        field: &'static str,
    ) -> Result<Vec<u8>, CredentialVaultError> {
        let length = self.read_u32(field)? as usize;
        if length > max_bytes {
            return Err(CredentialVaultError::InvalidRecord(format!(
                "{field} exceeds the bounded storage limit"
            )));
        }
        Ok(self.read_raw(length, field)?.to_vec())
    }

    fn read_sensitive_bytes(
        &mut self,
        max_bytes: usize,
        field: &'static str,
    ) -> Result<ZeroizingBytes, CredentialVaultError> {
        let length = self.read_u32(field)? as usize;
        if length > max_bytes {
            return Err(CredentialVaultError::InvalidRecord(format!(
                "{field} exceeds the bounded storage limit"
            )));
        }
        let mut bytes = ZeroizingBytes::with_capacity(length);
        bytes.extend_from_slice(self.read_raw(length, field)?);
        Ok(bytes)
    }

    fn read_text(&mut self, field: &'static str) -> Result<String, CredentialVaultError> {
        String::from_utf8(self.read_bytes(2048, field)?)
            .map_err(|_| CredentialVaultError::InvalidRecord(format!("{field} is not valid UTF-8")))
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, CredentialVaultError> {
        self.read_raw(1, field).map(|bytes| bytes[0])
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, CredentialVaultError> {
        let bytes = self.read_raw(4, field)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("bounded read has four bytes"),
        ))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, CredentialVaultError> {
        let bytes = self.read_raw(8, field)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("bounded read has eight bytes"),
        ))
    }

    fn read_raw(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], CredentialVaultError> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            CredentialVaultError::InvalidRecord(format!("{field} length overflows"))
        })?;
        if end > self.input.len() {
            return Err(CredentialVaultError::InvalidRecord(format!(
                "record ends before {field}"
            )));
        }
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::null_mut;

    type Bool = i32;
    type Dword = u32;

    const CRED_TYPE_GENERIC: Dword = 1;
    const CRED_PERSIST_LOCAL_MACHINE: Dword = 2;

    #[repr(C)]
    struct FileTime {
        low: Dword,
        high: Dword,
    }

    #[repr(C)]
    struct CredentialW {
        flags: Dword,
        type_: Dword,
        target_name: *mut u16,
        comment: *mut u16,
        last_written: FileTime,
        credential_blob_size: Dword,
        credential_blob: *mut u8,
        persist: Dword,
        attribute_count: Dword,
        attributes: *mut c_void,
        target_alias: *mut u16,
        user_name: *mut u16,
    }

    #[link(name = "Advapi32")]
    extern "system" {
        fn CredWriteW(credential: *const CredentialW, flags: Dword) -> Bool;
        fn CredReadW(
            target_name: *const u16,
            type_: Dword,
            reserved: Dword,
            credential: *mut *mut CredentialW,
        ) -> Bool;
        fn CredEnumerateW(
            filter: *const u16,
            flags: Dword,
            count: *mut Dword,
            credentials: *mut *mut *mut CredentialW,
        ) -> Bool;
        fn CredDeleteW(target_name: *const u16, type_: Dword, flags: Dword) -> Bool;
        fn CredFree(buffer: *mut c_void);
    }

    pub(super) fn write(
        address: &CredentialVaultAddress,
        record: &CachedCredential,
    ) -> Result<(), CredentialVaultError> {
        if record.scope.address != *address {
            return Err(CredentialVaultError::ScopeMismatch {
                expected: address.display_scope(),
                actual: record.scope.address.display_scope(),
            });
        }
        record.scope.validate()?;
        let blob = encode_record(record)?;
        let target = wide(record.scope.storage_target_name());
        let credential = CredentialW {
            flags: 0,
            type_: CRED_TYPE_GENERIC,
            target_name: target.as_ptr() as *mut u16,
            comment: null_mut(),
            last_written: FileTime { low: 0, high: 0 },
            credential_blob_size: blob.len() as Dword,
            credential_blob: blob.as_ptr() as *mut u8,
            persist: CRED_PERSIST_LOCAL_MACHINE,
            attribute_count: 0,
            attributes: null_mut(),
            target_alias: null_mut(),
            user_name: null_mut(),
        };
        let success = unsafe { CredWriteW(&credential, 0) };
        if success == 0 {
            return Err(platform_error("CredWriteW"));
        }
        Ok(())
    }

    pub(super) fn read(
        address: &CredentialVaultAddress,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        address.validate()?;
        let filter = wide(format!("{}/*", address.storage_target_name()));
        enumerate_records(address, &filter)
    }

    pub(super) fn read_scope(
        scope: &CredentialVaultScope,
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        let record = read_target(&scope.storage_target_name())?;
        let Some(record) = record else {
            return Ok(None);
        };
        if record.scope != *scope {
            return Err(CredentialVaultError::ScopeMismatch {
                expected: scope.address.display_scope(),
                actual: record.scope.address.display_scope(),
            });
        }
        Ok(Some(record))
    }

    fn read_target(target_name: &str) -> Result<Option<CachedCredential>, CredentialVaultError> {
        let target = wide(target_name.to_string());
        let mut credential: *mut CredentialW = null_mut();
        let success = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
        if success == 0 {
            let code = last_error_code();
            if code == CREDENTIAL_MANAGER_NOT_FOUND {
                return Ok(None);
            }
            return Err(CredentialVaultError::Storage {
                operation: "CredReadW",
                code,
            });
        }
        if credential.is_null() {
            return Err(CredentialVaultError::InvalidRecord(
                "CredReadW returned a null credential".to_string(),
            ));
        }
        let decoded = unsafe { decode_credential(credential) };
        unsafe { CredFree(credential as *mut c_void) };
        decoded.map(Some)
    }

    pub(super) fn delete(address: &CredentialVaultAddress) -> Result<(), CredentialVaultError> {
        address.validate()?;
        for target_name in enumerate_target_names(address)? {
            delete_target(&target_name)?;
        }
        Ok(())
    }

    fn enumerate_records(
        address: &CredentialVaultAddress,
        filter: &[u16],
    ) -> Result<Option<CachedCredential>, CredentialVaultError> {
        let mut count = 0;
        let mut credentials: *mut *mut CredentialW = null_mut();
        let success = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) };
        if success == 0 {
            let code = last_error_code();
            if code == CREDENTIAL_MANAGER_NOT_FOUND {
                return Ok(None);
            }
            return Err(CredentialVaultError::Storage {
                operation: "CredEnumerateW",
                code,
            });
        }
        if count == 0 {
            if !credentials.is_null() {
                unsafe { CredFree(credentials as *mut c_void) };
            }
            return Ok(None);
        }
        if credentials.is_null() {
            return Err(CredentialVaultError::InvalidRecord(
                "CredEnumerateW returned a null credential array".to_string(),
            ));
        }
        let decoded = unsafe {
            let values = std::slice::from_raw_parts(credentials, count as usize);
            let result = (|| {
                let mut selected = None;
                for credential in values {
                    let record = decode_credential(*credential)?;
                    if record.scope.address != *address {
                        return Err(CredentialVaultError::ScopeMismatch {
                            expected: address.display_scope(),
                            actual: record.scope.address.display_scope(),
                        });
                    }
                    if selected
                        .as_ref()
                        .is_none_or(|current: &CachedCredential| is_newer_record(&record, current))
                    {
                        selected = Some(record);
                    }
                }
                Ok(selected)
            })();
            result
        };
        unsafe { CredFree(credentials as *mut c_void) };
        decoded
    }

    fn enumerate_target_names(
        address: &CredentialVaultAddress,
    ) -> Result<Vec<String>, CredentialVaultError> {
        let filter = wide(format!("{}/*", address.storage_target_name()));
        let mut count = 0;
        let mut credentials: *mut *mut CredentialW = null_mut();
        let success = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) };
        if success == 0 {
            let code = last_error_code();
            if code == CREDENTIAL_MANAGER_NOT_FOUND {
                return Ok(Vec::new());
            }
            return Err(CredentialVaultError::Storage {
                operation: "CredEnumerateW",
                code,
            });
        }
        if count == 0 {
            if !credentials.is_null() {
                unsafe { CredFree(credentials as *mut c_void) };
            }
            return Ok(Vec::new());
        }
        if credentials.is_null() {
            return Err(CredentialVaultError::InvalidRecord(
                "CredEnumerateW returned a null credential array".to_string(),
            ));
        }
        let names = unsafe {
            let values = std::slice::from_raw_parts(credentials, count as usize);
            let result = (|| {
                let mut names = Vec::with_capacity(values.len());
                for credential in values {
                    if credential.is_null() {
                        return Err(CredentialVaultError::InvalidRecord(
                            "CredEnumerateW returned a null credential".to_string(),
                        ));
                    }
                    let name = (*(*credential)).target_name;
                    if name.is_null() {
                        return Err(CredentialVaultError::InvalidRecord(
                            "credential manager returned a null target name".to_string(),
                        ));
                    }
                    names.push(read_wide_string(name)?);
                }
                Ok(names)
            })();
            result
        };
        unsafe { CredFree(credentials as *mut c_void) };
        names
    }

    fn delete_target(target_name: &str) -> Result<(), CredentialVaultError> {
        let target = wide(target_name.to_string());
        let success = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if success == 0 {
            let code = last_error_code();
            if code == CREDENTIAL_MANAGER_NOT_FOUND {
                return Ok(());
            }
            return Err(CredentialVaultError::Storage {
                operation: "CredDeleteW",
                code,
            });
        }
        Ok(())
    }

    unsafe fn decode_credential(
        credential: *mut CredentialW,
    ) -> Result<CachedCredential, CredentialVaultError> {
        if credential.is_null() {
            return Err(CredentialVaultError::InvalidRecord(
                "Credential Manager returned a null credential".to_string(),
            ));
        }
        let value = &*credential;
        let size = value.credential_blob_size as usize;
        if size == 0 || size > CREDENTIAL_VAULT_MAX_RECORD_BYTES || value.credential_blob.is_null()
        {
            return Err(CredentialVaultError::InvalidRecord(
                "credential manager returned an invalid blob".to_string(),
            ));
        }
        let mut bytes = ZeroizingBytes::with_capacity(size);
        bytes.extend_from_slice(std::slice::from_raw_parts(value.credential_blob, size));
        let decoded = decode_record(bytes.as_slice());
        zeroize_bytes(std::slice::from_raw_parts_mut(value.credential_blob, size));
        decoded
    }

    unsafe fn read_wide_string(pointer: *const u16) -> Result<String, CredentialVaultError> {
        const MAX_TARGET_NAME_UNITS: usize = 2048;
        if pointer.is_null() {
            return Err(CredentialVaultError::InvalidRecord(
                "credential manager returned a null target name".to_string(),
            ));
        }
        let mut length = 0;
        while length < MAX_TARGET_NAME_UNITS {
            if *pointer.add(length) == 0 {
                let units = std::slice::from_raw_parts(pointer, length);
                return String::from_utf16(units).map_err(|_| {
                    CredentialVaultError::InvalidRecord(
                        "credential manager returned an invalid target name".to_string(),
                    )
                });
            }
            length += 1;
        }
        Err(CredentialVaultError::InvalidRecord(
            "credential manager target name is too long".to_string(),
        ))
    }

    fn wide(value: String) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error_code() -> u32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or_default() as u32
    }

    fn platform_error(operation: &'static str) -> CredentialVaultError {
        CredentialVaultError::Storage {
            operation,
            code: last_error_code(),
        }
    }
}
