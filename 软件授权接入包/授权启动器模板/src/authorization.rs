//! Product-neutral authorization.v1 and authorization-a-core.v1 contracts.
//!
//! The cloud response is the authorization fact. Authorization A may validate
//! it, cache it, and change the transport envelope for the local core, but it
//! must not change the identity, decision, timestamps, revision, or module
//! ownership. Cryptographic verification is deliberately represented by a
//! trait; this crate only provides a test-only verifier and never pretends that
//! an opaque fixture comparison is production cryptography.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use super::codec::{
    ensure_known_fields, json_array, json_object, json_required, json_required_string, json_string,
    serialize_json, JsonParser, JsonValue,
};
use super::contract::{
    contains_request_only_field, is_sensitive_parameter_key, looks_like_raw_credential,
    validate_identifier, validate_opaque_identifier, validate_parameter_key, validate_short_text,
    AuthorizationSnapshot, ContractError, LicenseState, ModuleEnvelope, MAX_CAPABILITIES,
    MAX_MODULE_PAYLOAD_ENTRIES, MAX_SNAPSHOT_MODULES,
};
use super::profile::ProductManifest;

pub const AUTHORIZATION_CLOUD_PROTOCOL_VERSION: &str = "authorization.v1";
pub const AUTHORIZATION_A_CORE_PROTOCOL_VERSION: &str = "authorization-a-core.v1";
pub const AUTHORIZATION_CLOUD_CONTRACT_VERSION: &str = "authorization.v1";
pub const AUTHORIZATION_A_CORE_CONTRACT_VERSION: &str = "authorization-a-core.v1";
pub const AUTHORIZATION_CONFIG_VERSION_MAX_CHARS: usize = 64;
pub const AUTHORIZATION_TIME_ZONE: &str = "Asia/Shanghai";
pub const AUTHORIZATION_INTEGRITY_ALGORITHM: &str = "ed25519";
pub const AUTHORIZATION_INTEGRITY_CANONICALIZATION: &str = "JCS-RFC8785";
pub const AUTHORIZATION_INTEGRITY_ORIGIN: &str = "authorization-a";
pub const AUTHORIZATION_INTEGRITY_AUDIENCE: &str = "authorization-a-core";
pub const AUTHORIZATION_DEVICE_SCOPE_SCHEMA_VERSION: &str = "device-scope.v1";
pub const DEVICE_PUBLIC_KEY_BYTES: usize = 32;
pub const DEVICE_PROOF_BYTES: usize = 64;
pub const DEVICE_SCOPE_MAX_SCOPE_CHARS: usize = 32;
pub const DEVICE_SCOPE_MAX_DEVICE_ID_CHARS: usize = 64;
pub const DEVICE_SCOPE_MAX_INSTALLATION_ID_CHARS: usize = 128;
pub const MOCK_INTEGRITY_ALGORITHM: &str = "mock-v1";
pub const MOCK_INTEGRITY_CANONICALIZATION: &str = "test-only-canonical-v1";
pub const MAX_REQUEST_IDEMPOTENCY_RECORDS: usize = 1024;

/// A server-confirmed device scope claim. The request still uses the legacy
/// string scope; this object is only accepted on the central response and is
/// preserved when A re-envelopes the response for the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredDeviceScopeV1 {
    pub scope: String,
    pub device_id: Option<String>,
    pub installation_id: Option<String>,
}

impl StructuredDeviceScopeV1 {
    pub fn new(
        scope: impl Into<String>,
        device_id: Option<impl Into<String>>,
        installation_id: Option<impl Into<String>>,
    ) -> Self {
        Self {
            scope: scope.into(),
            device_id: device_id.map(Into::into),
            installation_id: installation_id.map(Into::into),
        }
    }

    pub fn current_device(
        device_id: impl Into<String>,
        installation_id: Option<impl Into<String>>,
    ) -> Self {
        Self::new("current_device", Some(device_id), installation_id)
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        validate_trimmed_opaque_identifier(
            &self.scope,
            "device_scope.scope",
            DEVICE_SCOPE_MAX_SCOPE_CHARS,
        )
        .map_err(AuthorizationError::InvalidRequest)?;
        if self.scope != "current_device" {
            return Err(AuthorizationError::InvalidRequest(
                "device_scope.scope must be current_device".to_string(),
            ));
        }
        if let Some(device_id) = &self.device_id {
            validate_trimmed_opaque_identifier(
                device_id,
                "device_scope.device_id",
                DEVICE_SCOPE_MAX_DEVICE_ID_CHARS,
            )
            .map_err(AuthorizationError::InvalidRequest)?;
        }
        if let Some(installation_id) = &self.installation_id {
            validate_trimmed_opaque_identifier(
                installation_id,
                "device_scope.installation_id",
                DEVICE_SCOPE_MAX_INSTALLATION_ID_CHARS,
            )
            .map_err(AuthorizationError::InvalidRequest)?;
        }
        Ok(())
    }

    pub fn validate_for_authorization(&self) -> Result<(), AuthorizationError> {
        self.validate()?;
        if self.device_id.is_none() || self.installation_id.is_none() {
            return Err(AuthorizationError::InvalidRequest(
                "device_scope.device_id and installation_id must be confirmed before authorization"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        serialize_json(&structured_device_scope_to_json_value(self))
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        let value = JsonParser::new(input).parse()?;
        structured_device_scope_from_json_value(value, "device_scope")
    }
}

/// Explicit wire compatibility for a response scope. A legacy string is
/// retained for old consumers; a structured value is never silently reduced
/// to a client-supplied credential or another product-specific field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceScopeV1 {
    Legacy(String),
    Structured(StructuredDeviceScopeV1),
}

impl DeviceScopeV1 {
    pub fn legacy(value: impl Into<String>) -> Self {
        Self::Legacy(value.into())
    }

    pub fn structured(value: StructuredDeviceScopeV1) -> Self {
        Self::Structured(value)
    }

    pub fn legacy_scope(&self) -> Option<&str> {
        match self {
            Self::Legacy(value) => Some(value),
            Self::Structured(_) => None,
        }
    }

    pub fn structured_claim(&self) -> Option<&StructuredDeviceScopeV1> {
        match self {
            Self::Legacy(_) => None,
            Self::Structured(value) => Some(value),
        }
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        match self {
            Self::Legacy(value) => validate_opaque_identifier(value, "device_scope")
                .map_err(AuthorizationError::InvalidRequest),
            Self::Structured(value) => value.validate(),
        }
    }

    pub fn to_json(&self) -> String {
        serialize_json(&device_scope_to_json_value(self))
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        let value = JsonParser::new(input).parse()?;
        device_scope_from_json_value(value, "device_scope")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationIdentity {
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub device_scope: String,
    pub device_id: String,
}

impl AuthorizationIdentity {
    pub fn new(
        software_id: impl Into<String>,
        profile_id: impl Into<String>,
        client_id: impl Into<String>,
        device_scope: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Self {
        Self {
            software_id: software_id.into(),
            profile_id: profile_id.into(),
            client_id: client_id.into(),
            device_scope: device_scope.into(),
            device_id: device_id.into(),
        }
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        validate_identifier(&self.software_id, "software_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_identifier(&self.profile_id, "profile_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_opaque_identifier(&self.client_id, "client_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_opaque_identifier(&self.device_scope, "device_scope")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_opaque_identifier(&self.device_id, "device_id")
            .map_err(AuthorizationError::InvalidRequest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationBinding {
    pub product_id: String,
    pub identity: AuthorizationIdentity,
}

impl AuthorizationBinding {
    pub fn new(product_id: impl Into<String>, identity: AuthorizationIdentity) -> Self {
        Self {
            product_id: product_id.into(),
            identity,
        }
    }

    pub fn validate_for(&self, manifest: &ProductManifest) -> Result<(), AuthorizationError> {
        manifest.validate()?;
        validate_identifier(&self.product_id, "binding.product_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        if self.product_id != manifest.product_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "product_id".to_string(),
                expected: manifest.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        self.identity.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequestV1 {
    pub protocol: String,
    pub schema_version: String,
    pub contract_version: String,
    pub request_id: String,
    pub operation: String,
    pub product_id: String,
    pub identity: AuthorizationIdentity,
    pub target: String,
    pub arch: String,
    pub channel: String,
    pub config_version: String,
    pub known_authorization_revision: Option<u64>,
    /// Central public-request material. These fields are never copied into a
    /// response or the A-to-core envelope.
    pub device_public_key: String,
    pub device_proof: Option<String>,
    pub installation_id: String,
    pub client_version: String,
    pub nonce: String,
}

impl AuthorizationRequestV1 {
    pub fn new(
        request_id: impl Into<String>,
        binding: &AuthorizationBinding,
        config_version: impl Into<String>,
        known_authorization_revision: Option<u64>,
    ) -> Self {
        Self {
            protocol: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
            schema_version: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
            contract_version: AUTHORIZATION_CLOUD_CONTRACT_VERSION.to_string(),
            request_id: request_id.into(),
            operation: "activate".to_string(),
            product_id: binding.product_id.clone(),
            identity: binding.identity.clone(),
            target: String::new(),
            arch: String::new(),
            channel: String::new(),
            config_version: config_version.into(),
            known_authorization_revision,
            device_public_key: String::new(),
            device_proof: None,
            installation_id: String::new(),
            client_version: String::new(),
            nonce: String::new(),
        }
    }

    pub fn with_target_arch_channel(
        mut self,
        target: impl Into<String>,
        arch: impl Into<String>,
        channel: impl Into<String>,
    ) -> Self {
        self.target = target.into();
        self.arch = arch.into();
        self.channel = channel.into();
        self
    }

    pub fn with_platform_credentials(
        mut self,
        device_public_key: impl Into<String>,
        device_proof: Option<impl Into<String>>,
        installation_id: impl Into<String>,
        client_version: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        self.device_public_key = device_public_key.into().trim().to_string();
        self.device_proof = device_proof.map(|value| value.into().trim().to_string());
        self.installation_id = installation_id.into().trim().to_string();
        self.client_version = client_version.into().trim().to_string();
        self.nonce = nonce.into().trim().to_string();
        self
    }

    pub fn validate_for_platform(&self) -> Result<(), AuthorizationError> {
        self.validate_for_platform_with_proof_required(false)
    }

    pub fn validate_for_platform_with_proof_required(
        &self,
        proof_required: bool,
    ) -> Result<(), AuthorizationError> {
        self.validate()?;
        if !matches!(
            self.operation.as_str(),
            "activate" | "verify" | "deactivate"
        ) {
            return Err(AuthorizationError::InvalidRequest(format!(
                "unsupported public authorization operation: {}",
                self.operation
            )));
        }
        validate_base64url_bytes(
            &self.device_public_key,
            DEVICE_PUBLIC_KEY_BYTES,
            "device_public_key",
            256,
        )
        .map_err(AuthorizationError::InvalidRequest)?;
        match &self.device_proof {
            Some(proof) => validate_base64url_bytes(proof, DEVICE_PROOF_BYTES, "device_proof", 256)
                .map_err(AuthorizationError::InvalidRequest)?,
            None if proof_required => {
                return Err(AuthorizationError::DeviceProofRequired);
            }
            None => {}
        }
        validate_trimmed_opaque_identifier(&self.installation_id, "installation_id", 128)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_trimmed_opaque_identifier(&self.client_version, "client_version", 64)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_nonce(&self.nonce).map_err(AuthorizationError::InvalidRequest)
    }

    pub fn to_json(&self) -> String {
        serialize_json(&authorization_request_to_json_value(self))
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        let value = JsonParser::new(input).parse()?;
        authorization_request_from_json_value(value)
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        if self.protocol != AUTHORIZATION_CLOUD_PROTOCOL_VERSION {
            return Err(AuthorizationError::ProtocolMismatch {
                expected: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
                actual: self.protocol.clone(),
            });
        }
        if self.schema_version != AUTHORIZATION_CLOUD_PROTOCOL_VERSION {
            return Err(AuthorizationError::ProtocolMismatch {
                expected: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.contract_version != AUTHORIZATION_CLOUD_CONTRACT_VERSION {
            return Err(AuthorizationError::ContractMismatch {
                expected: AUTHORIZATION_CLOUD_CONTRACT_VERSION.to_string(),
                actual: self.contract_version.clone(),
            });
        }
        validate_opaque_identifier(&self.request_id, "request_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_identifier(&self.operation, "operation", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_identifier(&self.product_id, "product_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.target, "target").map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.arch, "arch").map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.channel, "channel")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_config_version(&self.config_version, "config_version")
            .map_err(AuthorizationError::InvalidRequest)?;
        if !self.device_public_key.is_empty() {
            validate_base64url_bytes(
                &self.device_public_key,
                DEVICE_PUBLIC_KEY_BYTES,
                "device_public_key",
                256,
            )
            .map_err(AuthorizationError::InvalidRequest)?;
        }
        if let Some(device_proof) = &self.device_proof {
            validate_base64url_bytes(device_proof, DEVICE_PROOF_BYTES, "device_proof", 256)
                .map_err(AuthorizationError::InvalidRequest)?;
        }
        if !self.installation_id.is_empty() {
            validate_trimmed_opaque_identifier(&self.installation_id, "installation_id", 128)
                .map_err(AuthorizationError::InvalidRequest)?;
        }
        if !self.client_version.is_empty() {
            validate_trimmed_opaque_identifier(&self.client_version, "client_version", 64)
                .map_err(AuthorizationError::InvalidRequest)?;
        }
        if !self.nonce.is_empty() {
            validate_nonce(&self.nonce).map_err(AuthorizationError::InvalidRequest)?;
        }
        self.identity.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityProof {
    pub algorithm: String,
    pub key_id: String,
    pub canonicalization: String,
    pub signature: String,
    pub origin: String,
    pub audience: String,
}

impl IntegrityProof {
    pub fn new(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        canonicalization: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            key_id: key_id.into(),
            canonicalization: canonicalization.into(),
            signature: signature.into(),
            origin: "unspecified-origin".to_string(),
            audience: "unspecified-audience".to_string(),
        }
    }

    pub fn with_origin_audience(
        mut self,
        origin: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        self.origin = origin.into();
        self.audience = audience.into();
        self
    }

    pub fn mock(key_id: impl Into<String>, signature: impl Into<String>) -> Self {
        Self::new(
            MOCK_INTEGRITY_ALGORITHM,
            key_id,
            MOCK_INTEGRITY_CANONICALIZATION,
            signature,
        )
        .with_origin_audience("mock-central", AUTHORIZATION_A_CORE_PROTOCOL_VERSION)
    }

    fn validate_shape(&self) -> Result<(), IntegrityError> {
        if self.algorithm.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.canonicalization.trim().is_empty()
            || self.signature.trim().is_empty()
        {
            return Err(IntegrityError::Missing);
        }
        for (field, value) in [
            ("integrity.algorithm", &self.algorithm),
            ("integrity.key_id", &self.key_id),
            ("integrity.canonicalization", &self.canonicalization),
            ("integrity.signature", &self.signature),
            ("integrity.origin", &self.origin),
            ("integrity.audience", &self.audience),
        ] {
            validate_short_text(value, field).map_err(IntegrityError::InvalidShape)?;
        }
        Ok(())
    }

    pub fn validate_for_core_contract(&self) -> Result<(), IntegrityError> {
        self.validate_shape()?;
        if self.algorithm != AUTHORIZATION_INTEGRITY_ALGORITHM {
            return Err(IntegrityError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        if self.canonicalization != AUTHORIZATION_INTEGRITY_CANONICALIZATION {
            return Err(IntegrityError::InvalidShape(
                "authorization integrity canonicalization is not JCS-RFC8785".to_string(),
            ));
        }
        if self.origin != AUTHORIZATION_INTEGRITY_ORIGIN
            || self.audience != AUTHORIZATION_INTEGRITY_AUDIENCE
        {
            return Err(IntegrityError::InvalidShape(
                "authorization integrity origin/audience do not match the A-to-core contract"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_cloud_contract(&self) -> Result<(), IntegrityError> {
        self.validate_shape()?;
        if self.algorithm != AUTHORIZATION_INTEGRITY_ALGORITHM {
            return Err(IntegrityError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        if self.canonicalization != AUTHORIZATION_INTEGRITY_CANONICALIZATION {
            return Err(IntegrityError::InvalidShape(
                "authorization integrity canonicalization is not JCS-RFC8785".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    Missing,
    InvalidShape(String),
    UnsupportedAlgorithm(String),
    UnknownKey(String),
    InvalidSignature,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "integrity proof is missing"),
            Self::InvalidShape(message) => write!(f, "integrity proof is malformed: {message}"),
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "integrity algorithm is unsupported: {algorithm}")
            }
            Self::UnknownKey(key_id) => write!(f, "integrity key is unknown: {key_id}"),
            Self::InvalidSignature => write!(f, "integrity signature is invalid"),
        }
    }
}

impl std::error::Error for IntegrityError {}

pub trait IntegrityVerifier {
    fn verify(&self, proof: &IntegrityProof, canonical_payload: &str)
        -> Result<(), IntegrityError>;
}

/// A signer seam for the second trust boundary. The central platform signs
/// the cloud response; A verifies that fact and then signs a separate local
/// `authorization-a-core.v1` response for the core. This trait has no key
/// storage or cryptographic implementation in the reference crate.
pub trait IntegritySigner: IntegrityVerifier {
    fn integrity_template(&self) -> IntegrityProof;

    fn sign(&self, canonical_payload: &str) -> Result<IntegrityProof, IntegrityError>;
}

/// A deterministic fixture verifier. It is deliberately not a cryptographic
/// implementation and must never be used as a production trust mechanism.
#[derive(Debug, Clone, Default)]
pub struct MockIntegrityVerifier {
    accepted: BTreeMap<(String, String, String, String), (String, String)>,
}

impl MockIntegrityVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(
        &mut self,
        proof: &IntegrityProof,
        canonical_payload: impl Into<String>,
    ) -> Result<(), IntegrityError> {
        proof.validate_shape()?;
        if proof.algorithm != MOCK_INTEGRITY_ALGORITHM
            && proof.algorithm != AUTHORIZATION_INTEGRITY_ALGORITHM
        {
            return Err(IntegrityError::UnsupportedAlgorithm(
                proof.algorithm.clone(),
            ));
        }
        self.accepted.insert(
            (
                proof.algorithm.clone(),
                proof.key_id.clone(),
                proof.origin.clone(),
                proof.audience.clone(),
            ),
            (canonical_payload.into(), proof.signature.clone()),
        );
        Ok(())
    }
}

impl IntegrityVerifier for MockIntegrityVerifier {
    fn verify(
        &self,
        proof: &IntegrityProof,
        canonical_payload: &str,
    ) -> Result<(), IntegrityError> {
        proof.validate_shape()?;
        if proof.algorithm != MOCK_INTEGRITY_ALGORITHM
            && proof.algorithm != AUTHORIZATION_INTEGRITY_ALGORITHM
        {
            return Err(IntegrityError::UnsupportedAlgorithm(
                proof.algorithm.clone(),
            ));
        }
        let expected = self
            .accepted
            .get(&(
                proof.algorithm.clone(),
                proof.key_id.clone(),
                proof.origin.clone(),
                proof.audience.clone(),
            ))
            .ok_or_else(|| IntegrityError::UnknownKey(proof.key_id.clone()))?;
        if expected.0 != canonical_payload || expected.1 != proof.signature {
            return Err(IntegrityError::InvalidSignature);
        }
        Ok(())
    }
}

/// Fixture-only signer for testing the two-signing-boundary flow. It returns
/// a configured proof and deliberately performs no cryptographic operation.
#[derive(Debug, Clone)]
pub struct MockIntegritySigner {
    template: IntegrityProof,
    signed_proof: IntegrityProof,
    last_signed_payload: RefCell<Option<String>>,
}

impl MockIntegritySigner {
    pub fn new(key_id: impl Into<String>, signature: impl Into<String>) -> Self {
        let template = IntegrityProof::new(
            AUTHORIZATION_INTEGRITY_ALGORITHM,
            key_id,
            AUTHORIZATION_INTEGRITY_CANONICALIZATION,
            "fixture-signature-placeholder",
        )
        .with_origin_audience(
            AUTHORIZATION_INTEGRITY_ORIGIN,
            AUTHORIZATION_INTEGRITY_AUDIENCE,
        );
        let signed_proof = IntegrityProof {
            signature: signature.into(),
            ..template.clone()
        };
        Self {
            template,
            signed_proof,
            last_signed_payload: RefCell::new(None),
        }
    }
}

impl IntegritySigner for MockIntegritySigner {
    fn integrity_template(&self) -> IntegrityProof {
        self.template.clone()
    }

    fn sign(&self, canonical_payload: &str) -> Result<IntegrityProof, IntegrityError> {
        if canonical_payload.trim().is_empty() {
            return Err(IntegrityError::InvalidShape(
                "canonical payload cannot be empty".to_string(),
            ));
        }
        self.last_signed_payload
            .replace(Some(canonical_payload.to_string()));
        Ok(self.signed_proof.clone())
    }
}

impl IntegrityVerifier for MockIntegritySigner {
    fn verify(
        &self,
        proof: &IntegrityProof,
        canonical_payload: &str,
    ) -> Result<(), IntegrityError> {
        proof.validate_for_core_contract()?;
        if proof != &self.signed_proof
            || self.last_signed_payload.borrow().as_deref() != Some(canonical_payload)
        {
            return Err(IntegrityError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationErrorCode {
    /// Local A-to-core denial used when a central result cannot be treated as
    /// an authorization fact (for example a stale idempotency replay or the
    /// platform's deactivate-only `unbound` compatibility response).
    AuthInvalid,
    InvalidRequest,
    ResponseSchemaInvalid,
    MissingRequiredField,
    Unauthorized,
    Forbidden,
    SoftwareMismatch,
    ProfileMismatch,
    ContractVersionUnsupported,
    LicenseNotFound,
    LicenseNotActive,
    LicenseExpired,
    AuthorizationRevoked,
    AuthorizationBlocked,
    DeviceScopeMismatch,
    DeviceNotBound,
    DeviceLimitReached,
    DeviceProofRequired,
    DeviceProofInvalid,
    ReplayDetected,
    SignatureInvalid,
    KeyUnknown,
    TimeRollbackDetected,
    TimeSkew,
    VersionBlocked,
    RiskBlocked,
    AdapterUnsupported,
    RateLimited,
    ServiceTemporarilyUnavailable,
    IdempotencyConflict,
    InternalError,
    // Rust-side compatibility names. Their wire values are the stable
    // product-neutral codes above.
    ProtocolMismatch,
    ContractMismatch,
    BindingMismatch,
    IntegrityMissing,
    IntegrityInvalid,
    IntegrityUnknownKey,
    ServerTimeRollback,
    RequestConflict,
    StaleRevision,
    Unavailable,
}

impl AuthorizationErrorCode {
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "AUTH_INVALID" => Self::AuthInvalid,
            "INVALID_REQUEST" => Self::InvalidRequest,
            "RESPONSE_SCHEMA_INVALID" => Self::ResponseSchemaInvalid,
            "MISSING_REQUIRED_FIELD" => Self::MissingRequiredField,
            "UNAUTHORIZED" => Self::Unauthorized,
            "FORBIDDEN" => Self::Forbidden,
            "SOFTWARE_MISMATCH" => Self::SoftwareMismatch,
            "PROFILE_MISMATCH" => Self::ProfileMismatch,
            "CONTRACT_VERSION_UNSUPPORTED" => Self::ContractVersionUnsupported,
            "LICENSE_NOT_FOUND" => Self::LicenseNotFound,
            "LICENSE_NOT_ACTIVE" => Self::LicenseNotActive,
            "LICENSE_EXPIRED" => Self::LicenseExpired,
            "AUTHORIZATION_REVOKED" => Self::AuthorizationRevoked,
            "AUTHORIZATION_BLOCKED" => Self::AuthorizationBlocked,
            "DEVICE_SCOPE_MISMATCH" => Self::DeviceScopeMismatch,
            "DEVICE_NOT_BOUND" => Self::DeviceNotBound,
            "DEVICE_LIMIT_REACHED" => Self::DeviceLimitReached,
            "DEVICE_PROOF_REQUIRED" => Self::DeviceProofRequired,
            "DEVICE_PROOF_INVALID" => Self::DeviceProofInvalid,
            "REPLAY_DETECTED" => Self::ReplayDetected,
            "SIGNATURE_INVALID" => Self::SignatureInvalid,
            "KEY_UNKNOWN" => Self::KeyUnknown,
            "TIME_ROLLBACK_DETECTED" => Self::TimeRollbackDetected,
            "TIME_SKEW" => Self::TimeSkew,
            "VERSION_BLOCKED" => Self::VersionBlocked,
            "RISK_BLOCKED" => Self::RiskBlocked,
            "ADAPTER_UNSUPPORTED" => Self::AdapterUnsupported,
            "RATE_LIMITED" => Self::RateLimited,
            "SERVICE_TEMPORARILY_UNAVAILABLE" => Self::ServiceTemporarilyUnavailable,
            "IDEMPOTENCY_CONFLICT" => Self::IdempotencyConflict,
            "INTERNAL_ERROR" => Self::InternalError,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthInvalid => "AUTH_INVALID",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ResponseSchemaInvalid => "RESPONSE_SCHEMA_INVALID",
            Self::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::SoftwareMismatch => "SOFTWARE_MISMATCH",
            Self::ProfileMismatch => "PROFILE_MISMATCH",
            Self::ContractVersionUnsupported | Self::ProtocolMismatch | Self::ContractMismatch => {
                "CONTRACT_VERSION_UNSUPPORTED"
            }
            Self::LicenseNotFound => "LICENSE_NOT_FOUND",
            Self::LicenseNotActive => "LICENSE_NOT_ACTIVE",
            Self::LicenseExpired => "LICENSE_EXPIRED",
            Self::AuthorizationRevoked => "AUTHORIZATION_REVOKED",
            Self::AuthorizationBlocked => "AUTHORIZATION_BLOCKED",
            Self::DeviceScopeMismatch => "DEVICE_SCOPE_MISMATCH",
            Self::DeviceNotBound => "DEVICE_NOT_BOUND",
            Self::DeviceLimitReached => "DEVICE_LIMIT_REACHED",
            Self::DeviceProofRequired => "DEVICE_PROOF_REQUIRED",
            Self::DeviceProofInvalid => "DEVICE_PROOF_INVALID",
            Self::ReplayDetected | Self::StaleRevision => "REPLAY_DETECTED",
            Self::SignatureInvalid | Self::IntegrityMissing | Self::IntegrityInvalid => {
                "SIGNATURE_INVALID"
            }
            Self::KeyUnknown | Self::IntegrityUnknownKey => "KEY_UNKNOWN",
            Self::TimeRollbackDetected | Self::ServerTimeRollback => "TIME_ROLLBACK_DETECTED",
            Self::TimeSkew => "TIME_SKEW",
            Self::VersionBlocked => "VERSION_BLOCKED",
            Self::RiskBlocked => "RISK_BLOCKED",
            Self::AdapterUnsupported => "ADAPTER_UNSUPPORTED",
            Self::RateLimited => "RATE_LIMITED",
            Self::ServiceTemporarilyUnavailable | Self::Unavailable => {
                "SERVICE_TEMPORARILY_UNAVAILABLE"
            }
            Self::IdempotencyConflict | Self::RequestConflict => "IDEMPOTENCY_CONFLICT",
            Self::InternalError => "INTERNAL_ERROR",
            Self::BindingMismatch => "FORBIDDEN",
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::ServiceTemporarilyUnavailable
                | Self::InternalError
                | Self::Unavailable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidRequest(String),
    ResponseSchemaInvalid(String),
    DeviceProofRequired,
    ProtocolMismatch {
        expected: String,
        actual: String,
    },
    ContractMismatch {
        expected: String,
        actual: String,
    },
    BindingMismatch {
        field: String,
        expected: String,
        actual: String,
    },
    Integrity(IntegrityError),
    ServerTimeRollback {
        last_seen: u64,
        received: u64,
    },
    RequestConflict {
        request_id: String,
    },
    StaleRevision {
        current: u64,
        received: u64,
    },
    Contract(ContractError),
}

impl AuthorizationError {
    pub fn code(&self) -> AuthorizationErrorCode {
        match self {
            Self::InvalidRequest(_) => AuthorizationErrorCode::InvalidRequest,
            Self::ResponseSchemaInvalid(_) => AuthorizationErrorCode::ResponseSchemaInvalid,
            Self::DeviceProofRequired => AuthorizationErrorCode::DeviceProofRequired,
            Self::ProtocolMismatch { .. } => AuthorizationErrorCode::ContractVersionUnsupported,
            Self::ContractMismatch { .. } => AuthorizationErrorCode::ContractVersionUnsupported,
            Self::BindingMismatch { field, .. } => {
                if field.contains("software") {
                    AuthorizationErrorCode::SoftwareMismatch
                } else if field.contains("profile") {
                    AuthorizationErrorCode::ProfileMismatch
                } else if field.contains("device") {
                    AuthorizationErrorCode::DeviceScopeMismatch
                } else {
                    AuthorizationErrorCode::Forbidden
                }
            }
            Self::Integrity(IntegrityError::Missing) => AuthorizationErrorCode::SignatureInvalid,
            Self::Integrity(IntegrityError::UnknownKey(_)) => AuthorizationErrorCode::KeyUnknown,
            Self::Integrity(_) => AuthorizationErrorCode::SignatureInvalid,
            Self::ServerTimeRollback { .. } => AuthorizationErrorCode::TimeRollbackDetected,
            Self::RequestConflict { .. } => AuthorizationErrorCode::IdempotencyConflict,
            Self::StaleRevision { .. } => AuthorizationErrorCode::ReplayDetected,
            Self::Contract(_) => AuthorizationErrorCode::InvalidRequest,
        }
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(f, "invalid authorization request: {message}"),
            Self::ResponseSchemaInvalid(message) => {
                write!(f, "authorization response schema is invalid: {message}")
            }
            Self::DeviceProofRequired => write!(f, "authorization device proof is required"),
            Self::ProtocolMismatch { expected, actual } => {
                write!(f, "authorization protocol mismatch: expected {expected}, received {actual}")
            }
            Self::ContractMismatch { expected, actual } => {
                write!(f, "authorization contract mismatch: expected {expected}, received {actual}")
            }
            Self::BindingMismatch {
                field,
                expected,
                actual,
            } => write!(f, "authorization binding mismatch for {field}: expected {expected}, received {actual}"),
            Self::Integrity(error) => error.fmt(f),
            Self::ServerTimeRollback {
                last_seen,
                received,
            } => write!(f, "authorization server time moved backwards: last {last_seen}, received {received}"),
            Self::RequestConflict { request_id } => {
                write!(f, "authorization request is not idempotent: {request_id}")
            }
            Self::StaleRevision { current, received } => {
                write!(f, "authorization revision is stale: current {current}, received {received}")
            }
            Self::Contract(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for AuthorizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Integrity(error) => Some(error),
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for AuthorizationError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<IntegrityError> for AuthorizationError {
    fn from(error: IntegrityError) -> Self {
        Self::Integrity(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationErrorResponseV1 {
    pub protocol: String,
    pub schema_version: String,
    pub contract_version: String,
    pub request_id: String,
    pub product_id: String,
    pub identity: AuthorizationIdentity,
    pub error_code: String,
    pub message: String,
    pub retryable: bool,
    pub server_time: u64,
    pub integrity: IntegrityProof,
}

impl AuthorizationErrorResponseV1 {
    /// Map a central platform error into the local A-to-core vocabulary.
    ///
    /// `IDEMPOTENCY_CONFLICT` is deliberately not forwarded as a central
    /// error name: the core's v1 consumer treats this semantic as
    /// `AUTH_INVALID`. Unknown central codes also fail closed to the same
    /// non-retryable local denial instead of becoming an allow decision.
    pub fn core_code_from_platform_error(platform_code: &str) -> AuthorizationErrorCode {
        match platform_code {
            "IDEMPOTENCY_CONFLICT" | "AUTH_INVALID" => AuthorizationErrorCode::AuthInvalid,
            code => AuthorizationErrorCode::from_str(code)
                .unwrap_or(AuthorizationErrorCode::AuthInvalid),
        }
    }

    pub fn new_core_from_platform_error(
        request_id: impl Into<String>,
        binding: &AuthorizationBinding,
        platform_code: &str,
        server_time: u64,
        integrity: IntegrityProof,
    ) -> Self {
        let code = Self::core_code_from_platform_error(platform_code);
        let message = if code == AuthorizationErrorCode::AuthInvalid {
            "AUTH_INVALID"
        } else {
            code.as_str()
        };
        Self::new_core_with_message(request_id, binding, code, message, server_time, integrity)
    }

    pub fn new_core(
        request_id: impl Into<String>,
        binding: &AuthorizationBinding,
        code: AuthorizationErrorCode,
        server_time: u64,
        integrity: IntegrityProof,
    ) -> Self {
        Self::new_core_with_message(
            request_id,
            binding,
            code,
            code.as_str(),
            server_time,
            integrity,
        )
    }

    pub fn new_core_with_message(
        request_id: impl Into<String>,
        binding: &AuthorizationBinding,
        code: AuthorizationErrorCode,
        message: impl Into<String>,
        server_time: u64,
        integrity: IntegrityProof,
    ) -> Self {
        Self {
            protocol: AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string(),
            schema_version: AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string(),
            contract_version: AUTHORIZATION_A_CORE_CONTRACT_VERSION.to_string(),
            request_id: request_id.into(),
            product_id: binding.product_id.clone(),
            identity: binding.identity.clone(),
            error_code: code.as_str().to_string(),
            message: message.into(),
            retryable: code.retryable(),
            server_time,
            integrity,
        }
    }

    pub fn validate_for_binding(
        &self,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
    ) -> Result<(), AuthorizationError> {
        binding.validate_for(manifest)?;
        if self.protocol != AUTHORIZATION_A_CORE_PROTOCOL_VERSION
            || self.schema_version != AUTHORIZATION_A_CORE_PROTOCOL_VERSION
        {
            return Err(AuthorizationError::ProtocolMismatch {
                expected: AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string(),
                actual: self.protocol.clone(),
            });
        }
        if self.contract_version != AUTHORIZATION_A_CORE_CONTRACT_VERSION {
            return Err(AuthorizationError::ContractMismatch {
                expected: AUTHORIZATION_A_CORE_CONTRACT_VERSION.to_string(),
                actual: self.contract_version.clone(),
            });
        }
        validate_opaque_identifier(&self.request_id, "request_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        if self.product_id != binding.product_id || self.identity != binding.identity {
            return Err(AuthorizationError::BindingMismatch {
                field: "identity".to_string(),
                expected: format!(
                    "{}:{}",
                    binding.product_id,
                    format_identity(&binding.identity)
                ),
                actual: format!("{}:{}", self.product_id, format_identity(&self.identity)),
            });
        }
        let code = AuthorizationErrorCode::from_str(&self.error_code).ok_or_else(|| {
            AuthorizationError::InvalidRequest(format!(
                "unknown authorization error code: {}",
                self.error_code
            ))
        })?;
        validate_short_text(&self.message, "error.message")
            .map_err(AuthorizationError::InvalidRequest)?;
        if self.retryable != code.retryable() {
            return Err(AuthorizationError::InvalidRequest(
                "error response retryable flag does not match error_code".to_string(),
            ));
        }
        self.integrity.validate_for_core_contract()?;
        Ok(())
    }

    pub fn validate_for_manifest(
        &self,
        manifest: &ProductManifest,
    ) -> Result<(), AuthorizationError> {
        let binding = AuthorizationBinding::new(self.product_id.clone(), self.identity.clone());
        self.validate_for_binding(manifest, &binding)
    }

    pub fn canonical_payload(&self) -> String {
        let mut object = BTreeMap::new();
        object.insert(
            "contract_version".to_string(),
            JsonValue::String(self.contract_version.clone()),
        );
        object.insert(
            "client_id".to_string(),
            JsonValue::String(self.identity.client_id.clone()),
        );
        object.insert(
            "device_id".to_string(),
            JsonValue::String(self.identity.device_id.clone()),
        );
        object.insert(
            "device_scope".to_string(),
            JsonValue::String(self.identity.device_scope.clone()),
        );
        object.insert(
            "error_code".to_string(),
            JsonValue::String(self.error_code.clone()),
        );
        object.insert(
            "message".to_string(),
            JsonValue::String(self.message.clone()),
        );
        object.insert(
            "product_id".to_string(),
            JsonValue::String(self.product_id.clone()),
        );
        object.insert(
            "profile_id".to_string(),
            JsonValue::String(self.identity.profile_id.clone()),
        );
        object.insert(
            "request_id".to_string(),
            JsonValue::String(self.request_id.clone()),
        );
        object.insert("retryable".to_string(), JsonValue::Bool(self.retryable));
        object.insert(
            "protocol".to_string(),
            JsonValue::String(self.protocol.clone()),
        );
        object.insert(
            "schema_version".to_string(),
            JsonValue::String(self.schema_version.clone()),
        );
        object.insert(
            "server_time".to_string(),
            JsonValue::Number(self.server_time),
        );
        object.insert(
            "software_id".to_string(),
            JsonValue::String(self.identity.software_id.clone()),
        );
        if let JsonValue::Object(mut integrity) = integrity_to_json_value(&self.integrity) {
            integrity.remove("signature");
            object.insert("integrity".to_string(), JsonValue::Object(integrity));
        }
        serialize_json(&JsonValue::Object(object))
    }

    pub fn verify<V: IntegrityVerifier>(&self, verifier: &V) -> Result<(), AuthorizationError> {
        verifier
            .verify(&self.integrity, &self.canonical_payload())
            .map_err(AuthorizationError::Integrity)
    }

    /// Sign a local structured denial with the A-owned signer. This helper is
    /// intentionally separate from central response adaptation: a denial is
    /// never a license fact and never reuses the central proof.
    pub fn sign_for_core<S: IntegritySigner>(
        mut self,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        signer: &S,
    ) -> Result<Self, AuthorizationError> {
        let template = signer.integrity_template();
        template.validate_for_core_contract()?;
        self.integrity = template;
        self.validate_for_binding(manifest, binding)?;
        self.integrity = signer.sign(&self.canonical_payload())?;
        self.validate_for_binding(manifest, binding)?;
        signer.verify(&self.integrity, &self.canonical_payload())?;
        Ok(self)
    }

    pub fn to_json(&self) -> String {
        serialize_json(&authorization_error_to_json_value(self))
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        let value = JsonParser::new(input).parse()?;
        authorization_error_from_json_value(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationModuleV1 {
    pub product_id: String,
    pub authorization_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub device_scope: String,
    pub device_id: String,
    pub module_id: String,
    pub module_type: String,
    pub version: String,
    pub capability: String,
    pub config_version: String,
    pub authorization_revision: u64,
    pub payload: BTreeMap<String, String>,
    pub structured_device_scope: Option<StructuredDeviceScopeV1>,
}

impl AuthorizationModuleV1 {
    pub fn new(
        product_id: impl Into<String>,
        authorization_id: impl Into<String>,
        identity: &AuthorizationIdentity,
        module_id: impl Into<String>,
        module_type: impl Into<String>,
        version: impl Into<String>,
        capability: impl Into<String>,
        config_version: impl Into<String>,
        authorization_revision: u64,
        payload: BTreeMap<String, String>,
    ) -> Self {
        Self {
            product_id: product_id.into(),
            authorization_id: authorization_id.into(),
            software_id: identity.software_id.clone(),
            profile_id: identity.profile_id.clone(),
            client_id: identity.client_id.clone(),
            device_scope: identity.device_scope.clone(),
            device_id: identity.device_id.clone(),
            module_id: module_id.into(),
            module_type: module_type.into(),
            version: version.into(),
            capability: capability.into(),
            config_version: config_version.into(),
            authorization_revision,
            payload,
            structured_device_scope: None,
        }
    }

    pub fn with_structured_device_scope(mut self, scope: StructuredDeviceScopeV1) -> Self {
        if let Some(device_id) = &scope.device_id {
            self.device_scope = scope.scope.clone();
            self.device_id = device_id.clone();
        }
        self.structured_device_scope = Some(scope);
        self
    }

    fn identity(&self) -> AuthorizationIdentity {
        AuthorizationIdentity::new(
            &self.software_id,
            &self.profile_id,
            &self.client_id,
            &self.device_scope,
            &self.device_id,
        )
    }

    fn validate_for(
        &self,
        response: &AuthorizationResponseV1,
        manifest: &ProductManifest,
    ) -> Result<(), AuthorizationError> {
        validate_identifier(&self.product_id, "module.product_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        if self.product_id != response.product_id || self.product_id != manifest.product_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "module.product_id".to_string(),
                expected: response.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        if self.authorization_id != response.authorization_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "module.authorization_id".to_string(),
                expected: response.authorization_id.clone(),
                actual: self.authorization_id.clone(),
            });
        }
        let identity = self.identity();
        identity.validate()?;
        if identity != response.identity {
            return Err(AuthorizationError::BindingMismatch {
                field: "module.identity".to_string(),
                expected: format_identity(&response.identity),
                actual: format_identity(&identity),
            });
        }
        match (
            &self.structured_device_scope,
            &response.structured_device_scope,
        ) {
            (Some(module_scope), Some(response_scope)) if module_scope == response_scope => {
                module_scope.validate_for_authorization()?;
            }
            (None, None) => {}
            (Some(_), Some(_)) => {
                return Err(AuthorizationError::BindingMismatch {
                    field: "module.device_scope".to_string(),
                    expected: response
                        .structured_device_scope
                        .as_ref()
                        .map(StructuredDeviceScopeV1::to_json)
                        .unwrap_or_default(),
                    actual: self
                        .structured_device_scope
                        .as_ref()
                        .map(StructuredDeviceScopeV1::to_json)
                        .unwrap_or_default(),
                });
            }
            _ => {
                return Err(AuthorizationError::InvalidRequest(
                    "module structured device_scope must match the response shape".to_string(),
                ));
            }
        }
        if self.authorization_revision != response.authorization_revision {
            return Err(AuthorizationError::BindingMismatch {
                field: "module.authorization_revision".to_string(),
                expected: response.authorization_revision.to_string(),
                actual: self.authorization_revision.to_string(),
            });
        }
        if self.config_version != response.config_version {
            return Err(AuthorizationError::BindingMismatch {
                field: "module.config_version".to_string(),
                expected: response.config_version.clone(),
                actual: self.config_version.clone(),
            });
        }
        validate_identifier(&self.module_id, "module.module_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_identifier(&self.module_type, "module.module_type", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.version, "module.version")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_identifier(&self.capability, "module.capability", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        if !response
            .capabilities
            .iter()
            .any(|capability| capability == &self.capability)
        {
            return Err(AuthorizationError::InvalidRequest(format!(
                "module capability was not granted: {}",
                self.capability
            )));
        }
        if self.payload.len() > MAX_MODULE_PAYLOAD_ENTRIES {
            return Err(AuthorizationError::InvalidRequest(format!(
                "module payload cannot contain more than {MAX_MODULE_PAYLOAD_ENTRIES} entries"
            )));
        }
        for (key, value) in &self.payload {
            validate_parameter_key(key).map_err(AuthorizationError::InvalidRequest)?;
            validate_short_text(value, &format!("module.payload.{key}"))
                .map_err(AuthorizationError::InvalidRequest)?;
            if is_sensitive_parameter_key(key) || looks_like_raw_credential(value) {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "module.payload.{key} cannot contain raw credentials"
                )));
            }
        }
        if self.module_type == "update" {
            for key in [
                "artifact_sha256",
                "artifact_size",
                "artifact_signature",
                "min_core_version",
                "channel",
            ] {
                if self
                    .payload
                    .get(key)
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(AuthorizationError::InvalidRequest(format!(
                        "update module requires payload.{key}"
                    )));
                }
            }
            if self.payload["artifact_size"].parse::<u64>().is_err() {
                return Err(AuthorizationError::InvalidRequest(
                    "update module payload.artifact_size must be an unsigned integer".to_string(),
                ));
            }
            if !self.payload["artifact_sha256"]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
                || self.payload["artifact_sha256"].len() != 64
            {
                return Err(AuthorizationError::InvalidRequest(
                    "update module payload.artifact_sha256 must be 64 hexadecimal characters"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn to_local_module(&self) -> ModuleEnvelope {
        ModuleEnvelope::new(
            self.product_id.clone(),
            self.module_id.clone(),
            self.version.clone(),
            self.capability.clone(),
            self.payload.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResponseV1 {
    pub protocol: String,
    pub schema_version: String,
    pub contract_version: String,
    pub request_id: String,
    pub product_id: String,
    pub identity: AuthorizationIdentity,
    /// Present only when the central response used the structured
    /// server-confirmed device_scope object. The legacy identity projection is
    /// retained for old consumers, while serialization keeps the object.
    pub structured_device_scope: Option<StructuredDeviceScopeV1>,
    pub authorization_id: String,
    pub target: String,
    pub arch: String,
    pub channel: String,
    pub authorization_revision: u64,
    pub config_version: String,
    pub snapshot_id: String,
    pub state_code: String,
    pub decision: LicenseState,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub server_time: u64,
    pub cache_until: Option<u64>,
    pub next_verify_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub integrity: IntegrityProof,
    pub capabilities: Vec<String>,
    pub modules: Vec<AuthorizationModuleV1>,
}

impl AuthorizationResponseV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_cloud(
        request: &AuthorizationRequestV1,
        authorization_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        decision: LicenseState,
        authorization_revision: u64,
        server_time: u64,
        issued_at: u64,
        expires_at: Option<u64>,
        cache_until: Option<u64>,
        next_verify_at: Option<u64>,
        grace_until: Option<u64>,
        integrity: IntegrityProof,
        capabilities: Vec<String>,
        modules: Vec<AuthorizationModuleV1>,
    ) -> Self {
        Self {
            protocol: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
            schema_version: AUTHORIZATION_CLOUD_PROTOCOL_VERSION.to_string(),
            contract_version: AUTHORIZATION_CLOUD_CONTRACT_VERSION.to_string(),
            request_id: request.request_id.clone(),
            product_id: request.product_id.clone(),
            identity: request.identity.clone(),
            structured_device_scope: None,
            authorization_id: authorization_id.into(),
            target: request.target.clone(),
            arch: request.arch.clone(),
            channel: request.channel.clone(),
            authorization_revision,
            config_version: request.config_version.clone(),
            snapshot_id: snapshot_id.into(),
            state_code: state_code_for(decision).to_string(),
            decision,
            issued_at,
            expires_at,
            server_time,
            cache_until,
            next_verify_at,
            grace_until,
            integrity,
            capabilities,
            modules,
        }
    }

    pub fn with_structured_device_scope(mut self, scope: StructuredDeviceScopeV1) -> Self {
        if let Some(device_id) = &scope.device_id {
            self.identity.device_scope = scope.scope.clone();
            self.identity.device_id = device_id.clone();
        }
        self.structured_device_scope = Some(scope);
        self
    }

    pub fn legacy_device_scope(&self) -> &str {
        &self.identity.device_scope
    }

    /// The platform can return this legacy state only while handling a
    /// deactivate compatibility request. It is not an A-core authorization
    /// state and must be converted to a signed `AUTH_INVALID` denial.
    pub fn is_unbound_compatibility_response(&self) -> bool {
        self.decision == LicenseState::Active && self.state_code == "unbound"
    }

    /// Convert a verified deactivate-only `active + unbound` platform result
    /// into the existing local structured denial. The method intentionally
    /// never creates an authorization response, so the caller cannot
    /// accidentally sign an active allow envelope.
    pub fn to_core_auth_invalid_for_unbound<V: IntegrityVerifier, S: IntegritySigner>(
        &self,
        request: &AuthorizationRequestV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        http_status: u16,
        central_verifier: &V,
        signer: &S,
    ) -> Result<AuthorizationErrorResponseV1, AuthorizationError> {
        if !(200..300).contains(&http_status) {
            return Err(AuthorizationError::InvalidRequest(format!(
                "active + unbound compatibility response requires a successful HTTP status, received {http_status}"
            )));
        }
        if !self.is_unbound_compatibility_response() {
            return Err(AuthorizationError::InvalidRequest(
                "only active + unbound compatibility responses can be mapped to AUTH_INVALID"
                    .to_string(),
            ));
        }
        request.validate_for_platform()?;
        if request.operation != "deactivate" {
            return Err(AuthorizationError::InvalidRequest(
                "active + unbound is only valid for deactivate compatibility requests".to_string(),
            ));
        }
        binding.validate_for(manifest)?;
        self.validate_unbound_rejection_shape(request, binding)?;
        self.integrity.validate_for_cloud_contract()?;
        self.verify(central_verifier)?;

        AuthorizationErrorResponseV1::new_core_from_platform_error(
            request.request_id.clone(),
            binding,
            "AUTH_INVALID",
            self.server_time,
            signer.integrity_template(),
        )
        .sign_for_core(manifest, binding, signer)
    }

    /// Parse the deactivate-only compatibility response through a dedicated
    /// restricted entry point. Ordinary `from_platform_json` intentionally
    /// rejects `active + unbound`, so callers cannot accidentally treat the
    /// compatibility result as an authorization fact.
    pub fn from_platform_unbound_deactivate_json<V: IntegrityVerifier, S: IntegritySigner>(
        input: &str,
        request: &AuthorizationRequestV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        http_status: u16,
        central_verifier: &V,
        signer: &S,
    ) -> Result<AuthorizationErrorResponseV1, AuthorizationError> {
        let value = JsonParser::new(input)
            .parse()
            .map_err(|error| AuthorizationError::ResponseSchemaInvalid(error.to_string()))?;
        let response = authorization_from_json_value(value)
            .map_err(AuthorizationError::ResponseSchemaInvalid)?;
        response.to_core_auth_invalid_for_unbound(
            request,
            manifest,
            binding,
            http_status,
            central_verifier,
            signer,
        )
    }

    fn validate_unbound_rejection_shape(
        &self,
        request: &AuthorizationRequestV1,
        binding: &AuthorizationBinding,
    ) -> Result<(), AuthorizationError> {
        // Reuse the complete central response shape gate with the legacy
        // compatibility state code normalized to the ordinary active code.
        // The public active path still rejects the original `active + unbound`
        // value before it can become an authorization fact.
        let mut shape = self.clone();
        shape.state_code = state_code_for(LicenseState::Active).to_string();
        shape.validate_for_platform_response()?;
        if self.request_id != request.request_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "request_id".to_string(),
                expected: request.request_id.clone(),
                actual: self.request_id.clone(),
            });
        }
        if self.product_id != binding.product_id || self.identity != binding.identity {
            return Err(AuthorizationError::BindingMismatch {
                field: "identity".to_string(),
                expected: format_identity(&binding.identity),
                actual: format_identity(&self.identity),
            });
        }
        if self.target != request.target
            || self.arch != request.arch
            || self.channel != request.channel
            || self.config_version != request.config_version
        {
            return Err(AuthorizationError::BindingMismatch {
                field: "target/arch/channel/config_version".to_string(),
                expected: format!(
                    "{}/{}/{}/{}",
                    request.target, request.arch, request.channel, request.config_version
                ),
                actual: format!(
                    "{}/{}/{}/{}",
                    self.target, self.arch, self.channel, self.config_version
                ),
            });
        }
        if request
            .known_authorization_revision
            .is_some_and(|known| self.authorization_revision < known)
        {
            return Err(AuthorizationError::StaleRevision {
                current: request.known_authorization_revision.unwrap_or_default(),
                received: self.authorization_revision,
            });
        }
        Ok(())
    }

    pub fn to_core(self) -> Result<Self, AuthorizationError> {
        self.validate_for_platform_response()?;
        if !self.modules.is_empty() {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "module-bearing responses require the manifest-bound A-to-core path".to_string(),
            ));
        }
        self.convert_to_core_protocol()
    }

    /// Verify a complete central response, then create a separately signed
    /// local envelope for the core. The central proof is never reused: the
    /// local proof covers the complete `authorization-a-core.v1` response
    /// after removing only `integrity.signature` from its canonical form.
    pub fn to_core_with_signer<V: IntegrityVerifier, S: IntegritySigner>(
        self,
        request: &AuthorizationRequestV1,
        central_verifier: &V,
        signer: &S,
    ) -> Result<Self, AuthorizationError> {
        if !self.modules.is_empty() {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "module-bearing responses require the manifest-bound A-to-core path".to_string(),
            ));
        }
        self.to_core_with_signer_after_request_validation(request, central_verifier, signer)
    }

    fn to_core_with_signer_after_request_validation<V: IntegrityVerifier, S: IntegritySigner>(
        self,
        request: &AuthorizationRequestV1,
        central_verifier: &V,
        signer: &S,
    ) -> Result<Self, AuthorizationError> {
        self.validate_for_platform_request(request)?;
        self.verify(central_verifier)?;

        let mut core = self.convert_to_core_protocol()?;
        let template = signer.integrity_template();
        template.validate_for_core_contract()?;
        core.integrity = template;

        let canonical_payload = core.canonical_payload();
        core.integrity = signer.sign(&canonical_payload)?;
        core.validate_protocol(AUTHORIZATION_A_CORE_PROTOCOL_VERSION)?;
        core.integrity.validate_for_core_contract()?;
        signer.verify(&core.integrity, &core.canonical_payload())?;
        Ok(core)
    }

    /// Product-facing variant of [`Self::to_core_with_signer`]. It validates
    /// the request, manifest, identity binding and optional modules before A
    /// signs the local envelope.
    pub fn to_core_with_signer_for<V: IntegrityVerifier, S: IntegritySigner>(
        self,
        request: &AuthorizationRequestV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        central_verifier: &V,
        signer: &S,
    ) -> Result<Self, AuthorizationError> {
        self.validate_for_request(request)?;
        self.validate_for_manifest(manifest)?;
        binding.validate_for(manifest)?;
        if self.product_id != binding.product_id || self.identity != binding.identity {
            return Err(AuthorizationError::BindingMismatch {
                field: "identity".to_string(),
                expected: format!(
                    "{}:{}",
                    binding.product_id,
                    format_identity(&binding.identity)
                ),
                actual: format!("{}:{}", self.product_id, format_identity(&self.identity)),
            });
        }
        self.to_core_with_signer_after_request_validation(request, central_verifier, signer)
    }

    fn convert_to_core_protocol(mut self) -> Result<Self, AuthorizationError> {
        self.protocol = AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string();
        self.schema_version = AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string();
        self.contract_version = AUTHORIZATION_A_CORE_CONTRACT_VERSION.to_string();
        self.validate_protocol(AUTHORIZATION_A_CORE_PROTOCOL_VERSION)?;
        Ok(self)
    }

    pub fn validate_for_request(
        &self,
        request: &AuthorizationRequestV1,
    ) -> Result<(), AuthorizationError> {
        request.validate()?;
        self.validate_protocol(AUTHORIZATION_CLOUD_PROTOCOL_VERSION)?;
        if self.request_id != request.request_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "request_id".to_string(),
                expected: request.request_id.clone(),
                actual: self.request_id.clone(),
            });
        }
        if self.product_id != request.product_id || self.identity != request.identity {
            return Err(AuthorizationError::BindingMismatch {
                field: "request.identity".to_string(),
                expected: format!(
                    "{}:{}",
                    request.product_id,
                    format_identity(&request.identity)
                ),
                actual: format!("{}:{}", self.product_id, format_identity(&self.identity)),
            });
        }
        if self.target != request.target
            || self.arch != request.arch
            || self.channel != request.channel
        {
            return Err(AuthorizationError::BindingMismatch {
                field: "target/arch/channel".to_string(),
                expected: format!("{}/{}/{}", request.target, request.arch, request.channel),
                actual: format!("{}/{}/{}", self.target, self.arch, self.channel),
            });
        }
        if self.decision == LicenseState::NotModified
            && self.config_version != request.config_version
        {
            return Err(AuthorizationError::BindingMismatch {
                field: "config_version".to_string(),
                expected: request.config_version.clone(),
                actual: self.config_version.clone(),
            });
        }
        if request
            .known_authorization_revision
            .is_some_and(|current| self.authorization_revision < current)
        {
            return Err(AuthorizationError::StaleRevision {
                current: request.known_authorization_revision.unwrap_or_default(),
                received: self.authorization_revision,
            });
        }
        Ok(())
    }

    pub fn validate_for_platform_request(
        &self,
        request: &AuthorizationRequestV1,
    ) -> Result<(), AuthorizationError> {
        request.validate_for_platform()?;
        self.validate_for_platform_response()?;
        self.validate_for_request(request)?;
        if let Some(scope) = &self.structured_device_scope {
            if scope
                .installation_id
                .as_deref()
                .is_some_and(|installation_id| installation_id != request.installation_id)
            {
                return Err(AuthorizationError::BindingMismatch {
                    field: "device_scope.installation_id".to_string(),
                    expected: request.installation_id.clone(),
                    actual: scope.installation_id.clone().unwrap_or_default(),
                });
            }
        }
        Ok(())
    }

    pub fn validate_for_platform_response(&self) -> Result<(), AuthorizationError> {
        if self.is_unbound_compatibility_response() {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "active + unbound is a deactivate compatibility result and must map to AUTH_INVALID"
                    .to_string(),
            ));
        }
        let scope = self.structured_device_scope.as_ref().ok_or_else(|| {
            AuthorizationError::ResponseSchemaInvalid(
                "authorization.v1 response requires structured device_scope".to_string(),
            )
        })?;
        self.validate_protocol(AUTHORIZATION_CLOUD_PROTOCOL_VERSION)
            .map_err(map_platform_response_shape_error)?;
        if scope.device_id.is_some() != scope.installation_id.is_some() {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "structured device_scope refusal must contain either both claims or two nulls"
                    .to_string(),
            ));
        }
        if matches!(
            self.decision,
            LicenseState::Active | LicenseState::Grace | LicenseState::NotModified
        ) {
            scope
                .validate_for_authorization()
                .map_err(|error| AuthorizationError::ResponseSchemaInvalid(error.to_string()))?;
            if self.expires_at.is_none() || self.server_time >= self.expires_at.unwrap_or(0) {
                return Err(AuthorizationError::ResponseSchemaInvalid(
                    "active, grace and not_modified responses require server_time < expires_at"
                        .to_string(),
                ));
            }
        }
        if self.cache_until != self.next_verify_at {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "central cache_until and next_verify_at must be equal".to_string(),
            ));
        }
        if let Some(expires_at) = self.expires_at {
            for (field, value) in [
                ("cache_until", self.cache_until),
                ("next_verify_at", self.next_verify_at),
                ("grace_until", self.grace_until),
            ] {
                if value.is_some_and(|value| value > expires_at) {
                    return Err(AuthorizationError::ResponseSchemaInvalid(format!(
                        "{field} cannot exceed expires_at"
                    )));
                }
            }
            if self.decision == LicenseState::Expired && self.server_time < expires_at {
                return Err(AuthorizationError::ResponseSchemaInvalid(
                    "expired response must have server_time >= expires_at".to_string(),
                ));
            }
        } else if self.decision == LicenseState::Expired {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "expired response requires expires_at".to_string(),
            ));
        }
        if matches!(
            self.decision,
            LicenseState::Active | LicenseState::Grace | LicenseState::NotModified
        ) && (self.cache_until.is_none() || self.next_verify_at.is_none())
        {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "launchable central response requires cache_until and next_verify_at".to_string(),
            ));
        }
        for module in &self.modules {
            for key in module.payload.keys() {
                if is_sensitive_parameter_key(key) {
                    return Err(AuthorizationError::ResponseSchemaInvalid(format!(
                        "authorization module payload contains request-only field {key}"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn validate_for_binding(
        &self,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
    ) -> Result<(), AuthorizationError> {
        binding.validate_for(manifest)?;
        self.validate_protocol(AUTHORIZATION_A_CORE_PROTOCOL_VERSION)?;
        if self.product_id != binding.product_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "product_id".to_string(),
                expected: binding.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        if self.identity != binding.identity {
            return Err(AuthorizationError::BindingMismatch {
                field: "identity".to_string(),
                expected: format_identity(&binding.identity),
                actual: format_identity(&self.identity),
            });
        }
        if self.structured_device_scope.is_none() {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "authorization-a-core.v1 requires structured device_scope".to_string(),
            ));
        }
        self.integrity.validate_for_core_contract()?;
        Ok(())
    }

    fn validate_protocol(&self, expected_protocol: &str) -> Result<(), AuthorizationError> {
        if self.protocol != expected_protocol {
            return Err(AuthorizationError::ProtocolMismatch {
                expected: expected_protocol.to_string(),
                actual: self.protocol.clone(),
            });
        }
        let expected_contract = if expected_protocol == AUTHORIZATION_CLOUD_PROTOCOL_VERSION {
            AUTHORIZATION_CLOUD_CONTRACT_VERSION
        } else {
            AUTHORIZATION_A_CORE_CONTRACT_VERSION
        };
        if self.schema_version != expected_protocol {
            return Err(AuthorizationError::ProtocolMismatch {
                expected: expected_protocol.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.contract_version != expected_contract {
            return Err(AuthorizationError::ContractMismatch {
                expected: expected_contract.to_string(),
                actual: self.contract_version.clone(),
            });
        }
        if self.decision == LicenseState::Unavailable {
            return Err(AuthorizationError::InvalidRequest(
                "unavailable is an error outcome, not an authorization decision".to_string(),
            ));
        }
        validate_identifier(&self.product_id, "product_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_opaque_identifier(&self.request_id, "request_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        self.identity.validate()?;
        if let Some(scope) = &self.structured_device_scope {
            scope.validate()?;
            if scope.scope != self.identity.device_scope
                || scope
                    .device_id
                    .as_deref()
                    .is_some_and(|device_id| device_id != self.identity.device_id)
            {
                return Err(AuthorizationError::BindingMismatch {
                    field: "device_scope".to_string(),
                    expected: format_identity(&self.identity),
                    actual: scope.to_json(),
                });
            }
        }
        validate_opaque_identifier(&self.snapshot_id, "snapshot_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_opaque_identifier(&self.authorization_id, "authorization_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.target, "target").map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.arch, "arch").map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.channel, "channel")
            .map_err(AuthorizationError::InvalidRequest)?;
        if self.authorization_revision == 0 {
            return Err(AuthorizationError::InvalidRequest(
                "authorization_revision must be greater than zero".to_string(),
            ));
        }
        validate_config_version(&self.config_version, "config_version")
            .map_err(AuthorizationError::InvalidRequest)?;
        if self.state_code != state_code_for(self.decision) {
            return Err(AuthorizationError::InvalidRequest(
                "state_code does not match decision".to_string(),
            ));
        }
        if self.server_time < self.issued_at {
            return Err(AuthorizationError::InvalidRequest(
                "server_time cannot be earlier than issued_at".to_string(),
            ));
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at < self.issued_at)
        {
            return Err(AuthorizationError::InvalidRequest(
                "expires_at cannot be earlier than issued_at".to_string(),
            ));
        }
        for (field, value) in [
            ("cache_until", self.cache_until),
            ("next_verify_at", self.next_verify_at),
            ("grace_until", self.grace_until),
        ] {
            if value.is_some_and(|value| value < self.issued_at) {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "{field} cannot be earlier than issued_at"
                )));
            }
        }
        if expected_protocol == AUTHORIZATION_A_CORE_PROTOCOL_VERSION {
            self.validate_core_temporal_claims()?;
        }
        if expected_protocol == AUTHORIZATION_CLOUD_PROTOCOL_VERSION {
            self.integrity.validate_for_cloud_contract()?;
        } else {
            self.integrity.validate_shape()?;
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(AuthorizationError::InvalidRequest(format!(
                "response cannot grant more than {MAX_CAPABILITIES} capabilities"
            )));
        }
        let mut capabilities = Vec::new();
        for capability in &self.capabilities {
            validate_identifier(capability, "capability", false)
                .map_err(AuthorizationError::InvalidRequest)?;
            if capabilities.iter().any(|current| current == capability) {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "duplicate granted capability: {capability}"
                )));
            }
            capabilities.push(capability.clone());
        }
        if self.modules.len() > MAX_SNAPSHOT_MODULES {
            return Err(AuthorizationError::InvalidRequest(format!(
                "response cannot contain more than {MAX_SNAPSHOT_MODULES} modules"
            )));
        }
        Ok(())
    }

    fn validate_core_temporal_claims(&self) -> Result<(), AuthorizationError> {
        if let Some(expires_at) = self.expires_at {
            for (field, value) in [
                ("cache_until", self.cache_until),
                ("next_verify_at", self.next_verify_at),
                ("grace_until", self.grace_until),
            ] {
                if value.is_some_and(|value| value > expires_at) {
                    return Err(AuthorizationError::ResponseSchemaInvalid(format!(
                        "{field} cannot exceed expires_at"
                    )));
                }
            }
            if self.decision == LicenseState::Expired && self.server_time < expires_at {
                return Err(AuthorizationError::ResponseSchemaInvalid(
                    "expired core response must have server_time >= expires_at".to_string(),
                ));
            }
        } else if matches!(
            self.decision,
            LicenseState::Active
                | LicenseState::Grace
                | LicenseState::NotModified
                | LicenseState::Expired
        ) {
            return Err(AuthorizationError::ResponseSchemaInvalid(
                "core response state requires expires_at".to_string(),
            ));
        }
        if matches!(
            self.decision,
            LicenseState::Active | LicenseState::Grace | LicenseState::NotModified
        ) {
            if self.server_time >= self.expires_at.unwrap_or(0) {
                return Err(AuthorizationError::ResponseSchemaInvalid(
                    "launchable core response is expired at server_time".to_string(),
                ));
            }
            self.structured_device_scope
                .as_ref()
                .ok_or_else(|| {
                    AuthorizationError::ResponseSchemaInvalid(
                        "launchable core response requires device_scope".to_string(),
                    )
                })?
                .validate_for_authorization()
                .map_err(|error| AuthorizationError::ResponseSchemaInvalid(error.to_string()))?;
        }
        Ok(())
    }

    pub fn validate_for_manifest(
        &self,
        manifest: &ProductManifest,
    ) -> Result<(), AuthorizationError> {
        self.validate_protocol(&self.protocol)?;
        if self.product_id != manifest.product_id {
            return Err(AuthorizationError::BindingMismatch {
                field: "product_id".to_string(),
                expected: manifest.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        for capability in &self.capabilities {
            if !manifest.declares_capability(capability) {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "capability is not declared by the product: {capability}"
                )));
            }
        }
        for capability in &manifest.capabilities {
            if capability.required
                && !self
                    .capabilities
                    .iter()
                    .any(|granted| granted == &capability.id)
            {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "required capability was not granted: {}",
                    capability.id
                )));
            }
        }
        let mut module_ids = Vec::new();
        for module in &self.modules {
            module.validate_for(self, manifest)?;
            if module_ids.iter().any(|id| id == &module.module_id) {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "duplicate module id: {}",
                    module.module_id
                )));
            }
            module_ids.push(module.module_id.clone());
        }
        Ok(())
    }

    pub fn verify<V: IntegrityVerifier>(&self, verifier: &V) -> Result<(), AuthorizationError> {
        verifier
            .verify(&self.integrity, &self.canonical_payload())
            .map_err(AuthorizationError::Integrity)
    }

    pub fn to_json(&self) -> String {
        serialize_json(&authorization_to_json_value(self))
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        let value = JsonParser::new(input).parse()?;
        authorization_from_json_value(value)
    }

    pub fn verify_for_core<V: IntegrityVerifier>(
        &self,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<(), AuthorizationError> {
        self.validate_for_binding(manifest, binding)?;
        self.validate_for_manifest(manifest)?;
        self.integrity.validate_for_core_contract()?;
        self.verify(verifier)
    }

    /// Stable fixture bytes for a verifier. This models the production rule:
    /// the complete response is signed after removing only
    /// `integrity.signature`. The production JCS-RFC8785 implementation
    /// remains an external dependency boundary.
    pub fn canonical_payload(&self) -> String {
        serialize_json(&authorization_claims_to_json_value(self))
    }

    /// Canonical claims excluding the request-specific replay key. This is
    /// used only to compare two signed revisions returned for separate
    /// requests; the signature payload itself still includes request_id.
    pub fn authority_payload(&self) -> String {
        let mut request_scoped = self.clone();
        request_scoped.request_id = "request-scoped".to_string();
        request_scoped.canonical_payload()
    }

    /// Parse and validate a central response at the A boundary. Structural
    /// failures are deliberately collapsed to one non-retryable code so the
    /// core cannot mistake malformed platform data for a product decision.
    pub fn from_platform_json(input: &str) -> Result<Self, AuthorizationError> {
        let value = JsonParser::new(input)
            .parse()
            .map_err(|error| AuthorizationError::ResponseSchemaInvalid(error.to_string()))?;
        let response = authorization_from_json_value(value)
            .map_err(|error| AuthorizationError::ResponseSchemaInvalid(error.to_string()))?;
        response.validate_for_platform_response()?;
        Ok(response)
    }

    pub fn to_snapshot(
        &self,
        manifest: &ProductManifest,
    ) -> Result<AuthorizationSnapshot, AuthorizationError> {
        self.validate_for_manifest(manifest)?;
        let modules = self
            .modules
            .iter()
            .map(AuthorizationModuleV1::to_local_module)
            .collect();
        Ok(AuthorizationSnapshot::new(
            self.product_id.clone(),
            self.snapshot_id.clone(),
            self.identity.client_id.clone(),
            self.identity.device_id.clone(),
            self.decision,
            self.issued_at,
            self.expires_at,
            self.capabilities.clone(),
            modules,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheApplyOutcome {
    Stored,
    Idempotent,
    NotModified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCacheRequestRecord {
    pub key: AuthorizationCacheKey,
    pub request_id: String,
    pub canonical_payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCacheWatermark {
    pub key: AuthorizationCacheKey,
    pub server_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorizationCacheKey {
    pub product_id: String,
    pub authorization_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub device_scope: String,
    pub device_id: String,
    pub contract_version: String,
    pub target: String,
    pub arch: String,
    pub channel: String,
    pub config_version: String,
}

impl AuthorizationCacheKey {
    pub fn from_binding(
        binding: &AuthorizationBinding,
        authorization_id: impl Into<String>,
        contract_version: impl Into<String>,
        target: impl Into<String>,
        arch: impl Into<String>,
        channel: impl Into<String>,
        config_version: impl Into<String>,
    ) -> Self {
        Self {
            product_id: binding.product_id.clone(),
            authorization_id: authorization_id.into(),
            software_id: binding.identity.software_id.clone(),
            profile_id: binding.identity.profile_id.clone(),
            client_id: binding.identity.client_id.clone(),
            device_scope: binding.identity.device_scope.clone(),
            device_id: binding.identity.device_id.clone(),
            contract_version: contract_version.into(),
            target: target.into(),
            arch: arch.into(),
            channel: channel.into(),
            config_version: config_version.into(),
        }
    }

    pub fn from_response(response: &AuthorizationResponseV1) -> Self {
        Self {
            product_id: response.product_id.clone(),
            authorization_id: response.authorization_id.clone(),
            software_id: response.identity.software_id.clone(),
            profile_id: response.identity.profile_id.clone(),
            client_id: response.identity.client_id.clone(),
            device_scope: response.identity.device_scope.clone(),
            device_id: response.identity.device_id.clone(),
            contract_version: response.contract_version.clone(),
            target: response.target.clone(),
            arch: response.arch.clone(),
            channel: response.channel.clone(),
            config_version: response.config_version.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        validate_identifier(&self.product_id, "cache_key.product_id", false)
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_opaque_identifier(&self.authorization_id, "cache_key.authorization_id")
            .map_err(AuthorizationError::InvalidRequest)?;
        AuthorizationIdentity::new(
            &self.software_id,
            &self.profile_id,
            &self.client_id,
            &self.device_scope,
            &self.device_id,
        )
        .validate()?;
        if self.contract_version != AUTHORIZATION_A_CORE_CONTRACT_VERSION {
            return Err(AuthorizationError::ContractMismatch {
                expected: AUTHORIZATION_A_CORE_CONTRACT_VERSION.to_string(),
                actual: self.contract_version.clone(),
            });
        }
        validate_short_text(&self.target, "cache_key.target")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.arch, "cache_key.arch")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_short_text(&self.channel, "cache_key.channel")
            .map_err(AuthorizationError::InvalidRequest)?;
        validate_config_version(&self.config_version, "cache_key.config_version")
            .map_err(AuthorizationError::InvalidRequest)
    }

    fn matches_binding(&self, binding: &AuthorizationBinding) -> bool {
        self.product_id == binding.product_id
            && self.software_id == binding.identity.software_id
            && self.profile_id == binding.identity.profile_id
            && self.client_id == binding.identity.client_id
            && self.device_scope == binding.identity.device_scope
            && self.device_id == binding.identity.device_id
    }

    fn same_idempotency_scope(&self, other: &Self) -> bool {
        self.product_id == other.product_id
            && self.software_id == other.software_id
            && self.profile_id == other.profile_id
            && self.client_id == other.client_id
            && self.device_scope == other.device_scope
            && self.device_id == other.device_id
            && self.contract_version == other.contract_version
            && self.target == other.target
            && self.arch == other.arch
            && self.channel == other.channel
            && self.config_version == other.config_version
    }

    fn same_authorization_scope(&self, other: &Self) -> bool {
        self.product_id == other.product_id
            && self.authorization_id == other.authorization_id
            && self.software_id == other.software_id
            && self.profile_id == other.profile_id
            && self.client_id == other.client_id
            && self.device_scope == other.device_scope
            && self.device_id == other.device_id
            && self.contract_version == other.contract_version
            && self.target == other.target
            && self.arch == other.arch
            && self.channel == other.channel
    }
}

pub(crate) fn validate_config_version(value: &str, field: &str) -> Result<(), String> {
    validate_short_text(value, field)?;
    if value.chars().count() > AUTHORIZATION_CONFIG_VERSION_MAX_CHARS {
        return Err(format!(
            "{field} must be at most {AUTHORIZATION_CONFIG_VERSION_MAX_CHARS} characters"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedAuthorization {
    response: AuthorizationResponseV1,
    canonical_payload: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationCache {
    entries: BTreeMap<AuthorizationCacheKey, CachedAuthorization>,
    request_results: BTreeMap<(AuthorizationCacheKey, String), String>,
    last_seen_server_time: BTreeMap<AuthorizationCacheKey, u64>,
}

impl AuthorizationCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_seen_server_time_for(&self, binding: &AuthorizationBinding) -> Option<u64> {
        self.last_seen_server_time
            .iter()
            .filter(|(key, _)| key.matches_binding(binding))
            .map(|(_, value)| *value)
            .max()
    }

    pub fn get(&self, key: &AuthorizationCacheKey) -> Option<&AuthorizationResponseV1> {
        self.entries.get(key).map(|entry| &entry.response)
    }

    pub(crate) fn responses(&self) -> impl Iterator<Item = &AuthorizationResponseV1> {
        self.entries.values().map(|entry| &entry.response)
    }

    pub(crate) fn persistence_request_records(&self) -> Vec<AuthorizationCacheRequestRecord> {
        self.request_results
            .iter()
            .map(
                |((key, request_id), canonical_payload)| AuthorizationCacheRequestRecord {
                    key: key.clone(),
                    request_id: request_id.clone(),
                    canonical_payload: canonical_payload.clone(),
                },
            )
            .collect()
    }

    pub(crate) fn persistence_watermarks(&self) -> Vec<AuthorizationCacheWatermark> {
        self.last_seen_server_time
            .iter()
            .map(|(key, server_time)| AuthorizationCacheWatermark {
                key: key.clone(),
                server_time: *server_time,
            })
            .collect()
    }

    pub(crate) fn restore_persistence_metadata(
        &mut self,
        request_records: Vec<AuthorizationCacheRequestRecord>,
        watermarks: Vec<AuthorizationCacheWatermark>,
        binding: &AuthorizationBinding,
    ) -> Result<(), AuthorizationError> {
        for record in request_records {
            record.key.validate()?;
            if !record.key.matches_binding(binding) {
                return Err(AuthorizationError::BindingMismatch {
                    field: "cache.request_record.scope".to_string(),
                    expected: format_identity(&binding.identity),
                    actual: format!("{}:{}", record.key.product_id, record.key.client_id),
                });
            }
            if !self.entries.contains_key(&record.key) {
                return Err(AuthorizationError::InvalidRequest(
                    "cache request record has no matching authorization response".to_string(),
                ));
            }
            validate_opaque_identifier(&record.request_id, "cache.request_record.request_id")
                .map_err(AuthorizationError::InvalidRequest)?;
            if record.canonical_payload.trim().is_empty() {
                return Err(AuthorizationError::InvalidRequest(
                    "cache.request_record.canonical_payload cannot be empty".to_string(),
                ));
            }
            if let Some(field) = contains_request_only_field(&record.canonical_payload) {
                return Err(AuthorizationError::InvalidRequest(format!(
                    "cache.request_record.canonical_payload cannot contain request-only field {field}"
                )));
            }
            let request_key = (record.key.clone(), record.request_id.clone());
            if let Some(previous) = self.request_results.get(&request_key) {
                if previous != &record.canonical_payload {
                    return Err(AuthorizationError::RequestConflict {
                        request_id: record.request_id,
                    });
                }
                continue;
            }
            let scope_count = self
                .request_results
                .keys()
                .filter(|(key, _)| key.same_idempotency_scope(&record.key))
                .count();
            if scope_count >= MAX_REQUEST_IDEMPOTENCY_RECORDS {
                return Err(AuthorizationError::InvalidRequest(
                    "request idempotency journal reached its per-scope bound".to_string(),
                ));
            }
            self.request_results
                .insert(request_key, record.canonical_payload);
        }

        for watermark in watermarks {
            watermark.key.validate()?;
            if !watermark.key.matches_binding(binding) {
                return Err(AuthorizationError::BindingMismatch {
                    field: "cache.watermark.scope".to_string(),
                    expected: format_identity(&binding.identity),
                    actual: format!("{}:{}", watermark.key.product_id, watermark.key.client_id),
                });
            }
            let response = self.entries.get(&watermark.key).ok_or_else(|| {
                AuthorizationError::InvalidRequest(
                    "cache watermark has no matching authorization response".to_string(),
                )
            })?;
            if watermark.server_time < response.response.server_time {
                return Err(AuthorizationError::ServerTimeRollback {
                    last_seen: response.response.server_time,
                    received: watermark.server_time,
                });
            }
            if let Some(previous) = self.last_seen_server_time.get(&watermark.key) {
                if watermark.server_time < *previous {
                    return Err(AuthorizationError::ServerTimeRollback {
                        last_seen: *previous,
                        received: watermark.server_time,
                    });
                }
            }
            self.last_seen_server_time
                .insert(watermark.key, watermark.server_time);
        }
        Ok(())
    }

    pub fn apply<V: IntegrityVerifier>(
        &mut self,
        response: AuthorizationResponseV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<CacheApplyOutcome, AuthorizationError> {
        response.validate_for_binding(manifest, binding)?;
        response.validate_for_manifest(manifest)?;
        response.verify(verifier)?;

        let key = AuthorizationCacheKey::from_response(&response);
        key.validate()?;
        let response_server_time = response.server_time;

        let authority_last_seen = self
            .last_seen_server_time
            .iter()
            .filter(|(existing_key, _)| existing_key.same_authorization_scope(&key))
            .map(|(_, server_time)| *server_time)
            .max()
            .unwrap_or_default();
        if authority_last_seen > 0 {
            if response.server_time < authority_last_seen {
                return Err(AuthorizationError::ServerTimeRollback {
                    last_seen: authority_last_seen,
                    received: response.server_time,
                });
            }
        }
        let canonical_payload = response.canonical_payload();
        let request_key = (key.clone(), response.request_id.clone());
        if let Some(previous) = self.request_results.get(&request_key) {
            if previous == &canonical_payload {
                let current = self
                    .last_seen_server_time
                    .get(&key)
                    .copied()
                    .unwrap_or_default();
                self.last_seen_server_time
                    .insert(key.clone(), current.max(response_server_time));
                return Ok(CacheApplyOutcome::Idempotent);
            }
            return Err(AuthorizationError::RequestConflict {
                request_id: response.request_id,
            });
        }

        let authority_revision = self
            .entries
            .iter()
            .filter(|(existing_key, _)| existing_key.same_authorization_scope(&key))
            .map(|(_, entry)| entry.response.authorization_revision)
            .max()
            .unwrap_or_default();
        if response.authorization_revision < authority_revision {
            return Err(AuthorizationError::StaleRevision {
                current: authority_revision,
                received: response.authorization_revision,
            });
        }

        if let Some(previous) = self.entries.get(&key) {
            if response.authorization_revision < previous.response.authorization_revision {
                return Err(AuthorizationError::StaleRevision {
                    current: previous.response.authorization_revision,
                    received: response.authorization_revision,
                });
            }
            if response.decision != LicenseState::NotModified
                && response.authorization_revision == previous.response.authorization_revision
                && previous.canonical_payload != canonical_payload
            {
                return Err(AuthorizationError::RequestConflict {
                    request_id: response.request_id,
                });
            }
        }

        if response.decision == LicenseState::NotModified {
            let previous = self.entries.get(&key).ok_or_else(|| {
                AuthorizationError::InvalidRequest(
                    "not_modified requires an existing cached authorization".to_string(),
                )
            })?;
            if !matches!(
                previous.response.decision,
                LicenseState::Active | LicenseState::Grace
            ) {
                return Err(AuthorizationError::InvalidRequest(
                    "not_modified cannot restore a non-launchable authorization".to_string(),
                ));
            }
            if response.authorization_revision != previous.response.authorization_revision {
                return Err(AuthorizationError::InvalidRequest(
                    "not_modified authorization_revision must match the cached authorization"
                        .to_string(),
                ));
            }
            let scope_count = self
                .request_results
                .keys()
                .filter(|(existing_key, _)| existing_key.same_idempotency_scope(&key))
                .count();
            if scope_count >= MAX_REQUEST_IDEMPOTENCY_RECORDS {
                return Err(AuthorizationError::InvalidRequest(
                    "request idempotency journal reached its per-scope bound".to_string(),
                ));
            }
            self.request_results.insert(request_key, canonical_payload);
            let current = self
                .last_seen_server_time
                .get(&key)
                .copied()
                .unwrap_or_default();
            self.last_seen_server_time
                .insert(key, current.max(response_server_time));
            return Ok(CacheApplyOutcome::NotModified);
        }

        let scope_count = self
            .request_results
            .keys()
            .filter(|(existing_key, _)| existing_key.same_idempotency_scope(&key))
            .count();
        if scope_count >= MAX_REQUEST_IDEMPOTENCY_RECORDS {
            return Err(AuthorizationError::InvalidRequest(
                "request idempotency journal reached its per-scope bound".to_string(),
            ));
        }

        self.entries
            .retain(|existing_key, _| !existing_key.same_authorization_scope(&key));
        self.request_results
            .retain(|(existing_key, _), _| !existing_key.same_authorization_scope(&key));
        self.last_seen_server_time
            .retain(|existing_key, _| !existing_key.same_authorization_scope(&key));

        self.request_results
            .insert(request_key, canonical_payload.clone());
        self.entries.insert(
            key.clone(),
            CachedAuthorization {
                response,
                canonical_payload,
            },
        );
        self.last_seen_server_time
            .insert(key, authority_last_seen.max(response_server_time));
        Ok(CacheApplyOutcome::Stored)
    }

    pub fn clear_binding(&mut self, binding: &AuthorizationBinding) {
        self.entries.retain(|key, _| !key.matches_binding(binding));
        self.last_seen_server_time
            .retain(|key, _| !key.matches_binding(binding));
        self.request_results
            .retain(|(key, _), _| !key.matches_binding(binding));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerTimeWatermark {
    last_seen_server_time: Option<u64>,
}

impl ServerTimeWatermark {
    pub fn last_seen_server_time(&self) -> Option<u64> {
        self.last_seen_server_time
    }

    pub fn observe(&mut self, server_time: u64) -> Result<(), AuthorizationError> {
        if let Some(last_seen) = self.last_seen_server_time {
            if server_time < last_seen {
                return Err(AuthorizationError::ServerTimeRollback {
                    last_seen,
                    received: server_time,
                });
            }
        }
        self.last_seen_server_time = Some(
            self.last_seen_server_time
                .unwrap_or_default()
                .max(server_time),
        );
        Ok(())
    }
}

fn format_identity(identity: &AuthorizationIdentity) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        identity.software_id,
        identity.profile_id,
        identity.client_id,
        identity.device_scope,
        identity.device_id
    )
}

fn state_code_for(state: LicenseState) -> &'static str {
    match state {
        LicenseState::Active => "AUTH_ACTIVE",
        LicenseState::Grace => "AUTH_GRACE",
        LicenseState::Expired => "AUTH_EXPIRED",
        LicenseState::Revoked => "AUTH_REVOKED",
        LicenseState::Blocked => "AUTH_BLOCKED",
        LicenseState::NotModified => "AUTH_NOT_MODIFIED",
        LicenseState::Unavailable => "AUTH_UNAVAILABLE",
    }
}

fn map_platform_response_shape_error(error: AuthorizationError) -> AuthorizationError {
    match error {
        AuthorizationError::Integrity(integrity) => AuthorizationError::Integrity(integrity),
        AuthorizationError::ResponseSchemaInvalid(message) => {
            AuthorizationError::ResponseSchemaInvalid(message)
        }
        other => AuthorizationError::ResponseSchemaInvalid(other.to_string()),
    }
}

pub(crate) fn authorization_to_json_value(response: &AuthorizationResponseV1) -> JsonValue {
    let capabilities = response
        .capabilities
        .iter()
        .cloned()
        .map(JsonValue::String)
        .collect();
    let modules = response
        .modules
        .iter()
        .map(authorization_module_to_json_value)
        .collect();
    let mut object = BTreeMap::new();
    object.insert("capabilities".to_string(), JsonValue::Array(capabilities));
    object.insert(
        "client_id".to_string(),
        JsonValue::String(response.identity.client_id.clone()),
    );
    object.insert(
        "authorization_id".to_string(),
        JsonValue::String(response.authorization_id.clone()),
    );
    object.insert("arch".to_string(), JsonValue::String(response.arch.clone()));
    object.insert(
        "cache_until".to_string(),
        response
            .cache_until
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "channel".to_string(),
        JsonValue::String(response.channel.clone()),
    );
    object.insert(
        "config_version".to_string(),
        JsonValue::String(response.config_version.clone()),
    );
    object.insert(
        "contract_version".to_string(),
        JsonValue::String(response.contract_version.clone()),
    );
    object.insert(
        "decision".to_string(),
        JsonValue::String(response.decision.as_str().to_string()),
    );
    object.insert(
        "device_id".to_string(),
        JsonValue::String(response.identity.device_id.clone()),
    );
    object.insert(
        "device_scope".to_string(),
        response
            .structured_device_scope
            .as_ref()
            .map(|scope| device_scope_to_json_value(&DeviceScopeV1::Structured(scope.clone())))
            .unwrap_or_else(|| JsonValue::String(response.identity.device_scope.clone())),
    );
    object.insert(
        "expires_at".to_string(),
        response
            .expires_at
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "integrity".to_string(),
        integrity_to_json_value(&response.integrity),
    );
    object.insert(
        "issued_at".to_string(),
        JsonValue::Number(response.issued_at),
    );
    object.insert("modules".to_string(), JsonValue::Array(modules));
    object.insert(
        "grace_until".to_string(),
        response
            .grace_until
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "next_verify_at".to_string(),
        response
            .next_verify_at
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "product_id".to_string(),
        JsonValue::String(response.product_id.clone()),
    );
    object.insert(
        "profile_id".to_string(),
        JsonValue::String(response.identity.profile_id.clone()),
    );
    object.insert(
        "protocol".to_string(),
        JsonValue::String(response.protocol.clone()),
    );
    object.insert(
        "request_id".to_string(),
        JsonValue::String(response.request_id.clone()),
    );
    object.insert(
        "schema_version".to_string(),
        JsonValue::String(response.schema_version.clone()),
    );
    object.insert(
        "server_time".to_string(),
        JsonValue::Number(response.server_time),
    );
    object.insert(
        "software_id".to_string(),
        JsonValue::String(response.identity.software_id.clone()),
    );
    object.insert(
        "snapshot_id".to_string(),
        JsonValue::String(response.snapshot_id.clone()),
    );
    object.insert(
        "state_code".to_string(),
        JsonValue::String(response.state_code.clone()),
    );
    object.insert(
        "target".to_string(),
        JsonValue::String(response.target.clone()),
    );
    object.insert(
        "authorization_revision".to_string(),
        JsonValue::Number(response.authorization_revision),
    );
    JsonValue::Object(object)
}

fn authorization_identity_to_json_value(identity: &AuthorizationIdentity) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "client_id".to_string(),
        JsonValue::String(identity.client_id.clone()),
    );
    object.insert(
        "device_id".to_string(),
        JsonValue::String(identity.device_id.clone()),
    );
    object.insert(
        "device_scope".to_string(),
        JsonValue::String(identity.device_scope.clone()),
    );
    object.insert(
        "profile_id".to_string(),
        JsonValue::String(identity.profile_id.clone()),
    );
    object.insert(
        "software_id".to_string(),
        JsonValue::String(identity.software_id.clone()),
    );
    JsonValue::Object(object)
}

fn authorization_identity_from_json_value(
    value: JsonValue,
) -> Result<AuthorizationIdentity, String> {
    let object =
        json_object(&value, "authorization identity").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &[
            "software_id",
            "profile_id",
            "client_id",
            "device_scope",
            "device_id",
        ],
        "authorization identity",
    )
    .map_err(|error| error.to_string())?;
    Ok(AuthorizationIdentity::new(
        required_text(object, "software_id", "identity.software_id")?,
        required_text(object, "profile_id", "identity.profile_id")?,
        required_text(object, "client_id", "identity.client_id")?,
        required_text(object, "device_scope", "identity.device_scope")?,
        required_text(object, "device_id", "identity.device_id")?,
    ))
}

pub(crate) fn authorization_error_to_json_value(error: &AuthorizationErrorResponseV1) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "client_id".to_string(),
        JsonValue::String(error.identity.client_id.clone()),
    );
    object.insert(
        "contract_version".to_string(),
        JsonValue::String(error.contract_version.clone()),
    );
    object.insert(
        "device_id".to_string(),
        JsonValue::String(error.identity.device_id.clone()),
    );
    object.insert(
        "device_scope".to_string(),
        JsonValue::String(error.identity.device_scope.clone()),
    );
    object.insert(
        "error_code".to_string(),
        JsonValue::String(error.error_code.clone()),
    );
    object.insert(
        "integrity".to_string(),
        integrity_to_json_value(&error.integrity),
    );
    object.insert(
        "message".to_string(),
        JsonValue::String(error.message.clone()),
    );
    object.insert(
        "product_id".to_string(),
        JsonValue::String(error.product_id.clone()),
    );
    object.insert(
        "profile_id".to_string(),
        JsonValue::String(error.identity.profile_id.clone()),
    );
    object.insert(
        "protocol".to_string(),
        JsonValue::String(error.protocol.clone()),
    );
    object.insert(
        "request_id".to_string(),
        JsonValue::String(error.request_id.clone()),
    );
    object.insert("retryable".to_string(), JsonValue::Bool(error.retryable));
    object.insert(
        "schema_version".to_string(),
        JsonValue::String(error.schema_version.clone()),
    );
    object.insert(
        "server_time".to_string(),
        JsonValue::Number(error.server_time),
    );
    object.insert(
        "software_id".to_string(),
        JsonValue::String(error.identity.software_id.clone()),
    );
    JsonValue::Object(object)
}

pub(crate) fn authorization_error_from_json_value(
    value: JsonValue,
) -> Result<AuthorizationErrorResponseV1, String> {
    let object = json_object(&value, "authorization error").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &[
            "protocol",
            "schema_version",
            "contract_version",
            "request_id",
            "product_id",
            "software_id",
            "profile_id",
            "client_id",
            "device_scope",
            "device_id",
            "error_code",
            "message",
            "retryable",
            "server_time",
            "integrity",
        ],
        "authorization error",
    )
    .map_err(|error| error.to_string())?;
    let integrity_object = json_object(
        json_required(object, "integrity", "error.integrity").map_err(|error| error.to_string())?,
        "error.integrity",
    )
    .map_err(|error| error.to_string())?;
    ensure_known_fields(
        integrity_object,
        &[
            "algorithm",
            "key_id",
            "canonicalization",
            "signature",
            "origin",
            "audience",
        ],
        "error.integrity",
    )
    .map_err(|error| error.to_string())?;
    let integrity = IntegrityProof::new(
        json_required_string(integrity_object, "algorithm", "integrity.algorithm")
            .map_err(|error| error.to_string())?,
        json_required_string(integrity_object, "key_id", "integrity.key_id")
            .map_err(|error| error.to_string())?,
        json_required_string(
            integrity_object,
            "canonicalization",
            "integrity.canonicalization",
        )
        .map_err(|error| error.to_string())?,
        json_required_string(integrity_object, "signature", "integrity.signature")
            .map_err(|error| error.to_string())?,
    )
    .with_origin_audience(
        json_required_string(integrity_object, "origin", "integrity.origin")
            .map_err(|error| error.to_string())?,
        json_required_string(integrity_object, "audience", "integrity.audience")
            .map_err(|error| error.to_string())?,
    );
    let retryable = match json_required(object, "retryable", "error.retryable")
        .map_err(|error| error.to_string())?
    {
        JsonValue::Bool(value) => *value,
        _ => return Err("error.retryable must be a boolean".to_string()),
    };
    Ok(AuthorizationErrorResponseV1 {
        protocol: required_text(object, "protocol", "error.protocol")?,
        schema_version: required_text(object, "schema_version", "error.schema_version")?,
        contract_version: required_text(object, "contract_version", "error.contract_version")?,
        request_id: required_text(object, "request_id", "error.request_id")?,
        product_id: required_text(object, "product_id", "error.product_id")?,
        identity: AuthorizationIdentity::new(
            required_text(object, "software_id", "error.software_id")?,
            required_text(object, "profile_id", "error.profile_id")?,
            required_text(object, "client_id", "error.client_id")?,
            required_text(object, "device_scope", "error.device_scope")?,
            required_text(object, "device_id", "error.device_id")?,
        ),
        error_code: required_text(object, "error_code", "error.error_code")?,
        message: required_text(object, "message", "error.message")?,
        retryable,
        server_time: required_number(object, "server_time")?,
        integrity,
    })
}

pub(crate) fn authorization_request_to_json_value(request: &AuthorizationRequestV1) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "contract_version".to_string(),
        JsonValue::String(request.contract_version.clone()),
    );
    object.insert(
        "identity".to_string(),
        authorization_identity_to_json_value(&request.identity),
    );
    object.insert("arch".to_string(), JsonValue::String(request.arch.clone()));
    object.insert(
        "channel".to_string(),
        JsonValue::String(request.channel.clone()),
    );
    object.insert(
        "config_version".to_string(),
        JsonValue::String(request.config_version.clone()),
    );
    object.insert(
        "client_version".to_string(),
        JsonValue::String(request.client_version.clone()),
    );
    object.insert(
        "device_public_key".to_string(),
        JsonValue::String(request.device_public_key.clone()),
    );
    if let Some(device_proof) = &request.device_proof {
        object.insert(
            "device_proof".to_string(),
            JsonValue::String(device_proof.clone()),
        );
    }
    object.insert(
        "installation_id".to_string(),
        JsonValue::String(request.installation_id.clone()),
    );
    object.insert(
        "known_authorization_revision".to_string(),
        request
            .known_authorization_revision
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "operation".to_string(),
        JsonValue::String(request.operation.clone()),
    );
    object.insert(
        "product_id".to_string(),
        JsonValue::String(request.product_id.clone()),
    );
    object.insert(
        "protocol".to_string(),
        JsonValue::String(request.protocol.clone()),
    );
    object.insert(
        "request_id".to_string(),
        JsonValue::String(request.request_id.clone()),
    );
    object.insert(
        "schema_version".to_string(),
        JsonValue::String(request.schema_version.clone()),
    );
    object.insert(
        "target".to_string(),
        JsonValue::String(request.target.clone()),
    );
    object.insert(
        "nonce".to_string(),
        JsonValue::String(request.nonce.clone()),
    );
    JsonValue::Object(object)
}

pub(crate) fn authorization_request_from_json_value(
    value: JsonValue,
) -> Result<AuthorizationRequestV1, String> {
    let object = json_object(&value, "authorization request").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &[
            "protocol",
            "schema_version",
            "contract_version",
            "request_id",
            "operation",
            "product_id",
            "identity",
            "target",
            "arch",
            "channel",
            "config_version",
            "known_authorization_revision",
            "device_public_key",
            "device_proof",
            "installation_id",
            "client_version",
            "nonce",
        ],
        "authorization request",
    )
    .map_err(|error| error.to_string())?;
    let identity = authorization_identity_from_json_value(
        json_required(object, "identity", "authorization.identity")
            .map_err(|error| error.to_string())?
            .clone(),
    )?;
    let device_proof = match object.get("device_proof") {
        None => None,
        Some(JsonValue::String(value)) => Some(value.clone()),
        Some(_) => return Err("authorization.device_proof must be a string".to_string()),
    };
    let known_authorization_revision = match object.get("known_authorization_revision") {
        None => None,
        Some(_) => optional_number(
            object,
            "known_authorization_revision",
            "authorization.known_authorization_revision",
        )?,
    };
    Ok(AuthorizationRequestV1 {
        protocol: required_text(object, "protocol", "authorization.protocol")?,
        schema_version: required_text(object, "schema_version", "authorization.schema_version")?,
        contract_version: required_text(
            object,
            "contract_version",
            "authorization.contract_version",
        )?,
        request_id: required_text(object, "request_id", "authorization.request_id")?,
        operation: required_text(object, "operation", "authorization.operation")?,
        product_id: required_text(object, "product_id", "authorization.product_id")?,
        identity,
        target: required_text(object, "target", "authorization.target")?,
        arch: required_text(object, "arch", "authorization.arch")?,
        channel: required_text(object, "channel", "authorization.channel")?,
        config_version: required_text(object, "config_version", "authorization.config_version")?,
        known_authorization_revision,
        device_public_key: required_text(
            object,
            "device_public_key",
            "authorization.device_public_key",
        )?,
        device_proof,
        installation_id: required_text(object, "installation_id", "authorization.installation_id")?,
        client_version: required_text(object, "client_version", "authorization.client_version")?,
        nonce: required_text(object, "nonce", "authorization.nonce")?,
    })
}

fn authorization_claims_to_json_value(response: &AuthorizationResponseV1) -> JsonValue {
    let mut value = match authorization_to_json_value(response) {
        JsonValue::Object(object) => object,
        _ => unreachable!("authorization serializer always returns an object"),
    };
    if let Some(JsonValue::Object(mut integrity)) = value.remove("integrity") {
        integrity.remove("signature");
        value.insert("integrity".to_string(), JsonValue::Object(integrity));
    }
    JsonValue::Object(value)
}

fn authorization_module_to_json_value(module: &AuthorizationModuleV1) -> JsonValue {
    let payload = module
        .payload
        .iter()
        .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
        .collect();
    let mut object = BTreeMap::new();
    object.insert(
        "authorization_revision".to_string(),
        JsonValue::Number(module.authorization_revision),
    );
    object.insert(
        "authorization_id".to_string(),
        JsonValue::String(module.authorization_id.clone()),
    );
    object.insert(
        "capability".to_string(),
        JsonValue::String(module.capability.clone()),
    );
    object.insert(
        "client_id".to_string(),
        JsonValue::String(module.client_id.clone()),
    );
    object.insert(
        "config_version".to_string(),
        JsonValue::String(module.config_version.clone()),
    );
    object.insert(
        "device_id".to_string(),
        JsonValue::String(module.device_id.clone()),
    );
    object.insert(
        "device_scope".to_string(),
        module
            .structured_device_scope
            .as_ref()
            .map(|scope| device_scope_to_json_value(&DeviceScopeV1::Structured(scope.clone())))
            .unwrap_or_else(|| JsonValue::String(module.device_scope.clone())),
    );
    object.insert(
        "module_id".to_string(),
        JsonValue::String(module.module_id.clone()),
    );
    object.insert(
        "module_type".to_string(),
        JsonValue::String(module.module_type.clone()),
    );
    object.insert("payload".to_string(), JsonValue::Object(payload));
    object.insert(
        "product_id".to_string(),
        JsonValue::String(module.product_id.clone()),
    );
    object.insert(
        "profile_id".to_string(),
        JsonValue::String(module.profile_id.clone()),
    );
    object.insert(
        "software_id".to_string(),
        JsonValue::String(module.software_id.clone()),
    );
    object.insert(
        "version".to_string(),
        JsonValue::String(module.version.clone()),
    );
    JsonValue::Object(object)
}

pub(crate) fn authorization_from_json_value(
    value: JsonValue,
) -> Result<AuthorizationResponseV1, String> {
    let object =
        json_object(&value, "authorization response").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &[
            "protocol",
            "schema_version",
            "contract_version",
            "request_id",
            "product_id",
            "software_id",
            "profile_id",
            "client_id",
            "device_scope",
            "device_id",
            "authorization_id",
            "target",
            "arch",
            "channel",
            "authorization_revision",
            "config_version",
            "snapshot_id",
            "decision",
            "state_code",
            "issued_at",
            "expires_at",
            "server_time",
            "cache_until",
            "next_verify_at",
            "grace_until",
            "integrity",
            "capabilities",
            "modules",
        ],
        "authorization response",
    )
    .map_err(|error| error.to_string())?;
    let capabilities = json_array(
        json_required(object, "capabilities", "authorization.capabilities")
            .map_err(|error| error.to_string())?,
        "authorization.capabilities",
    )
    .map_err(|error| error.to_string())?
    .iter()
    .enumerate()
    .map(|(index, value)| {
        json_string(value, &format!("authorization.capabilities[{index}]"))
            .map(str::to_string)
            .map_err(|error| error.to_string())
    })
    .collect::<Result<Vec<_>, _>>()?;
    let modules = json_array(
        json_required(object, "modules", "authorization.modules")
            .map_err(|error| error.to_string())?,
        "authorization.modules",
    )
    .map_err(|error| error.to_string())?
    .iter()
    .cloned()
    .map(authorization_module_from_json_value)
    .collect::<Result<Vec<_>, _>>()?;
    let expires_at = optional_number(object, "expires_at", "authorization.expires_at")?;
    let cache_until = optional_number(object, "cache_until", "authorization.cache_until")?;
    let next_verify_at = optional_number(object, "next_verify_at", "authorization.next_verify_at")?;
    let grace_until = optional_number(object, "grace_until", "authorization.grace_until")?;
    let decision = LicenseState::from_str(
        json_required_string(object, "decision", "authorization.decision")
            .map_err(|error| error.to_string())?,
    )
    .ok_or_else(|| "authorization.decision contains an unknown value".to_string())?;
    let integrity_object = json_object(
        json_required(object, "integrity", "authorization.integrity")
            .map_err(|error| error.to_string())?,
        "authorization.integrity",
    )
    .map_err(|error| error.to_string())?;
    ensure_known_fields(
        integrity_object,
        &[
            "algorithm",
            "key_id",
            "canonicalization",
            "signature",
            "origin",
            "audience",
        ],
        "authorization.integrity",
    )
    .map_err(|error| error.to_string())?;
    let integrity = IntegrityProof::new(
        json_required_string(integrity_object, "algorithm", "integrity.algorithm")
            .map_err(|error| error.to_string())?,
        json_required_string(integrity_object, "key_id", "integrity.key_id")
            .map_err(|error| error.to_string())?,
        json_required_string(
            integrity_object,
            "canonicalization",
            "integrity.canonicalization",
        )
        .map_err(|error| error.to_string())?,
        json_required_string(integrity_object, "signature", "integrity.signature")
            .map_err(|error| error.to_string())?,
    )
    .with_origin_audience(
        json_required_string(integrity_object, "origin", "integrity.origin")
            .map_err(|error| error.to_string())?,
        json_required_string(integrity_object, "audience", "integrity.audience")
            .map_err(|error| error.to_string())?,
    );
    let device_id = required_text(object, "device_id", "authorization.device_id")?;
    let device_scope_wire = device_scope_from_json_value(
        json_required(object, "device_scope", "authorization.device_scope")
            .map_err(|error| error.to_string())?
            .clone(),
        "authorization.device_scope",
    )?;
    let (device_scope, structured_device_scope) = match device_scope_wire {
        DeviceScopeV1::Legacy(scope) => (scope, None),
        DeviceScopeV1::Structured(scope) => {
            if let Some(confirmed_device_id) = &scope.device_id {
                if confirmed_device_id != &device_id {
                    return Err(
                        "authorization.device_scope.device_id must match authorization.device_id"
                            .to_string(),
                    );
                }
            }
            if scope.scope != "current_device" {
                return Err("authorization.device_scope.scope must be current_device".to_string());
            }
            (scope.scope.clone(), Some(scope))
        }
    };
    Ok(AuthorizationResponseV1 {
        protocol: required_text(object, "protocol", "authorization.protocol")?,
        schema_version: required_text(object, "schema_version", "authorization.schema_version")?,
        contract_version: required_text(
            object,
            "contract_version",
            "authorization.contract_version",
        )?,
        request_id: required_text(object, "request_id", "authorization.request_id")?,
        product_id: required_text(object, "product_id", "authorization.product_id")?,
        identity: AuthorizationIdentity::new(
            required_text(object, "software_id", "authorization.software_id")?,
            required_text(object, "profile_id", "authorization.profile_id")?,
            required_text(object, "client_id", "authorization.client_id")?,
            device_scope,
            device_id,
        ),
        structured_device_scope,
        authorization_id: required_text(
            object,
            "authorization_id",
            "authorization.authorization_id",
        )?,
        target: required_text(object, "target", "authorization.target")?,
        arch: required_text(object, "arch", "authorization.arch")?,
        channel: required_text(object, "channel", "authorization.channel")?,
        authorization_revision: required_number(object, "authorization_revision")?,
        config_version: required_text(object, "config_version", "authorization.config_version")?,
        snapshot_id: required_text(object, "snapshot_id", "authorization.snapshot_id")?,
        state_code: required_text(object, "state_code", "authorization.state_code")?,
        decision,
        issued_at: required_number(object, "issued_at")?,
        expires_at,
        server_time: required_number(object, "server_time")?,
        cache_until,
        next_verify_at,
        grace_until,
        integrity,
        capabilities,
        modules,
    })
}

fn authorization_module_from_json_value(value: JsonValue) -> Result<AuthorizationModuleV1, String> {
    let object = json_object(&value, "authorization module").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &[
            "authorization_id",
            "authorization_revision",
            "capability",
            "client_id",
            "config_version",
            "device_id",
            "device_scope",
            "module_id",
            "module_type",
            "payload",
            "product_id",
            "profile_id",
            "software_id",
            "version",
        ],
        "authorization module",
    )
    .map_err(|error| error.to_string())?;
    let payload_object = json_object(
        json_required(object, "payload", "module.payload").map_err(|error| error.to_string())?,
        "module.payload",
    )
    .map_err(|error| error.to_string())?;
    let mut payload = BTreeMap::new();
    for (key, value) in payload_object {
        payload.insert(
            key.clone(),
            json_string(value, &format!("module.payload.{key}"))
                .map(str::to_string)
                .map_err(|error| error.to_string())?,
        );
    }
    let device_id = required_text(object, "device_id", "module.device_id")?;
    let device_scope_wire = device_scope_from_json_value(
        json_required(object, "device_scope", "module.device_scope")
            .map_err(|error| error.to_string())?
            .clone(),
        "module.device_scope",
    )?;
    let (device_scope, structured_device_scope) = match device_scope_wire {
        DeviceScopeV1::Legacy(scope) => (scope, None),
        DeviceScopeV1::Structured(scope) => {
            let confirmed_device_id = scope
                .device_id
                .as_ref()
                .ok_or_else(|| "module.device_scope.device_id must be confirmed".to_string())?;
            if confirmed_device_id != &device_id {
                return Err("module.device_scope.device_id must match module.device_id".to_string());
            }
            (scope.scope.clone(), Some(scope))
        }
    };
    Ok(AuthorizationModuleV1 {
        product_id: required_text(object, "product_id", "module.product_id")?,
        authorization_id: required_text(object, "authorization_id", "module.authorization_id")?,
        software_id: required_text(object, "software_id", "module.software_id")?,
        profile_id: required_text(object, "profile_id", "module.profile_id")?,
        client_id: required_text(object, "client_id", "module.client_id")?,
        device_scope,
        device_id,
        module_id: required_text(object, "module_id", "module.module_id")?,
        module_type: required_text(object, "module_type", "module.module_type")?,
        version: required_text(object, "version", "module.version")?,
        capability: required_text(object, "capability", "module.capability")?,
        config_version: required_text(object, "config_version", "module.config_version")?,
        authorization_revision: required_number(object, "authorization_revision")?,
        payload,
        structured_device_scope,
    })
}

fn structured_device_scope_to_json_value(scope: &StructuredDeviceScopeV1) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "device_id".to_string(),
        match &scope.device_id {
            Some(value) => JsonValue::String(value.clone()),
            None => JsonValue::Null,
        },
    );
    object.insert(
        "installation_id".to_string(),
        match &scope.installation_id {
            Some(value) => JsonValue::String(value.clone()),
            None => JsonValue::Null,
        },
    );
    object.insert("scope".to_string(), JsonValue::String(scope.scope.clone()));
    JsonValue::Object(object)
}

fn device_scope_to_json_value(scope: &DeviceScopeV1) -> JsonValue {
    match scope {
        DeviceScopeV1::Legacy(value) => JsonValue::String(value.clone()),
        DeviceScopeV1::Structured(value) => structured_device_scope_to_json_value(value),
    }
}

fn structured_device_scope_from_json_value(
    value: JsonValue,
    field: &str,
) -> Result<StructuredDeviceScopeV1, String> {
    let object = json_object(&value, field).map_err(|error| error.to_string())?;
    ensure_known_fields(object, &["scope", "device_id", "installation_id"], field)
        .map_err(|error| error.to_string())?;
    let scope = required_text(object, "scope", &format!("{field}.scope"))?;
    let device_id = optional_nullable_text(object, "device_id", &format!("{field}.device_id"))?;
    let installation_id = optional_nullable_text(
        object,
        "installation_id",
        &format!("{field}.installation_id"),
    )?;
    let scope = StructuredDeviceScopeV1 {
        scope,
        device_id,
        installation_id,
    };
    scope.validate().map_err(|error| error.to_string())?;
    Ok(scope)
}

fn device_scope_from_json_value(value: JsonValue, field: &str) -> Result<DeviceScopeV1, String> {
    let scope = match value {
        JsonValue::String(value) => DeviceScopeV1::Legacy(value),
        JsonValue::Object(object) => DeviceScopeV1::Structured(
            structured_device_scope_from_json_value(JsonValue::Object(object), field)?,
        ),
        _ => return Err(format!("{field} must be a string or structured object")),
    };
    scope.validate().map_err(|error| error.to_string())?;
    Ok(scope)
}

fn optional_nullable_text(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
) -> Result<Option<String>, String> {
    match json_required(object, key, field).map_err(|error| error.to_string())? {
        JsonValue::Null => Ok(None),
        JsonValue::String(value) => Ok(Some(value.clone())),
        _ => Err(format!("{field} must be a string or null")),
    }
}

fn integrity_to_json_value(proof: &IntegrityProof) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "algorithm".to_string(),
        JsonValue::String(proof.algorithm.clone()),
    );
    object.insert(
        "canonicalization".to_string(),
        JsonValue::String(proof.canonicalization.clone()),
    );
    object.insert(
        "audience".to_string(),
        JsonValue::String(proof.audience.clone()),
    );
    object.insert(
        "key_id".to_string(),
        JsonValue::String(proof.key_id.clone()),
    );
    object.insert(
        "origin".to_string(),
        JsonValue::String(proof.origin.clone()),
    );
    object.insert(
        "signature".to_string(),
        JsonValue::String(proof.signature.clone()),
    );
    JsonValue::Object(object)
}

pub(crate) fn required_text(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
) -> Result<String, String> {
    json_required_string(object, key, field)
        .map(str::to_string)
        .map_err(|error| error.to_string())
}

fn validate_trimmed_opaque_identifier(
    value: &str,
    field: &str,
    max_chars: usize,
) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > max_chars {
        return Err(format!("{field} must contain 1 to {max_chars} characters"));
    }
    if value != value.trim() {
        return Err(format!("{field} must be trimmed before signing"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} contains a control character"));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), String> {
    validate_trimmed_opaque_identifier(value, "nonce", 128)?;
    if value.chars().count() < 8 {
        return Err("nonce must contain at least 8 characters".to_string());
    }
    Ok(())
}

fn validate_base64url_bytes(
    value: &str,
    expected_bytes: usize,
    field: &str,
    max_chars: usize,
) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > max_chars {
        return Err(format!("{field} must contain 1 to {max_chars} characters"));
    }
    if value != value.trim() {
        return Err(format!("{field} must be trimmed before signing"));
    }
    if value.len() % 4 == 1 {
        return Err(format!("{field} has an invalid base64url length"));
    }

    let mut accumulator: u16 = 0;
    let mut bits = 0u8;
    let mut decoded_len = 0usize;
    for byte in value.bytes() {
        let six_bits = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(format!(
                    "{field} must use unpadded base64url characters only"
                ))
            }
        } as u16;
        accumulator = (accumulator << 6) | six_bits;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            decoded_len += 1;
            accumulator &= if bits == 0 { 0 } else { (1u16 << bits) - 1 };
            if decoded_len > expected_bytes {
                return Err(format!(
                    "{field} must decode to exactly {expected_bytes} bytes"
                ));
            }
        }
    }
    if bits > 0 && accumulator != 0 {
        return Err(format!("{field} has non-canonical trailing base64url bits"));
    }
    if decoded_len != expected_bytes {
        return Err(format!(
            "{field} must decode to exactly {expected_bytes} bytes"
        ));
    }
    Ok(())
}

pub(crate) fn required_number(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<u64, String> {
    match json_required(object, key, key).map_err(|error| error.to_string())? {
        JsonValue::Number(value) => Ok(*value),
        _ => Err(format!("{key} must be an unsigned integer")),
    }
}

pub(crate) fn optional_number(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
) -> Result<Option<u64>, String> {
    match json_required(object, key, field).map_err(|error| error.to_string())? {
        JsonValue::Null => Ok(None),
        JsonValue::Number(value) => Ok(Some(*value)),
        _ => Err(format!("{field} must be an unsigned integer or null")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_request_json_round_trip_preserves_platform_fields() {
        let binding = AuthorizationBinding::new(
            "sample-product",
            AuthorizationIdentity::new(
                "software-generic",
                "profile-default",
                "client-1",
                "device-scope-1",
                "device-1",
            ),
        );
        let request = AuthorizationRequestV1::new("request-1", &binding, "config-7", Some(6))
            .with_target_arch_channel("windows", "x86_64", "stable");
        let decoded =
            authorization_request_from_json_value(authorization_request_to_json_value(&request))
                .unwrap();
        assert_eq!(decoded, request);
        decoded.validate().unwrap();
    }
}
