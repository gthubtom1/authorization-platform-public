//! Core product-neutral contract types and validation helpers.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use super::profile::ProductManifest;

pub const A_CORE_PROTOCOL_VERSION: &str = "a-core.v1";
pub const PRODUCT_MANIFEST_VERSION: &str = "product-manifest.v1";
pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_SNAPSHOT_MODULES: usize = 64;
pub const MAX_MODULE_PAYLOAD_ENTRIES: usize = 128;
pub const MAX_PROTOCOL_PARAMETERS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    InvalidManifest(String),
    InvalidSnapshot(String),
    InvalidModule(String),
    InvalidAdapter(String),
    DuplicateProductId(String),
    DuplicateStateRoot {
        state_root: String,
        existing_product_id: String,
    },
    DuplicateIpcName {
        ipc_name: String,
        existing_product_id: String,
    },
    ProductNotFound(String),
    ProductMismatch {
        expected: String,
        actual: String,
    },
    ProtocolMismatch {
        expected: String,
        actual: String,
    },
    CapabilityNotDeclared(String),
    RequiredCapabilityMissing(String),
    AdapterMismatch {
        expected: String,
        actual: String,
    },
    AuthorizationRejected {
        product_id: String,
        state: LicenseState,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(message) => write!(f, "invalid product manifest: {message}"),
            Self::InvalidSnapshot(message) => {
                write!(f, "invalid authorization snapshot: {message}")
            }
            Self::InvalidModule(message) => write!(f, "invalid module envelope: {message}"),
            Self::InvalidAdapter(message) => write!(f, "invalid legacy adapter: {message}"),
            Self::DuplicateProductId(product_id) => {
                write!(f, "product id is already registered: {product_id}")
            }
            Self::DuplicateStateRoot {
                state_root,
                existing_product_id,
            } => write!(
                f,
                "state root {state_root} is already owned by product {existing_product_id}"
            ),
            Self::DuplicateIpcName {
                ipc_name,
                existing_product_id,
            } => write!(
                f,
                "IPC name {ipc_name} is already owned by product {existing_product_id}"
            ),
            Self::ProductNotFound(product_id) => {
                write!(f, "product is not registered: {product_id}")
            }
            Self::ProductMismatch { expected, actual } => {
                write!(
                    f,
                    "product mismatch: expected {expected}, received {actual}"
                )
            }
            Self::ProtocolMismatch { expected, actual } => {
                write!(
                    f,
                    "protocol mismatch: expected {expected}, received {actual}"
                )
            }
            Self::CapabilityNotDeclared(capability) => {
                write!(f, "capability is not declared by the product: {capability}")
            }
            Self::RequiredCapabilityMissing(capability) => {
                write!(f, "required capability was not granted: {capability}")
            }
            Self::AdapterMismatch { expected, actual } => {
                write!(
                    f,
                    "adapter mismatch: expected {expected}, received {actual}"
                )
            }
            Self::AuthorizationRejected { product_id, state } => {
                write!(
                    f,
                    "authorization rejected for {product_id}: {}",
                    state.as_str()
                )
            }
        }
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub version: String,
    pub required: bool,
}

impl Capability {
    pub fn new(id: impl Into<String>, version: impl Into<String>, required: bool) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            required,
        }
    }

    pub fn required(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(id, version, true)
    }

    pub fn optional(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(id, version, false)
    }

    pub(crate) fn validate(&self, field_prefix: &str) -> Result<(), ContractError> {
        validate_identifier(&self.id, &format!("{field_prefix}.id"), false)
            .map_err(ContractError::InvalidManifest)?;
        validate_short_text(&self.version, &format!("{field_prefix}.version"))
            .map_err(ContractError::InvalidManifest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum CompatibilityMode {
    NativeCore,
    LegacyAuth,
    WrapperOnly,
}

impl CompatibilityMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeCore => "native_core",
            Self::LegacyAuth => "legacy_auth",
            Self::WrapperOnly => "wrapper_only",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "native_core" => Some(Self::NativeCore),
            "legacy_auth" => Some(Self::LegacyAuth),
            "wrapper_only" => Some(Self::WrapperOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]

pub struct ThemeTokens {
    pub accent: String,
    pub surface: String,
    pub text: String,
    pub danger: String,
}

impl ThemeTokens {
    pub fn new(
        accent: impl Into<String>,
        surface: impl Into<String>,
        text: impl Into<String>,
        danger: impl Into<String>,
    ) -> Self {
        Self {
            accent: accent.into(),
            surface: surface.into(),
            text: text.into(),
            danger: danger.into(),
        }
    }

    pub fn neutral() -> Self {
        Self::new("#2563EB", "#FFFFFF", "#111827", "#DC2626")
    }

    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        for (name, value) in [
            ("accent", &self.accent),
            ("surface", &self.surface),
            ("text", &self.text),
            ("danger", &self.danger),
        ] {
            validate_short_text(value, &format!("theme.{name}"))
                .map_err(ContractError::InvalidManifest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseState {
    Active,
    Grace,
    Expired,
    Revoked,
    Blocked,
    NotModified,
    Unavailable,
}

impl LicenseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Blocked => "blocked",
            Self::NotModified => "not_modified",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "grace" => Some(Self::Grace),
            "expired" => Some(Self::Expired),
            "revoked" => Some(Self::Revoked),
            "blocked" => Some(Self::Blocked),
            "not_modified" => Some(Self::NotModified),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }

    pub const fn allows_launch(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]

pub struct ModuleEnvelope {
    pub protocol: String,
    pub product_id: String,
    pub module_id: String,
    pub version: String,
    pub capability: String,
    pub payload: BTreeMap<String, String>,
}

impl ModuleEnvelope {
    pub fn new(
        product_id: impl Into<String>,
        module_id: impl Into<String>,
        version: impl Into<String>,
        capability: impl Into<String>,
        payload: BTreeMap<String, String>,
    ) -> Self {
        Self {
            protocol: A_CORE_PROTOCOL_VERSION.to_string(),
            product_id: product_id.into(),
            module_id: module_id.into(),
            version: version.into(),
            capability: capability.into(),
            payload,
        }
    }

    pub fn validate_for(&self, manifest: &ProductManifest) -> Result<(), ContractError> {
        if self.protocol != A_CORE_PROTOCOL_VERSION {
            return Err(ContractError::ProtocolMismatch {
                expected: A_CORE_PROTOCOL_VERSION.to_string(),
                actual: self.protocol.clone(),
            });
        }
        if self.product_id != manifest.product_id {
            return Err(ContractError::ProductMismatch {
                expected: manifest.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        validate_identifier(&self.module_id, "module_id", false)
            .map_err(ContractError::InvalidModule)?;
        validate_short_text(&self.version, "module.version")
            .map_err(ContractError::InvalidModule)?;
        validate_identifier(&self.capability, "module.capability", false)
            .map_err(ContractError::InvalidModule)?;
        if !manifest.declares_capability(&self.capability) {
            return Err(ContractError::CapabilityNotDeclared(
                self.capability.clone(),
            ));
        }
        if self.payload.len() > MAX_MODULE_PAYLOAD_ENTRIES {
            return Err(ContractError::InvalidModule(format!(
                "module payload cannot contain more than {MAX_MODULE_PAYLOAD_ENTRIES} entries"
            )));
        }
        for (key, value) in &self.payload {
            validate_parameter_key(key).map_err(ContractError::InvalidModule)?;
            validate_short_text(value, &format!("module.payload.{key}"))
                .map_err(ContractError::InvalidModule)?;
            if is_sensitive_parameter_key(key) || looks_like_raw_credential(value) {
                return Err(ContractError::InvalidModule(format!(
                    "module.payload.{key} cannot contain raw credentials"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]

pub struct AuthorizationSnapshot {
    pub protocol: String,
    pub product_id: String,
    pub snapshot_id: String,
    pub subject_id: String,
    pub device_id: String,
    pub license_state: LicenseState,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub capabilities: Vec<String>,
    pub modules: Vec<ModuleEnvelope>,
}

impl AuthorizationSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        product_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        subject_id: impl Into<String>,
        device_id: impl Into<String>,
        license_state: LicenseState,
        issued_at: u64,
        expires_at: Option<u64>,
        capabilities: Vec<String>,
        modules: Vec<ModuleEnvelope>,
    ) -> Self {
        Self {
            protocol: A_CORE_PROTOCOL_VERSION.to_string(),
            product_id: product_id.into(),
            snapshot_id: snapshot_id.into(),
            subject_id: subject_id.into(),
            device_id: device_id.into(),
            license_state,
            issued_at,
            expires_at,
            capabilities,
            modules,
        }
    }

    pub fn with_module(mut self, module: ModuleEnvelope) -> Self {
        self.modules.push(module);
        self
    }

    pub fn validate_for(&self, manifest: &ProductManifest) -> Result<(), ContractError> {
        manifest.validate()?;
        if self.protocol != A_CORE_PROTOCOL_VERSION {
            return Err(ContractError::ProtocolMismatch {
                expected: A_CORE_PROTOCOL_VERSION.to_string(),
                actual: self.protocol.clone(),
            });
        }
        if self.product_id != manifest.product_id {
            return Err(ContractError::ProductMismatch {
                expected: manifest.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        validate_opaque_identifier(&self.snapshot_id, "snapshot_id")
            .map_err(ContractError::InvalidSnapshot)?;
        validate_opaque_identifier(&self.subject_id, "subject_id")
            .map_err(ContractError::InvalidSnapshot)?;
        validate_opaque_identifier(&self.device_id, "device_id")
            .map_err(ContractError::InvalidSnapshot)?;
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at < self.issued_at)
        {
            return Err(ContractError::InvalidSnapshot(
                "expires_at cannot be earlier than issued_at".to_string(),
            ));
        }

        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ContractError::InvalidSnapshot(format!(
                "snapshot cannot grant more than {MAX_CAPABILITIES} capabilities"
            )));
        }
        if self.modules.len() > MAX_SNAPSHOT_MODULES {
            return Err(ContractError::InvalidSnapshot(format!(
                "snapshot cannot contain more than {MAX_SNAPSHOT_MODULES} modules"
            )));
        }

        let mut capability_ids = Vec::new();
        for capability_id in &self.capabilities {
            validate_identifier(capability_id, "snapshot.capabilities", false)
                .map_err(ContractError::InvalidSnapshot)?;
            if !manifest.declares_capability(capability_id) {
                return Err(ContractError::CapabilityNotDeclared(capability_id.clone()));
            }
            if capability_ids.iter().any(|id| id == capability_id) {
                return Err(ContractError::InvalidSnapshot(format!(
                    "duplicate granted capability: {capability_id}"
                )));
            }
            capability_ids.push(capability_id.clone());
        }

        for capability in &manifest.capabilities {
            if capability.required && !self.capabilities.iter().any(|id| id == &capability.id) {
                return Err(ContractError::RequiredCapabilityMissing(
                    capability.id.clone(),
                ));
            }
        }

        let mut module_ids = Vec::new();
        for module in &self.modules {
            module.validate_for(manifest)?;
            if !self.capabilities.iter().any(|id| id == &module.capability) {
                return Err(ContractError::InvalidSnapshot(format!(
                    "module capability was not granted: {}",
                    module.capability
                )));
            }
            if module_ids.iter().any(|id| id == &module.module_id) {
                return Err(ContractError::InvalidSnapshot(format!(
                    "duplicate module id: {}",
                    module.module_id
                )));
            }
            module_ids.push(module.module_id.clone());
        }
        Ok(())
    }

    pub fn is_launchable(&self) -> bool {
        self.license_state.allows_launch()
    }
}

pub(crate) fn validate_short_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.chars().count() > 256 {
        return Err(format!("{field} is too long"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} contains a control character"));
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &str,
    allow_uppercase: bool,
) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err(format!("{field} must contain 1 to 64 characters"));
    }
    for (index, character) in value.chars().enumerate() {
        let valid = character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.');
        let valid_case = allow_uppercase || !character.is_ascii_uppercase();
        if !valid || !valid_case || (index == 0 && !character.is_ascii_alphanumeric()) {
            return Err(format!("{field} contains an invalid identifier"));
        }
    }
    Ok(())
}

pub(crate) fn validate_locale(locale: &str) -> Result<(), String> {
    let parts: Vec<&str> = locale.split('-').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err("locale must use a language[-region[-variant]] shape".to_string());
    }
    if !(2..=8).contains(&parts[0].len())
        || !parts[0]
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        return Err("locale language must contain 2 to 8 ASCII letters".to_string());
    }
    for part in parts.iter().skip(1) {
        if !(2..=8).contains(&part.len())
            || !part
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
        {
            return Err(
                "locale region and variant must contain 2 to 8 ASCII letters or digits".to_string(),
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_ipc_name(ipc_name: &str) -> Result<(), String> {
    if ipc_name.is_empty() || ipc_name.len() > 128 {
        return Err("ipc_name must contain 1 to 128 characters".to_string());
    }
    for (index, character) in ipc_name.chars().enumerate() {
        let valid = character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.');
        if !valid || (index == 0 && !character.is_ascii_alphabetic()) {
            return Err("ipc_name contains an invalid character".to_string());
        }
    }
    Ok(())
}

pub(crate) fn validate_parameter_key(key: &str) -> Result<(), String> {
    validate_identifier(key, "parameter key", true)
}

pub(crate) fn validate_opaque_identifier(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 {
        return Err(format!("{field} must contain 1 to 256 characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} contains a control character"));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &Path, field: &str) -> Result<String, String> {
    let raw = path.to_string_lossy().replace('\\', "/");
    if raw.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if raw.starts_with('/') || (raw.len() >= 2 && raw.as_bytes()[1] == b':') {
        return Err(format!("{field} must be relative to the product profile"));
    }

    let mut parts = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(':') {
            return Err(format!("{field} contains an unsafe path component"));
        }
        parts.push(part.to_ascii_lowercase());
    }
    Ok(parts.join("/"))
}

pub(crate) fn is_sensitive_parameter_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "raw_card_key"
            | "card_key"
            | "license_key"
            | "credential"
            | "password"
            | "secret"
            | "access_token"
            | "refresh_token"
            | "device_public_key"
            | "device_proof"
            | "installation_id"
            | "client_version"
            | "nonce"
    )
}

pub(crate) fn contains_request_only_field(value: &str) -> Option<&'static str> {
    [
        "device_public_key",
        "device_proof",
        "client_version",
        "nonce",
    ]
    .into_iter()
    .find(|field| value.contains(&format!("\"{field}\"")))
}

pub(crate) fn looks_like_raw_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("card-") || lower.contains("license-key-") || lower.contains("secret=")
}
