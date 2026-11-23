//! Product-specific legacy authorization compatibility boundary.

use std::collections::BTreeMap;

use super::contract::*;
use super::profile::ProductManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityVerification {
    SimulatedOnly,
    RealExeUnverified,
}

impl CompatibilityVerification {
    pub const fn real_exe_verified(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAuthResult {
    pub product_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub license_state: LicenseState,
    pub granted: bool,
    pub legacy_protocol: String,
    pub legacy_parameters: BTreeMap<String, String>,
    pub compatibility: CompatibilityVerification,
}

impl LegacyAuthResult {
    pub const fn real_exe_compatibility_verified(&self) -> bool {
        self.compatibility.real_exe_verified()
    }

    pub const fn exposes_raw_credential(&self) -> bool {
        false
    }
}

pub trait LegacyAuthAdapter: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn adapter_version(&self) -> &str;
    fn adapt(
        &self,
        manifest: &ProductManifest,
        snapshot: &AuthorizationSnapshot,
    ) -> Result<LegacyAuthResult, ContractError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedLegacyAuthAdapter {
    adapter_id: String,
    adapter_version: String,
    legacy_protocol: String,
    fixed_parameters: BTreeMap<String, String>,
}

impl SimulatedLegacyAuthAdapter {
    pub fn new(
        adapter_id: impl Into<String>,
        adapter_version: impl Into<String>,
        legacy_protocol: impl Into<String>,
    ) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            adapter_version: adapter_version.into(),
            legacy_protocol: legacy_protocol.into(),
            fixed_parameters: BTreeMap::new(),
        }
    }

    pub fn try_new(
        adapter_id: impl Into<String>,
        adapter_version: impl Into<String>,
        legacy_protocol: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let adapter = Self::new(adapter_id, adapter_version, legacy_protocol);
        adapter.validate()?;
        Ok(adapter)
    }

    pub fn with_fixed_parameter(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.fixed_parameters.insert(key.into(), value.into());
        self
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.adapter_id, "adapter_id", false)
            .map_err(ContractError::InvalidAdapter)?;
        validate_short_text(&self.adapter_version, "adapter_version")
            .map_err(ContractError::InvalidAdapter)?;
        validate_short_text(&self.legacy_protocol, "legacy_protocol")
            .map_err(ContractError::InvalidAdapter)?;
        for (key, value) in &self.fixed_parameters {
            validate_parameter_key(key).map_err(ContractError::InvalidAdapter)?;
            validate_short_text(value, &format!("fixed_parameters.{key}"))
                .map_err(ContractError::InvalidAdapter)?;
            if is_sensitive_parameter_key(key) || looks_like_raw_credential(value) {
                return Err(ContractError::InvalidAdapter(format!(
                    "fixed_parameters.{key} cannot contain raw credentials"
                )));
            }
        }
        Ok(())
    }
}

impl LegacyAuthAdapter for SimulatedLegacyAuthAdapter {
    fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    fn adapt(
        &self,
        manifest: &ProductManifest,
        snapshot: &AuthorizationSnapshot,
    ) -> Result<LegacyAuthResult, ContractError> {
        self.validate()?;
        manifest.validate()?;
        snapshot.validate_for(manifest)?;

        if manifest.adapter_id != self.adapter_id
            || manifest.adapter_version != self.adapter_version
        {
            return Err(ContractError::AdapterMismatch {
                expected: format!("{}@{}", manifest.adapter_id, manifest.adapter_version),
                actual: format!("{}@{}", self.adapter_id, self.adapter_version),
            });
        }
        if !snapshot.license_state.allows_launch() {
            return Err(ContractError::AuthorizationRejected {
                product_id: manifest.product_id.clone(),
                state: snapshot.license_state,
            });
        }

        let mut legacy_parameters = self.fixed_parameters.clone();
        legacy_parameters.extend(manifest.protocol_parameters.clone());
        legacy_parameters.insert(
            "authorization_handle".to_string(),
            opaque_grant_handle(&manifest.product_id, &snapshot.snapshot_id),
        );
        legacy_parameters.insert(
            "license_state".to_string(),
            snapshot.license_state.as_str().to_string(),
        );

        Ok(LegacyAuthResult {
            product_id: manifest.product_id.clone(),
            adapter_id: self.adapter_id.clone(),
            adapter_version: self.adapter_version.clone(),
            license_state: snapshot.license_state,
            granted: true,
            legacy_protocol: self.legacy_protocol.clone(),
            legacy_parameters,
            compatibility: CompatibilityVerification::RealExeUnverified,
        })
    }
}

fn opaque_grant_handle(product_id: &str, snapshot_id: &str) -> String {
    // This is only a stable simulation label, not a cryptographic credential.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in product_id.bytes().chain([0u8]).chain(snapshot_id.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("simulated-grant-{hash:016x}")
}
