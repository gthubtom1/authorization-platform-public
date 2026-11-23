//! Product manifests, profile loading and product registry.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::codec::*;
use super::contract::*;

pub const MAX_PROFILE_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum ProfileStoreError {
    InvalidPath(String),
    ProfileTooLarge {
        path: PathBuf,
        max_bytes: usize,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Contract(ContractError),
}

impl fmt::Display for ProfileStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(message) => write!(f, "invalid profile path: {message}"),
            Self::ProfileTooLarge { path, max_bytes } => write!(
                f,
                "profile {} exceeds the {max_bytes}-byte limit",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(f, "cannot read profile {}: {source}", path.display())
            }
            Self::Contract(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ProfileStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Contract(error) => Some(error),
            Self::InvalidPath(_) | Self::ProfileTooLarge { .. } => None,
        }
    }
}

impl From<ContractError> for ProfileStoreError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductManifest {
    pub schema_version: String,
    pub product_id: String,
    pub display_name: String,
    pub category: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub locale: String,
    pub theme: ThemeTokens,
    pub core_path: PathBuf,
    pub state_root: PathBuf,
    pub ipc_name: String,
    pub compatibility: CompatibilityMode,
    pub capabilities: Vec<Capability>,
    pub protocol_parameters: BTreeMap<String, String>,
}

impl ProductManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        product_id: impl Into<String>,
        display_name: impl Into<String>,
        adapter_id: impl Into<String>,
        adapter_version: impl Into<String>,
        locale: impl Into<String>,
        theme: ThemeTokens,
        core_path: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        ipc_name: impl Into<String>,
        compatibility: CompatibilityMode,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            schema_version: PRODUCT_MANIFEST_VERSION.to_string(),
            product_id: product_id.into(),
            display_name: display_name.into(),
            category: "uncategorized".to_string(),
            adapter_id: adapter_id.into(),
            adapter_version: adapter_version.into(),
            locale: locale.into(),
            theme,
            core_path: core_path.into(),
            state_root: state_root.into(),
            ipc_name: ipc_name.into(),
            compatibility,
            capabilities,
            protocol_parameters: BTreeMap::new(),
        }
    }

    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }

    pub fn with_protocol_parameter(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.protocol_parameters.insert(key.into(), value.into());
        self
    }

    pub fn with_protocol_parameters(mut self, parameters: BTreeMap<String, String>) -> Self {
        self.protocol_parameters = parameters;
        self
    }

    /// Serialize the validated manifest as deterministic JSON for a profile file.
    pub fn to_json(&self) -> Result<String, ContractError> {
        self.validate()?;
        Ok(serialize_json(&manifest_to_json_value(self)))
    }

    /// Parse one `product-manifest.v1` profile and run the same validation as an in-memory manifest.
    pub fn from_json(input: &str) -> Result<Self, ContractError> {
        let value = JsonParser::new(input)
            .parse()
            .map_err(|message| ContractError::InvalidManifest(format!("JSON {message}")))?;
        manifest_from_json_value(value)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != PRODUCT_MANIFEST_VERSION {
            return Err(ContractError::InvalidManifest(format!(
                "schema_version must be {PRODUCT_MANIFEST_VERSION}"
            )));
        }
        validate_identifier(&self.product_id, "product_id", false)
            .map_err(ContractError::InvalidManifest)?;
        validate_short_text(&self.display_name, "display_name")
            .map_err(ContractError::InvalidManifest)?;
        validate_identifier(&self.category, "category", true)
            .map_err(ContractError::InvalidManifest)?;
        validate_identifier(&self.adapter_id, "adapter_id", false)
            .map_err(ContractError::InvalidManifest)?;
        validate_short_text(&self.adapter_version, "adapter_version")
            .map_err(ContractError::InvalidManifest)?;
        validate_locale(&self.locale).map_err(ContractError::InvalidManifest)?;
        self.theme.validate()?;

        let core_key = validate_relative_path(&self.core_path, "core_path")
            .map_err(ContractError::InvalidManifest)?;
        let state_key = validate_relative_path(&self.state_root, "state_root")
            .map_err(ContractError::InvalidManifest)?;
        if core_key == state_key {
            return Err(ContractError::InvalidManifest(
                "core_path and state_root must be different paths".to_string(),
            ));
        }

        validate_ipc_name(&self.ipc_name).map_err(ContractError::InvalidManifest)?;

        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ContractError::InvalidManifest(format!(
                "capabilities cannot contain more than {MAX_CAPABILITIES} entries"
            )));
        }

        let mut capability_ids = Vec::new();
        for (index, capability) in self.capabilities.iter().enumerate() {
            capability.validate(&format!("capabilities[{index}]"))?;
            if capability_ids.iter().any(|id| id == &capability.id) {
                return Err(ContractError::InvalidManifest(format!(
                    "duplicate capability id: {}",
                    capability.id
                )));
            }
            capability_ids.push(capability.id.clone());
        }

        if self.protocol_parameters.len() > MAX_PROTOCOL_PARAMETERS {
            return Err(ContractError::InvalidManifest(format!(
                "protocol_parameters cannot contain more than {MAX_PROTOCOL_PARAMETERS} entries"
            )));
        }
        for (key, value) in &self.protocol_parameters {
            validate_parameter_key(key).map_err(ContractError::InvalidManifest)?;
            validate_short_text(value, &format!("protocol_parameters.{key}"))
                .map_err(ContractError::InvalidManifest)?;
            if is_sensitive_parameter_key(key) || looks_like_raw_credential(value) {
                return Err(ContractError::InvalidManifest(format!(
                    "protocol_parameters.{key} cannot contain raw credentials"
                )));
            }
        }

        Ok(())
    }

    pub fn declares_capability(&self, capability_id: &str) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.id == capability_id)
    }
}

#[derive(Debug, Clone)]

pub struct ProductProfileStore {
    root: PathBuf,
}

impl ProductProfileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load_manifest(
        &self,
        relative_profile_path: impl AsRef<Path>,
    ) -> Result<ProductManifest, ProfileStoreError> {
        let path = self.resolve_profile_path(relative_profile_path.as_ref())?;
        let mut file = fs::File::open(&path).map_err(|source| ProfileStoreError::Io {
            path: path.clone(),
            source,
        })?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_PROFILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| ProfileStoreError::Io {
                path: path.clone(),
                source,
            })?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileStoreError::ProfileTooLarge {
                path,
                max_bytes: MAX_PROFILE_BYTES,
            });
        }
        let input = String::from_utf8(bytes).map_err(|_| {
            ProfileStoreError::Contract(ContractError::InvalidManifest(
                "profile is not valid UTF-8".to_string(),
            ))
        })?;
        ProductManifest::from_json(&input).map_err(ProfileStoreError::Contract)
    }

    pub fn load_manifest_for(
        &self,
        relative_profile_path: impl AsRef<Path>,
        expected_product_id: &str,
    ) -> Result<ProductManifest, ProfileStoreError> {
        let manifest = self.load_manifest(relative_profile_path)?;
        if manifest.product_id != expected_product_id {
            return Err(ProfileStoreError::Contract(
                ContractError::ProductMismatch {
                    expected: expected_product_id.to_string(),
                    actual: manifest.product_id,
                },
            ));
        }
        Ok(manifest)
    }

    pub fn load_registry<I, P>(
        &self,
        relative_profile_paths: I,
    ) -> Result<ProductRegistry, ProfileStoreError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut registry = ProductRegistry::new();
        for relative_profile_path in relative_profile_paths {
            registry
                .register(self.load_manifest(relative_profile_path)?)
                .map_err(ProfileStoreError::Contract)?;
        }
        Ok(registry)
    }

    fn resolve_profile_path(
        &self,
        relative_profile_path: &Path,
    ) -> Result<PathBuf, ProfileStoreError> {
        let normalized = validate_relative_path(relative_profile_path, "profile_path")
            .map_err(ProfileStoreError::InvalidPath)?;
        Ok(self.root.join(normalized))
    }
}

#[derive(Debug, Default, Clone)]

pub struct ProductRegistry {
    products: BTreeMap<String, ProductManifest>,
    state_roots: BTreeMap<String, String>,
    ipc_names: BTreeMap<String, String>,
}

impl ProductRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, manifest: ProductManifest) -> Result<(), ContractError> {
        manifest.validate()?;
        let state_key = validate_relative_path(&manifest.state_root, "state_root")
            .map_err(ContractError::InvalidManifest)?;
        let ipc_key = manifest.ipc_name.to_ascii_lowercase();

        if self.products.contains_key(&manifest.product_id) {
            return Err(ContractError::DuplicateProductId(manifest.product_id));
        }
        if let Some(existing_product_id) = self.state_roots.get(&state_key) {
            return Err(ContractError::DuplicateStateRoot {
                state_root: state_key,
                existing_product_id: existing_product_id.clone(),
            });
        }
        if let Some(existing_product_id) = self.ipc_names.get(&ipc_key) {
            return Err(ContractError::DuplicateIpcName {
                ipc_name: manifest.ipc_name,
                existing_product_id: existing_product_id.clone(),
            });
        }

        let product_id = manifest.product_id.clone();
        self.state_roots.insert(state_key, product_id.clone());
        self.ipc_names.insert(ipc_key, product_id.clone());
        self.products.insert(product_id, manifest);
        Ok(())
    }

    pub fn get(&self, product_id: &str) -> Option<&ProductManifest> {
        self.products.get(product_id)
    }

    pub fn require(&self, product_id: &str) -> Result<&ProductManifest, ContractError> {
        self.get(product_id)
            .ok_or_else(|| ContractError::ProductNotFound(product_id.to_string()))
    }

    pub fn len(&self) -> usize {
        self.products.len()
    }

    pub fn is_empty(&self) -> bool {
        self.products.is_empty()
    }

    pub fn products(&self) -> impl Iterator<Item = &ProductManifest> {
        self.products.values()
    }

    pub fn validate_snapshot(&self, snapshot: &AuthorizationSnapshot) -> Result<(), ContractError> {
        let manifest = self.require(&snapshot.product_id)?;
        snapshot.validate_for(manifest)
    }
}

fn manifest_to_json_value(manifest: &ProductManifest) -> JsonValue {
    let mut theme = BTreeMap::new();
    theme.insert(
        "accent".to_string(),
        JsonValue::String(manifest.theme.accent.clone()),
    );
    theme.insert(
        "danger".to_string(),
        JsonValue::String(manifest.theme.danger.clone()),
    );
    theme.insert(
        "surface".to_string(),
        JsonValue::String(manifest.theme.surface.clone()),
    );
    theme.insert(
        "text".to_string(),
        JsonValue::String(manifest.theme.text.clone()),
    );

    let capabilities = manifest
        .capabilities
        .iter()
        .map(|capability| {
            let mut object = BTreeMap::new();
            object.insert("id".to_string(), JsonValue::String(capability.id.clone()));
            object.insert("required".to_string(), JsonValue::Bool(capability.required));
            object.insert(
                "version".to_string(),
                JsonValue::String(capability.version.clone()),
            );
            JsonValue::Object(object)
        })
        .collect();

    let protocol_parameters = manifest
        .protocol_parameters
        .iter()
        .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
        .collect();

    let mut object = BTreeMap::new();
    object.insert(
        "adapter_id".to_string(),
        JsonValue::String(manifest.adapter_id.clone()),
    );
    object.insert(
        "adapter_version".to_string(),
        JsonValue::String(manifest.adapter_version.clone()),
    );
    object.insert("capabilities".to_string(), JsonValue::Array(capabilities));
    object.insert(
        "category".to_string(),
        JsonValue::String(manifest.category.clone()),
    );
    object.insert(
        "compatibility".to_string(),
        JsonValue::String(manifest.compatibility.as_str().to_string()),
    );
    object.insert(
        "core_path".to_string(),
        JsonValue::String(manifest.core_path.to_string_lossy().into_owned()),
    );
    object.insert(
        "display_name".to_string(),
        JsonValue::String(manifest.display_name.clone()),
    );
    object.insert(
        "ipc_name".to_string(),
        JsonValue::String(manifest.ipc_name.clone()),
    );
    object.insert(
        "locale".to_string(),
        JsonValue::String(manifest.locale.clone()),
    );
    object.insert(
        "product_id".to_string(),
        JsonValue::String(manifest.product_id.clone()),
    );
    object.insert(
        "protocol_parameters".to_string(),
        JsonValue::Object(protocol_parameters),
    );
    object.insert(
        "schema_version".to_string(),
        JsonValue::String(manifest.schema_version.clone()),
    );
    object.insert(
        "state_root".to_string(),
        JsonValue::String(manifest.state_root.to_string_lossy().into_owned()),
    );
    object.insert("theme".to_string(), JsonValue::Object(theme));
    JsonValue::Object(object)
}

fn manifest_from_json_value(value: JsonValue) -> Result<ProductManifest, ContractError> {
    let object = json_object(&value, "product manifest")?;
    ensure_known_fields(
        object,
        &[
            "schema_version",
            "product_id",
            "display_name",
            "category",
            "adapter_id",
            "adapter_version",
            "locale",
            "theme",
            "core_path",
            "state_root",
            "ipc_name",
            "compatibility",
            "capabilities",
            "protocol_parameters",
        ],
        "product manifest",
    )?;

    let schema_version = json_required_string(object, "schema_version", "schema_version")?;
    let product_id = json_required_string(object, "product_id", "product_id")?;
    let display_name = json_required_string(object, "display_name", "display_name")?;
    let category = json_required_string(object, "category", "category")?;
    let adapter_id = json_required_string(object, "adapter_id", "adapter_id")?;
    let adapter_version = json_required_string(object, "adapter_version", "adapter_version")?;
    let locale = json_required_string(object, "locale", "locale")?;
    let core_path = json_required_string(object, "core_path", "core_path")?;
    let state_root = json_required_string(object, "state_root", "state_root")?;
    let ipc_name = json_required_string(object, "ipc_name", "ipc_name")?;
    let compatibility = CompatibilityMode::from_str(json_required_string(
        object,
        "compatibility",
        "compatibility",
    )?)
    .ok_or_else(|| {
        ContractError::InvalidManifest("compatibility contains an unknown value".to_string())
    })?;

    let theme_object = json_object(json_required(object, "theme", "theme")?, "theme")?;
    ensure_known_fields(
        theme_object,
        &["accent", "surface", "text", "danger"],
        "theme",
    )?;
    let theme = ThemeTokens::new(
        json_required_string(theme_object, "accent", "theme.accent")?,
        json_required_string(theme_object, "surface", "theme.surface")?,
        json_required_string(theme_object, "text", "theme.text")?,
        json_required_string(theme_object, "danger", "theme.danger")?,
    );

    let capability_values = json_array(
        json_required(object, "capabilities", "capabilities")?,
        "capabilities",
    )?;
    let mut capabilities = Vec::with_capacity(capability_values.len());
    for (index, capability_value) in capability_values.iter().enumerate() {
        let capability_object = json_object(capability_value, &format!("capabilities[{index}]"))?;
        ensure_known_fields(
            capability_object,
            &["id", "version", "required"],
            &format!("capabilities[{index}]"),
        )?;
        capabilities.push(Capability::new(
            json_required_string(capability_object, "id", "capability.id")?,
            json_required_string(capability_object, "version", "capability.version")?,
            json_required_bool(capability_object, "required", "capability.required")?,
        ));
    }

    let parameter_object = json_object(
        json_required(object, "protocol_parameters", "protocol_parameters")?,
        "protocol_parameters",
    )?;
    let mut protocol_parameters = BTreeMap::new();
    for (key, value) in parameter_object {
        let parameter_value = json_string(value, &format!("protocol_parameters.{key}"))?;
        protocol_parameters.insert(key.clone(), parameter_value.to_string());
    }

    let manifest = ProductManifest {
        schema_version: schema_version.to_string(),
        product_id: product_id.to_string(),
        display_name: display_name.to_string(),
        category: category.to_string(),
        adapter_id: adapter_id.to_string(),
        adapter_version: adapter_version.to_string(),
        locale: locale.to_string(),
        theme,
        core_path: PathBuf::from(core_path),
        state_root: PathBuf::from(state_root),
        ipc_name: ipc_name.to_string(),
        compatibility,
        capabilities,
        protocol_parameters,
    };
    manifest.validate()?;
    Ok(manifest)
}
