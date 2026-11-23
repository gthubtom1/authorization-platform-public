//! Product-neutral Authorization A presentation contract.
//!
//! This module deliberately stops at a validated view model. It does not
//! authorize a user, contact the platform, launch a core, execute module
//! URLs, or persist credentials. A real desktop shell may render this model in
//! any supported language or UI toolkit while the runtime remains the only
//! owner of authorization decisions.

use std::collections::BTreeMap;
use std::fmt;

use super::codec::*;
use super::{
    is_sensitive_parameter_key, AuthorizationError, AuthorizationResponseV1, ContractError,
    LicenseState, ProductManifest,
};

pub const AUTHORIZATION_A_UI_PROTOCOL_VERSION: &str = "authorization-a-ui.v1";
pub const UI_MAX_COPY_ENTRIES: usize = 64;
pub const UI_MAX_MODULES: usize = 32;
const UI_MAX_DEVICE_CODE_CHARS: usize = 64;

/// Stable copy keys used by the shared shell. Product profiles may translate
/// these keys without changing the shell or the authorization contract.
pub const UI_COPY_KEYS: &[&str] = &[
    "app_kicker",
    "section_kicker",
    "headline",
    "subheadline",
    "credential_label",
    "credential_placeholder",
    "field_visible",
    "activate",
    "retry",
    "request_launch",
    "loading",
    "entering",
    "online",
    "offline",
    "authorized",
    "grace",
    "expired",
    "revoked",
    "blocked",
    "unavailable",
    "invalid_response",
    "request_failed",
    "purchase",
    "support",
    "qr",
    "announcement",
    "update",
    "no_modules",
    "unauthenticated",
    "source_live",
    "source_cache",
    "source_none",
    "retrying",
    "runtime_authority",
    "scope_current_device",
    "device_confirmed",
    "device_pending",
    "device_unconfirmed",
    "device_confirmed_detail",
    "device_pending_detail",
    "device_unconfirmed_detail",
    "device_code_label",
    "device_code_pending",
    "device_code_hint",
    "module_contact_hint",
    "module_purchase_hint",
    "module_qr_hint",
    "module_announcement_hint",
    "module_update_hint",
];

const UI_MODULE_TYPES: &[&str] = &[
    "contact",
    "purchase",
    "qr",
    "announcement",
    "notice",
    "update",
];

/// A product-local UI profile. Product identity, locale, copy and module
/// enablement are data; the common runtime never branches on a product name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiProfile {
    pub schema_version: String,
    pub product_id: String,
    pub profile_id: String,
    pub locale: String,
    pub copy: BTreeMap<String, String>,
    pub enabled_modules: Vec<String>,
}

impl UiProfile {
    pub fn new(
        product_id: impl Into<String>,
        profile_id: impl Into<String>,
        locale: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: AUTHORIZATION_A_UI_PROTOCOL_VERSION.to_string(),
            product_id: product_id.into(),
            profile_id: profile_id.into(),
            locale: locale.into(),
            copy: BTreeMap::new(),
            enabled_modules: Vec::new(),
        }
    }

    pub fn for_manifest(manifest: &ProductManifest, profile_id: impl Into<String>) -> Self {
        Self::new(&manifest.product_id, profile_id, &manifest.locale)
    }

    pub fn with_copy(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.copy.insert(key.into(), value.into());
        self
    }

    pub fn with_enabled_modules<I, S>(mut self, modules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.enabled_modules = modules.into_iter().map(Into::into).collect();
        self
    }

    pub fn enable_module(mut self, module_type: impl Into<String>) -> Self {
        self.enabled_modules.push(module_type.into());
        self
    }

    pub fn module_enabled(&self, module_type: &str) -> bool {
        self.enabled_modules
            .iter()
            .any(|value| value == module_type)
    }

    pub fn copy_text(&self, key: &str) -> Option<&str> {
        self.copy.get(key).map(String::as_str)
    }

    /// Missing copy is a safe presentation fallback, never an authorization
    /// fallback. The built-in table is locale-aware (Chinese for `zh-*`,
    /// English for `en-*`); products may provide a validated locale-specific
    /// profile without changing the stable keys.
    pub fn copy_text_or_default(&self, key: &str) -> &str {
        self.copy_text(key)
            .unwrap_or_else(|| default_copy_text_for_locale(&self.locale, key))
    }

    pub fn validate(&self) -> Result<(), UiError> {
        if self.schema_version != AUTHORIZATION_A_UI_PROTOCOL_VERSION {
            return Err(UiError::InvalidProfile(format!(
                "schema_version must be {AUTHORIZATION_A_UI_PROTOCOL_VERSION}"
            )));
        }
        validate_ui_identifier(&self.product_id, "product_id")?;
        validate_ui_identifier(&self.profile_id, "profile_id")?;
        super::validate_locale(&self.locale).map_err(UiError::InvalidProfile)?;

        if self.copy.len() > UI_MAX_COPY_ENTRIES {
            return Err(UiError::InvalidProfile(format!(
                "copy cannot contain more than {UI_MAX_COPY_ENTRIES} entries"
            )));
        }
        for (key, value) in &self.copy {
            if !UI_COPY_KEYS.contains(&key.as_str()) {
                return Err(UiError::InvalidProfile(format!(
                    "copy contains unknown key: {key}"
                )));
            }
            super::validate_short_text(value, &format!("copy.{key}"))
                .map_err(UiError::InvalidProfile)?;
        }

        if self.enabled_modules.len() > UI_MODULE_TYPES.len() {
            return Err(UiError::InvalidProfile(format!(
                "enabled_modules cannot contain more than {} entries",
                UI_MODULE_TYPES.len()
            )));
        }
        for module_type in &self.enabled_modules {
            if !UI_MODULE_TYPES.contains(&module_type.as_str()) {
                return Err(UiError::InvalidProfile(format!(
                    "enabled_modules contains unknown module type: {module_type}"
                )));
            }
            if self
                .enabled_modules
                .iter()
                .filter(|candidate| *candidate == module_type)
                .count()
                > 1
            {
                return Err(UiError::InvalidProfile(format!(
                    "enabled_modules contains a duplicate: {module_type}"
                )));
            }
        }
        Ok(())
    }

    pub fn validate_for_manifest(&self, manifest: &ProductManifest) -> Result<(), UiError> {
        manifest.validate()?;
        self.validate()?;
        if self.product_id != manifest.product_id {
            return Err(UiError::ProductMismatch {
                expected: manifest.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        if self.locale != manifest.locale {
            return Err(UiError::LocaleMismatch {
                expected: manifest.locale.clone(),
                actual: self.locale.clone(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, UiError> {
        self.validate()?;
        Ok(serialize_json(&ui_profile_to_json_value(self)))
    }

    pub fn from_json(input: &str) -> Result<Self, UiError> {
        let value = JsonParser::new(input)
            .parse()
            .map_err(|message| UiError::InvalidProfile(format!("JSON {message}")))?;
        let profile = ui_profile_from_json_value(value)?;
        profile.validate()?;
        Ok(profile)
    }
}

/// The four manifest colors are the source tokens for the shell. The shell
/// derives layout and neutral values in its renderer; arbitrary CSS is never
/// accepted from a product profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiThemeTokens {
    pub accent: String,
    pub surface: String,
    pub text: String,
    pub danger: String,
}

impl UiThemeTokens {
    pub fn from_manifest(manifest: &ProductManifest) -> Result<Self, UiError> {
        manifest.validate()?;
        let theme = &manifest.theme;
        for (name, value) in [
            ("accent", &theme.accent),
            ("surface", &theme.surface),
            ("text", &theme.text),
            ("danger", &theme.danger),
        ] {
            validate_ui_color(value, &format!("theme.{name}"))?;
        }
        Ok(Self {
            accent: theme.accent.clone(),
            surface: theme.surface.clone(),
            text: theme.text.clone(),
            danger: theme.danger.clone(),
        })
    }

    pub fn css_variables(&self) -> BTreeMap<String, String> {
        [
            ("--a-accent", self.accent.clone()),
            ("--a-surface", self.surface.clone()),
            ("--a-text", self.text.clone()),
            ("--a-danger", self.danger.clone()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiScreen {
    Login,
    Loading,
    Status,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiConnectivity {
    Loading,
    Online,
    Offline,
    Retrying,
    Unavailable,
}

impl UiConnectivity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Retrying => "retrying",
            Self::Unavailable => "unavailable",
        }
    }

    pub const fn copy_key(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Retrying => "retrying",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthorizationSource {
    None,
    Live,
    Cache,
}

impl UiAuthorizationSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Live => "live",
            Self::Cache => "cache",
        }
    }

    pub const fn copy_key(self) -> &'static str {
        match self {
            Self::None => "source_none",
            Self::Live => "source_live",
            Self::Cache => "source_cache",
        }
    }
}

impl UiScreen {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Loading => "loading",
            Self::Status => "status",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthorizationState {
    Unauthenticated,
    Pending,
    Active,
    Grace,
    Expired,
    Revoked,
    Blocked,
    Unavailable,
    ContractInvalid,
}

impl UiAuthorizationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Blocked => "blocked",
            Self::Unavailable => "unavailable",
            Self::ContractInvalid => "contract_invalid",
        }
    }
}

/// UI events are intents. In particular, `RequestLaunch` is not a grant; the
/// runtime must re-check the signed response and its offline lease when it
/// handles the event.
///
/// `OpenModule("purchase")` contract (product-side MUST implement): open the
/// downstream's `support.purchase_url` (usually the reseller card URL the
/// downstream configured) in the OS default browser for the user to buy there.
/// The launcher never buys, never embeds the page, never appends the card to
/// the URL. Empty/missing URL means no-op: the entry stays hidden and a click
/// does nothing. `OpenModule("contact"/"notice")` only shows the downstream
/// text verbatim, never opens anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiIntent {
    Activate,
    Retry,
    RequestLaunch,
    OpenModule(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiViewState {
    pub screen: UiScreen,
    pub authorization: UiAuthorizationState,
    pub connectivity: UiConnectivity,
    pub source: UiAuthorizationSource,
    pub intents: Vec<UiIntent>,
}

impl UiViewState {
    pub fn login() -> Self {
        Self {
            screen: UiScreen::Login,
            authorization: UiAuthorizationState::Unauthenticated,
            connectivity: UiConnectivity::Online,
            source: UiAuthorizationSource::None,
            intents: vec![UiIntent::Activate],
        }
    }

    pub fn loading() -> Self {
        Self {
            screen: UiScreen::Loading,
            authorization: UiAuthorizationState::Pending,
            connectivity: UiConnectivity::Loading,
            source: UiAuthorizationSource::None,
            intents: Vec::new(),
        }
    }

    pub fn from_license_state(state: LicenseState, online: bool) -> Result<Self, UiError> {
        let unavailable = state == LicenseState::Unavailable;
        Self::from_license_state_with_context(
            state,
            if unavailable {
                UiConnectivity::Unavailable
            } else if online {
                UiConnectivity::Online
            } else {
                UiConnectivity::Offline
            },
            if unavailable {
                UiAuthorizationSource::None
            } else if online {
                UiAuthorizationSource::Live
            } else {
                UiAuthorizationSource::Cache
            },
        )
    }

    pub fn from_license_state_with_context(
        state: LicenseState,
        connectivity: UiConnectivity,
        source: UiAuthorizationSource,
    ) -> Result<Self, UiError> {
        if matches!(state, LicenseState::Active | LicenseState::Grace)
            && matches!(source, UiAuthorizationSource::None)
        {
            return Err(UiError::InternalState(
                "launchable UI state requires a live or cached authorization source".to_string(),
            ));
        }
        if matches!(state, LicenseState::Active | LicenseState::Grace)
            && matches!(connectivity, UiConnectivity::Unavailable)
        {
            return Err(UiError::InternalState(
                "launchable UI state cannot use unavailable connectivity".to_string(),
            ));
        }
        if state == LicenseState::Unavailable
            && (!matches!(connectivity, UiConnectivity::Unavailable)
                || !matches!(source, UiAuthorizationSource::None))
        {
            return Err(UiError::InternalState(
                "unavailable UI state must not carry a grant source".to_string(),
            ));
        }
        let (screen, authorization, intents) = match state {
            LicenseState::Active => (
                UiScreen::Status,
                UiAuthorizationState::Active,
                vec![UiIntent::RequestLaunch],
            ),
            LicenseState::Grace => (
                UiScreen::Status,
                UiAuthorizationState::Grace,
                vec![UiIntent::RequestLaunch, UiIntent::Retry],
            ),
            LicenseState::Expired => (
                UiScreen::Error,
                UiAuthorizationState::Expired,
                vec![UiIntent::Activate],
            ),
            LicenseState::Revoked => (
                UiScreen::Error,
                UiAuthorizationState::Revoked,
                vec![UiIntent::OpenModule("contact".to_string())],
            ),
            LicenseState::Blocked => (
                UiScreen::Error,
                UiAuthorizationState::Blocked,
                vec![UiIntent::OpenModule("contact".to_string())],
            ),
            LicenseState::Unavailable => (
                UiScreen::Error,
                UiAuthorizationState::Unavailable,
                vec![UiIntent::Retry],
            ),
            LicenseState::NotModified => {
                return Err(UiError::InternalState(
                    "not_modified must be materialized by A before reaching the UI".to_string(),
                ));
            }
        };
        Ok(Self {
            screen,
            authorization,
            connectivity,
            source,
            intents,
        })
    }

    pub fn contract_invalid() -> Self {
        Self {
            screen: UiScreen::Error,
            authorization: UiAuthorizationState::ContractInvalid,
            connectivity: UiConnectivity::Unavailable,
            source: UiAuthorizationSource::None,
            intents: Vec::new(),
        }
    }

    pub fn is_offline(&self) -> bool {
        matches!(
            self.connectivity,
            UiConnectivity::Offline | UiConnectivity::Retrying
        )
    }

    pub fn can_request_launch(&self) -> bool {
        self.intents
            .iter()
            .any(|intent| matches!(intent, UiIntent::RequestLaunch))
    }

    pub fn status_copy_key(&self) -> &'static str {
        match self.authorization {
            UiAuthorizationState::Unauthenticated => "unauthenticated",
            UiAuthorizationState::Pending => "loading",
            UiAuthorizationState::Active => "authorized",
            UiAuthorizationState::Grace => "grace",
            UiAuthorizationState::Expired => "expired",
            UiAuthorizationState::Revoked => "revoked",
            UiAuthorizationState::Blocked => "blocked",
            UiAuthorizationState::Unavailable => "unavailable",
            UiAuthorizationState::ContractInvalid => "invalid_response",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiModuleKind {
    Contact,
    Purchase,
    Qr,
    Announcement,
    Update,
}

impl UiModuleKind {
    pub fn from_module_type(value: &str) -> Option<Self> {
        Some(match value {
            "contact" => Self::Contact,
            "purchase" => Self::Purchase,
            "qr" => Self::Qr,
            // Platform key is `notice`; the old template-internal
            // `announcement` stays accepted for existing product copies.
            "announcement" | "notice" => Self::Announcement,
            "update" => Self::Update,
            _ => return None,
        })
    }

    /// Platform wire key for this module (`notice`, not `announcement`).
    pub const fn platform_key(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Purchase => "purchase",
            Self::Qr => "qr",
            Self::Announcement => "notice",
            Self::Update => "update",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Purchase => "purchase",
            Self::Qr => "qr",
            Self::Announcement => "announcement",
            Self::Update => "update",
        }
    }

    pub const fn title_copy_key(self) -> &'static str {
        match self {
            Self::Contact => "support",
            Self::Purchase => "purchase",
            Self::Qr => "qr",
            Self::Announcement => "announcement",
            Self::Update => "update",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiModuleCard {
    pub module_id: String,
    pub kind: UiModuleKind,
    pub version: String,
    pub capability: String,
    /// Only typed, display-safe fields are exposed. Commands, executable
    /// paths, arbitrary script, and raw credentials never reach this map.
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UiModuleCatalog {
    entries: Vec<UiModuleCard>,
    ignored_module_ids: Vec<String>,
}

impl UiModuleCatalog {
    pub fn from_response(
        response: &AuthorizationResponseV1,
        manifest: &ProductManifest,
        profile: &UiProfile,
    ) -> Result<Self, UiError> {
        profile.validate_for_manifest(manifest)?;
        response.validate_for_manifest(manifest)?;
        if response.identity.profile_id != profile.profile_id {
            return Err(UiError::ProfileMismatch {
                expected: profile.profile_id.clone(),
                actual: response.identity.profile_id.clone(),
            });
        }
        if response.decision == LicenseState::NotModified {
            return Err(UiError::InternalState(
                "not_modified must not be rendered as a UI authorization state".to_string(),
            ));
        }

        if response.modules.len() > UI_MAX_MODULES {
            return Err(UiError::InvalidModule(format!(
                "response contains more than {UI_MAX_MODULES} UI modules"
            )));
        }

        let mut catalog = Self::default();
        for module in &response.modules {
            if module
                .payload
                .keys()
                .any(|key| is_sensitive_parameter_key(key))
            {
                return Err(UiError::InvalidModule(format!(
                    "module {} contains a request-only field",
                    module.module_id
                )));
            }
            let Some(kind) = UiModuleKind::from_module_type(&module.module_type) else {
                catalog.ignored_module_ids.push(module.module_id.clone());
                continue;
            };
            if !profile.module_enabled(kind.as_str()) {
                catalog.ignored_module_ids.push(module.module_id.clone());
                continue;
            }
            let fields = module
                .payload
                .iter()
                .filter(|(key, _)| ui_field_is_display_safe(kind, key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            catalog.entries.push(UiModuleCard {
                module_id: module.module_id.clone(),
                kind,
                version: module.version.clone(),
                capability: module.capability.clone(),
                fields,
            });
        }
        Ok(catalog)
    }

    pub fn entries(&self) -> &[UiModuleCard] {
        &self.entries
    }

    pub fn ignored_module_ids(&self) -> &[String] {
        &self.ignored_module_ids
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build display cards from a platform fixed-key modules object.
    /// Only non-empty display-safe fields reach the UI; empty blocks stay
    /// hidden. Profile gating accepts both the platform key (`notice`) and
    /// the legacy template name (`announcement`).
    pub fn from_platform_modules(
        modules: &super::platform::PlatformModules,
        profile: &UiProfile,
    ) -> Self {
        fn enabled(profile: &UiProfile, kind: UiModuleKind) -> bool {
            profile.module_enabled(kind.as_str()) || profile.module_enabled(kind.platform_key())
        }
        fn card(
            module_id: &str,
            kind: UiModuleKind,
            fields: Vec<(String, String)>,
        ) -> UiModuleCard {
            UiModuleCard {
                module_id: module_id.to_string(),
                kind,
                version: String::new(),
                capability: String::new(),
                fields: fields.into_iter().collect(),
            }
        }
        let mut catalog = Self::default();
        if !modules.contact.is_empty() && enabled(profile, UiModuleKind::Contact) {
            let mut fields = Vec::new();
            for (key, value) in [
                ("purchase_url", &modules.contact.purchase_url),
                ("qq", &modules.contact.qq),
                ("wechat", &modules.contact.wechat),
            ] {
                if let Some(text) = value {
                    if !text.trim().is_empty() {
                        fields.push((key.to_string(), text.clone()));
                    }
                }
            }
            if !fields.is_empty() {
                catalog
                    .entries
                    .push(card("platform-contact", UiModuleKind::Contact, fields));
            }
        }
        if !modules.notice.is_empty() && enabled(profile, UiModuleKind::Announcement) {
            let mut fields = Vec::new();
            for (key, value) in [
                ("title", &modules.notice.title),
                ("body", &modules.notice.body),
            ] {
                if let Some(text) = value {
                    if !text.trim().is_empty() {
                        fields.push((key.to_string(), text.clone()));
                    }
                }
            }
            if !fields.is_empty() {
                catalog
                    .entries
                    .push(card("platform-notice", UiModuleKind::Announcement, fields));
            }
        }
        for (present, kind, id) in [
            (
                modules.purchase_present,
                UiModuleKind::Purchase,
                "platform-purchase",
            ),
            (modules.qr_present, UiModuleKind::Qr, "platform-qr"),
            (
                modules.update.is_some(),
                UiModuleKind::Update,
                "platform-update",
            ),
        ] {
            if present && enabled(profile, kind) {
                catalog.entries.push(card(id, kind, Vec::new()));
            }
        }
        catalog
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiShellModel {
    pub schema_version: String,
    pub product_id: String,
    pub profile_id: String,
    pub display_name: String,
    pub locale: String,
    pub theme: UiThemeTokens,
    pub state: UiViewState,
    pub modules: UiModuleCatalog,
    /// A bounded display-only code supplied from a server-confirmed device
    /// scope. It is never authorization authority and must not contain a card
    /// credential or another secret.
    pub device_code: Option<String>,
}

impl UiShellModel {
    pub fn new(
        manifest: &ProductManifest,
        profile: &UiProfile,
        state: UiViewState,
    ) -> Result<Self, UiError> {
        profile.validate_for_manifest(manifest)?;
        Ok(Self {
            schema_version: AUTHORIZATION_A_UI_PROTOCOL_VERSION.to_string(),
            product_id: manifest.product_id.clone(),
            profile_id: profile.profile_id.clone(),
            display_name: manifest.display_name.clone(),
            locale: manifest.locale.clone(),
            theme: UiThemeTokens::from_manifest(manifest)?,
            state,
            modules: UiModuleCatalog::default(),
            device_code: None,
        })
    }

    pub fn with_modules(mut self, modules: UiModuleCatalog) -> Self {
        self.modules = modules;
        self
    }

    pub fn with_device_code(mut self, value: impl Into<String>) -> Result<Self, UiError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed.chars().count() > UI_MAX_DEVICE_CODE_CHARS
            || !trimmed
                .chars()
                .all(|character| character.is_ascii_graphic())
        {
            return Err(UiError::InvalidProfile(format!(
                "device code must contain 1-{UI_MAX_DEVICE_CODE_CHARS} visible ASCII characters"
            )));
        }
        self.device_code = Some(trimmed.to_string());
        Ok(self)
    }
}

/// The immutable, already-validated presentation snapshot passed to a
/// renderer. Keeping copy outside `UiShellModel` preserves the model's public
/// compatibility while ensuring a native renderer never reparses a profile or
/// reads raw authorization data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiRenderSnapshot {
    pub model: UiShellModel,
    pub copy: BTreeMap<String, String>,
    enabled_modules: Vec<String>,
}

impl UiRenderSnapshot {
    pub fn new(model: UiShellModel, profile: &UiProfile) -> Result<Self, UiError> {
        profile.validate()?;
        if model.product_id != profile.product_id {
            return Err(UiError::ProductMismatch {
                expected: model.product_id,
                actual: profile.product_id.clone(),
            });
        }
        if model.profile_id != profile.profile_id {
            return Err(UiError::ProfileMismatch {
                expected: model.profile_id,
                actual: profile.profile_id.clone(),
            });
        }
        if model.locale != profile.locale {
            return Err(UiError::LocaleMismatch {
                expected: model.locale,
                actual: profile.locale.clone(),
            });
        }
        Ok(Self {
            model,
            copy: profile.copy.clone(),
            enabled_modules: profile.enabled_modules.clone(),
        })
    }

    pub fn copy_text(&self, key: &str) -> Option<&str> {
        self.copy.get(key).map(String::as_str)
    }

    pub fn copy_text_or_default(&self, key: &str) -> &str {
        self.copy_text(key)
            .unwrap_or_else(|| default_copy_text_for_locale(&self.model.locale, key))
    }

    pub fn module_enabled(&self, module_type: &str) -> bool {
        self.enabled_modules
            .iter()
            .any(|value| value == module_type)
    }

    pub fn enabled_modules(&self) -> &[String] {
        &self.enabled_modules
    }
}

impl std::ops::Deref for UiRenderSnapshot {
    type Target = UiShellModel;

    fn deref(&self) -> &Self::Target {
        &self.model
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiError {
    InvalidProfile(String),
    InvalidModule(String),
    ProductMismatch { expected: String, actual: String },
    ProfileMismatch { expected: String, actual: String },
    LocaleMismatch { expected: String, actual: String },
    InternalState(String),
    Contract(ContractError),
    Authorization(AuthorizationError),
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(message) => write!(f, "invalid UI profile: {message}"),
            Self::InvalidModule(message) => write!(f, "invalid UI module: {message}"),
            Self::ProductMismatch { expected, actual } => {
                write!(
                    f,
                    "UI product mismatch: expected {expected}, received {actual}"
                )
            }
            Self::ProfileMismatch { expected, actual } => {
                write!(
                    f,
                    "UI profile mismatch: expected {expected}, received {actual}"
                )
            }
            Self::LocaleMismatch { expected, actual } => {
                write!(
                    f,
                    "UI locale mismatch: expected {expected}, received {actual}"
                )
            }
            Self::InternalState(message) => write!(f, "invalid UI state: {message}"),
            Self::Contract(error) => error.fmt(f),
            Self::Authorization(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for UiError {}

impl From<ContractError> for UiError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<AuthorizationError> for UiError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}

fn validate_ui_identifier(value: &str, field: &str) -> Result<(), UiError> {
    super::validate_identifier(value, field, false).map_err(UiError::InvalidProfile)
}

fn validate_ui_color(value: &str, field: &str) -> Result<(), UiError> {
    let valid_length = value.len() == 7 || value.len() == 9;
    if !valid_length
        || !value.starts_with('#')
        || !value.as_bytes()[1..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(UiError::InvalidProfile(format!(
            "{field} must be a #RRGGBB or #RRGGBBAA color"
        )));
    }
    Ok(())
}

fn ui_field_is_display_safe(kind: UiModuleKind, key: &str) -> bool {
    let common = ["title", "body", "label", "value"];
    let specific: &[&str] = match kind {
        UiModuleKind::Contact => &["contact", "qq", "wechat"],
        UiModuleKind::Purchase => &["price", "currency", "purchase_text"],
        UiModuleKind::Qr => &["caption", "qr_text"],
        UiModuleKind::Announcement => &["published_at"],
        UiModuleKind::Update => &[
            "release_id",
            "version",
            "artifact_size",
            "artifact_sha256",
            "artifact_signature",
            "min_core_version",
            "channel",
        ],
    };
    common.contains(&key) || specific.contains(&key)
}

fn default_copy_text_for_locale(locale: &str, key: &str) -> &'static str {
    if is_english_locale(locale) {
        return default_english_copy_text(key);
    }
    default_chinese_copy_text(key)
}

fn is_english_locale(locale: &str) -> bool {
    let bytes = locale.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    let english = (bytes[0] == b'e' || bytes[0] == b'E') && (bytes[1] == b'n' || bytes[1] == b'N');
    english && (bytes.len() == 2 || (bytes.len() >= 3 && bytes[2] == b'-'))
}

fn default_chinese_copy_text(key: &str) -> &'static str {
    match key {
        "app_kicker" => "本软件",
        "section_kicker" => "输入卡密",
        "headline" => "授权验证",
        "subheadline" => "通过后会自动打开本软件，不用再点。",
        "credential_label" => "卡密",
        "credential_placeholder" => "请输入卡密",
        "field_visible" => "可见",
        "activate" => "立即激活",
        "retry" => "重新检查",
        "request_launch" => "正在打开本软件",
        "loading" => "正在检查授权",
        "entering" => "正在打开本软件",
        "online" => "在线",
        "offline" => "离线缓存",
        "authorized" => "授权有效",
        "grace" => "离线宽限",
        "expired" => "授权已过期",
        "revoked" => "授权已撤销",
        "blocked" => "当前访问已阻断",
        "unavailable" => "服务暂时不可用",
        "invalid_response" => "无法验证授权响应",
        "request_failed" => "这次请求没有完成",
        "purchase" => "购买授权",
        "support" => "联系支持",
        "qr" => "二维码",
        "announcement" => "公告",
        "update" => "版本更新",
        "no_modules" => "当前没有可用的附加信息",
        "unauthenticated" => "尚未验证",
        "source_live" => "实时检查",
        "source_cache" => "离线租约",
        "source_none" => "尚未检查",
        "retrying" => "正在重试",
        "runtime_authority" => "授权仍由运行时决定",
        "scope_current_device" => "设备状态",
        "device_confirmed" => "已确认",
        "device_pending" => "确认中",
        "device_unconfirmed" => "未确认",
        "device_confirmed_detail" => "当前授权实例已绑定本机范围",
        "device_pending_detail" => "等待授权服务确认",
        "device_unconfirmed_detail" => "等待授权服务确认",
        "device_code_label" => "设备码",
        "device_code_pending" => "待确认",
        "device_code_hint" => "授权平台核对",
        "module_contact_hint" => "配置的支持方式会显示在这里。",
        "module_purchase_hint" => "配置的购买入口会显示在这里。",
        "module_qr_hint" => "经过验证的二维码信息会显示在这里。",
        "module_announcement_hint" => "经过验证的公告会显示在这里。",
        "module_update_hint" => "经过验证的版本信息会显示在这里。",
        _ => "",
    }
}

fn default_english_copy_text(key: &str) -> &'static str {
    match key {
        "app_kicker" => "This app",
        "section_kicker" => "Enter your key",
        "headline" => "Verify access",
        "subheadline" => "This app opens automatically after verification.",
        "credential_label" => "License key",
        "credential_placeholder" => "Enter your license key",
        "field_visible" => "Visible",
        "activate" => "Activate",
        "retry" => "Try again",
        "request_launch" => "Opening this app",
        "loading" => "Checking access",
        "entering" => "Opening this app",
        "online" => "Online",
        "offline" => "Offline cache",
        "authorized" => "Access verified",
        "grace" => "Grace access",
        "expired" => "Access expired",
        "revoked" => "Access revoked",
        "blocked" => "Access blocked",
        "unavailable" => "Service unavailable",
        "invalid_response" => "Unable to verify the authorization response",
        "request_failed" => "The request could not be completed",
        "purchase" => "Purchase",
        "support" => "Support",
        "qr" => "QR code",
        "announcement" => "Announcement",
        "update" => "Update",
        "no_modules" => "No optional information is available",
        "unauthenticated" => "Not verified",
        "source_live" => "Live check",
        "source_cache" => "Offline lease",
        "source_none" => "Not checked",
        "retrying" => "Retrying",
        "runtime_authority" => "Authorization remains runtime-controlled",
        "scope_current_device" => "Device status",
        "device_confirmed" => "Confirmed",
        "device_pending" => "Checking",
        "device_unconfirmed" => "Not confirmed",
        "device_confirmed_detail" => "This authorization is bound to the current device scope",
        "device_pending_detail" => "Waiting for the authorization service",
        "device_unconfirmed_detail" => "Waiting for the authorization service",
        "device_code_label" => "Device code",
        "device_code_pending" => "Pending",
        "device_code_hint" => "For platform checks",
        "module_contact_hint" => "Configured support channels appear here.",
        "module_purchase_hint" => "A configured purchase entry point appears here.",
        "module_qr_hint" => "A verified QR payload appears here.",
        "module_announcement_hint" => "A verified announcement appears here.",
        "module_update_hint" => "Verified release metadata appears here.",
        _ => "",
    }
}

fn ui_profile_to_json_value(profile: &UiProfile) -> JsonValue {
    let copy = profile
        .copy
        .iter()
        .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
        .collect();
    let enabled_modules = profile
        .enabled_modules
        .iter()
        .map(|value| JsonValue::String(value.clone()))
        .collect();
    let mut object = BTreeMap::new();
    object.insert("copy".to_string(), JsonValue::Object(copy));
    object.insert(
        "enabled_modules".to_string(),
        JsonValue::Array(enabled_modules),
    );
    object.insert(
        "locale".to_string(),
        JsonValue::String(profile.locale.clone()),
    );
    object.insert(
        "product_id".to_string(),
        JsonValue::String(profile.product_id.clone()),
    );
    object.insert(
        "profile_id".to_string(),
        JsonValue::String(profile.profile_id.clone()),
    );
    object.insert(
        "schema_version".to_string(),
        JsonValue::String(profile.schema_version.clone()),
    );
    JsonValue::Object(object)
}

fn ui_profile_from_json_value(value: JsonValue) -> Result<UiProfile, UiError> {
    let object = json_object(&value, "UI profile")
        .map_err(|error| UiError::InvalidProfile(error.to_string()))?;
    ensure_known_fields(
        object,
        &[
            "schema_version",
            "product_id",
            "profile_id",
            "locale",
            "copy",
            "enabled_modules",
        ],
        "UI profile",
    )
    .map_err(|error| UiError::InvalidProfile(error.to_string()))?;

    let schema_version = json_required_string(object, "schema_version", "schema_version")
        .map_err(|error| UiError::InvalidProfile(error.to_string()))?
        .to_string();
    let product_id = json_required_string(object, "product_id", "product_id")
        .map_err(|error| UiError::InvalidProfile(error.to_string()))?
        .to_string();
    let profile_id = json_required_string(object, "profile_id", "profile_id")
        .map_err(|error| UiError::InvalidProfile(error.to_string()))?
        .to_string();
    let locale = json_required_string(object, "locale", "locale")
        .map_err(|error| UiError::InvalidProfile(error.to_string()))?
        .to_string();

    let copy_object = json_object(
        json_required(object, "copy", "copy")
            .map_err(|error| UiError::InvalidProfile(error.to_string()))?,
        "copy",
    )
    .map_err(|error| UiError::InvalidProfile(error.to_string()))?;
    let mut copy = BTreeMap::new();
    for (key, value) in copy_object {
        copy.insert(
            key.clone(),
            json_string(value, &format!("copy.{key}"))
                .map(str::to_string)
                .map_err(|error| UiError::InvalidProfile(error.to_string()))?,
        );
    }

    let enabled_values = json_array(
        json_required(object, "enabled_modules", "enabled_modules")
            .map_err(|error| UiError::InvalidProfile(error.to_string()))?,
        "enabled_modules",
    )
    .map_err(|error| UiError::InvalidProfile(error.to_string()))?;
    let enabled_modules = enabled_values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json_string(value, &format!("enabled_modules[{index}]"))
                .map(str::to_string)
                .map_err(|error| UiError::InvalidProfile(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UiProfile {
        schema_version,
        product_id,
        profile_id,
        locale,
        copy,
        enabled_modules,
    })
}
