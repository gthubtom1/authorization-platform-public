//! Central-platform-shape (`authorization.v1`) response parsing.
//!
//! This module speaks the live platform contract, synced 2026-10-01 from
//! the platform checkout (`protocol/authorization.v1.schema.json`, fixtures
//! under `fixtures/authorization_v1/` and `fixtures/authorization_a_core_v1/`).
//! Source record: `protocol/SYNC-20251001.md`.
//!
//! Rules enforced here, all mirroring the platform:
//!
//! - Flat central envelope: no `protocol` / `product_id` / `snapshot_id` /
//!   top-level `device_id` / `identity` object. Unknown top-level fields are
//!   rejected, exactly like the platform schema (`additionalProperties: false`).
//! - `modules` is a fixed five-key object (`contact`, `notice`, `purchase`,
//!   `qr`, `update`) on this main path. The old module-array shape is NOT
//!   accepted here; it stays available on the separate legacy compatibility
//!   path (see `AuthorizationResponseV1`), which must not be deleted.
//! - Top-level `support` / `announcement` default to empty when absent;
//!   malformed presence still fails closed. (The platform schema marks them
//!   required, but real responses have been observed without display blocks.)
//! - Central `integrity` carries only `algorithm` / `key_id` /
//!   `canonicalization` / `signature`. `origin` / `audience` belong to the
//!   A-to-core envelope and are rejected on central responses.
//! - Request-only credentials (`device_public_key`, `device_proof`,
//!   `client_version`, `nonce`, top-level `installation_id`) must be absent.
//! - `decision` includes `unbound`; `not_modified` is a normal decision that
//!   keeps the core running, never an error.
//! - Structural failures collapse to one non-retryable
//!   `RESPONSE_SCHEMA_INVALID`, so the core cannot mistake malformed platform
//!   data for a product decision.
//!
//! Signature bytes themselves are NOT verified here: Ed25519/JCS-RFC8785
//! verification stays an explicit product-side dependency boundary (see
//! `docs/PLATFORM-INTEGRATION-HANDOFF.md`). Parsing only guarantees shape.

use std::collections::BTreeMap;

use super::authorization::{required_number, required_text, AuthorizationError};
use super::codec::{
    ensure_known_fields, json_object, json_required, json_required_string, JsonParser, JsonValue,
};

/// Support block: purchase link plus contact text. Empty means hide.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformSupport {
    pub purchase_url: Option<String>,
    pub qq: Option<String>,
    pub wechat: Option<String>,
}

impl PlatformSupport {
    pub fn is_empty(&self) -> bool {
        self.purchase_url
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
            && self.qq.as_ref().is_none_or(|value| value.trim().is_empty())
            && self
                .wechat
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
    }
}

/// Announcement block: title plus body text. Empty means hide.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformAnnouncement {
    pub title: Option<String>,
    pub body: Option<String>,
}

impl PlatformAnnouncement {
    pub fn is_empty(&self) -> bool {
        self.title
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
            && self
                .body
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
    }
}

/// Update block: presence plus best-effort extracted strings.
/// Unknown update fields are ignored; presence alone drives re-check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformUpdateInfo {
    pub version: Option<String>,
    pub open_url: Option<String>,
    pub has_update: Option<bool>,
}

/// Fixed five-key modules object. `notice` is the platform name;
/// the old template-internal `announcement` module name maps to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformModules {
    pub contact: PlatformSupport,
    pub notice: PlatformAnnouncement,
    pub purchase_present: bool,
    pub qr_present: bool,
    pub update: Option<PlatformUpdateInfo>,
}

/// Server-confirmed device scope. Null ids mean "not yet confirmed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDeviceScope {
    pub device_id: Option<String>,
    pub installation_id: Option<String>,
}

/// Central proof reference. Bytes are not verified in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformIntegrity {
    pub key_id: String,
}

/// Central decisions. `NotModified` keeps the core running on the
/// existing lease; `Unbound` is the deactivate-compatibility path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformDecision {
    Active,
    Grace,
    Expired,
    Revoked,
    Blocked,
    NotModified,
    Unbound,
}

impl PlatformDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Blocked => "blocked",
            Self::NotModified => "not_modified",
            Self::Unbound => "unbound",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "grace" => Some(Self::Grace),
            "expired" => Some(Self::Expired),
            "revoked" => Some(Self::Revoked),
            "blocked" => Some(Self::Blocked),
            "not_modified" => Some(Self::NotModified),
            "unbound" => Some(Self::Unbound),
            _ => None,
        }
    }

    /// Decisions that must stop the core immediately.
    pub const fn must_stop_core(self) -> bool {
        !matches!(self, Self::Active | Self::Grace | Self::NotModified)
    }
}

/// Parsed central response in platform shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformResponse {
    pub request_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub target: String,
    pub arch: String,
    pub channel: String,
    pub authorization_id: String,
    pub authorization_revision: u64,
    pub device_scope: PlatformDeviceScope,
    pub decision: PlatformDecision,
    pub state_code: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub server_time: u64,
    pub cache_until: u64,
    pub next_verify_at: u64,
    pub grace_until: u64,
    pub config_version: String,
    pub support: PlatformSupport,
    pub announcement: PlatformAnnouncement,
    pub modules: PlatformModules,
    pub integrity: PlatformIntegrity,
    /// Inline error detail some decisions (e.g. blocked) carry alongside
    /// the response. Presence never changes the decision.
    pub error_code: Option<String>,
}

/// Parsed central error envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
    pub retryable: bool,
    pub http_status: Option<u64>,
}

/// Either a central response or a central error envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformEnvelope {
    Response(PlatformResponse),
    Error(PlatformErrorBody),
}

fn invalid(message: String) -> AuthorizationError {
    AuthorizationError::ResponseSchemaInvalid(message)
}

fn capped_text(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
    max: usize,
) -> Result<String, String> {
    let value = required_text(object, key, field)?;
    if value.len() > max {
        return Err(format!("{field} exceeds {max} bytes"));
    }
    if value.trim().is_empty() {
        return Err(format!("{field} must not be blank"));
    }
    Ok(value.to_string())
}

fn nullable_capped_text(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
    max: usize,
) -> Result<Option<String>, String> {
    let value = json_required(object, key, field).map_err(|error| error.to_string())?;
    match value {
        JsonValue::Null => Ok(None),
        JsonValue::String(text) => {
            if text.len() > max {
                return Err(format!("{field} exceeds {max} bytes"));
            }
            if text.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(text.clone()))
            }
        }
        _ => Err(format!("{field} must be a string or null")),
    }
}

fn parse_support(value: &JsonValue, field: &str) -> Result<PlatformSupport, String> {
    match value {
        JsonValue::Null => Ok(PlatformSupport::default()),
        JsonValue::Object(object) => {
            ensure_known_fields(object, &["purchase_url", "qq", "wechat"], field)
                .map_err(|error| error.to_string())?;
            Ok(PlatformSupport {
                purchase_url: nullable_capped_text(
                    object,
                    "purchase_url",
                    &format!("{field}.purchase_url"),
                    2048,
                )?,
                qq: nullable_capped_text(object, "qq", &format!("{field}.qq"), 64)?,
                wechat: nullable_capped_text(object, "wechat", &format!("{field}.wechat"), 64)?,
            })
        }
        _ => Err(format!("{field} must be an object or null")),
    }
}

fn parse_announcement(value: &JsonValue, field: &str) -> Result<PlatformAnnouncement, String> {
    match value {
        JsonValue::Null => Ok(PlatformAnnouncement::default()),
        JsonValue::Object(object) => {
            ensure_known_fields(object, &["title", "body"], field)
                .map_err(|error| error.to_string())?;
            Ok(PlatformAnnouncement {
                title: nullable_capped_text(object, "title", &format!("{field}.title"), 120)?,
                body: nullable_capped_text(object, "body", &format!("{field}.body"), 2000)?,
            })
        }
        _ => Err(format!("{field} must be an object or null")),
    }
}

fn optional_string_in(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    max: usize,
) -> Option<String> {
    match object.get(key) {
        Some(JsonValue::String(text)) if !text.trim().is_empty() && text.len() <= max => {
            Some(text.clone())
        }
        _ => None,
    }
}

fn parse_update(value: &JsonValue, field: &str) -> Result<Option<PlatformUpdateInfo>, String> {
    match value {
        JsonValue::Null => Ok(None),
        JsonValue::Object(object) => {
            let has_update = match object.get("has_update") {
                Some(JsonValue::Bool(flag)) => Some(*flag),
                Some(JsonValue::Null) | None => None,
                _ => return Err(format!("{field}.has_update must be a boolean or null")),
            };
            let open_url = optional_string_in(object, "update_open_url", 2048)
                .or_else(|| optional_string_in(object, "download_url", 2048))
                .or_else(|| optional_string_in(object, "url", 2048));
            Ok(Some(PlatformUpdateInfo {
                version: optional_string_in(object, "version", 64),
                open_url,
                has_update,
            }))
        }
        _ => Err(format!("{field} must be an object or null")),
    }
}

fn parse_modules(value: &JsonValue) -> Result<PlatformModules, String> {
    let object = json_object(value, "modules").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &["contact", "notice", "purchase", "qr", "update"],
        "modules",
    )
    .map_err(|error| error.to_string())?;
    let get = |key: &str| {
        json_required(object, key, &format!("modules.{key}")).map_err(|error| error.to_string())
    };
    let contact = parse_support(get("contact")?, "modules.contact")?;
    let notice = parse_announcement(get("notice")?, "modules.notice")?;
    let purchase_present = !matches!(get("purchase")?, JsonValue::Null);
    if !matches!(get("purchase")?, JsonValue::Null | JsonValue::Object(_)) {
        return Err("modules.purchase must be an object or null".to_string());
    }
    let qr_present = !matches!(get("qr")?, JsonValue::Null);
    if !matches!(get("qr")?, JsonValue::Null | JsonValue::Object(_)) {
        return Err("modules.qr must be an object or null".to_string());
    }
    let update = parse_update(get("update")?, "modules.update")?;
    Ok(PlatformModules {
        contact,
        notice,
        purchase_present,
        qr_present,
        update,
    })
}

/// Ticket integrity carries six keys: the central four plus `origin` and
/// `audience`. The central 4-key gate must NOT be reused here, or real
/// tickets are rejected.
fn parse_ticket_integrity(
    value: &JsonValue,
    software_id: &str,
) -> Result<PlatformIntegrity, String> {
    let object = json_object(value, "integrity").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &[
            "algorithm",
            "key_id",
            "canonicalization",
            "origin",
            "audience",
            "signature",
        ],
        "integrity",
    )
    .map_err(|error| error.to_string())?;
    let algorithm = json_required_string(object, "algorithm", "integrity.algorithm")
        .map_err(|error| error.to_string())?;
    if algorithm != "ed25519" {
        return Err("integrity.algorithm must be ed25519".to_string());
    }
    let canonicalization =
        json_required_string(object, "canonicalization", "integrity.canonicalization")
            .map_err(|error| error.to_string())?;
    if canonicalization != "JCS-RFC8785" {
        return Err("integrity.canonicalization must be JCS-RFC8785".to_string());
    }
    let key_id = capped_text(object, "key_id", "integrity.key_id", 128)?;
    let signature = capped_text(object, "signature", "integrity.signature", 4096)?;
    let _ = signature;
    let origin = capped_text(object, "origin", "integrity.origin", 64)?;
    if origin != "authorization-platform" {
        return Err("ticket integrity.origin must be authorization-platform".to_string());
    }
    let audience = capped_text(object, "audience", "integrity.audience", 128)?;
    let expected = format!("{software_id}-core");
    if audience != expected {
        return Err(format!(
            "ticket integrity.audience must be {expected}, got {audience}"
        ));
    }
    Ok(PlatformIntegrity { key_id })
}

fn parse_device_scope(value: &JsonValue) -> Result<PlatformDeviceScope, String> {
    let object = json_object(value, "device_scope").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &["scope", "device_id", "installation_id"],
        "device_scope",
    )
    .map_err(|error| error.to_string())?;
    let scope = json_required_string(object, "scope", "device_scope.scope")
        .map_err(|error| error.to_string())?;
    if scope != "current_device" {
        return Err("device_scope.scope must be current_device".to_string());
    }
    Ok(PlatformDeviceScope {
        device_id: nullable_capped_text(object, "device_id", "device_scope.device_id", 64)?,
        installation_id: nullable_capped_text(
            object,
            "installation_id",
            "device_scope.installation_id",
            128,
        )?,
    })
}

fn parse_integrity(value: &JsonValue) -> Result<PlatformIntegrity, String> {
    let object = json_object(value, "integrity").map_err(|error| error.to_string())?;
    ensure_known_fields(
        object,
        &["algorithm", "key_id", "canonicalization", "signature"],
        "integrity",
    )
    .map_err(|error| error.to_string())?;
    let algorithm = json_required_string(object, "algorithm", "integrity.algorithm")
        .map_err(|error| error.to_string())?;
    if algorithm != "ed25519" {
        return Err("integrity.algorithm must be ed25519".to_string());
    }
    let canonicalization =
        json_required_string(object, "canonicalization", "integrity.canonicalization")
            .map_err(|error| error.to_string())?;
    if canonicalization != "JCS-RFC8785" {
        return Err("integrity.canonicalization must be JCS-RFC8785".to_string());
    }
    let key_id = capped_text(object, "key_id", "integrity.key_id", 128)?;
    let signature = capped_text(object, "signature", "integrity.signature", 4096)?;
    let _ = signature;
    Ok(PlatformIntegrity { key_id })
}

const RESPONSE_KNOWN_FIELDS: &[&str] = &[
    "schema_version",
    "request_id",
    "software_id",
    "profile_id",
    "client_id",
    "contract_version",
    "target",
    "arch",
    "channel",
    "authorization_id",
    "authorization_revision",
    "device_scope",
    "decision",
    "state_code",
    "issued_at",
    "expires_at",
    "server_time",
    "cache_until",
    "next_verify_at",
    "grace_until",
    "config_version",
    "status",
    "policy_version",
    "adapter_key",
    "adapter_version",
    "capabilities",
    "entitlements",
    "support",
    "announcement",
    "purchase",
    "qr",
    "update",
    "modules",
    "binding_state",
    "error",
    "extensions",
    "integrity",
];

/// Request-only credentials must never appear in a central response.
const REQUEST_ONLY_FIELDS: &[&str] = &[
    "device_public_key",
    "device_proof",
    "client_version",
    "nonce",
    "installation_id",
];

fn parse_response(object: BTreeMap<String, JsonValue>) -> Result<PlatformResponse, String> {
    ensure_known_fields(&object, RESPONSE_KNOWN_FIELDS, "platform response")
        .map_err(|error| error.to_string())?;
    for forbidden in REQUEST_ONLY_FIELDS {
        if object.contains_key(*forbidden) {
            return Err(format!(
                "platform response must not carry request-only field: {forbidden}"
            ));
        }
    }
    let schema_version = capped_text(&object, "schema_version", "schema_version", 64)?;
    if schema_version != "authorization.v1" {
        return Err("schema_version must be authorization.v1".to_string());
    }
    let contract_version = capped_text(&object, "contract_version", "contract_version", 64)?;
    if contract_version != "authorization.v1" {
        return Err("contract_version must be authorization.v1".to_string());
    }
    let decision =
        PlatformDecision::from_str(capped_text(&object, "decision", "decision", 32)?.as_str())
            .ok_or_else(|| "decision contains an unknown value".to_string())?;
    let expires_at = required_number(&object, "expires_at")?;
    let cache_until = required_number(&object, "cache_until")?;
    let next_verify_at = required_number(&object, "next_verify_at")?;
    // Platform invariant: re-ask times never exceed the card expiry.
    if cache_until > expires_at {
        return Err("cache_until must not exceed expires_at".to_string());
    }
    if next_verify_at > expires_at {
        return Err("next_verify_at must not exceed expires_at".to_string());
    }
    let revision = required_number(&object, "authorization_revision")?;
    if revision < 1 {
        return Err("authorization_revision must be at least 1".to_string());
    }
    // Deviation note (2026-10-01): the platform schema marks
    // support/announcement/modules required, but the platform's own
    // `blocked.json` fixture omits `announcement`. Real servers may drop
    // display blocks on some paths, so absence defaults to empty while
    // malformed presence still fails closed. All other required fields
    // stay strict.
    let support = match object.get("support") {
        None => PlatformSupport::default(),
        Some(value) => parse_support(value, "support")?,
    };
    let announcement = match object.get("announcement") {
        None => PlatformAnnouncement::default(),
        Some(value) => parse_announcement(value, "announcement")?,
    };
    let modules = match object.get("modules") {
        None => PlatformModules {
            contact: PlatformSupport::default(),
            notice: PlatformAnnouncement::default(),
            purchase_present: false,
            qr_present: false,
            update: None,
        },
        Some(value) => parse_modules(value)?,
    };
    if let Some(capabilities) = object.get("capabilities") {
        if !matches!(capabilities, JsonValue::Object(_)) {
            return Err("capabilities must be an object".to_string());
        }
    }
    if let Some(entitlements) = object.get("entitlements") {
        if !matches!(entitlements, JsonValue::Object(_)) {
            return Err("entitlements must be an object".to_string());
        }
    }
    // Some decisions (e.g. blocked) carry an inline error detail object
    // next to the response. It must be an object when present; only the
    // code is lifted, and it never overrides the decision.
    let error_code = match object.get("error") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Object(detail)) => match detail.get("code") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(code)) => Some(code.clone()),
            _ => return Err("error.code must be a string".to_string()),
        },
        _ => return Err("error must be an object".to_string()),
    };
    Ok(PlatformResponse {
        request_id: capped_text(&object, "request_id", "request_id", 128)?,
        software_id: capped_text(&object, "software_id", "software_id", 64)?,
        profile_id: capped_text(&object, "profile_id", "profile_id", 64)?,
        client_id: capped_text(&object, "client_id", "client_id", 128)?,
        target: capped_text(&object, "target", "target", 32)?,
        arch: capped_text(&object, "arch", "arch", 32)?,
        channel: capped_text(&object, "channel", "channel", 32)?,
        authorization_id: capped_text(&object, "authorization_id", "authorization_id", 64)?,
        authorization_revision: revision,
        device_scope: parse_device_scope(
            json_required(&object, "device_scope", "device_scope")
                .map_err(|error| error.to_string())?,
        )?,
        decision,
        state_code: capped_text(&object, "state_code", "state_code", 32)?,
        issued_at: required_number(&object, "issued_at")?,
        expires_at,
        server_time: required_number(&object, "server_time")?,
        cache_until,
        next_verify_at,
        grace_until: required_number(&object, "grace_until")?,
        config_version: capped_text(&object, "config_version", "config_version", 64)?,
        support,
        announcement,
        modules,
        integrity: parse_integrity(
            json_required(&object, "integrity", "integrity").map_err(|error| error.to_string())?,
        )?,
        error_code,
    })
}

fn parse_error_envelope(object: BTreeMap<String, JsonValue>) -> Result<PlatformErrorBody, String> {
    ensure_known_fields(&object, &["error", "transport"], "platform error envelope")
        .map_err(|error| error.to_string())?;
    let error = json_object(
        json_required(&object, "error", "error").map_err(|error| error.to_string())?,
        "error",
    )
    .map_err(|error| error.to_string())?;
    ensure_known_fields(
        error,
        &["code", "message", "request_id", "retryable"],
        "error",
    )
    .map_err(|error| error.to_string())?;
    let http_status = match object.get("transport") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Object(transport)) => match transport.get("http_status") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::Number(status)) => Some(*status),
            _ => return Err("transport.http_status must be a number".to_string()),
        },
        _ => return Err("transport must be an object".to_string()),
    };
    let retryable = match error.get("retryable") {
        Some(JsonValue::Bool(flag)) => *flag,
        _ => return Err("error.retryable must be a boolean".to_string()),
    };
    Ok(PlatformErrorBody {
        code: capped_text(error, "code", "error.code", 64)?,
        message: capped_text(error, "message", "error.message", 1024)?,
        request_id: capped_text(error, "request_id", "error.request_id", 128)?,
        retryable,
        http_status,
    })
}

/// Parse one central-platform payload: either a response or an error
/// envelope. Structural failures map to non-retryable
/// `RESPONSE_SCHEMA_INVALID`.
pub fn parse_platform_envelope(input: &str) -> Result<PlatformEnvelope, AuthorizationError> {
    let value = JsonParser::new(input)
        .parse()
        .map_err(|error| invalid(error.to_string()))?;
    let object =
        json_object(&value, "platform response").map_err(|error| invalid(error.to_string()))?;
    // Dispatch on shape: responses carry `decision`, standalone errors do
    // not (a response may still carry an inline `error` detail object).
    if object.contains_key("decision") {
        return parse_response(object.clone())
            .map(PlatformEnvelope::Response)
            .map_err(invalid);
    }
    if object.contains_key("error") {
        return parse_error_envelope(object.clone())
            .map(PlatformEnvelope::Error)
            .map_err(invalid);
    }
    Err(invalid(
        "platform payload has neither decision nor error".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Launch ticket (ADR-0018 on the platform side). One short-lived,
// single-device ticket per launch; the core pins only the platform public
// key. Real Ed25519/JCS verification stays a product-side boundary, same as
// central responses: parsing below guarantees shape, never authenticity.

/// Ticket decisions on the central envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketDecision {
    Issued,
    Consumed,
}

impl TicketDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Consumed => "consumed",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "issued" => Some(Self::Issued),
            "consumed" => Some(Self::Consumed),
            _ => None,
        }
    }
}

/// Parsed ticket body. Times are Unix seconds from the platform server clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTicket {
    pub ticket_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub installation_id: String,
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub audience: String,
}

/// Parsed ticket issue response (central envelope subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTicketResponse {
    pub request_id: String,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub authorization_id: String,
    pub authorization_revision: u64,
    pub decision: TicketDecision,
    pub server_time: u64,
    pub ticket: PlatformTicket,
    pub integrity_key_id: String,
}

const TICKET_KNOWN_FIELDS: &[&str] = &[
    "schema_version",
    "contract_version",
    "request_id",
    "software_id",
    "profile_id",
    "client_id",
    "target",
    "arch",
    "channel",
    "authorization_id",
    "authorization_revision",
    "decision",
    "server_time",
    "ticket",
    "integrity",
];

const TICKET_BODY_KNOWN_FIELDS: &[&str] = &[
    "ticket_id",
    "software_id",
    "profile_id",
    "client_id",
    "installation_id",
    "issued_at",
    "not_before",
    "expires_at",
    "audience",
];

/// Parse and validate a ticket issue response. Fails closed on any shape
/// deviation, including a wrong audience or a non-positive lifetime.
pub fn parse_ticket_response(input: &str) -> Result<PlatformTicketResponse, AuthorizationError> {
    let value = JsonParser::new(input)
        .parse()
        .map_err(|error| invalid(error.to_string()))?;
    let object =
        json_object(&value, "ticket response").map_err(|error| invalid(error.to_string()))?;
    if object.contains_key("decision") {
        return parse_ticket_object(object.clone()).map_err(invalid);
    }
    if object.contains_key("error") {
        let body = parse_error_envelope(object.clone()).map_err(invalid)?;
        return Err(invalid(format!("ticket endpoint refused: {}", body.code)));
    }
    Err(invalid(
        "ticket payload has neither decision nor error".to_string(),
    ))
}

fn parse_ticket_object(
    object: BTreeMap<String, JsonValue>,
) -> Result<PlatformTicketResponse, String> {
    ensure_known_fields(&object, TICKET_KNOWN_FIELDS, "ticket response")
        .map_err(|error| error.to_string())?;
    for forbidden in REQUEST_ONLY_FIELDS {
        if object.contains_key(*forbidden) {
            return Err(format!(
                "ticket response must not carry request-only field: {forbidden}"
            ));
        }
    }
    if capped_text(&object, "schema_version", "schema_version", 64)? != "authorization.v1" {
        return Err("ticket schema_version must be authorization.v1".to_string());
    }
    if capped_text(&object, "contract_version", "contract_version", 64)? != "authorization.v1" {
        return Err("ticket contract_version must be authorization.v1".to_string());
    }
    let decision =
        TicketDecision::from_str(capped_text(&object, "decision", "decision", 32)?.as_str())
            .ok_or_else(|| "ticket decision contains an unknown value".to_string())?;
    if decision != TicketDecision::Issued {
        return Err("ticket response decision must be issued".to_string());
    }
    let software_id = capped_text(&object, "software_id", "software_id", 64)?;
    let ticket = parse_ticket_body(
        json_required(&object, "ticket", "ticket").map_err(|error| error.to_string())?,
        &software_id,
    )?;
    if ticket.software_id != software_id {
        return Err("ticket.software_id must match the envelope".to_string());
    }
    let profile_id = capped_text(&object, "profile_id", "profile_id", 64)?;
    if ticket.profile_id != profile_id {
        return Err("ticket.profile_id must match the envelope".to_string());
    }
    let client_id = capped_text(&object, "client_id", "client_id", 128)?;
    if ticket.client_id != client_id {
        return Err("ticket.client_id must match the envelope".to_string());
    }
    let integrity = parse_ticket_integrity(
        json_required(&object, "integrity", "integrity").map_err(|error| error.to_string())?,
        &software_id,
    )?;
    let revision = required_number(&object, "authorization_revision")?;
    if revision < 1 {
        return Err("authorization_revision must be at least 1".to_string());
    }
    Ok(PlatformTicketResponse {
        request_id: capped_text(&object, "request_id", "request_id", 128)?,
        software_id,
        profile_id,
        client_id,
        authorization_id: capped_text(&object, "authorization_id", "authorization_id", 64)?,
        authorization_revision: revision,
        decision,
        server_time: required_number(&object, "server_time")?,
        ticket,
        integrity_key_id: integrity.key_id,
    })
}

fn parse_ticket_body(value: &JsonValue, software_id: &str) -> Result<PlatformTicket, String> {
    let object = json_object(value, "ticket").map_err(|error| error.to_string())?;
    ensure_known_fields(object, TICKET_BODY_KNOWN_FIELDS, "ticket")
        .map_err(|error| error.to_string())?;
    let audience = capped_text(object, "audience", "ticket.audience", 128)?;
    let expected = format!("{software_id}-core");
    if audience != expected {
        return Err(format!(
            "ticket audience must be {expected}, got {audience}"
        ));
    }
    let issued_at = required_number(object, "issued_at")?;
    let not_before = required_number(object, "not_before")?;
    let expires_at = required_number(object, "expires_at")?;
    if not_before > expires_at {
        return Err("ticket not_before must not exceed expires_at".to_string());
    }
    if expires_at <= issued_at {
        return Err("ticket lifetime must be positive".to_string());
    }
    Ok(PlatformTicket {
        ticket_id: capped_text(object, "ticket_id", "ticket.ticket_id", 64)?,
        software_id: capped_text(object, "software_id", "ticket.software_id", 64)?,
        profile_id: capped_text(object, "profile_id", "ticket.profile_id", 64)?,
        client_id: capped_text(object, "client_id", "ticket.client_id", 128)?,
        installation_id: capped_text(object, "installation_id", "ticket.installation_id", 128)?,
        issued_at,
        not_before,
        expires_at,
        audience,
    })
}

/// Single-use ticket wallet: the launcher holds at most one live ticket per
/// launch, consumes it when the core starts, and never reuses it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TicketWallet {
    ticket: Option<PlatformTicket>,
    consumed: bool,
}

impl TicketWallet {
    /// Store a freshly issued ticket, replacing any expired one. A live
    /// (unexpired, unconsumed) ticket is never overwritten by an older one.
    pub fn store(&mut self, ticket: PlatformTicket, now: u64) {
        let replace = match &self.ticket {
            None => true,
            Some(current) => self.consumed || current.expires_at <= now,
        };
        if replace {
            self.ticket = Some(ticket);
            self.consumed = false;
        }
    }

    /// Take the ticket for exactly one core launch. Fails closed when absent,
    /// already consumed, expired, bound to another device, or mis-addressed.
    pub fn take_for_launch(
        &mut self,
        software_id: &str,
        installation_id: &str,
        now: u64,
    ) -> Result<PlatformTicket, String> {
        let ticket = self
            .ticket
            .as_ref()
            .ok_or_else(|| "no launch ticket held".to_string())?;
        if self.consumed {
            return Err("launch ticket already consumed".to_string());
        }
        if ticket.software_id != software_id {
            return Err("launch ticket software mismatch".to_string());
        }
        if ticket.audience != format!("{software_id}-core") {
            return Err("launch ticket audience mismatch".to_string());
        }
        if ticket.installation_id != installation_id {
            return Err("launch ticket device mismatch".to_string());
        }
        if now < ticket.not_before || now >= ticket.expires_at {
            return Err("launch ticket not valid at this time".to_string());
        }
        self.consumed = true;
        Ok(ticket.clone())
    }
}

// ---------------------------------------------------------------------------
// Ticket request builder. Mirrors the platform `_normalize_request` gates so
// a malformed request fails locally before any network use.

/// Which ticket endpoint the request targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRequestAction {
    Issue,
    Consume,
}

impl TicketRequestAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "launch-ticket",
            Self::Consume => "ticket-consume",
        }
    }

    /// Endpoint path for this action.
    pub fn path(self) -> &'static str {
        match self {
            Self::Issue => "/api/v1/public/licenses/launch-ticket",
            Self::Consume => "/api/v1/public/licenses/launch-ticket/consume",
        }
    }
}

/// All ticket request fields. `device_proof` is attached by the product after
/// signing the proof message (see `protocol/launch-ticket.v1.md`); the
/// builder validates everything else up front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRequestParams {
    pub action: TicketRequestAction,
    pub request_id: String,
    /// Optional idempotency key; when absent the request_id is reused, matching
    /// the platform header/body rule.
    pub idempotency_key: Option<String>,
    pub software_id: String,
    pub profile_id: String,
    pub client_id: String,
    pub target: String,
    pub arch: String,
    pub channel: String,
    pub authorization_id: String,
    pub installation_id: String,
    pub device_public_key: String,
    pub client_version: String,
    pub nonce: String,
    pub ticket_id: Option<String>,
}

fn ticket_field(value: &str, field: &str, max: usize) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must not be blank"));
    }
    if trimmed.len() > max {
        return Err(format!("{field} exceeds {max} bytes"));
    }
    Ok(trimmed.to_string())
}

/// Build the canonical ticket request JSON (without `device_proof`, which
/// the product signs and attaches). Mirrors server gates: required fields,
/// lengths, `nonce` length, and `ticket_id` exactly for consume.
pub fn build_ticket_request(params: &TicketRequestParams) -> Result<String, String> {
    if params.nonce.trim().len() < 8 {
        return Err("nonce must contain at least 8 characters".to_string());
    }
    let mut object = BTreeMap::new();
    object.insert(
        "request_id".to_string(),
        JsonValue::String(ticket_field(&params.request_id, "request_id", 128)?),
    );
    let idempotency = params
        .idempotency_key
        .as_deref()
        .unwrap_or(params.request_id.trim());
    object.insert(
        "idempotency_key".to_string(),
        JsonValue::String(ticket_field(idempotency, "idempotency_key", 128)?),
    );
    object.insert(
        "software_id".to_string(),
        JsonValue::String(ticket_field(&params.software_id, "software_id", 64)?),
    );
    object.insert(
        "profile_id".to_string(),
        JsonValue::String(ticket_field(&params.profile_id, "profile_id", 64)?),
    );
    object.insert(
        "client_id".to_string(),
        JsonValue::String(ticket_field(&params.client_id, "client_id", 128)?),
    );
    object.insert(
        "contract_version".to_string(),
        JsonValue::String("authorization.v1".to_string()),
    );
    object.insert(
        "target".to_string(),
        JsonValue::String(ticket_field(&params.target, "target", 32)?),
    );
    object.insert(
        "arch".to_string(),
        JsonValue::String(ticket_field(&params.arch, "arch", 32)?),
    );
    object.insert(
        "channel".to_string(),
        JsonValue::String(ticket_field(&params.channel, "channel", 32)?),
    );
    object.insert(
        "authorization_id".to_string(),
        JsonValue::String(ticket_field(
            &params.authorization_id,
            "authorization_id",
            64,
        )?),
    );
    object.insert(
        "installation_id".to_string(),
        JsonValue::String(ticket_field(
            &params.installation_id,
            "installation_id",
            128,
        )?),
    );
    object.insert(
        "device_public_key".to_string(),
        JsonValue::String(ticket_field(
            &params.device_public_key,
            "device_public_key",
            256,
        )?),
    );
    object.insert(
        "client_version".to_string(),
        JsonValue::String(ticket_field(&params.client_version, "client_version", 64)?),
    );
    object.insert(
        "nonce".to_string(),
        JsonValue::String(params.nonce.trim().to_string()),
    );
    match (&params.action, &params.ticket_id) {
        (TicketRequestAction::Consume, Some(ticket_id)) => {
            object.insert(
                "ticket_id".to_string(),
                JsonValue::String(ticket_field(ticket_id, "ticket_id", 64)?),
            );
        }
        (TicketRequestAction::Consume, None) => {
            return Err("ticket_id is required for consume".to_string())
        }
        (TicketRequestAction::Issue, Some(_)) => {
            return Err("ticket_id must not appear on issue".to_string())
        }
        (TicketRequestAction::Issue, None) => {}
    }
    Ok(super::codec::serialize_json(&JsonValue::Object(object)))
}
