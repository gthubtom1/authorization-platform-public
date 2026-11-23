//! Bounded, transport-neutral ACV1 frames.

use std::collections::BTreeMap;
use std::fmt;

use super::authorization::{
    authorization_error_from_json_value, authorization_error_to_json_value,
    authorization_from_json_value, authorization_to_json_value, AuthorizationBinding,
    AuthorizationErrorResponseV1, AuthorizationResponseV1, IntegrityVerifier,
    AUTHORIZATION_A_CORE_PROTOCOL_VERSION,
};
use super::codec::*;
use super::contract::*;
use super::profile::ProductManifest;

pub const MAX_TRANSPORT_PAYLOAD_BYTES: usize = 64 * 1024;
pub const LOCAL_FRAME_HEADER_BYTES: usize = 8;
const LOCAL_FRAME_MAGIC: [u8; 4] = *b"ACV1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    FrameTooLarge { actual: usize, max: usize },
    Truncated,
    InvalidHeader,
    LengthMismatch { declared: usize, actual: usize },
    InvalidUtf8,
    MalformedPayload(String),
    Contract(ContractError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { actual, max } => {
                write!(
                    f,
                    "transport frame is too large: {actual} bytes (max {max})"
                )
            }
            Self::Truncated => write!(f, "transport frame is truncated"),
            Self::InvalidHeader => write!(f, "transport frame header is invalid"),
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "transport payload length mismatch: declared {declared}, received {actual}"
            ),
            Self::InvalidUtf8 => write!(f, "transport payload is not UTF-8"),
            Self::MalformedPayload(message) => {
                write!(f, "transport payload is malformed: {message}")
            }
            Self::Contract(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ContractError> for TransportError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]

pub enum CoreMessage {
    Snapshot(AuthorizationSnapshot),
    Authorization(AuthorizationResponseV1),
    Error(AuthorizationErrorResponseV1),
    Module(ModuleEnvelope),
}

impl CoreMessage {
    pub fn product_id(&self) -> &str {
        match self {
            Self::Snapshot(snapshot) => &snapshot.product_id,
            Self::Authorization(response) => &response.product_id,
            Self::Error(error) => &error.product_id,
            Self::Module(module) => &module.product_id,
        }
    }

    fn validate_for(&self, manifest: &ProductManifest) -> Result<(), ContractError> {
        match self {
            Self::Snapshot(snapshot) => snapshot.validate_for(manifest),
            Self::Authorization(response) => {
                if response.protocol != AUTHORIZATION_A_CORE_PROTOCOL_VERSION {
                    return Err(ContractError::ProtocolMismatch {
                        expected: AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string(),
                        actual: response.protocol.clone(),
                    });
                }
                response
                    .validate_for_manifest(manifest)
                    .map_err(|error| ContractError::InvalidSnapshot(error.to_string()))
            }
            Self::Error(error) => {
                if error.protocol != AUTHORIZATION_A_CORE_PROTOCOL_VERSION {
                    return Err(ContractError::ProtocolMismatch {
                        expected: AUTHORIZATION_A_CORE_PROTOCOL_VERSION.to_string(),
                        actual: error.protocol.clone(),
                    });
                }
                error
                    .validate_for_manifest(manifest)
                    .map_err(|error| ContractError::InvalidSnapshot(error.to_string()))
            }
            Self::Module(module) => module.validate_for(manifest),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTransportFrame {
    pub protocol: String,
    pub product_id: String,
    pub message: CoreMessage,
}

impl LocalTransportFrame {
    pub fn from_snapshot(snapshot: AuthorizationSnapshot) -> Self {
        Self {
            protocol: snapshot.protocol.clone(),
            product_id: snapshot.product_id.clone(),
            message: CoreMessage::Snapshot(snapshot),
        }
    }

    pub fn from_authorization(response: AuthorizationResponseV1) -> Self {
        Self {
            protocol: response.protocol.clone(),
            product_id: response.product_id.clone(),
            message: CoreMessage::Authorization(response),
        }
    }

    pub fn from_error(error: AuthorizationErrorResponseV1) -> Self {
        Self {
            protocol: error.protocol.clone(),
            product_id: error.product_id.clone(),
            message: CoreMessage::Error(error),
        }
    }

    pub fn from_module(module: ModuleEnvelope) -> Self {
        Self {
            protocol: module.protocol.clone(),
            product_id: module.product_id.clone(),
            message: CoreMessage::Module(module),
        }
    }

    pub fn validate_for(&self, manifest: &ProductManifest) -> Result<(), ContractError> {
        let expected_protocol = match &self.message {
            CoreMessage::Authorization(_) | CoreMessage::Error(_) => {
                AUTHORIZATION_A_CORE_PROTOCOL_VERSION
            }
            CoreMessage::Snapshot(_) | CoreMessage::Module(_) => A_CORE_PROTOCOL_VERSION,
        };
        if self.protocol != expected_protocol {
            return Err(ContractError::ProtocolMismatch {
                expected: expected_protocol.to_string(),
                actual: self.protocol.clone(),
            });
        }
        if self.product_id != manifest.product_id {
            return Err(ContractError::ProductMismatch {
                expected: manifest.product_id.clone(),
                actual: self.product_id.clone(),
            });
        }
        if self.message.product_id() != self.product_id {
            return Err(ContractError::ProductMismatch {
                expected: self.product_id.clone(),
                actual: self.message.product_id().to_string(),
            });
        }
        self.message.validate_for(manifest)
    }

    /// Encode a validated message as `ACV1` + little-endian payload length + UTF-8 JSON.
    /// The returned bytes are transport-neutral; no OS IPC endpoint is opened here.
    pub fn encode_for(&self, manifest: &ProductManifest) -> Result<Vec<u8>, TransportError> {
        self.validate_for(manifest)?;
        let payload = serialize_json(&transport_frame_to_json_value(self)).into_bytes();
        if payload.len() > MAX_TRANSPORT_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                actual: payload.len(),
                max: MAX_TRANSPORT_PAYLOAD_BYTES,
            });
        }

        let payload_length =
            u32::try_from(payload.len()).map_err(|_| TransportError::FrameTooLarge {
                actual: payload.len(),
                max: MAX_TRANSPORT_PAYLOAD_BYTES,
            })?;
        let mut frame = Vec::with_capacity(LOCAL_FRAME_HEADER_BYTES + payload.len());
        frame.extend_from_slice(&LOCAL_FRAME_MAGIC);
        frame.extend_from_slice(&payload_length.to_le_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    pub fn decode_for(bytes: &[u8], manifest: &ProductManifest) -> Result<Self, TransportError> {
        if bytes.len() < LOCAL_FRAME_HEADER_BYTES {
            return Err(TransportError::Truncated);
        }
        if bytes[..LOCAL_FRAME_MAGIC.len()] != LOCAL_FRAME_MAGIC {
            return Err(TransportError::InvalidHeader);
        }

        let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let actual = bytes.len() - LOCAL_FRAME_HEADER_BYTES;
        if declared != actual {
            return Err(TransportError::LengthMismatch { declared, actual });
        }
        if declared > MAX_TRANSPORT_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                actual: declared,
                max: MAX_TRANSPORT_PAYLOAD_BYTES,
            });
        }

        let payload = std::str::from_utf8(&bytes[LOCAL_FRAME_HEADER_BYTES..])
            .map_err(|_| TransportError::InvalidUtf8)?;
        let value = JsonParser::new(payload)
            .parse()
            .map_err(TransportError::MalformedPayload)?;
        let frame = transport_frame_from_json_value(value)?;
        frame.validate_for(manifest)?;
        Ok(frame)
    }

    pub fn encode_authorization_for(
        &self,
        manifest: &ProductManifest,
    ) -> Result<Vec<u8>, TransportError> {
        if !matches!(self.message, CoreMessage::Authorization(_)) {
            return Err(TransportError::MalformedPayload(
                "formal authorization encoder requires an authorization response".to_string(),
            ));
        }
        self.encode_for(manifest)
    }

    pub fn decode_authorization_for(
        bytes: &[u8],
        manifest: &ProductManifest,
    ) -> Result<Self, TransportError> {
        let frame = Self::decode_for(bytes, manifest)?;
        if !matches!(frame.message, CoreMessage::Authorization(_)) {
            return Err(TransportError::MalformedPayload(
                "formal authorization decoder requires an authorization response".to_string(),
            ));
        }
        Ok(frame)
    }

    /// Secure formal encoder. The fixture-only structural encoder above is
    /// intentionally separate so a production caller must provide the
    /// product binding and an actual verifier implementation.
    pub fn encode_verified_authorization_for<V: IntegrityVerifier>(
        response: AuthorizationResponseV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<Vec<u8>, TransportError> {
        response
            .verify_for_core(manifest, binding, verifier)
            .map_err(|error| {
                TransportError::Contract(ContractError::InvalidSnapshot(error.to_string()))
            })?;
        Self::from_authorization(response).encode_authorization_for(manifest)
    }

    /// Secure formal decoder. Structural parsing alone is not a trust
    /// decision; this method is the production-facing seam that requires the
    /// binding and verifier before the frame is accepted.
    pub fn decode_verified_authorization_for<V: IntegrityVerifier>(
        bytes: &[u8],
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<Self, TransportError> {
        let frame = Self::decode_authorization_for(bytes, manifest)?;
        if let CoreMessage::Authorization(response) = &frame.message {
            response
                .verify_for_core(manifest, binding, verifier)
                .map_err(|error| {
                    TransportError::Contract(ContractError::InvalidSnapshot(error.to_string()))
                })?;
            Ok(frame)
        } else {
            Err(TransportError::MalformedPayload(
                "formal authorization decoder requires an authorization response".to_string(),
            ))
        }
    }

    pub fn encode_verified_error_for<V: IntegrityVerifier>(
        error: AuthorizationErrorResponseV1,
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<Vec<u8>, TransportError> {
        error
            .validate_for_binding(manifest, binding)
            .map_err(|error| {
                TransportError::Contract(ContractError::InvalidSnapshot(error.to_string()))
            })?;
        error.verify(verifier).map_err(|error| {
            TransportError::Contract(ContractError::InvalidSnapshot(error.to_string()))
        })?;
        Self::from_error(error).encode_for(manifest)
    }

    pub fn decode_verified_error_for<V: IntegrityVerifier>(
        bytes: &[u8],
        manifest: &ProductManifest,
        binding: &AuthorizationBinding,
        verifier: &V,
    ) -> Result<Self, TransportError> {
        let frame = Self::decode_for(bytes, manifest)?;
        if let CoreMessage::Error(error) = &frame.message {
            error
                .validate_for_binding(manifest, binding)
                .map_err(|error| {
                    TransportError::Contract(ContractError::InvalidSnapshot(error.to_string()))
                })?;
            error.verify(verifier).map_err(|error| {
                TransportError::Contract(ContractError::InvalidSnapshot(error.to_string()))
            })?;
            Ok(frame)
        } else {
            Err(TransportError::MalformedPayload(
                "formal error decoder requires an authorization error response".to_string(),
            ))
        }
    }

    pub fn payload_len(&self) -> usize {
        serialize_json(&transport_frame_to_json_value(self)).len()
    }
}

fn transport_frame_to_json_value(frame: &LocalTransportFrame) -> JsonValue {
    let (kind, body) = match &frame.message {
        CoreMessage::Snapshot(snapshot) => {
            ("authorization_snapshot", snapshot_to_json_value(snapshot))
        }
        CoreMessage::Authorization(response) => (
            "authorization_response",
            authorization_to_json_value(response),
        ),
        CoreMessage::Error(error) => (
            "authorization_error",
            authorization_error_to_json_value(error),
        ),
        CoreMessage::Module(module) => ("module_envelope", module_to_json_value(module)),
    };
    let mut object = BTreeMap::new();
    object.insert("body".to_string(), body);
    object.insert("kind".to_string(), JsonValue::String(kind.to_string()));
    object.insert(
        "product_id".to_string(),
        JsonValue::String(frame.product_id.clone()),
    );
    object.insert(
        "protocol".to_string(),
        JsonValue::String(frame.protocol.clone()),
    );
    JsonValue::Object(object)
}

fn snapshot_to_json_value(snapshot: &AuthorizationSnapshot) -> JsonValue {
    let modules = snapshot.modules.iter().map(module_to_json_value).collect();
    let capabilities = snapshot
        .capabilities
        .iter()
        .cloned()
        .map(JsonValue::String)
        .collect();
    let mut object = BTreeMap::new();
    object.insert("capabilities".to_string(), JsonValue::Array(capabilities));
    object.insert(
        "device_id".to_string(),
        JsonValue::String(snapshot.device_id.clone()),
    );
    object.insert(
        "expires_at".to_string(),
        snapshot
            .expires_at
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "issued_at".to_string(),
        JsonValue::Number(snapshot.issued_at),
    );
    object.insert(
        "license_state".to_string(),
        JsonValue::String(snapshot.license_state.as_str().to_string()),
    );
    object.insert("modules".to_string(), JsonValue::Array(modules));
    object.insert(
        "product_id".to_string(),
        JsonValue::String(snapshot.product_id.clone()),
    );
    object.insert(
        "protocol".to_string(),
        JsonValue::String(snapshot.protocol.clone()),
    );
    object.insert(
        "snapshot_id".to_string(),
        JsonValue::String(snapshot.snapshot_id.clone()),
    );
    object.insert(
        "subject_id".to_string(),
        JsonValue::String(snapshot.subject_id.clone()),
    );
    JsonValue::Object(object)
}

fn module_to_json_value(module: &ModuleEnvelope) -> JsonValue {
    let payload = module
        .payload
        .iter()
        .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
        .collect();
    let mut object = BTreeMap::new();
    object.insert(
        "capability".to_string(),
        JsonValue::String(module.capability.clone()),
    );
    object.insert(
        "module_id".to_string(),
        JsonValue::String(module.module_id.clone()),
    );
    object.insert("payload".to_string(), JsonValue::Object(payload));
    object.insert(
        "product_id".to_string(),
        JsonValue::String(module.product_id.clone()),
    );
    object.insert(
        "protocol".to_string(),
        JsonValue::String(module.protocol.clone()),
    );
    object.insert(
        "version".to_string(),
        JsonValue::String(module.version.clone()),
    );
    JsonValue::Object(object)
}

fn transport_frame_from_json_value(
    value: JsonValue,
) -> Result<LocalTransportFrame, TransportError> {
    let object = json_object(&value, "transport frame")?;
    ensure_known_fields(
        object,
        &["protocol", "product_id", "kind", "body"],
        "transport frame",
    )?;
    let protocol = json_required_string(object, "protocol", "transport.protocol")?.to_string();
    let product_id =
        json_required_string(object, "product_id", "transport.product_id")?.to_string();
    let kind = json_required_string(object, "kind", "transport.kind")?;
    let body = json_required(object, "body", "transport.body")?.clone();
    let message = match kind {
        "authorization_snapshot" => CoreMessage::Snapshot(snapshot_from_json_value(body)?),
        "authorization_response" => CoreMessage::Authorization(
            authorization_from_json_value(body).map_err(TransportError::MalformedPayload)?,
        ),
        "authorization_error" => CoreMessage::Error(
            authorization_error_from_json_value(body).map_err(TransportError::MalformedPayload)?,
        ),
        "module_envelope" => CoreMessage::Module(module_from_json_value(body)?),
        _ => {
            return Err(TransportError::MalformedPayload(format!(
                "unknown transport message kind: {kind}"
            )))
        }
    };
    Ok(LocalTransportFrame {
        protocol,
        product_id,
        message,
    })
}

fn snapshot_from_json_value(value: JsonValue) -> Result<AuthorizationSnapshot, TransportError> {
    let object = json_object(&value, "authorization snapshot")?;
    ensure_known_fields(
        object,
        &[
            "protocol",
            "product_id",
            "snapshot_id",
            "subject_id",
            "device_id",
            "license_state",
            "issued_at",
            "expires_at",
            "capabilities",
            "modules",
        ],
        "authorization snapshot",
    )?;
    let capabilities = json_array(
        json_required(object, "capabilities", "snapshot.capabilities")?,
        "snapshot.capabilities",
    )?
    .iter()
    .enumerate()
    .map(|(index, value)| json_string(value, &format!("snapshot.capabilities[{index}]")))
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .map(str::to_string)
    .collect();
    let modules = json_array(
        json_required(object, "modules", "snapshot.modules")?,
        "snapshot.modules",
    )?
    .iter()
    .cloned()
    .map(module_from_json_value)
    .collect::<Result<Vec<_>, _>>()?;
    let expires_at = match json_required(object, "expires_at", "snapshot.expires_at")? {
        JsonValue::Null => None,
        value => Some(json_u64(value, "snapshot.expires_at")?),
    };
    let license_state = LicenseState::from_str(json_required_string(
        object,
        "license_state",
        "snapshot.license_state",
    )?)
    .ok_or_else(|| {
        TransportError::MalformedPayload("snapshot.license_state is unknown".to_string())
    })?;
    Ok(AuthorizationSnapshot {
        protocol: json_required_string(object, "protocol", "snapshot.protocol")?.to_string(),
        product_id: json_required_string(object, "product_id", "snapshot.product_id")?.to_string(),
        snapshot_id: json_required_string(object, "snapshot_id", "snapshot.snapshot_id")?
            .to_string(),
        subject_id: json_required_string(object, "subject_id", "snapshot.subject_id")?.to_string(),
        device_id: json_required_string(object, "device_id", "snapshot.device_id")?.to_string(),
        license_state,
        issued_at: json_u64(
            json_required(object, "issued_at", "snapshot.issued_at")?,
            "snapshot.issued_at",
        )?,
        expires_at,
        capabilities,
        modules,
    })
}

fn module_from_json_value(value: JsonValue) -> Result<ModuleEnvelope, TransportError> {
    let object = json_object(&value, "module envelope")?;
    ensure_known_fields(
        object,
        &[
            "protocol",
            "product_id",
            "module_id",
            "version",
            "capability",
            "payload",
        ],
        "module envelope",
    )?;
    let payload_object = json_object(
        json_required(object, "payload", "module.payload")?,
        "module.payload",
    )?;
    let mut payload = BTreeMap::new();
    for (key, value) in payload_object {
        payload.insert(
            key.clone(),
            json_string(value, &format!("module.payload.{key}"))?.to_string(),
        );
    }
    Ok(ModuleEnvelope {
        protocol: json_required_string(object, "protocol", "module.protocol")?.to_string(),
        product_id: json_required_string(object, "product_id", "module.product_id")?.to_string(),
        module_id: json_required_string(object, "module_id", "module.module_id")?.to_string(),
        version: json_required_string(object, "version", "module.version")?.to_string(),
        capability: json_required_string(object, "capability", "module.capability")?.to_string(),
        payload,
    })
}

fn json_u64(value: &JsonValue, field: &str) -> Result<u64, TransportError> {
    match value {
        JsonValue::Number(value) => Ok(*value),
        _ => Err(TransportError::MalformedPayload(format!(
            "{field} must be an unsigned integer"
        ))),
    }
}
