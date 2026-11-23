use std::collections::BTreeMap;
use std::path::PathBuf;

use authorization_a_template::{
    AuthorizationSnapshot, Capability, CompatibilityMode, ContractError, LicenseState,
    LocalTransportFrame, ModuleEnvelope, ProductManifest, ThemeTokens, TransportError,
    LOCAL_FRAME_HEADER_BYTES, MAX_MODULE_PAYLOAD_ENTRIES, MAX_SNAPSHOT_MODULES,
    MAX_TRANSPORT_PAYLOAD_BYTES,
};

fn manifest(
    product_id: &str,
    state_root: &str,
    ipc_name: &str,
    capabilities: Vec<Capability>,
) -> ProductManifest {
    ProductManifest::new(
        product_id,
        product_id,
        format!("{product_id}-adapter"),
        "1.0.0",
        "en-US",
        ThemeTokens::neutral(),
        PathBuf::from(format!("core/{product_id}.exe")),
        PathBuf::from(state_root),
        ipc_name,
        CompatibilityMode::LegacyAuth,
        capabilities,
    )
    .with_category("tools")
}

fn module(product_id: &str, module_id: &str, capability: &str) -> ModuleEnvelope {
    let mut payload = BTreeMap::new();
    payload.insert("channel".to_string(), "stable".to_string());
    payload.insert("version".to_string(), "2026.08".to_string());
    ModuleEnvelope::new(product_id, module_id, "1.0.0", capability, payload)
}

fn snapshot(product_id: &str, modules: Vec<ModuleEnvelope>) -> AuthorizationSnapshot {
    AuthorizationSnapshot::new(
        product_id,
        "snapshot-transport-1",
        "subject-transport-1",
        "device-transport-1",
        LicenseState::Active,
        1_755_000_000,
        None,
        vec!["launch".to_string(), "updates".to_string()],
        modules,
    )
}

#[test]
fn snapshot_and_module_frames_round_trip_with_product_binding() {
    let manifest = manifest(
        "skin-studio",
        "state/skin-studio",
        "a-skin",
        vec![
            Capability::required("launch", "1"),
            Capability::optional("updates", "1"),
        ],
    );
    let snapshot = snapshot(
        "skin-studio",
        vec![module("skin-studio", "update-metadata", "updates")],
    );

    let snapshot_frame = LocalTransportFrame::from_snapshot(snapshot);
    let snapshot_bytes = snapshot_frame.encode_for(&manifest).unwrap();
    let decoded_snapshot = LocalTransportFrame::decode_for(&snapshot_bytes, &manifest).unwrap();
    assert_eq!(decoded_snapshot, snapshot_frame);

    let module_frame =
        LocalTransportFrame::from_module(module("skin-studio", "channel-info", "updates"));
    let module_bytes = module_frame.encode_for(&manifest).unwrap();
    let decoded_module = LocalTransportFrame::decode_for(&module_bytes, &manifest).unwrap();
    assert_eq!(decoded_module, module_frame);
    assert_eq!(&module_bytes[..4], b"ACV1");
}

#[test]
fn acv1_snapshot_wire_bytes_remain_canonical() {
    let manifest = manifest(
        "wire-check",
        "state/wire-check",
        "a-wire-check",
        vec![Capability::required("launch", "1")],
    );
    let snapshot = AuthorizationSnapshot::new(
        "wire-check",
        "snapshot-wire",
        "subject-wire",
        "device-wire",
        LicenseState::Active,
        42,
        None,
        vec!["launch".to_string()],
        Vec::new(),
    );
    let frame = LocalTransportFrame::from_snapshot(snapshot);
    let bytes = frame.encode_for(&manifest).unwrap();
    let expected_payload = r#"{"body":{"capabilities":["launch"],"device_id":"device-wire","expires_at":null,"issued_at":42,"license_state":"active","modules":[],"product_id":"wire-check","protocol":"a-core.v1","snapshot_id":"snapshot-wire","subject_id":"subject-wire"},"kind":"authorization_snapshot","product_id":"wire-check","protocol":"a-core.v1"}"#;

    assert_eq!(&bytes[..4], b"ACV1");
    assert_eq!(
        u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize,
        expected_payload.len()
    );
    assert_eq!(
        std::str::from_utf8(&bytes[LOCAL_FRAME_HEADER_BYTES..]).unwrap(),
        expected_payload
    );
}

#[test]
fn transport_rejects_cross_product_and_message_field_mismatch() {
    let skin = manifest(
        "skin-studio",
        "state/skin-studio",
        "a-skin",
        vec![
            Capability::required("launch", "1"),
            Capability::optional("updates", "1"),
        ],
    );
    let media = manifest(
        "media-tool",
        "state/media-tool",
        "a-media",
        vec![
            Capability::required("launch", "1"),
            Capability::optional("updates", "1"),
        ],
    );
    let frame = LocalTransportFrame::from_snapshot(snapshot("skin-studio", Vec::new()));
    let bytes = frame.encode_for(&skin).unwrap();

    assert!(matches!(
        LocalTransportFrame::decode_for(&bytes, &media),
        Err(TransportError::Contract(
            ContractError::ProductMismatch { .. }
        ))
    ));

    let mut mismatched = frame.clone();
    mismatched.product_id = "media-tool".to_string();
    assert!(matches!(
        mismatched.encode_for(&skin),
        Err(TransportError::Contract(
            ContractError::ProductMismatch { .. }
        ))
    ));
}

#[test]
fn transport_rejects_invalid_header_truncation_and_length() {
    let manifest = manifest(
        "skin-studio",
        "state/skin-studio",
        "a-skin",
        vec![
            Capability::required("launch", "1"),
            Capability::optional("updates", "1"),
        ],
    );
    let frame = LocalTransportFrame::from_snapshot(snapshot("skin-studio", Vec::new()));
    let bytes = frame.encode_for(&manifest).unwrap();

    assert!(matches!(
        LocalTransportFrame::decode_for(&bytes[..LOCAL_FRAME_HEADER_BYTES - 1], &manifest),
        Err(TransportError::Truncated)
    ));

    let mut invalid_header = bytes.clone();
    invalid_header[0] = b'X';
    assert!(matches!(
        LocalTransportFrame::decode_for(&invalid_header, &manifest),
        Err(TransportError::InvalidHeader)
    ));

    let mut invalid_utf8 = bytes.clone();
    invalid_utf8[LOCAL_FRAME_HEADER_BYTES] = 0xFF;
    assert!(matches!(
        LocalTransportFrame::decode_for(&invalid_utf8, &manifest),
        Err(TransportError::InvalidUtf8)
    ));

    let mut invalid_length = bytes;
    invalid_length[4] = invalid_length[4].wrapping_add(1);
    assert!(matches!(
        LocalTransportFrame::decode_for(&invalid_length, &manifest),
        Err(TransportError::LengthMismatch { .. })
    ));
}

#[test]
fn transport_rejects_oversized_payloads_before_ipc() {
    let manifest = manifest(
        "skin-studio",
        "state/skin-studio",
        "a-skin",
        vec![
            Capability::required("launch", "1"),
            Capability::optional("updates", "1"),
        ],
    );
    let mut payload = BTreeMap::new();
    for index in 0..MAX_MODULE_PAYLOAD_ENTRIES {
        payload.insert(format!("key-{index}"), "x".repeat(256));
    }
    let modules = (0..MAX_SNAPSHOT_MODULES)
        .map(|index| {
            ModuleEnvelope::new(
                "skin-studio",
                format!("module-{index}"),
                "1.0.0",
                "launch",
                payload.clone(),
            )
        })
        .collect();
    let frame = LocalTransportFrame::from_snapshot(snapshot("skin-studio", modules));

    assert!(frame.payload_len() > MAX_TRANSPORT_PAYLOAD_BYTES);
    assert!(matches!(
        frame.encode_for(&manifest),
        Err(TransportError::FrameTooLarge { .. })
    ));
}

#[test]
fn transport_does_not_accept_sensitive_module_parameters() {
    let manifest = manifest(
        "skin-studio",
        "state/skin-studio",
        "a-skin",
        vec![Capability::required("launch", "1")],
    );
    let mut payload = BTreeMap::new();
    payload.insert(
        "raw_card_key".to_string(),
        "CARD-DO-NOT-FORWARD".to_string(),
    );
    let frame = LocalTransportFrame::from_module(ModuleEnvelope::new(
        "skin-studio",
        "legacy-handshake",
        "1.0.0",
        "launch",
        payload,
    ));

    assert!(matches!(
        frame.encode_for(&manifest),
        Err(TransportError::Contract(ContractError::InvalidModule(_)))
    ));
}
