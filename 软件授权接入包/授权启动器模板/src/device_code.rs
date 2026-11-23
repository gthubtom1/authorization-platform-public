//! Support-facing device code formatting.
//!
//! This is display-only. Requests, proofs, tickets and response correlation
//! continue to use the original stable `installation_id` unchanged.

use sha2::{Digest, Sha256};

const PREFIX: &str = "GS-";
const HEX_PAYLOAD_LENGTH: usize = 20;

/// Derive the same compact support code as the platform.
///
/// Existing formatted codes are canonicalized, other short opaque fixture IDs
/// are preserved, and the current 64-character hexadecimal hardware value is
/// mapped through SHA-256 before taking 80 display bits.
pub fn compact_device_code(installation_id: &str) -> String {
    let value = installation_id.trim();
    if is_compact_device_code(value) {
        return value.to_ascii_uppercase();
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let digest = Sha256::digest(value.as_bytes());
        let mut payload = String::with_capacity(HEX_PAYLOAD_LENGTH);
        for byte in digest.iter().take(HEX_PAYLOAD_LENGTH / 2) {
            use std::fmt::Write;
            write!(&mut payload, "{byte:02X}").expect("writing to a String cannot fail");
        }
        return format!(
            "{PREFIX}{}-{}-{}-{}-{}",
            &payload[0..4],
            &payload[4..8],
            &payload[8..12],
            &payload[12..16],
            &payload[16..20]
        );
    }
    value.to_string()
}

/// Check the canonical human-facing format, accepting lower-case input for
/// migration and normalizing it in `compact_device_code`.
pub fn is_compact_device_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    let group_count = match bytes.len() {
        22 => 4,
        27 => 5,
        _ => return false,
    };
    if !value
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
    {
        return false;
    }
    for group in 0..group_count {
        let start = PREFIX.len() + group * 5;
        if bytes[start..start + 4].iter().any(|byte| !byte.is_ascii_hexdigit()) {
            return false;
        }
        if group + 1 < group_count && bytes[start + 4] != b'-' {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{compact_device_code, is_compact_device_code};

    #[test]
    fn maps_a_hardware_hash_to_a_stable_grouped_code() {
        let raw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let first = compact_device_code(raw);
        assert_eq!(first, compact_device_code(raw));
        assert_eq!(first.len(), 27);
        assert!(first.starts_with("GS-"));
        assert!(is_compact_device_code(&first));
        assert!(!first.contains(raw));
    }

    #[test]
    fn preserves_existing_short_and_opaque_compatibility_values() {
        assert_eq!(compact_device_code("GS-65fb-f502-b439-270c-1234"), "GS-65FB-F502-B439-270C-1234");
        assert_eq!(compact_device_code("gs-65fb-f502-b439-270c-1234"), "GS-65FB-F502-B439-270C-1234");
        assert_eq!(compact_device_code("install-a"), "install-a");
        assert!(is_compact_device_code("GS-65FB-F502-B439-270C"));
    }
}
