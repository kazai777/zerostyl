//! Public-inputs wire format.
//!
//! Descriptors serialize public inputs as `{"inputs": [["0x…", …], …]}` —
//! one array per instance column, each element a 32-byte **little-endian**
//! field representation (`Fr::to_repr()`) encoded as `0x`-hex. These helpers
//! convert between that JSON and `[[u8; 32]]` without touching any curve
//! type, so they work host-side and in wasm alike.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SdkError};

#[derive(Debug, Serialize, Deserialize)]
struct PublicInputsDoc {
    inputs: Vec<Vec<String>>,
}

/// Hex-encode a 32-byte little-endian field representation (`0x`-prefixed).
pub fn fr_hex(repr: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(repr))
}

/// Parse a `0x`-prefixed hex string into a 32-byte representation.
pub fn parse_fr_hex(s: &str) -> Result<[u8; 32]> {
    let stripped = s
        .strip_prefix("0x")
        .ok_or_else(|| SdkError::Hex(format!("`{s}` is missing the 0x prefix")))?;
    let bytes =
        hex::decode(stripped).map_err(|e| SdkError::Hex(format!("`{s}` is not hex: {e}")))?;
    let arr: [u8; 32] =
        bytes.try_into().map_err(|_| SdkError::Hex(format!("`{s}` is not 32 bytes")))?;
    Ok(arr)
}

/// Encode public inputs (one `Vec` per instance column) into the JSON wire
/// format descriptors and verifiers consume.
pub fn encode_public_inputs(columns: &[Vec<[u8; 32]>]) -> String {
    let doc = PublicInputsDoc {
        inputs: columns.iter().map(|col| col.iter().map(fr_hex).collect()).collect(),
    };
    serde_json::to_string_pretty(&doc).expect("string/array JSON cannot fail to serialize")
}

/// Decode the public-inputs JSON wire format back into byte representations.
pub fn decode_public_inputs(json: &str) -> Result<Vec<Vec<[u8; 32]>>> {
    let doc: PublicInputsDoc = serde_json::from_str(json)?;
    doc.inputs.iter().map(|col| col.iter().map(|s| parse_fr_hex(s)).collect()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repr(byte: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = byte;
        r
    }

    #[test]
    fn hex_roundtrip() {
        let r = repr(0x2a);
        assert_eq!(parse_fr_hex(&fr_hex(&r)).unwrap(), r);
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        assert!(parse_fr_hex("2a").is_err());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_fr_hex("0x2a").is_err());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(parse_fr_hex(&format!("0x{}", "zz".repeat(32))).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let columns = vec![vec![repr(1), repr(2)], vec![repr(3)]];
        let json = encode_public_inputs(&columns);
        assert_eq!(decode_public_inputs(&json).unwrap(), columns);
    }

    #[test]
    fn encode_matches_descriptor_wire_shape() {
        let json = encode_public_inputs(&[vec![repr(0xab)]]);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first = value["inputs"][0][0].as_str().unwrap();
        assert!(first.starts_with("0xab"));
        assert_eq!(first.len(), 2 + 64);
    }
}
