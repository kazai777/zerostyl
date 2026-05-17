use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Output of a successful proof generation.
///
/// `public_inputs_json` is the canonical JSON encoding written next to
/// `bytes` on disk (one per circuit), so verification can be reproduced
/// without re-deriving inputs from the witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub bytes: Vec<u8>,
    pub public_inputs_json: String,
}

impl ProofArtifact {
    pub fn new(bytes: Vec<u8>, public_inputs_json: String) -> Self {
        Self { bytes, public_inputs_json }
    }
}

/// Lets verifiers reject foreign or corrupted inputs before allocating.
pub const PROOF_MAGIC: [u8; 4] = *b"ZSPF";

/// Bumped when the wire layout changes; the decoder rejects any other value.
pub const PROOF_VERSION: u32 = 1;

/// magic (4) + circuit_id (32) + version (4).
pub const PROOF_HEADER_LEN: usize = 40;

/// Wire layout (big-endian for multi-byte integers):
///
/// ```text
///   offset  size   field
///   ──────  ────   ─────────────────────────────────────────────
///        0     4   PROOF_MAGIC (b"ZSPF")
///        4    32   circuit_id (opaque, caller-derived)
///       36     4   version (u32 BE)
///       40     N   payload (raw proof bytes)
/// ```
///
/// `circuit_id` stays opaque here so callers can pick any deterministic
/// derivation (e.g. `keccak256(circuit_name)`) and stay consistent across
/// prove and verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProof {
    pub circuit_id: [u8; 32],
    pub version: u32,
    pub payload: Vec<u8>,
}

impl CanonicalProof {
    pub fn new(circuit_id: [u8; 32], payload: Vec<u8>) -> Self {
        Self { circuit_id, version: PROOF_VERSION, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&PROOF_MAGIC);
        out.extend_from_slice(&self.circuit_id);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProofFormatError> {
        if bytes.len() < PROOF_HEADER_LEN {
            return Err(ProofFormatError::TooShort { len: bytes.len() });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().expect("4-byte slice");
        if magic != PROOF_MAGIC {
            return Err(ProofFormatError::BadMagic { found: magic });
        }
        let circuit_id: [u8; 32] = bytes[4..36].try_into().expect("32-byte slice");
        let version = u32::from_be_bytes(bytes[36..40].try_into().expect("4-byte slice"));
        if version != PROOF_VERSION {
            return Err(ProofFormatError::UnsupportedVersion { version });
        }
        let payload = bytes[PROOF_HEADER_LEN..].to_vec();
        Ok(Self { circuit_id, version, payload })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofFormatError {
    #[error("proof too short ({len} bytes, need at least {PROOF_HEADER_LEN})")]
    TooShort { len: usize },

    #[error("bad magic {found:02x?}, expected {PROOF_MAGIC:02x?}")]
    BadMagic { found: [u8; 4] },

    #[error("unsupported proof format version {version} (this build supports {PROOF_VERSION})")]
    UnsupportedVersion { version: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_circuit_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = i as u8;
        }
        id
    }

    #[test]
    fn header_len_matches_field_sizes() {
        assert_eq!(PROOF_HEADER_LEN, PROOF_MAGIC.len() + 32 + 4);
    }

    #[test]
    fn magic_is_zspf() {
        assert_eq!(&PROOF_MAGIC, b"ZSPF");
    }

    #[test]
    fn current_version_is_one() {
        assert_eq!(PROOF_VERSION, 1);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let proof = CanonicalProof::new(sample_circuit_id(), vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let bytes = proof.encode();
        let decoded = CanonicalProof::decode(&bytes).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn encode_layout_is_stable() {
        let proof = CanonicalProof::new(sample_circuit_id(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = proof.encode();
        assert_eq!(&bytes[0..4], b"ZSPF");
        assert_eq!(&bytes[4..36], &sample_circuit_id());
        assert_eq!(&bytes[36..40], &1u32.to_be_bytes());
        assert_eq!(&bytes[40..], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(bytes.len(), PROOF_HEADER_LEN + 4);
    }

    #[test]
    fn encode_empty_payload_keeps_only_header() {
        let proof = CanonicalProof::new([0u8; 32], Vec::new());
        let bytes = proof.encode();
        assert_eq!(bytes.len(), PROOF_HEADER_LEN);
        assert_eq!(CanonicalProof::decode(&bytes).unwrap().payload, Vec::<u8>::new());
    }

    #[test]
    fn decode_rejects_short_input() {
        let short = vec![0u8; PROOF_HEADER_LEN - 1];
        let err = CanonicalProof::decode(&short).unwrap_err();
        assert_eq!(err, ProofFormatError::TooShort { len: PROOF_HEADER_LEN - 1 });
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = CanonicalProof::new([0u8; 32], vec![1, 2, 3]).encode();
        bytes[0] = b'X';
        let err = CanonicalProof::decode(&bytes).unwrap_err();
        match err {
            ProofFormatError::BadMagic { found } => assert_eq!(found, [b'X', b'S', b'P', b'F']),
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut bytes = CanonicalProof::new([0u8; 32], vec![1, 2, 3]).encode();
        bytes[36..40].copy_from_slice(&999u32.to_be_bytes());
        let err = CanonicalProof::decode(&bytes).unwrap_err();
        assert_eq!(err, ProofFormatError::UnsupportedVersion { version: 999 });
    }

    #[test]
    fn snapshot_known_bytes() {
        let proof = CanonicalProof::new([0x42u8; 32], vec![0x01, 0x02, 0x03]);
        let bytes = proof.encode();
        let expected: Vec<u8> = b"ZSPF"
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0x42u8, 32))
            .chain([0x00, 0x00, 0x00, 0x01])
            .chain([0x01, 0x02, 0x03])
            .collect();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn version_field_is_big_endian() {
        let proof = CanonicalProof::new([0u8; 32], Vec::new());
        let bytes = proof.encode();
        assert_eq!(bytes[36], 0x00);
        assert_eq!(bytes[37], 0x00);
        assert_eq!(bytes[38], 0x00);
        assert_eq!(bytes[39], 0x01);
    }
}
