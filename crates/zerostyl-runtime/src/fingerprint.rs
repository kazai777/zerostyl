//! Bytecode / circuit fingerprinting.
//!
//! A [`BytecodeFingerprint`] is the Keccak-256 digest of a byte string — typically a deployed
//! contract's WASM bytecode or a circuit's verifying key. It gives ZeroStyl tooling (dashboards,
//! event indexers) a stable, on-chain-comparable identifier for "which circuit/contract produced
//! this proof", without revealing anything about the private witnesses.
//!
//! Keccak-256 is used (rather than a faster hash) so a fingerprint computed off-chain matches one
//! a Stylus contract can recompute on-chain via the same digest, and so it lines up with EVM event
//! topics.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Keccak-256 fingerprint of a byte string (contract bytecode, verifying key, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BytecodeFingerprint(pub [u8; 32]);

impl BytecodeFingerprint {
    /// Compute the fingerprint of `bytes` (`keccak256(bytes)`).
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// The raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case `0x`-prefixed hex encoding, e.g. for logs and dashboards.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(2 + 64);
        s.push_str("0x");
        s.push_str(&hex::encode(self.0));
        s
    }
}

impl From<[u8; 32]> for BytecodeFingerprint {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(BytecodeFingerprint::of(b"circuit-v1"), BytecodeFingerprint::of(b"circuit-v1"));
    }

    #[test]
    fn distinguishes_inputs() {
        assert_ne!(BytecodeFingerprint::of(b"circuit-v1"), BytecodeFingerprint::of(b"circuit-v2"));
    }

    #[test]
    fn matches_known_keccak256_empty() {
        // keccak256("") is a well-known constant.
        let fp = BytecodeFingerprint::of(b"");
        assert_eq!(
            fp.to_hex(),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn hex_round_trips_len() {
        let fp = BytecodeFingerprint::of(b"abc");
        let h = fp.to_hex();
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 66);
    }

    #[test]
    fn from_array_and_as_bytes() {
        let raw = [7u8; 32];
        let fp = BytecodeFingerprint::from(raw);
        assert_eq!(fp.as_bytes(), &raw);
    }
}
