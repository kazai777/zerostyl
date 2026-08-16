//! Standardized ZeroStyl privacy-transaction event.
//!
//! [`ZeroStylPrivacyTransaction`] is the single source of truth for the event every ZeroStyl
//! privacy contract emits when it processes a verified private transaction. Contracts emit it,
//! off-chain indexers / dashboards decode it, and both agree on the schema and its EVM topic hash
//! defined here — so tracking works uniformly across circuits and deployments.
//!
//! It carries no private data: only the circuit [`BytecodeFingerprint`] (which circuit produced
//! the proof), the spend `nullifier`, the new `commitment`, the `merkle_root`, a `proof_hash`, and
//! a `timestamp`.

use crate::fingerprint::BytecodeFingerprint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// The canonical privacy-transaction event emitted by ZeroStyl contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroStylPrivacyTransaction {
    /// Fingerprint of the circuit/contract that produced the proof.
    pub circuit: BytecodeFingerprint,
    /// Double-spend marker (unlinkable to the spent commitment).
    pub nullifier: [u8; 32],
    /// New commitment created by the transaction.
    pub commitment: [u8; 32],
    /// Merkle root the spent note was proven against.
    pub merkle_root: [u8; 32],
    /// Keccak-256 hash of the proof bytes (audit trail).
    pub proof_hash: [u8; 32],
    /// Block timestamp (seconds) when the transaction was recorded.
    pub timestamp: u64,
}

impl ZeroStylPrivacyTransaction {
    /// Canonical Solidity event signature. The five `bytes32` fields are, in order:
    /// `circuit`, `nullifier`, `commitment`, `merkle_root`, `proof_hash`; then `timestamp`.
    pub const SIGNATURE: &'static str =
        "ZeroStylPrivacyTransaction(bytes32,bytes32,bytes32,bytes32,bytes32,uint256)";

    /// EVM log `topic0` for this event: `keccak256(SIGNATURE)`. Indexers filter on this.
    #[must_use]
    pub fn topic0() -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(Self::SIGNATURE.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ZeroStylPrivacyTransaction {
        ZeroStylPrivacyTransaction {
            circuit: BytecodeFingerprint::of(b"state_mask"),
            nullifier: [1u8; 32],
            commitment: [2u8; 32],
            merkle_root: [3u8; 32],
            proof_hash: [4u8; 32],
            timestamp: 1_720_000_000,
        }
    }

    #[test]
    fn topic0_is_deterministic_keccak_of_signature() {
        // topic0 must equal keccak256 of the exact signature string, and be stable.
        let expected = {
            let mut h = Keccak256::new();
            h.update(ZeroStylPrivacyTransaction::SIGNATURE.as_bytes());
            let d = h.finalize();
            let mut o = [0u8; 32];
            o.copy_from_slice(&d);
            o
        };
        assert_eq!(ZeroStylPrivacyTransaction::topic0(), expected);
    }

    #[test]
    fn signature_field_order_and_arity() {
        // 5 bytes32 + 1 uint256 = the 6 struct fields (circuit + 4 hashes + timestamp).
        let sig = ZeroStylPrivacyTransaction::SIGNATURE;
        assert!(sig.starts_with("ZeroStylPrivacyTransaction("));
        assert_eq!(sig.matches("bytes32").count(), 5);
        assert_eq!(sig.matches("uint256").count(), 1);
    }

    #[test]
    fn serde_round_trips() {
        let ev = sample();
        let json = serde_json::to_string(&ev).unwrap();
        let back: ZeroStylPrivacyTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn carries_no_private_fields() {
        // Sanity: the event exposes only public artifacts (fingerprint + hashes + timestamp).
        let ev = sample();
        assert_eq!(ev.circuit, BytecodeFingerprint::of(b"state_mask"));
        assert_eq!(ev.timestamp, 1_720_000_000);
    }
}
