//! Behavioral tests for the generated `contract_transformed` module, driven
//! through a mock host: guard ordering, replay protection, and the emitted
//! privacy-transaction record.

use std::collections::HashSet;

use alloy_primitives::{keccak256, Bytes, B256};
use zk_private_demo::contract_transformed::{
    deposit, derive_nullifier, public_inputs, DepositHost, PrivacyTransactionRecord, CIRCUIT_ID,
    ZEROSTYL_PRIVACY_TX_SIGNATURE, ZEROSTYL_PRIVACY_TX_TOPIC0,
};

const FIXED_TIMESTAMP: u64 = 1_700_000_000;

#[derive(Default)]
struct MockHost {
    nullifiers: HashSet<B256>,
    events: Vec<PrivacyTransactionRecord>,
    /// When set, the verification hook rejects everything.
    reject_proofs: bool,
}

impl DepositHost for MockHost {
    fn is_nullifier_used(&self, nullifier: B256) -> bool {
        self.nullifiers.contains(&nullifier)
    }

    fn mark_nullifier_used(&mut self, nullifier: B256) {
        self.nullifiers.insert(nullifier);
    }

    fn block_timestamp(&self) -> u64 {
        FIXED_TIMESTAMP
    }

    fn emit_privacy_transaction(&mut self, record: &PrivacyTransactionRecord) {
        self.events.push(*record);
    }

    fn verify_proof(&self, proof: &[u8], _public_inputs: &[[u8; 32]]) -> bool {
        !self.reject_proofs && !proof.is_empty()
    }
}

fn commitment() -> B256 {
    B256::repeat_byte(0x11)
}

fn proof() -> Bytes {
    Bytes::from(vec![0xab; 64])
}

#[test]
fn accepts_valid_submission_and_records_event() {
    let mut host = MockHost::default();
    assert!(deposit(&mut host, commitment(), 100, proof()));

    let expected_proof_hash = keccak256(proof());
    let expected_nullifier = derive_nullifier(commitment());
    assert!(host.nullifiers.contains(&expected_nullifier));

    assert_eq!(host.events.len(), 1);
    let record = &host.events[0];
    assert_eq!(record.circuit, B256::new(CIRCUIT_ID));
    assert_eq!(record.nullifier, expected_nullifier);
    assert_eq!(record.commitment, commitment());
    assert_eq!(record.merkle_root, B256::ZERO);
    assert_eq!(record.proof_hash, expected_proof_hash);
    assert_eq!(record.timestamp, FIXED_TIMESTAMP);
}

#[test]
fn rejects_empty_proof_without_state_change() {
    let mut host = MockHost::default();
    assert!(!deposit(&mut host, commitment(), 100, Bytes::new()));
    assert!(host.nullifiers.is_empty());
    assert!(host.events.is_empty());
}

#[test]
fn rejects_zero_commitment() {
    let mut host = MockHost::default();
    assert!(!deposit(&mut host, B256::ZERO, 100, proof()));
    assert!(host.nullifiers.is_empty());
    assert!(host.events.is_empty());
}

#[test]
fn rejects_when_verification_hook_fails() {
    let mut host = MockHost { reject_proofs: true, ..MockHost::default() };
    assert!(!deposit(&mut host, commitment(), 100, proof()));
    assert!(host.nullifiers.is_empty());
    assert!(host.events.is_empty());
}

#[test]
fn rejects_replayed_submission() {
    let mut host = MockHost::default();
    assert!(deposit(&mut host, commitment(), 100, proof()));
    assert!(!deposit(&mut host, commitment(), 100, proof()));
    assert_eq!(host.events.len(), 1);
}

#[test]
fn same_commitment_rejected_even_with_different_proof() {
    // The nullifier is keyed on the commitment ALONE, so a second submission of the same
    // commitment is rejected even if the proof bytes differ (re-proving mints a fresh,
    // transcript-randomized proof but the same idempotence key). This is the per-commitment
    // guarantee — without it, an attacker could inflate deposits by re-proving.
    let mut host = MockHost::default();
    assert!(deposit(&mut host, commitment(), 100, proof()));
    assert!(!deposit(&mut host, commitment(), 100, Bytes::from(vec![0xcd; 64])));
    assert_eq!(host.events.len(), 1);
}

#[test]
fn public_inputs_layout_matches_commitment() {
    assert_eq!(public_inputs(commitment()), [commitment().0]);
}

#[test]
fn event_constants_match_runtime() {
    assert_eq!(
        ZEROSTYL_PRIVACY_TX_SIGNATURE,
        zerostyl_runtime::ZeroStylPrivacyTransaction::SIGNATURE
    );
    assert_eq!(ZEROSTYL_PRIVACY_TX_TOPIC0, zerostyl_runtime::ZeroStylPrivacyTransaction::topic0());
    assert_eq!(CIRCUIT_ID, *zerostyl_runtime::BytecodeFingerprint::of(b"deposit").as_bytes());
}
