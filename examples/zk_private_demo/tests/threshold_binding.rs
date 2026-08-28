//! Adversarial tests for the public-parameter binding.
//!
//! `deposit` proves `collateral >= threshold`, and `threshold` is instance cell 1 of the circuit,
//! so the statement is pinned to the value the caller passes. These tests generate a *real*
//! halo2-KZG proof and check that swapping the threshold the verifier is told about makes
//! verification fail.

use std::collections::HashSet;

use alloy_primitives::{Bytes, B256};
use tempfile::TempDir;
use zk_private_demo::contract_transformed::{
    deposit, public_inputs, DepositHost, PrivacyTransactionRecord,
};
use zk_private_demo::descriptor;

const K: u32 = 10;

/// Witness for `collateral = 1000`, `threshold = <threshold>`.
fn witness(threshold: u64) -> String {
    format!(r#"{{ "collateral": "1000", "threshold": "{threshold}", "collateral_nonce": "42" }}"#)
}

/// 32-byte little-endian `Fr::to_repr()` of a `u64`, as the `0x`-hex the descriptor parses.
fn fr_hex(value: u64) -> String {
    let mut repr = [0u8; 32];
    repr[..8].copy_from_slice(&value.to_le_bytes());
    format!("0x{}", hex::encode(repr))
}

/// Rewrite the public-inputs document so the verifier is told `threshold` was `claimed`.
fn with_threshold(public_inputs_json: &str, claimed: u64) -> String {
    let mut doc: serde_json::Value =
        serde_json::from_str(public_inputs_json).expect("public inputs JSON");
    let row = doc["inputs"][0].as_array_mut().expect("one instance column");
    assert_eq!(row.len(), 2, "expected [collateral_commitment, threshold]");
    row[1] = serde_json::Value::String(fr_hex(claimed));
    doc.to_string()
}

#[test]
fn proof_for_one_threshold_does_not_verify_against_another() {
    let cache = TempDir::new().expect("tempdir");
    let d = descriptor();

    // Prove `collateral (1000) >= threshold (10)`.
    let artifact = d.prove(&witness(10), K, cache.path()).expect("prove succeeds");

    // Honest path: the proof verifies against the public inputs it was made for.
    assert!(
        d.verify(&artifact.bytes, &artifact.public_inputs_json, K, cache.path())
            .expect("verify runs"),
        "the proof must verify against its own public inputs"
    );

    // The threshold appears in the public inputs at all — otherwise there is nothing to tamper
    // with and this test would pass vacuously.
    assert!(
        artifact.public_inputs_json.contains(&fr_hex(10)),
        "threshold must be part of the public inputs: {}",
        artifact.public_inputs_json
    );

    // Adversarial path: same proof, but the call claims `threshold = 100`. A failed verification
    // surfaces as Ok(false) or Err depending on where it trips; both mean "not verified".
    let tampered = with_threshold(&artifact.public_inputs_json, 100);
    let result = d.verify(&artifact.bytes, &tampered, K, cache.path());
    assert!(
        !matches!(result, Ok(true)),
        "a proof generated for threshold = 10 must NOT verify for a call claiming threshold = 100"
    );
}

#[test]
fn commitment_alone_no_longer_determines_the_statement() {
    // Two proofs over the same collateral and the same commitment, differing only in the threshold
    // they were made for, produce different public inputs — so they are not interchangeable.
    let cache = TempDir::new().expect("tempdir");
    let d = descriptor();

    let low = d.prove(&witness(10), K, cache.path()).expect("prove low");
    let high = d.prove(&witness(500), K, cache.path()).expect("prove high");

    assert_ne!(
        low.public_inputs_json, high.public_inputs_json,
        "the threshold must be visible to the verifier"
    );
    assert!(!matches!(d.verify(&low.bytes, &high.public_inputs_json, K, cache.path()), Ok(true)));
}

/// Host that verifies through the real descriptor, so the contract-level guard is exercised
/// end-to-end rather than through a stub that ignores its public inputs.
struct VerifyingHost {
    cache: TempDir,
    proof_public_inputs: String,
    nullifiers: HashSet<B256>,
    events: Vec<PrivacyTransactionRecord>,
}

impl DepositHost for VerifyingHost {
    fn is_nullifier_used(&self, nullifier: B256) -> bool {
        self.nullifiers.contains(&nullifier)
    }

    fn mark_nullifier_used(&mut self, nullifier: B256) {
        self.nullifiers.insert(nullifier);
    }

    fn block_timestamp(&self) -> u64 {
        1_700_000_000
    }

    fn emit_privacy_transaction(&mut self, record: &PrivacyTransactionRecord) {
        self.events.push(*record);
    }

    fn verify_proof(&self, proof: &[u8], call_public_inputs: &[[u8; 32]]) -> bool {
        // The contract's public inputs must be the ones the proof commits to.
        let expected: Vec<[u8; 32]> = {
            let doc: serde_json::Value =
                serde_json::from_str(&self.proof_public_inputs).expect("public inputs JSON");
            doc["inputs"][0]
                .as_array()
                .expect("one column")
                .iter()
                .map(|v| {
                    let bytes = hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
                    let mut repr = [0u8; 32];
                    repr.copy_from_slice(&bytes);
                    repr
                })
                .collect()
        };
        if call_public_inputs != expected.as_slice() {
            return false;
        }
        matches!(
            descriptor().verify(proof, &self.proof_public_inputs, K, self.cache.path()),
            Ok(true)
        )
    }
}

#[test]
fn contract_call_with_a_raised_threshold_is_rejected() {
    let cache = TempDir::new().expect("tempdir");
    let artifact = descriptor().prove(&witness(10), K, cache.path()).expect("prove succeeds");

    // The commitment the contract is called with is the one the circuit bound (public input 0).
    let commitment = {
        let doc: serde_json::Value = serde_json::from_str(&artifact.public_inputs_json).unwrap();
        let hex_str = doc["inputs"][0][0].as_str().unwrap().trim_start_matches("0x").to_string();
        B256::from_slice(&hex::decode(hex_str).unwrap())
    };

    let mut host = VerifyingHost {
        cache,
        proof_public_inputs: artifact.public_inputs_json.clone(),
        nullifiers: HashSet::new(),
        events: Vec::new(),
    };
    let proof = Bytes::from(artifact.bytes.clone());

    // Calling with the threshold the proof was made for is accepted…
    assert!(deposit(&mut host, commitment, 10, proof.clone()));

    // …while raising the threshold on the call is not: `public_inputs(commitment, 100)` is a
    // different statement than the one the proof attests to.
    let mut host = VerifyingHost {
        cache: TempDir::new().expect("tempdir"),
        proof_public_inputs: artifact.public_inputs_json,
        nullifiers: HashSet::new(),
        events: Vec::new(),
    };
    assert!(
        !deposit(&mut host, commitment, 100, proof),
        "the contract must reject a proof made for threshold = 10 on a threshold = 100 call"
    );
    assert!(host.events.is_empty(), "a rejected call must not emit anything");
    assert_ne!(public_inputs(commitment, 10), public_inputs(commitment, 100));
}
