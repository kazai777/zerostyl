//! Integration tests for tx_privacy circuit with NativeProver.
//!
//! Tests full proof generation and verification using real Poseidon
//! commitments and Merkle tree membership proofs.

use halo2_proofs::circuit::Value;
use halo2curves::pasta::Fp;
use tempfile::TempDir;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

const INTEGRATION_K: u32 = 14;

fn make_integration_data(
    balance_old: u64,
    balance_new: u64,
    amount: u64,
) -> (TxPrivacyCircuit, Vec<Vec<Fp>>) {
    let randomness_old = Fp::from(42u64);
    let randomness_new = Fp::from(43u64);
    let siblings: Vec<Fp> =
        (0..tx_privacy::MERKLE_DEPTH).map(|i| Fp::from((i + 100) as u64)).collect();
    let indices: Vec<bool> = (0..tx_privacy::MERKLE_DEPTH).map(|i| i % 2 == 0).collect();

    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

    let circuit = TxPrivacyCircuit::new(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        siblings,
        indices,
    );

    let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];
    (circuit, public_inputs)
}

#[test]
fn test_tx_privacy_with_native_prover() {
    let temp_dir = TempDir::new().unwrap();
    let (circuit, public_inputs) = make_integration_data(1000, 800, 200);

    let mut prover = NativeProver::with_cache_dir(circuit, INTEGRATION_K, temp_dir.path()).unwrap();

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k: INTEGRATION_K,
        num_public_inputs: 3,
        num_private_witnesses: 69,
    };

    prover.setup(metadata).unwrap();

    let proof = prover.generate_proof(&public_inputs).unwrap();
    assert!(!proof.is_empty());

    let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
    assert!(is_valid, "Proof should be valid");

    // Wrong public inputs should be rejected
    let wrong_inputs = vec![vec![Fp::from(999u64), public_inputs[0][1], public_inputs[0][2]]];
    let is_valid_wrong = prover.verify_proof(&proof, &wrong_inputs).unwrap();
    assert!(!is_valid_wrong, "Proof should be invalid with wrong inputs");
}

#[test]
fn test_tx_privacy_different_amounts() {
    let temp_dir = TempDir::new().unwrap();

    let test_cases =
        vec![(1000u64, 900u64, 100u64), (1000u64, 500u64, 500u64), (1000u64, 1u64, 999u64)];

    for (balance_old, balance_new, amount) in test_cases {
        let (circuit, public_inputs) = make_integration_data(balance_old, balance_new, amount);

        let mut prover =
            NativeProver::with_cache_dir(circuit, INTEGRATION_K, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: format!("tx_privacy_{}", amount),
            k: INTEGRATION_K,
            num_public_inputs: 3,
            num_private_witnesses: 69,
        };

        prover.setup(metadata).unwrap();
        let proof = prover.generate_proof(&public_inputs).unwrap();
        let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
        assert!(is_valid, "Proof should be valid for amount {}", amount);
    }
}

#[test]
fn test_tx_privacy_invalid_amount_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let balance_old = 1000u64;
    let balance_new = 800u64;
    let wrong_amount = 100u64; // Should be 200
    let randomness_old = Fp::from(42u64);
    let randomness_new = Fp::from(43u64);
    let siblings: Vec<Fp> = (0..MERKLE_DEPTH).map(|i| Fp::from((i + 100) as u64)).collect();
    let indices: Vec<bool> = (0..MERKLE_DEPTH).map(|i| i % 2 == 0).collect();

    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

    // Bypass constructor to inject invalid amount (balance_old - balance_new != amount)
    let circuit = TxPrivacyCircuit {
        balance_old: Value::known(Fp::from(balance_old)),
        balance_new: Value::known(Fp::from(balance_new)),
        randomness_old: Value::known(randomness_old),
        randomness_new: Value::known(randomness_new),
        amount: Value::known(Fp::from(wrong_amount)),
        merkle_siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
        merkle_indices: indices
            .iter()
            .map(|&b| Value::known(if b { Fp::from(1u64) } else { Fp::from(0u64) }))
            .collect(),
    };

    let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];

    let mut prover = NativeProver::with_cache_dir(circuit, INTEGRATION_K, temp_dir.path()).unwrap();
    let metadata = KeyMetadata {
        circuit_name: "tx_privacy_negative".to_string(),
        k: INTEGRATION_K,
        num_public_inputs: 3,
        num_private_witnesses: 69,
    };
    prover.setup(metadata).unwrap();

    // Proof generation may succeed (prover doesn't check constraints) or fail.
    // If it succeeds, verification must reject the invalid proof.
    match prover.generate_proof(&public_inputs) {
        Ok(proof) => {
            let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
            assert!(!is_valid, "Proof with invalid amount must be rejected by verifier");
        }
        Err(_) => {
            // Prover rejected invalid witnesses during synthesis — also acceptable
        }
    }
}
