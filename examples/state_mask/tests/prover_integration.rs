//! Integration tests for state_mask circuit with NativeProver.
//!
//! Tests full proof generation and verification using real Poseidon
//! commitments, bounded range proofs, and balance comparisons.

use halo2_proofs::circuit::Value;
use halo2curves::pasta::Fp;
use state_mask::StateMaskCircuit;
use tempfile::TempDir;
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

const INTEGRATION_K: u32 = 10;

fn make_integration_data(
    state_value: u64,
    nonce_raw: u64,
    collateral_ratio: u64,
    hidden_balance: u64,
    threshold: u64,
) -> (StateMaskCircuit, Vec<Vec<Fp>>) {
    let nonce = Fp::from(nonce_raw);
    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);
    let circuit =
        StateMaskCircuit::new(state_value, nonce, collateral_ratio, hidden_balance, threshold);
    let public_inputs = vec![vec![commitment, Fp::from(threshold)]];
    (circuit, public_inputs)
}

#[test]
fn test_state_mask_with_native_prover() {
    let temp_dir = TempDir::new().unwrap();
    let (circuit, public_inputs) = make_integration_data(1000, 42, 200, 500, 100);

    let mut prover = NativeProver::with_cache_dir(circuit, INTEGRATION_K, temp_dir.path()).unwrap();

    let metadata = KeyMetadata {
        circuit_name: "state_mask".to_string(),
        k: INTEGRATION_K,
        num_public_inputs: 2,
        num_private_witnesses: 5,
    };

    prover.setup(metadata).unwrap();

    let proof = prover.generate_proof(&public_inputs).unwrap();
    assert!(!proof.is_empty());

    let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
    assert!(is_valid, "Proof should be valid");

    // Wrong public inputs should be rejected
    let wrong_inputs = vec![vec![Fp::from(999u64), public_inputs[0][1]]];
    let is_valid_wrong = prover.verify_proof(&proof, &wrong_inputs).unwrap();
    assert!(!is_valid_wrong, "Proof should be invalid with wrong inputs");
}

#[test]
fn test_state_mask_different_parameters() {
    let temp_dir = TempDir::new().unwrap();

    let test_cases = vec![
        (500u64, 10u64, 150u64, 1000u64, 100u64),
        (2000, 99, 250, 5000, 1000),
        (1, 1, 300, 2, 1),
    ];

    for (state_value, nonce_raw, ratio, balance, threshold) in test_cases {
        let (circuit, public_inputs) =
            make_integration_data(state_value, nonce_raw, ratio, balance, threshold);

        let mut prover =
            NativeProver::with_cache_dir(circuit, INTEGRATION_K, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: format!("state_mask_{}", state_value),
            k: INTEGRATION_K,
            num_public_inputs: 2,
            num_private_witnesses: 5,
        };

        prover.setup(metadata).unwrap();
        let proof = prover.generate_proof(&public_inputs).unwrap();
        let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
        assert!(is_valid, "Proof should be valid for state_value {}", state_value);
    }
}

#[test]
fn test_state_mask_balance_below_threshold_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let state_value = 1000u64;
    let nonce = Fp::from(42u64);
    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);
    let threshold = 600u64;

    // Bypass constructor to inject invalid witnesses: hidden_balance(500) < threshold(600)
    let circuit = StateMaskCircuit {
        state_value: Value::known(Fp::from(state_value)),
        nonce: Value::known(nonce),
        collateral_ratio: Value::known(Fp::from(200u64)),
        hidden_balance: Value::known(Fp::from(500u64)),
        threshold: Value::known(Fp::from(threshold)),
    };

    let public_inputs = vec![vec![commitment, Fp::from(threshold)]];

    let mut prover = NativeProver::with_cache_dir(circuit, INTEGRATION_K, temp_dir.path()).unwrap();
    let metadata = KeyMetadata {
        circuit_name: "state_mask_negative".to_string(),
        k: INTEGRATION_K,
        num_public_inputs: 2,
        num_private_witnesses: 5,
    };
    prover.setup(metadata).unwrap();

    // Proof generation may succeed (prover doesn't check constraints) or fail.
    // If it succeeds, verification must reject the invalid proof.
    match prover.generate_proof(&public_inputs) {
        Ok(proof) => {
            let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
            assert!(!is_valid, "Proof with balance below threshold must be rejected by verifier");
        }
        Err(_) => {
            // Prover rejected invalid witnesses during synthesis — also acceptable
        }
    }
}
