//! Integration test for tx_privacy circuit with NativeProver
//!
//! Tests that the native prover can generate and verify proofs
//! for the tx_privacy circuit.

use halo2curves::pasta::Fp;
use tempfile::TempDir;
use tx_privacy::TxPrivacyCircuit;
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

#[test]
fn test_tx_privacy_with_native_prover() {
    let temp_dir = TempDir::new().unwrap();

    // Circuit parameters
    let balance_old = 1000u64;
    let balance_new = 800u64;
    let randomness_old = Fp::from(42);
    let randomness_new = Fp::from(43);
    let amount = 200u64;
    let merkle_path = vec![Fp::from(0); tx_privacy::MERKLE_DEPTH];

    // Create circuit
    let circuit = TxPrivacyCircuit::new(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        merkle_path.clone(),
    );

    // Compute public inputs
    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &merkle_path);

    let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];

    // Setup prover
    let mut prover = NativeProver::with_cache_dir(circuit, 10, temp_dir.path()).unwrap();

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k: 10,
        num_public_inputs: 3,
        num_private_witnesses: 38,
    };

    println!("🔑 Setting up prover...");
    prover.setup(metadata).unwrap();

    // Generate proof
    println!("📊 Generating proof...");
    let proof = prover.generate_proof(&public_inputs).unwrap();
    println!("✅ Proof generated: {} bytes", proof.len());

    // Verify proof
    println!("🔍 Verifying proof...");
    let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
    assert!(is_valid, "Proof should be valid");
    println!("✅ Proof verified successfully!");

    // Test with wrong public inputs (should fail)
    println!("🔍 Testing with wrong public inputs...");
    let wrong_inputs = vec![vec![Fp::from(999), commitment_new, merkle_root]];
    let is_valid_wrong = prover.verify_proof(&proof, &wrong_inputs).unwrap();
    assert!(!is_valid_wrong, "Proof should be invalid with wrong inputs");
    println!("✅ Invalid proof correctly rejected!");
}

#[test]
fn test_tx_privacy_different_amounts() {
    let temp_dir = TempDir::new().unwrap();

    let test_cases = vec![
        (1000u64, 900u64, 100u64), // Small transfer
        (1000u64, 500u64, 500u64), // Medium transfer
        (1000u64, 1u64, 999u64),   // Large transfer
    ];

    for (balance_old, balance_new, amount) in test_cases {
        println!("\n📊 Testing: {} -> {} (amount: {})", balance_old, balance_new, amount);

        let randomness_old = Fp::from(42);
        let randomness_new = Fp::from(43);
        let merkle_path = vec![Fp::from(0); tx_privacy::MERKLE_DEPTH];

        let circuit = TxPrivacyCircuit::new(
            balance_old,
            balance_new,
            randomness_old,
            randomness_new,
            amount,
            merkle_path.clone(),
        );

        let commitment_old =
            TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
        let commitment_new =
            TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
        let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &merkle_path);

        let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];

        let mut prover = NativeProver::with_cache_dir(circuit, 10, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: format!("tx_privacy_{}", amount),
            k: 10,
            num_public_inputs: 3,
            num_private_witnesses: 38,
        };

        prover.setup(metadata).unwrap();
        let proof = prover.generate_proof(&public_inputs).unwrap();
        let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();

        assert!(is_valid, "Proof should be valid for amount {}", amount);
        println!("✅ Proof valid for amount: {}", amount);
    }
}
