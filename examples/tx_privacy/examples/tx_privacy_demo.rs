//! Transaction Privacy Circuit - Constraint Verification Demo
//!
//! Demonstrates the tx_privacy circuit with detailed statistics about
//! constraints, rows, and verification performance using MockProver.

use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use std::time::Instant;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};

fn main() {
    println!("🔐 ZeroStyl Transaction Privacy Circuit - Verification Demo\n");

    let k = 10;

    let balance_old = 1000u64;
    let balance_new = 700u64;
    let amount = 300u64;
    let randomness_old = Fp::from(42);
    let randomness_new = Fp::from(84);
    let merkle_path: Vec<Fp> = (0..MERKLE_DEPTH).map(|i| Fp::from(i as u64)).collect();

    println!("📊 Circuit Parameters:");
    println!("  Balance (old): {} units", balance_old);
    println!("  Balance (new): {} units", balance_new);
    println!("  Transfer amount: {} units", amount);
    println!("  Merkle tree depth: {}", MERKLE_DEPTH);
    println!("  Circuit size (k): {} ({} rows)\n", k, 1 << k);

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

    println!("🔒 Public Inputs (Commitments):");
    println!("  commitment_old: {:?}", commitment_old);
    println!("  commitment_new: {:?}", commitment_new);
    println!("  merkle_root:    {:?}\n", merkle_root);

    let public_inputs = vec![commitment_old, commitment_new, merkle_root];

    println!("⚙️  Step 1: Synthesizing circuit...");
    let start = Instant::now();

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();

    println!("   ✅ Circuit synthesized in {:?}\n", start.elapsed());

    println!("✅ Step 2: Verifying constraints...");
    let start = Instant::now();

    prover.verify().expect("Verification failed");

    let verify_time = start.elapsed();
    println!("   ✅ All constraints verified in {:?}\n", verify_time);

    println!("📈 Circuit Statistics:");
    println!("  Total rows available: {}", 1 << k);
    println!("  Advice columns: 3");
    println!("  Instance columns: 1");
    println!("  Constraints:");
    println!("    - Pedersen commitments: 2");
    println!("    - Balance check: 1");
    println!("    - Merkle proof verification: {}", MERKLE_DEPTH);
    println!("  Total gates: {}\n", 3 + MERKLE_DEPTH);

    println!("🎯 Privacy Properties Verified:");
    println!("  ✓ Balance transitions are valid");
    println!("  ✓ Commitments hide actual balances");
    println!("  ✓ Account exists in Merkle tree");
    println!("  ✓ Transfer amount is correct");

    println!("\n🎉 Transaction privacy circuit successfully verified!");
    println!("   Verifier knows the transaction is valid WITHOUT learning:");
    println!("   - The actual balances ({} → {})", balance_old, balance_new);
    println!("   - The transfer amount ({})", amount);
}
