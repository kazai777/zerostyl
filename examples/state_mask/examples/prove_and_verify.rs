//! State Mask Circuit - Range Proof Verification Demo
//!
//! Demonstrates the state_mask circuit with range proofs, showing how
//! zero-knowledge proofs can verify a value is in a range without revealing it.

use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use state_mask::StateMaskCircuit;
use std::time::Instant;

fn main() {
    println!("🎯 ZeroStyl State Mask Circuit - Range Proof Demo\n");

    let k = 10;

    let value = 42u64;
    let randomness = Fp::from(123);
    let range_min = 0u64;
    let range_max = 255u64;

    println!("📊 Circuit Parameters:");
    println!("  Secret value: {}", value);
    println!("  Range: [{}, {}]", range_min, range_max);
    println!("  Range bits: 8");
    println!("  Circuit size (k): {} ({} rows)\n", k, 1 << k);

    let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);

    let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);

    println!("🔒 Public Inputs:");
    println!("  commitment: {:?}\n", commitment);

    let public_inputs = vec![commitment];

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
    println!("    - Pedersen commitment: 1");
    println!("    - Boolean checks (8 bits): 8");
    println!("    - Bit decomposition: 8");
    println!("  Total gates: 17\n");

    println!("🎯 Range Proof Properties Verified:");
    println!("  ✓ Value is in range [{}, {}]", range_min, range_max);
    println!("  ✓ Commitment hides actual value");
    println!("  ✓ Bit decomposition is correct");
    println!("  ✓ Each bit is boolean (0 or 1)");

    println!("\n🎉 Range proof successfully verified!");
    println!(
        "   Verifier knows {} ∈ [{}, {}] WITHOUT learning the exact value!",
        value, range_min, range_max
    );

    println!("\n💡 Use Cases:");
    println!("  • Age verification (age > 18) without revealing exact age");
    println!("  • Balance checks (balance > 100) without revealing amount");
    println!("  • Credit score ranges without revealing exact score");
}
