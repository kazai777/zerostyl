//! Age Verification Range Proof Demo
//!
//! This demo shows how ZeroStyl enables proving a value is within a range
//! (e.g., age > 18) without revealing the actual value.
//!
//! Uses NativeProver from zerostyl-compiler for REAL cryptographic proof generation.

use halo2curves::ff::PrimeField;
use halo2curves::pasta::Fp;
use state_mask::StateMaskCircuit;
use std::time::Instant;
use tempfile::TempDir;
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

fn main() {
    println!("\n=== ZeroStyl Range Proof ===\n");

    println!("Using NativeProver for REAL cryptographic proof generation\n");

    // User's secret age
    let age = 25u64;
    let randomness = Fp::from(123);
    let range_min = 18u64;
    let range_max = 100u64;

    println!("SECRET input:");
    println!("  - Actual age: {} years old", age);
    println!();
    println!("RANGE to prove:");
    println!("  - Minimum: {}", range_min);
    println!("  - Maximum: {}", range_max);
    println!();

    let commitment = StateMaskCircuit::compute_commitment(Fp::from(age), randomness);

    println!("PUBLIC output:");
    println!(
        "  - Commitment: 0x{}... (hides the value {})",
        hex::encode(&commitment.to_repr().as_ref()[0..8]),
        age
    );
    println!();

    let circuit = StateMaskCircuit::new(age, randomness, range_min, range_max);

    let k = 10;
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    println!("ZEROSTYL-COMPILER INTEGRATION:");
    println!("  - Initializing NativeProver from zerostyl_compiler::codegen::prover");
    println!("  - Setting up proving/verification keys (k={})...", k);
    println!("  - Keys cached in {:?}", temp_dir.path());

    let setup_start = Instant::now();

    let mut prover = NativeProver::with_cache_dir(circuit, k, temp_dir.path())
        .expect("Failed to create NativeProver");

    let metadata = KeyMetadata {
        circuit_name: "state_mask".to_string(),
        k,
        num_public_inputs: 1,
        num_private_witnesses: 4, // age, randomness, range_min, range_max
    };

    prover.setup(metadata).expect("Failed to setup prover");
    let setup_elapsed = setup_start.elapsed();
    println!("  - Setup time: {:.2?}", setup_elapsed);
    println!();

    println!("PROOF GENERATION:");
    let proof_start = Instant::now();
    let public_inputs = vec![vec![commitment]];
    let proof = prover.generate_proof(&public_inputs).expect("Failed to generate proof");
    let proof_elapsed = proof_start.elapsed();

    println!("  - Proof size: {} bytes", proof.len());
    if proof.len() >= 16 {
        println!("  - First 16 bytes: 0x{}", hex::encode(&proof[0..16]));
        println!("  - Last 16 bytes:  0x{}", hex::encode(&proof[proof.len() - 16..]));
    }
    println!("  - Generation time: {:.2?}", proof_elapsed);
    println!();

    println!("PROOF VERIFICATION:");
    let verify_start = Instant::now();
    let is_valid = prover.verify_proof(&proof, &public_inputs).expect("Verification call failed");
    let verify_elapsed = verify_start.elapsed();

    println!("  - Status: {}", if is_valid { "VALID" } else { "INVALID" });
    println!("  - Verification time: {:.2?}", verify_elapsed);
    println!();

    if is_valid {
        println!("VERIFIED: Value is within range [{}, {}]", range_min, range_max);
        println!();
        println!("The blockchain knows:");
        println!("  + User is at least {} years old", range_min);
        println!("  + User is at most {} years old", range_max);
        println!();
        println!("The blockchain does NOT know:");
        println!("  - The actual age ({})", age);
        println!();
        println!("Use cases:");
        println!("  - Age verification without revealing exact age");
        println!("  - Credit score ranges without revealing score");
        println!("  - Balance thresholds without revealing amount");
        println!();
        println!("This proof ({} bytes) can be submitted on-chain for verification.", proof.len());
    } else {
        println!("ERROR: Proof verification failed!");
        std::process::exit(1);
    }
    println!();
}
