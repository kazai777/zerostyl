//! State Mask Privacy Demo — DeFi collateral health proof
//!
//! This demo shows how ZeroStyl enables proving:
//! 1. A committed state value is valid
//! 2. A collateral ratio is healthy (in [150%, 300%])
//! 3. A hidden balance exceeds a public threshold
//!
//! All without revealing the actual values.
//!
//! Uses NativeProver from zerostyl-compiler for REAL cryptographic proof generation.

use halo2curves::ff::PrimeField;
use halo2curves::pasta::Fp;
use state_mask::{StateMaskCircuit, COLLATERAL_MAX, COLLATERAL_MIN};
use std::time::Instant;
use tempfile::TempDir;
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

fn main() {
    println!("\n=== ZeroStyl State Mask Privacy Demo ===\n");

    println!("Using NativeProver for REAL cryptographic proof generation\n");

    let state_value = 1000u64;
    let nonce = Fp::from(42u64);
    let collateral_ratio = 200u64;
    let hidden_balance = 5000u64;
    let threshold = 1000u64;

    println!("SECRET inputs (only the prover knows):");
    println!("  - State value: {}", state_value);
    println!("  - Collateral ratio: {}%", collateral_ratio);
    println!("  - Hidden balance: {} tokens", hidden_balance);
    println!();

    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);

    println!("PUBLIC outputs (what the verifier sees):");
    println!(
        "  - Commitment: 0x{}... (hides state value {})",
        hex::encode(&commitment.to_repr().as_ref()[0..8]),
        state_value
    );
    println!("  - Threshold: {} tokens", threshold);
    println!("  - Collateral range: [{}%, {}%]", COLLATERAL_MIN, COLLATERAL_MAX);
    println!();

    let circuit =
        StateMaskCircuit::new(state_value, nonce, collateral_ratio, hidden_balance, threshold);

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
        num_public_inputs: 2,
        num_private_witnesses: 5,
    };

    prover.setup(metadata).expect("Failed to setup prover");
    let setup_elapsed = setup_start.elapsed();
    println!("  - Setup time: {:.2?}", setup_elapsed);
    println!();

    println!("PROOF GENERATION:");
    let proof_start = Instant::now();
    let public_inputs = vec![vec![commitment, Fp::from(threshold)]];
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
        println!("VERIFIED: All state proofs are valid!");
        println!();
        println!("The verifier confirmed:");
        println!("  + State value is correctly committed");
        println!("  + Collateral ratio is in [{}%, {}%]", COLLATERAL_MIN, COLLATERAL_MAX);
        println!("  + Hidden balance exceeds {} tokens", threshold);
        println!();
        println!("WITHOUT learning:");
        println!("  - The actual state value");
        println!("  - The exact collateral ratio");
        println!("  - The actual balance");
        println!();
        println!("This proof ({} bytes) can be submitted on-chain for verification.", proof.len());
    } else {
        println!("ERROR: Proof verification failed!");
        std::process::exit(1);
    }
    println!();
}
