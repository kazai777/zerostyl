//! Transaction Privacy Demo - Alice sends tokens to Bob privately
//!
//! This demo shows how ZeroStyl enables private transfers using
//! zero-knowledge proofs with Poseidon hash commitments and Merkle proofs.
//!
//! Uses NativeProver from zerostyl-compiler for REAL cryptographic proof generation.

use halo2curves::ff::PrimeField;
use halo2curves::pasta::Fp;
use std::time::Instant;
use tempfile::TempDir;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

fn main() {
    println!("\n=== ZeroStyl Transaction Privacy Demo ===\n");

    println!("Using NativeProver for REAL cryptographic proof generation\n");

    let balance_old = 1000u64;
    let balance_new = 700u64;
    let amount = 300u64;
    let randomness_old = Fp::from(42);
    let randomness_new = Fp::from(84);
    let siblings: Vec<Fp> = (0..MERKLE_DEPTH).map(|i| Fp::from((i + 100) as u64)).collect();
    let indices: Vec<bool> = (0..MERKLE_DEPTH).map(|i| i % 2 == 0).collect();

    println!("SECRET inputs (only Alice knows):");
    println!("  - Old balance: {} tokens", balance_old);
    println!("  - New balance: {} tokens", balance_new);
    println!("  - Transfer amount: {} tokens", amount);
    println!();

    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

    println!("PUBLIC outputs (what the blockchain sees):");
    println!(
        "  - Commitment old: 0x{}...  (hides {})",
        hex::encode(&commitment_old.to_repr().as_ref()[0..8]),
        balance_old
    );
    println!(
        "  - Commitment new: 0x{}...  (hides {})",
        hex::encode(&commitment_new.to_repr().as_ref()[0..8]),
        balance_new
    );
    println!("  - Merkle root:    0x{}...", hex::encode(&merkle_root.to_repr().as_ref()[0..8]));
    println!();

    let circuit = TxPrivacyCircuit::new(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        siblings,
        indices,
    );

    let k = 14;
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    println!("ZEROSTYL-COMPILER INTEGRATION:");
    println!("  - Initializing NativeProver from zerostyl_compiler::codegen::prover");
    println!("  - Setting up proving/verification keys (k={})...", k);
    println!("  - Keys cached in {:?}", temp_dir.path());

    let setup_start = Instant::now();

    let mut prover = NativeProver::with_cache_dir(circuit, k, temp_dir.path())
        .expect("Failed to create NativeProver");

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 69,
    };

    prover.setup(metadata).expect("Failed to setup prover");
    let setup_elapsed = setup_start.elapsed();
    println!("  - Setup time: {:.2?}", setup_elapsed);
    println!();

    println!("PROOF GENERATION:");
    let proof_start = Instant::now();
    let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];
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
        println!("VERIFIED: Transaction is valid!");
        println!();
        println!("The verifier confirmed:");
        println!("  + Alice had enough balance");
        println!("  + New balance = Old balance - Amount");
        println!("  + Account exists in Merkle tree");
        println!();
        println!("WITHOUT learning:");
        println!("  - The actual balances");
        println!("  - The transfer amount");
        println!("  - Any private financial data");
        println!();

        // ── Format public inputs as bytes32 for on-chain submission ─────
        let commitment_old_bytes = commitment_old.to_repr();
        let commitment_new_bytes = commitment_new.to_repr();
        let merkle_root_bytes = merkle_root.to_repr();

        // Fp::to_repr() is little-endian; reverse for big-endian (Solidity bytes32)
        let to_bytes32 = |repr: &[u8]| -> String {
            let mut padded = [0u8; 32];
            for (i, byte) in repr.iter().enumerate() {
                if i < 32 {
                    padded[31 - i] = *byte;
                }
            }
            format!("0x{}", hex::encode(padded))
        };

        let commit_old_hex = to_bytes32(commitment_old_bytes.as_ref());
        let commit_new_hex = to_bytes32(commitment_new_bytes.as_ref());
        let root_hex = to_bytes32(merkle_root_bytes.as_ref());
        let proof_hex = format!("0x{}", hex::encode(&proof));

        println!("=== ON-CHAIN SUBMISSION ===\n");
        println!("The proof and public inputs below can be submitted to the");
        println!("TxPrivacyVerifier Stylus contract on Arbitrum Sepolia.\n");
        println!("Public inputs (visible on-chain):");
        println!("  commitment_old : {}", commit_old_hex);
        println!("  commitment_new : {}", commit_new_hex);
        println!("  merkle_root    : {}", root_hex);
        println!("  proof size     : {} bytes", proof.len());
        println!();
        println!("Private data (NEVER sent on-chain):");
        println!("  balance_old    : {} tokens", balance_old);
        println!("  balance_new    : {} tokens", balance_new);
        println!("  amount         : {} tokens", amount);
        println!();

        println!("=== CAST COMMANDS ===\n");
        println!("# Pre-requisite: set these env vars BEFORE running (off-camera):");
        println!("# export CONTRACT=<deployed_address>");
        println!("# export RPC=https://sepolia-rollup.arbitrum.io/rpc");
        println!("# export PK=<your_private_key>\n");

        println!("# 1. Register the merkle root (owner only, one-time):");
        println!("cast send $CONTRACT \"registerMerkleRoot(bytes32)\" {} \\", root_hex);
        println!("  --private-key $PK --rpc-url $RPC\n");

        println!("# 2. Deposit the initial commitment (one-time):");
        println!("cast send $CONTRACT \"depositCommitment(bytes32)\" {} \\", commit_old_hex);
        println!("  --private-key $PK --rpc-url $RPC\n");

        println!("# 3. Submit the verified private transfer:");
        println!("cast send $CONTRACT \\");
        println!("  \"verifyTransfer(bytes,bytes32,bytes32,bytes32)\" \\");
        println!("  {} \\", proof_hex);
        println!("  {} \\", commit_old_hex);
        println!("  {} \\", commit_new_hex);
        println!("  {} \\", root_hex);
        println!("  --private-key $PK --rpc-url $RPC\n");

        println!("# 4. Verify on-chain state:");
        println!("cast call $CONTRACT \"isSpent(bytes32)\" {} --rpc-url $RPC", commit_old_hex);
        println!("cast call $CONTRACT \"getVerifiedCount()\" --rpc-url $RPC");
    } else {
        println!("ERROR: Proof verification failed!");
        std::process::exit(1);
    }
    println!();
}
