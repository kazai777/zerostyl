//! StateMaskVerifier — Arbitrum Stylus contract for state proof verification.
//!
//! On-chain component of the ZeroStyl state_mask circuit workflow.
//!
//! Architecture:
//!   - OFF-CHAIN: ZeroStyl NativeProver generates a halo2 proof attesting that:
//!       - collateral_ratio ∈ [150, 300]  (range constraint)
//!       - hidden_balance > threshold      (comparison constraint)
//!     The private witnesses (state_value, nonce) never leave the prover.
//!   - ON-CHAIN: This contract receives only the proof bytes and the commitment
//!     (Poseidon(state_value, nonce)). It registers verified commitments and
//!     enforces that each commitment is only proven once.
//!
//! The proof cryptographically guarantees that:
//!   - commitment = Poseidon(state_value, nonce)
//!   - collateral_ratio ∈ [150, 300]     (range constraint)
//!   - hidden_balance > threshold         (comparison constraint)
//!
//! Use cases:
//!   - "Prove collateral_ratio in [150%, 300%] without revealing the ratio"
//!   - "Prove hidden_balance > threshold without revealing the balance"
//!
//! On-chain SNARK verification: `verify_solvency` performs a **real** halo2 KZG verification via
//! the embedded state_mask verifying key (`zerostyl-verifier`, no runtime keygen). The legacy
//! `verify_range_proof` (hash-only, no cryptographic check) is kept for backward compatibility but
//! is deprecated — prefer `verify_solvency`.
//!
//! Size caveat — NOT deployable as-is. Arbitrum Stylus gates deployment on a **24 KB
//! Brotli-compressed** binary (the EVM code-size limit; up to 96 KB on a custom chain) and a
//! **128 KB uncompressed** WASM (`MaxWasmSize`; 256 KB at ArbOS 60+). This contract is ~240 KB
//! compressed / ~559 KB uncompressed. Trimming the embedded SRS to verifier-only points and
//! `wasm-opt` (~10%) do not close a ~10× gap: the halo2 `verify_proof` + BN254 pairing code alone
//! is ~91.5 KB compressed / ~374 KB uncompressed — over the limits before any data. Fitting Stylus
//! requires offloading the pairing to Arbitrum's BN254 precompile (0x08) with a hand-written
//! minimal KZG verifier, or wrapping the proof in Groth16. The verification logic here is correct
//! and tested (see the note above the module tests); it is a reference, not a deployable contract.

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;
#[allow(deprecated)]
use stylus_sdk::evm;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, B256, U256},
    alloy_sol_types::sol,
    msg,
    prelude::*,
};

// ─── Events ─────────────────────────────────────────────────────────────────

sol! {
    /// Emitted when a range proof is successfully verified.
    event RangeProofVerified(
        address indexed prover,
        bytes32 indexed commitment,
        bytes32 proof_hash,
        uint256 timestamp
    );

    /// Emitted when a range proof submission is rejected.
    event RangeProofRejected(
        address indexed prover,
        string reason
    );

    /// Emitted when a solvency proof is cryptographically verified on-chain.
    event SolvencyProofVerified(
        address indexed prover,
        bytes32 indexed commitment,
        bytes32 threshold,
        uint256 timestamp
    );
}

// ─── Storage ────────────────────────────────────────────────────────────────

sol_storage! {
    #[entrypoint]
    pub struct StateMaskVerifier {
        /// Total number of verified range proofs.
        uint256 verified_count;

        /// Registry of verified commitments.
        /// Maps commitment → prover address. Zero address means not verified.
        mapping(bytes32 => address) verified_commitments;

        /// The threshold each commitment was proven solvent against.
        /// Maps commitment → threshold (little-endian Fr repr). Without this, a verified
        /// commitment records "solvent" with no record of the bound it was proven against —
        /// a proof of `balance > 0` would be indistinguishable from `balance > 1_000_000`.
        mapping(bytes32 => bytes32) verified_thresholds;

        /// Contract owner (deployer).
        address owner;

        /// Whether the contract has been initialized.
        bool initialized;
    }
}

// ─── Verification plumbing ────────────────────────────────────────────────────

/// Run the embedded halo2 state_mask verifier on a proof and its two public inputs.
///
/// `commitment` and `threshold` are the public inputs as 32-byte **little-endian** field
/// representations (`Fr::to_repr()`); they are forwarded verbatim to the verifier. Returns
/// `Ok(true)` if the proof verifies, `Ok(false)` if it does not, and `Err` if an input is not a
/// canonical field element. Kept as a free function so it can be unit-tested without a VM.
fn verify_solvency_proof(proof: &[u8], commitment: B256, threshold: B256) -> Result<bool, Vec<u8>> {
    let public_inputs = [commitment.0, threshold.0];
    zerostyl_verifier::verify_state_mask_bytes(proof, &public_inputs)
}

// ─── Public interface ───────────────────────────────────────────────────────

#[public]
impl StateMaskVerifier {
    /// Initialize the contract. Can only be called once.
    pub fn initialize(&mut self) -> Result<(), Vec<u8>> {
        if self.initialized.get() {
            return Err(b"Already initialized".to_vec());
        }
        #[allow(deprecated)]
        self.owner.set(msg::sender());
        self.initialized.set(true);
        Ok(())
    }

    /// Submit a solvency proof and verify it **on-chain**.
    ///
    /// The caller provides:
    /// - `proof`: the halo2 KZG proof bytes produced by `zerostyl-prove` for the state_mask circuit
    /// - `commitment`: public input 0 — `Poseidon(state_value, collateral_ratio, hidden_balance,
    ///   nonce)`, as a 32-byte **little-endian** field representation (`Fr::to_repr()`)
    /// - `threshold`: public input 1 — the minimum balance, same little-endian encoding
    ///
    /// The contract calls the embedded halo2 verifier: the proof is accepted only if it
    /// cryptographically attests that `collateral_ratio ∈ [150,300]` and
    /// `hidden_balance > threshold` for the committed state. No secret data reaches the chain.
    ///
    /// On success the commitment is registered (each commitment can only be proven once, together
    /// with the threshold it was proven against — see [`Self::commitment_threshold`]) and a
    /// `SolvencyProofVerified` event is emitted.
    ///
    /// ⚠️ Byte order: `commitment` and `threshold` are **little-endian** field representations
    /// (`Fr::to_repr()`), exactly as emitted in `zerostyl-prove`'s `public_inputs.json`. Do NOT
    /// pass `abi.encode(uint256)` / `bytes32(uint256(x))` — EVM tooling produces big-endian bytes,
    /// which `Fr::from_repr` reads as a different (usually non-canonical) field element and the
    /// proof will fail to verify. Forward the `public_inputs.json` bytes verbatim.
    pub fn verify_solvency(
        &mut self,
        proof: Bytes,
        commitment: B256,
        threshold: B256,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // ── 1. Idempotency: a commitment can only be proven once ────────
        if self.verified_commitments.get(commitment) != Address::ZERO {
            #[allow(deprecated)]
            evm::log(RangeProofRejected {
                prover: caller,
                reason: "Commitment already verified".into(),
            });
            return Ok(false);
        }

        // ── 2. REAL on-chain KZG verification ───────────────────────────
        let verified = verify_solvency_proof(&proof.0, commitment, threshold)?;
        if !verified {
            #[allow(deprecated)]
            evm::log(RangeProofRejected { prover: caller, reason: "Invalid proof".into() });
            return Ok(false);
        }

        // ── 3. Register the commitment (with the threshold it was proven against) and emit ──
        self.verified_commitments.setter(commitment).set(caller);
        self.verified_thresholds.setter(commitment).set(threshold);
        let count = self.verified_count.get();
        self.verified_count.set(count + U256::from(1));

        #[allow(deprecated)]
        evm::log(SolvencyProofVerified {
            prover: caller,
            commitment,
            threshold,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(true)
    }

    /// Submit a range proof by hash only (**deprecated, no cryptographic verification**).
    ///
    /// Kept for backward compatibility with the original deployment. It records a commitment
    /// against a proof *hash* without checking the proof. Prefer [`Self::verify_solvency`], which
    /// verifies the halo2 proof on-chain.
    ///
    /// The caller provides:
    /// - `proof_hash`: keccak256 hash of the halo2 proof (not verified)
    /// - `commitment`: Poseidon commitment generated off-chain
    pub fn verify_range_proof(
        &mut self,
        proof_hash: B256,
        commitment: B256,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // ── 1. Commitment must not be already registered ────────────────
        let existing = self.verified_commitments.get(commitment);
        if existing != Address::ZERO {
            #[allow(deprecated)]
            evm::log(RangeProofRejected {
                prover: caller,
                reason: "Commitment already verified".into(),
            });
            return Ok(false);
        }

        // ── All checks passed — update state ────────────────────────────

        self.verified_commitments.setter(commitment).set(caller);

        let count = self.verified_count.get();
        self.verified_count.set(count + U256::from(1));

        #[allow(deprecated)]
        evm::log(RangeProofVerified {
            prover: caller,
            commitment,
            proof_hash,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(true)
    }

    // ─── View functions ─────────────────────────────────────────────────

    /// Check if a commitment has been verified.
    pub fn is_verified(&self, commitment: B256) -> bool {
        self.verified_commitments.get(commitment) != Address::ZERO
    }

    /// Get the prover address for a verified commitment (zero if not verified).
    pub fn commitment_prover(&self, commitment: B256) -> Address {
        self.verified_commitments.get(commitment)
    }

    /// Get the threshold (little-endian `Fr` repr) a commitment was proven solvent against.
    /// Returns zero if the commitment has not been verified.
    pub fn commitment_threshold(&self, commitment: B256) -> B256 {
        self.verified_thresholds.get(commitment)
    }

    /// Get the total number of verified range proofs.
    pub fn get_verified_count(&self) -> U256 {
        self.verified_count.get()
    }

    /// Get contract owner.
    pub fn get_owner(&self) -> Address {
        self.owner.get()
    }

    /// Check if the contract is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized.get()
    }
}

// NOTE: this crate cannot be unit-tested on a native host — stylus-sdk's `#[entrypoint]` links
// Stylus VM host symbols (`native_keccak256`, `pay_for_memory_grow`) that only exist in the VM,
// and the `stylus-test` harness that stubs them requires a newer toolchain than this contract is
// pinned to. The verification `verify_solvency_proof` performs is the exact function
// `zerostyl_verifier::verify_state_mask_bytes`, which is tested end-to-end (real proof accepted,
// tampered/wrong-input rejected, byte order) in `crates/zerostyl-verifier/tests/state_mask_roundtrip.rs`.
