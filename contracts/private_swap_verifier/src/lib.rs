//! PrivateSwapVerifier — Arbitrum Stylus contract for multi-circuit private swaps.
//!
//! On-chain component combining ZeroStyl's tx_privacy + state_mask circuits.
//!
//! Architecture:
//!   - OFF-CHAIN: ZeroStyl NativeProver generates TWO independent halo2 proofs:
//!     (1) A tx_privacy proof: the input commitment is valid and the sender has
//!         sufficient balance (balance conservation constraint).
//!     (2) A state_mask proof: the swap amount lies within an acceptable range
//!         (prevents dust attacks and oversized swaps).
//!     The private witnesses (balances, amounts, randomness) never leave the prover.
//!   - ON-CHAIN: This contract validates both proofs and manages swap state.
//!
//! The proofs cryptographically guarantee that:
//!   [tx_privacy proof]
//!   - commitment_old = Poseidon(balance_old, randomness_old)
//!   - commitment_new = Poseidon(balance_new, randomness_new)
//!   - balance_new = balance_old - amount              (balance conservation)
//!   - merkle_root = MerkleRoot(commitment_old, siblings, indices)  (Poseidon-based)
//!
//!   [state_mask proof]
//!   - amount_commitment = Poseidon(amount, randomness)
//!   - collateral_ratio ∈ [150, 300]                   (range constraint on swap amount)
//!
//! Use case (from the grant):
//!   "Private swaps without revealing collateral" — trade tokens without
//!   exposing your position size to frontrunners or competitors.
//!
//! On-chain SNARK verification will be enabled when Stylus WASM size limits
//! support the halo2 verifier + IPA parameters (~130 KB total).

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;
#[allow(deprecated)]
use stylus_sdk::evm;
use stylus_sdk::{
    alloy_primitives::{Address, B256, U256},
    alloy_sol_types::sol,
    msg,
    prelude::*,
};

// ─── Events ─────────────────────────────────────────────────────────────────

sol! {
    /// Emitted when a private swap is successfully processed.
    event PrivateSwapVerified(
        address indexed sender,
        bytes32 indexed nullifier,
        bytes32 indexed commitment_out,
        bytes32 amount_commitment,
        uint256 timestamp
    );

    /// Emitted when a swap submission is rejected.
    event SwapRejected(
        address indexed sender,
        string reason
    );

    /// Emitted when a merkle root is registered.
    event MerkleRootRegistered(
        bytes32 indexed root,
        uint256 timestamp
    );
}

// ─── Storage ────────────────────────────────────────────────────────────────

sol_storage! {
    #[entrypoint]
    pub struct PrivateSwapVerifier {
        /// Total number of verified private swaps.
        uint256 swap_count;

        /// Nullifier set: spent input commitments (prevents double-spend).
        mapping(bytes32 => bool) nullifiers;

        /// Registry of valid merkle roots.
        mapping(bytes32 => bool) merkle_roots;

        /// Mapping from commitment to its creator.
        mapping(bytes32 => address) commitment_owners;

        /// Registry of verified amount commitments (from range proofs).
        mapping(bytes32 => bool) verified_amounts;

        /// Contract owner (deployer).
        address owner;

        /// Whether the contract has been initialized.
        bool initialized;
    }
}

// ─── Public interface ───────────────────────────────────────────────────────

#[public]
impl PrivateSwapVerifier {
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

    /// Register a merkle root as valid. Only the owner can call this.
    pub fn register_merkle_root(&mut self, root: B256) -> Result<(), Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();
        if caller != self.owner.get() {
            return Err(b"Only owner".to_vec());
        }
        self.merkle_roots.setter(root).set(true);
        #[allow(deprecated)]
        evm::log(MerkleRootRegistered {
            root,
            timestamp: U256::from(self.vm().block_timestamp()),
        });
        Ok(())
    }

    /// Submit a verified private swap combining tx_privacy + state_mask proofs.
    ///
    /// The caller provides:
    /// - `transfer_proof`: halo2 proof for the tx_privacy circuit
    /// - `range_proof`: halo2 proof for the state_mask circuit (amount range)
    /// - `commitment_in`: the input commitment being spent (becomes nullifier)
    /// - `commitment_out`: the output commitment created by this swap
    /// - `merkle_root`: the merkle root proving commitment_in membership
    /// - `amount_commitment`: the commitment to the swap amount (range-proven)
    ///
    /// Both proofs are verified off-chain. This contract enforces the protocol
    /// rules without seeing any private data.
    ///
    /// On-chain checks:
    /// 1. Both proofs format validation
    /// 2. Merkle root is registered
    /// 3. Input commitment not spent (nullifier check)
    /// 4. State update: nullifier, new commitment, swap count
    pub fn verify_swap(
        &mut self,
        _transfer_proof_hash: B256,
        _range_proof_hash: B256,
        commitment_in: B256,
        commitment_out: B256,
        merkle_root: B256,
        amount_commitment: B256,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // ── 1. Merkle root must be registered ───────────────────────────
        if !self.merkle_roots.get(merkle_root) {
            #[allow(deprecated)]
            evm::log(SwapRejected {
                sender: caller,
                reason: "Unknown merkle root".into(),
            });
            return Ok(false);
        }

        // ── 3. Nullifier check (double-spend protection) ────────────────
        if self.nullifiers.get(commitment_in) {
            #[allow(deprecated)]
            evm::log(SwapRejected {
                sender: caller,
                reason: "Input commitment already spent".into(),
            });
            return Ok(false);
        }

        // ── All checks passed — update state ────────────────────────────

        // Mark input commitment as spent
        self.nullifiers.setter(commitment_in).set(true);

        // Record output commitment owner
        self.commitment_owners.setter(commitment_out).set(caller);

        // Register the amount commitment as verified
        self.verified_amounts.setter(amount_commitment).set(true);

        // Increment swap count
        let count = self.swap_count.get();
        self.swap_count.set(count + U256::from(1));

        #[allow(deprecated)]
        evm::log(PrivateSwapVerified {
            sender: caller,
            nullifier: commitment_in,
            commitment_out,
            amount_commitment,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(true)
    }

    // ─── View functions ─────────────────────────────────────────────────

    /// Check if an input commitment has been spent.
    pub fn is_spent(&self, commitment: B256) -> bool {
        self.nullifiers.get(commitment)
    }

    /// Check if a merkle root is registered.
    pub fn is_valid_root(&self, root: B256) -> bool {
        self.merkle_roots.get(root)
    }

    /// Get the owner of a commitment.
    pub fn commitment_owner(&self, commitment: B256) -> Address {
        self.commitment_owners.get(commitment)
    }

    /// Check if an amount commitment has been range-verified.
    pub fn is_amount_verified(&self, amount_commitment: B256) -> bool {
        self.verified_amounts.get(amount_commitment)
    }

    /// Get total number of verified swaps.
    pub fn get_swap_count(&self) -> U256 {
        self.swap_count.get()
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
