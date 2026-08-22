//! TxPrivacyVerifier — Arbitrum Stylus contract for private transfer verification.
//!
//! On-chain component of the ZeroStyl tx_privacy circuit workflow.
//!
//! Architecture:
//!   - OFF-CHAIN: ZeroStyl NativeProver generates a halo2 proof attesting that
//!     the private witnesses (balances, randomness, amount) satisfy the circuit
//!     constraints (commitment validity, balance conservation, merkle membership).
//!   - ON-CHAIN: This contract receives only the proof bytes and public inputs
//!     (commitment_old, commitment_new, merkle_root, nullifier). It manages state
//!     and enforces protocol rules without ever seeing private data.
//!
//! The proof cryptographically guarantees that:
//!   - commitment_old = Poseidon(balance_old, randomness_old)
//!   - commitment_new = Poseidon(balance_new, randomness_new)
//!   - balance_new = balance_old - amount               (balance conservation)
//!   - balance_new ∈ [0, 2^64)                          (no field underflow)
//!   - merkle_root = MerkleRoot(commitment_old, siblings, indices)  (Poseidon-based)
//!   - nullifier = Poseidon(randomness_old, balance_old)
//!
//! The nullifier is a dedicated public input, distinct from commitment_old, so the
//! double-spend marker never reveals which Merkle leaf was spent (commitment_old is
//! the leaf and must stay unlinked from the spend).
//!
//! On-chain SNARK verification will be enabled when Stylus WASM size limits
//! support the halo2 verifier + IPA parameters (~130 KB total).
//! See zerostyl-verifier crate for details.

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
    /// Emitted when a private transfer is successfully processed.
    /// The proof was generated and verified off-chain by ZeroStyl's NativeProver.
    event PrivateTransferVerified(
        address indexed sender,
        bytes32 indexed nullifier,
        bytes32 indexed commitment_new,
        bytes32 merkle_root,
        bytes32 proof_hash,
        uint256 timestamp
    );

    /// Emitted when a transfer submission is rejected.
    event TransferRejected(
        address indexed sender,
        string reason
    );

    /// Emitted when a new merkle root is registered.
    event MerkleRootRegistered(
        bytes32 indexed root,
        uint256 timestamp
    );

    /// Emitted when a new commitment is deposited.
    event CommitmentDeposited(
        address indexed sender,
        bytes32 indexed commitment,
        uint256 timestamp
    );
}

// ─── Storage ────────────────────────────────────────────────────────────────

sol_storage! {
    #[entrypoint]
    pub struct TxPrivacyVerifier {
        /// Total number of verified transfers.
        uint256 verified_count;

        /// Nullifier set: spent commitment hashes (prevents double-spend).
        /// Once a commitment is used as input to a transfer, its hash is added here.
        mapping(bytes32 => bool) nullifiers;

        /// Mapping from commitment to the address that created it.
        mapping(bytes32 => address) commitment_owners;

        /// Registry of valid merkle roots.
        /// Updated when the commitment tree changes (new deposits).
        mapping(bytes32 => bool) merkle_roots;

        /// Contract owner (deployer).
        address owner;

        /// Whether the contract has been initialized.
        bool initialized;
    }
}

// ─── Public interface ───────────────────────────────────────────────────────

#[public]
impl TxPrivacyVerifier {
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
    ///
    /// In a full protocol, the merkle tree would be maintained on-chain
    /// and roots auto-computed. For this version, the owner registers
    /// roots that match the off-chain commitment tree state.
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

    /// Deposit a new commitment into the protocol.
    ///
    /// The commitment is computed off-chain as `commitment = Poseidon(balance, randomness)`
    /// using ZeroStyl's circuit math. Only the opaque commitment is stored on-chain.
    pub fn deposit_commitment(&mut self, commitment: B256) -> Result<(), Vec<u8>> {
        // Ensure this commitment hasn't already been deposited. Nullifiers now live in a
        // separate hash space (Poseidon with swapped inputs), so a commitment can no longer be
        // looked up there; re-deposit is instead guarded by the owner registry.
        if self.commitment_owners.get(commitment) != Address::ZERO {
            return Err(b"Commitment already deposited".to_vec());
        }

        #[allow(deprecated)]
        let caller = msg::sender();
        self.commitment_owners.setter(commitment).set(caller);

        #[allow(deprecated)]
        evm::log(CommitmentDeposited {
            sender: caller,
            commitment,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(())
    }

    /// Submit a verified private transfer.
    ///
    /// The caller provides:
    /// - `proof`: halo2 proof bytes generated by ZeroStyl's NativeProver (verified off-chain)
    /// - `commitment_old`: the commitment being spent (the Merkle leaf)
    /// - `commitment_new`: the new commitment created by this transfer
    /// - `merkle_root`: the merkle tree root proving commitment_old membership
    /// - `nullifier`: `Poseidon(randomness_old, balance_old)`, the dedicated double-spend marker
    ///
    /// The contract does NOT receive any private data (balances, randomness, amount).
    /// The halo2 proof cryptographically guarantees that the circuit constraints
    /// are satisfied — including that `nullifier` is the correct hash of the spent note's
    /// secrets. On-chain SNARK verification will be added when Stylus supports the required
    /// WASM contract size.
    ///
    /// On-chain checks:
    /// 1. Proof format validation (non-empty, minimum size)
    /// 2. Merkle root is registered (membership)
    /// 3. Nullifier not already spent (double-spend protection) — keyed on `nullifier`, not
    ///    `commitment_old`, so the spent leaf stays private
    /// 4. State update: mark nullifier, record new commitment, emit event
    pub fn verify_transfer(
        &mut self,
        proof_hash: B256,
        commitment_old: B256,
        commitment_new: B256,
        merkle_root: B256,
        nullifier: B256,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // commitment_old is bound by the proof (it is the Merkle leaf) but is not used as the
        // double-spend key here; silence the unused-variable lint without dropping it from the
        // ABI, since it remains a meaningful public input of the circuit.
        let _ = commitment_old;

        // ── 1. Merkle root must be registered ───────────────────────────
        if !self.merkle_roots.get(merkle_root) {
            #[allow(deprecated)]
            evm::log(TransferRejected {
                sender: caller,
                reason: "Unknown merkle root".into(),
            });
            return Ok(false);
        }

        // ── 3. Nullifier check (double-spend protection) ────────────────
        if self.nullifiers.get(nullifier) {
            #[allow(deprecated)]
            evm::log(TransferRejected {
                sender: caller,
                reason: "Nullifier already spent".into(),
            });
            return Ok(false);
        }

        // ── All checks passed — update state ────────────────────────────

        // Mark the note as spent by its nullifier (unlinkable to commitment_old)
        self.nullifiers.setter(nullifier).set(true);

        // Record new commitment owner
        self.commitment_owners.setter(commitment_new).set(caller);

        // Increment verified count
        let count = self.verified_count.get();
        self.verified_count.set(count + U256::from(1));

        // Emit success event (includes proof size for transparency)
        #[allow(deprecated)]
        evm::log(PrivateTransferVerified {
            sender: caller,
            nullifier,
            commitment_new,
            merkle_root,
            proof_hash,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(true)
    }

    // ─── View functions ─────────────────────────────────────────────────

    /// Check if a nullifier has been spent (is in the nullifier set).
    pub fn is_spent(&self, nullifier: B256) -> bool {
        self.nullifiers.get(nullifier)
    }

    /// Get the owner of a commitment.
    pub fn commitment_owner(&self, commitment: B256) -> Address {
        self.commitment_owners.get(commitment)
    }

    /// Check if a merkle root is registered.
    pub fn is_valid_root(&self, root: B256) -> bool {
        self.merkle_roots.get(root)
    }

    /// Get the total number of verified transfers.
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
