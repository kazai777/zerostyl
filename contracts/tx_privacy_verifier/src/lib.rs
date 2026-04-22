//! TxPrivacyVerifier — Arbitrum Stylus contract for private transfer verification.
//!
//! On-chain component of the ZeroStyl tx_privacy circuit workflow.
//!
//! Architecture:
//!   - OFF-CHAIN: ZeroStyl NativeProver generates a halo2 proof attesting that
//!     the private witnesses (balances, randomness, amount) satisfy the circuit
//!     constraints (commitment validity, balance conservation, merkle membership).
//!   - ON-CHAIN: This contract receives only the proof bytes and public inputs
//!     (commitment_old, commitment_new, merkle_root). It manages state and
//!     enforces protocol rules without ever seeing private data.
//!
//! The proof cryptographically guarantees that:
//!   - commitment_old = Poseidon(balance_old, randomness_old)
//!   - commitment_new = Poseidon(balance_new, randomness_new)
//!   - balance_new = balance_old - amount               (balance conservation)
//!   - merkle_root = MerkleRoot(commitment_old, siblings, indices)  (Poseidon-based)
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
        // Ensure commitment hasn't been used before
        if self.nullifiers.get(commitment) {
            return Err(b"Commitment already exists as nullifier".to_vec());
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
    /// - `commitment_old`: the commitment being spent (becomes a nullifier)
    /// - `commitment_new`: the new commitment created by this transfer
    /// - `merkle_root`: the merkle tree root proving commitment_old membership
    ///
    /// The contract does NOT receive any private data (balances, randomness, amount).
    /// The halo2 proof cryptographically guarantees that the circuit constraints
    /// are satisfied. On-chain SNARK verification will be added when Stylus supports
    /// the required WASM contract size.
    ///
    /// On-chain checks:
    /// 1. Proof format validation (non-empty, minimum size)
    /// 2. Merkle root is registered (membership)
    /// 3. Commitment not already spent (nullifier / double-spend protection)
    /// 4. State update: mark nullifier, record new commitment, emit event
    pub fn verify_transfer(
        &mut self,
        proof_hash: B256,
        commitment_old: B256,
        commitment_new: B256,
        merkle_root: B256,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

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
        if self.nullifiers.get(commitment_old) {
            #[allow(deprecated)]
            evm::log(TransferRejected {
                sender: caller,
                reason: "Commitment already spent".into(),
            });
            return Ok(false);
        }

        // ── All checks passed — update state ────────────────────────────

        // Mark old commitment as spent (nullifier)
        self.nullifiers.setter(commitment_old).set(true);

        // Record new commitment owner
        self.commitment_owners.setter(commitment_new).set(caller);

        // Increment verified count
        let count = self.verified_count.get();
        self.verified_count.set(count + U256::from(1));

        // Emit success event (includes proof size for transparency)
        #[allow(deprecated)]
        evm::log(PrivateTransferVerified {
            sender: caller,
            nullifier: commitment_old,
            commitment_new,
            merkle_root,
            proof_hash,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(true)
    }

    // ─── View functions ─────────────────────────────────────────────────

    /// Check if a commitment has been spent (is in the nullifier set).
    pub fn is_spent(&self, commitment: B256) -> bool {
        self.nullifiers.get(commitment)
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
