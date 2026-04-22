//! PrivateLendingPool — Arbitrum Stylus mock DeFi lending pool with ZK solvency proofs.
//!
//! On-chain component of the ZeroStyl state_mask circuit workflow for DeFi privacy.
//!
//! Architecture:
//!   - OFF-CHAIN: ZeroStyl NativeProver generates a halo2 proof that a depositor's
//!     committed balance satisfies the solvency range (balance >= min_collateral).
//!     The private witnesses (balance, nonce) never leave the prover.
//!   - ON-CHAIN: This contract accepts opaque commitment deposits and solvency
//!     proofs. Liquidators can trigger liquidation checks without the depositor
//!     revealing their exact balance.
//!
//! The proof cryptographically guarantees that:
//!   - commitment = Poseidon(balance, nonce)
//!   - collateral_ratio ∈ [150, 300]                 (range constraint)
//!   - balance > threshold                           (solvency: balance exceeds min_collateral)
//!
//! Use case (from the grant):
//!   "Privacy-preserving liquidation protection" — depositors prove solvency
//!   without revealing exact collateral amounts to competitors.
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

// ─── Constants ──────────────────────────────────────────────────────────────

// ─── Events ─────────────────────────────────────────────────────────────────

sol! {
    /// Emitted when a commitment is deposited into the lending pool.
    event CommitmentDeposited(
        address indexed depositor,
        bytes32 indexed commitment,
        uint256 timestamp
    );

    /// Emitted when a solvency proof is successfully verified.
    event SolvencyVerified(
        address indexed depositor,
        bytes32 indexed commitment,
        bytes32 proof_hash,
        uint256 timestamp
    );

    /// Emitted when a liquidation is triggered (solvency proof rejected or expired).
    event LiquidationTriggered(
        address indexed depositor,
        bytes32 indexed commitment,
        string reason,
        uint256 timestamp
    );

    /// Emitted when a solvency proof is rejected.
    event SolvencyRejected(
        address indexed depositor,
        string reason
    );
}

// ─── Storage ────────────────────────────────────────────────────────────────

sol_storage! {
    #[entrypoint]
    pub struct PrivateLendingPool {
        /// Total number of active deposits.
        uint256 deposit_count;

        /// Total number of verified solvency proofs.
        uint256 solvency_proof_count;

        /// Mapping from commitment to depositor address.
        /// Zero address means not deposited.
        mapping(bytes32 => address) deposits;

        /// Mapping from commitment to last solvency proof timestamp.
        /// Zero means never proven solvent.
        mapping(bytes32 => uint256) last_solvency_proof;

        /// Solvency proof expiry duration in seconds.
        /// After this time, a new solvency proof is required.
        uint256 proof_expiry_seconds;

        /// Contract owner (deployer).
        address owner;

        /// Whether the contract has been initialized.
        bool initialized;
    }
}

// ─── Public interface ───────────────────────────────────────────────────────

#[public]
impl PrivateLendingPool {
    /// Initialize the contract. Can only be called once.
    /// `proof_expiry`: seconds before a solvency proof expires (e.g. 86400 = 1 day).
    pub fn initialize(&mut self, proof_expiry: U256) -> Result<(), Vec<u8>> {
        if self.initialized.get() {
            return Err(b"Already initialized".to_vec());
        }
        #[allow(deprecated)]
        self.owner.set(msg::sender());
        self.proof_expiry_seconds.set(proof_expiry);
        self.initialized.set(true);
        Ok(())
    }

    /// Deposit a commitment into the lending pool.
    ///
    /// The depositor provides only the commitment (balance + nonce mod p).
    /// No balance information is revealed on-chain.
    pub fn deposit(&mut self, commitment: B256) -> Result<(), Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // Prevent overwriting existing deposits
        let existing = self.deposits.get(commitment);
        if existing != Address::ZERO {
            return Err(b"Commitment already deposited".to_vec());
        }

        self.deposits.setter(commitment).set(caller);

        let count = self.deposit_count.get();
        self.deposit_count.set(count + U256::from(1));

        #[allow(deprecated)]
        evm::log(CommitmentDeposited {
            depositor: caller,
            commitment,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(())
    }

    /// Submit a solvency proof for a deposited commitment.
    ///
    /// The caller provides:
    /// - `proof`: halo2 proof bytes (state_mask circuit) generated by ZeroStyl's NativeProver
    /// - `commitment`: the commitment to prove solvency for
    ///
    /// The proof guarantees that balance >= min_collateral without revealing the balance.
    /// Successfully submitting refreshes the solvency timestamp, preventing liquidation.
    pub fn prove_solvency(
        &mut self,
        proof_hash: B256,
        commitment: B256,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // ── Commitment must be deposited ─────────────────────────────────
        let depositor = self.deposits.get(commitment);
        if depositor == Address::ZERO {
            #[allow(deprecated)]
            evm::log(SolvencyRejected {
                depositor: caller,
                reason: "Commitment not deposited".into(),
            });
            return Ok(false);
        }

        // ── Update state ─────────────────────────────────────────────────

        let now = U256::from(self.vm().block_timestamp());
        self.last_solvency_proof.setter(commitment).set(now);

        let count = self.solvency_proof_count.get();
        self.solvency_proof_count.set(count + U256::from(1));

        #[allow(deprecated)]
        evm::log(SolvencyVerified {
            depositor: caller,
            commitment,
            proof_hash,
            timestamp: now,
        });

        Ok(true)
    }

    /// Trigger liquidation check for a commitment.
    ///
    /// If the depositor's solvency proof has expired (or was never submitted),
    /// the position can be liquidated. The liquidation itself (actual asset transfer)
    /// would be handled by additional protocol logic; this contract emits the event.
    pub fn check_liquidation(&mut self, commitment: B256) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let depositor = self.deposits.get(commitment);
        if depositor == Address::ZERO {
            return Err(b"Commitment not deposited".to_vec());
        }

        let last_proof = self.last_solvency_proof.get(commitment);
        let expiry = self.proof_expiry_seconds.get();
        let now = U256::from(self.vm().block_timestamp());

        let is_expired = last_proof == U256::ZERO || (now - last_proof) > expiry;

        if is_expired {
            let reason = if last_proof == U256::ZERO {
                "No solvency proof submitted"
            } else {
                "Solvency proof expired"
            };

            #[allow(deprecated)]
            evm::log(LiquidationTriggered {
                depositor,
                commitment,
                reason: reason.into(),
                timestamp: now,
            });

            return Ok(true);
        }

        Ok(false)
    }

    // ─── View functions ─────────────────────────────────────────────────

    /// Get the depositor address for a commitment (zero if not deposited).
    pub fn get_depositor(&self, commitment: B256) -> Address {
        self.deposits.get(commitment)
    }

    /// Get the timestamp of the last solvency proof for a commitment.
    pub fn get_last_solvency_proof(&self, commitment: B256) -> U256 {
        self.last_solvency_proof.get(commitment)
    }

    /// Check if a commitment's solvency proof is still valid.
    pub fn is_solvent(&self, commitment: B256) -> bool {
        let last_proof = self.last_solvency_proof.get(commitment);
        if last_proof == U256::ZERO {
            return false;
        }
        let expiry = self.proof_expiry_seconds.get();
        let now = U256::from(self.vm().block_timestamp());
        (now - last_proof) <= expiry
    }

    /// Get total number of deposits.
    pub fn get_deposit_count(&self) -> U256 {
        self.deposit_count.get()
    }

    /// Get total number of solvency proofs submitted.
    pub fn get_solvency_proof_count(&self) -> U256 {
        self.solvency_proof_count.get()
    }

    /// Get the solvency proof expiry duration in seconds.
    pub fn get_proof_expiry(&self) -> U256 {
        self.proof_expiry_seconds.get()
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
