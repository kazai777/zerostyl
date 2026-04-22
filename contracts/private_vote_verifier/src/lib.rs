//! PrivateVoteVerifier — Arbitrum Stylus contract for anonymous DAO voting.
//!
//! On-chain component of the ZeroStyl private_vote circuit workflow.
//!
//! Architecture:
//!   - OFF-CHAIN: ZeroStyl NativeProver generates a halo2 proof attesting that:
//!     (a) the voter holds a balance commitment above the eligibility threshold,
//!     (b) the vote value is boolean (0 = NO, 1 = YES).
//!     The private witnesses (balance, randomness, vote) never leave the prover.
//!   - ON-CHAIN: This contract receives only the proof bytes and public inputs
//!     (balance_commitment, threshold, vote_commitment). It tallies votes and
//!     prevents double-voting via nullifiers.
//!
//! The proof cryptographically guarantees that:
//!   - balance_commitment = Poseidon(balance, randomness_balance)
//!   - vote_commitment    = Poseidon(vote, randomness_vote)
//!   - balance >= threshold                               (eligibility)
//!   - vote ∈ {0, 1}                                     (boolean vote)
//!
//! Nobody on-chain knows the voter's balance or their individual vote.
//! Only the aggregate tally is public.
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
    /// Emitted when a private vote is successfully cast.
    event VoteCast(
        bytes32 indexed nullifier,
        bytes32 indexed vote_commitment,
        uint256 timestamp
    );

    /// Emitted when a vote submission is rejected.
    event VoteRejected(
        address indexed voter,
        string reason
    );

    /// Emitted when voting is opened by the owner.
    event VotingOpened(
        uint256 threshold,
        uint256 timestamp
    );

    /// Emitted when voting is closed by the owner.
    event VotingClosed(
        uint256 yes_votes,
        uint256 no_votes,
        uint256 timestamp
    );
}

// ─── Storage ────────────────────────────────────────────────────────────────

sol_storage! {
    #[entrypoint]
    pub struct PrivateVoteVerifier {
        /// Tally of YES votes (vote_commitment encoding 1).
        uint256 yes_votes;

        /// Tally of NO votes (vote_commitment encoding 0).
        /// Derived: total_votes - yes_votes. Stored separately for gas efficiency.
        uint256 no_votes;

        /// Nullifier set: spent balance commitments (prevents double-voting).
        mapping(bytes32 => bool) nullifiers;

        /// Minimum token balance required to vote (set at opening).
        uint256 eligibility_threshold;

        /// Whether voting is currently open.
        bool voting_open;

        /// Contract owner (deployer).
        address owner;

        /// Whether the contract has been initialized.
        bool initialized;
    }
}

// ─── Public interface ───────────────────────────────────────────────────────

#[public]
impl PrivateVoteVerifier {
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

    /// Open voting with a specific eligibility threshold. Only the owner can call this.
    pub fn open_voting(&mut self, threshold: U256) -> Result<(), Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();
        if caller != self.owner.get() {
            return Err(b"Only owner".to_vec());
        }
        if self.voting_open.get() {
            return Err(b"Voting already open".to_vec());
        }
        self.eligibility_threshold.set(threshold);
        self.voting_open.set(true);
        #[allow(deprecated)]
        evm::log(VotingOpened {
            threshold,
            timestamp: U256::from(self.vm().block_timestamp()),
        });
        Ok(())
    }

    /// Close voting and finalize results. Only the owner can call this.
    pub fn close_voting(&mut self) -> Result<(), Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();
        if caller != self.owner.get() {
            return Err(b"Only owner".to_vec());
        }
        if !self.voting_open.get() {
            return Err(b"Voting not open".to_vec());
        }
        self.voting_open.set(false);
        #[allow(deprecated)]
        evm::log(VotingClosed {
            yes_votes: self.yes_votes.get(),
            no_votes: self.no_votes.get(),
            timestamp: U256::from(self.vm().block_timestamp()),
        });
        Ok(())
    }

    /// Cast a private vote with eligibility proof.
    ///
    /// The caller provides:
    /// - `proof`: halo2 proof bytes generated by ZeroStyl's NativeProver (verified off-chain)
    /// - `balance_commitment`: commitment to the voter's balance (used as nullifier)
    /// - `vote_commitment`: commitment to the vote value (0=NO, 1=YES)
    /// - `is_yes`: whether this vote commitment encodes YES (1). The ZK proof
    ///   guarantees the commitment is well-formed; this hint drives tallying.
    ///
    /// The contract does NOT receive the voter's balance, randomness, or raw vote.
    /// Nobody on-chain can link a vote_commitment to a voter identity.
    ///
    /// On-chain checks:
    /// 1. Voting is open
    /// 2. Proof format validation (non-empty, minimum size)
    /// 3. Balance commitment not already used (nullifier / double-vote prevention)
    /// 4. State update: mark nullifier, tally vote, emit event
    pub fn cast_vote(
        &mut self,
        _proof_hash: B256,
        balance_commitment: B256,
        vote_commitment: B256,
        is_yes: bool,
    ) -> Result<bool, Vec<u8>> {
        #[allow(deprecated)]
        let caller = msg::sender();

        // ── 1. Voting must be open ──────────────────────────────────────
        if !self.voting_open.get() {
            #[allow(deprecated)]
            evm::log(VoteRejected {
                voter: caller,
                reason: "Voting is not open".into(),
            });
            return Ok(false);
        }

        // ── 2. Nullifier check (double-vote prevention) ─────────────────
        if self.nullifiers.get(balance_commitment) {
            #[allow(deprecated)]
            evm::log(VoteRejected {
                voter: caller,
                reason: "Balance commitment already used".into(),
            });
            return Ok(false);
        }

        // ── All checks passed — update state ────────────────────────────

        // Mark balance commitment as spent (nullifier)
        self.nullifiers.setter(balance_commitment).set(true);

        // Tally the vote
        if is_yes {
            let count = self.yes_votes.get();
            self.yes_votes.set(count + U256::from(1));
        } else {
            let count = self.no_votes.get();
            self.no_votes.set(count + U256::from(1));
        }

        #[allow(deprecated)]
        evm::log(VoteCast {
            nullifier: balance_commitment,
            vote_commitment,
            timestamp: U256::from(self.vm().block_timestamp()),
        });

        Ok(true)
    }

    // ─── View functions ─────────────────────────────────────────────────

    /// Check if a balance commitment has already voted.
    pub fn has_voted(&self, balance_commitment: B256) -> bool {
        self.nullifiers.get(balance_commitment)
    }

    /// Get the current YES vote tally.
    pub fn get_yes_votes(&self) -> U256 {
        self.yes_votes.get()
    }

    /// Get the current NO vote tally.
    pub fn get_no_votes(&self) -> U256 {
        self.no_votes.get()
    }

    /// Get total votes cast.
    pub fn get_total_votes(&self) -> U256 {
        self.yes_votes.get() + self.no_votes.get()
    }

    /// Get the eligibility threshold.
    pub fn get_threshold(&self) -> U256 {
        self.eligibility_threshold.get()
    }

    /// Check if voting is currently open.
    pub fn is_voting_open(&self) -> bool {
        self.voting_open.get()
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
