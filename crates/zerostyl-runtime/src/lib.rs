//! ZeroStyl Runtime
//!
//! Shared runtime types and error handling for the ZeroStyl toolkit.
//! This crate provides common data structures used across all ZeroStyl components:
//!
//! - [`ZkProof`] - Binary representation of a halo2 zk-SNARK proof
//! - [`CommitmentHash`] - Poseidon hash commitment (32 bytes)
//! - [`MerkleRoot`] - Poseidon Merkle tree root (32 bytes)
//! - [`MerklePath`] - Merkle proof path (siblings + indices)
//! - [`RangeProofConfig`] - Bit-decomposition range proof configuration
//! - [`CircuitConfig`] - halo2 circuit parameters (k, columns)

pub mod error;
pub mod types;

pub use error::{Result, ZeroStylError};
pub use types::{CircuitConfig, CommitmentHash, MerklePath, MerkleRoot, RangeProofConfig, ZkProof};
