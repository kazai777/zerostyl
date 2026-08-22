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

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod events;
pub mod fingerprint;
pub mod types;

pub use error::{Result, ZeroStylError};
pub use events::ZeroStylPrivacyTransaction;
pub use fingerprint::BytecodeFingerprint;
pub use types::{CircuitConfig, CommitmentHash, MerklePath, MerkleRoot, RangeProofConfig, ZkProof};

/// Fixed seed for the development KZG structured reference string (SRS).
///
/// Both the prover (`zerostyl-compiler`'s `KeyManager`) and the on-chain verifier
/// (`zerostyl-verifier`'s `build.rs`) derive their `ParamsKZG` from this seed, so a proof produced
/// by the prover verifies against the verifier's embedded parameters. Making the SRS deterministic
/// is what enables that interoperability and reproducible builds.
///
/// **This is a development/test setup, NOT a secure trusted-setup ceremony.** The toxic waste of a
/// seeded RNG is public knowledge, so a production deployment must replace this with SRS from a
/// real Powers-of-Tau ceremony. The bytes spell "ZEROSTY".
pub const DEV_SRS_SEED: u64 = 0x005A_4552_4F53_5459;

/// Default directory for cached KZG parameters and keys, shared by the prover, the CLI, and the
/// SDK so a proof written by one is found by the others. A per-crate literal would silently
/// diverge on a rename, forcing full re-keygen with no error pointing at the mismatch.
pub const DEFAULT_CACHE_DIR: &str = ".zerostyl_cache";
