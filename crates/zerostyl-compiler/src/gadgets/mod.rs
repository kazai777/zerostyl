//! Reusable halo2 circuit gadgets for ZeroStyl.
//!
//! This module provides production-ready building blocks for privacy-preserving circuits:
//!
//! - [`PoseidonCommitmentChip`] — Poseidon hash commitment: `commitment = Poseidon(value, randomness)`
//! - [`MerkleTreeChip`] — Poseidon-based Merkle tree membership verification (depth up to 64)
//! - [`RangeProofChip`] — Bit-decomposition range proof (8/16/32/64 bits)
//! - [`ComparisonChip`] — Ordering proofs (`>`, `>=`, `<`, `<=`) via range-checked differences
//!
//! All gadgets use the Pasta Fp field and the P128Pow5T3 Poseidon specification
//! (128-bit security, x^5 S-box, width=3, rate=2).

pub mod comparison;
pub mod merkle;
pub mod poseidon_commitment;
pub mod range;

pub use comparison::{ComparisonChip, ComparisonConfig};
pub use merkle::{MerkleTreeChip, MerkleTreeConfig};
pub use poseidon_commitment::{PoseidonCommitmentChip, PoseidonCommitmentConfig};
pub use range::{RangeProofChip, RangeProofConfig};