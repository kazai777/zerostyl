//! Reusable halo2 circuit gadgets for ZeroStyl.
//!
//! Production-ready building blocks for privacy-preserving circuits:
//!
//! - [`PoseidonCommitmentChip`] — Poseidon hash commitment: `commitment = Poseidon(value, randomness)`
//! - [`MerkleTreeChip`] — Poseidon-based Merkle tree membership verification (default depth 32)
//! - [`RangeProofChip`] — Bit-decomposition range proof (8/16/32/64 bits)
//! - [`ComparisonChip`] — Ordering proofs (`>`, `>=`, `<`, `<=`) via range-checked differences
//!
//! All gadgets operate over the BN254 scalar field (`halo2curves::bn256::Fr`) and use the
//! P128Pow5T3 Poseidon specification (128-bit security, x^5 S-box, width=3, rate=2).
//!
//! This crate is `no_std` (it only needs `alloc`) so the circuits built from these gadgets can be
//! compiled for `wasm32` and embedded in an on-chain verifier, independently of the heavier
//! `zerostyl-compiler` (prover/CLI) crate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod comparison;
pub mod merkle;
pub mod poseidon_chip;
pub mod poseidon_commitment;
pub mod poseidon_native;
pub mod range;

pub use comparison::{ComparisonChip, ComparisonConfig};
pub use merkle::{MerkleTreeChip, MerkleTreeConfig};
pub use poseidon_commitment::{PoseidonCommitmentChip, PoseidonCommitmentConfig};
pub use range::{RangeProofChip, RangeProofConfig};
