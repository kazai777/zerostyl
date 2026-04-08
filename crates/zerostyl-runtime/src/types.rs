//! Core types for ZeroStyl toolkit
//!
//! This module defines fundamental data structures used throughout the ZeroStyl ecosystem
//! for representing zero-knowledge proofs, cryptographic commitments, and circuit configurations.

use serde::{Deserialize, Serialize};

/// Represents a zero-knowledge SNARK proof
///
/// A `ZkProof` encapsulates the binary representation of a zk-SNARK proof
/// generated from a halo2 circuit. This proof can be verified on-chain
/// within an Arbitrum Stylus smart contract.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::ZkProof;
///
/// let proof_bytes = vec![0u8; 192];
/// let proof = ZkProof::new(proof_bytes).unwrap();
/// assert_eq!(proof.size(), 192);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkProof {
    proof_data: Vec<u8>,
}

impl ZkProof {
    /// Minimum size in bytes for a valid halo2 IPA proof.
    pub const MIN_PROOF_SIZE: usize = 32;

    /// Creates a new `ZkProof` with validation.
    ///
    /// # Errors
    ///
    /// Returns [`ZeroStylError::InvalidProof`](crate::ZeroStylError::InvalidProof)
    /// if `proof_data` is smaller than [`MIN_PROOF_SIZE`](Self::MIN_PROOF_SIZE).
    pub fn new(proof_data: Vec<u8>) -> crate::Result<Self> {
        if proof_data.len() < Self::MIN_PROOF_SIZE {
            return Err(crate::ZeroStylError::InvalidProof(format!(
                "Proof too small: {} bytes (minimum {})",
                proof_data.len(),
                Self::MIN_PROOF_SIZE
            )));
        }
        Ok(Self { proof_data })
    }

    /// Returns the proof size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.proof_data.len()
    }

    /// Returns the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_data
    }

    /// Consumes self and returns the inner byte vector.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.proof_data
    }
}

/// Result of a Poseidon hash commitment: `Poseidon(value, randomness)`.
///
/// Stored as 32 bytes representing a field element from the Pasta Fp curve.
/// This is the on-chain representation — the preimage (value, randomness) is private.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::CommitmentHash;
///
/// let hash_bytes = [0xab_u8; 32];
/// let commitment = CommitmentHash::new(hash_bytes);
/// assert_eq!(commitment.as_bytes(), &[0xab; 32]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentHash([u8; 32]);

impl CommitmentHash {
    /// Creates a new commitment hash from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a commitment hash with all zero bytes (for testing/initialization).
    #[must_use]
    pub fn zero() -> Self {
        Self([0u8; 32])
    }
}

/// Merkle tree root hash (Poseidon-based).
///
/// Represents the root of a Poseidon Merkle tree.
/// Stored as 32 bytes representing a Pasta Fp field element.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::MerkleRoot;
///
/// let root = MerkleRoot::new([0xff_u8; 32]);
/// assert_eq!(root.as_bytes(), &[0xff; 32]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Creates a new Merkle root from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte root hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Merkle proof path for membership verification.
///
/// Contains the sibling hashes and path indices needed to recompute
/// a Merkle root from a leaf. Used with Poseidon hash at each level.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::MerklePath;
///
/// let siblings = vec![[0u8; 32]; 32];
/// let indices = vec![false; 32];
/// let path = MerklePath::new(siblings, indices).unwrap();
/// assert_eq!(path.depth(), 32);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    siblings: Vec<[u8; 32]>,
    indices: Vec<bool>,
}

impl MerklePath {
    /// Standard Merkle tree depth (2^32 ~4 billion leaves).
    pub const DEFAULT_DEPTH: usize = 32;

    /// Maximum supported Merkle tree depth.
    pub const MAX_DEPTH: usize = 64;

    /// Creates a new Merkle path with validation.
    ///
    /// # Errors
    ///
    /// Returns [`ZeroStylError::InvalidCommitment`](crate::ZeroStylError::InvalidCommitment) if:
    /// - `siblings` and `indices` have different lengths
    /// - Depth exceeds [`MAX_DEPTH`](Self::MAX_DEPTH)
    /// - Path is empty
    pub fn new(siblings: Vec<[u8; 32]>, indices: Vec<bool>) -> crate::Result<Self> {
        if siblings.len() != indices.len() {
            return Err(crate::ZeroStylError::InvalidCommitment(format!(
                "Merkle path length mismatch: {} siblings, {} indices",
                siblings.len(),
                indices.len()
            )));
        }
        if siblings.is_empty() {
            return Err(crate::ZeroStylError::InvalidCommitment(
                "Merkle path cannot be empty".to_string(),
            ));
        }
        if siblings.len() > Self::MAX_DEPTH {
            return Err(crate::ZeroStylError::InvalidCommitment(format!(
                "Merkle tree depth {} exceeds maximum {}",
                siblings.len(),
                Self::MAX_DEPTH
            )));
        }
        Ok(Self { siblings, indices })
    }

    /// Returns the tree depth (number of levels).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Returns the sibling hashes at each level.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    /// Returns the path indices (false = left child, true = right child).
    #[must_use]
    pub fn indices(&self) -> &[bool] {
        &self.indices
    }
}

/// Configuration for range proofs via bit decomposition.
///
/// Specifies the number of bits used to constrain a value's range.
/// A range proof with `num_bits = 64` proves that `value ∈ [0, 2^64)`.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::RangeProofConfig;
///
/// let config = RangeProofConfig::new(64).unwrap();
/// assert_eq!(config.num_bits(), 64);
/// assert_eq!(config.max_value(), u64::MAX as u128);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProofConfig {
    num_bits: usize,
}

impl RangeProofConfig {
    /// Maximum number of bits for a range proof (field element size limit).
    pub const MAX_BITS: usize = 64;

    /// Supported bit widths for range proofs.
    pub const SUPPORTED_BITS: [usize; 4] = [8, 16, 32, 64];

    /// Creates a new range proof configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ZeroStylError::InvalidCircuitConfig`](crate::ZeroStylError::InvalidCircuitConfig)
    /// if `num_bits` is not one of the supported widths (8, 16, 32, 64).
    pub fn new(num_bits: usize) -> crate::Result<Self> {
        if !Self::SUPPORTED_BITS.contains(&num_bits) {
            return Err(crate::ZeroStylError::InvalidCircuitConfig(format!(
                "Unsupported range proof bit width: {}. Supported: {:?}",
                num_bits,
                Self::SUPPORTED_BITS
            )));
        }
        Ok(Self { num_bits })
    }

    /// Returns the number of bits in this range proof.
    #[must_use]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Returns the maximum value representable: `2^num_bits - 1`.
    #[must_use]
    pub fn max_value(&self) -> u128 {
        (1u128 << self.num_bits) - 1
    }
}

/// Configuration for a halo2 zk-SNARK circuit.
///
/// Contains parameters needed to configure and compile a halo2 circuit.
/// The `k` parameter determines circuit size: a circuit with `k=16` has 2^16 = 65,536 rows.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::CircuitConfig;
///
/// let config = CircuitConfig::minimal(16).unwrap();
/// assert_eq!(config.k(), 16);
/// assert_eq!(config.num_rows(), 65536);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitConfig {
    k: u32,
    num_advice_columns: usize,
    num_instance_columns: usize,
    num_fixed_columns: usize,
}

impl CircuitConfig {
    /// Minimum k value (halo2 requirement).
    pub const MIN_K: u32 = 4;
    /// Maximum k value (memory limit).
    pub const MAX_K: u32 = 28;

    /// Creates a minimal configuration with default column counts.
    ///
    /// # Errors
    ///
    /// Returns error if `k` is outside valid range [4, 28].
    pub fn minimal(k: u32) -> crate::Result<Self> {
        Self::validate_k(k)?;
        Ok(Self { k, num_advice_columns: 1, num_instance_columns: 1, num_fixed_columns: 0 })
    }

    /// Creates a configuration with specified column counts.
    ///
    /// # Errors
    ///
    /// Returns error if `k` is outside valid range [4, 28].
    pub fn new(
        k: u32,
        num_advice_columns: usize,
        num_instance_columns: usize,
        num_fixed_columns: usize,
    ) -> crate::Result<Self> {
        Self::validate_k(k)?;
        Ok(Self { k, num_advice_columns, num_instance_columns, num_fixed_columns })
    }

    fn validate_k(k: u32) -> crate::Result<()> {
        if k < Self::MIN_K {
            return Err(crate::ZeroStylError::InvalidCircuitConfig(format!(
                "Circuit k must be >= {} (halo2 requirement), got {}",
                Self::MIN_K,
                k
            )));
        }
        if k > Self::MAX_K {
            return Err(crate::ZeroStylError::InvalidCircuitConfig(format!(
                "Circuit k={} too large (max {})",
                k,
                Self::MAX_K
            )));
        }
        Ok(())
    }

    /// Returns the k parameter.
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Returns the number of rows: `2^k`.
    #[must_use]
    pub fn num_rows(&self) -> usize {
        1 << self.k
    }

    /// Returns the number of advice columns.
    #[must_use]
    pub fn num_advice_columns(&self) -> usize {
        self.num_advice_columns
    }

    /// Returns the number of instance columns.
    #[must_use]
    pub fn num_instance_columns(&self) -> usize {
        self.num_instance_columns
    }

    /// Returns the number of fixed columns.
    #[must_use]
    pub fn num_fixed_columns(&self) -> usize {
        self.num_fixed_columns
    }
}
