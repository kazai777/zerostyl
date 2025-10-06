//! Core types for ZeroStyl toolkit
//!
//! This module defines fundamental data structures used throughout the ZeroStyl ecosystem
//! for representing zero-knowledge proofs, cryptographic commitments, and circuit configurations.

use serde::{Deserialize, Serialize};

/// Hash function type for cryptographic commitments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashType {
    /// Pedersen hash (efficient in circuits, elliptic curves)
    Pedersen,
    /// Poseidon hash (optimized for zk-SNARKs)
    Poseidon,
}

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
    pub const MIN_PROOF_SIZE: usize = 32;

    /// Creates a new ZkProof with validation
    ///
    /// # Errors
    /// Returns error if proof data is smaller than MIN_PROOF_SIZE
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

    pub fn size(&self) -> usize {
        self.proof_data.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.proof_data
    }
}

/// Cryptographic commitment for privacy-preserving operations
///
/// A `Commitment` hides sensitive data while allowing verification of its properties
/// in zero-knowledge proofs.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::{Commitment, HashType};
///
/// let value = vec![1, 2, 3, 4];
/// let randomness = vec![5; 32];
/// let commitment = Commitment::new(value, randomness, HashType::Pedersen).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    value: Vec<u8>,
    randomness: Vec<u8>,
    hash_type: HashType,
}

impl Commitment {
    pub const MIN_RANDOMNESS_SIZE: usize = 32;

    /// Creates a new commitment with validation
    ///
    /// # Arguments
    /// * `value` - Value to commit to (cannot be empty)
    /// * `randomness` - Random nonce for hiding (minimum 32 bytes)
    /// * `hash_type` - Hash function to use
    ///
    /// # Errors
    /// Returns error if value is empty or randomness is too short
    pub fn new(value: Vec<u8>, randomness: Vec<u8>, hash_type: HashType) -> crate::Result<Self> {
        if value.is_empty() {
            return Err(crate::ZeroStylError::InvalidCommitment(
                "Commitment value cannot be empty".to_string(),
            ));
        }
        if randomness.is_empty() {
            return Err(crate::ZeroStylError::InvalidCommitment(
                "Commitment requires non-empty randomness for security".to_string(),
            ));
        }
        if randomness.len() < Self::MIN_RANDOMNESS_SIZE {
            return Err(crate::ZeroStylError::InvalidCommitment(format!(
                "Randomness too short: {} bytes (minimum {})",
                randomness.len(),
                Self::MIN_RANDOMNESS_SIZE
            )));
        }
        Ok(Self { value, randomness, hash_type })
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn randomness(&self) -> &[u8] {
        &self.randomness
    }

    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }
}

/// Lookup tables available in circuits
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LookupTable {
    Sha256,
    Pedersen,
}

/// Custom gates for specific cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustomGate {
    PedersenHash,
    MerklePathGate,
}

/// Configuration for a halo2 zk-SNARK circuit
///
/// Contains all parameters needed to configure and compile a halo2 circuit.
/// The `k` parameter determines circuit size: a circuit with `k=16` has 2^16 = 65,536 rows.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::{CircuitConfig, LookupTable, CustomGate};
///
/// let config = CircuitConfig::minimal(16).unwrap();
/// assert_eq!(config.k(), 16);
/// assert_eq!(config.num_rows(), 65536);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitConfig {
    k: u32,
    lookup_tables: Vec<LookupTable>,
    custom_gates: Vec<CustomGate>,
    custom_params: std::collections::HashMap<String, String>,
}

impl CircuitConfig {
    pub const MIN_K: u32 = 4;
    pub const MAX_K: u32 = 28;

    /// Creates a minimal configuration with no lookup tables or custom gates
    ///
    /// # Errors
    /// Returns error if k is outside valid range [4, 28]
    pub fn minimal(k: u32) -> crate::Result<Self> {
        Self::validate_k(k)?;
        Ok(Self {
            k,
            lookup_tables: vec![],
            custom_gates: vec![],
            custom_params: std::collections::HashMap::new(),
        })
    }

    /// Creates a full configuration with lookup tables and custom gates
    ///
    /// # Errors
    /// Returns error if k is outside valid range [4, 28]
    pub fn new(
        k: u32,
        lookup_tables: Vec<LookupTable>,
        custom_gates: Vec<CustomGate>,
    ) -> crate::Result<Self> {
        Self::validate_k(k)?;
        Ok(Self { k, lookup_tables, custom_gates, custom_params: std::collections::HashMap::new() })
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

    pub fn k(&self) -> u32 {
        self.k
    }

    pub fn num_rows(&self) -> usize {
        1 << self.k
    }

    pub fn lookup_tables(&self) -> &[LookupTable] {
        &self.lookup_tables
    }

    pub fn custom_gates(&self) -> &[CustomGate] {
        &self.custom_gates
    }

    pub fn add_param(&mut self, key: String, value: String) {
        self.custom_params.insert(key, value);
    }

    pub fn custom_params(&self) -> &std::collections::HashMap<String, String> {
        &self.custom_params
    }
}
