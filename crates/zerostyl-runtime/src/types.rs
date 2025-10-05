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
/// let proof_bytes = vec![0u8; 192]; // Example proof data
/// let proof = ZkProof::new(proof_bytes);
/// assert_eq!(proof.size(), 192);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkProof {
    /// Raw bytes of the serialized proof
    proof_data: Vec<u8>,
}

impl ZkProof {
    /// Creates a new ZkProof from raw bytes
    pub fn new(proof_data: Vec<u8>) -> Self {
        Self { proof_data }
    }

    /// Returns the size of the proof in bytes
    pub fn size(&self) -> usize {
        self.proof_data.len()
    }

    /// Returns a reference to the raw proof data
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof_data
    }

    /// Consumes the proof and returns the raw bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.proof_data
    }
}

/// Represents a Pedersen commitment for privacy-preserving operations
///
/// A `Commitment` is a cryptographic commitment used in zero-knowledge proofs
/// to hide sensitive data while allowing verification of its properties.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::Commitment;
///
/// let value = vec![1, 2, 3, 4];
/// let randomness = vec![5, 6, 7, 8];
/// let commitment = Commitment::new(value, randomness);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// The committed value (hidden)
    value: Vec<u8>,
    /// Randomness used in the commitment scheme
    randomness: Vec<u8>,
}

impl Commitment {
    /// Creates a new Commitment with the given value and randomness
    pub fn new(value: Vec<u8>, randomness: Vec<u8>) -> Self {
        Self { value, randomness }
    }

    /// Returns a reference to the committed value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns a reference to the randomness
    pub fn randomness(&self) -> &[u8] {
        &self.randomness
    }
}

/// Configuration parameters for zk-SNARK circuits
///
/// `CircuitConfig` specifies the parameters needed to compile and execute
/// a halo2 circuit, including the number of rows (k parameter) and
/// custom circuit-specific settings.
///
/// # Examples
///
/// ```
/// use zerostyl_runtime::CircuitConfig;
///
/// let config = CircuitConfig::new(17, vec![("max_transfers".to_string(), "10".to_string())]);
/// assert_eq!(config.k(), 17);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitConfig {
    /// The k parameter (circuit has 2^k rows)
    k: u32,
    /// Custom circuit parameters as key-value pairs
    custom_params: Vec<(String, String)>,
}

impl CircuitConfig {
    /// Creates a new CircuitConfig with the specified parameters
    pub fn new(k: u32, custom_params: Vec<(String, String)>) -> Self {
        Self { k, custom_params }
    }

    /// Creates a minimal CircuitConfig with only the k parameter
    pub fn minimal(k: u32) -> Self {
        Self { k, custom_params: Vec::new() }
    }

    /// Returns the k parameter (circuit has 2^k rows)
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Returns the number of rows in the circuit (2^k)
    pub fn num_rows(&self) -> usize {
        1 << self.k
    }

    /// Returns a reference to the custom parameters
    pub fn custom_params(&self) -> &[(String, String)] {
        &self.custom_params
    }

    /// Adds a custom parameter to the configuration
    pub fn add_param(&mut self, key: String, value: String) {
        self.custom_params.push((key, value));
    }
}
