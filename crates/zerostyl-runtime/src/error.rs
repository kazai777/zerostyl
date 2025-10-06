//! Error types for ZeroStyl toolkit

use thiserror::Error;

/// Result type alias for ZeroStyl operations
pub type Result<T> = std::result::Result<T, ZeroStylError>;

/// Main error type for ZeroStyl operations
#[derive(Debug, Error)]
pub enum ZeroStylError {
    /// Invalid or malformed zero-knowledge proof
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Circuit compilation error
    #[error("Compilation error: {0}")]
    CompilationError(String),

    /// Serialization or deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// I/O error wrapper
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid cryptographic commitment
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Invalid circuit configuration parameters
    #[error("Invalid circuit configuration: {0}")]
    InvalidCircuitConfig(String),

    /// Other errors not covered by specific variants
    #[error("{0}")]
    Other(String),
}

impl ZeroStylError {
    pub fn invalid_proof(msg: impl Into<String>) -> Self {
        Self::InvalidProof(msg.into())
    }

    pub fn compilation_error(msg: impl Into<String>) -> Self {
        Self::CompilationError(msg.into())
    }

    pub fn serialization_error(msg: impl Into<String>) -> Self {
        Self::SerializationError(msg.into())
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
