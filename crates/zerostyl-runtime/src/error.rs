//! Error types for ZeroStyl toolkit
//!
//! This module defines the error types used throughout the ZeroStyl ecosystem,
//! providing consistent error handling across all components.

use thiserror::Error;

/// Result type alias for ZeroStyl operations
pub type Result<T> = std::result::Result<T, ZeroStylError>;

/// The main error type for ZeroStyl operations
///
/// This enum covers all error cases that can occur when working with
/// ZeroStyl components, from proof generation to compilation and serialization.
#[derive(Debug, Error)]
pub enum ZeroStylError {
    /// Invalid or malformed zero-knowledge proof
    ///
    /// This error occurs when a proof fails verification or has an invalid format
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Circuit compilation error
    ///
    /// This error occurs during the compilation of halo2 circuits to WASM
    #[error("Compilation error: {0}")]
    CompilationError(String),

    /// Serialization or deserialization error
    ///
    /// This error occurs when converting between binary and structured formats
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// I/O error
    ///
    /// This error wraps standard I/O errors
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Generic error for other cases
    ///
    /// This error covers any other error cases not specifically handled above
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
