//! SDK error type.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SdkError>;

#[derive(Debug, Error)]
pub enum SdkError {
    /// Filesystem access failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// An `abi.json` document is structurally invalid.
    #[error("invalid ABI schema: {0}")]
    Abi(String),

    /// A circuit operation (prove/verify/mock_prove/registry) failed.
    #[error(transparent)]
    Circuit(#[from] zerostyl_circuits::CircuitError),

    /// A hex-encoded field element could not be parsed.
    #[error("invalid field-element hex: {0}")]
    Hex(String),

    /// A proof envelope could not be decoded or belongs to another circuit.
    #[error("proof format error: {0}")]
    ProofFormat(String),

    /// A witness value is incompatible with the circuit's witness schema.
    #[error("invalid witness: {0}")]
    Witness(String),
}
