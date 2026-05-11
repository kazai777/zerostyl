use thiserror::Error;

use crate::report::MockProverReport;

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("invalid witness: {0}")]
    InvalidWitness(String),

    #[error("proof generation failed: {0}")]
    ProveFailed(String),

    #[error("verification failed: {0}")]
    VerifyFailed(String),

    #[error("mock prover surfaced {} failure(s)", .0.failures.len())]
    MockProverFailures(Box<MockProverReport>),

    #[error("circuit '{0}' not found in registry")]
    CircuitNotFound(String),

    #[error("circuit '{0}' is already registered")]
    AlreadyRegistered(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CircuitError>;
