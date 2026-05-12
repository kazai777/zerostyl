use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExporterError {
    #[error("circuit '{0}' not found in registry")]
    CircuitNotFound(String),

    #[error("invalid abi schema: {0}")]
    InvalidSchema(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ExporterError>;
