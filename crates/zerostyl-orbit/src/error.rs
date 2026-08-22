//! Error type for the Orbit adapter.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, OrbitError>;

#[derive(Debug, Error)]
pub enum OrbitError {
    /// Filesystem access failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A chain-profile TOML document could not be parsed.
    #[error("invalid chain profile TOML: {0}")]
    Toml(#[from] toml::de::Error),

    /// A named built-in chain profile does not exist.
    #[error("unknown chain profile `{0}` (use a built-in name or a path to a .toml file)")]
    UnknownChain(String),

    /// A chain profile is structurally invalid.
    #[error("invalid chain profile: {0}")]
    InvalidProfile(String),
}
