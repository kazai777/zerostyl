//! Compiler error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unsupported type for zk: {0}")]
    UnsupportedType(String),

    #[error("Unsupported zk type: {0}")]
    UnsupportedZkType(String),

    #[error("Invalid annotation: {0}")]
    InvalidAnnotation(String),

    #[error("Syntax error: {0}")]
    SynError(#[from] syn::Error),

    #[error(transparent)]
    RuntimeError(#[from] zerostyl_runtime::ZeroStylError),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CompilerError>;
