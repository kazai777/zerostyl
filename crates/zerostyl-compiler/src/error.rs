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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_display() {
        let err = CompilerError::ParseError("test error".to_string());
        assert_eq!(err.to_string(), "Parse error: test error");
    }

    #[test]
    fn test_unsupported_type_display() {
        let err = CompilerError::UnsupportedType("Vec<String>".to_string());
        assert_eq!(err.to_string(), "Unsupported type for zk: Vec<String>");
    }

    #[test]
    fn test_unsupported_zk_type_display() {
        let err = CompilerError::UnsupportedZkType("i128".to_string());
        assert_eq!(err.to_string(), "Unsupported zk type: i128");
    }

    #[test]
    fn test_invalid_annotation_display() {
        let err = CompilerError::InvalidAnnotation("missing parameter".to_string());
        assert_eq!(err.to_string(), "Invalid annotation: missing parameter");
    }

    #[test]
    fn test_other_error_display() {
        let err = CompilerError::Other("custom error message".to_string());
        assert_eq!(err.to_string(), "custom error message");
    }

    #[test]
    fn test_error_debug_format() {
        let err = CompilerError::ParseError("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ParseError"));
    }

    #[test]
    fn test_result_type_ok() {
        let result: Result<i32> = Ok(42);
        assert!(result.is_ok());
        if let Ok(value) = result {
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn test_result_type_err() {
        let result: Result<i32> = Err(CompilerError::Other("error".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_runtime_error_conversion() {
        let runtime_err = zerostyl_runtime::ZeroStylError::compilation_error("test error");
        let compiler_err: CompilerError = runtime_err.into();

        match compiler_err {
            CompilerError::RuntimeError(_) => (),
            _ => panic!("Expected RuntimeError variant"),
        }
    }

    #[test]
    fn test_parse_error_creation() {
        let err = CompilerError::ParseError("syntax error".to_string());
        let err_string = err.to_string();
        assert!(err_string.contains("Parse error"));
        assert!(err_string.contains("syntax error"));
    }

    #[test]
    fn test_unsupported_type_creation() {
        let err = CompilerError::UnsupportedType("HashMap".to_string());
        let err_string = err.to_string();
        assert!(err_string.contains("Unsupported type for zk"));
        assert!(err_string.contains("HashMap"));
    }
}
