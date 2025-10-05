//! Integration tests for error handling in zerostyl-runtime

use zerostyl_runtime::ZeroStylError;

#[test]
fn test_invalid_proof_error_message() {
    // Test that InvalidProof error displays the correct message
    let error = ZeroStylError::invalid_proof("proof verification failed");

    let error_msg = error.to_string();
    assert!(error_msg.contains("Invalid proof"));
    assert!(error_msg.contains("proof verification failed"));
}

#[test]
fn test_compilation_error_message() {
    // Test that CompilationError displays the correct message
    let error = ZeroStylError::compilation_error("circuit synthesis failed");

    let error_msg = error.to_string();
    assert!(error_msg.contains("Compilation error"));
    assert!(error_msg.contains("circuit synthesis failed"));
}

#[test]
fn test_serialization_error_message() {
    // Test that SerializationError displays the correct message
    let error = ZeroStylError::serialization_error("invalid JSON format");

    let error_msg = error.to_string();
    assert!(error_msg.contains("Serialization error"));
    assert!(error_msg.contains("invalid JSON format"));
}

#[test]
fn test_other_error_message() {
    // Test that Other error displays the correct message
    let error = ZeroStylError::other("unexpected error occurred");

    let error_msg = error.to_string();
    assert_eq!(error_msg, "unexpected error occurred");
}

#[test]
fn test_io_error_conversion() {
    // Test that std::io::Error can be converted to ZeroStylError
    let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let error: ZeroStylError = io_error.into();

    let error_msg = error.to_string();
    assert!(error_msg.contains("I/O error"));
    assert!(error_msg.contains("file not found"));
}

#[test]
fn test_error_debug_format() {
    // Test that errors can be formatted with Debug
    let error = ZeroStylError::invalid_proof("test");
    let debug_output = format!("{:?}", error);

    assert!(debug_output.contains("InvalidProof"));
}

#[test]
fn test_result_type_ok() {
    // Test that Result type alias works correctly for Ok case
    use zerostyl_runtime::Result;

    let result: Result<i32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_result_type_err() {
    // Test that Result type alias works correctly for Err case
    use zerostyl_runtime::Result;

    let result: Result<i32> = Err(ZeroStylError::other("test error"));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "test error");
}
