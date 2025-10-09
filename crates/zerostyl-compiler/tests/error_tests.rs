//! Tests for error handling and error messages

use zerostyl_compiler::{parse_contract, transform_to_ir, CompilerError};

// ============================================================================
// ERROR MESSAGE TESTS
// ============================================================================

#[test]
fn test_unsupported_type_error_message() {
    let input = r#"
        struct BadContract {
            #[zk_private]
            name: String,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let result = transform_to_ir(parsed);

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_msg = error.to_string();

    assert!(error_msg.contains("String"), "Error should mention the unsupported type");
    assert!(error_msg.contains("not supported"), "Error should clearly state it's not supported");
    assert!(error_msg.contains("Supported types"), "Error should list supported types");
}

#[test]
fn test_invalid_syntax_error_message() {
    let input = "not valid rust code at all";

    let result = parse_contract(input);
    assert!(result.is_err());

    let error = result.unwrap_err();
    let error_msg = error.to_string();

    assert!(
        error_msg.contains("Syntax error") || error_msg.contains("expected"),
        "Error should indicate syntax problem: {}",
        error_msg
    );
}

#[test]
fn test_no_struct_found_error() {
    let input = r#"
        fn some_function() {
            println!("hello");
        }
    "#;

    let result = parse_contract(input);
    assert!(result.is_err());

    let error = result.unwrap_err();
    let error_msg = error.to_string();

    assert!(error_msg.contains("No struct found"), "Error should mention no struct was found");
}

#[test]
fn test_vec_type_error_message() {
    let input = r#"
        struct DynamicArray {
            #[zk_private]
            items: Vec<u64>,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let result = transform_to_ir(parsed);

    assert!(result.is_err());
    let error = result.unwrap_err();
    let error_msg = error.to_string();

    assert!(
        error_msg.contains("Vec<u64>") || error_msg.contains("not supported"),
        "Error should mention Vec type is not supported"
    );
}

// ============================================================================
// ERROR TYPE TESTS
// ============================================================================

#[test]
fn test_error_type_variants() {
    let parse_err = CompilerError::ParseError("test parse error".to_string());
    assert!(parse_err.to_string().contains("test parse error"));

    let unsupported_type_err = CompilerError::UnsupportedType("SomeType".to_string());
    assert!(unsupported_type_err.to_string().contains("SomeType"));

    let unsupported_zk_type_err = CompilerError::UnsupportedZkType("ZkType".to_string());
    assert!(unsupported_zk_type_err.to_string().contains("ZkType"));

    let invalid_annotation_err = CompilerError::InvalidAnnotation("bad annotation".to_string());
    assert!(invalid_annotation_err.to_string().contains("bad annotation"));
}
