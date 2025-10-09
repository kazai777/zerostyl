//! Tests for the parser module

use zerostyl_compiler::{parse_contract, ParsedContract, PrivateField};

// ============================================================================
// BASIC PARSING TESTS
// ============================================================================

#[test]
fn test_parse_simple_private_field() {
    let input = r#"
        struct MyContract {
            #[zk_private]
            balance: u64,
            owner: Address,
        }
    "#;

    let result = parse_contract(input).unwrap();
    assert_eq!(result.contract_name, "MyContract");
    assert_eq!(result.private_fields.len(), 1);
    assert_eq!(result.private_fields[0].name, "balance");
    assert_eq!(result.private_fields[0].field_type, "u64");
}

#[test]
fn test_parse_multiple_private_fields() {
    let input = r#"
        struct Payment {
            #[zk_private]
            amount: u64,
            #[zk_private]
            recipient: Address,
            nonce: u32,
        }
    "#;

    let result = parse_contract(input).unwrap();
    assert_eq!(result.contract_name, "Payment");
    assert_eq!(result.private_fields.len(), 2);
    assert_eq!(result.private_fields[0].name, "amount");
    assert_eq!(result.private_fields[1].name, "recipient");
}

#[test]
fn test_parse_no_private_fields() {
    let input = r#"
        struct PublicData {
            timestamp: u64,
            hash: [u8; 32],
        }
    "#;

    let result = parse_contract(input).unwrap();
    assert_eq!(result.contract_name, "PublicData");
    assert!(result.private_fields.is_empty());
}

#[test]
fn test_parse_mixed_fields() {
    let input = r#"
        struct MixedContract {
            public_field: u32,
            #[zk_private]
            private_field: u64,
            another_public: bool,
            #[zk_private]
            another_private: u128,
        }
    "#;

    let result = parse_contract(input).unwrap();
    assert_eq!(result.contract_name, "MixedContract");
    assert_eq!(result.private_fields.len(), 2);
    assert_eq!(result.private_fields[0].name, "private_field");
    assert_eq!(result.private_fields[1].name, "another_private");
}

#[test]
fn test_parse_complex_types() {
    let input = r#"
        struct ComplexContract {
            #[zk_private]
            array_field: [u8; 32],
            #[zk_private]
            vec_field: Vec<u64>,
        }
    "#;

    let result = parse_contract(input).unwrap();
    assert_eq!(result.contract_name, "ComplexContract");
    assert_eq!(result.private_fields.len(), 2);
    assert_eq!(result.private_fields[0].field_type, "[u8;32]");
    assert_eq!(result.private_fields[1].field_type, "Vec<u64>");
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_parse_empty_struct() {
    let input = "struct Empty {}";
    let result = parse_contract(input).unwrap();
    assert_eq!(result.contract_name, "Empty");
    assert_eq!(result.private_fields.len(), 0);
}

#[test]
fn test_parse_tuple_struct() {
    let input = "struct Tuple(u64);";
    let result = parse_contract(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().private_fields.len(), 0);
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_parse_invalid_syntax() {
    let input = "not valid rust code";

    assert!(parse_contract(input).is_err());
}

// ============================================================================
// EQUALITY TESTS
// ============================================================================

#[test]
fn test_parsed_contract_equality() {
    let contract1 = ParsedContract {
        contract_name: "Test".to_string(),
        private_fields: vec![PrivateField {
            name: "field1".to_string(),
            field_type: "u64".to_string(),
        }],
    };

    let contract2 = ParsedContract {
        contract_name: "Test".to_string(),
        private_fields: vec![PrivateField {
            name: "field1".to_string(),
            field_type: "u64".to_string(),
        }],
    };

    assert_eq!(contract1, contract2);
}
