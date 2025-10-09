//! Tests for the AST transformation module

use zerostyl_compiler::{
    parse_contract, transform_to_ir, ArithOp, CircuitIR, ComparisonOp, Constraint,
    InterFieldConstraint, ParsedContract, PrivateField, ZkField, ZkType,
};
use zerostyl_runtime::CircuitConfig;

// ============================================================================
// TRANSFORMATION TESTS
// ============================================================================

#[test]
fn test_transform_simple_u64_field() {
    let parsed = ParsedContract {
        contract_name: "TestContract".to_string(),
        private_fields: vec![PrivateField {
            name: "balance".to_string(),
            field_type: "u64".to_string(),
        }],
    };

    let ir = transform_to_ir(parsed).unwrap();
    assert_eq!(ir.name, "TestContract");
    assert_eq!(ir.private_witnesses.len(), 1);
    assert_eq!(ir.private_witnesses[0].name, "balance");
    assert!(matches!(ir.private_witnesses[0].field_type, ZkType::U64));
}

#[test]
fn test_transform_multiple_fields() {
    let parsed = ParsedContract {
        contract_name: "MultiFieldContract".to_string(),
        private_fields: vec![
            PrivateField { name: "amount".to_string(), field_type: "u64".to_string() },
            PrivateField { name: "total".to_string(), field_type: "u128".to_string() },
            PrivateField { name: "hash".to_string(), field_type: "[u8;32]".to_string() },
        ],
    };

    let ir = transform_to_ir(parsed).unwrap();
    assert_eq!(ir.name, "MultiFieldContract");
    assert_eq!(ir.private_witnesses.len(), 3);

    assert_eq!(ir.private_witnesses[0].name, "amount");
    assert!(matches!(ir.private_witnesses[0].field_type, ZkType::U64));

    assert_eq!(ir.private_witnesses[1].name, "total");
    assert!(matches!(ir.private_witnesses[1].field_type, ZkType::U128));

    assert_eq!(ir.private_witnesses[2].name, "hash");
    assert!(matches!(ir.private_witnesses[2].field_type, ZkType::Bytes32));
}

// ============================================================================
// TYPE VALIDATION TESTS
// ============================================================================

#[test]
fn test_all_integer_types() {
    let input = r#"
        struct AllIntegers {
            #[zk_private]
            field_u8: u8,
            #[zk_private]
            field_u16: u16,
            #[zk_private]
            field_u32: u32,
            #[zk_private]
            field_u64: u64,
            #[zk_private]
            field_u128: u128,
            #[zk_private]
            field_i64: i64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 6);
}

#[test]
fn test_bool_and_address_types() {
    let input = r#"
        struct BoolAndAddress {
            #[zk_private]
            is_valid: bool,
            #[zk_private]
            owner: Address,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 2);
}

#[test]
fn test_field_type() {
    let input = r#"
        struct FieldTest {
            #[zk_private]
            native_field: Field,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 1);
    assert_eq!(ir.private_witnesses[0].constraints.len(), 0);
}

#[test]
fn test_unsupported_type() {
    let parsed = ParsedContract {
        contract_name: "UnsupportedContract".to_string(),
        private_fields: vec![PrivateField {
            name: "name".to_string(),
            field_type: "String".to_string(),
        }],
    };

    let result = transform_to_ir(parsed);
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("String"));
    assert!(err_msg.contains("not supported"));
}

#[test]
fn test_unsupported_vec_type() {
    let parsed = ParsedContract {
        contract_name: "VecTest".to_string(),
        private_fields: vec![PrivateField {
            name: "vec_field".to_string(),
            field_type: "Vec<u64>".to_string(),
        }],
    };

    let result = transform_to_ir(parsed);
    assert!(result.is_err());
}

// ============================================================================
// CONSTRAINT TESTS
// ============================================================================

#[test]
fn test_default_constraints() {
    let parsed = ParsedContract {
        contract_name: "ConstraintTest".to_string(),
        private_fields: vec![
            PrivateField { name: "u64_field".to_string(), field_type: "u64".to_string() },
            PrivateField { name: "u128_field".to_string(), field_type: "u128".to_string() },
            PrivateField { name: "bytes32_field".to_string(), field_type: "[u8;32]".to_string() },
        ],
    };

    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses[0].constraints.len(), 1);
    if let Constraint::RangeProof { min, max } = ir.private_witnesses[0].constraints[0] {
        assert_eq!(min, 0);
        assert_eq!(max, u64::MAX as u128);
    } else {
        panic!("Expected RangeProof for u64");
    }

    assert_eq!(ir.private_witnesses[1].constraints.len(), 1);
    if let Constraint::RangeProof { min, max } = ir.private_witnesses[1].constraints[0] {
        assert_eq!(min, 0);
        assert_eq!(max, u128::MAX);
    } else {
        panic!("Expected RangeProof for u128");
    }

    assert_eq!(ir.private_witnesses[2].constraints.len(), 0);
}

#[test]
fn test_comparison_constraint() {
    let constraint = Constraint::Comparison { operator: ComparisonOp::NotEqual, value: 0 };

    match constraint {
        Constraint::Comparison { operator: ComparisonOp::NotEqual, value } => {
            assert_eq!(value, 0);
        }
        _ => panic!("Expected NotEqual comparison"),
    }
}

#[test]
fn test_arithmetic_relation_constraint() {
    let constraint = Constraint::ArithmeticRelation {
        lhs_field: "balance_new".to_string(),
        operator: ArithOp::Sub,
        rhs_fields: vec![
            ("balance_old".to_string(), ArithOp::Sub),
            ("amount".to_string(), ArithOp::Sub),
        ],
    };

    match constraint {
        Constraint::ArithmeticRelation { lhs_field, operator, rhs_fields } => {
            assert_eq!(lhs_field, "balance_new");
            assert_eq!(operator, ArithOp::Sub);
            assert_eq!(rhs_fields.len(), 2);
        }
        _ => panic!("Expected ArithmeticRelation"),
    }
}

#[test]
fn test_merkle_proof_constraint() {
    let constraint = Constraint::MerkleProof {
        leaf_field: "commitment".to_string(),
        path_field: "merkle_path".to_string(),
        root_field: "merkle_root".to_string(),
        tree_depth: 32,
    };

    match constraint {
        Constraint::MerkleProof { leaf_field, path_field, root_field, tree_depth } => {
            assert_eq!(leaf_field, "commitment");
            assert_eq!(path_field, "merkle_path");
            assert_eq!(root_field, "merkle_root");
            assert_eq!(tree_depth, 32);
        }
        _ => panic!("Expected MerkleProof"),
    }
}

#[test]
fn test_inter_field_constraints() {
    let arith = InterFieldConstraint::ArithmeticRelation {
        result_field: "result".to_string(),
        operation: ArithOp::Add,
        operands: vec!["a".to_string(), "b".to_string()],
    };

    assert!(matches!(arith, InterFieldConstraint::ArithmeticRelation { .. }));

    let merkle = InterFieldConstraint::MerkleVerification {
        leaf: "leaf".to_string(),
        path: "path".to_string(),
        root: "root".to_string(),
    };

    assert!(matches!(merkle, InterFieldConstraint::MerkleVerification { .. }));
}

// ============================================================================
// CIRCUIT IR TESTS
// ============================================================================

#[test]
fn test_circuit_ir_creation() {
    let parsed = ParsedContract {
        contract_name: "PaymentContract".to_string(),
        private_fields: vec![
            PrivateField { name: "sender_balance".to_string(), field_type: "u64".to_string() },
            PrivateField { name: "recipient_balance".to_string(), field_type: "u64".to_string() },
        ],
    };

    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.name, "PaymentContract");
    assert_eq!(ir.private_witnesses.len(), 2);

    for field in &ir.private_witnesses {
        assert!(matches!(field.field_type, ZkType::U64));
        assert!(!field.constraints.is_empty());
    }
}

#[test]
fn test_circuit_ir_equality() {
    let ir1 = CircuitIR {
        name: "Test".to_string(),
        public_inputs: vec![],
        private_witnesses: vec![ZkField {
            name: "field1".to_string(),
            field_type: ZkType::U64,
            constraints: vec![Constraint::RangeProof { min: 0, max: u64::MAX as u128 }],
        }],
        inter_field_constraints: vec![],
        circuit_config: CircuitConfig::minimal(16).unwrap(),
    };

    let ir2 = CircuitIR {
        name: "Test".to_string(),
        public_inputs: vec![],
        private_witnesses: vec![ZkField {
            name: "field1".to_string(),
            field_type: ZkType::U64,
            constraints: vec![Constraint::RangeProof { min: 0, max: u64::MAX as u128 }],
        }],
        inter_field_constraints: vec![],
        circuit_config: CircuitConfig::minimal(16).unwrap(),
    };

    assert_eq!(ir1, ir2);
}

#[test]
fn test_circuit_config_structure() {
    let input = r#"
        struct TestCircuit {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.circuit_config.k(), 16);
    assert_eq!(ir.circuit_config.lookup_tables().len(), 0);
    assert_eq!(ir.circuit_config.custom_gates().len(), 0);
}

#[test]
fn test_public_private_separation() {
    let input = r#"
        struct Circuit {
            #[zk_private]
            secret: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.public_inputs.len(), 0);
    assert_eq!(ir.private_witnesses.len(), 1);
}

// ============================================================================
// EDGE CASES FOR COVERAGE
// ============================================================================

#[test]
fn test_parse_all_basic_types() {
    let input = r#"
        struct AllTypes {
            #[zk_private]
            v_u8: u8,
            #[zk_private]
            v_u16: u16,
            #[zk_private]
            v_u32: u32,
            #[zk_private]
            v_i64: i64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    
    assert_eq!(ir.private_witnesses.len(), 4);
    assert!(matches!(ir.private_witnesses[0].field_type, ZkType::U8));
    assert!(matches!(ir.private_witnesses[1].field_type, ZkType::U16));
    assert!(matches!(ir.private_witnesses[2].field_type, ZkType::U32));
    assert!(matches!(ir.private_witnesses[3].field_type, ZkType::I64));
}

#[test]
fn test_many_fields() {
    let mut fields = String::new();
    for i in 0..50 {
        fields.push_str(&format!("    #[zk_private]\n    field_{}: u64,\n", i));
    }

    let input = format!("struct LargeContract {{\n{}}}", fields);
    let result = parse_contract(&input).unwrap();
    assert_eq!(result.private_fields.len(), 50);

    let ir = transform_to_ir(result).unwrap();
    assert_eq!(ir.private_witnesses.len(), 50);
}
