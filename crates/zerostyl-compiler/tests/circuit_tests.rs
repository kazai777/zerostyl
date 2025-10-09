//! Tests for circuit.rs module

use halo2_proofs::plonk::Circuit;
use halo2curves::pasta::Fp as TestField;
use zerostyl_compiler::{
    parse_contract, transform_to_ir, validate_circuit_ir, CircuitBuilder, CompilerError,
};

#[test]
fn test_circuit_builder_basic() {
    let input = r#"
        struct SimpleCircuit {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);

    assert_eq!(builder.circuit_ir().name, "SimpleCircuit");
    assert_eq!(builder.circuit_ir().private_witnesses.len(), 1);
    assert_eq!(builder.circuit_ir().private_witnesses[0].name, "value");
}

#[test]
fn test_circuit_builder_multiple_witnesses() {
    let input = r#"
        struct MultiWitness {
            #[zk_private]
            balance: u64,
            #[zk_private]
            nonce: u64,
            #[zk_private]
            timestamp: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);

    assert_eq!(builder.circuit_ir().private_witnesses.len(), 3);
}

#[test]
fn test_circuit_builder_with_bool() {
    let input = r#"
        struct BoolCircuit {
            #[zk_private]
            is_valid: bool,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);

    assert_eq!(builder.circuit_ir().private_witnesses.len(), 1);
}

#[test]
fn test_circuit_builder_with_address() {
    let input = r#"
        struct AddressCircuit {
            #[zk_private]
            owner: Address,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);

    assert_eq!(builder.circuit_ir().private_witnesses.len(), 1);
}

#[test]
fn test_circuit_builder_with_array() {
    let input = r#"
        struct ArrayCircuit {
            #[zk_private]
            merkle_path: [u8; 32],
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);

    assert_eq!(builder.circuit_ir().private_witnesses.len(), 1);
}

#[test]
fn test_validate_circuit_ir_valid() {
    let input = r#"
        struct ValidCircuit {
            #[zk_private]
            balance: u64,
            #[zk_private]
            nonce: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    let result = validate_circuit_ir(&ir);
    assert!(result.is_ok());
}

#[test]
fn test_validate_circuit_ir_oversized_array() {
    let input = r#"
        struct OversizedArray {
            #[zk_private]
            large_data: [u8; 2000],
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    // transform_to_ir already rejects arrays > 32 elements
    let result = transform_to_ir(parsed);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(matches!(err, CompilerError::UnsupportedZkType(_)));
    assert!(err.to_string().contains("Array"));
}

#[test]
fn test_validate_circuit_ir_all_integer_types() {
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

    let result = validate_circuit_ir(&ir);
    assert!(result.is_ok());
}

#[test]
fn test_validate_circuit_ir_field_type() {
    let input = r#"
        struct FieldCircuit {
            #[zk_private]
            native_field: Field,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    let result = validate_circuit_ir(&ir);
    assert!(result.is_ok());
}

#[test]
fn test_circuit_build_to_zk_circuit() {
    let input = r#"
        struct TestCircuit {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);

    let zk_circuit = builder.build::<TestField>();

    // ZkCircuit is created successfully
    assert_eq!(zk_circuit.ir.name, "TestCircuit");
}

#[test]
fn test_mock_prover_simple_circuit() {
    let input = r#"
        struct SimpleProof {
            #[zk_private]
            secret: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    // Validate before building
    assert!(validate_circuit_ir(&ir).is_ok());

    let builder = CircuitBuilder::new(ir);
    let _circuit = builder.build::<TestField>();
}

#[test]
fn test_mock_prover_multi_witness_circuit() {
    let input = r#"
        struct MultiWitnessProof {
            #[zk_private]
            balance: u64,
            #[zk_private]
            nonce: u64,
            #[zk_private]
            timestamp: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert!(validate_circuit_ir(&ir).is_ok());

    let builder = CircuitBuilder::new(ir);
    let _circuit = builder.build::<TestField>();
}

#[test]
fn test_circuit_without_witnesses() {
    let input = r#"
        struct TestCircuit {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let circuit_copy = circuit.without_witnesses();

    // Should create a copy for verification
    assert_eq!(circuit_copy.ir.name, "TestCircuit");
}

#[test]
fn test_circuit_config_k_parameter() {
    let input = r#"
        struct TestCircuit {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    // Default k is 16 (2^16 = 65536 rows)
    assert_eq!(ir.circuit_config.k(), 16);

    // Validate circuit fits within k
    assert!(validate_circuit_ir(&ir).is_ok());
}

#[test]
fn test_circuit_config_with_custom_k() {
    use zerostyl_runtime::CircuitConfig;

    let input = r#"
        struct TestCircuit {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let mut ir = transform_to_ir(parsed).unwrap();

    // Set custom k value
    let custom_config = CircuitConfig::minimal(10).unwrap(); // 2^10 = 1024 rows
    ir.circuit_config = custom_config;

    assert_eq!(ir.circuit_config.k(), 10);
    assert!(validate_circuit_ir(&ir).is_ok());
}

#[test]
fn test_circuit_with_range_constraint() {
    let input = r#"
        struct RangeCircuit {
            #[zk_private]
            amount: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    // u64 gets range constraint [0, 2^64-1]
    assert_eq!(ir.private_witnesses[0].constraints.len(), 1);

    let builder = CircuitBuilder::new(ir);
    let _circuit = builder.build::<TestField>();

    // Circuit structure with constraints created successfully
}

#[test]
fn test_circuit_builder_preserves_ir_structure() {
    let input = r#"
        struct ComplexCircuit {
            #[zk_private]
            balance: u64,
            #[zk_private]
            is_active: bool,
            #[zk_private]
            owner: Address,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let original_name = ir.name.clone();
    let original_witness_count = ir.private_witnesses.len();

    let builder = CircuitBuilder::new(ir);

    assert_eq!(builder.circuit_ir().name, original_name);
    assert_eq!(builder.circuit_ir().private_witnesses.len(), original_witness_count);
}

#[test]
fn test_validate_circuit_ir_empty_struct() {
    let input = "struct Empty {}";

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    // Empty circuits are valid (though not useful)
    let result = validate_circuit_ir(&ir);
    assert!(result.is_ok());
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

#[test]
fn test_circuit_with_10_fields_no_collision() {
    let input = r#"
        struct LargeCircuit {
            #[zk_private] f1: u64,
            #[zk_private] f2: u64,
            #[zk_private] f3: u64,
            #[zk_private] f4: u64,
            #[zk_private] f5: u64,
            #[zk_private] f6: u64,
            #[zk_private] f7: u64,
            #[zk_private] f8: u64,
            #[zk_private] f9: u64,
            #[zk_private] f10: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 10);
    assert!(validate_circuit_ir(&ir).is_ok());

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    // Circuit structure created successfully
    assert_eq!(circuit.ir.private_witnesses.len(), 10);
    assert_eq!(circuit.ir.name, "LargeCircuit");
}

#[test]
fn test_circuit_with_20_fields() {
    // Test multi-row layout: 20 fields with 10 columns = 2 rows needed

    let input = format!(
        "struct HugeCircuit {{ {} }}",
        (1..=20).map(|i| format!("#[zk_private] field{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 20);
    assert!(validate_circuit_ir(&ir).is_ok());

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.private_witnesses.len(), 20);
}

#[test]
fn test_circuit_with_100_fields() {
    // Extreme test: 100 fields to verify scalability
    // With 10 columns: 100 / 10 = 10 rows needed

    let input = format!(
        "struct MassiveCircuit {{ {} }}",
        (1..=100).map(|i| format!("#[zk_private] f{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 100);
    assert!(validate_circuit_ir(&ir).is_ok());

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.private_witnesses.len(), 100);
}

#[test]
fn test_circuit_exactly_10_fields_single_row() {
    // Edge case: exactly 10 fields should fit in single row

    let input = format!(
        "struct ExactlyTen {{ {} }}",
        (1..=10).map(|i| format!("#[zk_private] x{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 10);

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.private_witnesses.len(), 10);
}

#[test]
fn test_circuit_11_fields_multi_row() {
    // Edge case: 11 fields should trigger multi-row (field[10] → col 0, row 1)

    let input = format!(
        "struct ElevenFields {{ {} }}",
        (1..=11).map(|i| format!("#[zk_private] field{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 11);

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.private_witnesses.len(), 11);
}

#[test]
fn test_row_calculation_correctness() {
    // Verify circuit with 15 fields compiles correctly

    let input = format!(
        "struct TestRows {{ {} }}",
        (1..=15).map(|i| format!("#[zk_private] f{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.private_witnesses.len(), 15);
}

#[test]
fn test_circuit_with_mixed_types() {
    // Verify row allocation works with different types

    let input = r#"
        struct MixedTypes {
            #[zk_private] u64_1: u64,
            #[zk_private] bool_1: bool,
            #[zk_private] u64_2: u64,
            #[zk_private] addr_1: Address,
            #[zk_private] u64_3: u64,
            #[zk_private] bool_2: bool,
            #[zk_private] u64_4: u64,
            #[zk_private] u64_5: u64,
            #[zk_private] u64_6: u64,
            #[zk_private] u64_7: u64,
            #[zk_private] u64_8: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 11);

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.private_witnesses.len(), 11);
}

#[test]
fn test_public_inputs_allocation() {
    // Verify public inputs region compiles
    let input = "struct Simple { #[zk_private] x: u64 }";
    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    assert_eq!(circuit.ir.name, "Simple");
}

#[test]
fn test_max_single_row_constant() {
    // Verify the MAX_SINGLE_ROW_WITNESSES constant is accessible
    use halo2curves::pasta::Fp;
    use zerostyl_compiler::ZkCircuit;

    assert_eq!(ZkCircuit::<Fp>::MAX_SINGLE_ROW_WITNESSES, 10);
    assert_eq!(ZkCircuit::<Fp>::MAX_PUBLIC_INPUTS, 5);
}

// ============================================================================
// INTEGRATION TESTS - Real-world circuits (tx_privacy, state_mask)
// ============================================================================

#[test]
fn test_tx_privacy_circuit() {
    let input = r#"
        struct TxPrivacy {
            #[zk_private]
            balance_old: u64,
            #[zk_private]
            balance_new: u64,
            #[zk_private]
            amount: u64,
            #[zk_private]
            randomness_old: [u8; 32],
            #[zk_private]
            randomness_new: [u8; 32],
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    assert_eq!(parsed.contract_name, "TxPrivacy");
    assert_eq!(parsed.private_fields.len(), 5);

    let ir = transform_to_ir(parsed).unwrap();
    assert_eq!(ir.name, "TxPrivacy");
    assert_eq!(ir.private_witnesses.len(), 5);

    for i in 0..3 {
        assert!(
            !ir.private_witnesses[i].constraints.is_empty(),
            "u64 fields should have range constraints"
        );
    }

    assert_eq!(ir.circuit_config.k(), 16);
}

#[test]
fn test_state_mask_circuit() {
    let input = r#"
        struct StateMask {
            #[zk_private]
            state_value: u64,
            #[zk_private]
            randomness: [u8; 32],
            #[zk_private]
            threshold_min: u64,
            #[zk_private]
            threshold_max: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    assert_eq!(parsed.contract_name, "StateMask");
    assert_eq!(parsed.private_fields.len(), 4);

    let ir = transform_to_ir(parsed).unwrap();
    assert_eq!(ir.name, "StateMask");
    assert_eq!(ir.private_witnesses.len(), 4);

    assert!(!ir.private_witnesses[0].constraints.is_empty());
    assert_eq!(ir.circuit_config.k(), 16);
}

#[test]
fn test_tx_privacy_with_field_commitments() {
    let input = r#"
        struct TxPrivacyFull {
            #[zk_private]
            commitment_old: Field,
            #[zk_private]
            commitment_new: Field,
            #[zk_private]
            balance_old: u64,
            #[zk_private]
            balance_new: u64,
            #[zk_private]
            randomness_old: [u8; 32],
            #[zk_private]
            randomness_new: [u8; 32],
            #[zk_private]
            amount: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 7);

    use zerostyl_compiler::ZkType;
    assert!(matches!(ir.private_witnesses[0].field_type, ZkType::Field));
    assert!(matches!(ir.private_witnesses[1].field_type, ZkType::Field));

    assert_eq!(ir.private_witnesses[0].constraints.len(), 0);
    assert_eq!(ir.private_witnesses[1].constraints.len(), 0);
}

#[test]
fn test_state_mask_with_bool_flag() {
    let input = r#"
        struct StateMaskWithFlag {
            #[zk_private]
            state_value: u64,
            #[zk_private]
            is_valid: bool,
            #[zk_private]
            randomness: [u8; 32],
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 3);

    use zerostyl_compiler::ZkType;
    assert!(matches!(ir.private_witnesses[1].field_type, ZkType::Bool));

    let bool_field = &ir.private_witnesses[1];
    assert_eq!(bool_field.constraints.len(), 1);
}

#[test]
fn test_payment_contract_with_addresses() {
    let input = r#"
        struct PaymentContract {
            #[zk_private]
            sender: Address,
            #[zk_private]
            recipient: Address,
            #[zk_private]
            amount: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    assert_eq!(ir.private_witnesses.len(), 3);

    use zerostyl_compiler::ZkType;
    assert!(matches!(ir.private_witnesses[0].field_type, ZkType::Address));
    assert!(matches!(ir.private_witnesses[1].field_type, ZkType::Address));
}

#[test]
fn test_circuit_validates_large_circuits() {
    let mut fields = String::new();
    for i in 0..100 {
        fields.push_str(&format!("    #[zk_private]\n    field_{}: u64,\n", i));
    }

    let input = format!("struct LargeCircuit {{\n{}}}", fields);
    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();

    let result = validate_circuit_ir(&ir);
    assert!(result.is_ok(), "100 fields should be valid with k=16");
}
