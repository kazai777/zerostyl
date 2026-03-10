//! MockProver integration tests for circuit execution
//!
//! These tests verify that circuits can be properly configured and synthesized
//! using halo2's MockProver, covering the configure() and synthesize() paths.
//! With real gadget-backed constraints, invalid witnesses are rejected.

use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{keygen_vk, Circuit};
use halo2_proofs::poly::commitment::Params;
use halo2curves::pasta::{EqAffine, Fp as TestField};
use zerostyl_compiler::{parse_contract, transform_to_ir, CircuitBuilder};

#[test]
fn test_mock_prover_empty_circuit() {
    let input = "struct Empty {}";

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_single_witness() {
    let input = r#"
        struct SingleWitness {
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_multiple_witnesses() {
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
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_max_single_row_witnesses() {
    let input = format!(
        "struct MaxSingleRow {{ {} }}",
        (1..=10).map(|i| format!("#[zk_private] f{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_multi_row_layout() {
    let input = format!(
        "struct MultiRow {{ {} }}",
        (1..=15).map(|i| format!("#[zk_private] w{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_mixed_types() {
    let input = r#"
        struct MixedTypes {
            #[zk_private] val_u64: u64,
            #[zk_private] val_bool: bool,
            #[zk_private] val_address: Address,
            #[zk_private] val_field: Field,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_with_array() {
    let input = r#"
        struct WithArray {
            #[zk_private]
            data: [u8; 32],
            #[zk_private]
            value: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_large_circuit() {
    let input = format!(
        "struct LargeCircuit {{ {} }}",
        (1..=50).map(|i| format!("#[zk_private] f{}: u64", i)).collect::<Vec<_>>().join(", ")
    );

    let parsed = parse_contract(&input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_without_witnesses_works_for_keygen() {
    let input = r#"
        struct TestCircuit {
            #[zk_private] x: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let circuit_no_witnesses = circuit.without_witnesses();

    // without_witnesses() is used by keygen_vk to extract the circuit structure.
    // It must produce Value::unknown() witnesses (not Value::known(ZERO)),
    // so that keygen succeeds regardless of constraint bounds.
    let k = circuit_no_witnesses.ir.circuit_config.k();
    let params = Params::<EqAffine>::new(k);
    let vk = keygen_vk(&params, &circuit_no_witnesses);
    assert!(vk.is_ok(), "keygen_vk must succeed with without_witnesses()");
}

#[test]
fn test_mock_prover_all_supported_integer_types() {
    // The generic circuit builder supports u8, u16, u32, u64 range checks.
    // u128 requires the proc-macro DualRange path (not the generic builder).
    let input = r#"
        struct SupportedIntegers {
            #[zk_private] v_u8: u8,
            #[zk_private] v_u16: u16,
            #[zk_private] v_u32: u32,
            #[zk_private] v_u64: u64,
            #[zk_private] v_i64: i64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_circuit_rejects_u128_range_in_builder() {
    // The generic builder cannot handle u128 RangeProof (bounds exceed u64).
    // It must return Err(Synthesis), not silently truncate.
    // u128 is handled correctly by the proc-macro via DualRange decomposition.
    let input = r#"
        struct U128Circuit {
            #[zk_private] v_u128: u128,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let circuit = CircuitBuilder::new(ir).build::<TestField>();

    let k = circuit.ir.circuit_config.k();
    let result = MockProver::run(k, &circuit, vec![vec![]]);
    assert!(
        result.is_err(),
        "Generic builder must reject u128 RangeProof (use proc-macro DualRange instead)"
    );
}

// ============================================================================
// CONSTRAINT REJECTION TESTS — MockProver rejects invalid witnesses
// ============================================================================

#[test]
fn test_mock_prover_range_rejects_overflow() {
    let input = r#"
        struct RangeTest {
            #[zk_private]
            value: u8,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let k = ir.circuit_config.k();
    let circuit = CircuitBuilder::new(ir)
        .build::<TestField>()
        .with_witnesses(vec![TestField::from(256u64)])
        .unwrap();

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    assert!(prover.verify().is_err(), "Value 256 should be rejected for u8 range");
}

#[test]
fn test_mock_prover_boolean_rejects_non_boolean() {
    let input = r#"
        struct BoolTest {
            #[zk_private]
            flag: bool,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let k = ir.circuit_config.k();
    let circuit = CircuitBuilder::new(ir)
        .build::<TestField>()
        .with_witnesses(vec![TestField::from(2u64)])
        .unwrap();

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    assert!(prover.verify().is_err(), "Value 2 should be rejected for boolean constraint");
}

#[test]
fn test_mock_prover_range_accepts_valid_u8() {
    let input = r#"
        struct RangeTest {
            #[zk_private]
            value: u8,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let k = ir.circuit_config.k();
    let circuit = CircuitBuilder::new(ir)
        .build::<TestField>()
        .with_witnesses(vec![TestField::from(255u64)])
        .unwrap();

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_range_accepts_valid_u64() {
    let input = r#"
        struct RangeTest {
            #[zk_private]
            amount: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let k = ir.circuit_config.k();
    let circuit = CircuitBuilder::new(ir)
        .build::<TestField>()
        .with_witnesses(vec![TestField::from(1_000_000_000_000u64)])
        .unwrap();

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_boolean_accepts_zero() {
    let input = r#"
        struct BoolTest {
            #[zk_private]
            flag: bool,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let k = ir.circuit_config.k();
    let circuit = CircuitBuilder::new(ir)
        .build::<TestField>()
        .with_witnesses(vec![TestField::from(0u64)])
        .unwrap();

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_boolean_accepts_one() {
    let input = r#"
        struct BoolTest {
            #[zk_private]
            flag: bool,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let k = ir.circuit_config.k();
    let circuit = CircuitBuilder::new(ir)
        .build::<TestField>()
        .with_witnesses(vec![TestField::from(1u64)])
        .unwrap();

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}