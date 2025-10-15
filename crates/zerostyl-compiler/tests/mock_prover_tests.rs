//! MockProver integration tests for circuit execution
//!
//! These tests verify that circuits can be properly configured and synthesized
//! using halo2's MockProver, covering the configure() and synthesize() paths.

use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::Circuit;
use halo2curves::pasta::Fp as TestField;
use zerostyl_compiler::{parse_contract, transform_to_ir, CircuitBuilder};

#[test]
fn test_mock_prover_empty_circuit() {
    let input = "struct Empty {}";

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
    let instances = vec![vec![]]; // One empty instance column
    let prover = MockProver::run(k, &circuit, instances).unwrap();

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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
    let prover_result = MockProver::run(k, &circuit, vec![vec![]]);
    if let Err(e) = &prover_result {
        eprintln!("MockProver::run failed: {:?}", e);
    }
    let prover = prover_result.unwrap();
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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 5; // Need more rows for multi-row layout
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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
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
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 7; // 2^7 = 128 rows
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_without_witnesses() {
    let input = r#"
        struct TestCircuit {
            #[zk_private] x: u64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let circuit_no_witnesses = circuit.without_witnesses();

    let k = 4;
    let prover = MockProver::run(k, &circuit_no_witnesses, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_mock_prover_all_integer_types() {
    let input = r#"
        struct AllIntegers {
            #[zk_private] v_u8: u8,
            #[zk_private] v_u16: u16,
            #[zk_private] v_u32: u32,
            #[zk_private] v_u64: u64,
            #[zk_private] v_u128: u128,
            #[zk_private] v_i64: i64,
        }
    "#;

    let parsed = parse_contract(input).unwrap();
    let ir = transform_to_ir(parsed).unwrap();
    let builder = CircuitBuilder::new(ir);
    let circuit = builder.build::<TestField>();

    let k = 4;
    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.verify().unwrap();
}
