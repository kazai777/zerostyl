//! Circuit generation for halo2-based zero-knowledge proofs
//!
//! This module transforms CircuitIR into halo2 circuits that can generate
//! and verify zk-SNARK proofs.
//!
//! # Examples
//!
//! ```rust
//! use zerostyl_compiler::{parse_contract, transform_to_ir, CircuitBuilder};
//! use halo2curves::pasta::Fp;
//!
//! let input = r#"
//!     struct MyCircuit {
//!         #[zk_private]
//!         secret_value: u64,
//!     }
//! "#;
//!
//! let parsed = parse_contract(input).unwrap();
//! let ir = transform_to_ir(parsed).unwrap();
//! let circuit = CircuitBuilder::new(ir).build::<Fp>();
//! ```

use crate::{CircuitIR, CompilerError, ZkType};
use halo2_proofs::{
    arithmetic::Field as Halo2Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error as Halo2Error, Instance},
};

pub struct CircuitBuilder {
    circuit_ir: CircuitIR,
}

impl CircuitBuilder {
    pub fn new(circuit_ir: CircuitIR) -> Self {
        Self { circuit_ir }
    }

    pub fn circuit_ir(&self) -> &CircuitIR {
        &self.circuit_ir
    }

    pub fn build<F: Halo2Field>(self) -> ZkCircuit<F> {
        if self.circuit_ir.private_witnesses.len() > ZkCircuit::<F>::MAX_SINGLE_ROW_WITNESSES {
            eprintln!(
                "Warning: Circuit '{}' has {} witnesses (max {} for single-row). \
                 Multi-row layout will be used, which may impact performance.",
                self.circuit_ir.name,
                self.circuit_ir.private_witnesses.len(),
                ZkCircuit::<F>::MAX_SINGLE_ROW_WITNESSES
            );
        }

        if self.circuit_ir.public_inputs.len() > ZkCircuit::<F>::MAX_PUBLIC_INPUTS {
            eprintln!(
                "Warning: Circuit '{}' has {} public inputs (recommended max {}). \
                 Consider reducing public inputs for better performance.",
                self.circuit_ir.name,
                self.circuit_ir.public_inputs.len(),
                ZkCircuit::<F>::MAX_PUBLIC_INPUTS
            );
        }

        ZkCircuit { ir: self.circuit_ir, _marker: std::marker::PhantomData }
    }
}

#[derive(Clone, Debug)]
pub struct ZkCircuitConfig {
    advice: Vec<Column<Advice>>,
    instance: Column<Instance>,
}

pub struct ZkCircuit<F: Halo2Field> {
    pub ir: CircuitIR,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Halo2Field> ZkCircuit<F> {
    pub const MAX_SINGLE_ROW_WITNESSES: usize = 10;
    pub const MAX_PUBLIC_INPUTS: usize = 5;
}

impl<F: Halo2Field> Circuit<F> for ZkCircuit<F> {
    type Config = ZkCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { ir: self.ir.clone(), _marker: std::marker::PhantomData }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        const MAX_ADVICE_COLUMNS: usize = 10;

        let advice: Vec<Column<Advice>> = (0..MAX_ADVICE_COLUMNS)
            .map(|_| {
                let col = meta.advice_column();
                meta.enable_equality(col);
                col
            })
            .collect();

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        ZkCircuitConfig { advice, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Halo2Error> {
        layouter.assign_region(
            || "public inputs",
            |mut region| {
                for (idx, public_input) in self.ir.public_inputs.iter().enumerate() {
                    let column_idx = idx % config.advice.len();
                    let row = idx / config.advice.len();

                    region.assign_advice_from_instance(
                        || format!("public {}", public_input.name),
                        config.instance,
                        idx,
                        config.advice[column_idx],
                        row,
                    )?;
                }
                Ok(())
            },
        )?;

        layouter.assign_region(
            || "private witnesses",
            |mut region| {
                for (idx, witness) in self.ir.private_witnesses.iter().enumerate() {
                    let column_idx = idx % config.advice.len();
                    let row = idx / config.advice.len();

                    let _cell: AssignedCell<F, F> = region.assign_advice(
                        || format!("witness {}", witness.name),
                        config.advice[column_idx],
                        row,
                        || Value::unknown(),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

pub fn validate_circuit_ir(ir: &CircuitIR) -> Result<(), CompilerError> {
    let max_rows = 1 << ir.circuit_config.k();
    let required_rows = estimate_required_rows(ir);

    if required_rows > max_rows {
        return Err(CompilerError::Other(format!(
            "Circuit requires {} rows but k={} only provides {} rows",
            required_rows,
            ir.circuit_config.k(),
            max_rows
        )));
    }

    for field in ir.private_witnesses.iter().chain(&ir.public_inputs) {
        validate_zk_type(&field.field_type)?;
    }

    Ok(())
}

fn estimate_required_rows(ir: &CircuitIR) -> usize {
    let witness_rows = ir.private_witnesses.len();
    let public_rows = ir.public_inputs.len();
    let constraint_rows: usize = ir.private_witnesses.iter().map(|w| w.constraints.len()).sum();

    (witness_rows + public_rows + constraint_rows) * 2
}

fn validate_zk_type(zk_type: &ZkType) -> Result<(), CompilerError> {
    match zk_type {
        ZkType::Field => Ok(()),
        ZkType::U8 | ZkType::U16 | ZkType::U32 | ZkType::U64 | ZkType::U128 => Ok(()),
        ZkType::I64 => Ok(()),
        ZkType::Bool => Ok(()),
        ZkType::Address => Ok(()),
        ZkType::Bytes32 => Ok(()),
        ZkType::Array { element_type: _, size } => {
            if *size > 1024 {
                Err(CompilerError::UnsupportedZkType(format!(
                    "Array size {} exceeds maximum 1024",
                    size
                )))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_contract, transform_to_ir};

    #[test]
    fn test_circuit_builder_creation() {
        let input = r#"
            struct TestCircuit {
                #[zk_private]
                value: u64,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();
        let builder = CircuitBuilder::new(ir);

        assert_eq!(builder.circuit_ir().name, "TestCircuit");
        assert_eq!(builder.circuit_ir().private_witnesses.len(), 1);
    }

    #[test]
    fn test_validate_circuit_ir_success() {
        let input = r#"
            struct ValidCircuit {
                #[zk_private]
                balance: u64,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();

        assert!(validate_circuit_ir(&ir).is_ok());
    }

    #[test]
    fn test_validate_circuit_ir_large_array() {
        let input = r#"
            struct LargeArray {
                #[zk_private]
                data: [u8; 2000],
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        // transform_to_ir already rejects arrays > 32 elements
        let result = transform_to_ir(parsed);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Array"));
    }

    #[test]
    fn test_estimate_required_rows() {
        let input = r#"
            struct MultiField {
                #[zk_private]
                field1: u64,
                #[zk_private]
                field2: u64,
                #[zk_private]
                field3: bool,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();

        let rows = estimate_required_rows(&ir);
        // 3 witnesses + constraints + padding
        assert!(rows >= 6); // 3 witnesses * 2 (padding factor)
    }
}
