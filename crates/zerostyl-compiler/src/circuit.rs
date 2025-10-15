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
    circuit::{Layouter, SimpleFloorPlanner, Value},
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

        // Initialize with zero values - use with_witnesses() to set actual values
        let witness_values = vec![Value::known(F::ZERO); self.circuit_ir.private_witnesses.len()];
        let public_values = vec![Value::known(F::ZERO); self.circuit_ir.public_inputs.len()];

        ZkCircuit { ir: self.circuit_ir, witness_values, public_values }
    }
}

#[derive(Clone, Debug)]
pub struct ZkCircuitConfig {
    advice: Vec<Column<Advice>>,
    instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct ZkCircuit<F: Halo2Field> {
    pub ir: CircuitIR,
    /// Private witness values for the circuit
    /// Each Value<F> corresponds to a private witness field in ir.private_witnesses
    /// Uses Value::unknown() during key generation, Value::known() during proving
    pub witness_values: Vec<Value<F>>,
    /// Public input values for the circuit
    /// Each Value<F> corresponds to a public input field in ir.public_inputs
    pub public_values: Vec<Value<F>>,
}

impl<F: Halo2Field> ZkCircuit<F> {
    pub const MAX_SINGLE_ROW_WITNESSES: usize = 10;
    pub const MAX_PUBLIC_INPUTS: usize = 5;

    /// Set witness values for proof generation
    ///
    /// # Arguments
    /// * `witnesses` - Field elements corresponding to private witness fields
    ///
    /// # Returns
    /// Self with updated witness values
    ///
    /// # Examples
    /// ```
    /// use zerostyl_compiler::{parse_contract, transform_to_ir, CircuitBuilder};
    /// use halo2curves::pasta::Fp;
    ///
    /// let input = r#"
    ///     struct MyCircuit {
    ///         #[zk_private]
    ///         secret: u64,
    ///     }
    /// "#;
    ///
    /// let parsed = parse_contract(input).unwrap();
    /// let ir = transform_to_ir(parsed).unwrap();
    /// let circuit = CircuitBuilder::new(ir)
    ///     .build::<Fp>()
    ///     .with_witnesses(vec![Fp::from(42)]);
    /// ```
    pub fn with_witnesses(mut self, witnesses: Vec<F>) -> Result<Self, CompilerError> {
        if witnesses.len() != self.ir.private_witnesses.len() {
            return Err(CompilerError::Other(format!(
                "Expected {} witnesses but got {}",
                self.ir.private_witnesses.len(),
                witnesses.len()
            )));
        }
        self.witness_values = witnesses.into_iter().map(Value::known).collect();
        Ok(self)
    }

    /// Set public input values for proof generation
    ///
    /// # Arguments
    /// * `public_inputs` - Field elements corresponding to public input fields
    ///
    /// # Returns
    /// Self with updated public input values
    pub fn with_public_inputs(mut self, public_inputs: Vec<F>) -> Result<Self, CompilerError> {
        if public_inputs.len() != self.ir.public_inputs.len() {
            return Err(CompilerError::Other(format!(
                "Expected {} public inputs but got {}",
                self.ir.public_inputs.len(),
                public_inputs.len()
            )));
        }
        self.public_values = public_inputs.into_iter().map(Value::known).collect();
        Ok(self)
    }

    /// Get the number of expected witnesses
    pub fn num_witnesses(&self) -> usize {
        self.ir.private_witnesses.len()
    }

    /// Get the number of expected public inputs
    pub fn num_public_inputs(&self) -> usize {
        self.ir.public_inputs.len()
    }
}

impl<F: Halo2Field> Circuit<F> for ZkCircuit<F> {
    type Config = ZkCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // Returns a copy with zero witness values for circuit structure testing
        Self {
            ir: self.ir.clone(),
            witness_values: vec![Value::known(F::ZERO); self.ir.private_witnesses.len()],
            public_values: vec![Value::known(F::ZERO); self.ir.public_inputs.len()],
        }
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
        // Assign private witness values to advice columns
        if !self.witness_values.is_empty() {
            let witness_values = self.witness_values.clone();
            layouter.assign_region(
                || "witness_region",
                |mut region| {
                    for (idx, &value) in witness_values.iter().enumerate() {
                        let column_idx = idx % config.advice.len();
                        let row = idx / config.advice.len();

                        region.assign_advice(
                            || format!("witness_{}", idx),
                            config.advice[column_idx],
                            row,
                            || value,
                        )?;
                    }
                    Ok(())
                },
            )?;
        }

        // Assign public input values from instance column to advice columns
        if !self.public_values.is_empty() {
            let public_values = self.public_values.clone();
            layouter.assign_region(
                || "public_input_region",
                |mut region| {
                    for (idx, _value) in public_values.iter().enumerate() {
                        region.assign_advice_from_instance(
                            || format!("public_{}", idx),
                            config.instance,
                            idx,
                            config.advice[0],
                            idx,
                        )?;
                    }
                    Ok(())
                },
            )?;
        }

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

    #[test]
    fn test_with_witnesses() {
        use halo2curves::pasta::Fp;

        let input = r#"
            struct TestCircuit {
                #[zk_private]
                value1: u64,
                #[zk_private]
                value2: u64,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();
        let circuit = CircuitBuilder::new(ir)
            .build::<Fp>()
            .with_witnesses(vec![Fp::from(42), Fp::from(100)])
            .unwrap();

        assert_eq!(circuit.witness_values.len(), 2);
    }

    #[test]
    fn test_with_witnesses_wrong_count() {
        use halo2curves::pasta::Fp;

        let input = r#"
            struct TestCircuit {
                #[zk_private]
                value: u64,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();
        let result =
            CircuitBuilder::new(ir).build::<Fp>().with_witnesses(vec![Fp::from(42), Fp::from(100)]);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected 1 witnesses but got 2"));
    }

    #[test]
    fn test_with_public_inputs_empty() {
        use halo2curves::pasta::Fp;

        let input = r#"
            struct TestCircuit {
                #[zk_private]
                secret: u64,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();

        // Currently our parser doesn't create public inputs
        assert_eq!(ir.public_inputs.len(), 0);

        let circuit = CircuitBuilder::new(ir).build::<Fp>();
        assert_eq!(circuit.num_public_inputs(), 0);
    }

    #[test]
    fn test_num_witnesses_and_public_inputs() {
        use halo2curves::pasta::Fp;

        let input = r#"
            struct TestCircuit {
                #[zk_private]
                w1: u64,
                #[zk_private]
                w2: u64,
            }
        "#;

        let parsed = parse_contract(input).unwrap();
        let ir = transform_to_ir(parsed).unwrap();
        let circuit = CircuitBuilder::new(ir).build::<Fp>();

        assert_eq!(circuit.num_witnesses(), 2);
        assert_eq!(circuit.num_public_inputs(), 0);
    }
}
