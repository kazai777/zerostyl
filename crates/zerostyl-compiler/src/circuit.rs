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

use crate::ast::ComparisonOp;
use crate::gadgets::{ComparisonChip, ComparisonConfig, RangeProofChip, RangeProofConfig};
use crate::{CircuitIR, CompilerError, Constraint, ZkType};
use halo2_proofs::{
    arithmetic::Field as Halo2Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
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
    range_config: RangeProofConfig,
    comparison_config: ComparisonConfig,
}

#[derive(Clone, Debug)]
pub struct ZkCircuit<F: Halo2Field> {
    pub ir: CircuitIR,
    /// Private witness values for the circuit
    /// Each `Value<F>` corresponds to a private witness field in ir.private_witnesses
    /// Uses `Value::unknown()` during key generation, `Value::known()` during proving
    pub witness_values: Vec<Value<F>>,
    /// Public input values for the circuit
    /// Each `Value<F>` corresponds to a public input field in ir.public_inputs
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

impl Circuit<Fp> for ZkCircuit<Fp> {
    type Config = ZkCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            ir: self.ir.clone(),
            witness_values: vec![Value::unknown(); self.ir.private_witnesses.len()],
            public_values: vec![Value::unknown(); self.ir.public_inputs.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Configure gadgets — each allocates its own columns and gates
        let range_config = RangeProofChip::configure(meta);
        let comparison_config = ComparisonChip::configure(meta);

        // General-purpose advice columns for unconstrained witnesses
        let advice: Vec<Column<Advice>> = (0..2)
            .map(|_| {
                let col = meta.advice_column();
                meta.enable_equality(col);
                col
            })
            .collect();

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        ZkCircuitConfig { advice, instance, range_config, comparison_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Halo2Error> {
        let range_chip = RangeProofChip::construct(config.range_config.clone());
        let comparison_chip = ComparisonChip::construct(config.comparison_config.clone());

        let mut unconstrained: Vec<(usize, Value<Fp>)> = Vec::new();

        for (idx, (field, &wv)) in
            self.ir.private_witnesses.iter().zip(self.witness_values.iter()).enumerate()
        {
            let mut field_constrained = false;

            for constraint in &field.constraints {
                match constraint {
                    Constraint::Range { num_bits } => {
                        let cell = range_chip
                            .load_value(layouter.namespace(|| format!("load_w{}", idx)), wv)?;
                        range_chip.check_range(
                            layouter.namespace(|| format!("range_{}", idx)),
                            cell,
                            *num_bits,
                        )?;
                        field_constrained = true;
                    }
                    Constraint::Boolean => {
                        let cell = range_chip
                            .load_value(layouter.namespace(|| format!("load_bool_{}", idx)), wv)?;
                        range_chip.check_range(
                            layouter.namespace(|| format!("bool_{}", idx)),
                            cell,
                            1,
                        )?;
                        field_constrained = true;
                    }
                    Constraint::RangeProof { min, max } => {
                        // The generic circuit builder only supports bounded range
                        // checks where min and max fit in u64. For u128 values,
                        // the proc-macro handles them via DualRange decomposition.
                        if *min > u64::MAX as u128 || *max > u64::MAX as u128 {
                            return Err(Halo2Error::Synthesis);
                        }
                        let min_fp = Fp::from(*min as u64);
                        let max_fp = Fp::from(*max as u64);
                        let cell = range_chip
                            .load_value(layouter.namespace(|| format!("load_rp_{}", idx)), wv)?;
                        range_chip.check_range_bounded(
                            layouter.namespace(|| format!("rangeproof_{}", idx)),
                            cell,
                            min_fp,
                            max_fp,
                            64,
                        )?;
                        field_constrained = true;
                    }
                    Constraint::Comparison { operator, value } => {
                        let witness_cell = comparison_chip
                            .load_value(layouter.namespace(|| format!("load_cmp_{}", idx)), wv)?;
                        let threshold = Value::known(Fp::from(*value));
                        let threshold_cell = comparison_chip.load_value(
                            layouter.namespace(|| format!("load_cmp_thr_{}", idx)),
                            threshold,
                        )?;
                        match operator {
                            ComparisonOp::GreaterThan => {
                                comparison_chip.assert_gt(
                                    layouter.namespace(|| format!("cmp_gt_{}", idx)),
                                    witness_cell,
                                    threshold_cell,
                                    64,
                                )?;
                            }
                            ComparisonOp::GreaterThanOrEqual => {
                                comparison_chip.assert_gte(
                                    layouter.namespace(|| format!("cmp_gte_{}", idx)),
                                    witness_cell,
                                    threshold_cell,
                                    64,
                                )?;
                            }
                            ComparisonOp::LessThan => {
                                comparison_chip.assert_lt(
                                    layouter.namespace(|| format!("cmp_lt_{}", idx)),
                                    witness_cell,
                                    threshold_cell,
                                    64,
                                )?;
                            }
                            ComparisonOp::LessThanOrEqual => {
                                comparison_chip.assert_lte(
                                    layouter.namespace(|| format!("cmp_lte_{}", idx)),
                                    witness_cell,
                                    threshold_cell,
                                    64,
                                )?;
                            }
                            ComparisonOp::Equal | ComparisonOp::NotEqual => {
                                // Equal/NotEqual comparisons are not supported in the generic
                                // circuit builder. Return a synthesis error rather than silently
                                // marking the field as constrained without any actual constraint.
                                return Err(Halo2Error::Synthesis);
                            }
                        }
                        field_constrained = true;
                    }
                    Constraint::Commitment { .. }
                    | Constraint::ArithmeticRelation { .. }
                    | Constraint::MerkleProof { .. } => {
                        // These are cross-field constraints that require hand-written circuits
                        // (tx_privacy, private_vote, state_mask) using gadgets directly.
                        // The generic builder cannot generate these constraints, so the field
                        // is left unconstrained (assigned to general advice columns with a
                        // warning). Do NOT mark field_constrained = true here.
                    }
                }
            }

            if !field_constrained {
                unconstrained.push((idx, wv));
            }
        }

        // Assign unconstrained witnesses to general advice columns
        if !unconstrained.is_empty() {
            layouter.assign_region(
                || "unconstrained_witnesses",
                |mut region| {
                    for (i, (idx, value)) in unconstrained.iter().enumerate() {
                        let col = i % config.advice.len();
                        let row = i / config.advice.len();
                        region.assign_advice(
                            || format!("witness_{}", idx),
                            config.advice[col],
                            row,
                            || *value,
                        )?;
                    }
                    Ok(())
                },
            )?;
        }

        // Assign public inputs from the instance column into advice cells.
        // NOTE: In the generic builder, these public inputs are accessible but
        // not linked to any private witness via constraints. The generic builder
        // cannot infer cross-field relationships (e.g. commitment == Poseidon(witness)).
        // Hand-written circuits (tx_privacy, state_mask, private_vote) handle this
        // explicitly using constrain_instance() after computing derived values.
        if !self.public_values.is_empty() {
            layouter.assign_region(
                || "public_inputs",
                |mut region| {
                    for (idx, _) in self.public_values.iter().enumerate() {
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
    ir.estimate_rows()
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