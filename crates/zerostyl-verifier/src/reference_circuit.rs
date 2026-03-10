//! Reference circuit for VK generation and verification testing
//!
//! This module defines a simple addition circuit used as the default
//! circuit for VK generation in halo2_proofs v0.3.2, which lacks
//! VK serialization. The VK is regenerated at runtime via `keygen_vk`.
//!
//! Gate: `a + b = sum` where `sum` is a public input.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

/// Circuit size parameter for the reference circuit.
pub const REFERENCE_K: u32 = 4;

/// Simple addition circuit: proves knowledge of `a` and `b` such that `a + b = sum`.
///
/// - `a` and `b` are private witnesses
/// - `sum` is a public input (instance column, row 0)
#[derive(Clone, Debug)]
pub struct ReferenceCircuit {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl Default for ReferenceCircuit {
    fn default() -> Self {
        Self { a: Value::unknown(), b: Value::unknown() }
    }
}

#[derive(Clone, Debug)]
pub struct ReferenceConfig {
    advice: Column<Advice>,
    #[allow(dead_code)]
    instance: Column<Instance>,
    selector: Selector,
}

impl Circuit<Fp> for ReferenceCircuit {
    type Config = ReferenceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(advice);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());
            let sum = meta.query_instance(instance, Rotation::cur());

            vec![s * (a + b - sum)]
        });

        ReferenceConfig { advice, instance, selector }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "add",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.advice, 0, || self.a)?;
                region.assign_advice(|| "b", config.advice, 1, || self.b)?;
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp};

    #[test]
    fn test_reference_circuit_valid() {
        let circuit =
            ReferenceCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let public_inputs = vec![Fp::from(5)];
        let prover =
            MockProver::run(REFERENCE_K, &circuit, vec![public_inputs]).expect("MockProver failed");
        prover.verify().expect("Valid proof should verify");
    }

    #[test]
    fn test_reference_circuit_wrong_sum() {
        let circuit =
            ReferenceCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let wrong_inputs = vec![Fp::from(10)]; // 2 + 3 != 10
        let prover =
            MockProver::run(REFERENCE_K, &circuit, vec![wrong_inputs]).expect("MockProver failed");
        assert!(prover.verify().is_err(), "Wrong sum should be rejected");
    }

    #[test]
    fn test_reference_circuit_zero_values() {
        let circuit =
            ReferenceCircuit { a: Value::known(Fp::from(0)), b: Value::known(Fp::from(0)) };

        let public_inputs = vec![Fp::from(0)]; // 0 + 0 = 0
        let prover =
            MockProver::run(REFERENCE_K, &circuit, vec![public_inputs]).expect("MockProver failed");
        prover.verify().expect("Zero values should verify");
    }
}
