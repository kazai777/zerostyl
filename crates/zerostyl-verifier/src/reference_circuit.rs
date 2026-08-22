//! Reference circuit for VK generation and verification testing.
//!
//! A minimal addition circuit used as the built-in verifiable circuit. Its verifying key is
//! generated and serialized at build time (see `build.rs`) and deserialized at runtime — halo2
//! 0.3.0 (PSE fork) supports VK serialization, so there is no `keygen_vk` on the verify path.
//! This exact circuit is duplicated in `build.rs`; a drift-guard test keeps the two in sync.
//!
//! Gate: `a + b = sum` where `sum` is a public input.

#[cfg(not(feature = "std"))]
use alloc::vec;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Circuit size parameter for the reference circuit.
pub const REFERENCE_K: u32 = 4;

/// Simple addition circuit: proves knowledge of `a` and `b` such that `a + b = sum`.
///
/// - `a` and `b` are private witnesses
/// - `sum` is a public input (instance column, row 0)
#[derive(Clone, Debug)]
pub struct ReferenceCircuit {
    pub a: Value<Fr>,
    pub b: Value<Fr>,
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

impl Circuit<Fr> for ReferenceCircuit {
    type Config = ReferenceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
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
        mut layouter: impl Layouter<Fr>,
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
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;

    #[test]
    fn test_reference_circuit_valid() {
        let circuit =
            ReferenceCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

        let public_inputs = vec![Fr::from(5)];
        let prover =
            MockProver::run(REFERENCE_K, &circuit, vec![public_inputs]).expect("MockProver failed");
        prover.verify().expect("Valid proof should verify");
    }

    #[test]
    fn test_reference_circuit_wrong_sum() {
        let circuit =
            ReferenceCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

        let wrong_inputs = vec![Fr::from(10)]; // 2 + 3 != 10
        let prover =
            MockProver::run(REFERENCE_K, &circuit, vec![wrong_inputs]).expect("MockProver failed");
        assert!(prover.verify().is_err(), "Wrong sum should be rejected");
    }

    #[test]
    fn test_reference_circuit_zero_values() {
        let circuit =
            ReferenceCircuit { a: Value::known(Fr::from(0)), b: Value::known(Fr::from(0)) };

        let public_inputs = vec![Fr::from(0)]; // 0 + 0 = 0
        let prover =
            MockProver::run(REFERENCE_K, &circuit, vec![public_inputs]).expect("MockProver failed");
        prover.verify().expect("Zero values should verify");
    }
}
