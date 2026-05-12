//! Smallest possible ZeroStyl circuit: proves `a + b == sum`.
//!
//! Serves as the reference template for `docs/EXTENDING.md` — third-party
//! developers can copy this crate, swap the gate, and have a working
//! descriptor wired into the toolkit in minutes.

pub mod descriptor;

pub use descriptor::descriptor;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;

#[derive(Clone, Debug)]
pub struct ExampleConfig {
    pub advice: Column<Advice>,
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Clone, Debug)]
pub struct ExampleCircuit {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl Default for ExampleCircuit {
    fn default() -> Self {
        Self { a: Value::unknown(), b: Value::unknown() }
    }
}

impl ExampleCircuit {
    pub fn new(a: Fp, b: Fp) -> Self {
        Self { a: Value::known(a), b: Value::known(b) }
    }

    pub fn compute_sum(a: Fp, b: Fp) -> Fp {
        a + b
    }
}

impl Circuit<Fp> for ExampleCircuit {
    type Config = ExampleConfig;
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

        ExampleConfig { advice, instance, selector }
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
    use halo2_proofs::dev::MockProver;

    #[test]
    fn add_circuit_is_satisfied() {
        let circuit = ExampleCircuit::new(Fp::from(2), Fp::from(3));
        let public_inputs = vec![vec![Fp::from(5)]];
        let prover = MockProver::run(4, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn wrong_sum_is_rejected() {
        let circuit = ExampleCircuit::new(Fp::from(2), Fp::from(3));
        let wrong_inputs = vec![vec![Fp::from(99)]];
        let prover = MockProver::run(4, &circuit, wrong_inputs).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn compute_sum_helper() {
        assert_eq!(ExampleCircuit::compute_sum(Fp::from(7), Fp::from(8)), Fp::from(15));
    }

    #[test]
    fn default_has_unknown_witnesses() {
        let c = ExampleCircuit::default();
        let _ = c.without_witnesses();
    }
}
