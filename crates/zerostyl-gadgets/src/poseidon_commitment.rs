//! Poseidon commitment chip: `commitment = Poseidon(value, randomness)`.
//!
//! Uses the P128Pow5T3 specification (128-bit security, width=3, rate=2)
//! with `ConstantLength<2>` domain separation, over the BN254 scalar field
//! (`halo2curves::bn256::Fr`) and the Poseidon constants vendored from
//! Scroll's audited Poseidon implementation.

use halo2_poseidon::ConstantLength;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};
use halo2curves::bn256::Fr;

use super::poseidon_chip::{Hash, Pow5Chip, Pow5Config};
use super::poseidon_native::{self, Bn254P128Pow5T3};

#[derive(Debug, Clone)]
pub struct PoseidonCommitmentConfig {
    pow5_config: Pow5Config<Fr, 3, 2>,
    state: [Column<Advice>; 3],
}

impl PoseidonCommitmentConfig {
    #[must_use]
    pub fn state_columns(&self) -> &[Column<Advice>; 3] {
        &self.state
    }

    #[must_use]
    pub fn pow5_config(&self) -> &Pow5Config<Fr, 3, 2> {
        &self.pow5_config
    }
}

pub struct PoseidonCommitmentChip {
    config: PoseidonCommitmentConfig,
}

impl PoseidonCommitmentChip {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> PoseidonCommitmentConfig {
        let state: [Column<Advice>; 3] =
            [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();

        let rc_a: [Column<Fixed>; 3] =
            [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b: [Column<Fixed>; 3] =
            [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];

        meta.enable_constant(rc_b[0]);

        let pow5_config =
            Pow5Chip::configure::<Bn254P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        PoseidonCommitmentConfig { pow5_config, state }
    }

    #[must_use]
    pub fn construct(config: PoseidonCommitmentConfig) -> Self {
        Self { config }
    }

    pub fn commit(
        &self,
        mut layouter: impl Layouter<Fr>,
        value: AssignedCell<Fr, Fr>,
        randomness: AssignedCell<Fr, Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let chip = Pow5Chip::construct(self.config.pow5_config.clone());

        let hasher = Hash::<_, _, Bn254P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon_init"),
        )?;

        hasher.hash(layouter.namespace(|| "poseidon_hash"), [value, randomness])
    }

    pub fn hash_two(
        &self,
        mut layouter: impl Layouter<Fr>,
        left: AssignedCell<Fr, Fr>,
        right: AssignedCell<Fr, Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let chip = Pow5Chip::construct(self.config.pow5_config.clone());

        let hasher = Hash::<_, _, Bn254P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon_init"),
        )?;

        hasher.hash(layouter.namespace(|| "poseidon_hash"), [left, right])
    }

    pub fn load_private(
        &self,
        mut layouter: impl Layouter<Fr>,
        value: Value<Fr>,
        column_idx: usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        if column_idx >= 3 {
            return Err(Error::Synthesis);
        }

        layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(|| "private input", self.config.state[column_idx], 0, || value)
            },
        )
    }

    #[must_use]
    pub fn config(&self) -> &PoseidonCommitmentConfig {
        &self.config
    }

    #[must_use]
    pub fn hash_outside_circuit(value: Fr, randomness: Fr) -> Fr {
        poseidon_native::hash(value, randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, Instance},
    };
    use halo2curves::group::ff::Field;

    #[derive(Clone)]
    struct CommitmentTestCircuit {
        value: Value<Fr>,
        randomness: Value<Fr>,
    }

    #[derive(Debug, Clone)]
    struct CommitmentTestConfig {
        poseidon: PoseidonCommitmentConfig,
        instance: Column<Instance>,
    }

    impl Circuit<Fr> for CommitmentTestCircuit {
        type Config = CommitmentTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { value: Value::unknown(), randomness: Value::unknown() }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> CommitmentTestConfig {
            let poseidon = PoseidonCommitmentChip::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);

            CommitmentTestConfig { poseidon, instance }
        }

        fn synthesize(
            &self,
            config: CommitmentTestConfig,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = PoseidonCommitmentChip::construct(config.poseidon);

            let value_cell =
                chip.load_private(layouter.namespace(|| "load value"), self.value, 0)?;
            let randomness_cell =
                chip.load_private(layouter.namespace(|| "load randomness"), self.randomness, 1)?;

            let commitment =
                chip.commit(layouter.namespace(|| "commitment"), value_cell, randomness_cell)?;

            layouter.constrain_instance(commitment.cell(), config.instance, 0)?;

            Ok(())
        }
    }

    #[test]
    fn poseidon_commitment_valid() {
        let value = Fr::from(100u64);
        let randomness = Fr::from(42u64);
        let expected = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);

        let circuit = CommitmentTestCircuit {
            value: Value::known(value),
            randomness: Value::known(randomness),
        };

        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn poseidon_commitment_wrong_hash_rejected() {
        let value = Fr::from(100u64);
        let randomness = Fr::from(42u64);
        let wrong_expected = Fr::from(999u64);

        let circuit = CommitmentTestCircuit {
            value: Value::known(value),
            randomness: Value::known(randomness),
        };

        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![vec![wrong_expected]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn poseidon_commitment_different_randomness_different_hash() {
        let value = Fr::from(100u64);
        let r1 = Fr::from(1u64);
        let r2 = Fr::from(2u64);

        let h1 = PoseidonCommitmentChip::hash_outside_circuit(value, r1);
        let h2 = PoseidonCommitmentChip::hash_outside_circuit(value, r2);

        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon_commitment_deterministic() {
        let value = Fr::from(42u64);
        let randomness = Fr::from(7u64);

        let h1 = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);
        let h2 = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);

        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon_commitment_zero_values() {
        let value = Fr::ZERO;
        let randomness = Fr::ZERO;
        let expected = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);

        let circuit = CommitmentTestCircuit {
            value: Value::known(value),
            randomness: Value::known(randomness),
        };

        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn poseidon_commitment_large_values() {
        let value = Fr::from(u64::MAX);
        let randomness = Fr::from(u64::MAX - 1);
        let expected = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);

        let circuit = CommitmentTestCircuit {
            value: Value::known(value),
            randomness: Value::known(randomness),
        };

        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn load_private_invalid_column_returns_error() {
        #[derive(Clone)]
        struct BadColumnCircuit;

        impl Circuit<Fr> for BadColumnCircuit {
            type Config = CommitmentTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> CommitmentTestConfig {
                let poseidon = PoseidonCommitmentChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                CommitmentTestConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: CommitmentTestConfig,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                let chip = PoseidonCommitmentChip::construct(config.poseidon);
                chip.load_private(layouter.namespace(|| "bad column"), Value::known(Fr::ONE), 3)?;
                Ok(())
            }
        }

        let result = MockProver::run(7, &BadColumnCircuit, vec![vec![]]);
        assert!(result.is_err());
    }

    #[test]
    fn in_circuit_hash_matches_native() {
        let a = Fr::from(10u64);
        let b = Fr::from(20u64);
        let expected = poseidon_native::hash(a, b);

        let circuit = CommitmentTestCircuit { value: Value::known(a), randomness: Value::known(b) };

        let prover = MockProver::run(7, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }
}
