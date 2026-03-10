//! Poseidon commitment chip for halo2 circuits.
//!
//! Implements `commitment = Poseidon(value, randomness)` using the P128Pow5T3 specification
//! from `halo2_gadgets`. This is the standard approach used by Zcash Orchard, Semaphore,
//! and Tornado Cash Nova for privacy-preserving commitments in ZK circuits.
//!
//! # Column requirements
//!
//! The Poseidon P128Pow5T3 chip requires:
//! - 4 advice columns (3 state + 1 partial S-box)
//! - 6 fixed columns (3 rc_a + 3 rc_b for round constants)
//! - 3 selectors (full round, partial round, pad-and-add)
//!
//! # Example
//!
//! ```
//! use halo2_proofs::pasta::Fp;
//! use zerostyl_compiler::gadgets::PoseidonCommitmentChip;
//!
//! // Compute a commitment outside the circuit (for witness generation)
//! let value = Fp::from(100u64);
//! let randomness = Fp::from(42u64);
//! let commitment = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);
//! ```

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};

/// Configuration for the Poseidon commitment chip.
///
/// Stores the underlying Pow5 config and the advice column references
/// needed for loading private inputs.
#[derive(Debug, Clone)]
pub struct PoseidonCommitmentConfig {
    pow5_config: Pow5Config<Fp, 3, 2>,
    state: [Column<Advice>; 3],
}

impl PoseidonCommitmentConfig {
    /// Returns the advice columns used by the Poseidon state.
    ///
    /// These columns can be reused for loading private inputs when
    /// no Poseidon computation is active on the same rows.
    #[must_use]
    pub fn state_columns(&self) -> &[Column<Advice>; 3] {
        &self.state
    }

    /// Returns a reference to the underlying Pow5 config.
    #[must_use]
    pub fn pow5_config(&self) -> &Pow5Config<Fp, 3, 2> {
        &self.pow5_config
    }
}

/// Poseidon commitment chip: `commitment = Poseidon(value, randomness)`.
///
/// Uses the P128Pow5T3 specification (128-bit security, width=3, rate=2)
/// with `ConstantLength<2>` domain separation.
pub struct PoseidonCommitmentChip {
    config: PoseidonCommitmentConfig,
}

impl PoseidonCommitmentChip {
    /// Configures the Poseidon chip columns and gates in the constraint system.
    ///
    /// Allocates 4 advice columns, 6 fixed columns, and 3 selectors.
    /// This must be called exactly once during `Circuit::configure()`.
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonCommitmentConfig {
        let state: [Column<Advice>; 3] =
            [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();

        let rc_a: [Column<Fixed>; 3] =
            [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b: [Column<Fixed>; 3] =
            [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];

        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        PoseidonCommitmentConfig { pow5_config, state }
    }

    /// Constructs the chip from a previously created configuration.
    #[must_use]
    pub fn construct(config: PoseidonCommitmentConfig) -> Self {
        Self { config }
    }

    /// Computes `Poseidon(value, randomness)` inside the circuit.
    ///
    /// Both `value` and `randomness` must be previously assigned cells.
    /// Returns the commitment as an assigned cell that can be constrained
    /// against public inputs or used in subsequent computations.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the Poseidon chip fails during synthesis.
    pub fn commit(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: AssignedCell<Fp, Fp>,
        randomness: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let chip = Pow5Chip::construct(self.config.pow5_config.clone());

        let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon_init"),
        )?;

        hasher.hash(layouter.namespace(|| "poseidon_hash"), [value, randomness])
    }

    /// Computes `Poseidon(left, right)` inside the circuit.
    ///
    /// Generic two-input Poseidon hash, useful for Merkle tree nodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the Poseidon chip fails during synthesis.
    pub fn hash_two(
        &self,
        mut layouter: impl Layouter<Fp>,
        left: AssignedCell<Fp, Fp>,
        right: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let chip = Pow5Chip::construct(self.config.pow5_config.clone());

        let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon_init"),
        )?;

        hasher.hash(layouter.namespace(|| "poseidon_hash"), [left, right])
    }

    /// Loads a private value into an advice cell.
    ///
    /// Uses `state[column_idx]` for assignment. `column_idx` must be 0, 1, or 2.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Synthesis`] if `column_idx >= 3` or if the region assignment fails.
    pub fn load_private(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<Fp>,
        column_idx: usize,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
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

    /// Returns a reference to the chip configuration.
    #[must_use]
    pub fn config(&self) -> &PoseidonCommitmentConfig {
        &self.config
    }

    /// Computes `Poseidon(value, randomness)` outside the circuit.
    ///
    /// Used for witness generation: compute the expected hash to provide
    /// as a public input or for verification.
    #[must_use]
    pub fn hash_outside_circuit(value: Fp, randomness: Fp) -> Fp {
        poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([value, randomness])
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

    /// Test circuit that computes commitment = Poseidon(value, randomness)
    /// and exposes the commitment as a public input.
    #[derive(Clone)]
    struct CommitmentTestCircuit {
        value: Value<Fp>,
        randomness: Value<Fp>,
    }

    #[derive(Debug, Clone)]
    struct CommitmentTestConfig {
        poseidon: PoseidonCommitmentConfig,
        instance: Column<Instance>,
    }

    impl Circuit<Fp> for CommitmentTestCircuit {
        type Config = CommitmentTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { value: Value::unknown(), randomness: Value::unknown() }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> CommitmentTestConfig {
            let poseidon = PoseidonCommitmentChip::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);

            CommitmentTestConfig { poseidon, instance }
        }

        fn synthesize(
            &self,
            config: CommitmentTestConfig,
            mut layouter: impl Layouter<Fp>,
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
    fn test_poseidon_commitment_valid() {
        let value = Fp::from(100u64);
        let randomness = Fp::from(42u64);
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
    fn test_poseidon_commitment_wrong_hash_rejected() {
        let value = Fp::from(100u64);
        let randomness = Fp::from(42u64);
        let wrong_expected = Fp::from(999u64);

        let circuit = CommitmentTestCircuit {
            value: Value::known(value),
            randomness: Value::known(randomness),
        };

        let k = 7;
        let prover = MockProver::run(k, &circuit, vec![vec![wrong_expected]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_poseidon_commitment_different_randomness_different_hash() {
        let value = Fp::from(100u64);
        let r1 = Fp::from(1u64);
        let r2 = Fp::from(2u64);

        let h1 = PoseidonCommitmentChip::hash_outside_circuit(value, r1);
        let h2 = PoseidonCommitmentChip::hash_outside_circuit(value, r2);

        assert_ne!(h1, h2, "Different randomness must produce different commitments");
    }

    #[test]
    fn test_poseidon_commitment_deterministic() {
        let value = Fp::from(42u64);
        let randomness = Fp::from(7u64);

        let h1 = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);
        let h2 = PoseidonCommitmentChip::hash_outside_circuit(value, randomness);

        assert_eq!(h1, h2, "Same inputs must produce same commitment");
    }

    #[test]
    fn test_poseidon_commitment_zero_values() {
        let value = Fp::zero();
        let randomness = Fp::zero();
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
    fn test_poseidon_commitment_large_values() {
        let value = Fp::from(u64::MAX);
        let randomness = Fp::from(u64::MAX - 1);
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
    fn test_load_private_invalid_column_returns_error() {
        #[derive(Clone)]
        struct BadColumnCircuit;

        impl Circuit<Fp> for BadColumnCircuit {
            type Config = CommitmentTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> CommitmentTestConfig {
                let poseidon = PoseidonCommitmentChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                CommitmentTestConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: CommitmentTestConfig,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let chip = PoseidonCommitmentChip::construct(config.poseidon);
                // column_idx=3 is invalid — must return Err, not panic
                chip.load_private(layouter.namespace(|| "bad column"), Value::known(Fp::one()), 3)?;
                Ok(())
            }
        }

        let result = MockProver::run(7, &BadColumnCircuit, vec![vec![]]);
        assert!(result.is_err(), "load_private(column_idx=3) must return Err, not panic");
    }

    #[test]
    fn test_hash_two_same_as_commit() {
        let a = Fp::from(10u64);
        let b = Fp::from(20u64);

        let h_commit = PoseidonCommitmentChip::hash_outside_circuit(a, b);

        // hash_two uses same Poseidon(a, b), so result should be identical
        // (both use ConstantLength<2> with P128Pow5T3)
        let h_direct =
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b]);

        assert_eq!(h_commit, h_direct);
    }
}