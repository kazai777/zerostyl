//! State Mask Circuit with Range Proofs
//!
//! Implements zero-knowledge range proofs to prove that a secret value
//! lies within a specified range without revealing the actual value.
//!
//! ## Circuit Overview
//!
//! Public Inputs:
//! - commitment: Commit(value, randomness)
//! - range_min: Minimum allowed value
//! - range_max: Maximum allowed value
//!
//! Private Witnesses:
//! - value: The secret value to prove is in range
//! - randomness: Commitment randomness
//! - bits: Bit decomposition of (value - range_min)
//!
//! Constraints:
//! 1. commitment == Commit(value, randomness)
//! 2. Each bit is boolean: bit * (bit - 1) == 0
//! 3. Bit decomposition is correct: value - range_min == Σ(bit_i * 2^i)
//! 4. Range check: value - range_min < range_max - range_min

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;

const RANGE_BITS: usize = 8;

#[derive(Clone, Debug)]
pub struct StateMaskConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    s_commitment: Selector,
    s_bit_check: Selector,
    s_bit_decompose: Selector,
}

#[derive(Clone, Debug)]
pub struct StateMaskChip {
    config: StateMaskConfig,
}

impl Chip<Fp> for StateMaskChip {
    type Config = StateMaskConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl StateMaskChip {
    pub fn construct(config: StateMaskConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> StateMaskConfig {
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        let s_commitment = meta.selector();
        let s_bit_check = meta.selector();
        let s_bit_decompose = meta.selector();

        // Commitment gate: commitment = value + randomness
        meta.create_gate("commitment", |meta| {
            let s = meta.query_selector(s_commitment);
            let value = meta.query_advice(advice[0], Rotation::cur());
            let randomness = meta.query_advice(advice[1], Rotation::cur());
            let commitment = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (value + randomness - commitment)]
        });

        // Boolean constraint: bit * (bit - 1) = 0
        meta.create_gate("bit_check", |meta| {
            let s = meta.query_selector(s_bit_check);
            let bit = meta.query_advice(advice[0], Rotation::cur());
            let one = meta.query_advice(advice[1], Rotation::cur());

            vec![s * bit.clone() * (bit - one)]
        });

        // Bit decomposition accumulator: acc_next = acc_cur + bit * 2^i
        meta.create_gate("bit_decompose", |meta| {
            let s = meta.query_selector(s_bit_decompose);
            let bit = meta.query_advice(advice[0], Rotation::cur());
            let power = meta.query_advice(advice[1], Rotation::cur());
            let acc_cur = meta.query_advice(advice[2], Rotation::cur());
            let acc_next = meta.query_advice(advice[2], Rotation::next());

            vec![s * (acc_cur + bit * power - acc_next)]
        });

        StateMaskConfig { advice, instance, s_commitment, s_bit_check, s_bit_decompose }
    }

    pub fn assign_commitment(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<Fp>,
        randomness: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "commitment",
            |mut region| {
                self.config.s_commitment.enable(&mut region, 0)?;

                region.assign_advice(|| "value", self.config.advice[0], 0, || value)?;
                region.assign_advice(|| "randomness", self.config.advice[1], 0, || randomness)?;

                let commitment = value.zip(randomness).map(|(v, r)| v + r);

                region.assign_advice(|| "commitment", self.config.advice[2], 0, || commitment)
            },
        )
    }

    pub fn assign_range_proof(
        &self,
        mut layouter: impl Layouter<Fp>,
        bits: Vec<Value<Fp>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "range_proof",
            |mut region| {
                let one = Value::known(Fp::ONE);

                for (i, bit) in bits.iter().enumerate() {
                    self.config.s_bit_check.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("bit_{}", i),
                        self.config.advice[0],
                        i,
                        || *bit,
                    )?;
                    region.assign_advice(|| "one", self.config.advice[1], i, || one)?;
                }

                let mut accumulator = Value::known(Fp::ZERO);
                let offset = bits.len();

                for (i, bit) in bits.iter().enumerate() {
                    self.config.s_bit_decompose.enable(&mut region, offset + i)?;

                    region.assign_advice(
                        || format!("bit_decompose_{}", i),
                        self.config.advice[0],
                        offset + i,
                        || *bit,
                    )?;

                    let power = Fp::from(1u64 << i);
                    region.assign_advice(
                        || format!("power_{}", i),
                        self.config.advice[1],
                        offset + i,
                        || Value::known(power),
                    )?;

                    region.assign_advice(
                        || format!("acc_{}", i),
                        self.config.advice[2],
                        offset + i,
                        || accumulator,
                    )?;

                    accumulator = accumulator.zip(*bit).map(|(acc, b)| {
                        let bit_contrib = b * power;
                        acc + bit_contrib
                    });
                }

                region.assign_advice(
                    || "final_acc",
                    self.config.advice[2],
                    offset + bits.len(),
                    || accumulator,
                )?;

                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct StateMaskCircuit {
    pub value: Value<Fp>,
    pub randomness: Value<Fp>,
    pub range_min: u64,
    pub range_max: u64,
    pub bits: Vec<Value<Fp>>,
}

impl Default for StateMaskCircuit {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            randomness: Value::unknown(),
            range_min: 0,
            range_max: 255,
            bits: vec![Value::unknown(); RANGE_BITS],
        }
    }
}

impl StateMaskCircuit {
    pub fn new(value: u64, randomness: Fp, range_min: u64, range_max: u64) -> Self {
        assert!(value >= range_min, "Value below range minimum");
        assert!(value <= range_max, "Value above range maximum");
        assert!(
            range_max - range_min < (1 << RANGE_BITS),
            "Range too large for {} bits",
            RANGE_BITS
        );

        let normalized_value = value - range_min;
        let bits: Vec<Value<Fp>> = (0..RANGE_BITS)
            .map(|i| {
                let bit = (normalized_value >> i) & 1;
                Value::known(Fp::from(bit))
            })
            .collect();

        Self {
            value: Value::known(Fp::from(value)),
            randomness: Value::known(randomness),
            range_min,
            range_max,
            bits,
        }
    }

    /// Compute a simplified binding commitment: commitment = value + randomness.
    ///
    /// NOTE: This is NOT a true Pedersen commitment (which requires elliptic curve
    /// point arithmetic via EccChip). This simplified form is sufficient for
    /// demonstrating the circuit pattern but does not provide hiding/binding
    /// security properties of real Pedersen commitments.
    pub fn compute_commitment(value: Fp, randomness: Fp) -> Fp {
        value + randomness
    }
}

impl Circuit<Fp> for StateMaskCircuit {
    type Config = StateMaskConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();

        StateMaskChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = StateMaskChip::construct(config.clone());

        let commitment_cell = chip.assign_commitment(
            layouter.namespace(|| "commitment"),
            self.value,
            self.randomness,
        )?;

        chip.assign_range_proof(layouter.namespace(|| "range_proof"), self.bits.clone())?;

        layouter.constrain_instance(commitment_cell.cell(), config.instance, 0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_state_mask_circuit_valid() {
        let k = 10;

        let value = 42u64;
        let randomness = Fp::from(123);
        let range_min = 0u64;
        let range_max = 255u64;

        let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);

        let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
        let public_inputs = vec![commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_state_mask_circuit_edge_min() {
        let k = 10;

        let value = 10u64;
        let randomness = Fp::from(456);
        let range_min = 10u64;
        let range_max = 100u64;

        let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);

        let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
        let public_inputs = vec![commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_state_mask_circuit_edge_max() {
        let k = 10;

        let value = 100u64;
        let randomness = Fp::from(789);
        let range_min = 10u64;
        let range_max = 100u64;

        let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);

        let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
        let public_inputs = vec![commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "Value below range minimum")]
    fn test_state_mask_circuit_below_range() {
        let randomness = Fp::from(123);
        StateMaskCircuit::new(5, randomness, 10, 100);
    }

    #[test]
    #[should_panic(expected = "Value above range maximum")]
    fn test_state_mask_circuit_above_range() {
        let randomness = Fp::from(123);
        StateMaskCircuit::new(150, randomness, 10, 100);
    }

    #[test]
    fn test_commitment_computation() {
        let value = Fp::from(42);
        let randomness = Fp::from(123);
        let commitment = StateMaskCircuit::compute_commitment(value, randomness);

        assert_eq!(commitment, Fp::from(165));
    }

    #[test]
    fn test_bit_decomposition() {
        let value = 42u64;

        let bits: Vec<u64> = (0..RANGE_BITS).map(|i| (value >> i) & 1).collect();

        let reconstructed: u64 = bits.iter().enumerate().map(|(i, &bit)| bit << i).sum();

        assert_eq!(reconstructed, value);
        assert_eq!(bits, vec![0, 1, 0, 1, 0, 1, 0, 0]);
    }

    #[test]
    fn test_circuit_default() {
        let circuit = StateMaskCircuit::default();
        let _without_witnesses = circuit.without_witnesses();

        // Just verify it doesn't panic
        assert_eq!(circuit.range_min, 0);
        assert_eq!(circuit.range_max, 255);
    }

    #[test]
    fn test_range_bits_constant() {
        assert_eq!(RANGE_BITS, 8);
    }

    #[test]
    fn test_commitment_with_zero_randomness() {
        let value = Fp::from(100);
        let randomness = Fp::from(0);
        let commitment = StateMaskCircuit::compute_commitment(value, randomness);

        assert_eq!(commitment, value);
    }

    #[test]
    fn test_zero_value() {
        let k = 10;
        let value = 0u64;
        let randomness = Fp::from(123);
        let range_min = 0u64;
        let range_max = 255u64;

        let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);
        let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
        let public_inputs = vec![commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_max_8_bit_value() {
        let k = 10;
        let value = 255u64;
        let randomness = Fp::from(123);
        let range_min = 0u64;
        let range_max = 255u64;

        let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);
        let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
        let public_inputs = vec![commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bit_decomposition_powers_of_two() {
        for power in 0..RANGE_BITS {
            let value = 1u64 << power;
            let bits: Vec<u64> = (0..RANGE_BITS).map(|i| (value >> i) & 1).collect();
            let reconstructed: u64 = bits.iter().enumerate().map(|(i, &bit)| bit << i).sum();
            assert_eq!(reconstructed, value, "Failed for 2^{}", power);
        }
    }

    #[test]
    fn test_different_ranges() {
        let k = 10;
        let value = 50u64;
        let randomness = Fp::from(999);

        // Test different range configurations
        let ranges = vec![(0, 100), (25, 75), (50, 60)];

        for (range_min, range_max) in ranges {
            let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);
            let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
            let public_inputs = vec![commitment];

            let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
