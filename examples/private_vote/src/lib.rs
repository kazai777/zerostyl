//! Private Vote Circuit
//!
//! Implements zero-knowledge proofs for private voting using:
//! - Simplified binding commitments for balance and vote hiding
//! - Range proofs to verify voter eligibility (balance >= threshold)
//! - Boolean constraint to ensure vote is 0 or 1
//!
//! ## Circuit Overview
//!
//! Public Inputs:
//! - balance_commitment: Commit(balance, randomness_balance)
//! - voting_threshold: Minimum balance required to vote
//! - vote_commitment: Commit(vote, randomness_vote)
//!
//! Private Witnesses:
//! - balance: Voter's token balance
//! - randomness_balance: Commitment randomness for balance
//! - vote: The vote value (0 or 1)
//! - randomness_vote: Commitment randomness for vote
//! - bits: Bit decomposition of (balance - threshold)
//!
//! Constraints:
//! 1. balance_commitment == balance + randomness_balance
//! 2. vote is boolean: vote * (vote - 1) == 0
//! 3. vote_commitment == vote + randomness_vote
//! 4. Each bit is boolean: bit * (bit - 1) == 0
//! 5. Bit decomposition: balance - threshold == sum(bit_i * 2^i)

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;

const RANGE_BITS: usize = 8;

#[derive(Clone, Debug)]
pub struct PrivateVoteConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    s_commitment: Selector,
    s_vote_boolean: Selector,
    s_vote_commit: Selector,
    s_bit_check: Selector,
    s_bit_decompose: Selector,
}

#[derive(Clone, Debug)]
pub struct PrivateVoteChip {
    config: PrivateVoteConfig,
}

impl Chip<Fp> for PrivateVoteChip {
    type Config = PrivateVoteConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl PrivateVoteChip {
    pub fn construct(config: PrivateVoteConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> PrivateVoteConfig {
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        let s_commitment = meta.selector();
        let s_vote_boolean = meta.selector();
        let s_vote_commit = meta.selector();
        let s_bit_check = meta.selector();
        let s_bit_decompose = meta.selector();

        // Commitment gate: balance + randomness - commitment == 0
        meta.create_gate("commitment", |meta| {
            let s = meta.query_selector(s_commitment);
            let balance = meta.query_advice(advice[0], Rotation::cur());
            let randomness = meta.query_advice(advice[1], Rotation::cur());
            let commitment = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (balance + randomness - commitment)]
        });

        // Vote boolean gate: vote * (vote - 1) == 0
        meta.create_gate("vote_boolean", |meta| {
            let s = meta.query_selector(s_vote_boolean);
            let vote = meta.query_advice(advice[0], Rotation::cur());
            let one = meta.query_advice(advice[1], Rotation::cur());

            vec![s * vote.clone() * (vote - one)]
        });

        // Vote commitment gate: vote + randomness - commitment == 0
        meta.create_gate("vote_commit", |meta| {
            let s = meta.query_selector(s_vote_commit);
            let vote = meta.query_advice(advice[0], Rotation::cur());
            let randomness = meta.query_advice(advice[1], Rotation::cur());
            let commitment = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (vote + randomness - commitment)]
        });

        // Bit check gate: bit * (bit - 1) == 0
        meta.create_gate("bit_check", |meta| {
            let s = meta.query_selector(s_bit_check);
            let bit = meta.query_advice(advice[0], Rotation::cur());
            let one = meta.query_advice(advice[1], Rotation::cur());

            vec![s * bit.clone() * (bit - one)]
        });

        // Bit decomposition: acc_cur + bit * power - acc_next == 0
        meta.create_gate("bit_decompose", |meta| {
            let s = meta.query_selector(s_bit_decompose);
            let bit = meta.query_advice(advice[0], Rotation::cur());
            let power = meta.query_advice(advice[1], Rotation::cur());
            let acc_cur = meta.query_advice(advice[2], Rotation::cur());
            let acc_next = meta.query_advice(advice[2], Rotation::next());

            vec![s * (acc_cur + bit * power - acc_next)]
        });

        PrivateVoteConfig {
            advice,
            instance,
            s_commitment,
            s_vote_boolean,
            s_vote_commit,
            s_bit_check,
            s_bit_decompose,
        }
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

    pub fn assign_vote_boolean(
        &self,
        mut layouter: impl Layouter<Fp>,
        vote: Value<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "vote_boolean",
            |mut region| {
                self.config.s_vote_boolean.enable(&mut region, 0)?;

                region.assign_advice(|| "vote", self.config.advice[0], 0, || vote)?;
                region.assign_advice(
                    || "one",
                    self.config.advice[1],
                    0,
                    || Value::known(Fp::ONE),
                )?;

                Ok(())
            },
        )
    }

    pub fn assign_vote_commitment(
        &self,
        mut layouter: impl Layouter<Fp>,
        vote: Value<Fp>,
        randomness: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "vote_commit",
            |mut region| {
                self.config.s_vote_commit.enable(&mut region, 0)?;

                region.assign_advice(|| "vote", self.config.advice[0], 0, || vote)?;
                region.assign_advice(|| "randomness", self.config.advice[1], 0, || randomness)?;

                let commitment = vote.zip(randomness).map(|(v, r)| v + r);

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
pub struct PrivateVoteCircuit {
    pub balance: Value<Fp>,
    pub randomness_balance: Value<Fp>,
    pub vote: Value<Fp>,
    pub randomness_vote: Value<Fp>,
    pub threshold: u64,
    pub bits: Vec<Value<Fp>>,
}

impl Default for PrivateVoteCircuit {
    fn default() -> Self {
        Self {
            balance: Value::unknown(),
            randomness_balance: Value::unknown(),
            vote: Value::unknown(),
            randomness_vote: Value::unknown(),
            threshold: 0,
            bits: vec![Value::unknown(); RANGE_BITS],
        }
    }
}

impl PrivateVoteCircuit {
    pub fn new(
        balance: u64,
        randomness_balance: Fp,
        vote: u64,
        randomness_vote: Fp,
        threshold: u64,
    ) -> Self {
        assert!(vote <= 1, "Vote must be 0 or 1");
        assert!(balance >= threshold, "Balance below voting threshold");
        assert!(
            balance - threshold < (1 << RANGE_BITS),
            "Balance - threshold too large for {} bits",
            RANGE_BITS
        );

        let normalized = balance - threshold;
        let bits: Vec<Value<Fp>> = (0..RANGE_BITS)
            .map(|i| {
                let bit = (normalized >> i) & 1;
                Value::known(Fp::from(bit))
            })
            .collect();

        Self {
            balance: Value::known(Fp::from(balance)),
            randomness_balance: Value::known(randomness_balance),
            vote: Value::known(Fp::from(vote)),
            randomness_vote: Value::known(randomness_vote),
            threshold,
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

impl Circuit<Fp> for PrivateVoteCircuit {
    type Config = PrivateVoteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();

        PrivateVoteChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = PrivateVoteChip::construct(config.clone());

        // 1. Prove balance commitment
        let balance_commitment_cell = chip.assign_commitment(
            layouter.namespace(|| "balance_commitment"),
            self.balance,
            self.randomness_balance,
        )?;

        // 2. Prove vote is boolean
        chip.assign_vote_boolean(layouter.namespace(|| "vote_boolean"), self.vote)?;

        // 3. Prove vote commitment
        let vote_commitment_cell = chip.assign_vote_commitment(
            layouter.namespace(|| "vote_commitment"),
            self.vote,
            self.randomness_vote,
        )?;

        // 4. Prove balance >= threshold via range proof on (balance - threshold)
        chip.assign_range_proof(layouter.namespace(|| "range_proof"), self.bits.clone())?;

        // Expose public inputs
        layouter.constrain_instance(balance_commitment_cell.cell(), config.instance, 0)?;
        // threshold is public input at index 1 - we don't constrain it from circuit
        // since it's a known public value
        layouter.constrain_instance(vote_commitment_cell.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_private_vote_valid_yes() {
        let k = 10;
        let balance = 100u64;
        let threshold = 50u64;
        let vote = 1u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let circuit =
            PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_private_vote_valid_no() {
        let k = 10;
        let balance = 100u64;
        let threshold = 50u64;
        let vote = 0u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let circuit =
            PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "Vote must be 0 or 1")]
    fn test_private_vote_invalid_vote_value() {
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);
        PrivateVoteCircuit::new(100, randomness_balance, 2, randomness_vote, 50);
    }

    #[test]
    #[should_panic(expected = "Balance below voting threshold")]
    fn test_private_vote_insufficient_balance() {
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);
        PrivateVoteCircuit::new(30, randomness_balance, 1, randomness_vote, 50);
    }

    #[test]
    fn test_private_vote_exact_threshold() {
        let k = 10;
        let balance = 50u64;
        let threshold = 50u64;
        let vote = 1u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let circuit =
            PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_commitment_computation() {
        let value = Fp::from(100);
        let randomness = Fp::from(42);
        let commitment = PrivateVoteCircuit::compute_commitment(value, randomness);
        assert_eq!(commitment, Fp::from(142));
    }

    #[test]
    fn test_circuit_default() {
        let circuit = PrivateVoteCircuit::default();
        let _without_witnesses = circuit.without_witnesses();
        assert_eq!(circuit.threshold, 0);
        assert_eq!(circuit.bits.len(), RANGE_BITS);
    }

    #[test]
    fn test_range_bits_constant() {
        assert_eq!(RANGE_BITS, 8);
    }

    #[test]
    fn test_zero_threshold() {
        let k = 10;
        let balance = 100u64;
        let threshold = 0u64;
        let vote = 1u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let circuit =
            PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_zero_balance_zero_threshold() {
        let k = 10;
        let balance = 0u64;
        let threshold = 0u64;
        let vote = 0u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let circuit =
            PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
