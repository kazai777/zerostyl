//! Private Vote Circuit
//!
//! Implements zero-knowledge proofs for private voting using:
//! - Poseidon commitments for balance and vote hiding (real ZK-friendly hash)
//! - Range proofs to verify voter eligibility (balance >= threshold)
//! - Boolean constraint to ensure vote is 0 or 1
//!
//! ## Circuit Overview
//!
//! Public Inputs:
//! - balance_commitment: Poseidon(balance, randomness_balance)
//! - voting_threshold: Minimum balance required to vote
//! - vote_commitment: Poseidon(vote, randomness_vote)
//!
//! Private Witnesses:
//! - balance: Voter's token balance
//! - randomness_balance: Commitment randomness for balance
//! - vote: The vote value (0 or 1)
//! - randomness_vote: Commitment randomness for vote
//!
//! Constraints:
//! 1. balance_commitment == Poseidon(balance, randomness_balance)
//! 2. vote is boolean: vote ∈ {0, 1}
//! 3. vote_commitment == Poseidon(vote, randomness_vote)
//! 4. balance - threshold ∈ [0, 2^RANGE_BITS) (proves balance >= threshold)

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;
use zerostyl_compiler::gadgets::{
    PoseidonCommitmentChip, PoseidonCommitmentConfig, RangeProofChip, RangeProofConfig,
};

/// Number of bits for the balance-threshold range proof.
const RANGE_BITS: usize = 8;

/// Configuration for the private vote circuit.
#[derive(Debug, Clone)]
pub struct PrivateVoteConfig {
    poseidon_config: PoseidonCommitmentConfig,
    range_config: RangeProofConfig,
    /// Advice columns for the eligibility gate: [balance, threshold, diff].
    eligibility_advice: [Column<Advice>; 3],
    /// Selector for the eligibility gate: `balance - threshold - diff = 0`.
    eligibility_selector: Selector,
    instance: Column<Instance>,
}

/// Private vote circuit with Poseidon commitments and range proofs.
#[derive(Clone, Debug)]
pub struct PrivateVoteCircuit {
    pub balance: Value<Fp>,
    pub randomness_balance: Value<Fp>,
    pub vote: Value<Fp>,
    pub randomness_vote: Value<Fp>,
    pub threshold: u64,
}

impl Default for PrivateVoteCircuit {
    fn default() -> Self {
        Self {
            balance: Value::unknown(),
            randomness_balance: Value::unknown(),
            vote: Value::unknown(),
            randomness_vote: Value::unknown(),
            threshold: 0,
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

        Self {
            balance: Value::known(Fp::from(balance)),
            randomness_balance: Value::known(randomness_balance),
            vote: Value::known(Fp::from(vote)),
            randomness_vote: Value::known(randomness_vote),
            threshold,
        }
    }

    /// Constructs a circuit without validating inputs — for use in the debugger only.
    pub fn from_raw(
        balance: u64,
        randomness_balance: Fp,
        vote: u64,
        randomness_vote: Fp,
        threshold: u64,
    ) -> Self {
        Self {
            balance: Value::known(Fp::from(balance)),
            randomness_balance: Value::known(randomness_balance),
            vote: Value::known(Fp::from(vote)),
            randomness_vote: Value::known(randomness_vote),
            threshold,
        }
    }

    /// Uses the P128Pow5T3 specification (128-bit security, width=3, rate=2)
    /// matching halo2_gadgets Poseidon. This provides both hiding and binding
    /// security properties.
    pub fn compute_commitment(value: Fp, randomness: Fp) -> Fp {
        PoseidonCommitmentChip::hash_outside_circuit(value, randomness)
    }
}

impl Circuit<Fp> for PrivateVoteCircuit {
    type Config = PrivateVoteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let poseidon_config = PoseidonCommitmentChip::configure(meta);
        let range_config = RangeProofChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Eligibility gate columns: [balance, threshold, diff]
        let eligibility_advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for col in &eligibility_advice {
            meta.enable_equality(*col);
        }
        let eligibility_selector = meta.selector();

        // Gate: balance - threshold - diff = 0
        // Ensures diff is exactly (balance - threshold), preventing free witness forgery.
        meta.create_gate("eligibility check", |meta| {
            let s = meta.query_selector(eligibility_selector);
            let balance = meta.query_advice(eligibility_advice[0], Rotation::cur());
            let threshold = meta.query_advice(eligibility_advice[1], Rotation::cur());
            let diff = meta.query_advice(eligibility_advice[2], Rotation::cur());
            vec![s * (balance - threshold - diff)]
        });

        PrivateVoteConfig {
            poseidon_config,
            range_config,
            eligibility_advice,
            eligibility_selector,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonCommitmentChip::construct(config.poseidon_config.clone());
        let range_chip = RangeProofChip::construct(config.range_config.clone());

        // 1. Poseidon commitment: balance_commitment = Poseidon(balance, randomness_balance)
        let balance_cell =
            poseidon_chip.load_private(layouter.namespace(|| "load balance"), self.balance, 0)?;
        // Clone for use in eligibility region (commit() consumes the original)
        let balance_for_eligibility = balance_cell.clone();
        let randomness_balance_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load randomness_balance"),
            self.randomness_balance,
            1,
        )?;
        let balance_commitment = poseidon_chip.commit(
            layouter.namespace(|| "balance commitment"),
            balance_cell,
            randomness_balance_cell,
        )?;

        // 2. Load vote into Poseidon and clone for boolean check.
        //    The clone creates a copy constraint linking the boolean-checked cell
        //    to the Poseidon commitment input, preventing a malicious prover from
        //    committing a non-boolean value while passing the boolean check.
        let vote_cell_poseidon =
            poseidon_chip.load_private(layouter.namespace(|| "load vote"), self.vote, 0)?;
        let vote_cell_for_bool = vote_cell_poseidon.clone();
        let randomness_vote_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load randomness_vote"),
            self.randomness_vote,
            1,
        )?;
        let vote_commitment = poseidon_chip.commit(
            layouter.namespace(|| "vote commitment"),
            vote_cell_poseidon,
            randomness_vote_cell,
        )?;

        // 3. Vote boolean: vote ∈ {0, 1} via 1-bit range check
        //    Uses the clone of the Poseidon input cell (copy-constrained).
        range_chip.check_range(layouter.namespace(|| "vote boolean"), vote_cell_for_bool, 1)?;

        // 4. Eligibility check: balance - threshold ∈ [0, 2^RANGE_BITS)
        //
        // The gate constrains: balance - threshold - diff = 0
        // - balance is linked to the Poseidon commitment input via copy_advice
        // - threshold is loaded from public instance[1] via assign_advice_from_instance
        // - diff is fully determined by the gate (no free witness)
        //
        // Then diff is range-checked to prove it fits in RANGE_BITS bits,
        // which proves balance >= threshold (for values fitting in RANGE_BITS).
        let threshold_fp = Fp::from(self.threshold);
        let diff_cell = layouter.assign_region(
            || "eligibility check",
            |mut region| {
                config.eligibility_selector.enable(&mut region, 0)?;

                // Copy balance from Poseidon input cell (permutation-constrained)
                balance_for_eligibility.copy_advice(
                    || "balance",
                    &mut region,
                    config.eligibility_advice[0],
                    0,
                )?;

                // Load threshold from instance column index 1
                // This creates a copy constraint: advice cell == instance[1]
                region.assign_advice_from_instance(
                    || "threshold from instance",
                    config.instance,
                    1,
                    config.eligibility_advice[1],
                    0,
                )?;

                // Assign diff = balance - threshold (gate forces correctness)
                let diff_val = self.balance.map(|b| b - threshold_fp);
                let diff_cell = region.assign_advice(
                    || "balance - threshold",
                    config.eligibility_advice[2],
                    0,
                    || diff_val,
                )?;

                Ok(diff_cell)
            },
        )?;

        // Range check: diff ∈ [0, 2^RANGE_BITS) proves balance >= threshold
        range_chip.check_range(
            layouter.namespace(|| "balance >= threshold"),
            diff_cell,
            RANGE_BITS,
        )?;

        // Expose public inputs: [balance_commitment, threshold, vote_commitment]
        // Note: threshold at instance[1] is already constrained via
        // assign_advice_from_instance in the eligibility region above.
        layouter.constrain_instance(balance_commitment.cell(), config.instance, 0)?;
        layouter.constrain_instance(vote_commitment.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_private_vote_valid_yes() {
        let k = 11;
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
        let k = 11;
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
        let k = 11;
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
    fn test_commitment_is_poseidon() {
        let value = Fp::from(100);
        let randomness = Fp::from(42);
        let commitment = PrivateVoteCircuit::compute_commitment(value, randomness);
        // Poseidon hash is deterministic but NOT a simple addition
        assert_ne!(commitment, value + randomness);
        // Verify it matches the Poseidon chip's output
        assert_eq!(commitment, PoseidonCommitmentChip::hash_outside_circuit(value, randomness));
    }

    #[test]
    fn test_circuit_default() {
        let circuit = PrivateVoteCircuit::default();
        let _without_witnesses = circuit.without_witnesses();
        assert_eq!(circuit.threshold, 0);
    }

    #[test]
    fn test_range_bits_constant() {
        assert_eq!(RANGE_BITS, 8);
    }

    #[test]
    fn test_zero_threshold() {
        let k = 11;
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
        let k = 11;
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

    #[test]
    fn test_wrong_commitment_rejected() {
        let k = 11;
        let balance = 100u64;
        let threshold = 50u64;
        let vote = 1u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let circuit =
            PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

        // Use a wrong balance commitment (different randomness)
        let wrong_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), Fp::from(999));
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        let public_inputs = vec![wrong_commitment, Fp::from(threshold), vote_commitment];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_circuit_rejects_forged_eligibility() {
        let k = 11;
        let balance = 10u64; // Below threshold
        let threshold = 100u64;
        let vote = 1u64;
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        // Build circuit directly, bypassing constructor assertions
        let circuit = PrivateVoteCircuit {
            balance: Value::known(Fp::from(balance)),
            randomness_balance: Value::known(randomness_balance),
            vote: Value::known(Fp::from(vote)),
            randomness_vote: Value::known(randomness_vote),
            threshold,
        };

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(
            prover.verify().is_err(),
            "Circuit must reject when balance < threshold (eligibility gate)"
        );
    }

    #[test]
    fn test_circuit_rejects_non_boolean_vote() {
        let k = 11;
        let balance = 1000u64;
        let threshold = 100u64;
        let vote = 2u64; // NOT boolean (neither 0 nor 1)
        let randomness_balance = Fp::from(42);
        let randomness_vote = Fp::from(84);

        let balance_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
        let vote_commitment =
            PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

        // Build circuit directly, bypassing constructor assertions
        let circuit = PrivateVoteCircuit {
            balance: Value::known(Fp::from(balance)),
            randomness_balance: Value::known(randomness_balance),
            vote: Value::known(Fp::from(vote)),
            randomness_vote: Value::known(randomness_vote),
            threshold,
        };

        let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(
            prover.verify().is_err(),
            "Circuit must reject non-boolean vote (vote=2 does not fit in 1 bit)"
        );
    }
}
