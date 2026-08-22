//! State Mask Circuit — Privacy-preserving state proofs.
//!
//! Proves three properties about secret state values without revealing them:
//!
//! 1. **Commitment**: a Poseidon hash chain binds *all* committed secrets —
//!    `commitment = H(H(H(state_value, collateral_ratio), hidden_balance), nonce)` (public)
//! 2. **Range proof**: `collateral_ratio ∈ [150, 300]` (private, bounded)
//! 3. **Comparison**: `hidden_balance > threshold` (threshold is public)
//!
//! The commitment binds `collateral_ratio` and `hidden_balance` so the range and comparison
//! statements are about the *committed* values, not free witnesses. Without this binding a prover
//! could satisfy the proof with any in-range collateral and any balance above the threshold,
//! regardless of their actual (public) state — the proof would be vacuous.
//!
//! ## Public Inputs
//!
//! - `commitment`: Poseidon hash chain over (state_value, collateral_ratio, hidden_balance, nonce)
//! - `threshold`: minimum balance requirement
//!
//! ## Private Witnesses
//!
//! - `state_value`: an additional secret value bound into the commitment
//! - `nonce`: commitment randomness
//! - `collateral_ratio`: a ratio that must be in [150, 300]
//! - `hidden_balance`: a balance that must exceed `threshold`
//!
//! ## Use Cases
//!
//! - DeFi collateral health proofs (prove healthy ratio without revealing position)
//! - Balance threshold proofs (prove solvency without revealing balance)
//! - General privacy-preserving state attestation

// The circuit itself is no_std/wasm-compatible. The CircuitDescriptor (prover, witness JSON) needs
// std and lives behind the `std` feature.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod descriptor;

#[cfg(feature = "std")]
pub use descriptor::descriptor;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::bn256::Fr;
// Gadgets come from the standalone no_std crate directly (not via zerostyl-compiler), so the
// circuit does not pull the std-only compiler.
use zerostyl_gadgets::{
    ComparisonChip, ComparisonConfig, PoseidonCommitmentChip, PoseidonCommitmentConfig,
    RangeProofChip, RangeProofConfig,
};

/// Minimum collateral ratio (inclusive).
pub const COLLATERAL_MIN: u64 = 150;
/// Maximum collateral ratio (inclusive).
pub const COLLATERAL_MAX: u64 = 300;

/// Number of bits for the collateral bounded range check.
const COLLATERAL_RANGE_BITS: usize = 16;
/// Number of bits for the balance comparison.
const COMPARISON_BITS: usize = 64;

/// Configuration for the state mask circuit.
#[derive(Debug, Clone)]
pub struct StateMaskConfig {
    poseidon_config: PoseidonCommitmentConfig,
    range_config: RangeProofConfig,
    comparison_config: ComparisonConfig,
    instance: Column<Instance>,
}

/// State mask circuit: proves commitment, range, and comparison properties.
#[derive(Clone, Debug)]
pub struct StateMaskCircuit {
    pub state_value: Value<Fr>,
    pub nonce: Value<Fr>,
    pub collateral_ratio: Value<Fr>,
    pub hidden_balance: Value<Fr>,
    pub threshold: Value<Fr>,
}

// `Value::default()` only exists when halo2's optional features pull it in (e.g. under
// `--all-features`); without them the manual impl is required, so this cannot simply be derived
// across all feature sets.
#[allow(clippy::derivable_impls)]
impl Default for StateMaskCircuit {
    fn default() -> Self {
        Self {
            state_value: Value::unknown(),
            nonce: Value::unknown(),
            collateral_ratio: Value::unknown(),
            hidden_balance: Value::unknown(),
            threshold: Value::unknown(),
        }
    }
}

impl StateMaskCircuit {
    /// Creates a new state mask circuit with all private witnesses.
    ///
    /// # Panics
    ///
    /// - If `collateral_ratio` is not in [`COLLATERAL_MIN`, `COLLATERAL_MAX`]
    /// - If `hidden_balance <= threshold`
    pub fn new(
        state_value: u64,
        nonce: Fr,
        collateral_ratio: u64,
        hidden_balance: u64,
        threshold: u64,
    ) -> Self {
        assert!(
            collateral_ratio >= COLLATERAL_MIN,
            "Collateral ratio {} below minimum {}",
            collateral_ratio,
            COLLATERAL_MIN
        );
        assert!(
            collateral_ratio <= COLLATERAL_MAX,
            "Collateral ratio {} above maximum {}",
            collateral_ratio,
            COLLATERAL_MAX
        );
        assert!(
            hidden_balance > threshold,
            "Hidden balance {} must be greater than threshold {}",
            hidden_balance,
            threshold
        );

        Self {
            state_value: Value::known(Fr::from(state_value)),
            nonce: Value::known(nonce),
            collateral_ratio: Value::known(Fr::from(collateral_ratio)),
            hidden_balance: Value::known(Fr::from(hidden_balance)),
            threshold: Value::known(Fr::from(threshold)),
        }
    }

    /// Constructs a circuit without validating inputs — for use in the debugger only.
    ///
    /// Allows injecting invalid or edge-case witnesses so the MockProver can surface
    /// the exact failing constraint.
    pub fn from_raw(
        state_value: u64,
        nonce: Fr,
        collateral_ratio: u64,
        hidden_balance: u64,
        threshold: u64,
    ) -> Self {
        Self {
            state_value: Value::known(Fr::from(state_value)),
            nonce: Value::known(nonce),
            collateral_ratio: Value::known(Fr::from(collateral_ratio)),
            hidden_balance: Value::known(Fr::from(hidden_balance)),
            threshold: Value::known(Fr::from(threshold)),
        }
    }

    /// Computes the committed state hash outside the circuit.
    ///
    /// Mirrors the in-circuit Poseidon hash chain exactly:
    /// `H(H(H(state_value, collateral_ratio), hidden_balance), nonce)`. Used for witness
    /// generation and public input computation. All four secrets are bound, so the public
    /// commitment pins the exact `collateral_ratio` and `hidden_balance` the proof reasons about.
    #[must_use]
    pub fn compute_commitment(
        state_value: Fr,
        collateral_ratio: Fr,
        hidden_balance: Fr,
        nonce: Fr,
    ) -> Fr {
        let c1 = PoseidonCommitmentChip::hash_outside_circuit(state_value, collateral_ratio);
        let c2 = PoseidonCommitmentChip::hash_outside_circuit(c1, hidden_balance);
        PoseidonCommitmentChip::hash_outside_circuit(c2, nonce)
    }
}

impl Circuit<Fr> for StateMaskCircuit {
    type Config = StateMaskConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poseidon_config = PoseidonCommitmentChip::configure(meta);
        let range_config = RangeProofChip::configure(meta);
        let comparison_config = ComparisonChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        StateMaskConfig { poseidon_config, range_config, comparison_config, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonCommitmentChip::construct(config.poseidon_config);
        let range_chip = RangeProofChip::construct(config.range_config);
        let comparison_chip = ComparisonChip::construct(config.comparison_config);

        // --- Load private witnesses ---
        let state_value_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load state_value"),
            self.state_value,
            0,
        )?;
        let nonce_cell =
            poseidon_chip.load_private(layouter.namespace(|| "load nonce"), self.nonce, 1)?;
        let collateral_cell = range_chip
            .load_value(layouter.namespace(|| "load collateral_ratio"), self.collateral_ratio)?;
        let balance_cell = comparison_chip
            .load_value(layouter.namespace(|| "load hidden_balance"), self.hidden_balance)?;
        let threshold_cell =
            comparison_chip.load_value(layouter.namespace(|| "load threshold"), self.threshold)?;

        // --- 1. Commitment: Poseidon hash chain binding all committed secrets ---
        // commitment = H(H(H(state_value, collateral_ratio), hidden_balance), nonce).
        // Feeding the *same* collateral_cell / balance_cell that are range-checked and compared
        // below (copy_advice enforces equality) ties the public commitment to those exact values,
        // so the range/comparison statements are not about free witnesses.
        let c1 = poseidon_chip.hash_two(
            layouter.namespace(|| "commit chain: state_value, collateral"),
            state_value_cell,
            collateral_cell.clone(),
        )?;
        let c2 = poseidon_chip.hash_two(
            layouter.namespace(|| "commit chain: + hidden_balance"),
            c1,
            balance_cell.clone(),
        )?;
        let commitment = poseidon_chip.hash_two(
            layouter.namespace(|| "commit chain: + nonce"),
            c2,
            nonce_cell,
        )?;

        // --- 2. Range: collateral_ratio in [COLLATERAL_MIN, COLLATERAL_MAX] ---
        range_chip.check_range_bounded(
            layouter.namespace(|| "range check collateral"),
            collateral_cell,
            Fr::from(COLLATERAL_MIN),
            Fr::from(COLLATERAL_MAX),
            COLLATERAL_RANGE_BITS,
        )?;

        // --- 3. Comparison: hidden_balance > threshold ---
        // Range-check both operands first: assert_gt reduces to a range check on their difference,
        // which is only sound when both operands are already in [0, 2^COMPARISON_BITS). Otherwise a
        // field-wrapped hidden_balance (≈ p) could make the difference small and pass falsely.
        range_chip.check_range(
            layouter.namespace(|| "range check hidden_balance"),
            balance_cell.clone(),
            COMPARISON_BITS,
        )?;
        range_chip.check_range(
            layouter.namespace(|| "range check threshold"),
            threshold_cell.clone(),
            COMPARISON_BITS,
        )?;

        // Save Cell reference before consuming threshold_cell in assert_gt
        let threshold_cell_ref = threshold_cell.cell();

        comparison_chip.assert_gt(
            layouter.namespace(|| "balance > threshold"),
            balance_cell,
            threshold_cell,
            COMPARISON_BITS,
        )?;

        // --- Constrain public inputs ---
        layouter.constrain_instance(commitment.cell(), config.instance, 0)?;
        layouter.constrain_instance(threshold_cell_ref, config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    const TEST_K: u32 = 10;

    fn make_test_data(
        state_value: u64,
        nonce_raw: u64,
        collateral_ratio: u64,
        hidden_balance: u64,
        threshold: u64,
    ) -> (StateMaskCircuit, Vec<Vec<Fr>>) {
        let nonce = Fr::from(nonce_raw);
        let commitment = StateMaskCircuit::compute_commitment(
            Fr::from(state_value),
            Fr::from(collateral_ratio),
            Fr::from(hidden_balance),
            nonce,
        );
        let circuit =
            StateMaskCircuit::new(state_value, nonce, collateral_ratio, hidden_balance, threshold);
        let public_inputs = vec![vec![commitment, Fr::from(threshold)]];
        (circuit, public_inputs)
    }

    #[test]
    fn test_valid_circuit() {
        let (circuit, public_inputs) = make_test_data(1000, 42, 200, 500, 100);
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_wrong_commitment_rejected() {
        let (circuit, _) = make_test_data(1000, 42, 200, 500, 100);
        let wrong_inputs = vec![vec![Fr::from(999u64), Fr::from(100u64)]];
        let prover = MockProver::run(TEST_K, &circuit, wrong_inputs).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_wrong_threshold_rejected() {
        let (circuit, _) = make_test_data(1000, 42, 200, 500, 100);
        let commitment = StateMaskCircuit::compute_commitment(
            Fr::from(1000u64),
            Fr::from(200u64),
            Fr::from(500u64),
            Fr::from(42u64),
        );
        let wrong_inputs = vec![vec![commitment, Fr::from(200u64)]];
        let prover = MockProver::run(TEST_K, &circuit, wrong_inputs).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    #[should_panic(expected = "Collateral ratio")]
    fn test_collateral_below_min_panics() {
        make_test_data(1000, 42, 149, 500, 100);
    }

    #[test]
    #[should_panic(expected = "Collateral ratio")]
    fn test_collateral_above_max_panics() {
        make_test_data(1000, 42, 301, 500, 100);
    }

    #[test]
    #[should_panic(expected = "Hidden balance")]
    fn test_balance_not_above_threshold_panics() {
        make_test_data(1000, 42, 200, 100, 500);
    }

    #[test]
    #[should_panic(expected = "Hidden balance")]
    fn test_balance_equal_threshold_panics() {
        make_test_data(1000, 42, 200, 100, 100);
    }

    #[test]
    fn test_collateral_at_min() {
        let (circuit, public_inputs) = make_test_data(1000, 42, 150, 500, 100);
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_collateral_at_max() {
        let (circuit, public_inputs) = make_test_data(1000, 42, 300, 500, 100);
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_balance_just_above_threshold() {
        let (circuit, public_inputs) = make_test_data(1000, 42, 200, 101, 100);
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_commitment_deterministic() {
        let value = Fr::from(42u64);
        let nonce = Fr::from(123u64);
        let c1 =
            StateMaskCircuit::compute_commitment(value, Fr::from(200u64), Fr::from(500u64), nonce);
        let c2 =
            StateMaskCircuit::compute_commitment(value, Fr::from(200u64), Fr::from(500u64), nonce);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_different_nonce() {
        let value = Fr::from(42u64);
        let c1 = StateMaskCircuit::compute_commitment(
            value,
            Fr::from(200u64),
            Fr::from(500u64),
            Fr::from(1u64),
        );
        let c2 = StateMaskCircuit::compute_commitment(
            value,
            Fr::from(200u64),
            Fr::from(500u64),
            Fr::from(2u64),
        );
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_binds_hidden_balance() {
        // Changing only hidden_balance must change the commitment — this is what makes the
        // "balance > threshold" statement about the committed balance rather than a free witness.
        let base = StateMaskCircuit::compute_commitment(
            Fr::from(42u64),
            Fr::from(200u64),
            Fr::from(500u64),
            Fr::from(7u64),
        );
        let changed = StateMaskCircuit::compute_commitment(
            Fr::from(42u64),
            Fr::from(200u64),
            Fr::from(501u64),
            Fr::from(7u64),
        );
        assert_ne!(base, changed);
    }

    #[test]
    fn test_default() {
        let circuit = StateMaskCircuit::default();
        let _ = circuit.without_witnesses();
    }

    #[test]
    fn test_collateral_constants() {
        assert_eq!(COLLATERAL_MIN, 150);
        assert_eq!(COLLATERAL_MAX, 300);
    }

    #[test]
    fn test_different_state_values() {
        let test_cases = vec![
            (500u64, 42u64, 200u64, 1000u64, 100u64),
            (1_000_000, 99, 250, 5000, 1000),
            (1, 1, 150, 2, 1),
        ];
        for (state_value, nonce_raw, ratio, balance, threshold) in test_cases {
            let (circuit, public_inputs) =
                make_test_data(state_value, nonce_raw, ratio, balance, threshold);
            let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
            prover.assert_satisfied();
        }
    }

    #[test]
    fn test_circuit_rejects_collateral_below_min() {
        let state_value = 1000u64;
        let nonce = Fr::from(42u64);
        // Commitment computed over the actual (invalid) witness so the commitment binding holds
        // and the *only* failing constraint is the collateral range check.
        let commitment = StateMaskCircuit::compute_commitment(
            Fr::from(state_value),
            Fr::from(149u64),
            Fr::from(500u64),
            nonce,
        );

        let circuit = StateMaskCircuit {
            state_value: Value::known(Fr::from(state_value)),
            nonce: Value::known(nonce),
            collateral_ratio: Value::known(Fr::from(149u64)), // Below COLLATERAL_MIN
            hidden_balance: Value::known(Fr::from(500u64)),
            threshold: Value::known(Fr::from(100u64)),
        };

        let public_inputs = vec![vec![commitment, Fr::from(100u64)]];
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "Circuit must reject collateral_ratio below min");
    }

    #[test]
    fn test_circuit_rejects_collateral_above_max() {
        let state_value = 1000u64;
        let nonce = Fr::from(42u64);
        let commitment = StateMaskCircuit::compute_commitment(
            Fr::from(state_value),
            Fr::from(301u64),
            Fr::from(500u64),
            nonce,
        );

        let circuit = StateMaskCircuit {
            state_value: Value::known(Fr::from(state_value)),
            nonce: Value::known(nonce),
            collateral_ratio: Value::known(Fr::from(301u64)), // Above COLLATERAL_MAX
            hidden_balance: Value::known(Fr::from(500u64)),
            threshold: Value::known(Fr::from(100u64)),
        };

        let public_inputs = vec![vec![commitment, Fr::from(100u64)]];
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "Circuit must reject collateral_ratio above max");
    }

    #[test]
    fn test_circuit_rejects_balance_below_threshold() {
        let state_value = 1000u64;
        let nonce = Fr::from(42u64);
        let commitment = StateMaskCircuit::compute_commitment(
            Fr::from(state_value),
            Fr::from(200u64),
            Fr::from(500u64),
            nonce,
        );

        let circuit = StateMaskCircuit {
            state_value: Value::known(Fr::from(state_value)),
            nonce: Value::known(nonce),
            collateral_ratio: Value::known(Fr::from(200u64)),
            hidden_balance: Value::known(Fr::from(500u64)),
            threshold: Value::known(Fr::from(600u64)), // threshold > balance
        };

        let public_inputs = vec![vec![commitment, Fr::from(600u64)]];
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "Circuit must reject balance below threshold");
    }

    #[test]
    fn test_circuit_rejects_balance_equal_threshold() {
        let state_value = 1000u64;
        let nonce = Fr::from(42u64);
        let commitment = StateMaskCircuit::compute_commitment(
            Fr::from(state_value),
            Fr::from(200u64),
            Fr::from(500u64),
            nonce,
        );

        let circuit = StateMaskCircuit {
            state_value: Value::known(Fr::from(state_value)),
            nonce: Value::known(nonce),
            collateral_ratio: Value::known(Fr::from(200u64)),
            hidden_balance: Value::known(Fr::from(500u64)),
            threshold: Value::known(Fr::from(500u64)), // threshold == balance
        };

        let public_inputs = vec![vec![commitment, Fr::from(500u64)]];
        let prover = MockProver::run(TEST_K, &circuit, public_inputs).unwrap();
        assert!(prover.verify().is_err(), "Circuit must reject balance equal to threshold");
    }
}
