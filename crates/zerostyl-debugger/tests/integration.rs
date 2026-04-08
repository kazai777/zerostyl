//! Integration tests for the zerostyl-debugger crate.
//!
//! Tests circuit inspection and debugging using the project's real circuits:
//! tx_privacy, state_mask, private_vote. Verifies that the debugger produces
//! accurate, actionable diagnostics for both valid and invalid witnesses.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;
use state_mask::StateMaskCircuit;
use tx_privacy::TxPrivacyCircuit;
use zerostyl_debugger::{
    debug_circuit, inspect_circuit, CircuitStats, ColumnType, ConstraintFailure, DebugReport,
};

// ─── Inspect: real circuits ─────────────────────────────────────────────────

#[test]
fn test_inspect_tx_privacy() {
    let stats = inspect_circuit::<TxPrivacyCircuit>("tx_privacy", 14).unwrap();
    assert_eq!(stats.name, "tx_privacy");
    assert_eq!(stats.k, 14);
    assert!(stats.num_advice_columns >= 3);
    assert_eq!(stats.num_instance_columns, 1);
    assert!(stats.num_gates >= 1);
    assert!(stats.num_constraints >= 1);
    assert!(stats.degree >= 2);
    assert_eq!(stats.num_rows(), 1 << 14);
}

#[test]
fn test_inspect_state_mask() {
    let stats = inspect_circuit::<StateMaskCircuit>("state_mask", 10).unwrap();
    assert_eq!(stats.name, "state_mask");
    assert_eq!(stats.k, 10);
    assert!(stats.num_advice_columns >= 3);
    assert_eq!(stats.num_instance_columns, 1);
    assert!(stats.num_gates >= 1);
    assert!(stats.num_constraints >= 1);
    assert!(stats.degree >= 2);
    assert_eq!(stats.num_rows(), 1 << 10);
}

#[test]
fn test_inspect_private_vote() {
    let stats = inspect_circuit::<PrivateVoteCircuit>("private_vote", 10).unwrap();
    assert_eq!(stats.name, "private_vote");
    assert_eq!(stats.k, 10);
    assert!(stats.num_advice_columns >= 3);
    assert_eq!(stats.num_instance_columns, 1);
    assert!(stats.num_gates >= 1);
    assert!(stats.num_constraints >= 1);
    assert!(stats.degree >= 2);
}

#[test]
fn test_inspect_stats_display_format() {
    let stats = inspect_circuit::<StateMaskCircuit>("state_mask", 10).unwrap();
    let output = stats.to_string();
    assert!(output.contains("Circuit: state_mask"));
    assert!(output.contains("rows)"));
    assert!(output.contains("Gates:"));
    assert!(output.contains("max degree"));
}

#[test]
fn test_inspect_stats_serialization_roundtrip() {
    let stats = inspect_circuit::<PrivateVoteCircuit>("private_vote", 10).unwrap();
    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: CircuitStats = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, "private_vote");
    assert_eq!(deserialized.k, stats.k);
    assert_eq!(deserialized.num_advice_columns, stats.num_advice_columns);
    assert_eq!(deserialized.num_gates, stats.num_gates);
    assert_eq!(deserialized.constraints.len(), stats.constraints.len());
}

// ─── Debug: valid witnesses ─────────────────────────────────────────────────

#[test]
fn test_debug_state_mask_valid() {
    let state_value = 1000u64;
    let nonce = Fp::from(42u64);
    let collateral_ratio = 200u64;
    let hidden_balance = 500u64;
    let threshold = 100u64;

    let circuit = StateMaskCircuit::new(state_value, nonce, collateral_ratio, hidden_balance, threshold);
    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);
    let public_inputs = vec![vec![commitment, Fp::from(threshold)]];

    let report = debug_circuit(&circuit, public_inputs, 10, "state_mask").unwrap();
    assert!(report.is_satisfied);
    assert_eq!(report.num_failures(), 0);
    assert_eq!(report.circuit_name, "state_mask");
    assert_eq!(report.k, 10);
    assert!(report.stats.num_gates >= 1);
}

#[test]
fn test_debug_private_vote_valid() {
    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fp::from(42u64);
    let randomness_vote = Fp::from(84u64);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);
    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);
    let public_inputs = vec![vec![balance_commitment, Fp::from(threshold), vote_commitment]];

    let report = debug_circuit(&circuit, public_inputs, 10, "private_vote").unwrap();
    assert!(report.is_satisfied);
    assert_eq!(report.num_failures(), 0);
}

// ─── Debug: invalid witnesses (regression tests) ────────────────────────────

#[test]
fn test_debug_state_mask_wrong_commitment() {
    let state_value = 1000u64;
    let nonce = Fp::from(42u64);

    let circuit = StateMaskCircuit::from_raw(state_value, nonce, 200, 500, 100);

    // Wrong commitment: use Fp::from(999) instead of the real Poseidon commitment
    let wrong_commitment = Fp::from(999u64);
    let public_inputs = vec![vec![wrong_commitment, Fp::from(100u64)]];

    let report = debug_circuit(&circuit, public_inputs, 10, "state_mask").unwrap();
    assert!(!report.is_satisfied);
    assert!(report.num_failures() > 0);

    // The report should contain actionable failure info
    let output = report.to_string();
    assert!(output.contains("CONSTRAINT(S) FAILED"));
    assert!(output.contains("Hint:"));
}

#[test]
fn test_debug_private_vote_wrong_balance_commitment() {
    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fp::from(42u64);
    let randomness_vote = Fp::from(84u64);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

    // Wrong balance commitment
    let wrong_commitment = Fp::from(9999u64);
    let public_inputs = vec![vec![wrong_commitment, Fp::from(threshold), vote_commitment]];

    let report = debug_circuit(&circuit, public_inputs, 10, "private_vote").unwrap();
    assert!(!report.is_satisfied);
    assert!(report.num_failures() > 0);

    // Verify failures have gate names and hints
    for failure in &report.failures {
        assert!(!failure.gate_name.is_empty());
        assert!(!failure.hint.is_empty());
    }
}

#[test]
fn test_debug_private_vote_wrong_vote_commitment() {
    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fp::from(42u64);
    let randomness_vote = Fp::from(84u64);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);
    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);

    // Wrong vote commitment
    let wrong_vote_commitment = Fp::from(7777u64);
    let public_inputs = vec![vec![balance_commitment, Fp::from(threshold), wrong_vote_commitment]];

    let report = debug_circuit(&circuit, public_inputs, 10, "private_vote").unwrap();
    assert!(!report.is_satisfied);
    assert!(report.num_failures() > 0);
}

// ─── Debug report structure validation ──────────────────────────────────────

#[test]
fn test_debug_report_failure_structure() {
    // Create a deliberately broken circuit with wrong public input
    let state_value = 1000u64;
    let nonce = Fp::from(7u64);

    let circuit = StateMaskCircuit::from_raw(state_value, nonce, 200, 500, 100);

    // Completely wrong public inputs
    let wrong_inputs = vec![vec![Fp::from(999u64), Fp::from(100u64)]];
    let report = debug_circuit(&circuit, wrong_inputs, 10, "state_mask").unwrap();

    assert!(!report.is_satisfied);

    // Each failure should have:
    for failure in &report.failures {
        // Non-empty gate name
        assert!(!failure.gate_name.is_empty(), "Gate name should not be empty");
        // Non-empty hint
        assert!(!failure.hint.is_empty(), "Hint should not be empty");
        // Serializable
        let json = serde_json::to_string(failure).unwrap();
        let deserialized: ConstraintFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.gate_name, failure.gate_name);
        assert_eq!(deserialized.row, failure.row);
    }
}

#[test]
fn test_debug_report_serialization_with_failures() {
    let state_value = 1000u64;
    let nonce = Fp::from(123u64);
    let circuit = StateMaskCircuit::from_raw(state_value, nonce, 200, 500, 100);
    let wrong_inputs = vec![vec![Fp::from(0u64), Fp::from(100u64)]];

    let report = debug_circuit(&circuit, wrong_inputs, 10, "state_mask").unwrap();
    assert!(!report.is_satisfied);

    // Full report should serialize and deserialize cleanly
    let json = serde_json::to_string_pretty(&report).unwrap();
    let deserialized: DebugReport = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.circuit_name, "state_mask");
    assert!(!deserialized.is_satisfied);
    assert_eq!(deserialized.failures.len(), report.failures.len());
}

// ─── Debug: constraint failure cell values ──────────────────────────────────

/// Test that cell values from ConstraintNotSatisfied failures contain column info.
#[test]
fn test_debug_failure_cell_values_have_column_info() {
    // Simple addition circuit with wrong sum
    #[derive(Clone)]
    struct TestConfig {
        advice: Column<Advice>,
        _instance: Column<Instance>,
        selector: Selector,
    }

    #[derive(Clone, Default)]
    struct TestCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> TestConfig {
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
            TestConfig { advice, _instance: instance, selector }
        }

        fn synthesize(
            &self,
            config: TestConfig,
            mut layouter: impl Layouter<Fp>,
        ) -> std::result::Result<(), Error> {
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

    let circuit =
        TestCircuit { a: Value::known(Fp::from(10u64)), b: Value::known(Fp::from(20u64)) };
    let report = debug_circuit(&circuit, vec![vec![Fp::from(999u64)]], 4, "test").unwrap();

    assert!(!report.is_satisfied);
    let failure = &report.failures[0];
    assert_eq!(failure.gate_name, "add");
    assert!(!failure.cell_values.is_empty());

    // Cell values should have column type info
    let has_advice = failure.cell_values.iter().any(|w| w.column.column_type == ColumnType::Advice);
    assert!(has_advice, "Cell values should contain Advice columns");
}

// ─── Multiple failures in single report ─────────────────────────────────────

#[test]
fn test_debug_multiple_failures_display() {
    // A circuit with intentionally many wrong public inputs will produce multiple failures
    let state_value = 1000u64;
    let nonce = Fp::from(123u64);
    let circuit = StateMaskCircuit::from_raw(state_value, nonce, 200, 500, 100);

    // Wrong public input
    let wrong_inputs = vec![vec![Fp::from(0u64), Fp::from(100u64)]];
    let report = debug_circuit(&circuit, wrong_inputs, 10, "state_mask").unwrap();

    assert!(!report.is_satisfied);
    // Should have at least one failure
    assert!(report.num_failures() >= 1);

    let output = report.to_string();
    assert!(output.contains("CONSTRAINT(S) FAILED"));
    // Each failure should be numbered
    assert!(output.contains("Failure 1"));
}

// ─── Inspect: edge cases ────────────────────────────────────────────────────

#[test]
fn test_inspect_tx_privacy_total_columns() {
    let stats = inspect_circuit::<TxPrivacyCircuit>("tx_privacy", 14).unwrap();
    let total = stats.total_columns();
    assert!(total >= 4, "tx_privacy should have at least 4 total columns");
    assert_eq!(
        total,
        stats.num_advice_columns + stats.num_instance_columns + stats.num_fixed_columns
    );
}

#[test]
fn test_inspect_private_vote_constraints_list() {
    let stats = inspect_circuit::<PrivateVoteCircuit>("private_vote", 10).unwrap();
    assert!(!stats.constraints.is_empty());
    // Each constraint should have a gate name
    for constraint in &stats.constraints {
        assert!(!constraint.gate_name.is_empty());
        assert!(constraint.degree >= 2);
    }
}

// ─── Debug: k values ────────────────────────────────────────────────────────

#[test]
fn test_debug_state_mask_insufficient_k() {
    let circuit = StateMaskCircuit::new(1000, Fp::from(42u64), 200, 500, 100);
    let commitment = StateMaskCircuit::compute_commitment(Fp::from(1000u64), Fp::from(42u64));
    let public_inputs = vec![vec![commitment, Fp::from(100u64)]];

    // k=4 is too small for state_mask circuit
    let result = debug_circuit(&circuit, public_inputs, 4, "state_mask");
    assert!(result.is_err());
}
