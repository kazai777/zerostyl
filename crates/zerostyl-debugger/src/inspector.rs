//! Circuit inspector for static analysis of halo2 circuits.
//!
//! Extracts circuit structure (columns, gates, constraints, degree) without
//! running a prover, by configuring a constraint system and analyzing it.

use halo2_proofs::dev::CircuitGates;
use halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2curves::pasta::Fp;

use crate::error::{DebugError, Result};
use crate::types::{CircuitStats, ConstraintInfo};

/// Inspect a halo2 circuit and extract its structural metadata as [`CircuitStats`].
///
/// Performs static analysis: configures the circuit's constraint system and
/// extracts column counts, gate info, and polynomial degrees. No prover is run.
pub fn inspect_circuit<C: Circuit<Fp>>(name: &str, k: u32) -> Result<CircuitStats> {
    let mut cs = ConstraintSystem::<Fp>::default();
    let _ = C::configure(&mut cs);

    let degree = cs.degree();

    // Column counts from PinnedConstraintSystem debug output
    // (fields are pub(crate) in halo2_proofs, so Debug is the only external access)
    let debug_str = format!("{:?}", cs.pinned());
    let num_advice_columns = parse_usize_field(&debug_str, "num_advice_columns")?;
    let num_instance_columns = parse_usize_field(&debug_str, "num_instance_columns")?;
    let num_fixed_columns = parse_usize_field(&debug_str, "num_fixed_columns")?;
    let num_selectors = parse_usize_field(&debug_str, "num_selectors")?;

    // Gate details from CircuitGates (official halo2 dev tool)
    let circuit_gates = CircuitGates::collect::<Fp, C>();
    let gates_display = format!("{}", circuit_gates);
    let (num_gates, num_constraints, constraints) = parse_gates_display(&gates_display, degree);

    Ok(CircuitStats {
        name: name.to_string(),
        k,
        num_advice_columns,
        num_instance_columns,
        num_fixed_columns,
        num_selectors,
        num_gates,
        num_constraints,
        degree,
        constraints,
    })
}

/// Parse a usize field from a Rust Debug format string.
///
/// Looks for `field_name: N` where N is a sequence of digits.
fn parse_usize_field(debug_str: &str, field_name: &str) -> Result<usize> {
    let pattern = format!("{}: ", field_name);
    let start = debug_str.find(&pattern).ok_or_else(|| {
        DebugError::CircuitError(format!(
            "Field '{}' not found in constraint system debug output",
            field_name
        ))
    })?;
    let after = &debug_str[start + pattern.len()..];
    let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
    after[..end]
        .parse()
        .map_err(|e| DebugError::CircuitError(format!("Failed to parse '{}': {}", field_name, e)))
}

/// Parse the `Display` output of `CircuitGates` to extract gate and constraint details.
///
/// The format is:
/// ```text
/// gate_name:
/// - constraint_name:
///   expression
/// Total gates: N
/// Total custom constraint polynomials: M
/// ...
/// ```
fn parse_gates_display(
    display: &str,
    overall_degree: usize,
) -> (usize, usize, Vec<ConstraintInfo>) {
    let mut num_gates = 0;
    let mut num_constraints = 0;
    let mut constraints = Vec::new();
    let mut current_gate_name: Option<String> = None;
    let mut current_gate_index: usize = 0;
    let mut expr_index: usize = 0;

    for line in display.lines() {
        // Parse summary totals
        if let Some(n) = line.strip_prefix("Total gates: ") {
            num_gates = n.trim().parse().unwrap_or(0);
            continue;
        }
        if let Some(n) = line.strip_prefix("Total custom constraint polynomials: ") {
            num_constraints = n.trim().parse().unwrap_or(0);
            continue;
        }
        if line.starts_with("Total ") {
            continue;
        }

        // Gate header line: "gate_name:" (not indented, ends with colon)
        if !line.starts_with(' ') && !line.starts_with('-') && line.ends_with(':') {
            let gate_name = line.trim_end_matches(':').to_string();
            if current_gate_name.is_some() {
                current_gate_index += 1;
            }
            current_gate_name = Some(gate_name);
            expr_index = 0;
            continue;
        }

        // Constraint line: "- expression" or "- name:" (each "- " is one constraint)
        if line.starts_with("- ") {
            if let Some(ref gate_name) = current_gate_name {
                constraints.push(ConstraintInfo {
                    gate_name: gate_name.clone(),
                    gate_index: current_gate_index,
                    expression_index: expr_index,
                    degree: overall_degree,
                });
                expr_index += 1;
            }
        }
        // Lines starting with "  " are expression details for named constraints — skip
    }

    (num_gates, num_constraints, constraints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Column, Error, Instance, Selector},
        poly::Rotation,
    };

    // ─── Test circuits ─────────────────────────────────────────────────────

    #[derive(Clone, Default)]
    struct AddCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
    }

    #[derive(Clone)]
    struct AddConfig {
        advice: Column<Advice>,
        _instance: Column<Instance>,
        selector: Selector,
    }

    impl Circuit<Fp> for AddCircuit {
        type Config = AddConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> AddConfig {
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

            AddConfig { advice, _instance: instance, selector }
        }

        fn synthesize(
            &self,
            config: AddConfig,
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

    #[derive(Clone, Default)]
    struct MultiGateCircuit;

    #[derive(Clone)]
    struct MultiGateConfig {
        _a: Column<Advice>,
        _b: Column<Advice>,
        _c: Column<Advice>,
        _s_add: Selector,
        _s_mul: Selector,
    }

    impl Circuit<Fp> for MultiGateCircuit {
        type Config = MultiGateConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> MultiGateConfig {
            let a = meta.advice_column();
            let b = meta.advice_column();
            let c = meta.advice_column();
            let s_add = meta.selector();
            let s_mul = meta.selector();

            meta.create_gate("add", |meta| {
                let s = meta.query_selector(s_add);
                let a = meta.query_advice(a, Rotation::cur());
                let b = meta.query_advice(b, Rotation::cur());
                let c = meta.query_advice(c, Rotation::cur());
                vec![s * (a + b - c)]
            });

            meta.create_gate("mul", |meta| {
                let s = meta.query_selector(s_mul);
                let a = meta.query_advice(a, Rotation::cur());
                let b = meta.query_advice(b, Rotation::cur());
                let c = meta.query_advice(c, Rotation::cur());
                vec![s * (a * b - c)]
            });

            MultiGateConfig { _a: a, _b: b, _c: c, _s_add: s_add, _s_mul: s_mul }
        }

        fn synthesize(
            &self,
            _config: MultiGateConfig,
            _layouter: impl Layouter<Fp>,
        ) -> std::result::Result<(), Error> {
            Ok(())
        }
    }

    // ─── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_inspect_add_circuit() {
        let stats = inspect_circuit::<AddCircuit>("add_circuit", 4).unwrap();
        assert_eq!(stats.name, "add_circuit");
        assert_eq!(stats.k, 4);
        assert_eq!(stats.num_advice_columns, 1);
        assert_eq!(stats.num_instance_columns, 1);
        assert_eq!(stats.num_fixed_columns, 0);
        assert_eq!(stats.num_selectors, 1);
        assert_eq!(stats.num_gates, 1);
        assert_eq!(stats.num_constraints, 1);
        assert!(stats.degree >= 2);
        assert_eq!(stats.constraints.len(), 1);
        assert_eq!(stats.constraints[0].gate_name, "add");
        assert_eq!(stats.constraints[0].gate_index, 0);
        assert_eq!(stats.constraints[0].expression_index, 0);
    }

    #[test]
    fn test_inspect_multi_gate_circuit() {
        let stats = inspect_circuit::<MultiGateCircuit>("multi", 4).unwrap();
        assert_eq!(stats.num_advice_columns, 3);
        assert_eq!(stats.num_instance_columns, 0);
        assert_eq!(stats.num_selectors, 2);
        assert_eq!(stats.num_gates, 2);
        assert_eq!(stats.num_constraints, 2);
        assert_eq!(stats.constraints.len(), 2);
        assert_eq!(stats.constraints[0].gate_name, "add");
        assert_eq!(stats.constraints[0].gate_index, 0);
        assert_eq!(stats.constraints[1].gate_name, "mul");
        assert_eq!(stats.constraints[1].gate_index, 1);
    }

    #[test]
    fn test_inspect_empty_circuit() {
        #[derive(Clone, Default)]
        struct EmptyCircuit;

        impl Circuit<Fp> for EmptyCircuit {
            type Config = ();
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self
            }

            fn configure(_meta: &mut ConstraintSystem<Fp>) {}

            fn synthesize(
                &self,
                _config: (),
                _layouter: impl Layouter<Fp>,
            ) -> std::result::Result<(), Error> {
                Ok(())
            }
        }

        let stats = inspect_circuit::<EmptyCircuit>("empty", 4).unwrap();
        assert_eq!(stats.num_advice_columns, 0);
        assert_eq!(stats.num_instance_columns, 0);
        assert_eq!(stats.num_fixed_columns, 0);
        assert_eq!(stats.num_selectors, 0);
        assert_eq!(stats.num_gates, 0);
        assert_eq!(stats.num_constraints, 0);
        assert_eq!(stats.constraints.len(), 0);
    }

    #[test]
    fn test_inspect_num_rows_and_total_columns() {
        let stats = inspect_circuit::<AddCircuit>("test", 4).unwrap();
        assert_eq!(stats.num_rows(), 16);
        assert_eq!(
            stats.total_columns(),
            stats.num_advice_columns + stats.num_instance_columns + stats.num_fixed_columns
        );
    }

    #[test]
    fn test_inspect_display_output() {
        let stats = inspect_circuit::<AddCircuit>("add", 4).unwrap();
        let output = stats.to_string();
        assert!(output.contains("Circuit: add"));
        assert!(output.contains("Gates: 1"));
        assert!(output.contains("gate[0] \"add\""));
    }

    #[test]
    fn test_parse_usize_field_valid() {
        let debug = "PinnedConstraintSystem { num_fixed_columns: 5, num_advice_columns: 3 }";
        assert_eq!(parse_usize_field(debug, "num_fixed_columns").unwrap(), 5);
        assert_eq!(parse_usize_field(debug, "num_advice_columns").unwrap(), 3);
    }

    #[test]
    fn test_parse_usize_field_missing() {
        let debug = "PinnedConstraintSystem { num_fixed_columns: 5 }";
        assert!(parse_usize_field(debug, "nonexistent").is_err());
    }

    #[test]
    fn test_parse_usize_field_zero() {
        let debug = "PinnedConstraintSystem { num_selectors: 0, gates: [] }";
        assert_eq!(parse_usize_field(debug, "num_selectors").unwrap(), 0);
    }

    #[test]
    fn test_parse_gates_display_empty() {
        let display = "Total gates: 0\nTotal custom constraint polynomials: 0\nTotal negations: 0\nTotal additions: 0\nTotal multiplications: 0\n";
        let (gates, constraints, infos) = parse_gates_display(display, 2);
        assert_eq!(gates, 0);
        assert_eq!(constraints, 0);
        assert!(infos.is_empty());
    }

    #[test]
    fn test_parse_gates_display_single_gate() {
        let display = "add:\n- R1CS:\n  S0 * (A0@0 + A1@0 - I0@0)\nTotal gates: 1\nTotal custom constraint polynomials: 1\nTotal negations: 1\nTotal additions: 1\nTotal multiplications: 1\n";
        let (gates, constraints, infos) = parse_gates_display(display, 3);
        assert_eq!(gates, 1);
        assert_eq!(constraints, 1);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].gate_name, "add");
        assert_eq!(infos[0].gate_index, 0);
        assert_eq!(infos[0].expression_index, 0);
        assert_eq!(infos[0].degree, 3);
    }

    #[test]
    fn test_parse_gates_display_multiple_gates() {
        let display = "add:\n- S0 * (A0@0 + A1@0 - A2@0)\nmul:\n- S1 * (A0@0 * A1@0 - A2@0)\nTotal gates: 2\nTotal custom constraint polynomials: 2\nTotal negations: 2\nTotal additions: 1\nTotal multiplications: 3\n";
        let (gates, constraints, infos) = parse_gates_display(display, 3);
        assert_eq!(gates, 2);
        assert_eq!(constraints, 2);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].gate_name, "add");
        assert_eq!(infos[0].gate_index, 0);
        assert_eq!(infos[1].gate_name, "mul");
        assert_eq!(infos[1].gate_index, 1);
    }
}