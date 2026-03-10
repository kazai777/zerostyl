//! Witness debugger with enhanced MockProver diagnostics.
//!
//! Wraps halo2's `MockProver` to capture verification failures and produce
//! structured [`DebugReport`]s with human-readable constraint failure details.

use halo2_proofs::dev::{FailureLocation, MockProver, VerifyFailure};
use halo2_proofs::plonk::Circuit;
use halo2curves::pasta::Fp;

use crate::error::{DebugError, Result};
use crate::types::{ColumnInfo, ColumnType, ConstraintFailure, DebugReport, WitnessInfo};

/// Debug a halo2 circuit by running MockProver and producing a structured report.
///
/// Combines static analysis (via [`inspect_circuit`](crate::inspector::inspect_circuit))
/// with dynamic verification (via `MockProver`) to produce a complete [`DebugReport`].
pub fn debug_circuit<C: Circuit<Fp>>(
    circuit: &C,
    instances: Vec<Vec<Fp>>,
    k: u32,
    name: &str,
) -> Result<DebugReport> {
    let stats = crate::inspector::inspect_circuit::<C>(name, k)?;

    let prover = MockProver::run(k, circuit, instances)
        .map_err(|e| DebugError::MockProverError(format!("{:?}", e)))?;

    match prover.verify() {
        Ok(()) => Ok(DebugReport {
            circuit_name: name.to_string(),
            k,
            is_satisfied: true,
            failures: vec![],
            stats,
        }),
        Err(failures) => {
            let constraint_failures = failures.iter().map(convert_verify_failure).collect();

            Ok(DebugReport {
                circuit_name: name.to_string(),
                k,
                is_satisfied: false,
                failures: constraint_failures,
                stats,
            })
        }
    }
}

/// Convert a halo2 `VerifyFailure` into our structured `ConstraintFailure`.
fn convert_verify_failure(failure: &VerifyFailure) -> ConstraintFailure {
    let hint = format!("{}", failure);

    match failure {
        VerifyFailure::ConstraintNotSatisfied { constraint, location, cell_values } => {
            let constraint_str = format!("{}", constraint);
            let gate_name = extract_gate_name_from_constraint(&constraint_str);
            let expression_index = extract_constraint_index(&constraint_str);
            let row = extract_row_from_location(location);
            let cells = cell_values
                .iter()
                .map(|(vc, val)| {
                    let vc_str = format!("{}", vc);
                    let (col_info, cell_row) = parse_virtual_cell(&vc_str, row);
                    WitnessInfo { column: col_info, row: cell_row, value: Some(val.clone()) }
                })
                .collect();

            ConstraintFailure { gate_name, row, expression_index, cell_values: cells, hint }
        }
        VerifyFailure::CellNotAssigned { gate, gate_offset, column, .. } => {
            let gate_str = format!("{}", gate);
            let gate_name = extract_gate_name_from_gate(&gate_str);
            let col_type = convert_any_column_type(column.column_type());
            let col_index = extract_column_index(column);

            ConstraintFailure {
                gate_name,
                row: *gate_offset,
                expression_index: 0,
                cell_values: vec![WitnessInfo {
                    column: ColumnInfo { column_type: col_type, index: col_index },
                    row: *gate_offset,
                    value: None,
                }],
                hint,
            }
        }
        VerifyFailure::InstanceCellNotAssigned { gate, column, row, .. } => {
            let gate_str = format!("{}", gate);
            let gate_name = extract_gate_name_from_gate(&gate_str);

            let col_index = extract_column_index(column);

            ConstraintFailure {
                gate_name,
                row: *row,
                expression_index: 0,
                cell_values: vec![WitnessInfo {
                    column: ColumnInfo { column_type: ColumnType::Instance, index: col_index },
                    row: *row,
                    value: None,
                }],
                hint,
            }
        }
        VerifyFailure::ConstraintPoisoned { constraint } => {
            let constraint_str = format!("{}", constraint);
            let gate_name = extract_gate_name_from_constraint(&constraint_str);
            let expression_index = extract_constraint_index(&constraint_str);

            ConstraintFailure { gate_name, row: 0, expression_index, cell_values: vec![], hint }
        }
        VerifyFailure::Lookup { lookup_index, location } => {
            let row = extract_row_from_location(location);

            ConstraintFailure {
                gate_name: format!("lookup[{}]", lookup_index),
                row,
                expression_index: *lookup_index,
                cell_values: vec![],
                hint,
            }
        }
        VerifyFailure::Permutation { column, location } => {
            let row = extract_row_from_location(location);
            let col_str = format!("{}", column);

            ConstraintFailure {
                gate_name: format!("permutation({})", col_str),
                row,
                expression_index: 0,
                cell_values: vec![],
                hint,
            }
        }
    }
}

// ─── Parsing helpers ───────────────────────────────────────────────────────

/// Extract gate name from constraint Display: "Constraint N ('name') in gate M ('gate_name')"
fn extract_gate_name_from_constraint(s: &str) -> String {
    // The gate name is in the last ('...') group
    if let Some(start) = s.rfind("('") {
        if let Some(end) = s[start..].find("')") {
            return s[start + 2..start + end].to_string();
        }
    }
    s.to_string()
}

/// Extract gate name from gate Display: "Gate N ('gate_name')"
fn extract_gate_name_from_gate(s: &str) -> String {
    if let Some(start) = s.find("('") {
        if let Some(end) = s[start..].find("')") {
            return s[start + 2..start + end].to_string();
        }
    }
    s.to_string()
}

/// Extract constraint index from Display: "Constraint N ..."
fn extract_constraint_index(s: &str) -> usize {
    if let Some(rest) = s.strip_prefix("Constraint ") {
        if let Some(end) = rest.find(|c: char| !c.is_ascii_digit()) {
            return rest[..end].parse().unwrap_or(0);
        }
    }
    0
}

/// Extract row/offset from FailureLocation Display.
///
/// - "in Region N ('name') at offset X" → X
/// - "outside any region, on row X" → X
fn extract_row_from_location(location: &FailureLocation) -> usize {
    let s = format!("{}", location);
    if let Some(idx) = s.rfind("offset ") {
        let after = &s[idx + 7..];
        let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        return after[..end].parse().unwrap_or(0);
    }
    if let Some(idx) = s.rfind("row ") {
        let after = &s[idx + 4..];
        let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        return after[..end].parse().unwrap_or(0);
    }
    0
}

/// Parse a VirtualCell Display string: "Column('Advice', 0)@0(name)"
fn parse_virtual_cell(s: &str, default_row: usize) -> (ColumnInfo, usize) {
    let col_type = if s.contains("'Advice'") {
        ColumnType::Advice
    } else if s.contains("'Fixed'") {
        ColumnType::Fixed
    } else if s.contains("'Instance'") {
        ColumnType::Instance
    } else {
        ColumnType::Advice
    };

    // Extract column index: between ", " and ")"
    let index = s
        .find(", ")
        .and_then(|start| {
            let after = &s[start + 2..];
            after.find(')').and_then(|end| after[..end].parse::<usize>().ok())
        })
        .unwrap_or(0);

    // Extract rotation: after "@"
    let rotation: i32 = s
        .find('@')
        .map(|at_idx| {
            let after = &s[at_idx + 1..];
            let end = after.find(|c: char| c != '-' && !c.is_ascii_digit()).unwrap_or(after.len());
            after[..end].parse().unwrap_or(0)
        })
        .unwrap_or(0);

    let actual_row = (default_row as i32 + rotation).max(0) as usize;

    (ColumnInfo { column_type: col_type, index }, actual_row)
}

/// Convert halo2 `Any` column type to our `ColumnType`.
fn convert_any_column_type(any: &halo2_proofs::plonk::Any) -> ColumnType {
    match any {
        halo2_proofs::plonk::Any::Advice => ColumnType::Advice,
        halo2_proofs::plonk::Any::Fixed => ColumnType::Fixed,
        halo2_proofs::plonk::Any::Instance => ColumnType::Instance,
    }
}

/// Extract column index from a Column's Debug output.
///
/// `Column::index()` is `pub(crate)` in halo2_proofs, so we parse the Debug format:
/// `Column { index: N, column_type: ... }`
fn extract_column_index(column: &impl std::fmt::Debug) -> usize {
    let debug = format!("{:?}", column);
    if let Some(start) = debug.find("index: ") {
        let after = &debug[start + 7..];
        let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        after[..end].parse().unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Column, Error, Instance, Selector},
        poly::Rotation,
    };

    // ─── Test circuit: a + b = sum ──────────────────────────────────────────

    #[derive(Clone)]
    struct AddConfig {
        advice: Column<Advice>,
        _instance: Column<Instance>,
        selector: Selector,
    }

    #[derive(Clone, Default)]
    struct AddCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
    }

    impl Circuit<Fp> for AddCircuit {
        type Config = AddConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fp>) -> AddConfig {
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

    // ─── Tests ──────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_circuit_satisfied() {
        let circuit = AddCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(5)]], 4, "add").unwrap();

        assert!(report.is_satisfied);
        assert_eq!(report.num_failures(), 0);
        assert_eq!(report.circuit_name, "add");
        assert_eq!(report.k, 4);
        assert_eq!(report.stats.num_gates, 1);
    }

    #[test]
    fn test_debug_circuit_constraint_violation() {
        let circuit = AddCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        // Wrong public input: 2 + 3 != 99
        let report = debug_circuit(&circuit, vec![vec![Fp::from(99)]], 4, "add").unwrap();

        assert!(!report.is_satisfied);
        assert!(report.num_failures() > 0);

        let failure = &report.failures[0];
        assert_eq!(failure.gate_name, "add");
        assert!(!failure.hint.is_empty());
    }

    #[test]
    fn test_debug_circuit_display_satisfied() {
        let circuit = AddCircuit { a: Value::known(Fp::from(1)), b: Value::known(Fp::from(1)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(2)]], 4, "test").unwrap();
        let output = report.to_string();
        assert!(output.contains("ALL CONSTRAINTS SATISFIED"));
    }

    #[test]
    fn test_debug_circuit_display_failed() {
        let circuit = AddCircuit { a: Value::known(Fp::from(1)), b: Value::known(Fp::from(1)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(99)]], 4, "test").unwrap();
        let output = report.to_string();
        assert!(output.contains("CONSTRAINT(S) FAILED"));
        assert!(output.contains("Hint:"));
    }

    #[test]
    fn test_debug_circuit_failure_has_cell_values() {
        let circuit = AddCircuit { a: Value::known(Fp::from(10)), b: Value::known(Fp::from(20)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(99)]], 4, "add").unwrap();

        assert!(!report.is_satisfied);
        let failure = &report.failures[0];
        // ConstraintNotSatisfied should have cell values
        assert!(!failure.cell_values.is_empty());
    }

    #[test]
    fn test_debug_circuit_includes_stats() {
        let circuit = AddCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(5)]], 4, "add").unwrap();

        assert_eq!(report.stats.num_advice_columns, 1);
        assert_eq!(report.stats.num_instance_columns, 1);
        assert_eq!(report.stats.num_gates, 1);
        assert_eq!(report.stats.num_rows(), 16);
    }

    #[test]
    fn test_debug_circuit_invalid_k() {
        let circuit = AddCircuit { a: Value::known(Fp::from(1)), b: Value::known(Fp::from(1)) };
        // k=1 → only 2 rows, not enough for the circuit
        let result = debug_circuit(&circuit, vec![vec![Fp::from(2)]], 1, "add");
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_circuit_wrong_instance_count() {
        let circuit = AddCircuit { a: Value::known(Fp::from(1)), b: Value::known(Fp::from(1)) };
        // Circuit needs 1 instance column but we provide 0
        let result = debug_circuit(&circuit, vec![], 4, "add");
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_circuit_serialization() {
        let circuit = AddCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(5)]], 4, "add").unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: DebugReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.circuit_name, "add");
        assert!(deserialized.is_satisfied);
    }

    // ─── Parsing helper tests ───────────────────────────────────────────────

    #[test]
    fn test_extract_gate_name_from_constraint() {
        assert_eq!(extract_gate_name_from_constraint("Constraint 0 in gate 1 ('add')"), "add");
        assert_eq!(
            extract_gate_name_from_constraint("Constraint 2 ('range') in gate 0 ('balance check')"),
            "balance check"
        );
    }

    #[test]
    fn test_extract_gate_name_from_gate() {
        assert_eq!(extract_gate_name_from_gate("Gate 0 ('add')"), "add");
        assert_eq!(extract_gate_name_from_gate("Gate 5 ('balance check')"), "balance check");
    }

    #[test]
    fn test_extract_constraint_index() {
        assert_eq!(extract_constraint_index("Constraint 0 in gate 1 ('add')"), 0);
        assert_eq!(extract_constraint_index("Constraint 3 ('range') in gate 0 ('check')"), 3);
    }

    #[test]
    fn test_parse_virtual_cell_advice() {
        let (col, row) = parse_virtual_cell("Column('Advice', 2)@0", 5);
        assert_eq!(col.column_type, ColumnType::Advice);
        assert_eq!(col.index, 2);
        assert_eq!(row, 5);
    }

    #[test]
    fn test_parse_virtual_cell_with_rotation() {
        let (col, row) = parse_virtual_cell("Column('Advice', 0)@1", 5);
        assert_eq!(col.column_type, ColumnType::Advice);
        assert_eq!(col.index, 0);
        assert_eq!(row, 6); // 5 + 1
    }

    #[test]
    fn test_parse_virtual_cell_instance() {
        let (col, _) = parse_virtual_cell("Column('Instance', 0)@0", 0);
        assert_eq!(col.column_type, ColumnType::Instance);
        assert_eq!(col.index, 0);
    }

    #[test]
    fn test_parse_virtual_cell_with_name() {
        let (col, row) = parse_virtual_cell("Column('Fixed', 1)@-1(constant)", 3);
        assert_eq!(col.column_type, ColumnType::Fixed);
        assert_eq!(col.index, 1);
        assert_eq!(row, 2); // 3 + (-1)
    }

    #[test]
    fn test_parse_virtual_cell_negative_clamp_to_zero() {
        // Negative rotation that would go below row 0 should clamp to 0
        let (_, row) = parse_virtual_cell("Column('Advice', 0)@-5", 2);
        assert_eq!(row, 0); // max(2 + (-5), 0) = 0
    }

    #[test]
    fn test_parse_virtual_cell_unknown_type() {
        // Unknown column type defaults to Advice
        let (col, _) = parse_virtual_cell("Column('Unknown', 0)@0", 0);
        assert_eq!(col.column_type, ColumnType::Advice);
    }

    #[test]
    fn test_extract_row_from_location_offset_format() {
        // Test the extract function with FailureLocation display
        let location = halo2_proofs::dev::FailureLocation::InRegion {
            region: halo2_proofs::dev::metadata::Region::from((0, "test".to_string())),
            offset: 7,
        };
        let row = extract_row_from_location(&location);
        assert_eq!(row, 7);
    }

    #[test]
    fn test_extract_row_from_location_outside_region() {
        let location = halo2_proofs::dev::FailureLocation::OutsideRegion { row: 42 };
        let row = extract_row_from_location(&location);
        assert_eq!(row, 42);
    }

    #[test]
    fn test_convert_any_column_type_all_variants() {
        assert_eq!(convert_any_column_type(&halo2_proofs::plonk::Any::Advice), ColumnType::Advice);
        assert_eq!(convert_any_column_type(&halo2_proofs::plonk::Any::Fixed), ColumnType::Fixed);
        assert_eq!(
            convert_any_column_type(&halo2_proofs::plonk::Any::Instance),
            ColumnType::Instance
        );
    }

    #[test]
    fn test_extract_gate_name_from_constraint_no_quotes() {
        // Fallback: no ('...') found, returns entire string
        let result = extract_gate_name_from_constraint("no quotes here");
        assert_eq!(result, "no quotes here");
    }

    #[test]
    fn test_extract_gate_name_from_gate_no_quotes() {
        let result = extract_gate_name_from_gate("Gate 0 no quotes");
        assert_eq!(result, "Gate 0 no quotes");
    }

    #[test]
    fn test_extract_constraint_index_no_prefix() {
        // No "Constraint " prefix, returns 0
        assert_eq!(extract_constraint_index("some other string"), 0);
    }

    #[test]
    fn test_debug_circuit_multiple_failures() {
        // Create circuit with a=10, b=20, but give a very wrong sum
        let circuit = AddCircuit { a: Value::known(Fp::from(10)), b: Value::known(Fp::from(20)) };
        let report = debug_circuit(&circuit, vec![vec![Fp::from(0)]], 4, "add").unwrap();

        assert!(!report.is_satisfied);
        // Display should list all failures
        let output = report.to_string();
        assert!(output.contains("Failure 1"));
    }
}
