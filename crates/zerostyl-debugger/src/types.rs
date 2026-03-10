//! Types for circuit inspection and debugging.
//!
//! These types represent the static and dynamic analysis results
//! of halo2 circuits, providing structured diagnostics for developers.

use serde::{Deserialize, Serialize};

// ─── Column metadata ────────────────────────────────────────────────────────

/// Type of a column in a halo2 circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    Advice,
    Instance,
    Fixed,
}

impl std::fmt::Display for ColumnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ColumnType::Advice => write!(f, "advice"),
            ColumnType::Instance => write!(f, "instance"),
            ColumnType::Fixed => write!(f, "fixed"),
        }
    }
}

/// Metadata about a single column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub column_type: ColumnType,
    pub index: usize,
}

impl std::fmt::Display for ColumnInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}[{}]", self.column_type, self.index)
    }
}

// ─── Constraint metadata ────────────────────────────────────────────────────

/// Information about a single constraint expression within a gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintInfo {
    pub gate_name: String,
    pub gate_index: usize,
    pub expression_index: usize,
    pub degree: usize,
}

impl std::fmt::Display for ConstraintInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "gate[{}] \"{}\" expr[{}] (degree {})",
            self.gate_index, self.gate_name, self.expression_index, self.degree
        )
    }
}

// ─── Circuit statistics ─────────────────────────────────────────────────────

/// Static analysis statistics for a halo2 circuit.
///
/// Extracted from a configured `ConstraintSystem` without running any prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStats {
    pub name: String,
    pub k: u32,
    pub num_advice_columns: usize,
    pub num_instance_columns: usize,
    pub num_fixed_columns: usize,
    pub num_selectors: usize,
    pub num_gates: usize,
    pub num_constraints: usize,
    pub degree: usize,
    pub constraints: Vec<ConstraintInfo>,
}

impl CircuitStats {
    /// Total number of rows in the circuit (2^k).
    pub fn num_rows(&self) -> usize {
        1 << self.k
    }

    /// Total number of columns (advice + instance + fixed).
    pub fn total_columns(&self) -> usize {
        self.num_advice_columns + self.num_instance_columns + self.num_fixed_columns
    }
}

impl std::fmt::Display for CircuitStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Circuit: {}", self.name)?;
        writeln!(f, "  k: {} (2^k = {} rows)", self.k, self.num_rows())?;
        writeln!(f, "  Columns: {} total", self.total_columns())?;
        writeln!(f, "    advice:   {}", self.num_advice_columns)?;
        writeln!(f, "    instance: {}", self.num_instance_columns)?;
        writeln!(f, "    fixed:    {}", self.num_fixed_columns)?;
        writeln!(f, "  Selectors: {}", self.num_selectors)?;
        writeln!(f, "  Gates: {}", self.num_gates)?;
        writeln!(f, "  Constraints: {} (max degree {})", self.num_constraints, self.degree)?;
        for c in &self.constraints {
            writeln!(f, "    - {}", c)?;
        }
        Ok(())
    }
}

// ─── Witness information ────────────────────────────────────────────────────

/// Debug information for a witness cell assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessInfo {
    pub column: ColumnInfo,
    pub row: usize,
    pub value: Option<String>,
}

impl std::fmt::Display for WitnessInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.value {
            Some(v) => write!(f, "{} row {} = {}", self.column, self.row, v),
            None => write!(f, "{} row {} = <unassigned>", self.column, self.row),
        }
    }
}

// ─── Constraint failure ─────────────────────────────────────────────────────

/// A single constraint that failed verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintFailure {
    pub gate_name: String,
    pub row: usize,
    pub expression_index: usize,
    pub cell_values: Vec<WitnessInfo>,
    pub hint: String,
}

impl std::fmt::Display for ConstraintFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "FAILED: gate \"{}\" at row {}", self.gate_name, self.row)?;
        writeln!(f, "  Expression index: {}", self.expression_index)?;
        if !self.cell_values.is_empty() {
            writeln!(f, "  Cell values:")?;
            for cell in &self.cell_values {
                writeln!(f, "    - {}", cell)?;
            }
        }
        writeln!(f, "  Hint: {}", self.hint)?;
        Ok(())
    }
}

// ─── Debug report ───────────────────────────────────────────────────────────

/// Complete debug report for a circuit execution.
///
/// Contains both static analysis (circuit stats) and dynamic analysis
/// (constraint failures from MockProver).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugReport {
    pub circuit_name: String,
    pub k: u32,
    pub is_satisfied: bool,
    pub failures: Vec<ConstraintFailure>,
    pub stats: CircuitStats,
}

impl DebugReport {
    /// Number of failed constraints.
    pub fn num_failures(&self) -> usize {
        self.failures.len()
    }
}

impl std::fmt::Display for DebugReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Debug Report: {} ===", self.circuit_name)?;
        writeln!(f)?;
        write!(f, "{}", self.stats)?;
        writeln!(f)?;
        if self.is_satisfied {
            writeln!(f, "Result: ALL CONSTRAINTS SATISFIED")?;
        } else {
            writeln!(f, "Result: {} CONSTRAINT(S) FAILED", self.num_failures())?;
            writeln!(f)?;
            for (i, failure) in self.failures.iter().enumerate() {
                writeln!(f, "--- Failure {} ---", i + 1)?;
                write!(f, "{}", failure)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_type_display() {
        assert_eq!(ColumnType::Advice.to_string(), "advice");
        assert_eq!(ColumnType::Instance.to_string(), "instance");
        assert_eq!(ColumnType::Fixed.to_string(), "fixed");
    }

    #[test]
    fn test_column_info_display() {
        let col = ColumnInfo { column_type: ColumnType::Advice, index: 3 };
        assert_eq!(col.to_string(), "advice[3]");
    }

    #[test]
    fn test_column_info_equality() {
        let a = ColumnInfo { column_type: ColumnType::Advice, index: 0 };
        let b = ColumnInfo { column_type: ColumnType::Advice, index: 0 };
        let c = ColumnInfo { column_type: ColumnType::Instance, index: 0 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_constraint_info_display() {
        let info = ConstraintInfo {
            gate_name: "balance check".to_string(),
            gate_index: 2,
            expression_index: 0,
            degree: 3,
        };
        assert_eq!(info.to_string(), "gate[2] \"balance check\" expr[0] (degree 3)");
    }

    #[test]
    fn test_circuit_stats_num_rows() {
        let stats = CircuitStats {
            name: "test".to_string(),
            k: 10,
            num_advice_columns: 5,
            num_instance_columns: 1,
            num_fixed_columns: 2,
            num_selectors: 3,
            num_gates: 4,
            num_constraints: 6,
            degree: 3,
            constraints: vec![],
        };
        assert_eq!(stats.num_rows(), 1024);
        assert_eq!(stats.total_columns(), 8);
    }

    #[test]
    fn test_circuit_stats_display() {
        let stats = CircuitStats {
            name: "example".to_string(),
            k: 4,
            num_advice_columns: 1,
            num_instance_columns: 1,
            num_fixed_columns: 0,
            num_selectors: 1,
            num_gates: 1,
            num_constraints: 1,
            degree: 2,
            constraints: vec![ConstraintInfo {
                gate_name: "add".to_string(),
                gate_index: 0,
                expression_index: 0,
                degree: 2,
            }],
        };
        let output = stats.to_string();
        assert!(output.contains("Circuit: example"));
        assert!(output.contains("k: 4"));
        assert!(output.contains("16 rows"));
        assert!(output.contains("Gates: 1"));
        assert!(output.contains("gate[0] \"add\""));
    }

    #[test]
    fn test_witness_info_with_value() {
        let info = WitnessInfo {
            column: ColumnInfo { column_type: ColumnType::Advice, index: 0 },
            row: 5,
            value: Some("42".to_string()),
        };
        assert_eq!(info.to_string(), "advice[0] row 5 = 42");
    }

    #[test]
    fn test_witness_info_unassigned() {
        let info = WitnessInfo {
            column: ColumnInfo { column_type: ColumnType::Advice, index: 0 },
            row: 0,
            value: None,
        };
        assert!(info.to_string().contains("<unassigned>"));
    }

    #[test]
    fn test_constraint_failure_display() {
        let failure = ConstraintFailure {
            gate_name: "balance check".to_string(),
            row: 3,
            expression_index: 0,
            cell_values: vec![WitnessInfo {
                column: ColumnInfo { column_type: ColumnType::Advice, index: 0 },
                row: 3,
                value: Some("1000".to_string()),
            }],
            hint: "balance_old - amount != balance_new".to_string(),
        };
        let output = failure.to_string();
        assert!(output.contains("FAILED: gate \"balance check\" at row 3"));
        assert!(output.contains("advice[0] row 3 = 1000"));
        assert!(output.contains("balance_old - amount != balance_new"));
    }

    #[test]
    fn test_debug_report_satisfied() {
        let stats = CircuitStats {
            name: "test".to_string(),
            k: 4,
            num_advice_columns: 1,
            num_instance_columns: 1,
            num_fixed_columns: 0,
            num_selectors: 1,
            num_gates: 1,
            num_constraints: 1,
            degree: 2,
            constraints: vec![],
        };
        let report = DebugReport {
            circuit_name: "test".to_string(),
            k: 4,
            is_satisfied: true,
            failures: vec![],
            stats,
        };
        assert_eq!(report.num_failures(), 0);
        assert!(report.to_string().contains("ALL CONSTRAINTS SATISFIED"));
    }

    #[test]
    fn test_debug_report_failed() {
        let stats = CircuitStats {
            name: "test".to_string(),
            k: 4,
            num_advice_columns: 1,
            num_instance_columns: 1,
            num_fixed_columns: 0,
            num_selectors: 1,
            num_gates: 1,
            num_constraints: 1,
            degree: 2,
            constraints: vec![],
        };
        let report = DebugReport {
            circuit_name: "test".to_string(),
            k: 4,
            is_satisfied: false,
            failures: vec![ConstraintFailure {
                gate_name: "add".to_string(),
                row: 0,
                expression_index: 0,
                cell_values: vec![],
                hint: "a + b != sum".to_string(),
            }],
            stats,
        };
        assert_eq!(report.num_failures(), 1);
        let output = report.to_string();
        assert!(output.contains("1 CONSTRAINT(S) FAILED"));
        assert!(output.contains("a + b != sum"));
    }

    #[test]
    fn test_debug_report_serialization() {
        let stats = CircuitStats {
            name: "test".to_string(),
            k: 4,
            num_advice_columns: 1,
            num_instance_columns: 1,
            num_fixed_columns: 0,
            num_selectors: 1,
            num_gates: 1,
            num_constraints: 1,
            degree: 2,
            constraints: vec![],
        };
        let report = DebugReport {
            circuit_name: "test".to_string(),
            k: 4,
            is_satisfied: true,
            failures: vec![],
            stats,
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: DebugReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.circuit_name, "test");
        assert!(deserialized.is_satisfied);
        assert_eq!(deserialized.stats.k, 4);
    }
}
