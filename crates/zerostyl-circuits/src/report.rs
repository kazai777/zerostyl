use serde::{Deserialize, Serialize};

/// Result of running the `MockProver` against a witness.
///
/// Structured so the debugger never has to import halo2 types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockProverReport {
    pub circuit_name: String,
    pub k: u32,
    pub satisfied: bool,
    pub failures: Vec<FailureEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureEntry {
    pub kind: FailureKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    ConstraintNotSatisfied,
    Permutation,
    InstanceCellMismatch,
    Lookup,
}

/// Static introspection of a circuit's shape — columns, gates, degree.
///
/// Powers the `inspect` debugger command without exposing halo2 internals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitIntrospection {
    pub circuit_name: String,
    pub k: u32,
    pub num_advice_columns: usize,
    pub num_fixed_columns: usize,
    pub num_instance_columns: usize,
    pub num_selectors: usize,
    pub max_constraint_degree: usize,
    pub gates: Vec<GateInfo>,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInfo {
    pub name: String,
    pub constraint_count: usize,
    pub max_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub kind: String,
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
}
