//! ZeroStyl Privacy Debugger
//!
//! Debugging tools for halo2 zk-SNARK circuits. Provides:
//!
//! - **Circuit inspection**: static analysis of circuit structure (columns, gates, constraints)
//! - **Witness debugging**: enhanced MockProver diagnostics with human-readable failure reports
//! - **Debug reports**: structured output for identifying and fixing constraint violations
//!
//! # Architecture
//!
//! - `types` — Data structures for circuit stats, constraint info, and debug reports
//! - `error` — Error types for the debugger
//! - `inspector` — Static analysis of circuit structure via constraint system introspection
//! - `witness` — Enhanced MockProver wrapper with structured failure diagnostics

pub mod error;
pub mod inspector;
pub mod types;
pub mod witness;

pub use error::{DebugError, Result};
pub use inspector::inspect_circuit;
pub use types::{
    CircuitStats, ColumnInfo, ColumnType, ConstraintFailure, ConstraintInfo, DebugReport,
    WitnessInfo,
};
pub use witness::debug_circuit;
