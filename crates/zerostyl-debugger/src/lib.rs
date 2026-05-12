//! ZeroStyl Debugger — formatters for descriptor diagnostics.
//!
//! The actual circuit introspection lives inside each `CircuitDescriptor`
//! (see `zerostyl-circuits`). This crate exposes pure formatters that turn
//! the structured diagnostics into human-readable output for the CLI.

pub mod inspector;
pub mod witness;

pub use inspector::format_introspection;
pub use witness::{format_mock_prover_report, OutputFormat};
