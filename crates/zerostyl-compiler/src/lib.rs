//! ZeroStyl Compiler
//!
//! Compiles Rust code with `#[zk_private]` annotations to halo2 zk-SNARK circuits
//! for deployment on Arbitrum Stylus.

pub mod ast;
pub mod circuit;
pub mod codegen;
pub mod error;
pub mod parser;

/// halo2 circuit gadgets. Re-exported from the standalone, `no_std` `zerostyl-gadgets` crate so
/// existing `zerostyl_compiler::gadgets::*` paths keep working while the gadgets themselves can be
/// compiled for `wasm32` independently of this (std-only) compiler crate.
pub use zerostyl_gadgets as gadgets;

pub use ast::{
    compute_k, ArithOp, CircuitIR, ComparisonOp, Constraint, HashType, InterFieldConstraint,
    ZkField, ZkType,
};
pub use circuit::{validate_circuit_ir, CircuitBuilder, ZkCircuit, ZkCircuitConfig};
pub use codegen::{validate_wasm, CircuitMetadata, CodegenConfig, WasmCodegen};
pub use error::{CompilerError, Result};
pub use parser::{parse_contract, ParsedContract, PrivateField};

// Re-export runtime types for convenience
pub use zerostyl_runtime::CircuitConfig;

// Re-export the main transformation function
pub use ast::transform_to_ir;
