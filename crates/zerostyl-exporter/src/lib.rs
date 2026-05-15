//! Generates [`AbiSchema`] JSON metadata for circuits registered in a `zerostyl_circuits::Registry`.

pub mod cli;
pub mod codegen;
pub mod error;
pub mod extractor;
pub mod parser;
pub mod resolver;
pub mod schema;
pub mod transform;
pub mod version;

pub use cli::run;
pub use codegen::{emit_circuit, emit_descriptor, emit_transformed_contract};
pub use error::{ExporterError, Result};
pub use extractor::{emit_abi_json, from_attrs, from_descriptor};
pub use parser::{
    parse_fn, AttrSpec, CommitScheme, Constraint, MerkleMemberSpec, RangeSpec, ZkPrivateAttr,
};
pub use resolver::{resolve, resolve_all, ComparisonOp, GadgetBinding, ResolvedAttr, MERKLE_DEPTH};
pub use schema::{
    AbiSchema, CircuitMetadata, OnChainBinding, ProofMetadata, ProvingSystem, PublicInputsSchema,
    WitnessSchema,
};
pub use transform::{transform_contract, TransformReport};
pub use version::ABI_VERSION;
