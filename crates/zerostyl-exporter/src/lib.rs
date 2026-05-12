//! Generates [`AbiSchema`] JSON metadata for circuits registered in a `zerostyl_circuits::Registry`.

pub mod cli;
pub mod error;
pub mod extractor;
pub mod parser;
pub mod schema;
pub mod version;

pub use cli::run;
pub use error::{ExporterError, Result};
pub use extractor::from_descriptor;
pub use parser::{
    parse_fn, AttrSpec, CommitScheme, Constraint, MerkleMemberSpec, RangeSpec, ZkPrivateAttr,
};
pub use schema::{
    AbiSchema, CircuitMetadata, OnChainBinding, ProofMetadata, ProvingSystem, PublicInputsSchema,
    WitnessSchema,
};
pub use version::ABI_VERSION;
