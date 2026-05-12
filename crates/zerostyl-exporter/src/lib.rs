//! Generates [`AbiSchema`] JSON metadata for circuits registered in a `zerostyl_circuits::Registry`.

pub mod error;
pub mod extractor;
pub mod schema;
pub mod version;

pub use error::{ExporterError, Result};
pub use extractor::from_descriptor;
pub use schema::{
    AbiSchema, CircuitMetadata, OnChainBinding, ProofMetadata, ProvingSystem, PublicInputsSchema,
    WitnessSchema,
};
pub use version::ABI_VERSION;
