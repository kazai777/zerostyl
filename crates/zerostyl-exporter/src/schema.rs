//! Re-exports of the canonical ABI schema types.
//!
//! The types live in `zerostyl_circuits::abi` so that SDK crates can consume
//! them without depending on the exporter; this module keeps the exporter's
//! historical import paths working.

pub use zerostyl_circuits::{
    AbiSchema, CircuitMetadata, OnChainBinding, ProofMetadata, ProvingSystem, PublicInputsSchema,
    WitnessSchema,
};
