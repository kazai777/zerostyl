//! Core abstractions for plugging zk circuits into the ZeroStyl toolkit.
//!
//! Each circuit exposes a `&'static dyn CircuitDescriptor` from its own crate.
//! The CLI and debugger consume circuits through a [`Registry`] populated at
//! startup, so adding a new circuit never requires editing the dispatcher.

pub mod abi;
pub mod descriptor;
pub mod error;
pub mod proof;
pub mod registry;
pub mod report;
pub mod schema;

pub use abi::AbiMetadata;
pub use descriptor::CircuitDescriptor;
pub use error::{CircuitError, Result};
pub use proof::ProofArtifact;
pub use registry::Registry;
pub use report::{
    CircuitIntrospection, ColumnInfo, FailureEntry, FailureKind, GateInfo, MockProverReport,
};
pub use schema::{
    FieldType, FieldVisibility, PublicInputField, PublicInputsSchema, WitnessField, WitnessSchema,
};
