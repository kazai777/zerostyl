//! Rust SDK for the ZeroStyl zk toolkit on Arbitrum Stylus.
//!
//! This crate is a thin, ergonomic facade over the toolkit's stable core:
//!
//! - [`ZeroStyl`] — a client owning a circuit [`Registry`] and a key cache
//!   directory, handing out [`CircuitHandle`]s for proving and verification.
//! - [`WitnessBuilder`] — builds the witness JSON a
//!   [`CircuitDescriptor`] expects, with optional schema checking.
//! - [`abi`] — loads and validates `abi.json` ([`AbiSchema`]) files produced
//!   by the exporter.
//! - [`inputs`] — encodes/decodes the public-inputs JSON wire format
//!   (32-byte little-endian field representations as `0x`-hex strings).
//! - Proof envelope helpers ([`CircuitHandle::seal`] / [`CircuitHandle::open`])
//!   wrapping raw proof bytes in the [`CanonicalProof`] wire format.
//!
//! # Example
//!
//! ```no_run
//! use zerostyl_sdk::{WitnessBuilder, ZeroStyl};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = ZeroStyl::new()?;
//! client.register(zk_private_demo::descriptor())?;
//!
//! let witness = WitnessBuilder::new()
//!     .set_u64("collateral", 500_000)
//!     .set_u64("collateral_nonce", 42)
//!     .set_u64("threshold", 100_000)
//!     .build();
//!
//! let circuit = client.circuit("deposit")?;
//! let artifact = circuit.prove(&witness)?;
//! assert!(circuit.verify(&artifact.bytes, &artifact.public_inputs_json)?);
//! # Ok(())
//! # }
//! ```

pub mod abi;
pub mod client;
pub mod error;
pub mod inputs;
pub mod witness;

pub use abi::{load_abi_file, load_abi_str};
pub use client::{CircuitHandle, ZeroStyl};
pub use error::{Result, SdkError};
pub use inputs::{decode_public_inputs, encode_public_inputs, fr_hex, parse_fr_hex};
pub use witness::WitnessBuilder;

// Stable core types, re-exported so SDK users need a single dependency.
pub use zerostyl_circuits::{
    register_circuit, AbiSchema, CanonicalProof, CircuitDescriptor, CircuitError,
    CircuitIntrospection, CircuitMetadata, FieldType, FieldVisibility, MockProverReport,
    OnChainBinding, ProofArtifact, ProofMetadata, ProvingSystem, PublicInputField,
    PublicInputsSchema, Registry, WitnessField, WitnessSchema, ABI_VERSION,
};
pub use zerostyl_runtime::{BytecodeFingerprint, ZeroStylPrivacyTransaction, DEV_SRS_SEED};
