//! Orbit zk-Adapter for the ZeroStyl toolkit.
//!
//! Describes the deployment-relevant configuration of Arbitrum and Orbit chains — contract/WASM
//! size limits, the gas/ink model, and available precompiles — and answers the question the rest
//! of the toolkit only documents in prose: **can this WASM artifact be deployed on this chain, and
//! can this proving system be verified on-chain there?**
//!
//! - [`ChainProfile`] — one chain's limits/gas/precompiles; built-ins ([`arbitrum_one`],
//!   [`arbitrum_sepolia`], …) or loaded from a TOML file ([`ChainProfile::load_file`]).
//! - [`assess`] — size a [`ArtifactSize`] against a chain's caps → [`DeployabilityReport`].
//! - [`assess_verification`] — does a chain expose the precompiles a [`zerostyl_circuits::ProvingSystem`]
//!   needs for on-chain verification (BN254 pairing for KZG/Groth16)?
//!
//! Scope: **analysis and configuration only** — no RPC, signing, or deployment. Use `cargo-stylus`
//! to actually deploy; the Brotli figure here is indicative, not byte-identical to it.

pub mod deployability;
pub mod error;
pub mod precompiles;
pub mod profile;

mod cli;

pub use cli::run;
pub use deployability::{
    assess, assess_verification, ArtifactSize, DeployabilityReport, SizeCheck, VerificationReport,
};
pub use error::{OrbitError, Result};
pub use precompiles::{required_for, Precompile, PrecompileSet};
pub use profile::{
    arbitrum_nova, arbitrum_one, arbitrum_sepolia, builtin, builtins, orbit_template, ChainProfile,
    GasModel, SizeLimits, WasmBudget,
};

// ── Chain-parameter constants ───────────────────────────────────────────────
// These live only in prose elsewhere in the repo (contracts/CONTRACTS.md, zerostyl-verifier
// docs); this crate is their single source of truth.

/// EIP-170 default max contract (compressed) code size: 24 KB.
pub const EIP170_MAX_CODE_SIZE: usize = 24_576;

/// Maximum `MaxCodeSize` configurable on a custom Orbit chain (at genesis): 96 KB.
pub const MAX_CONFIGURABLE_CODE_SIZE: usize = 98_304;

/// Default `MaxWasmSize` (decompressed WASM cap): 128 KB.
pub const STYLUS_DEFAULT_MAX_WASM_SIZE: usize = 131_072;

/// `MaxWasmSize` from ArbOS 60 onward: 256 KB.
pub const STYLUS_ARBOS60_MAX_WASM_SIZE: usize = 262_144;

/// ArbOS version at which the `MaxWasmSize` default rises from 128 KB to 256 KB.
pub const ARBOS_WASM_SIZE_BUMP_VERSION: u32 = 60;

/// Fixed ink-to-gas ratio across Arbitrum: 10 000 ink = 1 gas.
pub const INK_PER_GAS: u64 = 10_000;
