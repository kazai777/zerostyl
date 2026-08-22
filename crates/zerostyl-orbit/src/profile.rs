//! Per-chain configuration profiles.
//!
//! A [`ChainProfile`] captures the deployment-relevant configuration of an Arbitrum or Orbit
//! chain: contract/WASM size limits, the gas/ink model, and which precompiles are available.
//! Built-in profiles cover the public Arbitrum chains; custom Orbit chains are loaded from a TOML
//! file (see [`ChainProfile::load_file`]).

use serde::{Deserialize, Serialize};

use crate::error::{OrbitError, Result};
use crate::precompiles::PrecompileSet;
use crate::{
    ARBOS_WASM_SIZE_BUMP_VERSION, EIP170_MAX_CODE_SIZE, INK_PER_GAS, MAX_CONFIGURABLE_CODE_SIZE,
    STYLUS_ARBOS60_MAX_WASM_SIZE, STYLUS_DEFAULT_MAX_WASM_SIZE,
};

/// Size limits that gate deployment.
///
/// `max_code_size` is the **compressed** (Brotli) on-chain code cap — the one Stylus deployment
/// hits first (24 KB default, up to 96 KB on a custom chain). `max_wasm_size` is the
/// **decompressed** WASM cap (`MaxWasmSize`: 128 KB, or 256 KB at ArbOS ≥ 60).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeLimits {
    /// Compressed on-chain code cap, in bytes (`MaxCodeSize`).
    pub max_code_size: usize,
    /// Decompressed WASM cap, in bytes (`MaxWasmSize`).
    pub max_wasm_size: usize,
    /// Init-code cap, in bytes (`MaxInitCodeSize`).
    pub max_init_code_size: usize,
}

impl SizeLimits {
    /// Standard (non-custom) Arbitrum limits for a given ArbOS version: EIP-170 compressed cap,
    /// and the 128 KB → 256 KB `MaxWasmSize` bump at ArbOS 60.
    #[must_use]
    pub fn standard_for_arbos(arbos_version: u32) -> Self {
        let max_wasm_size = if arbos_version >= ARBOS_WASM_SIZE_BUMP_VERSION {
            STYLUS_ARBOS60_MAX_WASM_SIZE
        } else {
            STYLUS_DEFAULT_MAX_WASM_SIZE
        };
        Self {
            max_code_size: EIP170_MAX_CODE_SIZE,
            max_wasm_size,
            max_init_code_size: 2 * EIP170_MAX_CODE_SIZE,
        }
    }
}

/// The gas/ink model of a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GasModel {
    /// Ink units per gas unit (fixed at 10 000 across Arbitrum).
    pub ink_per_gas: u64,
    /// Ink price in wei, when known (chain-owner configurable; `None` = chain default).
    pub ink_price_wei: Option<u64>,
}

impl Default for GasModel {
    fn default() -> Self {
        Self { ink_per_gas: INK_PER_GAS, ink_price_wei: None }
    }
}

/// Recommended compressed/decompressed budgets for a WASM artifact on a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmBudget {
    /// Max compressed (Brotli) size, bytes.
    pub compressed: usize,
    /// Max decompressed size, bytes.
    pub uncompressed: usize,
}

/// Deployment-relevant configuration of one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProfile {
    /// Short identifier (e.g. `"arbitrum-sepolia"`).
    pub name: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// ArbOS version the chain runs (drives the default `MaxWasmSize`).
    pub arbos_version: u32,
    /// Size limits.
    pub limits: SizeLimits,
    /// Gas/ink model.
    #[serde(default)]
    pub gas: GasModel,
    /// Available precompiles.
    #[serde(default)]
    pub precompiles: PrecompileSet,
}

impl ChainProfile {
    /// The WASM size budget: compressed = `max_code_size`, uncompressed = `max_wasm_size`.
    #[must_use]
    pub fn wasm_budget(&self) -> WasmBudget {
        WasmBudget {
            compressed: self.limits.max_code_size,
            uncompressed: self.limits.max_wasm_size,
        }
    }

    /// A `[profile.release]` snippet tuned for small Stylus WASM, matching the workspace profile.
    #[must_use]
    pub fn recommended_cargo_profile(&self) -> &'static str {
        "[profile.release]\n\
         opt-level = \"z\"\n\
         lto = true\n\
         codegen-units = 1\n\
         panic = \"abort\"\n\
         strip = true\n"
    }

    /// Parse a profile from a TOML string.
    ///
    /// # Errors
    /// Returns [`OrbitError::Toml`] on malformed TOML, or [`OrbitError::InvalidProfile`] on a
    /// structurally invalid profile.
    pub fn load_str(toml_src: &str) -> Result<Self> {
        let profile: ChainProfile = toml::from_str(toml_src)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Read and parse a profile from a TOML file.
    ///
    /// # Errors
    /// Returns [`OrbitError::Io`] if the file cannot be read, else as [`Self::load_str`].
    pub fn load_file(path: &std::path::Path) -> Result<Self> {
        let src = std::fs::read_to_string(path)?;
        Self::load_str(&src)
    }

    /// Serialize the profile to a TOML string.
    #[must_use]
    pub fn to_toml(&self) -> String {
        // Serialization of this fixed structure cannot fail.
        toml::to_string_pretty(self).expect("ChainProfile serializes to TOML")
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(OrbitError::InvalidProfile("name is empty".into()));
        }
        if self.limits.max_code_size == 0 || self.limits.max_wasm_size == 0 {
            return Err(OrbitError::InvalidProfile("size limits must be non-zero".into()));
        }
        if self.limits.max_code_size > self.limits.max_wasm_size {
            return Err(OrbitError::InvalidProfile(
                "max_code_size (compressed) cannot exceed max_wasm_size (decompressed)".into(),
            ));
        }
        Ok(())
    }
}

/// Built-in profile: Arbitrum One (mainnet).
#[must_use]
pub fn arbitrum_one() -> ChainProfile {
    ChainProfile {
        name: "arbitrum-one".into(),
        chain_id: 42161,
        arbos_version: 60,
        limits: SizeLimits::standard_for_arbos(60),
        gas: GasModel::default(),
        precompiles: PrecompileSet::default(),
    }
}

/// Built-in profile: Arbitrum Nova.
#[must_use]
pub fn arbitrum_nova() -> ChainProfile {
    ChainProfile {
        name: "arbitrum-nova".into(),
        chain_id: 42170,
        arbos_version: 60,
        limits: SizeLimits::standard_for_arbos(60),
        gas: GasModel::default(),
        precompiles: PrecompileSet::default(),
    }
}

/// Built-in profile: Arbitrum Sepolia (testnet) — where ZeroStyl's demo contracts are deployed.
#[must_use]
pub fn arbitrum_sepolia() -> ChainProfile {
    ChainProfile {
        name: "arbitrum-sepolia".into(),
        chain_id: 421614,
        arbos_version: 60,
        limits: SizeLimits::standard_for_arbos(60),
        gas: GasModel::default(),
        precompiles: PrecompileSet::default(),
    }
}

/// Template for a custom Orbit chain configured for large Stylus contracts (compressed cap raised
/// to the 96 KB maximum, `MaxWasmSize` at the ArbOS-60 256 KB). Copy and edit for your chain.
#[must_use]
pub fn orbit_template() -> ChainProfile {
    ChainProfile {
        name: "my-orbit-chain".into(),
        chain_id: 0,
        arbos_version: 60,
        limits: SizeLimits {
            max_code_size: MAX_CONFIGURABLE_CODE_SIZE,
            max_wasm_size: STYLUS_ARBOS60_MAX_WASM_SIZE,
            max_init_code_size: 2 * MAX_CONFIGURABLE_CODE_SIZE,
        },
        gas: GasModel::default(),
        precompiles: PrecompileSet::default(),
    }
}

/// All built-in profiles, in display order.
#[must_use]
pub fn builtins() -> Vec<ChainProfile> {
    vec![arbitrum_one(), arbitrum_nova(), arbitrum_sepolia(), orbit_template()]
}

/// Look up a built-in profile by name.
#[must_use]
pub fn builtin(name: &str) -> Option<ChainProfile> {
    builtins().into_iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_valid_and_named() {
        for p in builtins() {
            assert!(p.validate().is_ok(), "{} invalid", p.name);
            assert!(!p.name.is_empty());
        }
    }

    #[test]
    fn sepolia_matches_deployments_chain_id() {
        assert_eq!(arbitrum_sepolia().chain_id, 421614);
    }

    #[test]
    fn arbos60_bumps_wasm_size_to_256k() {
        assert_eq!(SizeLimits::standard_for_arbos(60).max_wasm_size, STYLUS_ARBOS60_MAX_WASM_SIZE);
        assert_eq!(SizeLimits::standard_for_arbos(11).max_wasm_size, STYLUS_DEFAULT_MAX_WASM_SIZE);
    }

    #[test]
    fn standard_chain_uses_eip170_compressed_cap() {
        assert_eq!(arbitrum_sepolia().limits.max_code_size, EIP170_MAX_CODE_SIZE);
    }

    #[test]
    fn orbit_template_raises_caps() {
        let t = orbit_template();
        assert_eq!(t.limits.max_code_size, MAX_CONFIGURABLE_CODE_SIZE);
        assert!(t.wasm_budget().compressed > arbitrum_one().wasm_budget().compressed);
    }

    #[test]
    fn toml_round_trips() {
        let original = orbit_template();
        let toml_src = original.to_toml();
        let parsed = ChainProfile::load_str(&toml_src).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn toml_defaults_gas_and_precompiles() {
        // A minimal profile omitting [gas] and [precompiles] gets sane defaults.
        let src = r#"
            name = "minimal"
            chain_id = 1234
            arbos_version = 60
            [limits]
            max_code_size = 24576
            max_wasm_size = 131072
            max_init_code_size = 49152
        "#;
        let p = ChainProfile::load_str(src).unwrap();
        assert_eq!(p.gas.ink_per_gas, INK_PER_GAS);
        assert!(p.precompiles.bn256_pairing);
    }

    #[test]
    fn rejects_compressed_gt_uncompressed() {
        let src = r#"
            name = "bad"
            chain_id = 1
            arbos_version = 60
            [limits]
            max_code_size = 200000
            max_wasm_size = 131072
            max_init_code_size = 49152
        "#;
        assert!(ChainProfile::load_str(src).is_err());
    }
}
