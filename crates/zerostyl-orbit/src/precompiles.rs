//! Precompiles relevant to ZeroStyl deployment and on-chain verification.
//!
//! Arbitrum Nitro supports every standard Ethereum precompile (including the BN254 pairing at
//! `0x08`, which a KZG/Groth16 on-chain verifier needs), plus Arbitrum-specific ones such as
//! `ArbOwner` (`0x70`) and `ArbWasm` (`0x71`). An Orbit chain may customize or remove precompiles,
//! so availability is modeled per [`ChainProfile`](crate::ChainProfile).

use serde::{Deserialize, Serialize};

use zerostyl_circuits::ProvingSystem;

/// A precompile identified by its low address byte and canonical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Precompile {
    /// Low byte of the 20-byte address (all relevant precompiles live in `0x00..=0xff`).
    pub address: u8,
    /// Canonical name.
    pub name: &'static str,
}

// Standard Ethereum precompiles used by BN254 proof verification.
pub const MODEXP: Precompile = Precompile { address: 0x05, name: "modexp" };
pub const EC_ADD: Precompile = Precompile { address: 0x06, name: "ecAdd (bn256)" };
pub const EC_MUL: Precompile = Precompile { address: 0x07, name: "ecMul (bn256)" };
pub const BN256_PAIRING: Precompile = Precompile { address: 0x08, name: "ecPairing (bn256)" };

// Arbitrum-specific precompiles (informational; used by Stylus tooling / chain owners).
pub const ARB_GAS_INFO: Precompile = Precompile { address: 0x6c, name: "ArbGasInfo" };
pub const ARB_OWNER: Precompile = Precompile { address: 0x70, name: "ArbOwner" };
pub const ARB_WASM: Precompile = Precompile { address: 0x71, name: "ArbWasm" };

/// Which precompiles are available on a chain.
///
/// Defaults to a standard Arbitrum/Orbit chain: all Ethereum precompiles present, Arbitrum
/// precompiles present. Set a field to `false` to model an Orbit chain that removed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrecompileSet {
    /// `0x05` modexp.
    pub modexp: bool,
    /// `0x06` bn256 addition.
    pub ec_add: bool,
    /// `0x07` bn256 scalar multiplication.
    pub ec_mul: bool,
    /// `0x08` bn256 pairing — required for KZG/Groth16 on-chain verification.
    pub bn256_pairing: bool,
    /// Arbitrum-specific precompiles (`ArbOwner`, `ArbWasm`, `ArbGasInfo`, …).
    pub arbitrum: bool,
}

impl Default for PrecompileSet {
    fn default() -> Self {
        Self { modexp: true, ec_add: true, ec_mul: true, bn256_pairing: true, arbitrum: true }
    }
}

impl PrecompileSet {
    /// Whether a given precompile is available.
    #[must_use]
    pub fn has(&self, p: Precompile) -> bool {
        match p.address {
            0x05 => self.modexp,
            0x06 => self.ec_add,
            0x07 => self.ec_mul,
            0x08 => self.bn256_pairing,
            0x6c | 0x70 | 0x71 => self.arbitrum,
            _ => false,
        }
    }
}

/// The precompiles an on-chain verifier for `system` would require.
///
/// KZG-on-BN254 and the Groth16 wrap both reduce to a BN254 pairing check, so they need the
/// `0x06`/`0x07`/`0x08` trio. Transparent systems (STARK/FRI) need none. IPA-on-Pasta cannot use
/// the BN254 precompiles at all (different curve), so it has no supported on-chain path here.
#[must_use]
pub fn required_for(system: ProvingSystem) -> &'static [Precompile] {
    match system {
        ProvingSystem::Halo2Kzg | ProvingSystem::Halo2KzgGroth16Wrap => {
            &[EC_ADD, EC_MUL, BN256_PAIRING]
        }
        ProvingSystem::StarkFri => &[],
        ProvingSystem::Halo2Ipa => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_has_everything() {
        let s = PrecompileSet::default();
        assert!(s.has(BN256_PAIRING));
        assert!(s.has(EC_ADD));
        assert!(s.has(ARB_WASM));
    }

    #[test]
    fn removing_pairing_is_reflected() {
        let s = PrecompileSet { bn256_pairing: false, ..Default::default() };
        assert!(!s.has(BN256_PAIRING));
        assert!(s.has(EC_ADD));
    }

    #[test]
    fn kzg_requires_bn256_pairing() {
        let req = required_for(ProvingSystem::Halo2Kzg);
        assert!(req.contains(&BN256_PAIRING));
        assert!(req.contains(&EC_ADD));
        assert!(req.contains(&EC_MUL));
    }

    #[test]
    fn groth16_wrap_requires_pairing() {
        assert!(required_for(ProvingSystem::Halo2KzgGroth16Wrap).contains(&BN256_PAIRING));
    }

    #[test]
    fn stark_requires_no_precompiles() {
        assert!(required_for(ProvingSystem::StarkFri).is_empty());
    }

    #[test]
    fn ipa_has_no_bn254_path() {
        // IPA is on Pasta, not BN254 — the BN254 precompiles do not help it.
        assert!(required_for(ProvingSystem::Halo2Ipa).is_empty());
    }
}
