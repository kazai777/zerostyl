//! WASM verifier for ZeroStyl circuits on Arbitrum Stylus
//!
//! This crate provides two verification modes:
//! - Standard mode (default): Uses halo2_proofs with std for testing and development
//! - Stylus mode (feature="stylus"): No-std verifier for Arbitrum Stylus deployment
//!
//! ## Scope
//!
//! The crate ships the `ReferenceCircuit` (a + b = sum) as the default verifiable circuit. Its KZG
//! params and verifying key are serialized at build time and deserialized at runtime — there is no
//! `keygen_vk` on the verification path.
//!
//! With the `state_mask_vk` feature it also embeds the **real** state_mask circuit's params (k=10)
//! and serialized VK, and exposes [`verify_state_mask`]. Because the params are derived from the
//! same `zerostyl_runtime::DEV_SRS_SEED` the prover uses, a proof produced by `zerostyl-prove`
//! for state_mask verifies here directly (see `tests/state_mask_roundtrip.rs`).
//!
//! ## On-chain (wasm)
//!
//! Both the `ReferenceCircuit` and `state_mask` verification paths compile for
//! `wasm32-unknown-unknown` (including under the `stylus` feature). The circuit gadgets live in the
//! standalone `no_std` `zerostyl-gadgets` crate and the state_mask circuit is pulled in
//! circuit-only (its std-only descriptor/prover is feature-gated away), so no part of the heavy
//! compiler ends up in the contract.
//!
//! **Size — not deployable as a Stylus contract.** Stylus gates on a 24 KB Brotli-compressed
//! binary and a 128 KB uncompressed WASM. A contract that actually calls `verify_state_mask`
//! (e.g. `state_mask_verifier`) is ~240 KB compressed / ~559 KB uncompressed, and the halo2
//! `verify_proof` + BN254 pairing code alone is ~91.5 KB compressed — already ~4× the limit before
//! any data. Trimming the embedded SRS to verifier-only points (the verifier only reads `g[0]`,
//! `g2`, `s_g2`; SHPLONK sets `QUERY_INSTANCE=false` so `g_lagrange` is unused) and lowering k help
//! but cannot bridge that gap. Deploying on-chain requires a hand-written minimal KZG verifier that
//! offloads pairing to Arbitrum's BN254 precompile (0x08), or wrapping the proof in Groth16. This
//! crate is therefore a correct, tested reference verifier — not a deployable Stylus contract.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(any(not(feature = "std"), feature = "stylus"))]
extern crate alloc;

#[cfg(all(target_arch = "wasm32", not(feature = "std")))]
mod getrandom_custom {
    use getrandom::{register_custom_getrandom, Error};

    fn custom_getrandom(_buf: &mut [u8]) -> Result<(), Error> {
        Err(Error::UNSUPPORTED)
    }

    register_custom_getrandom!(custom_getrandom);
}

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod reference_circuit;

#[cfg(feature = "std")]
pub mod verifier;

pub mod verifier_nostd;
pub mod vk_components;

#[cfg(feature = "embedded_vk")]
pub mod embedded;

// wasm32-only: the `#[entrypoint]` exports reference Stylus VM host symbols
// (`account_balance`, …) that exist only in the Stylus runtime. On a native
// host the cdylib link would fail (Mach-O rejects undefined symbols), so the
// module is compiled solely for the target it can actually run on.
#[cfg(all(feature = "stylus", target_arch = "wasm32"))]
pub mod stylus;

/// Verify a halo2 proof with embedded VK and params (std mode).
#[cfg(feature = "std")]
pub fn verify(proof: &[u8], public_inputs: &[u8]) -> Result<bool, Vec<u8>> {
    verifier::verify_halo2_proof(proof, public_inputs)
}

/// Verify a halo2 proof (no_std stub — returns error unless `embedded_vk` is enabled).
#[cfg(not(feature = "std"))]
pub fn verify(_proof: &[u8], _public_inputs: &[u8]) -> Result<bool, Vec<u8>> {
    Err(Vec::from(b"VK not embedded. Use verify_with_vk() or enable embedded_vk feature"))
}

/// Re-export verify_with_vk_and_params from verifier_nostd for direct access
pub use verifier_nostd::verify_with_vk_and_params;

/// Verify a real state_mask proof against the embedded state_mask verifying key.
///
/// Uses the params + serialized VK embedded at build time (shared deterministic SRS with the
/// prover), so a proof produced by `zerostyl-prove` for the state_mask circuit verifies here with
/// no runtime keygen. Compiles for both std and `wasm32` (no_std), so this is a real on-chain
/// verification path — see the crate-level docs for the measured contract size.
#[cfg(feature = "state_mask_vk")]
pub fn verify_state_mask(
    proof: &[u8],
    public_inputs: &[Vec<halo2curves::bn256::Fr>],
) -> Result<bool, Vec<u8>> {
    let vk = embedded::load_state_mask_vk()?;
    let params = embedded::load_state_mask_params()?;
    verify_with_vk_and_params(proof, public_inputs, &vk, &params)
}

/// Verify a state_mask proof from raw calldata-friendly bytes.
///
/// Callers (e.g. a Stylus contract) pass the single instance column's field elements as 32-byte
/// **little-endian canonical representations** — exactly what `Fr::to_repr()` produces and what the
/// `public_inputs.json` hex encodes. For state_mask that is `[commitment, threshold]`. Returns
/// `Err` if any element is not a canonical field element.
///
/// This wrapper exists so on-chain callers never have to name `halo2curves::bn256::Fr`.
#[cfg(feature = "state_mask_vk")]
pub fn verify_state_mask_bytes(proof: &[u8], public_inputs: &[[u8; 32]]) -> Result<bool, Vec<u8>> {
    use halo2curves::bn256::Fr;
    use halo2curves::ff::PrimeField;

    let mut column = Vec::with_capacity(public_inputs.len());
    for repr in public_inputs {
        let fr = Option::<Fr>::from(Fr::from_repr(*repr))
            .ok_or_else(|| Vec::from(&b"non-canonical public input"[..]))?;
        column.push(fr);
    }
    verify_state_mask(proof, &[column])
}

#[cfg(feature = "std")]
pub use verifier::verify_halo2_proof;

/// Returns JSON metadata about the reference circuit (std mode).
#[cfg(feature = "std")]
pub fn get_metadata() -> Vec<u8> {
    verifier::get_circuit_metadata()
}

/// Returns JSON metadata about the reference circuit (no_std mode).
#[cfg(not(feature = "std"))]
pub fn get_metadata() -> Vec<u8> {
    Vec::from(b"{\"circuit\":\"ReferenceCircuit\",\"version\":\"0.1.0\",\"k\":4}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_empty_proof() {
        let result = verify(&[], &[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_empty_inputs() {
        let result = verify(&[1, 2, 3], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_metadata() {
        let metadata = get_metadata();
        assert!(!metadata.is_empty());
        let json_str = String::from_utf8(metadata).unwrap();
        assert!(json_str.contains("ReferenceCircuit"));
    }
}
