//! WASM verifier for ZeroStyl circuits on Arbitrum Stylus
//!
//! This crate provides two verification modes:
//! - Standard mode (default): Uses halo2_proofs with std for testing and development
//! - Stylus mode (feature="stylus"): No-std verifier for Arbitrum Stylus deployment
//!
//! ## Current limitations
//!
//! The crate currently only includes the `ReferenceCircuit` (a + b = sum) as a
//! built-in verifiable circuit. Verifying arbitrary user circuits (tx_privacy,
//! state_mask, etc.) requires generating a verifier with the circuit's verification
//! key embedded. Use `zerostyl-prove` for off-chain proof generation and
//! verification of user-defined circuits.

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

#[cfg(feature = "stylus")]
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
