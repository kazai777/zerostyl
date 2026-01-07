//! WASM verifier for ZeroStyl circuits on Arbitrum Stylus
//!
//! This crate provides two verification modes:
//! - Standard mode (default): Uses halo2_proofs with std for testing and development
//! - Stylus mode (feature="stylus"): No-std verifier for Arbitrum Stylus deployment

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

#[cfg(feature = "std")]
pub mod verifier;

pub mod verifier_nostd;
pub mod vk_components;

#[cfg(feature = "stylus")]
pub mod stylus;

#[cfg(feature = "std")]
pub fn verify(proof: &[u8], public_inputs: &[u8]) -> Result<bool, Vec<u8>> {
    verifier::verify_halo2_proof(proof, public_inputs)
}

#[cfg(not(feature = "std"))]
pub fn verify(_proof: &[u8], _public_inputs: &[u8]) -> Result<bool, Vec<u8>> {
    // For no_std mode without embedded VK, verification requires explicit VK/params.
    // Use verify_with_vk() instead, or deploy with embedded_vk feature.
    //
    // This function returns Err (not panic) to satisfy safety requirements.
    Err(Vec::from(b"VK not embedded. Use verify_with_vk() or enable embedded_vk feature"))
}

/// Re-export verify_with_vk_and_params from verifier_nostd for direct access
pub use verifier_nostd::verify_with_vk_and_params;

#[cfg(feature = "std")]
pub fn get_metadata() -> Vec<u8> {
    verifier::get_circuit_metadata()
}

#[cfg(not(feature = "std"))]
pub fn get_metadata() -> Vec<u8> {
    // NOTE: Hardcoded for M1; dynamic generation deferred to M2
    Vec::from(b"{\"circuit\":\"ZeroStylCircuit\",\"version\":\"0.1.0\"}")
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
        assert!(json_str.contains("ZeroStylCircuit"));
    }
}
