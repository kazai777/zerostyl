//! WASM verifier for ZeroStyl circuits on Arbitrum Stylus
//!
//! This crate provides two verification modes:
//! - Standard mode (default): Uses halo2_proofs with std for testing and development
//! - Stylus mode (feature="stylus"): No-std verifier for Arbitrum Stylus deployment

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(any(not(feature = "std"), feature = "stylus"))]
extern crate alloc;

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
pub fn verify(proof: &[u8], _public_inputs: &[u8]) -> Result<bool, Vec<u8>> {
    // For no_std, we need to deserialize public_inputs first
    // TODO: Implement proper deserialization
    verifier_nostd::verify_proof_nostd(proof, &[])
}

#[cfg(feature = "std")]
pub fn get_metadata() -> Vec<u8> {
    verifier::get_circuit_metadata()
}

#[cfg(not(feature = "std"))]
pub fn get_metadata() -> Vec<u8> {
    // TODO: Implement metadata for no_std mode
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
