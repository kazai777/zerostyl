//! Arbitrum Stylus entrypoint for ZeroStyl verifier
//!
//! This module provides the Stylus contract interface for on-chain proof verification.
//!
//! # Usage
//!
//! The verifier requires a VerifyingKey (VK) and commitment parameters to verify proofs.
//! Currently, VK must be embedded at compile time using the `embedded_vk` feature.
//!
//! # Future Work
//!
//! - VK storage in contract state (M2)
//! - VK passed as calldata with serialization (M3)

use stylus_sdk::{abi::Bytes, prelude::*};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
use std::{vec, vec::Vec};

sol_storage! {
    #[entrypoint]
    pub struct ZeroStylVerifier {}
}

#[public]
impl ZeroStylVerifier {
    /// Verify a zk-SNARK proof on-chain
    ///
    /// # Arguments
    /// * `proof` - The serialized proof bytes
    /// * `public_inputs` - The serialized public inputs
    ///
    /// # Returns
    /// * `Ok(true)` - Proof is valid
    /// * `Ok(false)` - Proof is invalid
    /// * `Err` - VK not configured or malformed inputs
    ///
    /// # Note
    /// Currently returns Err because VK is not embedded.
    /// Use `verify_with_vk_and_params` from the library directly when
    /// VK and params are available.
    pub fn verify(&self, proof: Bytes, _public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        if proof.0.is_empty() {
            return Err(Vec::from(b"Empty proof"));
        }

        Err(Vec::from(
            b"VK not configured. Deploy with embedded_vk feature or use library directly.",
        ))
    }

    /// Get circuit metadata
    ///
    /// Returns JSON metadata about the circuit configuration.
    pub fn get_metadata(&self) -> Result<Bytes, Vec<u8>> {
        let metadata = crate::get_metadata();
        Ok(Bytes(metadata))
    }
}
