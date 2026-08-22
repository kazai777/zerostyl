//! Arbitrum Stylus entrypoint for ZeroStyl verifier
//!
//! This module provides the Stylus contract interface for on-chain proof verification.
//!
//! When deployed with the `embedded_vk` feature, the contract verifies proofs against the
//! embedded reference circuit, reading the KZG params + serialized VK that were baked in at build
//! time (no runtime `keygen_vk`).
//!
//! Caveat: this entrypoint pulls in the full halo2 SHPLONK verifier. It compiles for
//! `wasm32-unknown-unknown`, but its size and gas cost have not been shown to fit Arbitrum
//! Stylus limits — the deployed demo contracts still record a proof hash rather than calling this
//! path (see `contracts/CONTRACTS.md`). Treat it as the reference verification path, not a
//! production-ready on-chain verifier.

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
    /// * `public_inputs` - The serialized public inputs (postcard format)
    ///
    /// # Returns
    /// * `Ok(true)` - Proof is valid
    /// * `Ok(false)` - Proof is invalid
    /// * `Err` - VK not configured or malformed inputs
    pub fn verify(&self, proof: Bytes, public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        if proof.0.is_empty() {
            return Err(Vec::from(b"Empty proof"));
        }

        #[cfg(feature = "embedded_vk")]
        {
            let vk = crate::embedded::load_embedded_vk()?;
            let params = crate::embedded::load_embedded_params()?;

            #[cfg(feature = "std")]
            {
                let inputs = crate::verifier::deserialize_public_inputs(&public_inputs.0)?;
                crate::verifier_nostd::verify_with_vk_and_params(&proof.0, &inputs, &vk, &params)
            }

            #[cfg(not(feature = "std"))]
            {
                // In no_std mode, use verifier_nostd directly with raw deserialization
                let inputs: Vec<Vec<halo2curves::bn256::Fr>> =
                    postcard::from_bytes(&public_inputs.0)
                        .map_err(|_| Vec::from(b"Failed to deserialize public inputs"))?;
                crate::verifier_nostd::verify_with_vk_and_params(&proof.0, &inputs, &vk, &params)
            }
        }

        #[cfg(not(feature = "embedded_vk"))]
        {
            let _ = public_inputs;
            Err(Vec::from(b"VK not configured. Deploy with embedded_vk feature."))
        }
    }

    /// Get circuit metadata
    ///
    /// Returns JSON metadata about the circuit configuration.
    pub fn get_metadata(&self) -> Result<Bytes, Vec<u8>> {
        let metadata = crate::get_metadata();
        Ok(Bytes(metadata))
    }
}
