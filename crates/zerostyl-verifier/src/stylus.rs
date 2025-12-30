//! Arbitrum Stylus entrypoint for ZeroStyl verifier

use stylus_sdk::{abi::Bytes, prelude::*};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::verifier_nostd;

sol_storage! {
    #[entrypoint]
    pub struct ZeroStylVerifier {}
}

#[public]
impl ZeroStylVerifier {
    pub fn verify(&self, proof: Bytes, _public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        // TODO: Deserialize public_inputs from bytes to Vec<Vec<Fp>>
        // For now, use empty inputs as placeholder
        verifier_nostd::verify_proof_nostd(&proof, &[])
    }

    pub fn get_metadata(&self) -> Result<Bytes, Vec<u8>> {
        let metadata = crate::get_metadata();
        Ok(Bytes(metadata))
    }
}
