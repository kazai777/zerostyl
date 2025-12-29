//! Arbitrum Stylus entrypoint for ZeroStyl verifier

use stylus_sdk::{abi::Bytes, prelude::*};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

sol_storage! {
    #[entrypoint]
    pub struct ZeroStylVerifier {}
}

#[public]
impl ZeroStylVerifier {
    pub fn verify(&self, proof: Bytes, public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        crate::verify(&proof, &public_inputs)
    }

    pub fn get_metadata(&self) -> Result<Bytes, Vec<u8>> {
        let metadata = crate::get_metadata();
        Ok(Bytes(metadata))
    }
}
