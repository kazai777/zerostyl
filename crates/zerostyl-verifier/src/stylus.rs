//! Arbitrum Stylus entrypoint for ZeroStyl verifier

use stylus_sdk::{abi::Bytes, prelude::*};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
use std::vec::Vec;

sol_storage! {
    #[entrypoint]
    pub struct ZeroStylVerifier {}
}

#[public]
impl ZeroStylVerifier {
    pub fn verify(&self, _proof: Bytes, _public_inputs: Bytes) -> Result<bool, Vec<u8>> {
        // TODO: Implement verification with VK passed as parameter or stored in contract storage
        // Current limitation: embedded_vk feature not yet working
        Err(Vec::from(b"Verification not yet implemented - VK embedding in progress"))
    }

    pub fn get_metadata(&self) -> Result<Bytes, Vec<u8>> {
        let metadata = crate::get_metadata();
        Ok(Bytes(metadata))
    }
}
