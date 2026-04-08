//! Embedded verification key and parameters
//!
//! When the `embedded_vk` feature is enabled, IPA params are embedded
//! at compile time via build.rs. The VK is regenerated at runtime
//! via `keygen_vk` because halo2_proofs 0.3.2 lacks VK serialization.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use halo2_proofs::{
    plonk::{keygen_vk, VerifyingKey},
    poly::commitment::Params,
};
use halo2curves::pasta::EqAffine;

use crate::reference_circuit::ReferenceCircuit;

// Include the generated embedded keys from build.rs
include!(concat!(env!("OUT_DIR"), "/embedded_keys.rs"));

type VerifyError = Vec<u8>;

/// Get the raw embedded params bytes
pub fn embedded_params_bytes() -> &'static [u8] {
    PARAMS_BYTES
}

/// Load the embedded commitment parameters
pub fn load_embedded_params() -> Result<Params<EqAffine>, VerifyError> {
    if PARAMS_BYTES.is_empty() {
        return Err(Vec::from(b"Embedded params are empty"));
    }

    Params::read(&mut &PARAMS_BYTES[..]).map_err(|e| {
        let msg = format!("Failed to deserialize embedded params: {:?}", e);
        Vec::from(msg.as_bytes())
    })
}

/// Regenerate the VK from embedded params and the reference circuit.
///
/// halo2_proofs 0.3.2 does not support VK serialization, so the VK
/// is regenerated at runtime using `keygen_vk`.
pub fn load_embedded_vk() -> Result<VerifyingKey<EqAffine>, VerifyError> {
    let params = load_embedded_params()?;
    let circuit = ReferenceCircuit::default();
    keygen_vk(&params, &circuit).map_err(|e| {
        let msg = format!("Failed to generate VK: {:?}", e);
        Vec::from(msg.as_bytes())
    })
}

/// Get the circuit size parameter k
pub fn embedded_k() -> u32 {
    K
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_k() {
        assert_eq!(embedded_k(), 4);
    }

    #[test]
    fn test_embedded_params_bytes_not_empty() {
        assert!(!embedded_params_bytes().is_empty());
    }

    #[test]
    fn test_load_embedded_params() {
        let result = load_embedded_params();
        assert!(result.is_ok(), "Failed to load embedded params: {:?}", result.err());
    }

    #[test]
    fn test_load_embedded_vk() {
        let result = load_embedded_vk();
        assert!(result.is_ok(), "Failed to generate embedded VK: {:?}", result.err());
    }
}
