//! Embedded verification key and KZG parameters.
//!
//! When the `embedded_vk` feature is enabled, both the KZG parameters and the serialized
//! verifying key are embedded at compile time via `build.rs` (see that file for how they are
//! produced). The VK is deserialized with [`VerifyingKey::read`] — halo2_proofs 0.3.0 (PSE fork)
//! supports VK serialization, so there is **no** `keygen_vk` on the verification path anymore.

#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

use halo2_proofs::{
    plonk::VerifyingKey,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use halo2curves::bn256::{Bn256, G1Affine};

use crate::reference_circuit::ReferenceCircuit;

// Include the generated embedded keys from build.rs (PARAMS_BYTES, VK_BYTES, K).
include!(concat!(env!("OUT_DIR"), "/embedded_keys.rs"));

type VerifyError = Vec<u8>;

// The VK is serialized with `SerdeFormat::RawBytes` in build.rs; read it back the same way.
const VK_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

/// Get the raw embedded params bytes.
pub fn embedded_params_bytes() -> &'static [u8] {
    PARAMS_BYTES
}

/// Get the raw embedded verifying-key bytes.
pub fn embedded_vk_bytes() -> &'static [u8] {
    VK_BYTES
}

/// Load the embedded commitment parameters.
pub fn load_embedded_params() -> Result<ParamsKZG<Bn256>, VerifyError> {
    if PARAMS_BYTES.is_empty() {
        return Err(Vec::from(b"Embedded params are empty"));
    }

    ParamsKZG::<Bn256>::read(&mut &PARAMS_BYTES[..]).map_err(|e| {
        let msg = format!("Failed to deserialize embedded params: {:?}", e);
        Vec::from(msg.as_bytes())
    })
}

/// Deserialize the embedded verifying key.
///
/// No `keygen_vk` here — the VK is read directly from the bytes embedded at build time.
pub fn load_embedded_vk() -> Result<VerifyingKey<G1Affine>, VerifyError> {
    if VK_BYTES.is_empty() {
        return Err(Vec::from(b"Embedded verifying key is empty"));
    }

    VerifyingKey::<G1Affine>::read::<_, ReferenceCircuit>(&mut &VK_BYTES[..], VK_SERDE_FORMAT)
        .map_err(|e| {
            let msg = format!("Failed to deserialize embedded VK: {:?}", e);
            Vec::from(msg.as_bytes())
        })
}

/// Get the circuit size parameter k.
pub fn embedded_k() -> u32 {
    K
}

/// Embedded verification material for the real state_mask circuit (k=10).
#[cfg(feature = "state_mask_vk")]
pub use state_mask_impls::{
    load_state_mask_params, load_state_mask_vk, state_mask_k, state_mask_vk_bytes,
};

#[cfg(feature = "state_mask_vk")]
mod state_mask_impls {
    #[cfg(not(feature = "std"))]
    use alloc::{format, vec::Vec};

    use super::{
        VerifyError, STATE_MASK_K, STATE_MASK_PARAMS_BYTES, STATE_MASK_VK_BYTES, VK_SERDE_FORMAT,
    };
    use halo2_proofs::{
        plonk::VerifyingKey,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    };
    use halo2curves::bn256::{Bn256, G1Affine};
    use state_mask::StateMaskCircuit;

    /// Circuit size parameter for the embedded state_mask VK.
    pub fn state_mask_k() -> u32 {
        STATE_MASK_K
    }

    /// Raw embedded state_mask verifying-key bytes.
    pub fn state_mask_vk_bytes() -> &'static [u8] {
        STATE_MASK_VK_BYTES
    }

    /// Deserialize the embedded state_mask KZG parameters.
    pub fn load_state_mask_params() -> Result<ParamsKZG<Bn256>, VerifyError> {
        ParamsKZG::<Bn256>::read(&mut &STATE_MASK_PARAMS_BYTES[..]).map_err(|e| {
            Vec::from(format!("Failed to deserialize state_mask params: {:?}", e).as_bytes())
        })
    }

    /// Deserialize the embedded state_mask verifying key (no runtime keygen).
    pub fn load_state_mask_vk() -> Result<VerifyingKey<G1Affine>, VerifyError> {
        VerifyingKey::<G1Affine>::read::<_, StateMaskCircuit>(
            &mut &STATE_MASK_VK_BYTES[..],
            VK_SERDE_FORMAT,
        )
        .map_err(|e| Vec::from(format!("Failed to deserialize state_mask VK: {:?}", e).as_bytes()))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use halo2_proofs::plonk::keygen_vk;

    #[test]
    fn test_embedded_k() {
        assert_eq!(embedded_k(), 4);
    }

    #[test]
    fn test_embedded_params_bytes_not_empty() {
        assert!(!embedded_params_bytes().is_empty());
    }

    #[test]
    fn test_embedded_vk_bytes_not_empty() {
        assert!(!embedded_vk_bytes().is_empty());
    }

    #[test]
    fn test_load_embedded_params() {
        let result = load_embedded_params();
        assert!(result.is_ok(), "Failed to load embedded params: {:?}", result.err());
    }

    #[test]
    fn test_load_embedded_vk_deserializes() {
        let result = load_embedded_vk();
        assert!(result.is_ok(), "Failed to deserialize embedded VK: {:?}", result.err());
    }

    /// Drift guard: the VK embedded at build time must equal the VK re-derived from the real
    /// `ReferenceCircuit`. If `src/reference_circuit.rs` and the copy in `build.rs` ever diverge,
    /// the serialized bytes differ and this test fails.
    #[test]
    fn embedded_vk_matches_runtime_keygen() {
        let params = load_embedded_params().unwrap();
        let fresh = keygen_vk(&params, &ReferenceCircuit::default()).unwrap();
        let fresh_bytes = fresh.to_bytes(VK_SERDE_FORMAT);
        assert_eq!(
            fresh_bytes,
            embedded_vk_bytes(),
            "embedded VK is stale — reference_circuit.rs and build.rs have diverged; rebuild"
        );
    }
}
