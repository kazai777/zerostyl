//! no_std verifier shim around halo2_proofs (PSE fork, KZG-BN254).
//!
//! Thin wrapper used by tests and downstream tooling. The actual on-chain
//! Stylus verifier will not call this path directly — it dispatches BN254
//! pairing checks via precompiles 0x06/0x07/0x08. This module exists so
//! the workspace lib compiles and so descriptor-side tests can verify
//! proofs in a no_std-shaped API.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::VerifierSHPLONK,
        strategy::SingleStrategy,
    },
    transcript::{Challenge255, Keccak256Read, TranscriptReadBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

pub type VerifyError = Vec<u8>;
pub type Result<T> = core::result::Result<T, VerifyError>;

pub fn verify_with_vk_and_params(
    proof_bytes: &[u8],
    public_inputs: &[Vec<Fr>],
    vk: &VerifyingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
) -> Result<bool> {
    let mut transcript = Keccak256Read::<_, G1Affine, Challenge255<G1Affine>>::init(proof_bytes);

    let instances: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();
    let instances_slice: &[&[Fr]] = &instances;
    let strategy = SingleStrategy::new(params);

    match verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        params,
        vk,
        strategy,
        &[instances_slice],
        &mut transcript,
    ) {
        Ok(_) => Ok(true),
        Err(e) => {
            #[cfg(feature = "std")]
            {
                let error_msg = format!("Verification failed: {:?}", e);
                Err(error_msg.into_bytes())
            }
            #[cfg(not(feature = "std"))]
            {
                let _ = e;
                Err(Vec::from(b"Verification failed"))
            }
        }
    }
}
