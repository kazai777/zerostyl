//! Halo2-KZG-BN254 proof verification entry points for ZeroStyl circuits.
//!
//! This is the legacy verifier crate that ZeroStyl used to embed inside a
//! per-circuit Stylus binary. The Bloc 0 universal verifier replaces this
//! path with a single Stylus router that staticcalls SP1's deployed
//! Groth16 verifier. The functions here remain to keep the workspace
//! coherent and to support older tooling that wraps proofs directly.

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

type VerifyError = Vec<u8>;

pub fn verify_halo2_proof(
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, VerifyError> {
    if proof_bytes.is_empty() {
        return Err(Vec::from(b"Empty proof"));
    }
    if public_inputs_bytes.is_empty() {
        return Err(Vec::from(b"Empty public inputs"));
    }

    let vk = load_verifying_key()?;
    let params = load_params()?;
    let public_inputs = deserialize_public_inputs(public_inputs_bytes)?;

    verify_with_vk_and_params(proof_bytes, &public_inputs, &vk, &params)
}

pub fn verify_with_vk_and_params(
    proof_bytes: &[u8],
    public_inputs: &[Vec<Fr>],
    vk: &VerifyingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
) -> Result<bool, VerifyError> {
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
        Err(_) => Ok(false),
    }
}

pub(crate) fn deserialize_public_inputs(inputs_bytes: &[u8]) -> Result<Vec<Vec<Fr>>, VerifyError> {
    postcard::from_bytes(inputs_bytes)
        .map_err(|e| Vec::from(format!("Failed to deserialize public inputs: {}", e).as_bytes()))
}

fn load_verifying_key() -> Result<VerifyingKey<G1Affine>, VerifyError> {
    #[cfg(feature = "embedded_vk")]
    {
        crate::embedded::load_embedded_vk()
    }
    #[cfg(not(feature = "embedded_vk"))]
    {
        Err(Vec::from(b"Verifying key not embedded. Enable embedded_vk feature."))
    }
}

fn load_params() -> Result<ParamsKZG<Bn256>, VerifyError> {
    #[cfg(feature = "embedded_vk")]
    {
        crate::embedded::load_embedded_params()
    }
    #[cfg(not(feature = "embedded_vk"))]
    {
        Err(Vec::from(b"Commitment parameters not embedded"))
    }
}

pub fn get_circuit_metadata() -> Vec<u8> {
    let metadata = r#"{
        "name": "ReferenceCircuit",
        "version": "0.1.0",
        "k": 4,
        "num_public_inputs": 1,
        "num_private_witnesses": 2
    }"#;
    Vec::from(metadata.as_bytes())
}
