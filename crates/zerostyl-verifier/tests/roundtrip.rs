//! End-to-end KZG proof round-trip against the embedded, serialized verifying key.
//!
//! This is the test the crate was missing: it generates a *real* halo2-KZG proof for the
//! reference circuit and verifies it against the VK that was serialized at build time and
//! deserialized at runtime (no `keygen_vk` on the verify path). It proves the whole real
//! verification pipeline works, and that a tampered proof / wrong public input is rejected.

#![cfg(feature = "embedded_vk")]

use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk},
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
    transcript::{Challenge255, Keccak256Write, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;

use zerostyl_verifier::embedded::{load_embedded_params, load_embedded_vk};
use zerostyl_verifier::reference_circuit::ReferenceCircuit;
use zerostyl_verifier::verify_with_vk_and_params;

/// Produce a real KZG proof for `a + b = sum` using the embedded params.
fn prove(a: u64, b: u64, sum: u64) -> (Vec<u8>, Vec<Vec<Fr>>) {
    let params = load_embedded_params().expect("embedded params");
    let vk = load_embedded_vk().expect("embedded vk");
    let pk = keygen_pk(&params, vk, &ReferenceCircuit::default()).expect("keygen_pk");

    let circuit = ReferenceCircuit { a: Value::known(Fr::from(a)), b: Value::known(Fr::from(b)) };
    let public_inputs = vec![vec![Fr::from(sum)]];
    let instances: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();

    let mut transcript = Keccak256Write::<_, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        std::slice::from_ref(&circuit),
        &[instances.as_slice()],
        OsRng,
        &mut transcript,
    )
    .expect("create_proof");

    (transcript.finalize(), public_inputs)
}

#[test]
fn embedded_vk_verifies_a_real_proof() {
    let (proof, public_inputs) = prove(2, 3, 5);
    let params = load_embedded_params().unwrap();
    let vk = load_embedded_vk().unwrap();

    let ok = verify_with_vk_and_params(&proof, &public_inputs, &vk, &params).unwrap();
    assert!(ok, "a valid KZG proof must verify against the embedded VK");
}

#[test]
fn embedded_vk_rejects_wrong_public_input() {
    let (proof, _) = prove(2, 3, 5);
    let params = load_embedded_params().unwrap();
    let vk = load_embedded_vk().unwrap();

    // Claim 2 + 3 = 6 instead of 5. A failed verification surfaces either as Ok(false) or Err
    // depending on the entry point; both are "not verified".
    let wrong = vec![vec![Fr::from(6u64)]];
    let result = verify_with_vk_and_params(&proof, &wrong, &vk, &params);
    assert!(!matches!(result, Ok(true)), "a mismatched public input must not verify");
}

#[test]
fn embedded_vk_rejects_tampered_proof() {
    let (mut proof, public_inputs) = prove(2, 3, 5);
    // Flip a byte in the middle of the proof.
    let mid = proof.len() / 2;
    proof[mid] ^= 0xff;

    let params = load_embedded_params().unwrap();
    let vk = load_embedded_vk().unwrap();
    let result = verify_with_vk_and_params(&proof, &public_inputs, &vk, &params);
    assert!(!matches!(result, Ok(true)), "a tampered proof must be rejected");
}
