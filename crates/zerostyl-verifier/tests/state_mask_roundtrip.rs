//! End-to-end verification of a real state_mask proof against the embedded serialized VK.
//!
//! The proof is generated with the *embedded* KZG parameters, which are derived from the shared
//! `DEV_SRS_SEED` — the exact same SRS the prover (`zerostyl-compiler`'s `KeyManager`) uses. So a
//! proof produced off-chain by `zerostyl-prove` for state_mask verifies against these embedded
//! bytes with no runtime keygen. This test exercises that path with the real circuit.

#![cfg(feature = "state_mask_vk")]

use halo2_proofs::{
    plonk::{create_proof, keygen_pk},
    poly::kzg::{commitment::KZGCommitmentScheme, multiopen::ProverSHPLONK},
    transcript::{Challenge255, Keccak256Write, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;

use state_mask::StateMaskCircuit;
use zerostyl_verifier::embedded::{load_state_mask_params, load_state_mask_vk};
use zerostyl_verifier::{verify_state_mask, verify_state_mask_bytes};

/// Prove a valid state_mask statement using the embedded params.
fn prove(
    state_value: u64,
    nonce: u64,
    collateral: u64,
    hidden_balance: u64,
    threshold: u64,
) -> (Vec<u8>, Vec<Vec<Fr>>) {
    let params = load_state_mask_params().expect("embedded state_mask params");
    let vk = load_state_mask_vk().expect("embedded state_mask vk");
    let pk = keygen_pk(&params, vk, &StateMaskCircuit::default()).expect("keygen_pk");

    let nonce_fp = Fr::from(nonce);
    let circuit =
        StateMaskCircuit::new(state_value, nonce_fp, collateral, hidden_balance, threshold);
    let commitment = StateMaskCircuit::compute_commitment(
        Fr::from(state_value),
        Fr::from(collateral),
        Fr::from(hidden_balance),
        nonce_fp,
    );
    let public_inputs = vec![vec![commitment, Fr::from(threshold)]];
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
fn embedded_state_mask_vk_verifies_a_real_proof() {
    // collateral 200 ∈ [150,300], hidden_balance 500 > threshold 100 → valid.
    let (proof, public_inputs) = prove(1000, 42, 200, 500, 100);
    let ok = verify_state_mask(&proof, &public_inputs).unwrap();
    assert!(ok, "a valid state_mask proof must verify against the embedded VK");
}

#[test]
fn embedded_state_mask_vk_rejects_wrong_commitment() {
    let (proof, mut public_inputs) = prove(1000, 42, 200, 500, 100);
    // Corrupt the public commitment.
    public_inputs[0][0] = Fr::from(999u64);
    let result = verify_state_mask(&proof, &public_inputs);
    assert!(!matches!(result, Ok(true)), "a wrong public commitment must not verify");
}

#[test]
fn embedded_state_mask_vk_rejects_tampered_proof() {
    let (mut proof, public_inputs) = prove(1000, 42, 200, 500, 100);
    let mid = proof.len() / 2;
    proof[mid] ^= 0xff;
    let result = verify_state_mask(&proof, &public_inputs);
    assert!(!matches!(result, Ok(true)), "a tampered state_mask proof must be rejected");
}

/// The bytes-based API a Stylus contract calls: public inputs are passed as 32-byte little-endian
/// field reprs (what `Fr::to_repr()` / `public_inputs.json` produce). This locks in the byte order.
#[test]
fn verify_state_mask_bytes_accepts_le_reprs() {
    use halo2curves::ff::PrimeField;

    let (proof, public_inputs) = prove(1000, 42, 200, 500, 100);
    // Single instance column: [commitment, threshold] as little-endian reprs.
    let reprs: Vec<[u8; 32]> = public_inputs[0].iter().map(|f| f.to_repr()).collect();

    assert!(
        verify_state_mask_bytes(&proof, &reprs).unwrap(),
        "byte-encoded public inputs must verify"
    );

    // Corrupt the commitment repr → must not verify.
    let mut bad = reprs.clone();
    bad[0][0] ^= 0x01;
    assert!(
        !matches!(verify_state_mask_bytes(&proof, &bad), Ok(true)),
        "a corrupted public-input repr must not verify"
    );
}

/// The real interop test: a proof produced through the actual prover path
/// (`descriptor().prove()` → `KeyManager` deterministic SRS → `keygen_pk`/`create_proof`) verifies
/// against the VK embedded in this crate. This only holds because both sides derive their SRS from
/// the shared `DEV_SRS_SEED`; if the prover's SRS diverged from the embedded one, it would fail.
#[test]
fn prover_generated_state_mask_proof_verifies_against_embedded_vk() {
    // CircuitDescriptor is brought into scope for `.prove()`; under some feature unifications the
    // method resolves without it, so suppress the conditional unused-import warning.
    #[allow(unused_imports)]
    use zerostyl_circuits::CircuitDescriptor;

    let tmp = tempfile::TempDir::new().unwrap();
    let witness = r#"{"state_value":"1000","nonce":"42","collateral_ratio":"200","hidden_balance":"500","threshold":"100"}"#;

    // Real prover path (KeyManager deterministic params + keygen).
    let artifact = state_mask::descriptor().prove(witness, 10, tmp.path()).unwrap();

    // Public inputs are deterministic from the witness: [commitment, threshold].
    let commitment = StateMaskCircuit::compute_commitment(
        Fr::from(1000u64),
        Fr::from(200u64),
        Fr::from(500u64),
        Fr::from(42u64),
    );
    let public_inputs = vec![vec![commitment, Fr::from(100u64)]];

    let ok = verify_state_mask(&artifact.bytes, &public_inputs).unwrap();
    assert!(ok, "a prover-generated proof must verify against the embedded VK (shared SRS)");
}
