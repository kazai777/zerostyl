#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use halo2_proofs::{
    plonk::{verify_proof, Circuit, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::{Challenge255, Keccak256Read, TranscriptReadBuffer},
    SerdeFormat,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use tiny_keccak::{Hasher, Keccak};
use zerostyl_verifier::reference_circuit::ReferenceCircuit;

sp1_zkvm::entrypoint!(main);

#[repr(u16)]
enum CircuitKind {
    Reference = 0,
}

impl CircuitKind {
    fn from_u16(v: u16) -> Self {
        match v {
            0 => CircuitKind::Reference,
            other => panic!("unknown circuit_kind {other}"),
        }
    }
}

pub fn main() {
    let circuit_kind = sp1_zkvm::io::read::<u16>();
    let params_bytes = sp1_zkvm::io::read_vec();
    let vk_bytes = sp1_zkvm::io::read_vec();
    let proof_bytes = sp1_zkvm::io::read_vec();
    let inputs_bytes = sp1_zkvm::io::read_vec();

    let inputs: Vec<Vec<Fr>> =
        postcard::from_bytes(&inputs_bytes).expect("decode public inputs (postcard)");

    let params = ParamsKZG::<Bn256>::read(&mut params_bytes.as_slice())
        .expect("decode ParamsKZG<Bn256>");

    let ok = match CircuitKind::from_u16(circuit_kind) {
        CircuitKind::Reference => verify_one::<ReferenceCircuit>(&params, &vk_bytes, &proof_bytes, &inputs),
    };
    assert!(ok, "proof verification failed");

    let vk_hash = keccak(&vk_bytes);
    let inputs_hash = keccak(&inputs_bytes);

    sp1_zkvm::io::commit_slice(&vk_hash);
    sp1_zkvm::io::commit_slice(&inputs_hash);
}

fn verify_one<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    inputs: &[Vec<Fr>],
) -> bool {
    let vk = VerifyingKey::<G1Affine>::read::<_, C>(
        &mut vk_bytes.to_vec().as_slice(),
        SerdeFormat::RawBytes,
    )
    .expect("decode VerifyingKey");

    let instances: Vec<&[Fr]> = inputs.iter().map(|v| v.as_slice()).collect();
    let strategy = SingleStrategy::new(params);
    let mut transcript =
        Keccak256Read::<&[u8], G1Affine, Challenge255<G1Affine>>::init(proof_bytes);

    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        params,
        &vk,
        strategy,
        &[&instances[..]],
        &mut transcript,
    )
    .is_ok()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(bytes);
    h.finalize(&mut out);
    out
}
