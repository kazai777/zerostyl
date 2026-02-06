//! Integration tests for private vote circuit

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::pasta::{EqAffine, Fp};
use private_vote::PrivateVoteCircuit;
use rand::rngs::OsRng;

#[test]
fn test_private_vote_real_proof() {
    let k = 10;

    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fp::from(42);
    let randomness_vote = Fp::from(84);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

    let params = Params::<EqAffine>::new(k);
    let vk = keygen_vk(&params, &circuit).expect("VK generation failed");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("PK generation failed");

    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

    let public_inputs = [vec![balance_commitment, Fp::from(threshold), vote_commitment]];
    let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[instances.as_slice()], OsRng, &mut transcript)
        .expect("Proof generation failed");
    let proof = transcript.finalize();

    // Verify
    use halo2_proofs::plonk::{verify_proof, SingleVerifier};
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
    let result = verify_proof(&params, &vk, strategy, &[instances.as_slice()], &mut transcript);
    assert!(result.is_ok(), "Proof verification failed: {:?}", result);
}
