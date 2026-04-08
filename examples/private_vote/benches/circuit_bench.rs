//! Benchmark for the private vote circuit.
//!
//! Uses Poseidon commitments (P128Pow5T3, 128-bit security, width=3, rate=2)
//! for both balance and vote hiding. The circuit proves:
//! - balance_commitment == Poseidon(balance, randomness_balance)
//! - vote_commitment == Poseidon(vote, randomness_vote)
//! - vote ∈ {0, 1}
//! - balance >= threshold (via range proof on balance - threshold)

use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;

fn bench_private_vote_mock(c: &mut Criterion) {
    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fp::from(42);
    let randomness_vote = Fp::from(84);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);
    let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

    c.bench_function("private_vote_mock_prover", |b| {
        b.iter(|| {
            let prover = MockProver::run(11, &circuit, vec![public_inputs.clone()]).unwrap();
            prover.verify().unwrap();
        });
    });
}

criterion_group!(benches, bench_private_vote_mock);
criterion_main!(benches);
