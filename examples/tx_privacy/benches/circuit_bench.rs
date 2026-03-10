use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};

fn benchmark_tx_privacy_circuit(c: &mut Criterion) {
    let k = 14;
    let balance_old = 1000u64;
    let balance_new = 700u64;
    let amount = 300u64;
    let randomness_old = Fp::from(42u64);
    let randomness_new = Fp::from(84u64);
    let siblings: Vec<Fp> = (0..MERKLE_DEPTH).map(|i| Fp::from((i + 100) as u64)).collect();
    let indices: Vec<bool> = (0..MERKLE_DEPTH).map(|i| i % 2 == 0).collect();

    let circuit = TxPrivacyCircuit::new(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        siblings.clone(),
        indices.clone(),
    );

    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

    let public_inputs = vec![commitment_old, commitment_new, merkle_root];

    c.bench_function("tx_privacy_circuit_prove", |b| {
        b.iter(|| {
            let prover = MockProver::run(
                black_box(k),
                black_box(&circuit),
                black_box(vec![public_inputs.clone()]),
            )
            .unwrap();
            black_box(prover)
        });
    });

    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();

    c.bench_function("tx_privacy_circuit_verify", |b| {
        b.iter(|| {
            let result = black_box(&prover).verify();
            black_box(result)
        });
    });
}

criterion_group!(benches, benchmark_tx_privacy_circuit);
criterion_main!(benches);
