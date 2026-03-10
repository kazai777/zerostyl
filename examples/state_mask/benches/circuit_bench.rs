use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use state_mask::StateMaskCircuit;

fn benchmark_state_mask_circuit(c: &mut Criterion) {
    let k = 10;
    let state_value = 1000u64;
    let nonce = Fp::from(42u64);
    let collateral_ratio = 200u64;
    let hidden_balance = 500u64;
    let threshold = 100u64;

    let circuit =
        StateMaskCircuit::new(state_value, nonce, collateral_ratio, hidden_balance, threshold);

    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);
    let public_inputs = vec![commitment, Fp::from(threshold)];

    c.bench_function("state_mask_circuit_prove", |b| {
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

    c.bench_function("state_mask_circuit_verify", |b| {
        b.iter(|| {
            let result = black_box(&prover).verify();
            black_box(result)
        });
    });
}

criterion_group!(benches, benchmark_state_mask_circuit);
criterion_main!(benches);
