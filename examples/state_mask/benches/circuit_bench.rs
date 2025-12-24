use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use state_mask::StateMaskCircuit;

fn benchmark_state_mask_circuit(c: &mut Criterion) {
    let k = 10;
    let value = 42u64;
    let randomness = Fp::from(123);
    let range_min = 0u64;
    let range_max = 255u64;

    let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);

    let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
    let public_inputs = vec![commitment];

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

fn benchmark_range_values(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_values");

    for value in [0, 64, 128, 192, 255] {
        let k = 10;
        let randomness = Fp::from(123);
        let range_min = 0u64;
        let range_max = 255u64;

        let circuit = StateMaskCircuit::new(value, randomness, range_min, range_max);

        let commitment = StateMaskCircuit::compute_commitment(Fp::from(value), randomness);
        let public_inputs = vec![commitment];

        group.bench_function(format!("value_{}", value), |b| {
            b.iter(|| {
                let prover = MockProver::run(
                    black_box(k),
                    black_box(&circuit),
                    black_box(vec![public_inputs.clone()]),
                )
                .unwrap();
                black_box(prover.verify())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_state_mask_circuit, benchmark_range_values);
criterion_main!(benches);
