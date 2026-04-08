//! Criterion benchmark: overhead of debug_circuit vs raw MockProver
//!
//! Measures the execution time difference between:
//!   - Raw: MockProver::run() + .verify()
//!   - ZeroStyl: debug_circuit() (wraps MockProver + adds structured output)
//!
//! Run with: cargo bench -p zerostyl-debugger

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;
use state_mask::StateMaskCircuit;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_debugger::debug_circuit;

// ─── Scenario A: state_mask — wrong commitment ──────────────────────────────

fn bench_state_mask_raw(c: &mut Criterion) {
    let state_value = 1000u64;
    let nonce = Fp::from(42u64);
    let wrong_commitment = Fp::from(999u64);
    let threshold = 100u64;
    let k = 10u32;

    c.bench_function("state_mask/raw_mockprover", |b| {
        b.iter_batched(
            || StateMaskCircuit::from_raw(state_value, nonce, 200, 500, threshold),
            |circuit| {
                let prover = MockProver::run(
                    k,
                    black_box(&circuit),
                    vec![vec![wrong_commitment, Fp::from(threshold)]],
                )
                .expect("MockProver::run failed");
                black_box(prover.verify())
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_state_mask_zerostyl(c: &mut Criterion) {
    let state_value = 1000u64;
    let nonce = Fp::from(42u64);
    let wrong_commitment = Fp::from(999u64);
    let threshold = 100u64;
    let k = 10u32;

    c.bench_function("state_mask/zerostyl_debug_circuit", |b| {
        b.iter_batched(
            || StateMaskCircuit::from_raw(state_value, nonce, 200, 500, threshold),
            |circuit| {
                black_box(
                    debug_circuit(
                        black_box(&circuit),
                        vec![vec![wrong_commitment, Fp::from(threshold)]],
                        k,
                        "state_mask",
                    )
                    .expect("debug_circuit failed"),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

// ─── Scenario B: tx_privacy — wrong balance ─────────────────────────────────

fn bench_tx_privacy_raw(c: &mut Criterion) {
    let balance_old = 1000u64;
    let balance_new = 800u64;
    let r_old = Fp::from(7u64);
    let r_new = Fp::from(13u64);
    let amount = 300u64; // wrong: should be 200
    let path = vec![Fp::ZERO; MERKLE_DEPTH];
    let indices = vec![false; MERKLE_DEPTH];
    let k = 14u32;

    let comm_old = TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), r_old);
    let comm_new = TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), r_new);
    let root = TxPrivacyCircuit::compute_merkle_root(comm_old, &path, &indices);
    let public_inputs = vec![vec![comm_old, comm_new, root]];

    c.bench_function("tx_privacy/raw_mockprover", |b| {
        b.iter_batched(
            || TxPrivacyCircuit::from_raw(balance_old, balance_new, r_old, r_new, amount, path.clone(), indices.clone()),
            |circuit| {
                let prover = MockProver::run(k, black_box(&circuit), public_inputs.clone())
                    .expect("MockProver::run failed");
                black_box(prover.verify())
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_tx_privacy_zerostyl(c: &mut Criterion) {
    let balance_old = 1000u64;
    let balance_new = 800u64;
    let r_old = Fp::from(7u64);
    let r_new = Fp::from(13u64);
    let amount = 300u64;
    let path = vec![Fp::ZERO; MERKLE_DEPTH];
    let indices = vec![false; MERKLE_DEPTH];
    let k = 14u32;

    let comm_old = TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), r_old);
    let comm_new = TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), r_new);
    let root = TxPrivacyCircuit::compute_merkle_root(comm_old, &path, &indices);
    let public_inputs = vec![vec![comm_old, comm_new, root]];

    c.bench_function("tx_privacy/zerostyl_debug_circuit", |b| {
        b.iter_batched(
            || TxPrivacyCircuit::from_raw(balance_old, balance_new, r_old, r_new, amount, path.clone(), indices.clone()),
            |circuit| {
                black_box(
                    debug_circuit(black_box(&circuit), public_inputs.clone(), k, "tx_privacy")
                        .expect("debug_circuit failed"),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

// ─── Scenario C: private_vote — illegal vote value ───────────────────────────

fn bench_private_vote_raw(c: &mut Criterion) {
    let balance = 100u64;
    let r_bal = Fp::from(42u64);
    let vote = 2u64; // must be 0 or 1
    let r_vote = Fp::from(84u64);
    let threshold = 50u64;
    let k = 11u32;

    let bal_commit = PrivateVoteCircuit::compute_commitment(Fp::from(balance), r_bal);
    let vote_commit = PrivateVoteCircuit::compute_commitment(Fp::from(vote), r_vote);
    let public_inputs = vec![vec![bal_commit, Fp::from(threshold), vote_commit]];

    c.bench_function("private_vote/raw_mockprover", |b| {
        b.iter_batched(
            || PrivateVoteCircuit::from_raw(balance, r_bal, vote, r_vote, threshold),
            |circuit| {
                let prover = MockProver::run(k, black_box(&circuit), public_inputs.clone())
                    .expect("MockProver::run failed");
                black_box(prover.verify())
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_private_vote_zerostyl(c: &mut Criterion) {
    let balance = 100u64;
    let r_bal = Fp::from(42u64);
    let vote = 2u64;
    let r_vote = Fp::from(84u64);
    let threshold = 50u64;
    let k = 11u32;

    let bal_commit = PrivateVoteCircuit::compute_commitment(Fp::from(balance), r_bal);
    let vote_commit = PrivateVoteCircuit::compute_commitment(Fp::from(vote), r_vote);
    let public_inputs = vec![vec![bal_commit, Fp::from(threshold), vote_commit]];

    c.bench_function("private_vote/zerostyl_debug_circuit", |b| {
        b.iter_batched(
            || PrivateVoteCircuit::from_raw(balance, r_bal, vote, r_vote, threshold),
            |circuit| {
                black_box(
                    debug_circuit(black_box(&circuit), public_inputs.clone(), k, "private_vote")
                        .expect("debug_circuit failed"),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

// ─── Groups ──────────────────────────────────────────────────────────────────

criterion_group!(state_mask_benches, bench_state_mask_raw, bench_state_mask_zerostyl);

criterion_group!(tx_privacy_benches, bench_tx_privacy_raw, bench_tx_privacy_zerostyl);

criterion_group!(private_vote_benches, bench_private_vote_raw, bench_private_vote_zerostyl);

criterion_main!(state_mask_benches, tx_privacy_benches, private_vote_benches);
