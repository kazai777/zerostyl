//! Private Vote circuit demonstration

use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;

fn main() {
    println!("=== Private Vote Circuit Demo ===\n");

    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fp::from(42);
    let randomness_vote = Fp::from(84);

    println!("Setting up circuit:");
    println!("  Balance: {} (private)", balance);
    println!("  Threshold: {} (public)", threshold);
    println!("  Vote: {} (private)", vote);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

    let public_inputs = vec![balance_commitment, Fp::from(threshold), vote_commitment];

    println!("\nRunning MockProver (k=10)...");
    let prover = MockProver::run(10, &circuit, vec![public_inputs]).unwrap();
    match prover.verify() {
        Ok(()) => println!("Verification PASSED"),
        Err(e) => println!("Verification FAILED: {:?}", e),
    }
}
