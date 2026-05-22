//! Private Vote circuit demonstration

use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use private_vote::PrivateVoteCircuit;

fn main() {
    println!("=== Private Vote Circuit Demo ===\n");

    let balance = 100u64;
    let threshold = 50u64;
    let vote = 1u64;
    let randomness_balance = Fr::from(42);
    let randomness_vote = Fr::from(84);

    println!("Setting up circuit:");
    println!("  Balance: {} (private)", balance);
    println!("  Threshold: {} (public)", threshold);
    println!("  Vote: {} (private)", vote);

    let circuit =
        PrivateVoteCircuit::new(balance, randomness_balance, vote, randomness_vote, threshold);

    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fr::from(balance), randomness_balance);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fr::from(vote), randomness_vote);

    let public_inputs = vec![balance_commitment, Fr::from(threshold), vote_commitment];

    println!("\nRunning MockProver (k=10)...");
    let prover = MockProver::run(10, &circuit, vec![public_inputs]).unwrap();
    match prover.verify() {
        Ok(()) => println!("Verification PASSED"),
        Err(e) => println!("Verification FAILED: {:?}", e),
    }
}
