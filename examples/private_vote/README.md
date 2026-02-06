# Private Vote Circuit

Zero-knowledge circuit for private voting, ensuring voter anonymity while verifying eligibility.

## Overview

This circuit proves in zero-knowledge that a user is eligible to vote (owns sufficient balance) and submits a valid vote (0 or 1) without revealing their exact balance or vote choice.

### Public Inputs

- `balance_commitment`: Commitment to the balance (Commit(balance, randomness_balance))
- `voting_threshold`: Minimum token balance required to vote
- `vote_commitment`: Commitment to the vote (Commit(vote, randomness_vote))

### Private Witnesses

- `balance`: Voter's actual token balance
- `randomness_balance`: Randomness for the balance commitment
- `vote`: The vote value (0 or 1)
- `randomness_vote`: Randomness for the vote commitment
- `bits`: Bit decomposition of (balance - threshold) over 8 bits

## Circuit Architecture

### Implemented Gates

1. **Commitment gate**: Verifies `balance + randomness - commitment == 0`
2. **Vote boolean gate**: Verifies `vote * (vote - 1) == 0` (boolean constraint)
3. **Vote commitment gate**: Verifies `vote + randomness - commitment == 0`
4. **Bit check gate**: Verifies each bit is 0 or 1
5. **Bit decomposition gate**: Verifies `balance - threshold == sum(bit_i * 2^i)`

### Configuration

- **Advice columns**: 3
- **Instance columns**: 1
- **Selectors**: 5 (s_commitment, s_vote_boolean, s_vote_commit, s_bit_check, s_bit_decompose)
- **k**: 10 (1024 rows)
- **RANGE_BITS**: 8 (proves balance - threshold < 256)

## Usage

### Run the demo

```bash
cargo run -p private_vote --example private_vote_demo
```

### Run tests

```bash
cargo test -p private_vote
```

### Run benchmarks

```bash
cargo bench -p private_vote
```

## Code Example

```rust
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;

// Vote configuration
let balance = 100u64;
let threshold = 50u64;
let vote = 1u64; // 0 for "no", 1 for "yes"
let randomness_balance = Fp::from(42);
let randomness_vote = Fp::from(84);

// Create the circuit
let circuit = PrivateVoteCircuit::new(
    balance,
    randomness_balance,
    vote,
    randomness_vote,
    threshold,
);

// Compute public inputs
let balance_commitment = PrivateVoteCircuit::compute_commitment(
    Fp::from(balance),
    randomness_balance
);
let vote_commitment = PrivateVoteCircuit::compute_commitment(
    Fp::from(vote),
    randomness_vote
);

let public_inputs = vec![
    balance_commitment,
    Fp::from(threshold),
    vote_commitment
];
```

## Security Properties

### What the circuit proves

1. The voter owns a balance >= voting threshold
2. The vote is strictly 0 or 1
3. The commitments are well-formed
4. The range proof on (balance - threshold) is valid

### What remains private

- The voter's exact balance (only the commitment is public)
- The vote choice (0 or 1) (only the commitment is public)
- The commitment randomness values

### Limitations

- **Simplified commitment**: This circuit uses `commitment = value + randomness` which is a simplified form. Production use requires true Pedersen commitments with `EccChip`.
- **Limited range proof**: The range proof is limited to 8 bits (balance - threshold < 256).
- **No double-vote protection**: This circuit only validates individual votes. Double-vote protection requires an additional layer (nullifiers, merkle trees).

## Benchmark Caveats

The benchmarks in this crate use **simplified binding commitments** (`value + randomness`) instead of true Pedersen commitments (elliptic curve point multiplication).

A production implementation with real Pedersen commitments (using EccChip) would:
- Require significantly more constraints (hundreds to thousands more)
- Need a larger circuit size (k=12-14 instead of k=10)
- Be approximately **10-100x slower**

The current benchmarks are representative of the M2 implementation, NOT of a cryptographically secure production system.

## Tests

The circuit includes comprehensive tests:

- Vote "yes" valid (vote=1)
- Vote "no" valid (vote=0)
- Balance exactly at threshold
- Zero threshold
- Zero balance and zero threshold
- Invalid vote (vote=2) - should panic
- Insufficient balance (balance < threshold) - should panic
- Commitment computation
- Circuit without witnesses (for keygen)

## Arbitrum Stylus Integration

This circuit can be integrated into a Stylus contract to create an on-chain voting system with privacy. The Stylus smart contract would manage:

1. Registration of balance commitments
2. Vote submission (commitments)
3. ZK proof verification
4. Double-vote prevention (via nullifiers)
5. Vote tallying

## References

- Pattern based on `tx_privacy` and `state_mask`
- Uses standard gates from the zerostyl framework
- Compatible with the compiler/runtime/verifier workflow
