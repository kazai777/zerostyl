# ZeroStyl Stylus Contracts

On-chain components of the ZeroStyl privacy framework, deployed on Arbitrum Stylus.

---

## Honest Assessment: What These Contracts Do (and Don't Do)

> Read this section before deploying. It matters for understanding the security model.

### Without ZeroStyl

These contracts are pure state machines. They:
- Accept a `bytes32` keccak256 hash of the proof (no cryptographic verification of the proof itself)
- Track commitments, nullifiers, and merkle roots in on-chain mappings
- Emit events on state changes

> **Why `bytes32` instead of `bytes`?** Passing raw proof bytes (~3.5 KB) as calldata triggers a
> known ABI dispatcher limitation in stylus-sdk 0.9.x with `Vec<u8>` parameters. The proof hash
> preserves the audit trail (verifiers can confirm off-chain that the proof matches) while working
> within current SDK constraints.

### With ZeroStyl

ZeroStyl provides the off-chain layer that gives these contracts real cryptographic meaning:

1. **ZeroStyl circuits** define the constraints (balance conservation, range checks, vote validity)
2. **ZeroStyl NativeProver** generates a real halo2/IPA proof that witnesses satisfy constraints
3. **ZeroStyl CLI** (`zerostyl-prove`) handles the full workflow: generate proof → verify locally → submit

The privacy guarantee is real regardless: private witnesses (balances, randomness, vote values)
are never submitted to the chain. Even without on-chain verification, the data privacy holds —
only commitments and proof bytes reach the blockchain.

### Current Security Model (Testnet)

| Property | Status |
|----------|--------|
| Data privacy (witnesses never on-chain) | ✅ Enforced by design |
| Double-spend / double-vote prevention | ✅ Enforced by nullifier sets |
| Merkle membership enforcement | ✅ Enforced by root registry |
| Cryptographic proof validity | ⚠️ Verified off-chain only (client-side) |
| On-chain SNARK verification | 🔜 Pending Stylus WASM size increase |

**This is testnet-ready**: demonstrates the full ZK privacy workflow. Not production-ready until
on-chain verification is enabled.

---

## Architecture

```
┌──────────────────────────────────────┐    ┌─────────────────────────────────────┐
│         OFF-CHAIN (Client)           │    │        ON-CHAIN (Stylus)            │
│                                      │    │                                     │
│  1. Define private witnesses:        │    │  4. Accept proof hash (bytes32)      │
│     balances, amounts, randomness    │    │  5. Protocol-specific state checks  │
│                                      │    │     (nullifiers, roots, registry)   │
│  2. Build halo2 circuit              │    │  6. Update state on success         │
│     (ZeroStyl circuit crate)         │    │  7. Emit events                     │
│                                      │    │                                     │
│  3. Generate + verify proof          │    │  Private data NEVER touches         │
│     (zerostyl-prove generate)        │───>│  the blockchain.                    │
│     → proof.bin (~1-2 KB)            │    │                                     │
│     → public_inputs.json             │    │  On-chain SNARK verification:       │
└──────────────────────────────────────┘    │  enabled when Stylus supports       │
                                            │  larger WASM contracts (~130 KB).   │
                                            └─────────────────────────────────────┘
```

---

## Contracts

### 1. TxPrivacyVerifier — `contracts/tx_privacy_verifier/`

Manages private token transfers. A sender proves they have sufficient balance and a valid
commitment in the merkle tree, without revealing their balance or amount.

**Circuit**: `tx_privacy` | **WASM size**: ~18 KB
**Arbitrum Sepolia Contract**: 0x0c61c2d2f15a2f26c13bbe9882e56d545f393bd3
**Demo**: `vhs docs/assets/tx_privacy.tape` → [`docs/assets/tx_privacy.gif`](../docs/assets/tx_privacy.gif)

The ZeroStyl proof guarantees:
- `commitment_old = Poseidon(balance_old, randomness_old)`
- `commitment_new = Poseidon(balance_new, randomness_new)`
- `balance_new = balance_old − amount` (balance conservation)
- `commitment_old` is a leaf in the registered merkle tree

| Method | Caller | Description |
|--------|--------|-------------|
| `initialize()` | Deployer (once) | Sets caller as owner |
| `registerMerkleRoot(root)` | Owner | Register a valid merkle root |
| `depositCommitment(commitment)` | Anyone | Deposit a new commitment |
| `verifyTransfer(proof_hash, commitment_old, commitment_new, merkle_root)` | Anyone | Submit a transfer |
| `isSpent(commitment)` | Read | Is this commitment in the nullifier set? |
| `commitmentOwner(commitment)` | Read | Who created this commitment? |
| `isValidRoot(root)` | Read | Is this merkle root registered? |
| `getVerifiedCount()` | Read | Total verified transfers |
| `getOwner()` | Read | Contract owner address |
| `isInitialized()` | Read | Is the contract initialized? |

**Events**: `PrivateTransferVerified`, `TransferRejected`, `MerkleRootRegistered`, `CommitmentDeposited`

**On-chain checks**: merkle root registered → nullifier not spent

---

### 2. StateMaskVerifier — `contracts/state_mask_verifier/`

Registers state proofs: proves a hidden value satisfies range/comparison constraints
without revealing the value itself.

**Circuit**: `state_mask` | **Use cases**: collateral ratios, credit score thresholds, balance minimums
**Arbitrum Sepolia Contract**: 0xf88346c0a80690a2f9d359f70d157fa36f1be7e0
**Demo**: `vhs docs/assets/state_mask.tape` → [`docs/assets/state_mask.gif`](../docs/assets/state_mask.gif)

The ZeroStyl proof guarantees:
- `commitment = Poseidon(state_value, nonce)`
- `collateral_ratio ∈ [150, 300]` (range constraint)
- `hidden_balance > threshold` (comparison constraint)

| Method | Caller | Description |
|--------|--------|-------------|
| `initialize()` | Deployer (once) | Sets caller as owner |
| `verifyRangeProof(proof_hash, commitment)` | Anyone | Submit a verified state proof |
| `isVerified(commitment)` | Read | Has this commitment been proven? |
| `commitmentProver(commitment)` | Read | Who submitted the proof for this commitment? |
| `getVerifiedCount()` | Read | Total verified proofs |
| `getOwner()` | Read | Contract owner address |
| `isInitialized()` | Read | Is the contract initialized? |

**Events**: `RangeProofVerified`, `RangeProofRejected`

**On-chain checks**: commitment not already registered

---

### 3. PrivateVoteVerifier — `contracts/private_vote_verifier/`

Anonymous DAO voting with eligibility proofs. Nobody on-chain can link a vote to a voter.
The tally is public; individual votes are cryptographically hidden.

**Circuit**: `private_vote` | **Anti-fraud**: nullifier prevents double-voting
**Arbitrum Sepolia Contract**: 0xd21389dffe34235a9f8d6c4e88ac1fec70670edf
**Demo**: `vhs docs/assets/private_vote.tape` → [`docs/assets/private_vote.gif`](../docs/assets/private_vote.gif)

The ZeroStyl proof guarantees:
- `balance_commitment = Poseidon(balance, randomness_balance)`
- `vote_commitment = Poseidon(vote, randomness_vote)`
- `balance ≥ threshold` (eligibility)
- `vote ∈ {0, 1}` (boolean vote)

| Method | Caller | Description |
|--------|--------|-------------|
| `initialize()` | Deployer (once) | Sets caller as owner |
| `openVoting(threshold)` | Owner | Open voting with eligibility threshold |
| `castVote(proof_hash, balance_commitment, vote_commitment, is_yes)` | Anyone | Submit a private vote |
| `closeVoting()` | Owner | Close voting, emit final tally |
| `hasVoted(balance_commitment)` | Read | Has this commitment already voted? |
| `getYesVotes()` | Read | Current YES tally |
| `getNoVotes()` | Read | Current NO tally |
| `getTotalVotes()` | Read | Total votes cast |
| `getThreshold()` | Read | Minimum balance to vote |
| `isVotingOpen()` | Read | Is voting currently active? |
| `getOwner()` | Read | Contract owner address |
| `isInitialized()` | Read | Is the contract initialized? |

**Events**: `VoteCast`, `VoteRejected`, `VotingOpened`, `VotingClosed`

**On-chain checks**: voting open → nullifier not used

---

### 4. PrivateLendingPool — `contracts/private_lending_pool/`

Mock DeFi lending pool with privacy-preserving solvency proofs. Depositors prove they
are solvent on a schedule without revealing their exact balance to liquidators or competitors.

**Circuit**: `state_mask` | **Use case**: prove `balance ≥ min_collateral` without revealing balance
**Arbitrum Sepolia Contract**: 0xaa948bd92dbe5b1de9af384add42fc6859288f36
**Demo**: `vhs docs/assets/lending_pool.tape` → [`docs/assets/lending_pool.gif`](../docs/assets/lending_pool.gif)

The ZeroStyl proof guarantees (reuses state_mask circuit):
- `commitment = Poseidon(balance, nonce)`
- `collateral_ratio ∈ [150, 300]` (range constraint)
- `balance > threshold` (solvency: balance exceeds min_collateral)

| Method | Caller | Description |
|--------|--------|-------------|
| `initialize(proof_expiry)` | Deployer (once) | Setup with solvency proof TTL in seconds |
| `deposit(commitment)` | Anyone | Deposit an opaque commitment |
| `proveSolvency(proof_hash, commitment)` | Anyone | Refresh solvency proof timestamp |
| `checkLiquidation(commitment)` | Anyone | Trigger liquidation if proof expired or missing |
| `isSolvent(commitment)` | Read | Is this commitment's proof still valid? |
| `getDepositor(commitment)` | Read | Depositor address (zero if not deposited) |
| `getLastSolvencyProof(commitment)` | Read | Last solvency proof timestamp (unix) |
| `getDepositCount()` | Read | Total commitments deposited |
| `getSolvencyProofCount()` | Read | Total solvency proofs submitted |
| `getProofExpiry()` | Read | Proof TTL in seconds |
| `getOwner()` | Read | Contract owner address |
| `isInitialized()` | Read | Is the contract initialized? |

**Events**: `CommitmentDeposited`, `SolvencyVerified`, `LiquidationTriggered`, `SolvencyRejected`

**On-chain checks**: commitment deposited → proof expiry on liquidation

---

### 5. PrivateSwapVerifier — `contracts/private_swap_verifier/`

Multi-circuit private swaps. Combines `tx_privacy` (balance transfer) and `state_mask`
(amount range check) to swap tokens without revealing position size to frontrunners.

**Circuits**: `tx_privacy` + `state_mask`
**Arbitrum Sepolia Contract**: 0xd5dfa87f650453dbb5f3da46b6faadf02134bb76
**Demo**: `vhs docs/assets/private_swap.tape` → [`docs/assets/private_swap.gif`](../docs/assets/private_swap.gif)

The ZeroStyl proofs guarantee:
- `commitment_in = Poseidon(balance_old, randomness_old)` — input commitment is valid
- `commitment_out = Poseidon(balance_new, randomness_new)` — output commitment is valid
- `balance_new = balance_old − amount` (balance conservation)
- `amount_commitment = Poseidon(amount, randomness)` — amount is committed
- `collateral_ratio ∈ [150, 300]` (range constraint on swap amount)

| Method | Caller | Description |
|--------|--------|-------------|
| `initialize()` | Deployer (once) | Sets caller as owner |
| `registerMerkleRoot(root)` | Owner | Register a valid merkle root |
| `verifySwap(transfer_proof_hash, range_proof_hash, commitment_in, commitment_out, merkle_root, amount_commitment)` | Anyone | Submit a verified swap |
| `isSpent(commitment)` | Read | Was this input commitment spent? |
| `isValidRoot(root)` | Read | Is this merkle root registered? |
| `isAmountVerified(amount_commitment)` | Read | Was this amount range-verified? |
| `commitmentOwner(commitment)` | Read | Who owns this output commitment? |
| `getSwapCount()` | Read | Total verified swaps |
| `getOwner()` | Read | Contract owner address |
| `isInitialized()` | Read | Is the contract initialized? |

**Events**: `PrivateSwapVerified`, `SwapRejected`, `MerkleRootRegistered`

**On-chain checks**: merkle root registered → nullifier not spent

---

## Project Structure

```
contracts/
├── tx_privacy_verifier/      # Private token transfers
│   ├── Cargo.toml            # stylus-sdk 0.9.0, alloy
│   ├── Stylus.toml           # cargo-stylus project marker
│   ├── rust-toolchain.toml   # Rust 1.85.0 + wasm32
│   └── src/
│       ├── lib.rs            # Contract logic
│       └── main.rs           # WASM entrypoint + ABI export
├── state_mask_verifier/      # Range proof registry
├── private_vote_verifier/    # Anonymous voting + tally
├── private_lending_pool/     # Solvency proofs + liquidation
└── private_swap_verifier/    # Multi-circuit private swaps
```

Each contract is an independent Rust crate with its own `rust-toolchain.toml` pinned to
Rust 1.85.0. Deployment addresses are tracked in [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md).
