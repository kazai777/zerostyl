# zerostyl-runtime

Shared, `no_std` runtime types for the [ZeroStyl](https://github.com/kazai777/zerostyl) privacy
toolkit on Arbitrum Stylus: proof/commitment types, a standardized privacy-transaction event, and
bytecode fingerprinting.

## Installation

```toml
[dependencies]
zerostyl-runtime = "0.1.0"
# For a Stylus contract / wasm32 target:
# zerostyl-runtime = { version = "0.1.0", default-features = false }
```

The crate is `no_std` (only `alloc` is required). The default `std` feature adds `std::io` error
interop; disable it for on-chain / wasm builds.

## Quick example

```rust
use zerostyl_runtime::{BytecodeFingerprint, ZeroStylPrivacyTransaction, ZkProof};

// Validate a proof blob (minimum size enforced).
let proof = ZkProof::new(vec![0u8; 192]).unwrap();

// Fingerprint the circuit / contract bytecode (keccak256).
let circuit = BytecodeFingerprint::of(b"...contract wasm bytes...");
println!("circuit = {}", circuit.to_hex());

// The standardized event every ZeroStyl contract emits. `topic0()` is the EVM log topic
// (keccak256 of the canonical signature) that indexers filter on.
let _sig = ZeroStylPrivacyTransaction::SIGNATURE;
let _topic0 = ZeroStylPrivacyTransaction::topic0();
```

## What it provides

- **`ZeroStylPrivacyTransaction`** — the canonical privacy-transaction event (circuit fingerprint,
  nullifier, commitment, merkle root, proof hash, timestamp). Single source of truth for the event
  schema and its EVM `topic0`, shared by every ZeroStyl contract and off-chain indexer. Carries no
  private witness data.
- **`BytecodeFingerprint`** — a keccak256 digest of contract bytecode / verifying key, giving a
  stable on-chain-comparable "which circuit produced this proof" identifier.
- **Core types** — `ZkProof`, `CommitmentHash`, `MerkleRoot`, `MerklePath`, `RangeProofConfig`,
  `CircuitConfig`, all with input validation.
- **`ZeroStylError` / `Result`** — the shared error type (the `IoError` variant is `std`-only).
- **`DEV_SRS_SEED`** — the fixed development KZG SRS seed shared by the prover and the on-chain
  verifier (reproducible dev setup, not a ceremony).

## Validation constraints

- `ZkProof`: minimum 32 bytes.
- `MerklePath`: non-empty, matching siblings/indices lengths.
- `CircuitConfig`: `k` within halo2's supported range.

## License

MIT — see [LICENSE](../../LICENSE).
