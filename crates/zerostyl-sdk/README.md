# zerostyl-sdk

Rust SDK for the [ZeroStyl](https://github.com/kazai777/zerostyl) zk toolkit on Arbitrum
Stylus. A thin, ergonomic facade over `zerostyl-circuits` (registry, descriptors, proof
formats) and `zerostyl-runtime` (standardized event, fingerprinting).

## What it provides

- **`ZeroStyl` client** — owns a circuit `Registry` and the KZG params cache directory;
  hands out `CircuitHandle`s.
- **`CircuitHandle`** — `prove` / `verify` (defaulting to the circuit's `k`),
  `mock_prove`, `inspect`, `abi()` (the same `AbiSchema` document the exporter writes),
  `circuit_id()` (keccak256 of the circuit name), and `seal`/`open` for the
  `CanonicalProof` wire envelope.
- **`WitnessBuilder`** — assembles the witness JSON descriptors consume
  (decimal / `0x`-hex strings, arrays for Merkle paths), with optional schema checking
  via `build_checked`.
- **`abi::load_abi_file` / `load_abi_str`** — load and validate `abi.json` documents.
- **`inputs`** — encode/decode the public-inputs wire format
  (`{"inputs": [["0x…", …]]}`, 32-byte little-endian `Fr::to_repr()` hex).
- Re-exports of the core types (`CircuitDescriptor`, `AbiSchema`, `ProofArtifact`,
  `ZeroStylPrivacyTransaction`, `BytecodeFingerprint`, …) so one dependency suffices.

## Example

```rust,no_run
use zerostyl_sdk::{WitnessBuilder, ZeroStyl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ZeroStyl::new()?;
    client.register(zk_private_demo::descriptor())?;

    let witness = WitnessBuilder::new()
        .set_u64("collateral", 500_000)
        .set_u64("collateral_nonce", 42)
        .set_u64("threshold", 100_000)
        .build();

    let circuit = client.circuit("deposit")?;
    let artifact = circuit.prove(&witness)?;
    assert!(circuit.verify(&artifact.bytes, &artifact.public_inputs_json)?);

    // Ship the proof in the canonical envelope (magic + circuit id + version).
    let sealed = circuit.seal(&artifact);
    let raw = circuit.open(&sealed)?;
    assert_eq!(raw, artifact.bytes);
    Ok(())
}
```

Any crate exposing `pub fn descriptor() -> &'static dyn CircuitDescriptor` plugs in the
same way — the exporter generates such a descriptor from `#[zk_private]` annotations
(see `docs/EXTENDING.md`).

## Scope and future work

The SDK wraps proving and verification on the host. Per-circuit generated Rust bindings
(typed witness structs emitted next to `abi.json`) and on-chain submission helpers are
future work — the TypeScript SDK (`packages/sdk-ts`) follows the same trajectory.

## License

MIT — see [LICENSE](../../LICENSE).
