# Extending ZeroStyl with your own circuit

ZeroStyl ships with four built-in circuits (`example`, `state_mask`, `tx_privacy`, `private_vote`). There are two ways to add your own:

1. **`#[zk_private]` annotations** — write a Stylus contract with declarative privacy attributes on the params you want to hide; `zerostyl-export transform` generates the halo2 circuit, the descriptor, the privacy-safe ABI, and an `abi.json` schema in one shot. Best when your circuit fits the supported attribute matrix (commit / range / constraint / merkle_member). See [Faster path: `#[zk_private]` annotations](#faster-path-zk_private-annotations).
2. **Manual descriptor** — write the halo2 circuit by hand and implement `CircuitDescriptor` directly. Use this when your constraints don't fit the supported attributes (custom gates, non-standard chip composition).

Both paths produce a `&'static dyn CircuitDescriptor` registered the same way, so the CLI, the debugger, and the ABI/SDK tooling consume them identically.

---

## The five-step recipe

The minimal template is [`examples/example_demo/`](../examples/example_demo). Read its ~250 lines side-by-side with this guide — every section below maps to a part of that crate.

### 1. Write your halo2 circuit

Create a crate (or add a module to an existing one) and implement `halo2_proofs::plonk::Circuit<Fp>`:

```rust
// my_circuit/src/lib.rs
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::pasta::Fp;

#[derive(Clone, Default)]
pub struct MyCircuit {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl Circuit<Fp> for MyCircuit {
    type Config = /* your config */;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config { /* … */ }
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        /* … */
    }
}
```

Add `zerostyl-circuits`, `zerostyl-compiler`, `halo2_proofs`, `halo2curves` to your `Cargo.toml` dependencies.

### 2. Add `descriptor.rs`

Implement [`CircuitDescriptor`](../crates/zerostyl-circuits/src/descriptor.rs) for a zero-sized struct:

```rust
// my_circuit/src/descriptor.rs
use std::path::Path;
use std::sync::OnceLock;

use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::Circuit;
use halo2curves::pasta::Fp;
use serde::Deserialize;
use zerostyl_circuits::{
    CircuitDescriptor, CircuitError, CircuitIntrospection, FieldType, FieldVisibility,
    MockProverReport, ProofArtifact, PublicInputField, PublicInputsSchema, Result,
    WitnessField, WitnessSchema,
};
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

use crate::MyCircuit;

const NAME: &str = "my_circuit";
const DEFAULT_K: u32 = 8;
// ...

struct MyDescriptor;

impl CircuitDescriptor for MyDescriptor {
    fn name(&self) -> &'static str { NAME }
    fn version(&self) -> &'static str { "0.1.0" }
    fn description(&self) -> &'static str { "What your circuit proves." }
    fn default_k(&self) -> u32 { DEFAULT_K }
    fn num_public_inputs(&self) -> usize { 1 }
    fn num_private_witnesses(&self) -> usize { 2 }
    fn witness_schema(&self) -> &'static WitnessSchema { /* WitnessField for each input */ }
    fn public_inputs_schema(&self) -> &'static PublicInputsSchema { /* PublicInputField for each output */ }
    fn prove(&self, witness_json: &str, k: u32, cache_dir: &Path) -> Result<ProofArtifact> { /* … */ }
    fn verify(&self, proof: &[u8], inputs_json: &str, k: u32, cache_dir: &Path) -> Result<bool> { /* … */ }
    fn mock_prove(&self, witness_json: &str, k: u32) -> Result<MockProverReport> { /* … */ }
    fn inspect(&self) -> Result<CircuitIntrospection> { /* … */ }
}
```

The fastest way is to **copy `examples/example_demo/src/descriptor.rs` and rename**. Replace the `WitnessJson` struct, the `WitnessSchema`/`PublicInputsSchema` definitions, and the body of `build_inputs` to match your circuit.

### 3. Expose `pub fn descriptor()`

The canonical entry point — every ZeroStyl-aware crate exports this exact signature:

```rust
// my_circuit/src/descriptor.rs (bottom)
pub fn descriptor() -> &'static dyn CircuitDescriptor {
    static D: MyDescriptor = MyDescriptor;
    &D
}
```

Then in `lib.rs`:

```rust
pub mod descriptor;
pub use descriptor::descriptor;
```

### 4. Register in your binary

Use the [`register_circuit!`](../crates/zerostyl-circuits/src/macros.rs) macro to plug your crate into a `Registry`:

```rust
// your-binary/src/main.rs
use anyhow::Result;
use zerostyl_circuits::{register_circuit, Registry};

fn main() -> Result<()> {
    let registry = Registry::new();
    register_circuit!(registry, my_circuit)?;
    // also register any builtins you want to keep:
    register_circuit!(registry, state_mask)?;
    zerostyl_cli::run(&registry)
}
```

Add your crate to your binary's `Cargo.toml`:

```toml
[dependencies]
zerostyl-circuits = { path = "..." }
zerostyl-cli      = { path = "..." }   # or zerostyl-debugger, or both
my_circuit        = { path = "../my_circuit" }
```

### 5. Use it

```bash
# Show what your circuit expects
cargo run -- info my_circuit

# Generate a proof
cargo run -- generate --circuit my_circuit --witnesses my_witness.json

# Debug a failing witness
cargo run --bin zerostyl-debug -- debug --circuit my_circuit --witnesses bad.json
```

That's it. Your circuit is now indistinguishable from the built-ins — same CLI, same debugger, same schemas, same exporter (M3 bloc A) once it lands.

---

## What the trait gives you "for free"

Once your descriptor compiles, you immediately get:

| Tool | Command | Source |
|---|---|---|
| Proof generation | `zerostyl-prove generate --circuit my_circuit` | calls `descriptor.prove(...)` |
| Verification | `zerostyl-prove verify --circuit my_circuit` | calls `descriptor.verify(...)` |
| Schema + JSON template | `zerostyl-prove info my_circuit` | reads `witness_schema()` |
| Circuit introspection | `zerostyl-debug inspect --circuit my_circuit` | calls `descriptor.inspect()` |
| Failure diagnostics | `zerostyl-debug debug --circuit my_circuit --witnesses w.json` | calls `descriptor.mock_prove(...)` |
| Witness preview | `zerostyl-debug witness --circuit my_circuit --witnesses w.json` | reads `witness_schema()` |

In addition, `zerostyl-export schema --circuit my_circuit` serializes your descriptor to the canonical `AbiSchema` JSON format — the same format the SDK generators (TypeScript, Rust, Python) consume to emit client code targeting your circuit's privacy-safe ABI.

---

## Faster path: `#[zk_private]` annotations

Instead of writing the halo2 circuit by hand, annotate the params you want to hide on your Stylus function. `zerostyl-export transform` parses the source, composes a halo2 circuit from the M1 gadgets (Poseidon, range, comparison, Merkle), and writes four artifacts in one shot.

### Supported attributes

Each `#[zk_private(...)]` attribute key maps to a specific gadget. You can declare multiple attributes on the same parameter; they compose as a logical AND inside the circuit.

| Attribute | Effect | Gadget |
|---|---|---|
| `commit = "poseidon"` | Replace the raw value with `Poseidon(value, nonce)` as a public input | `PoseidonCommitmentChip` |
| `range = "a..b"` / `range = "a..=b"` | Prove `a <= value < b` (or `<=`) | `RangeProofChip` |
| `constraint = "value >= other"` | Prove a comparison against another fn param | `ComparisonChip` (`>=`, `>`, `<=`, `<`) |
| `constraint = "merkle_member(value, root, siblings, indices)"` | Prove membership in a depth-32 Merkle tree | `MerkleTreeChip` |

Supported param types: `u8`, `u16`, `u32`, `u64`, `u128`, `bool`, `U256`. Other types require the manual path.

### Worked example

The source contract:

```rust
// contract_source.rs
pub fn deposit(
    #[zk_private(
        commit = "poseidon",
        range = "0..1000000",
        constraint = "value >= threshold"
    )]
    collateral: u64,
    threshold: u64,
) -> bool {
    let _ = (collateral, threshold);
    true
}
```

Run the transform:

```bash
zerostyl-export transform --contract contract_source.rs
```

You get four artifacts in `./generated/`:

- **`circuit.rs`** — a halo2 `Circuit<Fp>` impl that wires `PoseidonCommitmentChip`, `RangeProofChip`, and `ComparisonChip` according to the attributes. Witnesses: `collateral`, `collateral_nonce`, `threshold`.
- **`descriptor.rs`** — a `CircuitDescriptor` impl with `prove` / `verify` / `mock_prove` / `inspect` implemented against `NativeProver` and `MockProver`. Also re-exposes `pub fn descriptor() -> &'static dyn CircuitDescriptor` so it slots into `register_circuit!`.
- **`contract_transformed.rs`** — the privacy-safe ABI:
  ```rust
  pub fn deposit(collateral_commitment: B256, threshold: u64, proof: Bytes) -> bool {
      todo!()  // verifier wiring lands with the universal on-chain verifier
  }
  ```
- **`abi.json`** — the canonical `AbiSchema` describing the witness fields, public inputs, and proof metadata. Same shape SDK generators consume.

### Integrating the generated artifacts

Drop the four files into a Cargo crate, expose `pub fn descriptor()` at the crate root, and register it:

```rust
// my_demo/src/lib.rs
pub mod circuit;
pub mod contract_transformed;
pub mod descriptor;
pub use descriptor::descriptor;
```

```rust
// main.rs (or wherever your tool lives)
use zerostyl_circuits::{register_circuit, Registry};

let registry = Registry::new();
register_circuit!(registry, my_demo)?;
```

The end-to-end reference is [`examples/zk_private_demo/`](../examples/zk_private_demo) — `contract_source.rs` + generated artifacts + a `tests/mock_prove.rs` that exercises the full pipeline.

### Limitations

- **One `commit = "poseidon"` per circuit.** The chip column layout doesn't accommodate multiple commits cleanly yet. Split into separate circuits if you need more than one.
- **MerkleMember requires a Poseidon commit on the same param.** The tree leaf is the commitment.
- **Equality comparison is not exposed** by `ComparisonChip`. Use a different gadget (or the manual path) when you need `value == other`.
- **No body inference.** ZeroStyl reads only the attribute declarations — the function body is ignored. Anything not expressible via the supported attributes requires the manual path.
- **The generated `contract_transformed.rs` body is `todo!()`.** Universal on-chain verifier wiring lands in a later milestone; until then, the transformed ABI is a stub.

---

## Design conventions to follow

- **Witness JSON shape**: every field is a string (`u64` decimals or `"0x…"` hex). Arrays are JSON arrays of strings. See `examples/example_demo/`, `examples/state_mask/`, and `examples/tx_privacy/` for examples ranging from "2 scalars" to "5 scalars + two 32-element arrays".
- **`_debug` overrides** (optional): if you accept a `_debug` object in your witness, document which public inputs it can override. The `state_mask` descriptor lets you inject a wrong `commitment` to surface the commitment-check failure in the MockProver — useful for tutorials and testing.
- **Cache keys**: `NativeProver::with_cache_dir(..., cache_dir)` keys files by `circuit_name`. Pick a unique name; never reuse a builtin's.
- **Errors**: return `CircuitError::InvalidWitness(...)` for user-input problems and `CircuitError::ProveFailed(...)` / `CircuitError::VerifyFailed(...)` for downstream halo2 errors. Avoid panicking — the CLI wraps everything in `anyhow` and your messages reach the user.

---

## Troubleshooting

**`circuit '<name>' not found in registry`** — you forgot to `register_circuit!` it in your binary.

**`circuit '<name>' is already registered`** — two crates exported the same `name()`. Pick a unique one; the registry refuses overwrites on purpose.

**`thread 'main' panicked at ... left != right`** — your circuit's `Circuit::synthesize` is panicking on the witness. Run with `--bin zerostyl-debug debug` to surface the failing constraint structurally.

**Slow first run, fast after** — `NativeProver::setup` caches IPA parameters and keys under `.zerostyl_cache/` (~few MB per `k`). Delete the directory to force regeneration.

---

## Reference

- Trait definition: [`crates/zerostyl-circuits/src/descriptor.rs`](../crates/zerostyl-circuits/src/descriptor.rs)
- Schema types: [`crates/zerostyl-circuits/src/schema.rs`](../crates/zerostyl-circuits/src/schema.rs)
- Macro: [`crates/zerostyl-circuits/src/macros.rs`](../crates/zerostyl-circuits/src/macros.rs)
- Minimal template: [`examples/example_demo/`](../examples/example_demo/)
- Realistic templates: [`examples/state_mask/`](../examples/state_mask/), [`examples/tx_privacy/`](../examples/tx_privacy/), [`examples/private_vote/`](../examples/private_vote/)
