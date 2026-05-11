# Extending ZeroStyl with your own circuit

ZeroStyl ships with four built-in circuits (`example`, `state_mask`, `tx_privacy`, `private_vote`). Adding your own takes about ten minutes if you already have a halo2 circuit handy.

The toolkit's CLI (`zerostyl-prove`), debugger (`zerostyl-debug`), and — soon — the ABI exporter and SDK generators all consume circuits through a single trait: [`CircuitDescriptor`](../crates/zerostyl-circuits/src/descriptor.rs). Implement that trait once, hand the resulting `&'static dyn CircuitDescriptor` to a `Registry`, and your circuit is wired into every tool.

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

Coming next (M3 bloc A and B): the ABI exporter will produce a privacy-safe Solidity/Stylus ABI from your `witness_schema()` and `public_inputs_schema()`, and the SDK generators will emit TypeScript / Rust / Python clients targeting that ABI.

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
