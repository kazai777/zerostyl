<div align="center">

# ZeroStyl

**Privacy-preserving smart contracts on Arbitrum Stylus, in Rust.**

Build, debug, prove, and verify halo2 zk-SNARK circuits — then ship privacy-safe
contract ABIs and typed client SDKs.

[![CI](https://img.shields.io/github/actions/workflow/status/kazai777/zerostyl/ci.yml?branch=main&label=CI)](https://github.com/kazai777/zerostyl/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/github/actions/workflow/status/kazai777/zerostyl/coverage.yml?branch=main&label=coverage)](https://github.com/kazai777/zerostyl/actions/workflows/coverage.yml)
[![crates.io](https://img.shields.io/crates/v/zerostyl-sdk.svg?label=zerostyl-sdk)](https://crates.io/crates/zerostyl-sdk)
[![Docs](https://img.shields.io/badge/docs-zerostyl.dev-12AAFF)](https://docs.zerostyl.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Arbitrum Stylus](https://img.shields.io/badge/Arbitrum-Stylus-2D374B)](https://arbitrum.io/stylus)

[Website](https://zerostyl.dev) ·
[Documentation](https://docs.zerostyl.dev) ·
[Dashboard](https://zerostyl.dev/dashboard) ·
[Changelog](CHANGELOG.md)

</div>

> [!WARNING]
> **Active development — not production-ready.** APIs, proof formats, and circuit
> implementations may change. Do not deploy to mainnet. See [Security & status](#security--status).

ZeroStyl is a Rust toolchain that closes the gap between zk-SNARK circuit development and
EVM-compatible contracts. You write privacy logic as halo2 circuits (KZG commitment on BN254),
validate and prove them locally with a focused set of CLI tools, and export privacy-safe ABIs plus
typed TypeScript, Python, and Rust bindings — everything runs locally, with no external proving service.

## Table of contents

- [Highlights](#highlights)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command-line tools](#command-line-tools)
- [Circuits](#circuits)
- [Workspace layout](#workspace-layout)
- [Add your own circuit](#add-your-own-circuit)
- [Client SDKs](#client-sdks)
- [Documentation](#documentation)
- [Development](#development)
- [MSRV & platforms](#msrv--platforms)
- [Security & status](#security--status)
- [Contributing](#contributing)
- [License](#license)

## Highlights

- **Local end-to-end workflow** — debug a witness, generate a proof, and verify it, all off-chain.
- **halo2-KZG on BN254** — the PSE halo2 fork with a SHPLONK/Keccak transcript, aligned with the
  universal on-chain verifier path.
- **Readable diagnostics** — on a failing witness, `zerostyl-debug` surfaces the failing gate near
  the top and strips the clutter: **−72% output lines · −74% noise · −90% cell-value dump** versus
  bare halo2 (reproduce with the bundled benchmark).
- **Three reference circuits** — confidential state assertions, private transfers, anonymous voting.
- **Privacy-safe ABI export** — `#[zk_private]` turns an annotated Stylus function into a circuit, a
  descriptor, a privacy-safe ABI (`abi.json`), and a transformed contract.
- **Typed SDKs** — one `abi.json`, three clients (Rust, TypeScript, Python).
- **`no_std` verifier** — a Stylus-ready halo2-KZG verifier; `zerostyl-orbit` reports whether it
  fits a given chain's on-chain size budget.
- **Plug-in by design** — implement one trait, register with one line, and every tool picks the
  circuit up automatically.

## Installation

**Prerequisites:** Rust **1.85+** (`rustup update stable`).

### CLI tools — build from source

The command-line binaries are built from the workspace:

```bash
git clone https://github.com/kazai777/zerostyl.git
cd zerostyl
cargo build --release
```

The binaries land in `target/release/` (`zerostyl-debug`, `zerostyl-prove`, `zerostyl-export`,
`zerostyl-orbit`). Add them to your `PATH`, or install individually:

```bash
cargo install --path crates/zerostyl-debugger   # zerostyl-debug
cargo install --path crates/zerostyl-cli        # zerostyl-prove
cargo install --path crates/zerostyl-exporter   # zerostyl-export
cargo install --path crates/zerostyl-orbit      # zerostyl-orbit
```

### Library crates — from crates.io

The reusable, halo2-free library crates are published:

```bash
cargo add zerostyl-sdk        # also: zerostyl-circuits, zerostyl-runtime, zerostyl-orbit
```

### Client SDKs

```bash
npm install @zerostyl/sdk-ts     # https://www.npmjs.com/package/@zerostyl/sdk-ts
pip install zerostyl-sdk         # https://pypi.org/project/zerostyl-sdk/
```

## Quick start

Debug → prove → verify, using the bundled `state_mask` circuit and an example witness:

```console
$ zerostyl-debug debug --circuit state_mask --witnesses witnesses/state_mask_valid.json

=== Debug Report: state_mask ===

Circuit: state_mask  k=10

Result: ALL CONSTRAINTS SATISFIED

$ zerostyl-prove generate --circuit state_mask --witnesses witnesses/state_mask_valid.json

ZeroStyl Prover — circuit: state_mask  k: 10
  Proof: 2720 bytes  →  proof.bin
  Public inputs  →  public_inputs.json
Done.

$ zerostyl-prove verify --circuit state_mask --proof proof.bin

ZeroStyl Verifier — circuit: state_mask  k: 10
  Proof is VALID
Done.
```

Step 1 runs the MockProver (instant — no keygen, no proof), so it is the fastest way to catch a bad
witness. From a fresh clone, prefix any command with `cargo run --bin <name> --`. Proving keys are
cached in `.zerostyl_cache/` after the first run.

## Command-line tools

| Tool | Crate | Purpose |
|------|-------|---------|
| `zerostyl-debug` | `zerostyl-debugger` | Inspect circuits, view witness assignments, and trace which constraint fails |
| `zerostyl-prove` | `zerostyl-cli` | Generate and verify halo2-KZG proofs off-chain |
| `zerostyl-export` | `zerostyl-exporter` | `#[zk_private]` → circuit + descriptor + privacy-safe ABI + typed bindings |
| `zerostyl-orbit` | `zerostyl-orbit` | Per-chain deployability analysis (size, gas, precompiles) |

Each tool is independent — use `zerostyl-debug` during development without ever touching the prover.

### zerostyl-debug

Inspect circuit structure and debug failing witnesses with readable diagnostics. On a failing
witness, the report surfaces the offending gate near the top and drops the deep constraint dump
bare halo2 prints — in the benchmark's debug scenario, −72% output lines and −74% noise.

```bash
zerostyl-debug inspect  --circuit state_mask                                   # columns, gates, constraints, degree
zerostyl-debug schema   --circuit state_mask                                   # expected witness JSON
zerostyl-debug witness  --circuit state_mask --witnesses witnesses/state_mask_valid.json
zerostyl-debug debug    --circuit state_mask --witnesses witnesses/state_mask_wrong_commitment.json

cargo run -p debug-workflow-bench --release -- --verbose                       # reproduce the diagnostics benchmark
```

### zerostyl-prove

Generate and verify halo2 proofs off-chain, using the same witness files as `zerostyl-debug`
(see the transcript in [Quick start](#quick-start)).

```bash
zerostyl-prove generate --circuit state_mask --witnesses witnesses/state_mask_valid.json
zerostyl-prove verify   --circuit state_mask --proof proof.bin   # --inputs defaults to public_inputs.json
zerostyl-prove info     state_mask                               # circuit metadata + witness format
```

## Circuits

| Circuit | `k` | What it proves |
|---------|-----|----------------|
| `state_mask` | 10 | A hidden `collateral_ratio` lies in `[150, 300]` and `hidden_balance > threshold`, committing to the secret values with a Poseidon hash |
| `tx_privacy` | 14 | A token transfer is valid — balance conservation, Merkle membership of the spent note, and an unlinkable nullifier |
| `private_vote` | 11 | A voter's `balance ≥ threshold` and a valid boolean vote, committing to both with Poseidon |

### Witness files

Witnesses are JSON documents of decimal (or `0x`-hex) field strings. Print the exact schema for any
circuit with `zerostyl-debug schema --circuit <name>`. Example (`witnesses/state_mask_valid.json`):

```json
{ "state_value": "42", "nonce": "123", "collateral_ratio": "200", "hidden_balance": "500", "threshold": "100" }
```

Inject a deliberate fault with a `_debug` override (unknown fields are ignored by the circuit, so the
prover forces the given value) — used to demonstrate a failing witness:

```json
{ "state_value": "42", "nonce": "123", "collateral_ratio": "200", "hidden_balance": "500",
  "threshold": "100", "_debug": { "commitment": "999" } }
```

Eight example witnesses, valid and broken, live in [`witnesses/`](witnesses/).

## Workspace layout

```
crates/
├── zerostyl-circuits    Backend-agnostic circuit descriptors, registry & ABI schema (no halo2 dep)   [crates.io]
├── zerostyl-gadgets     no_std/wasm32 halo2 gadgets — Poseidon, range, comparison, Merkle
├── zerostyl-compiler    halo2 circuit construction shared by the reference circuits
├── zerostyl-runtime     On-chain runtime primitives — privacy event schema & bytecode fingerprint     [crates.io]
├── zerostyl-verifier    no_std halo2-KZG verifier for the Arbitrum Stylus runtime
├── zerostyl-sdk         Rust client — registry, prove/verify, witness builder, proof envelope          [crates.io]
├── zerostyl-orbit       Per-chain deployability analysis + `zerostyl-orbit` CLI                        [crates.io]
├── zerostyl-debugger    `zerostyl-debug` binary — circuit inspection & witness diagnostics
├── zerostyl-cli         `zerostyl-prove` binary — off-chain proving & verification
└── zerostyl-exporter    `zerostyl-export` binary — #[zk_private] → circuit + ABI + bindings

packages/                TypeScript (@zerostyl/sdk-ts) and Python (zerostyl-sdk) client SDKs
examples/                Reference circuits and the #[zk_private] worked example
contracts/               Stylus verifier contracts (built outside the workspace)
docs/                    Architecture, extending guide, STARK feasibility, deployments
```

## Add your own circuit

ZeroStyl is plug-in by design: implement the `CircuitDescriptor` trait, register it with one line,
and the CLI, debugger, and ABI exporter all pick it up automatically. See
[docs/EXTENDING.md](docs/EXTENDING.md) for the five-step recipe and
[`examples/example_demo/`](examples/example_demo/) for the minimal template.

## Client SDKs

Three SDKs consume the exporter's language-neutral `abi.json`:

| Language | Package | Registry | Scope |
|----------|---------|----------|-------|
| Rust | [`zerostyl-sdk`](crates/zerostyl-sdk/) | [crates.io](https://crates.io/crates/zerostyl-sdk) | Full client — registry, prove/verify, witness builder, proof envelope |
| TypeScript | [`@zerostyl/sdk-ts`](packages/sdk-ts/) | [npm](https://www.npmjs.com/package/@zerostyl/sdk-ts) | `abi.json` → typed TypeScript module |
| Python | [`zerostyl-sdk`](packages/sdk-py/) | [PyPI](https://pypi.org/project/zerostyl-sdk/) | `abi.json` → typed dataclasses, pure Python |

```bash
npx zerostyl-sdk generate --abi abi.json --out circuit.ts      # TypeScript bindings
zerostyl-sdk-py generate  --abi abi.json --out bindings.py     # Python bindings
```

The remaining crates (`zerostyl-gadgets`, `zerostyl-compiler`, `zerostyl-verifier`, `zerostyl-cli`,
`zerostyl-exporter`, `zerostyl-debugger`) are used from a clone — they depend on the halo2 PSE fork
via `[patch.crates-io]`, which crates.io cannot express. Proof generation from TypeScript/Python and
on-chain submission helpers are planned for subsequent releases.

## Documentation

- **[docs.zerostyl.dev](https://docs.zerostyl.dev)** — guides, tutorials, CLI and circuit reference.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system design, proof system, size constraints.
- [docs/EXTENDING.md](docs/EXTENDING.md) — add your own circuit (manual or `#[zk_private]`).
- [docs/STARK_FEASIBILITY.md](docs/STARK_FEASIBILITY.md) — why halo2-KZG today, and when a
  post-quantum STARK backend would make sense.
- [contracts/CONTRACTS.md](contracts/CONTRACTS.md) — deployed contracts and the on-chain
  verification model.
- [CHANGELOG.md](CHANGELOG.md) · [docs/RELEASING.md](docs/RELEASING.md) — versioning and release process.

## Development

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
```

## MSRV & platforms

- **MSRV:** Rust 1.85.
- **Tested on:** Linux (x86_64) and macOS (Apple Silicon and x86_64).
- **Windows:** via WSL2 (native builds are not supported).

## Security & status

ZeroStyl is under active development and has **not** been audited. It is not production-ready and is
not deployed to any mainnet. The testnet contracts on Arbitrum Sepolia currently record a proof hash
and do **not** yet verify the SNARK on-chain — their integrity guarantees are conditional. Read the
"Current Security Model" section of [contracts/CONTRACTS.md](contracts/CONTRACTS.md) before relying
on anything here.

Found a vulnerability? Please open a security advisory on the repository rather than a public issue.

## Contributing

Contributions are welcome. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) before opening a pull
request.

## License

MIT — see [LICENSE](LICENSE).
