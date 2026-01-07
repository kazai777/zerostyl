# ZeroStyl

[![Build Status](https://img.shields.io/github/actions/workflow/status/kazai777/zerostyl/ci.yml?branch=main)](https://github.com/kazai777/zerostyl/actions)
[![Coverage](https://github.com/kazai777/zerostyl/workflows/Coverage/badge.svg)](https://github.com/kazai777/zerostyl/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Arbitrum Stylus](https://img.shields.io/badge/Arbitrum-Stylus-blue)](https://arbitrum.io/stylus)

**Privacy Toolkit for Arbitrum Stylus**

---

## Description

**ZeroStyl** is an open-source Rust toolkit for building privacy-preserving smart contracts on **Arbitrum Stylus** using zero-knowledge proofs (zk-SNARKs).

### The Challenge

Zero-knowledge cryptography offers powerful privacy guarantees, but integration complexity remains a major barrier for smart contract developers. Existing tools require deep cryptographic expertise and lack native support for modern platforms like Arbitrum Stylus.

### Our Solution

**ZeroStyl** bridges this gap by providing Rust-native tools specifically designed for Stylus (WASM-based smart contracts with 10x EVM performance):

- **Automated circuit compilation** from high-level Rust code
- **Developer-friendly debugging** with zk-mocking capabilities
- **Privacy-safe ABI generation** for seamless frontend integration

By simplifying the zk-SNARK development workflow, **ZeroStyl** makes privacy-first applications accessible to all Rust developers.

---

## Features

ZeroStyl consists of three integrated components designed to cover the entire privacy development workflow:

### **zk-Compiler**

Compiles halo2 zk-SNARK circuits to WASM bytecode optimized for Arbitrum Stylus.

**Included Circuits:**
- `tx_privacy`: Transaction privacy using Pedersen commitments and Merkle proofs (depth 32)
- `state_mask`: State masking with range proofs and comparison gates

**Target performance:** <100ms proof generation

### **Privacy Debugger**

Debug privacy-preserving applications with zk-mocking capabilities. Inspect circuit constraints, witness values, and proof generation without compromising sensitive data during development.

### **ABI Exporter**

Generates privacy-safe Application Binary Interfaces (ABIs) for zk-powered Stylus contracts, ensuring seamless integration with frontend applications and tooling while maintaining zero-knowledge guarantees.

---

## Use Cases

ZeroStyl enables privacy-preserving applications across DeFi, gaming, and beyond:

**Private DeFi**
- Confidential lending (hide collateral amounts from liquidation bots)
- Anonymous token swaps (dark pool trading like Renegade)
- Private DAO voting (prove token holdings without revealing balance)

**Privacy-First Gaming**
- Hidden player stats and inventories
- Confidential in-game transactions
- Private matchmaking and rankings

**Compliance & KYC**
- Prove regulatory compliance without revealing identity
- Selective disclosure of credentials
- Privacy-preserving audit trails

---

## Quick Start

### Try It Yourself (2 Commands)

```bash
# 1. Clone and build
git clone https://github.com/kazai777/zerostyl.git && cd zerostyl && cargo build --release

# 2. Run the privacy circuit demo
cargo run --example tx_privacy_demo -p tx_privacy
```

### Prerequisites

- **Rust 1.70+** ([install from rustup.rs](https://rustup.rs/))
- **Git**

### Full Installation

```bash
# Clone the repository
git clone https://github.com/kazai777/zerostyl.git
cd zerostyl

# Build and test everything
cargo build --workspace --release
cargo test --workspace

# Run benchmarks
cargo bench -p tx_privacy
cargo bench -p state_mask
```

### Example: Private Transfer Circuit

```rust
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use halo2curves::pasta::Fp;

// Create a private transfer: 1000 -> 700 (amount: 300)
let circuit = TxPrivacyCircuit::new(
    1000,                           // balance_old
    700,                            // balance_new
    Fp::from(42),                   // randomness_old
    Fp::from(84),                   // randomness_new
    300,                            // amount
    vec![Fp::from(0); MERKLE_DEPTH] // merkle_path (depth 32)
);

// Generate and verify proof
let prover = NativeProver::new(circuit, 10)?;
let proof = prover.generate_proof(&public_inputs)?;
assert!(prover.verify_proof(&proof, &public_inputs)?);
```

### Example: Range Proof Circuit

```rust
use state_mask::StateMaskCircuit;
use halo2curves::pasta::Fp;

// Prove value 42 is in range [0, 255] without revealing it
let circuit = StateMaskCircuit::new(
    42,             // secret value
    Fp::from(123),  // randomness
    0,              // range_min
    255             // range_max
);
```

---

## Project Status

| Phase | Status |
|-------|--------|
| **Phase 0: Infrastructure** | ✅ Complete |
| **Milestone 1: zk-Compiler** | ✅ Complete |
| **Milestone 2: Privacy Debugger** | ⏳ Planned |
| **Milestone 3: ABI Exporter** | ⏳ Planned |

---


## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for more details on the architecture.

```
┌─────────────────────┐
│ zerostyl-compiler   │──┐
│ (halo2 → WASM)      │  │
└─────────────────────┘  │
                          │
┌─────────────────────┐  │    ┌──────────────────────┐
│ zerostyl-debugger   │  │    │ zerostyl-runtime     │
│ (zk-mocking)        │──┼───▶│ (shared types/error) │
└─────────────────────┘  │    └──────────────────────┘
                          │
┌─────────────────────┐  │
│ zerostyl-exporter   │──┘
│ (privacy-safe ABI)  │
└─────────────────────┘
```

**Design Principles:**
- **Modular**: Each component is independently usable
- **Type-safe**: Rust's type system prevents common zk pitfalls
- **Performant**: WASM-optimized for on-chain execution
- **Developer-friendly**: Clear APIs with comprehensive documentation

---

## 🛠️ Tech Stack

- **Rust** - Memory-safe systems programming
- **halo2_proofs** - State-of-the-art zk-SNARK library
- **Arbitrum Stylus SDK** - Next-gen smart contract platform
- **WebAssembly (WASM)** - High-performance execution target

---

## Development

### Manual Commands

```bash
# Build workspace
cargo build --workspace

# Run tests
cargo test --workspace

# Run linter
cargo clippy --workspace --all-targets --all-features

# Format code
cargo fmt --all

# Generate documentation
cargo doc --workspace --no-deps --open
```

---

## Contributing

We welcome contributions from the community! Whether you're fixing bugs, adding features, or improving documentation, your help is appreciated.

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines on:
- Code style and conventions
- Testing requirements (target: 80%+ coverage)
- Pull request process
- Commit message conventions
- Code of conduct

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Contact & Community

- **GitHub Issues**: [Report bugs or request features](https://github.com/kazai777/zerostyl/issues)
- **Discussions**: [Join the conversation](https://github.com/kazai777/zerostyl/discussions)

