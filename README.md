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

### Prerequisites

- **Rust 1.70+** ([install from rustup.rs](https://rustup.rs/))
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/kazai777/zerostyl.git
cd zerostyl

# Run setup script (installs tools, builds workspace, runs tests)
./scripts/setup.sh

# Verify installation
./scripts/check.sh
```

### Current Status

The project is currently in **Phase 0 - Infrastructure ✅** (completed).

The `zerostyl-runtime` crate is functional and ready to use:

```rust
use zerostyl_runtime::{ZkProof, Commitment, CircuitConfig};

// Create a zero-knowledge proof
let proof = ZkProof::new(vec![1, 2, 3, 4]);
println!("Proof size: {} bytes", proof.size());

// Create a Pedersen commitment
let commitment = Commitment::new(
    vec![100, 200],  // value
    vec![50, 75]     // randomness
);

// Configure a zk-SNARK circuit
let mut config = CircuitConfig::minimal(17); // 2^17 rows
config.add_param("max_transfers".to_string(), "10".to_string());
println!("Circuit has {} rows", config.num_rows());
```

**Next:** Milestone 1 implementation starts with the `zk-compiler` (halo2 circuit parser and WASM compilation).

---

## Project Status

| Phase | Status | Timeline |
|-------|--------|----------|
| **Phase 0: Infrastructure** | ✅ Complete | Weeks 1-2 |
| **Milestone 1: zk-Compiler** | 🚧 In Progress | Months 1-2 |
| **Milestone 2: Privacy Debugger** | ⏳ Planned | Months 3-4 |
| **Milestone 3: ABI Exporter** | ⏳ Planned | Months 5-6 |

**Current Focus:** Building the core compiler infrastructure and halo2 integration.

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

### Using Scripts

We provide helper scripts for common development tasks:

```bash
# Setup development environment (first time only)
./scripts/setup.sh

# Run all tests with coverage
./scripts/test.sh

# Full validation (build + test + clippy + fmt)
./scripts/check.sh

# Clean build artifacts
./scripts/clean.sh
```

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

### Project Structure

```
zerostyl/
├── crates/
│   ├── zerostyl-compiler/    # M1: zk-SNARK compiler (in development)
│   ├── zerostyl-debugger/    # M2: Privacy debugger (planned)
│   ├── zerostyl-exporter/    # M3: ABI exporter (planned)
│   └── zerostyl-runtime/     # ✅ Shared runtime (completed - 29 tests)
├── docs/                     # Architecture & contribution guides
│   ├── ARCHITECTURE.md       # Technical deep dive
│   └── CONTRIBUTING.md       # Contributor guidelines
├── scripts/                  # Development utilities
│   ├── setup.sh              # Initial setup
│   ├── test.sh               # Run tests + coverage
│   ├── check.sh              # Pre-commit validation
│   └── clean.sh              # Clean workspace
└── examples/                 # Example circuits (coming in M1)
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

---

<div align="center">

**Built with ❤️ for the privacy-first Web3 future**

</div>
