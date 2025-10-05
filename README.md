# ZeroStyl 🔐

[![Build Status](https://img.shields.io/github/actions/workflow/status/kazai777/zerostyl/ci.yml?branch=main)](https://github.com/kazai777/zerostyl/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Arbitrum Stylus](https://img.shields.io/badge/Arbitrum-Stylus-blue)](https://arbitrum.io/stylus)

**Privacy Toolkit for Arbitrum Stylus**

---

## 📖 Description

**ZeroStyl** is a comprehensive toolkit for building privacy-preserving smart contracts on Arbitrum Stylus using zero-knowledge proofs (zk-SNARKs). It bridges the gap between cryptographic theory and practical Web3 development by providing Rust-native tools specifically designed for the Stylus environment.

Despite the proven benefits of zero-knowledge cryptography for privacy and scalability, **only 20% of Web3 developers** have adopted zk technologies due to steep learning curves, complex tooling, and limited integration with modern smart contract platforms. ZeroStyl addresses these challenges by offering a streamlined development experience that makes privacy-first applications accessible to all Rust developers.

Our mission is to **reduce zk-SNARK development time by 50%** and **boost privacy adoption by 30%** within the Arbitrum ecosystem, empowering developers to build the next generation of private, scalable decentralized applications.

---

## ✨ Features

ZeroStyl consists of three integrated components designed to cover the entire privacy development workflow:

### 🔧 **zk-Compiler**
Compiles halo2 zk-SNARK circuits to WASM bytecode optimized for Arbitrum Stylus contracts. Seamlessly integrates cryptographic proofs into your smart contract logic with minimal overhead.

### 🐛 **Privacy Debugger**
Debug privacy-preserving applications with zk-mocking capabilities. Inspect circuit constraints, witness values, and proof generation without compromising sensitive data during development.

### 📦 **ABI Exporter**
Generates privacy-safe Application Binary Interfaces (ABIs) for zk-powered Stylus contracts, ensuring seamless integration with frontend applications and tooling while maintaining zero-knowledge guarantees.

---

## 🚀 Quick Start

### Installation

Add ZeroStyl to your Rust project:

```bash
cargo add zerostyl-compiler
cargo add zerostyl-runtime
```

### Basic Example

```rust
use zerostyl_runtime::{CircuitConfig, ZkProof};
use zerostyl_compiler::Compiler;

fn main() {
    // Configure your zk-SNARK circuit
    let config = CircuitConfig::minimal(17); // 2^17 rows

    // TODO: Compile circuit and generate proof
    // (Full examples coming in Milestone 1)

    println!("ZeroStyl is ready! 🔐");
}
```

---

## 📊 Project Status

| Phase | Status | Timeline |
|-------|--------|----------|
| **Phase 0: Infrastructure** | ✅ Complete | Weeks 1-2 |
| **Milestone 1: zk-Compiler** | 🚧 In Progress | Months 1-2 |
| **Milestone 2: Privacy Debugger** | ⏳ Planned | Months 3-4 |
| **Milestone 3: ABI Exporter** | ⏳ Planned | Months 5-6 |

**Current Focus:** Building the core compiler infrastructure and halo2 integration.

---

## 🏗️ Architecture

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

- **🦀 Rust** - Memory-safe systems programming
- **🔐 halo2_proofs** - State-of-the-art zk-SNARK library
- **⚡ Arbitrum Stylus SDK** - Next-gen smart contract platform
- **🌐 WebAssembly (WASM)** - High-performance execution target

---

## 💻 Development

### Build the workspace

```bash
cargo build --workspace
```

### Run all tests

```bash
cargo test --workspace
```

### Lint and format

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

### Build documentation

```bash
cargo doc --workspace --no-deps --open
```

---

## 🗺️ Roadmap

For detailed milestone breakdowns and technical specifications, see [docs/ROADMAP.md](docs/ROADMAP.md) *(coming soon)*.

**Key Milestones:**
1. **Q1 2025**: zk-Compiler with halo2 integration
2. **Q2 2025**: Privacy Debugger with constraint visualization
3. **Q3 2025**: ABI Exporter and ecosystem integration

---

## 🤝 Contributing

We welcome contributions from the community! Whether you're fixing bugs, adding features, or improving documentation, your help is appreciated.

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) *(coming soon)* for guidelines on:
- Code style and conventions
- Testing requirements
- Pull request process
- Community standards

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

ZeroStyl is made possible by:

- **Arbitrum DAO Grant Program** - Financial support and ecosystem collaboration
- **halo2 Community** - Pioneering zk-SNARK research and tooling
- **Stylus Team** - Next-generation smart contract platform
- **Open Source Contributors** - Everyone who helps make privacy accessible

---

## 📬 Contact & Community

- **GitHub Issues**: [Report bugs or request features](https://github.com/kazai777/zerostyl/issues)
- **Discussions**: [Join the conversation](https://github.com/kazai777/zerostyl/discussions)
- **Twitter**: [@zerostyl_dev](https://twitter.com/zerostyl_dev) *(placeholder)*

---

<div align="center">

**Built with ❤️ for the privacy-first Web3 future**

[Documentation](https://docs.zerostyl.dev) • [Examples](examples/) • [Changelog](CHANGELOG.md)

</div>
