# zerostyl-runtime

Shared runtime utilities and types for the ZeroStyl toolkit.

## Installation

```toml
[dependencies]
zerostyl-runtime = "0.1.0"
```

## Quick Example

```rust
use zerostyl_runtime::{ZkProof, Commitment, CircuitConfig, HashType};

// Create a zero-knowledge proof (minimum 32 bytes)
let proof = ZkProof::new(vec![0u8; 192]).unwrap();
println!("Proof size: {} bytes", proof.size());

// Create a cryptographic commitment
let commitment = Commitment::new(
    vec![100, 200],        // value to commit
    vec![0u8; 32],         // randomness (min 32 bytes)
    HashType::Pedersen     // hash function
).unwrap();

// Configure a circuit (k must be in range [4, 28])
let mut config = CircuitConfig::minimal(17).unwrap(); // 2^17 = 131,072 rows
config.add_param("max_transfers".to_string(), "10".to_string());
println!("Circuit has {} rows", config.num_rows());
```

## Features

- Core types used across all ZeroStyl components
- Input validation with security constraints
- Serialization support (JSON via serde)
- Comprehensive error handling with `ZeroStylError`
- Type-safe circuit configuration

## Types

### Core Types
- **`ZkProof`**: Zero-knowledge SNARK proof (min 32 bytes)
- **`Commitment`**: Cryptographic commitment with configurable hash
- **`CircuitConfig`**: halo2 circuit configuration with validation
- **`ZeroStylError`**: Unified error type with detailed messages

### Supporting Types
- **`HashType`**: Pedersen or Poseidon hash functions
- **`LookupTable`**: SHA256 and Pedersen lookup tables
- **`CustomGate`**: PedersenHash and MerklePathGate

## Validation Constraints

- `ZkProof`: Minimum 32 bytes
- `Commitment`: Randomness minimum 32 bytes, non-empty value
- `CircuitConfig`: k must be in range [4, 28] (halo2 requirement)

## Part of ZeroStyl Toolkit

This crate is part of the [ZeroStyl privacy toolkit](https://github.com/kazai777/zerostyl) for Arbitrum Stylus.

See the main repository for complete documentation.

## License

MIT - See [LICENSE](../../LICENSE) for details
