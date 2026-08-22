//! The canonical circuit ABI schema (`abi.json`).
//!
//! [`AbiSchema`] is the language-neutral contract between the exporter, the
//! SDK generators (TypeScript, Rust, Python), and on-chain tooling: it
//! describes a circuit's witness fields, public inputs, and proof metadata.

use serde::{Deserialize, Serialize};

use crate::descriptor::CircuitDescriptor;
use crate::schema::{PublicInputsSchema, WitnessSchema};

/// Current version of the ABI JSON layout.
pub const ABI_VERSION: u32 = 1;

/// Top-level `abi.json` document describing one circuit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiSchema {
    /// ABI layout version ([`ABI_VERSION`]).
    pub abi_version: u32,
    /// Circuit identity and dimensions.
    pub circuit: CircuitMetadata,
    /// Private witness fields.
    pub witness: WitnessSchema,
    /// Public input fields, in instance-column order.
    pub public_inputs: PublicInputsSchema,
    /// Proof format metadata.
    pub proof: ProofMetadata,
    /// Optional binding to a deployed on-chain verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_chain: Option<OnChainBinding>,
}

impl AbiSchema {
    /// The ABI layout version this crate writes ([`ABI_VERSION`]).
    pub fn current_version() -> u32 {
        ABI_VERSION
    }

    /// Build the schema of a live [`CircuitDescriptor`].
    ///
    /// Proof metadata defaults to [`ProvingSystem::Halo2Kzg`] with no size
    /// estimate, matching what the toolkit's provers produce.
    pub fn from_descriptor(desc: &dyn CircuitDescriptor) -> AbiSchema {
        AbiSchema {
            abi_version: ABI_VERSION,
            circuit: CircuitMetadata {
                name: desc.name().to_string(),
                version: desc.version().to_string(),
                description: desc.description().to_string(),
                default_k: desc.default_k(),
                num_public_inputs: desc.num_public_inputs(),
                num_private_witnesses: desc.num_private_witnesses(),
            },
            witness: desc.witness_schema().clone(),
            public_inputs: desc.public_inputs_schema().clone(),
            proof: ProofMetadata {
                format_version: 1,
                approx_size_bytes: None,
                proving_system: ProvingSystem::Halo2Kzg,
            },
            on_chain: None,
        }
    }
}

/// Circuit identity and dimensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitMetadata {
    /// Circuit name (registry key).
    pub name: String,
    /// Circuit semantic version.
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Default halo2 `k` parameter (2^k rows).
    pub default_k: u32,
    /// Number of public inputs.
    pub num_public_inputs: usize,
    /// Number of private witness fields.
    pub num_private_witnesses: usize,
}

/// Proof format metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofMetadata {
    /// Proof wire-format version.
    pub format_version: u32,
    /// Approximate proof size in bytes, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approx_size_bytes: Option<usize>,
    /// Proving system that produced/verifies the proof.
    pub proving_system: ProvingSystem,
}

/// Supported proving systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvingSystem {
    /// halo2 with IPA polynomial commitment on Pasta curves.
    /// Transparent (no trusted setup), large verifier.
    Halo2Ipa,
    /// halo2-IPA proofs wrapped via halo2-KZG aggregation + final Groth16
    /// wrap on BN254. Universal on-chain verifier path.
    Halo2KzgGroth16Wrap,
    /// halo2 with KZG commitment on BN254 directly. Requires trusted setup.
    Halo2Kzg,
    /// STARK with FRI-based commitment. Transparent, post-quantum-friendly.
    StarkFri,
}

/// Binding of a circuit to a deployed on-chain verifier contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainBinding {
    /// EVM chain id of the deployment.
    pub chain_id: u64,
    /// Verifier contract address (`0x`-prefixed hex).
    pub contract_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{FieldType, FieldVisibility, PublicInputField, WitnessField};

    fn sample_witness() -> WitnessSchema {
        WitnessSchema {
            fields: vec![WitnessField {
                name: "x".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: None,
            }],
        }
    }

    fn sample_public() -> PublicInputsSchema {
        PublicInputsSchema {
            fields: vec![PublicInputField {
                name: "commitment".into(),
                kind: FieldType::Fp,
                description: None,
            }],
        }
    }

    fn sample_schema() -> AbiSchema {
        AbiSchema {
            abi_version: AbiSchema::current_version(),
            circuit: CircuitMetadata {
                name: "demo".into(),
                version: "1.0.0".into(),
                description: "test".into(),
                default_k: 4,
                num_public_inputs: 1,
                num_private_witnesses: 1,
            },
            witness: sample_witness(),
            public_inputs: sample_public(),
            proof: ProofMetadata {
                format_version: 1,
                approx_size_bytes: Some(3520),
                proving_system: ProvingSystem::Halo2Kzg,
            },
            on_chain: None,
        }
    }

    #[test]
    fn current_version_is_1() {
        assert_eq!(AbiSchema::current_version(), 1);
    }

    #[test]
    fn schema_serde_roundtrip() {
        let schema = sample_schema();
        let json = serde_json::to_string(&schema).unwrap();
        let back: AbiSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, back);
    }

    #[test]
    fn on_chain_none_is_omitted_in_json() {
        let schema = sample_schema();
        let json = serde_json::to_string(&schema).unwrap();
        assert!(!json.contains("on_chain"));
    }

    #[test]
    fn on_chain_binding_roundtrip() {
        let mut schema = sample_schema();
        schema.on_chain = Some(OnChainBinding {
            chain_id: 421614,
            contract_address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        });
        let json = serde_json::to_string(&schema).unwrap();
        let back: AbiSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, back);
        assert!(json.contains("chain_id"));
    }

    #[test]
    fn proving_system_snake_case() {
        let s = serde_json::to_string(&ProvingSystem::Halo2KzgGroth16Wrap).unwrap();
        assert_eq!(s, "\"halo2_kzg_groth16_wrap\"");
    }

    #[test]
    fn proof_metadata_approx_size_optional() {
        let m = ProofMetadata {
            format_version: 1,
            approx_size_bytes: None,
            proving_system: ProvingSystem::StarkFri,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("approx_size_bytes"));
    }
}
