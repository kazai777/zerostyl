use serde::{Deserialize, Serialize};

pub use zerostyl_circuits::{PublicInputsSchema, WitnessSchema};

use crate::version::ABI_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbiSchema {
    pub abi_version: u32,
    pub circuit: CircuitMetadata,
    pub witness: WitnessSchema,
    pub public_inputs: PublicInputsSchema,
    pub proof: ProofMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_chain: Option<OnChainBinding>,
}

impl AbiSchema {
    pub fn current_version() -> u32 {
        ABI_VERSION
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub default_k: u32,
    pub num_public_inputs: usize,
    pub num_private_witnesses: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofMetadata {
    pub format_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approx_size_bytes: Option<usize>,
    pub proving_system: ProvingSystem,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainBinding {
    pub chain_id: u64,
    pub contract_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerostyl_circuits::{FieldType, FieldVisibility, PublicInputField, WitnessField};

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
                proving_system: ProvingSystem::Halo2Ipa,
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
