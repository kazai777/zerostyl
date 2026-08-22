//! Loading and validating `abi.json` documents.

use std::fs;
use std::path::Path;

use zerostyl_circuits::{AbiSchema, ABI_VERSION};

use crate::error::{Result, SdkError};

/// Parse an [`AbiSchema`] from a JSON string and validate it.
pub fn load_abi_str(json: &str) -> Result<AbiSchema> {
    let schema: AbiSchema = serde_json::from_str(json)?;
    validate(&schema)?;
    Ok(schema)
}

/// Read and parse an `abi.json` file.
pub fn load_abi_file(path: &Path) -> Result<AbiSchema> {
    let json = fs::read_to_string(path)?;
    load_abi_str(&json)
}

fn validate(schema: &AbiSchema) -> Result<()> {
    if schema.abi_version != ABI_VERSION {
        return Err(SdkError::Abi(format!(
            "unsupported abi_version {} (this SDK supports {})",
            schema.abi_version, ABI_VERSION
        )));
    }
    if schema.circuit.num_public_inputs != schema.public_inputs.fields.len() {
        return Err(SdkError::Abi(format!(
            "circuit.num_public_inputs ({}) does not match public_inputs.fields length ({})",
            schema.circuit.num_public_inputs,
            schema.public_inputs.fields.len()
        )));
    }
    if schema.circuit.num_private_witnesses != schema.witness.fields.len() {
        return Err(SdkError::Abi(format!(
            "circuit.num_private_witnesses ({}) does not match witness.fields length ({})",
            schema.circuit.num_private_witnesses,
            schema.witness.fields.len()
        )));
    }
    if schema.circuit.name.is_empty() {
        return Err(SdkError::Abi("circuit.name is empty".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerostyl_circuits::{
        CircuitMetadata, FieldType, FieldVisibility, ProofMetadata, ProvingSystem,
        PublicInputField, PublicInputsSchema, WitnessField, WitnessSchema,
    };

    fn sample() -> AbiSchema {
        AbiSchema {
            abi_version: ABI_VERSION,
            circuit: CircuitMetadata {
                name: "demo".into(),
                version: "1.0.0".into(),
                description: "test".into(),
                default_k: 10,
                num_public_inputs: 1,
                num_private_witnesses: 1,
            },
            witness: WitnessSchema {
                fields: vec![WitnessField {
                    name: "x".into(),
                    kind: FieldType::U64,
                    visibility: FieldVisibility::Private,
                    description: None,
                }],
            },
            public_inputs: PublicInputsSchema {
                fields: vec![PublicInputField {
                    name: "x_commitment".into(),
                    kind: FieldType::Fp,
                    description: None,
                }],
            },
            proof: ProofMetadata {
                format_version: 1,
                approx_size_bytes: None,
                proving_system: ProvingSystem::Halo2Kzg,
            },
            on_chain: None,
        }
    }

    #[test]
    fn valid_schema_roundtrips() {
        let json = serde_json::to_string(&sample()).unwrap();
        let loaded = load_abi_str(&json).unwrap();
        assert_eq!(loaded, sample());
    }

    #[test]
    fn rejects_wrong_abi_version() {
        let mut schema = sample();
        schema.abi_version = 99;
        let json = serde_json::to_string(&schema).unwrap();
        let err = load_abi_str(&json).unwrap_err();
        assert!(format!("{err}").contains("abi_version"));
    }

    #[test]
    fn rejects_public_input_count_mismatch() {
        let mut schema = sample();
        schema.circuit.num_public_inputs = 3;
        let json = serde_json::to_string(&schema).unwrap();
        let err = load_abi_str(&json).unwrap_err();
        assert!(format!("{err}").contains("num_public_inputs"));
    }

    #[test]
    fn rejects_witness_count_mismatch() {
        let mut schema = sample();
        schema.circuit.num_private_witnesses = 0;
        let json = serde_json::to_string(&schema).unwrap();
        let err = load_abi_str(&json).unwrap_err();
        assert!(format!("{err}").contains("num_private_witnesses"));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(load_abi_str("{not json").is_err());
    }

    #[test]
    fn load_abi_file_reads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abi.json");
        std::fs::write(&path, serde_json::to_string(&sample()).unwrap()).unwrap();
        assert_eq!(load_abi_file(&path).unwrap(), sample());
    }
}
