use zerostyl_circuits::CircuitDescriptor;

use crate::{
    schema::{AbiSchema, CircuitMetadata, ProofMetadata, ProvingSystem},
    version::ABI_VERSION,
};

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
            proving_system: ProvingSystem::Halo2Ipa,
        },
        on_chain: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::OnceLock;
    use zerostyl_circuits::{
        CircuitIntrospection, FieldType, FieldVisibility, MockProverReport, ProofArtifact,
        PublicInputField, PublicInputsSchema, Result as CResult, WitnessField, WitnessSchema,
    };

    struct DummyDescriptor;

    fn witness() -> &'static WitnessSchema {
        static S: OnceLock<WitnessSchema> = OnceLock::new();
        S.get_or_init(|| WitnessSchema {
            fields: vec![WitnessField {
                name: "secret".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: Some("test field".into()),
            }],
        })
    }

    fn public() -> &'static PublicInputsSchema {
        static S: OnceLock<PublicInputsSchema> = OnceLock::new();
        S.get_or_init(|| PublicInputsSchema {
            fields: vec![PublicInputField {
                name: "commit".into(),
                kind: FieldType::Fp,
                description: None,
            }],
        })
    }

    impl CircuitDescriptor for DummyDescriptor {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn description(&self) -> &'static str {
            "a test circuit"
        }
        fn default_k(&self) -> u32 {
            4
        }
        fn num_public_inputs(&self) -> usize {
            1
        }
        fn num_private_witnesses(&self) -> usize {
            1
        }
        fn witness_schema(&self) -> &'static WitnessSchema {
            witness()
        }
        fn public_inputs_schema(&self) -> &'static PublicInputsSchema {
            public()
        }
        fn prove(&self, _: &str, _: u32, _: &Path) -> CResult<ProofArtifact> {
            unimplemented!()
        }
        fn verify(&self, _: &[u8], _: &str, _: u32, _: &Path) -> CResult<bool> {
            unimplemented!()
        }
        fn mock_prove(&self, _: &str, _: u32) -> CResult<MockProverReport> {
            unimplemented!()
        }
        fn inspect(&self) -> CResult<CircuitIntrospection> {
            unimplemented!()
        }
    }

    #[test]
    fn populates_circuit_metadata_from_descriptor() {
        let abi = from_descriptor(&DummyDescriptor);
        assert_eq!(abi.circuit.name, "dummy");
        assert_eq!(abi.circuit.version, "0.1.0");
        assert_eq!(abi.circuit.description, "a test circuit");
        assert_eq!(abi.circuit.default_k, 4);
        assert_eq!(abi.circuit.num_public_inputs, 1);
        assert_eq!(abi.circuit.num_private_witnesses, 1);
    }

    #[test]
    fn copies_witness_and_public_input_schemas() {
        let abi = from_descriptor(&DummyDescriptor);
        assert_eq!(abi.witness.fields.len(), 1);
        assert_eq!(abi.witness.fields[0].name, "secret");
        assert_eq!(abi.public_inputs.fields.len(), 1);
        assert_eq!(abi.public_inputs.fields[0].name, "commit");
    }

    #[test]
    fn defaults_to_halo2_ipa_and_unknown_size() {
        let abi = from_descriptor(&DummyDescriptor);
        assert_eq!(abi.proof.proving_system, ProvingSystem::Halo2Ipa);
        assert_eq!(abi.proof.approx_size_bytes, None);
        assert_eq!(abi.proof.format_version, 1);
    }

    #[test]
    fn abi_version_matches_constant() {
        let abi = from_descriptor(&DummyDescriptor);
        assert_eq!(abi.abi_version, ABI_VERSION);
    }

    #[test]
    fn on_chain_is_none_by_default() {
        let abi = from_descriptor(&DummyDescriptor);
        assert!(abi.on_chain.is_none());
    }

    #[test]
    fn roundtrips_through_json() {
        let abi = from_descriptor(&DummyDescriptor);
        let json = serde_json::to_string(&abi).unwrap();
        let back: AbiSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(abi, back);
    }
}
