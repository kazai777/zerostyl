use zerostyl_circuits::{
    CircuitDescriptor, FieldType, FieldVisibility, PublicInputField, PublicInputsSchema,
    WitnessField, WitnessSchema,
};

use crate::{
    error::{ExporterError, Result},
    resolver::{GadgetBinding, ResolvedAttr, MERKLE_DEPTH},
    schema::{AbiSchema, CircuitMetadata, ProofMetadata, ProvingSystem},
    version::ABI_VERSION,
};

pub const GENERATED_DESCRIPTOR_VERSION: &str = "1.0.0";
pub const GENERATED_DESCRIPTOR_DEFAULT_K: u32 = 10;

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

pub fn from_attrs(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<AbiSchema> {
    let witness = build_witness_schema(attrs)?;
    let public_inputs = build_public_inputs_schema(attrs);
    Ok(AbiSchema {
        abi_version: ABI_VERSION,
        circuit: CircuitMetadata {
            name: circuit_name.to_string(),
            version: GENERATED_DESCRIPTOR_VERSION.to_string(),
            description: format!(
                "Auto-generated descriptor for the '{circuit_name}' privacy-aware circuit."
            ),
            default_k: GENERATED_DESCRIPTOR_DEFAULT_K,
            num_public_inputs: public_inputs.fields.len(),
            num_private_witnesses: witness.fields.len(),
        },
        witness,
        public_inputs,
        proof: ProofMetadata {
            format_version: 1,
            approx_size_bytes: None,
            proving_system: ProvingSystem::Halo2Ipa,
        },
        on_chain: None,
    })
}

pub fn emit_abi_json(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<String> {
    let schema = from_attrs(circuit_name, attrs)?;
    serde_json::to_string_pretty(&schema)
        .map_err(|e| ExporterError::Other(format!("AbiSchema serialization failed: {e}")))
}

fn field_type_from(ty: &str) -> Result<FieldType> {
    let cleaned = ty.split("::").last().unwrap_or(ty).trim();
    match cleaned {
        "u8" | "u16" | "u32" | "u64" => Ok(FieldType::U64),
        "u128" => Ok(FieldType::U128),
        "bool" => Ok(FieldType::Bool),
        "U256" => Ok(FieldType::Fp),
        other => Err(ExporterError::Parse(format!(
            "cannot map type '{other}' to FieldType (supported: u8/u16/u32/u64/u128/bool/U256)"
        ))),
    }
}

fn build_witness_schema(attrs: &[ResolvedAttr]) -> Result<WitnessSchema> {
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut fields = Vec::new();

    for attr in attrs {
        if seen.insert(attr.param_name.clone()) {
            fields.push(WitnessField {
                name: attr.param_name.clone(),
                kind: field_type_from(&attr.param_type)?,
                visibility: FieldVisibility::Private,
                description: None,
            });
        }
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    if seen.insert(nonce_var.clone()) {
                        fields.push(WitnessField {
                            name: nonce_var.clone(),
                            kind: FieldType::Fp,
                            visibility: FieldVisibility::Private,
                            description: None,
                        });
                    }
                }
                GadgetBinding::Comparison { other, .. } => {
                    if is_simple_ident(other) && seen.insert(other.clone()) {
                        fields.push(WitnessField {
                            name: other.clone(),
                            kind: field_type_from(&attr.param_type)?,
                            visibility: FieldVisibility::Private,
                            description: None,
                        });
                    }
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    if seen.insert(root_var.clone()) {
                        fields.push(WitnessField {
                            name: root_var.clone(),
                            kind: FieldType::Fp,
                            visibility: FieldVisibility::Private,
                            description: None,
                        });
                    }
                    if seen.insert(siblings_var.clone()) {
                        fields.push(WitnessField {
                            name: siblings_var.clone(),
                            kind: FieldType::Array {
                                kind: Box::new(FieldType::Fp),
                                len: MERKLE_DEPTH,
                            },
                            visibility: FieldVisibility::Private,
                            description: None,
                        });
                    }
                    if seen.insert(indices_var.clone()) {
                        fields.push(WitnessField {
                            name: indices_var.clone(),
                            kind: FieldType::Array {
                                kind: Box::new(FieldType::Bool),
                                len: MERKLE_DEPTH,
                            },
                            visibility: FieldVisibility::Private,
                            description: None,
                        });
                    }
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }
    Ok(WitnessSchema { fields })
}

fn build_public_inputs_schema(attrs: &[ResolvedAttr]) -> PublicInputsSchema {
    let mut fields = Vec::new();
    for attr in attrs {
        for b in &attr.bindings {
            if matches!(b, GadgetBinding::PoseidonCommit { .. }) {
                fields.push(PublicInputField {
                    name: format!("{}_commitment", attr.param_name),
                    kind: FieldType::Fp,
                    description: None,
                });
            }
        }
    }
    PublicInputsSchema { fields }
}

fn is_simple_ident(s: &str) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty()
        && trimmed.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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

    use crate::parser::{AttrSpec, CommitScheme, Constraint, MerkleMemberSpec, RangeSpec};
    use crate::resolver::resolve;

    fn resolved(name: &str, ty: &str, specs: Vec<AttrSpec>) -> ResolvedAttr {
        let parsed =
            crate::parser::ZkPrivateAttr { param_name: name.into(), param_type: ty.into(), specs };
        resolve(&parsed).unwrap()
    }

    #[test]
    fn from_attrs_poseidon_only_emits_one_commitment_public_input() {
        let attrs =
            vec![resolved("collateral", "U256", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let abi = from_attrs("deposit", &attrs).unwrap();
        assert_eq!(abi.circuit.name, "deposit");
        assert_eq!(abi.circuit.num_public_inputs, 1);
        assert_eq!(abi.public_inputs.fields.len(), 1);
        assert_eq!(abi.public_inputs.fields[0].name, "collateral_commitment");
        assert_eq!(abi.public_inputs.fields[0].kind, FieldType::Fp);
        assert_eq!(abi.witness.fields.len(), 2);
        let names: Vec<&str> = abi.witness.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"collateral"));
        assert!(names.contains(&"collateral_nonce"));
    }

    #[test]
    fn from_attrs_range_only_has_no_public_inputs() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "100".into(),
                inclusive: true,
            })],
        )];
        let abi = from_attrs("rangeonly", &attrs).unwrap();
        assert_eq!(abi.circuit.num_public_inputs, 0);
        assert!(abi.public_inputs.fields.is_empty());
        assert_eq!(abi.witness.fields.len(), 1);
        assert_eq!(abi.witness.fields[0].name, "x");
        assert_eq!(abi.witness.fields[0].kind, FieldType::U64);
    }

    #[test]
    fn from_attrs_comparison_adds_other_witness() {
        let attrs = vec![resolved(
            "value",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))],
        )];
        let abi = from_attrs("compare", &attrs).unwrap();
        let names: Vec<&str> = abi.witness.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"value"));
        assert!(names.contains(&"threshold"));
    }

    #[test]
    fn from_attrs_merkle_emits_typed_array_witnesses() {
        let attrs = vec![resolved(
            "leaf",
            "U256",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
            ],
        )];
        let abi = from_attrs("merkle", &attrs).unwrap();
        let sib = abi.witness.fields.iter().find(|f| f.name == "siblings").unwrap();
        match &sib.kind {
            FieldType::Array { kind, len } => {
                assert_eq!(**kind, FieldType::Fp);
                assert_eq!(*len, MERKLE_DEPTH);
            }
            other => panic!("expected Array, got {other:?}"),
        }
        let idx = abi.witness.fields.iter().find(|f| f.name == "indices").unwrap();
        match &idx.kind {
            FieldType::Array { kind, len } => {
                assert_eq!(**kind, FieldType::Bool);
                assert_eq!(*len, MERKLE_DEPTH);
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    #[test]
    fn from_attrs_unknown_type_errors() {
        let attrs = vec![ResolvedAttr {
            param_name: "x".into(),
            param_type: "MyCustomType".into(),
            bindings: vec![GadgetBinding::PoseidonCommit { nonce_var: "x_nonce".into() }],
        }];
        let err = from_attrs("foo", &attrs).unwrap_err();
        assert!(format!("{err}").contains("MyCustomType"));
    }

    #[test]
    fn emit_abi_json_returns_pretty_serialized_schema() {
        let attrs =
            vec![resolved("collateral", "U256", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let json = emit_abi_json("deposit", &attrs).unwrap();
        assert!(json.contains("\"abi_version\": 1"));
        assert!(json.contains("\"name\": \"deposit\""));
        assert!(json.contains("\"proving_system\": \"halo2_ipa\""));
        let parsed: AbiSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.circuit.name, "deposit");
    }

    #[test]
    fn from_attrs_matches_generated_descriptor_constants() {
        let attrs =
            vec![resolved("collateral", "U256", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let abi = from_attrs("deposit", &attrs).unwrap();
        assert_eq!(abi.circuit.version, GENERATED_DESCRIPTOR_VERSION);
        assert_eq!(abi.circuit.default_k, GENERATED_DESCRIPTOR_DEFAULT_K);
        assert_eq!(
            abi.circuit.description,
            "Auto-generated descriptor for the 'deposit' privacy-aware circuit."
        );
        assert_eq!(abi.proof.proving_system, ProvingSystem::Halo2Ipa);
        assert_eq!(abi.proof.format_version, 1);
        assert!(abi.on_chain.is_none());
    }
}
