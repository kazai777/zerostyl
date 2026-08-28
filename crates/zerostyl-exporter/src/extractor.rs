use zerostyl_circuits::{
    CircuitDescriptor, FieldType, FieldVisibility, PublicInputField, PublicInputsSchema,
    WitnessField, WitnessSchema,
};

use crate::{
    error::{ExporterError, Result},
    resolver::{
        public_input_layout, GadgetBinding, OperandBinding, PublicInput, ResolvedAttr, MERKLE_DEPTH,
    },
    schema::{AbiSchema, CircuitMetadata, ProofMetadata, ProvingSystem},
    version::ABI_VERSION,
};

pub const GENERATED_DESCRIPTOR_VERSION: &str = "1.0.0";
pub const GENERATED_DESCRIPTOR_DEFAULT_K: u32 = 10;

pub fn from_descriptor(desc: &dyn CircuitDescriptor) -> AbiSchema {
    AbiSchema::from_descriptor(desc)
}

pub fn from_attrs(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<AbiSchema> {
    let witness = build_witness_schema(attrs)?;
    let public_inputs = build_public_inputs_schema(attrs)?;
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
            num_private_witnesses: count_private(&witness),
        },
        witness,
        public_inputs,
        proof: ProofMetadata {
            format_version: 1,
            approx_size_bytes: None,
            proving_system: ProvingSystem::Halo2Kzg,
        },
        on_chain: None,
    })
}

pub fn emit_abi_json(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<String> {
    let schema = from_attrs(circuit_name, attrs)?;
    serde_json::to_string_pretty(&schema)
        .map_err(|e| ExporterError::Other(format!("AbiSchema serialization failed: {e}")))
}

/// Witness fields the schema marks private. Public operands stay in `witness.fields` — the prover
/// needs them to assign their cell — but they are counted as public inputs instead.
fn count_private(witness: &WitnessSchema) -> usize {
    witness.fields.iter().filter(|f| f.visibility == FieldVisibility::Private).count()
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
                // A public operand still travels in the witness document (the prover assigns the
                // cell) but is flagged public: the cell is copied into the instance column.
                GadgetBinding::Comparison { other, operand, .. } => {
                    if seen.insert(other.clone()) {
                        let (kind, visibility) = match operand {
                            OperandBinding::PublicInput { ty } => {
                                (field_type_from(ty)?, FieldVisibility::Public)
                            }
                            OperandBinding::PrivateWitness => {
                                (field_type_from(&attr.param_type)?, FieldVisibility::Private)
                            }
                        };
                        fields.push(WitnessField {
                            name: other.clone(),
                            kind,
                            visibility,
                            description: None,
                        });
                    }
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    // The root the prover supplies is checked against the recomputed one, which is
                    // an instance cell — so it is a public input, not a private witness.
                    if seen.insert(root_var.clone()) {
                        fields.push(WitnessField {
                            name: root_var.clone(),
                            kind: FieldType::Fp,
                            visibility: FieldVisibility::Public,
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

/// Mirrors `resolver::public_input_layout`, the single source of truth for the instance column, so
/// the ABI lists exactly the cells the generated circuit constrains, in the same order.
fn build_public_inputs_schema(attrs: &[ResolvedAttr]) -> Result<PublicInputsSchema> {
    let mut fields = Vec::new();
    for entry in public_input_layout(attrs) {
        let kind = match &entry {
            PublicInput::Commitment { .. } | PublicInput::MerkleRoot { .. } => FieldType::Fp,
            PublicInput::Param { ty, .. } => field_type_from(ty)?,
        };
        fields.push(PublicInputField { name: entry.name(), kind, description: None });
    }
    Ok(PublicInputsSchema { fields })
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
    fn defaults_to_halo2_kzg_and_unknown_size() {
        let abi = from_descriptor(&DummyDescriptor);
        assert_eq!(abi.proof.proving_system, ProvingSystem::Halo2Kzg);
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

    use crate::parser::{AttrSpec, CommitScheme, Constraint, FnParam, MerkleMemberSpec, RangeSpec};
    use crate::resolver::resolve;

    /// Resolve one annotated param; `extra` declares the rest of the enclosing signature.
    fn resolved_with(
        name: &str,
        ty: &str,
        specs: Vec<AttrSpec>,
        extra: Vec<FnParam>,
    ) -> ResolvedAttr {
        let parsed =
            crate::parser::ZkPrivateAttr { param_name: name.into(), param_type: ty.into(), specs };
        let mut params = vec![FnParam { name: name.into(), ty: ty.into(), is_private: true }];
        params.extend(extra);
        resolve(&parsed, &params).unwrap()
    }

    fn resolved(name: &str, ty: &str, specs: Vec<AttrSpec>) -> ResolvedAttr {
        resolved_with(name, ty, specs, vec![])
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
    fn from_attrs_public_comparison_operand_becomes_a_public_input() {
        let attrs = vec![resolved_with(
            "value",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))],
            vec![FnParam { name: "threshold".into(), ty: "u64".into(), is_private: false }],
        )];
        let abi = from_attrs("compare", &attrs).unwrap();

        // `threshold` is what the caller passes to the contract: it must be an instance cell, not a
        // witness the prover is free to pick.
        let public_names: Vec<&str> =
            abi.public_inputs.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(public_names, vec!["threshold"]);
        assert_eq!(abi.circuit.num_public_inputs, 1);

        // It still travels in the witness document (the prover must assign the cell), flagged
        // public so consumers know it is verifier-visible.
        assert_eq!(abi.witness.fields.len(), 2);
        let threshold = abi.witness.fields.iter().find(|f| f.name == "threshold").unwrap();
        assert_eq!(threshold.visibility, FieldVisibility::Public);
        let value = abi.witness.fields.iter().find(|f| f.name == "value").unwrap();
        assert_eq!(value.visibility, FieldVisibility::Private);

        // …and it does not inflate the private-witness count: only `value` is private.
        assert_eq!(abi.circuit.num_private_witnesses, 1);
    }

    #[test]
    fn from_attrs_private_comparison_operand_stays_a_private_witness() {
        let attrs = vec![resolved_with(
            "value",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Gte("other".into()))],
            vec![FnParam { name: "other".into(), ty: "u64".into(), is_private: true }],
        )];
        let abi = from_attrs("compare", &attrs).unwrap();
        assert!(abi.public_inputs.fields.is_empty());
        let other = abi.witness.fields.iter().find(|f| f.name == "other").unwrap();
        assert_eq!(other.visibility, FieldVisibility::Private);

        // A genuinely private operand does count towards num_private_witnesses.
        assert_eq!(abi.witness.fields.len(), 2);
        assert_eq!(abi.circuit.num_private_witnesses, 2);
    }

    #[test]
    fn from_attrs_num_private_witnesses_counts_only_private_fields() {
        let attrs = vec![resolved_with(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
            vec![FnParam { name: "threshold".into(), ty: "u64".into(), is_private: false }],
        )];
        let abi = from_attrs("deposit", &attrs).unwrap();

        assert_eq!(abi.witness.fields.len(), 3);
        assert_eq!(abi.circuit.num_private_witnesses, 2);
        assert_eq!(abi.circuit.num_public_inputs, 2);
        assert_eq!(
            abi.circuit.num_private_witnesses,
            abi.witness.fields.iter().filter(|f| f.visibility == FieldVisibility::Private).count()
        );
        assert_eq!(abi.circuit.num_public_inputs, abi.public_inputs.fields.len());
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
    fn from_attrs_merkle_exposes_commitment_and_root_public_inputs() {
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
        let abi = from_attrs("claim", &attrs).unwrap();
        // The recomputed Merkle root must be a public input alongside the commitment, otherwise
        // the membership proof is vacuous (any tree would satisfy it).
        assert_eq!(abi.circuit.num_public_inputs, 2);
        let names: Vec<&str> = abi.public_inputs.fields.iter().map(|f| f.name.as_str()).collect();
        // Order must match the circuit's instance bindings: commitment (idx 0), root (idx 1).
        assert_eq!(names, vec!["leaf_commitment", "root"]);
    }

    #[test]
    fn from_attrs_merkle_root_is_a_public_witness_field() {
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
        let abi = from_attrs("claim", &attrs).unwrap();

        // The root stays in the witness document — the prover assigns its cell — but it is checked
        // against the recomputed root bound to the instance column, so it is public.
        let root = abi.witness.fields.iter().find(|f| f.name == "root").unwrap();
        assert_eq!(root.visibility, FieldVisibility::Public);
        assert!(abi.public_inputs.fields.iter().any(|f| f.name == "root"));

        // …and it must not be counted as a private witness: leaf, leaf_nonce, siblings, indices.
        assert_eq!(abi.witness.fields.len(), 5);
        assert_eq!(abi.circuit.num_private_witnesses, 4);
        let private: Vec<&str> = abi
            .witness
            .fields
            .iter()
            .filter(|f| f.visibility == FieldVisibility::Private)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(private, vec!["leaf", "leaf_nonce", "siblings", "indices"]);
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
        assert!(json.contains("\"proving_system\": \"halo2_kzg\""));
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
        assert_eq!(abi.proof.proving_system, ProvingSystem::Halo2Kzg);
        assert_eq!(abi.proof.format_version, 1);
        assert!(abi.on_chain.is_none());
    }
}
