//! `CircuitDescriptor` implementation for the `example` demo circuit.
//!
//! Reference template for adding a new circuit to ZeroStyl — see
//! `docs/EXTENDING.md` (J6).

use std::path::Path;
use std::sync::OnceLock;

use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    plonk::{Circuit, ConstraintSystem},
};
use halo2curves::pasta::Fp;
use serde::{Deserialize, Serialize};
use zerostyl_circuits::{
    CircuitDescriptor, CircuitError, CircuitIntrospection, FailureEntry, FailureKind, FieldType,
    FieldVisibility, MockProverReport, ProofArtifact, PublicInputField, PublicInputsSchema, Result,
    WitnessField, WitnessSchema,
};
use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};

use crate::ExampleCircuit;

const NAME: &str = "example";
const VERSION: &str = "1.0.0";
const DESCRIPTION: &str =
    "Minimal circuit proving a + b = sum. Reference template for new circuits.";
const DEFAULT_K: u32 = 4;
const NUM_PUBLIC_INPUTS: usize = 1;
const NUM_PRIVATE_WITNESSES: usize = 2;

#[derive(Debug, Deserialize)]
struct WitnessJson {
    a: String,
    b: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicInputsJson {
    inputs: Vec<Vec<String>>,
}

struct ExampleDescriptor;

pub fn descriptor() -> &'static dyn CircuitDescriptor {
    static D: ExampleDescriptor = ExampleDescriptor;
    &D
}

fn witness_schema_static() -> &'static WitnessSchema {
    static S: OnceLock<WitnessSchema> = OnceLock::new();
    S.get_or_init(|| WitnessSchema {
        fields: vec![
            WitnessField {
                name: "a".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: Some("First addend.".into()),
            },
            WitnessField {
                name: "b".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: Some("Second addend.".into()),
            },
        ],
    })
}

fn public_inputs_schema_static() -> &'static PublicInputsSchema {
    static S: OnceLock<PublicInputsSchema> = OnceLock::new();
    S.get_or_init(|| PublicInputsSchema {
        fields: vec![PublicInputField {
            name: "sum".into(),
            kind: FieldType::Fp,
            description: Some("a + b expressed as a field element.".into()),
        }],
    })
}

fn parse_u64(s: &str, field: &str) -> Result<u64> {
    s.parse::<u64>().map_err(|_| {
        CircuitError::InvalidWitness(format!("field '{field}': expected u64, got '{s}'"))
    })
}

fn parse_field(s: &str) -> Result<Fp> {
    use halo2curves::group::ff::PrimeField;
    if let Some(hex_str) = s.strip_prefix("0x") {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CircuitError::InvalidWitness(format!("invalid hex '{s}': {e}")))?;
        let mut repr = [0u8; 32];
        let len = bytes.len().min(32);
        repr[..len].copy_from_slice(&bytes[..len]);
        Option::from(Fp::from_repr(repr))
            .ok_or_else(|| CircuitError::InvalidWitness(format!("invalid field element '{s}'")))
    } else {
        Ok(Fp::from(parse_u64(s, "field")?))
    }
}

fn parse_witness(json: &str) -> Result<WitnessJson> {
    serde_json::from_str(json)
        .map_err(|e| CircuitError::InvalidWitness(format!("example witness JSON: {e}")))
}

struct ParsedInputs {
    circuit: ExampleCircuit,
    public_inputs: Vec<Vec<Fp>>,
}

fn build_inputs(w: &WitnessJson) -> Result<ParsedInputs> {
    let a = parse_u64(&w.a, "a")?;
    let b = parse_u64(&w.b, "b")?;
    let a_fp = Fp::from(a);
    let b_fp = Fp::from(b);
    let sum = ExampleCircuit::compute_sum(a_fp, b_fp);
    Ok(ParsedInputs { circuit: ExampleCircuit::new(a_fp, b_fp), public_inputs: vec![vec![sum]] })
}

fn encode_public_inputs(inputs: &[Vec<Fp>]) -> String {
    use halo2curves::group::ff::PrimeField;
    let rows: Vec<Vec<String>> = inputs
        .iter()
        .map(|row| row.iter().map(|fp| format!("0x{}", hex::encode(fp.to_repr()))).collect())
        .collect();
    serde_json::to_string_pretty(&PublicInputsJson { inputs: rows })
        .expect("PublicInputsJson serialization is infallible")
}

fn decode_public_inputs(json: &str) -> Result<Vec<Vec<Fp>>> {
    let parsed: PublicInputsJson = serde_json::from_str(json)?;
    parsed.inputs.iter().map(|row| row.iter().map(|s| parse_field(s)).collect()).collect()
}

fn convert_failure(f: &VerifyFailure) -> FailureEntry {
    let details = format!("{f}");
    match f {
        VerifyFailure::ConstraintNotSatisfied { constraint, location, .. } => FailureEntry {
            kind: FailureKind::ConstraintNotSatisfied,
            gate_name: Some(format!("{constraint}")),
            region: Some(format!("{location}")),
            row: None,
            column: None,
            details,
        },
        VerifyFailure::CellNotAssigned { gate, gate_offset, column, .. } => FailureEntry {
            kind: FailureKind::ConstraintNotSatisfied,
            gate_name: Some(format!("{gate}")),
            region: None,
            row: Some(*gate_offset),
            column: Some(format!("{column:?}")),
            details,
        },
        VerifyFailure::InstanceCellNotAssigned { gate, column, row, .. } => FailureEntry {
            kind: FailureKind::InstanceCellMismatch,
            gate_name: Some(format!("{gate}")),
            region: None,
            row: Some(*row),
            column: Some(format!("{column:?}")),
            details,
        },
        VerifyFailure::ConstraintPoisoned { constraint } => FailureEntry {
            kind: FailureKind::ConstraintNotSatisfied,
            gate_name: Some(format!("{constraint}")),
            region: None,
            row: None,
            column: None,
            details,
        },
        VerifyFailure::Lookup { lookup_index, location } => FailureEntry {
            kind: FailureKind::Lookup,
            gate_name: Some(format!("lookup[{lookup_index}]")),
            region: Some(format!("{location}")),
            row: None,
            column: None,
            details,
        },
        VerifyFailure::Permutation { column, location } => FailureEntry {
            kind: FailureKind::Permutation,
            gate_name: None,
            region: Some(format!("{location}")),
            row: None,
            column: Some(format!("{column}")),
            details,
        },
    }
}

fn parse_usize_field(debug_str: &str, name: &str) -> usize {
    let needle = format!("{name}: ");
    if let Some(start) = debug_str.find(&needle) {
        let after = &debug_str[start + needle.len()..];
        let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        after[..end].parse().unwrap_or(0)
    } else {
        0
    }
}

impl CircuitDescriptor for ExampleDescriptor {
    fn name(&self) -> &'static str {
        NAME
    }
    fn version(&self) -> &'static str {
        VERSION
    }
    fn description(&self) -> &'static str {
        DESCRIPTION
    }
    fn default_k(&self) -> u32 {
        DEFAULT_K
    }
    fn num_public_inputs(&self) -> usize {
        NUM_PUBLIC_INPUTS
    }
    fn num_private_witnesses(&self) -> usize {
        NUM_PRIVATE_WITNESSES
    }
    fn witness_schema(&self) -> &'static WitnessSchema {
        witness_schema_static()
    }
    fn public_inputs_schema(&self) -> &'static PublicInputsSchema {
        public_inputs_schema_static()
    }

    fn prove(&self, witness_json: &str, k: u32, cache_dir: &Path) -> Result<ProofArtifact> {
        let w = parse_witness(witness_json)?;
        let ParsedInputs { circuit, public_inputs } = build_inputs(&w)?;

        let mut prover = NativeProver::with_cache_dir(circuit, k, cache_dir)
            .map_err(|e| CircuitError::ProveFailed(e.to_string()))?;
        prover
            .setup(KeyMetadata {
                circuit_name: NAME.to_string(),
                k,
                num_public_inputs: NUM_PUBLIC_INPUTS,
                num_private_witnesses: NUM_PRIVATE_WITNESSES,
            })
            .map_err(|e| CircuitError::ProveFailed(e.to_string()))?;

        let proof_bytes = prover
            .generate_proof(&public_inputs)
            .map_err(|e| CircuitError::ProveFailed(e.to_string()))?;

        Ok(ProofArtifact::new(proof_bytes, encode_public_inputs(&public_inputs)))
    }

    fn verify(
        &self,
        proof: &[u8],
        public_inputs_json: &str,
        k: u32,
        cache_dir: &Path,
    ) -> Result<bool> {
        let public_inputs = decode_public_inputs(public_inputs_json)?;
        let circuit = ExampleCircuit::default();

        let mut prover = NativeProver::with_cache_dir(circuit, k, cache_dir)
            .map_err(|e| CircuitError::VerifyFailed(e.to_string()))?;
        prover
            .setup(KeyMetadata {
                circuit_name: NAME.to_string(),
                k,
                num_public_inputs: NUM_PUBLIC_INPUTS,
                num_private_witnesses: NUM_PRIVATE_WITNESSES,
            })
            .map_err(|e| CircuitError::VerifyFailed(e.to_string()))?;

        prover
            .verify_proof(proof, &public_inputs)
            .map_err(|e| CircuitError::VerifyFailed(e.to_string()))
    }

    fn mock_prove(&self, witness_json: &str, k: u32) -> Result<MockProverReport> {
        let w = parse_witness(witness_json)?;
        let ParsedInputs { circuit, public_inputs } = build_inputs(&w)?;

        let prover = MockProver::run(k, &circuit, public_inputs)
            .map_err(|e| CircuitError::Other(format!("MockProver setup failed: {e:?}")))?;

        let (satisfied, failures) = match prover.verify() {
            Ok(()) => (true, Vec::new()),
            Err(errs) => (false, errs.iter().map(convert_failure).collect()),
        };

        Ok(MockProverReport { circuit_name: NAME.to_string(), k, satisfied, failures })
    }

    fn inspect(&self) -> Result<CircuitIntrospection> {
        let mut cs = ConstraintSystem::<Fp>::default();
        let _ = ExampleCircuit::configure(&mut cs);
        let debug = format!("{:?}", cs.pinned());

        Ok(CircuitIntrospection {
            circuit_name: NAME.to_string(),
            k: DEFAULT_K,
            num_advice_columns: parse_usize_field(&debug, "num_advice_columns"),
            num_fixed_columns: parse_usize_field(&debug, "num_fixed_columns"),
            num_instance_columns: parse_usize_field(&debug, "num_instance_columns"),
            num_selectors: parse_usize_field(&debug, "num_selectors"),
            max_constraint_degree: cs.degree(),
            gates: Vec::new(),
            columns: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const VALID_WITNESS: &str = r#"{"a":"2","b":"3"}"#;

    #[test]
    fn metadata_matches_circuit() {
        let d = descriptor();
        assert_eq!(d.name(), "example");
        assert_eq!(d.default_k(), 4);
        assert_eq!(d.num_public_inputs(), 1);
        assert_eq!(d.num_private_witnesses(), 2);
    }

    #[test]
    fn witness_schema_has_two_fields() {
        let schema = descriptor().witness_schema();
        assert_eq!(schema.fields.len(), 2);
        assert_eq!(schema.fields[0].name, "a");
        assert_eq!(schema.fields[1].name, "b");
    }

    #[test]
    fn mock_prove_valid_witness_is_satisfied() {
        let report = descriptor().mock_prove(VALID_WITNESS, 4).unwrap();
        assert!(report.satisfied, "got failures: {:?}", report.failures);
    }

    #[test]
    fn invalid_witness_returns_typed_error() {
        let err = descriptor().mock_prove("not json", 4).err().unwrap();
        assert!(matches!(err, CircuitError::InvalidWitness(_)));
    }

    #[test]
    fn inspect_returns_non_zero_counts() {
        let intro = descriptor().inspect().unwrap();
        assert_eq!(intro.circuit_name, "example");
        assert!(intro.num_advice_columns > 0);
    }

    #[test]
    fn prove_and_verify_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let artifact = descriptor().prove(VALID_WITNESS, 4, tmp.path()).unwrap();
        assert!(!artifact.bytes.is_empty());

        let ok = descriptor()
            .verify(&artifact.bytes, &artifact.public_inputs_json, 4, tmp.path())
            .unwrap();
        assert!(ok);
    }
}
