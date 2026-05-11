//! `CircuitDescriptor` implementation for the tx-privacy circuit.

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

use crate::{TxPrivacyCircuit, MERKLE_DEPTH};

const NAME: &str = "tx_privacy";
const VERSION: &str = "1.0.0";
const DESCRIPTION: &str =
    "Private token transfer: balance conservation + Poseidon commitments + Merkle membership.";
const DEFAULT_K: u32 = 14;
const NUM_PUBLIC_INPUTS: usize = 3;
const NUM_PRIVATE_WITNESSES: usize = 6;

#[derive(Debug, Deserialize)]
struct WitnessJson {
    balance_old: String,
    balance_new: String,
    randomness_old: String,
    randomness_new: String,
    amount: String,
    merkle_siblings: Vec<String>,
    merkle_indices: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicInputsJson {
    inputs: Vec<Vec<String>>,
}

struct TxPrivacyDescriptor;

pub fn descriptor() -> &'static dyn CircuitDescriptor {
    static D: TxPrivacyDescriptor = TxPrivacyDescriptor;
    &D
}

fn witness_schema_static() -> &'static WitnessSchema {
    static S: OnceLock<WitnessSchema> = OnceLock::new();
    S.get_or_init(|| WitnessSchema {
        fields: vec![
            WitnessField {
                name: "balance_old".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: Some("Sender balance before the transfer.".into()),
            },
            WitnessField {
                name: "balance_new".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: Some("Sender balance after the transfer.".into()),
            },
            WitnessField {
                name: "randomness_old".into(),
                kind: FieldType::Fp,
                visibility: FieldVisibility::Private,
                description: Some("Commitment randomness for balance_old.".into()),
            },
            WitnessField {
                name: "randomness_new".into(),
                kind: FieldType::Fp,
                visibility: FieldVisibility::Private,
                description: Some("Commitment randomness for balance_new.".into()),
            },
            WitnessField {
                name: "amount".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: Some("Transfer amount; must equal balance_old - balance_new.".into()),
            },
            WitnessField {
                name: "merkle_siblings".into(),
                kind: FieldType::Array { kind: Box::new(FieldType::Fp), len: MERKLE_DEPTH },
                visibility: FieldVisibility::Private,
                description: Some("Merkle authentication path siblings.".into()),
            },
            WitnessField {
                name: "merkle_indices".into(),
                kind: FieldType::Array { kind: Box::new(FieldType::Bool), len: MERKLE_DEPTH },
                visibility: FieldVisibility::Private,
                description: Some("Merkle path direction bits (false=left, true=right).".into()),
            },
        ],
    })
}

fn public_inputs_schema_static() -> &'static PublicInputsSchema {
    static S: OnceLock<PublicInputsSchema> = OnceLock::new();
    S.get_or_init(|| PublicInputsSchema {
        fields: vec![
            PublicInputField {
                name: "commitment_old".into(),
                kind: FieldType::Fp,
                description: Some("Poseidon(balance_old, randomness_old).".into()),
            },
            PublicInputField {
                name: "commitment_new".into(),
                kind: FieldType::Fp,
                description: Some("Poseidon(balance_new, randomness_new).".into()),
            },
            PublicInputField {
                name: "merkle_root".into(),
                kind: FieldType::Fp,
                description: Some("Account-set Merkle root containing commitment_old.".into()),
            },
        ],
    })
}

fn parse_u64(s: &str, field: &str) -> Result<u64> {
    s.parse::<u64>().map_err(|_| {
        CircuitError::InvalidWitness(format!("field '{field}': expected u64, got '{s}'"))
    })
}

fn parse_bool_str(s: &str, field: &str) -> Result<bool> {
    let v: u64 = s.parse().map_err(|_| {
        CircuitError::InvalidWitness(format!("field '{field}': expected 0 or 1, got '{s}'"))
    })?;
    if v > 1 {
        return Err(CircuitError::InvalidWitness(format!(
            "field '{field}': expected 0 or 1, got '{s}'"
        )));
    }
    Ok(v != 0)
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
        .map_err(|e| CircuitError::InvalidWitness(format!("tx_privacy witness JSON: {e}")))
}

struct ParsedInputs {
    circuit: TxPrivacyCircuit,
    public_inputs: Vec<Vec<Fp>>,
}

fn build_inputs(w: &WitnessJson) -> Result<ParsedInputs> {
    if w.merkle_siblings.len() != MERKLE_DEPTH {
        return Err(CircuitError::InvalidWitness(format!(
            "expected {MERKLE_DEPTH} merkle_siblings, got {}",
            w.merkle_siblings.len()
        )));
    }
    if w.merkle_indices.len() != MERKLE_DEPTH {
        return Err(CircuitError::InvalidWitness(format!(
            "expected {MERKLE_DEPTH} merkle_indices, got {}",
            w.merkle_indices.len()
        )));
    }

    let balance_old = parse_u64(&w.balance_old, "balance_old")?;
    let balance_new = parse_u64(&w.balance_new, "balance_new")?;
    let randomness_old = parse_field(&w.randomness_old)?;
    let randomness_new = parse_field(&w.randomness_new)?;
    let amount = parse_u64(&w.amount, "amount")?;
    let siblings: Vec<Fp> =
        w.merkle_siblings.iter().map(|s| parse_field(s)).collect::<Result<_>>()?;
    let indices: Vec<bool> = w
        .merkle_indices
        .iter()
        .map(|s| parse_bool_str(s, "merkle_indices"))
        .collect::<Result<_>>()?;

    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

    let circuit = TxPrivacyCircuit::from_raw(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        siblings,
        indices,
    );

    Ok(ParsedInputs {
        circuit,
        public_inputs: vec![vec![commitment_old, commitment_new, merkle_root]],
    })
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

// See state_mask::descriptor for rationale — halo2 0.3 keeps column counts
// behind pub(crate) fields, so Debug parsing is the only external access.
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

impl CircuitDescriptor for TxPrivacyDescriptor {
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
        let circuit = TxPrivacyCircuit::default();

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
        let _ = TxPrivacyCircuit::configure(&mut cs);
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

    fn zero_array() -> String {
        let zeros: Vec<&str> = (0..MERKLE_DEPTH).map(|_| "0").collect();
        format!("[\"{}\"]", zeros.join("\",\""))
    }

    fn valid_witness() -> String {
        format!(
            r#"{{"balance_old":"1000","balance_new":"700","randomness_old":"7","randomness_new":"13","amount":"300","merkle_siblings":{0},"merkle_indices":{0}}}"#,
            zero_array()
        )
    }

    fn wrong_balance_witness() -> String {
        format!(
            r#"{{"balance_old":"1000","balance_new":"800","randomness_old":"7","randomness_new":"13","amount":"300","merkle_siblings":{0},"merkle_indices":{0}}}"#,
            zero_array()
        )
    }

    #[test]
    fn metadata_matches_circuit() {
        let d = descriptor();
        assert_eq!(d.name(), "tx_privacy");
        assert_eq!(d.default_k(), 14);
        assert_eq!(d.num_public_inputs(), 3);
        assert_eq!(d.num_private_witnesses(), 6);
    }

    #[test]
    fn witness_schema_has_seven_fields() {
        let schema = descriptor().witness_schema();
        assert_eq!(schema.fields.len(), 7);
        let merkle_field = schema.fields.iter().find(|f| f.name == "merkle_siblings").unwrap();
        assert!(matches!(
            &merkle_field.kind,
            FieldType::Array { kind, len } if **kind == FieldType::Fp && *len == MERKLE_DEPTH
        ));
        let idx_field = schema.fields.iter().find(|f| f.name == "merkle_indices").unwrap();
        assert!(matches!(
            &idx_field.kind,
            FieldType::Array { kind, len } if **kind == FieldType::Bool && *len == MERKLE_DEPTH
        ));
    }

    #[test]
    fn public_inputs_schema_has_three_fields() {
        let schema = descriptor().public_inputs_schema();
        assert_eq!(schema.fields.len(), 3);
        let names: Vec<&str> = schema.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["commitment_old", "commitment_new", "merkle_root"]);
    }

    #[test]
    fn mock_prove_valid_witness_is_satisfied() {
        let report = descriptor().mock_prove(&valid_witness(), 14).unwrap();
        assert!(report.satisfied, "got failures: {:?}", report.failures);
        assert!(report.failures.is_empty());
        assert_eq!(report.k, 14);
    }

    #[test]
    fn mock_prove_wrong_balance_fails() {
        let report = descriptor().mock_prove(&wrong_balance_witness(), 14).unwrap();
        assert!(!report.satisfied);
        assert!(!report.failures.is_empty());
    }

    #[test]
    fn invalid_witness_json_returns_typed_error() {
        let err = descriptor().mock_prove("nope", 14).err().unwrap();
        assert!(matches!(err, CircuitError::InvalidWitness(_)));
    }

    #[test]
    fn wrong_merkle_depth_returns_invalid_witness() {
        let bad = r#"{"balance_old":"1000","balance_new":"700","randomness_old":"7","randomness_new":"13","amount":"300","merkle_siblings":["0"],"merkle_indices":["0"]}"#;
        let err = descriptor().mock_prove(bad, 14).err().unwrap();
        assert!(matches!(err, CircuitError::InvalidWitness(_)));
    }

    #[test]
    fn inspect_returns_non_zero_counts() {
        let intro = descriptor().inspect().unwrap();
        assert_eq!(intro.circuit_name, "tx_privacy");
        assert!(intro.num_advice_columns > 0);
        assert!(intro.num_instance_columns > 0);
        assert!(intro.max_constraint_degree > 0);
    }

    // k=14 → ~30s for params + key generation. Run with `--include-ignored`.
    #[test]
    #[ignore]
    fn prove_and_verify_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let artifact = descriptor().prove(&valid_witness(), 14, tmp.path()).unwrap();
        assert!(!artifact.bytes.is_empty());

        let ok = descriptor()
            .verify(&artifact.bytes, &artifact.public_inputs_json, 14, tmp.path())
            .unwrap();
        assert!(ok);
    }
}
