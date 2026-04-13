//! ZeroStyl Proof Generation CLI
//!
//! Generate zero-knowledge proofs for halo2 circuits off-chain.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;
use serde::{Deserialize, Serialize};
use state_mask::StateMaskCircuit;
use std::{fs, path::PathBuf};
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_compiler::codegen::{
    keys::KeyMetadata,
    prover::{string_to_field, NativeProver},
};

#[derive(Parser)]
#[command(name = "zerostyl-prove")]
#[command(about = "Generate zero-knowledge proofs for halo2 circuits", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a proof for a circuit
    Generate {
        /// Circuit name (example, tx_privacy, state_mask, private_vote)
        #[arg(short, long)]
        circuit: String,

        /// Path to witnesses JSON file
        #[arg(short, long)]
        witnesses: PathBuf,

        /// Output file for the proof
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,

        /// Circuit parameter k (size = 2^k). Defaults to circuit-specific value.
        #[arg(short, long)]
        k: Option<u32>,

        /// Cache directory for keys
        #[arg(long, default_value = ".zerostyl_cache")]
        cache_dir: PathBuf,
    },

    /// Verify a proof
    Verify {
        /// Circuit name
        #[arg(short, long)]
        circuit: String,

        /// Path to proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Path to public inputs JSON file (generated automatically by `generate`)
        #[arg(short = 'i', long, default_value = "public_inputs.json")]
        inputs: PathBuf,

        /// Circuit parameter k
        #[arg(short, long)]
        k: Option<u32>,

        /// Cache directory for keys
        #[arg(long, default_value = ".zerostyl_cache")]
        cache_dir: PathBuf,
    },

    /// Show information about a circuit
    Info {
        /// Circuit name
        circuit: String,
    },
}

fn default_k(circuit_name: &str) -> u32 {
    match circuit_name {
        "example" => 4,
        "tx_privacy" => 14,
        "state_mask" => 10,
        "private_vote" => 11,
        _ => 10,
    }
}

// ─── Example circuit (a + b = sum) ──────────────────────────────────────────

#[derive(Clone, Debug)]
struct ExampleCircuit {
    a: Value<Fp>,
    b: Value<Fp>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ExampleConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

impl Circuit<Fp> for ExampleCircuit {
    type Config = ExampleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { a: Value::unknown(), b: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(advice);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());
            let sum = meta.query_instance(instance, Rotation::cur());

            vec![s * (a + b - sum)]
        });

        ExampleConfig { advice, instance, selector }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "add",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.advice, 0, || self.a)?;
                region.assign_advice(|| "b", config.advice, 1, || self.b)?;
                Ok(())
            },
        )
    }
}

// ─── Witness JSON types ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct ExampleWitnessData {
    private: Vec<String>,
    public: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct StateMaskWitness {
    state_value: String,
    nonce: String,
    collateral_ratio: String,
    hidden_balance: String,
    threshold: String,
}

#[derive(Debug, Deserialize)]
struct TxPrivacyWitness {
    balance_old: String,
    balance_new: String,
    randomness_old: String,
    randomness_new: String,
    amount: String,
    merkle_siblings: Vec<String>,
    merkle_indices: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PrivateVoteWitness {
    balance: String,
    randomness_balance: String,
    vote: String,
    randomness_vote: String,
    threshold: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicInputsData {
    inputs: Vec<Vec<String>>,
}

// ─── Field parsing helper ────────────────────────────────────────────────────

fn parse_field(s: &str) -> Result<Fp> {
    if let Some(hex_str) = s.strip_prefix("0x") {
        use halo2curves::group::ff::PrimeField;
        let bytes = hex::decode(hex_str).context("Invalid hex string")?;
        let mut repr = [0u8; 32];
        let len = bytes.len().min(32);
        repr[..len].copy_from_slice(&bytes[..len]);
        let opt: Option<Fp> = Fp::from_repr(repr).into();
        opt.ok_or_else(|| anyhow::anyhow!("Invalid field element: {}", s))
    } else {
        let val: u64 = s.parse().context(format!("Expected u64 integer, got '{}'", s))?;
        Ok(Fp::from(val))
    }
}

fn load_public_inputs(path: &PathBuf) -> Result<PublicInputsData> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read public inputs file: {:?}", path))?;
    serde_json::from_str(&content).context("Failed to parse public inputs JSON")
}

/// Serialize public inputs to JSON alongside the proof.
///
/// Each Fp is written as `"0x<little-endian hex>"` via `to_repr()`,
/// which round-trips correctly through `parse_field`'s `from_repr` path.
fn write_public_inputs(proof_output: &std::path::Path, inputs: &[Vec<Fp>]) -> Result<()> {
    use halo2curves::group::ff::PrimeField;
    let rows: Vec<Vec<String>> = inputs
        .iter()
        .map(|row| row.iter().map(|fp| format!("0x{}", hex::encode(fp.to_repr()))).collect())
        .collect();
    let data = PublicInputsData { inputs: rows };
    let json = serde_json::to_string_pretty(&data)?;
    let path = proof_output.with_file_name("public_inputs.json");
    fs::write(&path, json).context(format!("Failed to write public inputs to {:?}", path))?;
    println!("  Public inputs  →  {:?}", path);
    Ok(())
}

// ─── Prove functions ─────────────────────────────────────────────────────────

fn prove_example(
    witnesses_path: &PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    let content = fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;
    let witnesses: ExampleWitnessData =
        serde_json::from_str(&content).context("Failed to parse example witnesses JSON.\n\nExpected format: {\"private\": [\"2\", \"3\"], \"public\": [[\"5\"]]}")?;

    if witnesses.private.len() != 2 {
        anyhow::bail!("Example circuit requires exactly 2 private witnesses (a, b)");
    }

    let a = string_to_field(&witnesses.private[0])?;
    let b = string_to_field(&witnesses.private[1])?;
    let circuit = ExampleCircuit { a: Value::known(a), b: Value::known(b) };

    println!("  Setting up prover (k={})...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;
    prover.setup(KeyMetadata {
        circuit_name: "example".to_string(),
        k,
        num_public_inputs: 1,
        num_private_witnesses: 2,
    })?;

    let public_inputs: Result<Vec<Vec<Fp>>> = witnesses
        .public
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    println!("  Generating proof...");
    let pi = public_inputs?;
    let proof = prover.generate_proof(&pi)?;
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;
    println!("  Proof: {} bytes  →  {:?}", proof.len(), output);
    write_public_inputs(&output, &pi)?;
    Ok(())
}

fn prove_state_mask(
    witnesses_path: &PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    let content = fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;
    let w: StateMaskWitness = serde_json::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Invalid witness JSON for 'state_mask': {}\n\nRun `zerostyl-debug schema --circuit state_mask` to see the expected format.",
            e
        )
    })?;

    let state_value: u64 = w.state_value.parse().context("field 'state_value': expected u64")?;
    let nonce = parse_field(&w.nonce).context("field 'nonce'")?;
    let collateral_ratio: u64 =
        w.collateral_ratio.parse().context("field 'collateral_ratio': expected u64")?;
    let hidden_balance: u64 =
        w.hidden_balance.parse().context("field 'hidden_balance': expected u64")?;
    let threshold: u64 = w.threshold.parse().context("field 'threshold': expected u64")?;

    let circuit =
        StateMaskCircuit::from_raw(state_value, nonce, collateral_ratio, hidden_balance, threshold);
    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);

    println!("  Setting up prover (k={})...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;
    prover.setup(KeyMetadata {
        circuit_name: "state_mask".to_string(),
        k,
        num_public_inputs: 2,
        num_private_witnesses: 5,
    })?;

    println!("  Generating proof...");
    let pi = vec![vec![commitment, Fp::from(threshold)]];
    let proof = prover.generate_proof(&pi)?;
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;
    println!("  Commitment (public input): {:?}", commitment);
    println!("  Proof: {} bytes  →  {:?}", proof.len(), output);
    write_public_inputs(&output, &pi)?;
    Ok(())
}

fn prove_tx_privacy(
    witnesses_path: &PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    let content = fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;
    let w: TxPrivacyWitness = serde_json::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Invalid witness JSON for 'tx_privacy': {}\n\nRun `zerostyl-debug schema --circuit tx_privacy` to see the expected format.",
            e
        )
    })?;

    let balance_old: u64 = w.balance_old.parse().context("field 'balance_old': expected u64")?;
    let balance_new: u64 = w.balance_new.parse().context("field 'balance_new': expected u64")?;
    let randomness_old = parse_field(&w.randomness_old).context("field 'randomness_old'")?;
    let randomness_new = parse_field(&w.randomness_new).context("field 'randomness_new'")?;
    let amount: u64 = w.amount.parse().context("field 'amount': expected u64")?;

    if w.merkle_siblings.len() != MERKLE_DEPTH {
        anyhow::bail!("Expected {} Merkle siblings, got {}", MERKLE_DEPTH, w.merkle_siblings.len());
    }
    if w.merkle_indices.len() != MERKLE_DEPTH {
        anyhow::bail!("Expected {} merkle_indices, got {}", MERKLE_DEPTH, w.merkle_indices.len());
    }
    let merkle_siblings: Result<Vec<Fp>> =
        w.merkle_siblings.iter().map(|s| parse_field(s)).collect();
    let merkle_siblings = merkle_siblings.context("field 'merkle_siblings'")?;
    let merkle_indices: Result<Vec<bool>> = w
        .merkle_indices
        .iter()
        .map(|s| {
            let v: u64 = s.parse().context("field 'merkle_indices': expected 0 or 1")?;
            Ok(v != 0)
        })
        .collect();
    let merkle_indices = merkle_indices?;

    let circuit = TxPrivacyCircuit::from_raw(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        merkle_siblings.clone(),
        merkle_indices.clone(),
    );
    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root =
        TxPrivacyCircuit::compute_merkle_root(commitment_old, &merkle_siblings, &merkle_indices);

    println!("  Setting up prover (k={})...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;
    prover.setup(KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 6,
    })?;

    println!("  Generating proof...");
    let pi = vec![vec![commitment_old, commitment_new, merkle_root]];
    let proof = prover.generate_proof(&pi)?;
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;
    println!(
        "  Public inputs: commitment_old={:?}  commitment_new={:?}  merkle_root={:?}",
        commitment_old, commitment_new, merkle_root
    );
    println!("  Proof: {} bytes  →  {:?}", proof.len(), output);
    write_public_inputs(&output, &pi)?;
    Ok(())
}

fn prove_private_vote(
    witnesses_path: &PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    let content = fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;
    let w: PrivateVoteWitness = serde_json::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Invalid witness JSON for 'private_vote': {}\n\nRun `zerostyl-debug schema --circuit private_vote` to see the expected format.",
            e
        )
    })?;

    let balance: u64 = w.balance.parse().context("field 'balance': expected u64")?;
    let randomness_balance =
        parse_field(&w.randomness_balance).context("field 'randomness_balance'")?;
    let vote: u64 = w.vote.parse().context("field 'vote': expected u64")?;
    let randomness_vote = parse_field(&w.randomness_vote).context("field 'randomness_vote'")?;
    let threshold: u64 = w.threshold.parse().context("field 'threshold': expected u64")?;

    let circuit =
        PrivateVoteCircuit::from_raw(balance, randomness_balance, vote, randomness_vote, threshold);
    let balance_commitment =
        PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
    let vote_commitment = PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

    println!("  Setting up prover (k={})...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;
    prover.setup(KeyMetadata {
        circuit_name: "private_vote".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 5,
    })?;

    println!("  Generating proof...");
    let pi = vec![vec![balance_commitment, Fp::from(threshold), vote_commitment]];
    let proof = prover.generate_proof(&pi)?;
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;
    println!(
        "  Public inputs: balance_commitment={:?}  threshold={}  vote_commitment={:?}",
        balance_commitment, threshold, vote_commitment
    );
    println!("  Proof: {} bytes  →  {:?}", proof.len(), output);
    write_public_inputs(&output, &pi)?;
    Ok(())
}

// ─── Verify functions ─────────────────────────────────────────────────────────

fn verify_with_circuit<C: Circuit<Fp> + Clone>(
    circuit: C,
    circuit_name: &str,
    proof_path: &PathBuf,
    inputs_path: &PathBuf,
    k: u32,
    cache_dir: PathBuf,
) -> Result<()> {
    let proof =
        fs::read(proof_path).context(format!("Failed to read proof file: {:?}", proof_path))?;
    let inputs_data = load_public_inputs(inputs_path)?;

    println!("  Setting up verifier (k={})...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;
    prover.setup(KeyMetadata {
        circuit_name: circuit_name.to_string(),
        k,
        num_public_inputs: 0,
        num_private_witnesses: 0,
    })?;

    let public_inputs: Result<Vec<Vec<Fp>>> =
        inputs_data.inputs.iter().map(|row| row.iter().map(|s| parse_field(s)).collect()).collect();

    println!("  Verifying...");
    let is_valid = prover.verify_proof(&proof, &public_inputs?)?;

    if is_valid {
        println!("  Proof is VALID");
    } else {
        anyhow::bail!("Proof is INVALID");
    }
    Ok(())
}

fn show_circuit_info(circuit_name: &str) {
    match circuit_name {
        "example" => {
            println!("Circuit: example (a + b = sum)");
            println!("  Private witnesses: a, b");
            println!("  Public inputs:     sum");
            println!("  Default k:         4");
            println!();
            println!("  Witness file format:");
            println!(r#"  {{"private": ["2", "3"], "public": [["5"]]}}"#);
        }
        "state_mask" => {
            println!("Circuit: state_mask (Privacy-preserving state proof)");
            println!("  Proves collateral_ratio in [150, 300] and hidden_balance > threshold");
            println!("  Private witnesses: state_value, nonce, collateral_ratio, hidden_balance, threshold");
            println!("  Public inputs:     commitment = Poseidon(state_value, nonce), threshold");
            println!("  Default k:         10");
            println!();
            println!("  Witness file format:");
            println!(
                r#"  {{"state_value": "42", "nonce": "123", "collateral_ratio": "200", "hidden_balance": "500", "threshold": "100"}}"#
            );
            println!();
            println!("  Example: witnesses/state_mask_valid.json");
        }
        "tx_privacy" => {
            println!("Circuit: tx_privacy (Private Transfer)");
            println!(
                "  Proves a token transfer is valid with balance conservation + Merkle membership"
            );
            println!(
                "  Private witnesses: balance_old, balance_new, randomness_old, randomness_new,"
            );
            println!(
                "                     amount, merkle_siblings[{d}], merkle_indices[{d}]",
                d = MERKLE_DEPTH
            );
            println!("  Public inputs:     commitment_old, commitment_new, merkle_root");
            println!("  Default k:         14");
            println!();
            println!("  Example: witnesses/tx_privacy_valid.json");
        }
        "private_vote" => {
            println!("Circuit: private_vote (Anonymous Voting)");
            println!("  Proves a voter holds sufficient balance and cast a valid boolean vote");
            println!("  Private witnesses: balance, randomness_balance, vote, randomness_vote, threshold");
            println!("  Public inputs:     balance_commitment, threshold, vote_commitment");
            println!("  Default k:         11");
            println!();
            println!("  Example: witnesses/private_vote_valid.json");
        }
        _ => {
            eprintln!("Unknown circuit: {}", circuit_name);
            eprintln!("Available: example, state_mask, tx_privacy, private_vote");
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { circuit, witnesses, output, k, cache_dir } => {
            let k = k.unwrap_or_else(|| default_k(&circuit));
            println!("ZeroStyl Prover — circuit: {}  k: {}", circuit, k);
            match circuit.as_str() {
                "example" => prove_example(&witnesses, k, cache_dir, output)?,
                "state_mask" => prove_state_mask(&witnesses, k, cache_dir, output)?,
                "tx_privacy" => prove_tx_privacy(&witnesses, k, cache_dir, output)?,
                "private_vote" => prove_private_vote(&witnesses, k, cache_dir, output)?,
                _ => anyhow::bail!(
                    "Unknown circuit: '{}'. Available: example, state_mask, tx_privacy, private_vote",
                    circuit
                ),
            }
            println!("Done.");
        }
        Commands::Verify { circuit, proof, inputs, k, cache_dir } => {
            let k = k.unwrap_or_else(|| default_k(&circuit));
            println!("ZeroStyl Verifier — circuit: {}  k: {}", circuit, k);
            match circuit.as_str() {
                "example" => {
                    let c = ExampleCircuit { a: Value::unknown(), b: Value::unknown() };
                    verify_with_circuit(c, "example", &proof, &inputs, k, cache_dir)?;
                }
                "state_mask" => {
                    let c = StateMaskCircuit::default();
                    verify_with_circuit(c, "state_mask", &proof, &inputs, k, cache_dir)?;
                }
                "tx_privacy" => {
                    let c = TxPrivacyCircuit::default();
                    verify_with_circuit(c, "tx_privacy", &proof, &inputs, k, cache_dir)?;
                }
                "private_vote" => {
                    let c = PrivateVoteCircuit::default();
                    verify_with_circuit(c, "private_vote", &proof, &inputs, k, cache_dir)?;
                }
                _ => anyhow::bail!(
                    "Unknown circuit: '{}'. Available: example, state_mask, tx_privacy, private_vote",
                    circuit
                ),
            }
            println!("Done.");
        }
        Commands::Info { circuit } => {
            show_circuit_info(&circuit);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_public_inputs_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"inputs": [["5"], ["10"]]}}"#).unwrap();

        let result = load_public_inputs(&file.path().to_path_buf());
        assert!(result.is_ok());
        let inputs = result.unwrap();
        assert_eq!(inputs.inputs.len(), 2);
        assert_eq!(inputs.inputs[0][0], "5");
        assert_eq!(inputs.inputs[1][0], "10");
    }

    #[test]
    fn test_load_public_inputs_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not valid json").unwrap();

        let result = load_public_inputs(&file.path().to_path_buf());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_field_decimal() {
        let f = parse_field("42").unwrap();
        assert_eq!(f, Fp::from(42));
    }

    #[test]
    fn test_parse_field_zero() {
        let f = parse_field("0").unwrap();
        assert_eq!(f, Fp::from(0));
    }

    #[test]
    fn test_parse_field_invalid() {
        assert!(parse_field("not_a_number").is_err());
    }

    #[test]
    fn test_default_k() {
        assert_eq!(default_k("example"), 4);
        assert_eq!(default_k("state_mask"), 10);
        assert_eq!(default_k("tx_privacy"), 14);
        assert_eq!(default_k("private_vote"), 11);
        assert_eq!(default_k("unknown"), 10);
    }

    #[test]
    fn test_show_circuit_info_all() {
        show_circuit_info("example");
        show_circuit_info("state_mask");
        show_circuit_info("tx_privacy");
        show_circuit_info("private_vote");
        show_circuit_info("unknown");
    }

    #[test]
    fn test_example_circuit_without_witnesses() {
        let circuit = ExampleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let _ = circuit.without_witnesses();
    }

    #[test]
    fn test_public_inputs_data_serialization() {
        let data = PublicInputsData { inputs: vec![vec!["1".to_string(), "2".to_string()]] };
        let json = serde_json::to_string(&data).unwrap();
        let deserialized: PublicInputsData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.inputs, data.inputs);
    }
}
