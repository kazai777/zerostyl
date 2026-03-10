//! ZeroStyl Proof Generation CLI
//!
//! Generate zero-knowledge proofs for halo2 circuits off-chain.
//! Supports: example, tx_privacy, state_mask circuits.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;
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
    Prove {
        /// Circuit name (example, tx_privacy, state_mask)
        #[arg(short, long)]
        circuit: String,

        /// Path to witnesses JSON file
        #[arg(short, long)]
        witnesses: PathBuf,

        /// Output file for the proof
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,

        /// Circuit parameter k (size = 2^k)
        #[arg(short, long, default_value = "10")]
        k: u32,

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

        /// Path to public inputs JSON file
        #[arg(short = 'i', long)]
        inputs: PathBuf,

        /// Circuit parameter k
        #[arg(short, long, default_value = "10")]
        k: u32,

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

// ─── Example circuit (simple addition: a + b = sum) ─────────────────────────

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

// ─── Witness types ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct WitnessData {
    private: Vec<String>,
    public: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicInputsData {
    inputs: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TxPrivacyWitness {
    balance_old: String,
    balance_new: String,
    randomness_old: String,
    randomness_new: String,
    amount: String,
    merkle_siblings: Vec<String>,
    merkle_indices: Vec<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StateMaskWitness {
    state_value: String,
    nonce: String,
    collateral_ratio: String,
    hidden_balance: String,
    threshold: String,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn fp_to_string(f: &Fp) -> String {
    use halo2curves::group::ff::PrimeField;
    let repr = f.to_repr();
    format!("0x{}", hex::encode(repr.as_ref()))
}

fn save_public_inputs(path: &PathBuf, public_inputs: &[Vec<Fp>]) -> Result<()> {
    let data = PublicInputsData {
        inputs: public_inputs.iter().map(|row| row.iter().map(fp_to_string).collect()).collect(),
    };
    let json = serde_json::to_string_pretty(&data)?;
    fs::write(path, json).context(format!("Failed to write public inputs to {:?}", path))
}

// ─── Loaders ────────────────────────────────────────────────────────────────

fn load_witnesses(path: &PathBuf) -> Result<WitnessData> {
    let content =
        fs::read_to_string(path).context(format!("Failed to read witnesses file: {:?}", path))?;
    serde_json::from_str(&content).context("Failed to parse witnesses JSON")
}

fn load_public_inputs(path: &PathBuf) -> Result<PublicInputsData> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read public inputs file: {:?}", path))?;
    serde_json::from_str(&content).context("Failed to parse public inputs JSON")
}

fn load_tx_privacy_witness(path: &PathBuf) -> Result<TxPrivacyWitness> {
    let content =
        fs::read_to_string(path).context(format!("Failed to read witnesses file: {:?}", path))?;
    serde_json::from_str(&content).context("Failed to parse tx_privacy witnesses JSON")
}

fn load_state_mask_witness(path: &PathBuf) -> Result<StateMaskWitness> {
    let content =
        fs::read_to_string(path).context(format!("Failed to read witnesses file: {:?}", path))?;
    serde_json::from_str(&content).context("Failed to parse state_mask witnesses JSON")
}

// ─── Prove / Verify: example ────────────────────────────────────────────────

fn prove_example(
    witnesses: WitnessData,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("Loading witnesses...");

    if witnesses.private.len() != 2 {
        anyhow::bail!("Example circuit requires exactly 2 private witnesses (a, b)");
    }

    let a = string_to_field(&witnesses.private[0])?;
    let b = string_to_field(&witnesses.private[1])?;

    let circuit = ExampleCircuit { a: Value::known(a), b: Value::known(b) };

    println!("Setting up prover with k={}...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "example".to_string(),
        k,
        num_public_inputs: 1,
        num_private_witnesses: 2,
    };

    prover.setup(metadata)?;

    println!("Generating proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = witnesses
        .public
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let proof = prover.generate_proof(&public_inputs)?;

    println!("Saving proof to {:?}...", output);
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;

    let inputs_path = output.with_extension("inputs.json");
    save_public_inputs(&inputs_path, &public_inputs)?;

    println!("Proof generated successfully!");
    println!("   Size: {} bytes", proof.len());
    println!("   Proof: {:?}", output);
    println!("   Public inputs: {:?}", inputs_path);

    Ok(())
}

fn verify_example(
    proof_path: PathBuf,
    inputs_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
) -> Result<()> {
    println!("Loading proof and public inputs...");

    let proof =
        fs::read(&proof_path).context(format!("Failed to read proof file: {:?}", proof_path))?;

    let inputs_data = load_public_inputs(&inputs_path)?;

    println!("Setting up verifier with k={}...", k);

    let circuit = ExampleCircuit { a: Value::unknown(), b: Value::unknown() };

    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "example".to_string(),
        k,
        num_public_inputs: 1,
        num_private_witnesses: 2,
    };

    prover.setup(metadata)?;

    println!("Verifying proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = inputs_data
        .inputs
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let is_valid = prover.verify_proof(&proof, &public_inputs)?;

    if is_valid {
        println!("Proof is VALID!");
    } else {
        println!("Proof is INVALID!");
        anyhow::bail!("Proof verification failed");
    }

    Ok(())
}

// ─── Prove / Verify: tx_privacy ─────────────────────────────────────────────

fn prove_tx_privacy(
    witness_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("Loading tx_privacy witnesses...");
    let witness = load_tx_privacy_witness(&witness_path)?;

    let balance_old: u64 = witness.balance_old.parse().context("Invalid balance_old")?;
    let balance_new: u64 = witness.balance_new.parse().context("Invalid balance_new")?;
    let randomness_old = string_to_field(&witness.randomness_old)?;
    let randomness_new = string_to_field(&witness.randomness_new)?;
    let amount: u64 = witness.amount.parse().context("Invalid amount")?;

    if witness.merkle_siblings.len() != MERKLE_DEPTH {
        anyhow::bail!(
            "Expected {} Merkle siblings, got {}",
            MERKLE_DEPTH,
            witness.merkle_siblings.len()
        );
    }
    if witness.merkle_indices.len() != MERKLE_DEPTH {
        anyhow::bail!(
            "Expected {} Merkle indices, got {}",
            MERKLE_DEPTH,
            witness.merkle_indices.len()
        );
    }

    let merkle_siblings: Result<Vec<Fp>> =
        witness.merkle_siblings.iter().map(|s| string_to_field(s)).collect();
    let merkle_siblings = merkle_siblings?;

    // Auto-compute public inputs from private witnesses
    let commitment_old =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
    let commitment_new =
        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
    let merkle_root = TxPrivacyCircuit::compute_merkle_root(
        commitment_old,
        &merkle_siblings,
        &witness.merkle_indices,
    );

    let circuit = TxPrivacyCircuit::new(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        merkle_siblings,
        witness.merkle_indices,
    );

    println!("Setting up prover with k={}...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 69,
    };

    prover.setup(metadata)?;

    println!("Generating proof...");
    let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];
    let proof = prover.generate_proof(&public_inputs)?;

    println!("Saving proof to {:?}...", output);
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;

    let inputs_path = output.with_extension("inputs.json");
    save_public_inputs(&inputs_path, &public_inputs)?;

    println!("Proof generated successfully!");
    println!("   Size: {} bytes", proof.len());
    println!("   Proof: {:?}", output);
    println!("   Public inputs: {:?}", inputs_path);

    Ok(())
}

fn verify_tx_privacy(
    proof_path: PathBuf,
    inputs_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
) -> Result<()> {
    println!("Loading proof and public inputs...");

    let proof =
        fs::read(&proof_path).context(format!("Failed to read proof file: {:?}", proof_path))?;
    let inputs_data = load_public_inputs(&inputs_path)?;

    println!("Setting up verifier with k={}...", k);
    let circuit = TxPrivacyCircuit::default();

    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 69,
    };

    prover.setup(metadata)?;

    println!("Verifying proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = inputs_data
        .inputs
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let is_valid = prover.verify_proof(&proof, &public_inputs)?;

    if is_valid {
        println!("Proof is VALID!");
    } else {
        println!("Proof is INVALID!");
        anyhow::bail!("Proof verification failed");
    }

    Ok(())
}

// ─── Prove / Verify: state_mask ─────────────────────────────────────────────

fn prove_state_mask(
    witness_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("Loading state_mask witnesses...");
    let witness = load_state_mask_witness(&witness_path)?;

    let state_value: u64 = witness.state_value.parse().context("Invalid state_value")?;
    let nonce = string_to_field(&witness.nonce)?;
    let collateral_ratio: u64 =
        witness.collateral_ratio.parse().context("Invalid collateral_ratio")?;
    let hidden_balance: u64 = witness.hidden_balance.parse().context("Invalid hidden_balance")?;
    let threshold: u64 = witness.threshold.parse().context("Invalid threshold")?;

    // Auto-compute public inputs
    let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);

    let circuit =
        StateMaskCircuit::new(state_value, nonce, collateral_ratio, hidden_balance, threshold);

    println!("Setting up prover with k={}...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "state_mask".to_string(),
        k,
        num_public_inputs: 2,
        num_private_witnesses: 5,
    };

    prover.setup(metadata)?;

    println!("Generating proof...");
    let public_inputs = vec![vec![commitment, Fp::from(threshold)]];
    let proof = prover.generate_proof(&public_inputs)?;

    println!("Saving proof to {:?}...", output);
    fs::write(&output, &proof).context(format!("Failed to write proof to {:?}", output))?;

    let inputs_path = output.with_extension("inputs.json");
    save_public_inputs(&inputs_path, &public_inputs)?;

    println!("Proof generated successfully!");
    println!("   Size: {} bytes", proof.len());
    println!("   Proof: {:?}", output);
    println!("   Public inputs: {:?}", inputs_path);

    Ok(())
}

fn verify_state_mask(
    proof_path: PathBuf,
    inputs_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
) -> Result<()> {
    println!("Loading proof and public inputs...");

    let proof =
        fs::read(&proof_path).context(format!("Failed to read proof file: {:?}", proof_path))?;
    let inputs_data = load_public_inputs(&inputs_path)?;

    println!("Setting up verifier with k={}...", k);
    let circuit = StateMaskCircuit::default();

    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "state_mask".to_string(),
        k,
        num_public_inputs: 2,
        num_private_witnesses: 5,
    };

    prover.setup(metadata)?;

    println!("Verifying proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = inputs_data
        .inputs
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let is_valid = prover.verify_proof(&proof, &public_inputs)?;

    if is_valid {
        println!("Proof is VALID!");
    } else {
        println!("Proof is INVALID!");
        anyhow::bail!("Proof verification failed");
    }

    Ok(())
}

// ─── Circuit info ───────────────────────────────────────────────────────────

fn show_circuit_info(circuit_name: &str) {
    match circuit_name {
        "example" => {
            println!("Circuit: example");
            println!("   Description: Simple addition circuit (a + b = sum)");
            println!("   Recommended k: 4");
            println!("   Private witnesses: 2 (a, b)");
            println!("   Public inputs: 1 (sum)");
            println!();
            println!("   Witness format (witnesses.json):");
            println!(
                r#"   {{
     "private": ["2", "3"],
     "public": [["5"]]
   }}"#
            );
        }
        "tx_privacy" => {
            println!("Circuit: tx_privacy");
            println!(
                "   Description: Private token transfer with Poseidon commitments and Merkle tree"
            );
            println!("   Recommended k: 14 (for MERKLE_DEPTH=32)");
            println!("   Private witnesses: 69 (5 scalars + 32 siblings + 32 indices)");
            println!("   Public inputs: 3 (commitment_old, commitment_new, merkle_root)");
            println!();
            println!("   Public inputs are auto-computed from private witnesses:");
            println!("   - commitment_old = Poseidon(balance_old, randomness_old)");
            println!("   - commitment_new = Poseidon(balance_new, randomness_new)");
            println!("   - merkle_root = MerkleRoot(commitment_old, siblings, indices)");
            println!();
            println!("   Witness format (witnesses.json):");
            println!(
                r#"   {{
     "balance_old": "1000",
     "balance_new": "700",
     "randomness_old": "42",
     "randomness_new": "84",
     "amount": "300",
     "merkle_siblings": ["100", "101", ...32 entries],
     "merkle_indices": [true, false, ...32 entries]
   }}"#
            );
        }
        "state_mask" => {
            println!("Circuit: state_mask");
            println!(
                "   Description: Privacy-preserving state proof (commitment + range + comparison)"
            );
            println!("   Recommended k: 10");
            println!("   Private witnesses: 5");
            println!("   Public inputs: 2 (commitment, threshold)");
            println!();
            println!("   Public inputs are auto-computed from private witnesses:");
            println!("   - commitment = Poseidon(state_value, nonce)");
            println!("   - threshold (passed through from witness)");
            println!();
            println!("   Constraints enforced:");
            println!("   - Poseidon(state_value, nonce) == commitment");
            println!("   - collateral_ratio in [150, 300]");
            println!("   - hidden_balance > threshold");
            println!();
            println!("   Witness format (witnesses.json):");
            println!(
                r#"   {{
     "state_value": "1000",
     "nonce": "42",
     "collateral_ratio": "200",
     "hidden_balance": "500",
     "threshold": "100"
   }}"#
            );
        }
        _ => {
            eprintln!("Unknown circuit: {}", circuit_name);
            eprintln!("   Available circuits: example, tx_privacy, state_mask");
        }
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove { circuit, witnesses, output, k, cache_dir } => {
            println!("ZeroStyl Prover");
            println!("   Circuit: {}", circuit);
            println!();

            match circuit.as_str() {
                "example" => {
                    let witnesses = load_witnesses(&witnesses)?;
                    prove_example(witnesses, k, cache_dir, output)?
                }
                "tx_privacy" => prove_tx_privacy(witnesses, k, cache_dir, output)?,
                "state_mask" => prove_state_mask(witnesses, k, cache_dir, output)?,
                _ => {
                    anyhow::bail!(
                        "Unknown circuit: {}. Available: example, tx_privacy, state_mask",
                        circuit
                    );
                }
            }
        }
        Commands::Verify { circuit, proof, inputs, k, cache_dir } => {
            println!("ZeroStyl Verifier");
            println!("   Circuit: {}", circuit);
            println!();

            match circuit.as_str() {
                "example" => verify_example(proof, inputs, k, cache_dir)?,
                "tx_privacy" => verify_tx_privacy(proof, inputs, k, cache_dir)?,
                "state_mask" => verify_state_mask(proof, inputs, k, cache_dir)?,
                _ => {
                    anyhow::bail!(
                        "Unknown circuit: {}. Available: example, tx_privacy, state_mask",
                        circuit
                    );
                }
            }
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

    // ─── Loader tests ───────────────────────────────────────────────────

    #[test]
    fn test_load_witnesses_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"private": ["2", "3"], "public": [["5"]]}}"#).unwrap();

        let witnesses = load_witnesses(&file.path().to_path_buf()).unwrap();
        assert_eq!(witnesses.private, vec!["2", "3"]);
        assert_eq!(witnesses.public, vec![vec!["5"]]);
    }

    #[test]
    fn test_load_witnesses_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"invalid": json}}"#).unwrap();
        assert!(load_witnesses(&file.path().to_path_buf()).is_err());
    }

    #[test]
    fn test_load_witnesses_missing_file() {
        assert!(load_witnesses(&PathBuf::from("/nonexistent/file.json")).is_err());
    }

    #[test]
    fn test_load_public_inputs_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"inputs": [["5"], ["10"]]}}"#).unwrap();

        let inputs = load_public_inputs(&file.path().to_path_buf()).unwrap();
        assert_eq!(inputs.inputs.len(), 2);
        assert_eq!(inputs.inputs[0][0], "5");
        assert_eq!(inputs.inputs[1][0], "10");
    }

    #[test]
    fn test_load_public_inputs_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not valid json").unwrap();
        assert!(load_public_inputs(&file.path().to_path_buf()).is_err());
    }

    #[test]
    fn test_load_tx_privacy_witness_valid() {
        let mut file = NamedTempFile::new().unwrap();
        let siblings: Vec<String> = (0..32).map(|i| format!("{}", i + 100)).collect();
        let indices: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
        let witness = TxPrivacyWitness {
            balance_old: "1000".to_string(),
            balance_new: "700".to_string(),
            randomness_old: "42".to_string(),
            randomness_new: "84".to_string(),
            amount: "300".to_string(),
            merkle_siblings: siblings,
            merkle_indices: indices,
        };
        let json = serde_json::to_string(&witness).unwrap();
        writeln!(file, "{}", json).unwrap();

        let loaded = load_tx_privacy_witness(&file.path().to_path_buf()).unwrap();
        assert_eq!(loaded.balance_old, "1000");
        assert_eq!(loaded.balance_new, "700");
        assert_eq!(loaded.amount, "300");
        assert_eq!(loaded.merkle_siblings.len(), 32);
        assert_eq!(loaded.merkle_indices.len(), 32);
    }

    #[test]
    fn test_load_tx_privacy_witness_missing_fields() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"balance_old": "1000"}}"#).unwrap();
        assert!(load_tx_privacy_witness(&file.path().to_path_buf()).is_err());
    }

    #[test]
    fn test_load_state_mask_witness_valid() {
        let mut file = NamedTempFile::new().unwrap();
        let witness = StateMaskWitness {
            state_value: "1000".to_string(),
            nonce: "42".to_string(),
            collateral_ratio: "200".to_string(),
            hidden_balance: "500".to_string(),
            threshold: "100".to_string(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        writeln!(file, "{}", json).unwrap();

        let loaded = load_state_mask_witness(&file.path().to_path_buf()).unwrap();
        assert_eq!(loaded.state_value, "1000");
        assert_eq!(loaded.nonce, "42");
        assert_eq!(loaded.collateral_ratio, "200");
        assert_eq!(loaded.hidden_balance, "500");
        assert_eq!(loaded.threshold, "100");
    }

    #[test]
    fn test_load_state_mask_witness_missing_fields() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"state_value": "1000"}}"#).unwrap();
        assert!(load_state_mask_witness(&file.path().to_path_buf()).is_err());
    }

    // ─── Serialization roundtrip tests ──────────────────────────────────

    #[test]
    fn test_witness_data_serialization_roundtrip() {
        let data = WitnessData {
            private: vec!["1".to_string(), "2".to_string()],
            public: vec![vec!["3".to_string()]],
        };
        let json = serde_json::to_string(&data).unwrap();
        let deserialized: WitnessData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.private, data.private);
        assert_eq!(deserialized.public, data.public);
    }

    #[test]
    fn test_public_inputs_data_serialization_roundtrip() {
        let data = PublicInputsData { inputs: vec![vec!["1".to_string(), "2".to_string()]] };
        let json = serde_json::to_string(&data).unwrap();
        let deserialized: PublicInputsData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.inputs, data.inputs);
    }

    #[test]
    fn test_tx_privacy_witness_serialization_roundtrip() {
        let siblings: Vec<String> = (0..32).map(|i| format!("{}", i)).collect();
        let indices: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
        let witness = TxPrivacyWitness {
            balance_old: "1000".to_string(),
            balance_new: "700".to_string(),
            randomness_old: "42".to_string(),
            randomness_new: "84".to_string(),
            amount: "300".to_string(),
            merkle_siblings: siblings.clone(),
            merkle_indices: indices.clone(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        let deserialized: TxPrivacyWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.balance_old, "1000");
        assert_eq!(deserialized.merkle_siblings, siblings);
        assert_eq!(deserialized.merkle_indices, indices);
    }

    #[test]
    fn test_state_mask_witness_serialization_roundtrip() {
        let witness = StateMaskWitness {
            state_value: "1000".to_string(),
            nonce: "42".to_string(),
            collateral_ratio: "200".to_string(),
            hidden_balance: "500".to_string(),
            threshold: "100".to_string(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        let deserialized: StateMaskWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.state_value, "1000");
        assert_eq!(deserialized.threshold, "100");
    }

    #[test]
    fn test_witness_data_with_multiple_public() {
        let data = WitnessData {
            private: vec!["10".to_string(), "20".to_string()],
            public: vec![vec!["30".to_string()], vec!["40".to_string()]],
        };
        let json = serde_json::to_string(&data).unwrap();
        let deserialized: WitnessData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.public.len(), 2);
        assert_eq!(deserialized.public[0][0], "30");
        assert_eq!(deserialized.public[1][0], "40");
    }

    // ─── Field element helpers ──────────────────────────────────────────

    #[test]
    fn test_fp_to_string_roundtrip() {
        let values = vec![0u64, 1, 42, 255, 1000, 999999, u64::MAX];
        for val in values {
            let fp = Fp::from(val);
            let s = fp_to_string(&fp);
            assert!(s.starts_with("0x"));
            let parsed = string_to_field(&s).unwrap();
            assert_eq!(parsed, fp, "Roundtrip failed for value {}", val);
        }
    }

    #[test]
    fn test_save_and_load_public_inputs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("inputs.json");
        let public_inputs = vec![vec![Fp::from(42), Fp::from(100)]];
        save_public_inputs(&path, &public_inputs).unwrap();

        let loaded = load_public_inputs(&path).unwrap();
        assert_eq!(loaded.inputs.len(), 1);
        assert_eq!(loaded.inputs[0].len(), 2);

        let fp0 = string_to_field(&loaded.inputs[0][0]).unwrap();
        let fp1 = string_to_field(&loaded.inputs[0][1]).unwrap();
        assert_eq!(fp0, Fp::from(42));
        assert_eq!(fp1, Fp::from(100));
    }

    // ─── Circuit info smoke tests ───────────────────────────────────────

    #[test]
    fn test_show_circuit_info_all() {
        // Verify all known circuits produce output without panicking
        show_circuit_info("example");
        show_circuit_info("tx_privacy");
        show_circuit_info("state_mask");
        show_circuit_info("unknown_circuit");
    }

    // ─── End-to-end prove + verify: example circuit ─────────────────────

    #[test]
    fn test_prove_and_verify_example() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        let proof_path = temp_dir.path().join("proof.bin");

        // Create witness file: a=2, b=3, sum=5
        let witness_path = temp_dir.path().join("witness.json");
        let witness = WitnessData {
            private: vec!["2".to_string(), "3".to_string()],
            public: vec![vec!["5".to_string()]],
        };
        let json = serde_json::to_string(&witness).unwrap();
        fs::write(&witness_path, json).unwrap();

        // Prove
        let witness = load_witnesses(&witness_path).unwrap();
        prove_example(witness, 4, cache_dir.clone(), proof_path.clone()).unwrap();
        assert!(proof_path.exists());

        let proof_bytes = fs::read(&proof_path).unwrap();
        assert!(!proof_bytes.is_empty());

        // Create public inputs file for verification
        let inputs_path = temp_dir.path().join("inputs.json");
        let inputs = PublicInputsData { inputs: vec![vec!["5".to_string()]] };
        let inputs_json = serde_json::to_string(&inputs).unwrap();
        fs::write(&inputs_path, inputs_json).unwrap();

        // Verify
        verify_example(proof_path, inputs_path, 4, cache_dir).unwrap();
    }

    #[test]
    fn test_verify_example_wrong_inputs_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        let proof_path = temp_dir.path().join("proof.bin");

        // Prove with a=2, b=3, sum=5
        let witness = WitnessData {
            private: vec!["2".to_string(), "3".to_string()],
            public: vec![vec!["5".to_string()]],
        };
        prove_example(witness, 4, cache_dir.clone(), proof_path.clone()).unwrap();

        // Try to verify with wrong public input (sum=10 instead of 5)
        let inputs_path = temp_dir.path().join("inputs.json");
        let wrong_inputs = PublicInputsData { inputs: vec![vec!["10".to_string()]] };
        let inputs_json = serde_json::to_string(&wrong_inputs).unwrap();
        fs::write(&inputs_path, inputs_json).unwrap();

        let result = verify_example(proof_path, inputs_path, 4, cache_dir);
        assert!(result.is_err(), "Verification should fail with wrong public inputs");
    }

    #[test]
    fn test_prove_example_wrong_witness_count() {
        let witness = WitnessData {
            private: vec!["2".to_string()], // only 1 instead of 2
            public: vec![vec!["5".to_string()]],
        };
        let temp_dir = tempfile::tempdir().unwrap();
        let result = prove_example(
            witness,
            4,
            temp_dir.path().join("cache"),
            temp_dir.path().join("proof.bin"),
        );
        assert!(result.is_err());
    }

    // ─── Witness validation tests ───────────────────────────────────────

    #[test]
    fn test_prove_tx_privacy_wrong_siblings_length() {
        let temp_dir = tempfile::tempdir().unwrap();
        let witness_path = temp_dir.path().join("witness.json");

        // Only 10 siblings instead of 32
        let witness = TxPrivacyWitness {
            balance_old: "1000".to_string(),
            balance_new: "700".to_string(),
            randomness_old: "42".to_string(),
            randomness_new: "84".to_string(),
            amount: "300".to_string(),
            merkle_siblings: (0..10).map(|i| format!("{}", i)).collect(),
            merkle_indices: (0..10).map(|i| i % 2 == 0).collect(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        fs::write(&witness_path, json).unwrap();

        let result = prove_tx_privacy(
            witness_path,
            14,
            temp_dir.path().join("cache"),
            temp_dir.path().join("proof.bin"),
        );
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Merkle siblings"), "Error should mention Merkle siblings");
    }

    #[test]
    fn test_prove_tx_privacy_invalid_balance_field() {
        let temp_dir = tempfile::tempdir().unwrap();
        let witness_path = temp_dir.path().join("witness.json");

        let witness = TxPrivacyWitness {
            balance_old: "not_a_number".to_string(),
            balance_new: "700".to_string(),
            randomness_old: "42".to_string(),
            randomness_new: "84".to_string(),
            amount: "300".to_string(),
            merkle_siblings: (0..32).map(|i| format!("{}", i)).collect(),
            merkle_indices: (0..32).map(|i| i % 2 == 0).collect(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        fs::write(&witness_path, json).unwrap();

        let result = prove_tx_privacy(
            witness_path,
            14,
            temp_dir.path().join("cache"),
            temp_dir.path().join("proof.bin"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_prove_state_mask_invalid_threshold_field() {
        let temp_dir = tempfile::tempdir().unwrap();
        let witness_path = temp_dir.path().join("witness.json");

        let witness = StateMaskWitness {
            state_value: "1000".to_string(),
            nonce: "42".to_string(),
            collateral_ratio: "200".to_string(),
            hidden_balance: "500".to_string(),
            threshold: "not_a_number".to_string(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        fs::write(&witness_path, json).unwrap();

        let result = prove_state_mask(
            witness_path,
            10,
            temp_dir.path().join("cache"),
            temp_dir.path().join("proof.bin"),
        );
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Collateral ratio")]
    fn test_prove_state_mask_collateral_out_of_range() {
        let temp_dir = tempfile::tempdir().unwrap();
        let witness_path = temp_dir.path().join("witness.json");

        // collateral_ratio = 149, below min of 150
        let witness = StateMaskWitness {
            state_value: "1000".to_string(),
            nonce: "42".to_string(),
            collateral_ratio: "149".to_string(),
            hidden_balance: "500".to_string(),
            threshold: "100".to_string(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        fs::write(&witness_path, json).unwrap();

        let _ = prove_state_mask(
            witness_path,
            10,
            temp_dir.path().join("cache"),
            temp_dir.path().join("proof.bin"),
        );
    }

    // ─── End-to-end prove + verify: state_mask circuit ──────────────────

    #[test]
    fn test_prove_and_verify_state_mask() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        let proof_path = temp_dir.path().join("proof.bin");
        let witness_path = temp_dir.path().join("witness.json");

        let witness = StateMaskWitness {
            state_value: "1000".to_string(),
            nonce: "42".to_string(),
            collateral_ratio: "200".to_string(),
            hidden_balance: "500".to_string(),
            threshold: "100".to_string(),
        };
        let json = serde_json::to_string(&witness).unwrap();
        fs::write(&witness_path, json).unwrap();

        // Prove
        prove_state_mask(witness_path, 10, cache_dir.clone(), proof_path.clone()).unwrap();
        assert!(proof_path.exists());

        // Public inputs were auto-saved
        let inputs_path = proof_path.with_extension("inputs.json");
        assert!(inputs_path.exists());

        // Verify using auto-saved public inputs
        verify_state_mask(proof_path, inputs_path, 10, cache_dir).unwrap();
    }
}
