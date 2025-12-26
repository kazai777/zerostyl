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
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tx_privacy::TxPrivacyCircuit;
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

// Example circuit for demonstration
// In production, this would be replaced with actual circuits from examples/
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
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
        }
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

        ExampleConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
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

#[derive(Debug, Serialize, Deserialize)]
struct WitnessData {
    private: Vec<String>,
    public: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TxPrivacyWitnessData {
    balance_old: String,
    balance_new: String,
    randomness_old: String,
    randomness_new: String,
    amount: String,
    merkle_path: Vec<String>,
    public: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicInputsData {
    inputs: Vec<Vec<String>>,
}

fn load_witnesses(path: &PathBuf) -> Result<WitnessData> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read witnesses file: {:?}", path))?;

    serde_json::from_str(&content).context("Failed to parse witnesses JSON")
}

fn load_public_inputs(path: &PathBuf) -> Result<PublicInputsData> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read public inputs file: {:?}", path))?;

    serde_json::from_str(&content).context("Failed to parse public inputs JSON")
}

fn load_tx_privacy_witnesses(path: &PathBuf) -> Result<TxPrivacyWitnessData> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read witnesses file: {:?}", path))?;

    serde_json::from_str(&content).context("Failed to parse tx_privacy witnesses JSON")
}

fn prove_example(
    witnesses: WitnessData,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("🔧 Loading witnesses...");

    if witnesses.private.len() != 2 {
        anyhow::bail!("Example circuit requires exactly 2 private witnesses (a, b)");
    }

    let a = string_to_field(&witnesses.private[0])?;
    let b = string_to_field(&witnesses.private[1])?;

    let circuit = ExampleCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };

    println!("🔑 Setting up prover with k={}...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "example".to_string(),
        k,
        num_public_inputs: 1,
        num_private_witnesses: 2,
    };

    prover.setup(metadata)?;

    println!("📊 Generating proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = witnesses
        .public
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let proof = prover.generate_proof(&public_inputs)?;

    println!("💾 Saving proof to {:?}...", output);
    fs::write(&output, &proof)
        .context(format!("Failed to write proof to {:?}", output))?;

    println!("✅ Proof generated successfully!");
    println!("   Size: {} bytes", proof.len());
    println!("   Output: {:?}", output);

    Ok(())
}

fn prove_tx_privacy(
    witnesses_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("🔧 Loading tx_privacy witnesses...");

    let witnesses = load_tx_privacy_witnesses(&witnesses_path)?;

    let balance_old: u64 = witnesses.balance_old.parse()
        .context("Invalid balance_old")?;
    let balance_new: u64 = witnesses.balance_new.parse()
        .context("Invalid balance_new")?;
    let randomness_old = string_to_field(&witnesses.randomness_old)?;
    let randomness_new = string_to_field(&witnesses.randomness_new)?;
    let amount: u64 = witnesses.amount.parse()
        .context("Invalid amount")?;

    let merkle_path: Result<Vec<Fp>> = witnesses.merkle_path
        .iter()
        .map(|s| string_to_field(s))
        .collect();
    let merkle_path = merkle_path?;

    if merkle_path.len() != tx_privacy::MERKLE_DEPTH {
        anyhow::bail!(
            "Merkle path must have depth {}, got {}",
            tx_privacy::MERKLE_DEPTH,
            merkle_path.len()
        );
    }

    println!("📊 Circuit parameters:");
    println!("   Balance: {} -> {}", balance_old, balance_new);
    println!("   Amount: {}", amount);
    println!("   Merkle depth: {}", merkle_path.len());

    let circuit = TxPrivacyCircuit::new(
        balance_old,
        balance_new,
        randomness_old,
        randomness_new,
        amount,
        merkle_path,
    );

    println!("🔑 Setting up prover with k={}...", k);
    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 38, // 5 + 32 merkle path + amount
    };

    prover.setup(metadata)?;

    println!("📊 Generating proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = witnesses
        .public
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let proof = prover.generate_proof(&public_inputs)?;

    println!("💾 Saving proof to {:?}...", output);
    fs::write(&output, &proof)
        .context(format!("Failed to write proof to {:?}", output))?;

    println!("✅ Proof generated successfully!");
    println!("   Size: {} bytes", proof.len());
    println!("   Output: {:?}", output);

    Ok(())
}

fn verify_tx_privacy(
    proof_path: PathBuf,
    inputs_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
) -> Result<()> {
    println!("🔧 Loading proof and public inputs...");

    let proof = fs::read(&proof_path)
        .context(format!("Failed to read proof file: {:?}", proof_path))?;

    let inputs_data = load_public_inputs(&inputs_path)?;

    println!("🔑 Setting up verifier with k={}...", k);

    let circuit = TxPrivacyCircuit::default();

    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "tx_privacy".to_string(),
        k,
        num_public_inputs: 3,
        num_private_witnesses: 38,
    };

    prover.setup(metadata)?;

    println!("🔍 Verifying proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = inputs_data
        .inputs
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let is_valid = prover.verify_proof(&proof, &public_inputs)?;

    if is_valid {
        println!("✅ Proof is VALID!");
    } else {
        println!("❌ Proof is INVALID!");
        anyhow::bail!("Proof verification failed");
    }

    Ok(())
}

fn verify_example(
    proof_path: PathBuf,
    inputs_path: PathBuf,
    k: u32,
    cache_dir: PathBuf,
) -> Result<()> {
    println!("🔧 Loading proof and public inputs...");

    let proof = fs::read(&proof_path)
        .context(format!("Failed to read proof file: {:?}", proof_path))?;

    let inputs_data = load_public_inputs(&inputs_path)?;

    println!("🔑 Setting up verifier with k={}...", k);

    // Create circuit without witnesses for verification
    let circuit = ExampleCircuit {
        a: Value::unknown(),
        b: Value::unknown(),
    };

    let mut prover = NativeProver::with_cache_dir(circuit, k, &cache_dir)?;

    let metadata = KeyMetadata {
        circuit_name: "example".to_string(),
        k,
        num_public_inputs: 1,
        num_private_witnesses: 2,
    };

    prover.setup(metadata)?;

    println!("🔍 Verifying proof...");

    let public_inputs: Result<Vec<Vec<Fp>>> = inputs_data
        .inputs
        .iter()
        .map(|row| row.iter().map(|s| string_to_field(s)).collect())
        .collect();

    let public_inputs = public_inputs?;

    let is_valid = prover.verify_proof(&proof, &public_inputs)?;

    if is_valid {
        println!("✅ Proof is VALID!");
    } else {
        println!("❌ Proof is INVALID!");
        anyhow::bail!("Proof verification failed");
    }

    Ok(())
}

fn show_circuit_info(circuit_name: &str) {
    match circuit_name {
        "example" => {
            println!("📋 Circuit: example");
            println!("   Description: Simple addition circuit (a + b = sum)");
            println!("   Private witnesses: 2 (a, b)");
            println!("   Public inputs: 1 (sum)");
            println!();
            println!("   Witness format (witnesses.json):");
            println!(r#"   {{
     "private": ["2", "3"],
     "public": [["5"]]
   }}"#);
        }
        "tx_privacy" => {
            println!("📋 Circuit: tx_privacy");
            println!("   Description: Transaction privacy with Pedersen commitments");
            println!("   Private witnesses: balance_old, balance_new, randomness_old, randomness_new, amount, merkle_path[32]");
            println!("   Public inputs: 3 (commitment_old, commitment_new, merkle_root)");
            println!();
            println!("   Witness format (witnesses.json):");
            println!(r#"   {{
     "balance_old": "1000",
     "balance_new": "800",
     "randomness_old": "42",
     "randomness_new": "43",
     "amount": "200",
     "merkle_path": ["0", "0", ..., "0"],
     "public": [["1042", "843", "0"]]
   }}"#);
        }
        "state_mask" => {
            println!("📋 Circuit: state_mask");
            println!("   Description: Range proof for state masking");
            println!("   Status: Available in examples/state_mask");
            println!("   Note: Integration with CLI coming soon");
        }
        _ => {
            eprintln!("❌ Unknown circuit: {}", circuit_name);
            eprintln!("   Available circuits: example, tx_privacy, state_mask");
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove {
            circuit,
            witnesses,
            output,
            k,
            cache_dir,
        } => {
            println!("🚀 ZeroStyl Prover");
            println!("   Circuit: {}", circuit);
            println!();

            match circuit.as_str() {
                "example" => {
                    let witnesses = load_witnesses(&witnesses)?;
                    prove_example(witnesses, k, cache_dir, output)?
                }
                "tx_privacy" => prove_tx_privacy(witnesses, k, cache_dir, output)?,
                "state_mask" => {
                    anyhow::bail!(
                        "Circuit 'state_mask' not yet integrated with CLI. Use 'example' or 'tx_privacy'.",
                    );
                }
                _ => {
                    anyhow::bail!("Unknown circuit: {}. Available: example, tx_privacy", circuit);
                }
            }
        }
        Commands::Verify {
            circuit,
            proof,
            inputs,
            k,
            cache_dir,
        } => {
            println!("🔍 ZeroStyl Verifier");
            println!("   Circuit: {}", circuit);
            println!();

            match circuit.as_str() {
                "example" => verify_example(proof, inputs, k, cache_dir)?,
                "tx_privacy" => verify_tx_privacy(proof, inputs, k, cache_dir)?,
                "state_mask" => {
                    anyhow::bail!(
                        "Circuit 'state_mask' not yet integrated with CLI. Use 'example' or 'tx_privacy'.",
                    );
                }
                _ => {
                    anyhow::bail!("Unknown circuit: {}. Available: example, tx_privacy", circuit);
                }
            }
        }
        Commands::Info { circuit } => {
            show_circuit_info(&circuit);
        }
    }

    Ok(())
}
