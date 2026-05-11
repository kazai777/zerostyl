//! ZeroStyl CLI — proof generation, verification, and schema inspection.
//!
//! All circuit-specific behavior lives in `CircuitDescriptor` implementations
//! provided by the binary at startup. This crate contains zero hardcoded
//! circuit names: adding a new circuit only requires registering its
//! descriptor before calling [`run`].

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Map, Value};
use zerostyl_circuits::{FieldType, FieldVisibility, Registry, WitnessSchema};

#[derive(Parser)]
#[command(name = "zerostyl-prove")]
#[command(about = "Generate and verify zero-knowledge proofs for halo2 circuits", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a proof for a circuit
    Generate {
        /// Circuit name (must be registered)
        #[arg(short, long)]
        circuit: String,
        /// Path to the witness JSON file
        #[arg(short, long)]
        witnesses: PathBuf,
        /// Output path for the proof
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,
        /// Circuit parameter k (size = 2^k). Defaults to the descriptor's value.
        #[arg(short, long)]
        k: Option<u32>,
        /// Cache directory for proving/verifying keys
        #[arg(long, default_value = ".zerostyl_cache")]
        cache_dir: PathBuf,
    },

    /// Verify a proof
    Verify {
        #[arg(short, long)]
        circuit: String,
        #[arg(short, long)]
        proof: PathBuf,
        /// Public inputs JSON (written automatically by `generate`)
        #[arg(short = 'i', long, default_value = "public_inputs.json")]
        inputs: PathBuf,
        #[arg(short, long)]
        k: Option<u32>,
        #[arg(long, default_value = ".zerostyl_cache")]
        cache_dir: PathBuf,
    },

    /// Show circuit metadata and witness template
    Info {
        /// Circuit name, or "list" to show every registered circuit
        circuit: String,
    },
}

/// Parse CLI args and dispatch to the registry.
pub fn run(registry: &Registry) -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { circuit, witnesses, output, k, cache_dir } => {
            cmd_generate(registry, &circuit, &witnesses, &output, k, &cache_dir)
        }
        Commands::Verify { circuit, proof, inputs, k, cache_dir } => {
            cmd_verify(registry, &circuit, &proof, &inputs, k, &cache_dir)
        }
        Commands::Info { circuit } => cmd_info(registry, &circuit),
    }
}

fn cmd_generate(
    registry: &Registry,
    circuit_name: &str,
    witnesses_path: &Path,
    output: &Path,
    k_override: Option<u32>,
    cache_dir: &Path,
) -> Result<()> {
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let k = k_override.unwrap_or_else(|| desc.default_k());
    let witness_json = fs::read_to_string(witnesses_path)
        .with_context(|| format!("reading witness file: {}", witnesses_path.display()))?;

    println!("ZeroStyl Prover — circuit: {}  k: {}", desc.name(), k);

    let artifact = desc.prove(&witness_json, k, cache_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

    fs::write(output, &artifact.bytes)
        .with_context(|| format!("writing proof to {}", output.display()))?;
    let inputs_path = output.with_file_name("public_inputs.json");
    fs::write(&inputs_path, &artifact.public_inputs_json)
        .with_context(|| format!("writing public inputs to {}", inputs_path.display()))?;

    println!("  Proof: {} bytes  →  {}", artifact.bytes.len(), output.display());
    println!("  Public inputs  →  {}", inputs_path.display());
    println!("Done.");
    Ok(())
}

fn cmd_verify(
    registry: &Registry,
    circuit_name: &str,
    proof_path: &Path,
    inputs_path: &Path,
    k_override: Option<u32>,
    cache_dir: &Path,
) -> Result<()> {
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let k = k_override.unwrap_or_else(|| desc.default_k());
    let proof =
        fs::read(proof_path).with_context(|| format!("reading proof: {}", proof_path.display()))?;
    let inputs_json = fs::read_to_string(inputs_path)
        .with_context(|| format!("reading public inputs: {}", inputs_path.display()))?;

    println!("ZeroStyl Verifier — circuit: {}  k: {}", desc.name(), k);

    let ok = desc.verify(&proof, &inputs_json, k, cache_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    if ok {
        println!("  Proof is VALID");
        println!("Done.");
        Ok(())
    } else {
        anyhow::bail!("Proof is INVALID")
    }
}

fn cmd_info(registry: &Registry, circuit_name: &str) -> Result<()> {
    if matches!(circuit_name, "list" | "all" | "ls") {
        let names = registry.list();
        if names.is_empty() {
            println!("No circuits registered.");
            return Ok(());
        }
        println!("Registered circuits:");
        for name in names {
            let d = registry.get(name).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("  {} (v{}, k={})", d.name(), d.version(), d.default_k());
        }
        return Ok(());
    }

    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Circuit: {} v{}", desc.name(), desc.version());
    println!("  {}", desc.description());
    println!("  Default k:         {}", desc.default_k());
    println!("  Public inputs:     {}", desc.num_public_inputs());
    println!("  Private witnesses: {}", desc.num_private_witnesses());
    println!();
    println!("Witness fields:");
    for f in &desc.witness_schema().fields {
        let vis = match f.visibility {
            FieldVisibility::Private => "private",
            FieldVisibility::Public => "public ",
        };
        let kind = render_field_type(&f.kind);
        let descr = f.description.as_deref().unwrap_or("");
        println!("  - [{vis}] {:<20} : {:<24} {}", f.name, kind, descr);
    }
    println!();
    println!("Public inputs:");
    for f in &desc.public_inputs_schema().fields {
        let kind = render_field_type(&f.kind);
        let descr = f.description.as_deref().unwrap_or("");
        println!("  - {:<20} : {:<24} {}", f.name, kind, descr);
    }
    println!();
    println!("Witness template (copy, fill, save as <circuit>.json):");
    let template = render_witness_template(desc.witness_schema());
    println!("{}", serde_json::to_string_pretty(&template)?);
    Ok(())
}

fn render_field_type(t: &FieldType) -> String {
    match t {
        FieldType::U64 => "u64".into(),
        FieldType::U128 => "u128".into(),
        FieldType::Bool => "bool".into(),
        FieldType::Bytes32 => "bytes32".into(),
        FieldType::Address => "address".into(),
        FieldType::Fp => "fp".into(),
        FieldType::Array { kind, len } => format!("[{}; {len}]", render_field_type(kind)),
    }
}

fn render_witness_template(schema: &WitnessSchema) -> Value {
    let mut map = Map::new();
    for f in &schema.fields {
        map.insert(f.name.clone(), example_value(&f.kind));
    }
    Value::Object(map)
}

fn example_value(t: &FieldType) -> Value {
    match t {
        FieldType::U64 | FieldType::U128 | FieldType::Bool | FieldType::Fp => json!("0"),
        FieldType::Bytes32 => json!(format!("0x{}", "00".repeat(32))),
        FieldType::Address => json!(format!("0x{}", "00".repeat(20))),
        FieldType::Array { kind, len } => {
            Value::Array((0..*len).map(|_| example_value(kind)).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerostyl_circuits::{WitnessField, WitnessSchema};

    #[test]
    fn render_field_type_handles_array() {
        let t = FieldType::Array { kind: Box::new(FieldType::Bool), len: 32 };
        assert_eq!(render_field_type(&t), "[bool; 32]");
    }

    #[test]
    fn template_renders_scalars_as_zero_string() {
        let schema = WitnessSchema {
            fields: vec![WitnessField {
                name: "x".into(),
                kind: FieldType::U64,
                visibility: FieldVisibility::Private,
                description: None,
            }],
        };
        let t = render_witness_template(&schema);
        assert_eq!(t.get("x"), Some(&json!("0")));
    }

    #[test]
    fn template_renders_array_of_correct_length() {
        let schema = WitnessSchema {
            fields: vec![WitnessField {
                name: "siblings".into(),
                kind: FieldType::Array { kind: Box::new(FieldType::Fp), len: 32 },
                visibility: FieldVisibility::Private,
                description: None,
            }],
        };
        let t = render_witness_template(&schema);
        assert_eq!(t["siblings"].as_array().unwrap().len(), 32);
    }

    #[test]
    fn template_renders_bytes32_as_hex() {
        let schema = WitnessSchema {
            fields: vec![WitnessField {
                name: "h".into(),
                kind: FieldType::Bytes32,
                visibility: FieldVisibility::Private,
                description: None,
            }],
        };
        let t = render_witness_template(&schema);
        assert_eq!(t["h"].as_str().unwrap().len(), 2 + 64);
    }
}
