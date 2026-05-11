//! ZeroStyl Circuit Debugger CLI.
//!
//! Inspect circuit structure, run the MockProver against a witness with structured
//! failure diagnostics, and display the witness/schema of any circuit registered
//! at startup. Adding a new circuit requires only registering its descriptor here;
//! no other file in this crate needs to change.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use zerostyl_circuits::{FieldType, FieldVisibility, Registry, WitnessSchema};
use zerostyl_debugger::{format_introspection, format_mock_prover_report, OutputFormat};

#[derive(Parser)]
#[command(name = "zerostyl-debug")]
#[command(about = "Debug and inspect halo2 zero-knowledge circuits", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect circuit structure (columns, gates, constraints, degree)
    Inspect {
        #[arg(short, long)]
        circuit: String,
    },

    /// Show the expected witness schema and a copy-pastable template
    Schema {
        #[arg(short, long)]
        circuit: String,
    },

    /// Run the MockProver against a witness and surface failing constraints
    Debug {
        #[arg(short, long)]
        circuit: String,
        #[arg(short, long)]
        witnesses: PathBuf,
        #[arg(short, long)]
        k: Option<u32>,
        /// Output format: text (default) or json
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Pretty-print a witness file alongside the circuit's schema
    Witness {
        #[arg(short, long)]
        circuit: String,
        #[arg(short, long)]
        witnesses: PathBuf,
    },
}

fn main() -> Result<()> {
    let registry = Registry::new();
    for d in [
        example_demo::descriptor(),
        state_mask::descriptor(),
        tx_privacy::descriptor(),
        private_vote::descriptor(),
    ] {
        registry.register(d).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect { circuit } => cmd_inspect(&registry, &circuit),
        Commands::Schema { circuit } => cmd_schema(&registry, &circuit),
        Commands::Debug { circuit, witnesses, k, format } => {
            cmd_debug(&registry, &circuit, &witnesses, k, &format)
        }
        Commands::Witness { circuit, witnesses } => cmd_witness(&registry, &circuit, &witnesses),
    }
}

fn cmd_inspect(registry: &Registry, circuit_name: &str) -> Result<()> {
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let intro = desc.inspect().map_err(|e| anyhow::anyhow!("{e}"))?;
    print!("{}", format_introspection(&intro));
    Ok(())
}

fn cmd_schema(registry: &Registry, circuit_name: &str) -> Result<()> {
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Circuit: {} v{}", desc.name(), desc.version());
    println!("  {}", desc.description());
    println!();
    println!("Witness fields:");
    print_witness_schema(desc.witness_schema());
    println!();
    println!("Public inputs:");
    for f in &desc.public_inputs_schema().fields {
        let kind = render_field_type(&f.kind);
        let descr = f.description.as_deref().unwrap_or("");
        println!("  - {:<24} : {:<24} {}", f.name, kind, descr);
    }
    println!();
    println!("Witness template (copy, fill, save as <circuit>.json):");
    let template = render_witness_template(desc.witness_schema());
    println!("{}", serde_json::to_string_pretty(&template)?);
    Ok(())
}

fn cmd_debug(
    registry: &Registry,
    circuit_name: &str,
    witnesses_path: &std::path::Path,
    k_override: Option<u32>,
    format_str: &str,
) -> Result<()> {
    let format = OutputFormat::parse(format_str)?;
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let k = k_override.unwrap_or_else(|| desc.default_k());
    let witness_json = fs::read_to_string(witnesses_path)
        .with_context(|| format!("reading witness file: {}", witnesses_path.display()))?;

    let report = desc.mock_prove(&witness_json, k).map_err(|e| anyhow::anyhow!("{e}"))?;
    print!("{}", format_mock_prover_report(&report, format)?);
    Ok(())
}

fn cmd_witness(
    registry: &Registry,
    circuit_name: &str,
    witnesses_path: &std::path::Path,
) -> Result<()> {
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let witness_raw = fs::read_to_string(witnesses_path)
        .with_context(|| format!("reading witness file: {}", witnesses_path.display()))?;

    let parsed: serde_json::Value = serde_json::from_str(&witness_raw)
        .with_context(|| format!("witness file is not valid JSON: {}", witnesses_path.display()))?;

    println!("Circuit: {}", desc.name());
    println!();
    println!("Witness contents ({}):", witnesses_path.display());
    println!("{}", serde_json::to_string_pretty(&parsed)?);
    println!();
    println!("Expected schema:");
    print_witness_schema(desc.witness_schema());
    println!();
    println!("(Run `zerostyl-debug debug --circuit {} --witnesses {}` to validate", desc.name(), witnesses_path.display());
    println!(" against the constraint system.)");
    Ok(())
}

fn print_witness_schema(schema: &WitnessSchema) {
    for f in &schema.fields {
        let vis = match f.visibility {
            FieldVisibility::Private => "private",
            FieldVisibility::Public => "public ",
        };
        let kind = render_field_type(&f.kind);
        let descr = f.description.as_deref().unwrap_or("");
        println!("  - [{vis}] {:<20} : {:<24} {}", f.name, kind, descr);
    }
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

fn render_witness_template(schema: &WitnessSchema) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for f in &schema.fields {
        map.insert(f.name.clone(), example_value(&f.kind));
    }
    serde_json::Value::Object(map)
}

fn example_value(t: &FieldType) -> serde_json::Value {
    use serde_json::json;
    match t {
        FieldType::U64 | FieldType::U128 | FieldType::Bool | FieldType::Fp => json!("0"),
        FieldType::Bytes32 => json!(format!("0x{}", "00".repeat(32))),
        FieldType::Address => json!(format!("0x{}", "00".repeat(20))),
        FieldType::Array { kind, len } => {
            serde_json::Value::Array((0..*len).map(|_| example_value(kind)).collect())
        }
    }
}
