use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use zerostyl_circuits::Registry;

use crate::extractor::from_descriptor;

#[derive(Parser)]
#[command(name = "zerostyl-export")]
#[command(about = "Export privacy-safe ABI metadata for registered circuits", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Emit the AbiSchema JSON for a registered circuit.
    Schema {
        #[arg(short, long)]
        circuit: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List every registered circuit with its summary.
    List,
}

pub fn run(registry: &Registry) -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Schema { circuit, output } => cmd_schema(registry, &circuit, output.as_deref()),
        Commands::List => cmd_list(registry),
    }
}

fn cmd_schema(registry: &Registry, circuit_name: &str, output: Option<&Path>) -> Result<()> {
    let desc = registry.get(circuit_name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let abi = from_descriptor(desc);
    let json = serde_json::to_string_pretty(&abi)?;
    match output {
        Some(path) => {
            std::fs::write(path, &json)?;
            eprintln!("wrote {} bytes -> {}", json.len(), path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn cmd_list(registry: &Registry) -> Result<()> {
    let names = registry.list();
    if names.is_empty() {
        eprintln!("No circuits registered.");
        return Ok(());
    }
    for name in names {
        let d = registry.get(name).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{} (v{}, k={})", d.name(), d.version(), d.default_k());
    }
    Ok(())
}
