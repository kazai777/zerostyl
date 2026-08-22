//! `zerostyl-orbit` command-line interface.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use zerostyl_circuits::ProvingSystem;

use crate::deployability::{assess, assess_verification, ArtifactSize};
use crate::profile::{builtin, builtins, orbit_template, ChainProfile};

#[derive(Parser)]
#[command(name = "zerostyl-orbit")]
#[command(about = "Per-chain size/gas/precompile profiles and deployability analysis", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List the built-in chain profiles.
    List,

    /// Show a chain profile (built-in name or path to a .toml file).
    Show {
        /// Built-in chain name (e.g. `arbitrum-sepolia`) or a path to a profile `.toml`.
        #[arg(short, long)]
        chain: String,
    },

    /// Check whether a WASM artifact is deployable on a chain.
    Check {
        /// Built-in chain name or a path to a profile `.toml`.
        #[arg(short, long)]
        chain: String,
        /// Path to the `.wasm` artifact to measure.
        #[arg(short, long)]
        wasm: PathBuf,
        /// Also check the precompiles this proving system needs on-chain.
        #[arg(long, value_parser = parse_proving_system)]
        proving_system: Option<ProvingSystem>,
    },

    /// Check one WASM artifact against every built-in chain profile.
    Matrix {
        /// Path to the `.wasm` artifact to measure.
        #[arg(short, long)]
        wasm: PathBuf,
        /// Also check the precompiles this proving system needs on-chain.
        #[arg(long, value_parser = parse_proving_system)]
        proving_system: Option<ProvingSystem>,
    },

    /// Write a customizable Orbit chain-profile template to a `.toml` file.
    Init {
        /// Output path for the template.
        #[arg(short, long, default_value = "orbit-chain.toml")]
        output: PathBuf,
    },
}

/// Parse a proving-system name (matching the `abi.json` `snake_case` spellings).
fn parse_proving_system(s: &str) -> std::result::Result<ProvingSystem, String> {
    match s {
        "halo2_kzg" => Ok(ProvingSystem::Halo2Kzg),
        "halo2_kzg_groth16_wrap" => Ok(ProvingSystem::Halo2KzgGroth16Wrap),
        "halo2_ipa" => Ok(ProvingSystem::Halo2Ipa),
        "stark_fri" => Ok(ProvingSystem::StarkFri),
        other => Err(format!(
            "unknown proving system `{other}` (expected halo2_kzg, halo2_kzg_groth16_wrap, halo2_ipa, or stark_fri)"
        )),
    }
}

/// Resolve a `--chain` argument: a built-in name, else a path to a TOML profile.
fn resolve_chain(chain: &str) -> Result<ChainProfile> {
    if let Some(p) = builtin(chain) {
        return Ok(p);
    }
    let path = Path::new(chain);
    if path.exists() {
        return ChainProfile::load_file(path)
            .with_context(|| format!("loading chain profile from {}", path.display()));
    }
    Err(anyhow!(
        "unknown chain `{chain}`: not a built-in profile and not a file path. Run `zerostyl-orbit list`."
    ))
}

/// Entry point invoked by the binary.
///
/// # Errors
/// Returns any CLI, I/O, or parsing error for the process to surface.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::List => cmd_list(),
        Commands::Show { chain } => cmd_show(&chain),
        Commands::Check { chain, wasm, proving_system } => cmd_check(&chain, &wasm, proving_system),
        Commands::Matrix { wasm, proving_system } => cmd_matrix(&wasm, proving_system),
        Commands::Init { output } => cmd_init(&output),
    }
}

fn cmd_list() -> Result<()> {
    println!("Built-in chain profiles:\n");
    for p in builtins() {
        let b = p.wasm_budget();
        println!(
            "  {:<16} chain_id={:<8} ArbOS {:<3} code≤{} KB  wasm≤{} KB",
            p.name,
            p.chain_id,
            p.arbos_version,
            b.compressed / 1024,
            b.uncompressed / 1024,
        );
    }
    Ok(())
}

fn cmd_show(chain: &str) -> Result<()> {
    let p = resolve_chain(chain)?;
    print!("{}", p.to_toml());
    Ok(())
}

fn cmd_check(chain: &str, wasm: &Path, system: Option<ProvingSystem>) -> Result<()> {
    let profile = resolve_chain(chain)?;
    let artifact = ArtifactSize::measure_wasm(wasm)
        .with_context(|| format!("measuring {}", wasm.display()))?;
    print!("{}", assess(&profile, &artifact));
    if let Some(system) = system {
        println!();
        print!("{}", assess_verification(&profile, system));
    }
    Ok(())
}

fn cmd_matrix(wasm: &Path, system: Option<ProvingSystem>) -> Result<()> {
    let artifact = ArtifactSize::measure_wasm(wasm)
        .with_context(|| format!("measuring {}", wasm.display()))?;
    println!(
        "Artifact: {} compressed / {} decompressed\n",
        human(artifact.compressed),
        human(artifact.uncompressed)
    );
    for profile in builtins() {
        let report = assess(&profile, &artifact);
        println!("{report}");
        if let Some(system) = system {
            print!("{}", assess_verification(&profile, system));
            println!();
        }
    }
    Ok(())
}

fn cmd_init(output: &Path) -> Result<()> {
    if output.exists() {
        return Err(anyhow!("{} already exists; refusing to overwrite", output.display()));
    }
    std::fs::write(output, orbit_template().to_toml())
        .with_context(|| format!("writing {}", output.display()))?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn human(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
