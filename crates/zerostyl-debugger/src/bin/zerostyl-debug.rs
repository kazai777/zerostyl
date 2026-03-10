//! ZeroStyl Circuit Debugger CLI
//!
//! Inspect circuit structure, debug witness assignments with enhanced MockProver
//! diagnostics, and display witness values for halo2 circuits.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};
use halo2_proofs::poly::Rotation;
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;
use serde::Deserialize;
use state_mask::StateMaskCircuit;
use std::path::PathBuf;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_debugger::{debug_circuit, inspect_circuit};

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
        /// Circuit name (example, tx_privacy, state_mask, private_vote)
        #[arg(short, long)]
        circuit: String,

        /// Circuit parameter k (size = 2^k). Defaults to circuit-specific value.
        #[arg(short, long)]
        k: Option<u32>,
    },

    /// Debug a circuit with witnesses using enhanced MockProver diagnostics
    Debug {
        /// Circuit name (example, tx_privacy, state_mask, private_vote)
        #[arg(short, long)]
        circuit: String,

        /// Path to witnesses JSON file
        #[arg(short, long)]
        witnesses: PathBuf,

        /// Circuit parameter k (size = 2^k). Defaults to circuit-specific value.
        #[arg(short, long)]
        k: Option<u32>,

        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Display witness values from a JSON file
    Witness {
        /// Circuit name (example, tx_privacy, state_mask, private_vote)
        #[arg(short, long)]
        circuit: String,

        /// Path to witnesses JSON file
        #[arg(short, long)]
        witnesses: PathBuf,
    },
}

// ─── Built-in example circuit: a + b = sum ──────────────────────────────────

#[derive(Clone)]
struct ExampleConfig {
    advice: Column<Advice>,
    _instance: Column<Instance>,
    selector: Selector,
}

#[derive(Clone, Default)]
struct ExampleCircuit {
    a: Value<Fp>,
    b: Value<Fp>,
}

impl Circuit<Fp> for ExampleCircuit {
    type Config = ExampleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> ExampleConfig {
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

        ExampleConfig { advice, _instance: instance, selector }
    }

    fn synthesize(
        &self,
        config: ExampleConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> std::result::Result<(), Error> {
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

// ─── Witness JSON types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ExampleWitness {
    a: String,
    b: String,
    sum: String,
}

#[derive(Debug, Deserialize)]
struct TxPrivacyWitness {
    balance_old: String,
    balance_new: String,
    randomness_old: String,
    randomness_new: String,
    amount: String,
    merkle_siblings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StateMaskWitness {
    state_value: String,
    nonce: String,
    range_min: String,
    range_max: String,
}

#[derive(Debug, Deserialize)]
struct PrivateVoteWitness {
    balance: String,
    randomness_balance: String,
    vote: String,
    randomness_vote: String,
    threshold: String,
}

// ─── Field element parsing ──────────────────────────────────────────────────

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
        let val: u64 = s.parse().context(format!("Invalid integer: {}", s))?;
        Ok(Fp::from(val))
    }
}

// ─── Default k values ───────────────────────────────────────────────────────

fn default_k(circuit_name: &str) -> u32 {
    match circuit_name {
        "example" => 4,
        "tx_privacy" => 14,
        "state_mask" => 10,
        "private_vote" => 11,
        _ => 10,
    }
}

// ─── Inspect command ────────────────────────────────────────────────────────

fn run_inspect(circuit_name: &str, k: u32) -> Result<()> {
    let stats = match circuit_name {
        "example" => inspect_circuit::<ExampleCircuit>(circuit_name, k)?,
        "tx_privacy" => inspect_circuit::<TxPrivacyCircuit>(circuit_name, k)?,
        "state_mask" => inspect_circuit::<StateMaskCircuit>(circuit_name, k)?,
        "private_vote" => inspect_circuit::<PrivateVoteCircuit>(circuit_name, k)?,
        _ => {
            anyhow::bail!(
                "Unknown circuit: {}. Available: example, tx_privacy, state_mask, private_vote",
                circuit_name
            );
        }
    };

    println!("{}", stats);
    Ok(())
}

// ─── Debug command ──────────────────────────────────────────────────────────

fn run_debug(circuit_name: &str, witnesses_path: &PathBuf, k: u32, format: &str) -> Result<()> {
    let content = std::fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;

    let report = match circuit_name {
        "example" => {
            let w: ExampleWitness =
                serde_json::from_str(&content).context("Failed to parse example witness JSON")?;
            let a = parse_field(&w.a)?;
            let b = parse_field(&w.b)?;
            let sum = parse_field(&w.sum)?;
            let circuit = ExampleCircuit { a: Value::known(a), b: Value::known(b) };
            debug_circuit(&circuit, vec![vec![sum]], k, circuit_name)?
        }
        "tx_privacy" => {
            let w: TxPrivacyWitness = serde_json::from_str(&content)
                .context("Failed to parse tx_privacy witness JSON")?;

            let balance_old: u64 = w.balance_old.parse().context("Invalid balance_old")?;
            let balance_new: u64 = w.balance_new.parse().context("Invalid balance_new")?;
            let randomness_old = parse_field(&w.randomness_old)?;
            let randomness_new = parse_field(&w.randomness_new)?;
            let amount: u64 = w.amount.parse().context("Invalid amount")?;

            if w.merkle_siblings.len() != MERKLE_DEPTH {
                anyhow::bail!(
                    "Expected {} Merkle siblings, got {}",
                    MERKLE_DEPTH,
                    w.merkle_siblings.len()
                );
            }

            let merkle_siblings: Result<Vec<Fp>> =
                w.merkle_siblings.iter().map(|s| parse_field(s)).collect();
            let merkle_siblings = merkle_siblings?;

            let commitment_old =
                TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
            let commitment_new =
                TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
            let merkle_root =
                TxPrivacyCircuit::compute_merkle_root(commitment_old, &merkle_siblings);

            let circuit = TxPrivacyCircuit::new(
                balance_old,
                balance_new,
                randomness_old,
                randomness_new,
                amount,
                merkle_siblings,
            );

            let public_inputs = vec![vec![commitment_old, commitment_new, merkle_root]];
            debug_circuit(&circuit, public_inputs, k, circuit_name)?
        }
        "state_mask" => {
            let w: StateMaskWitness = serde_json::from_str(&content)
                .context("Failed to parse state_mask witness JSON")?;

            let state_value: u64 = w.state_value.parse().context("Invalid state_value")?;
            let nonce = parse_field(&w.nonce)?;
            let range_min: u64 = w.range_min.parse().context("Invalid range_min")?;
            let range_max: u64 = w.range_max.parse().context("Invalid range_max")?;

            let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);

            let circuit = StateMaskCircuit::new(state_value, nonce, range_min, range_max);

            let public_inputs = vec![vec![commitment]];
            debug_circuit(&circuit, public_inputs, k, circuit_name)?
        }
        "private_vote" => {
            let w: PrivateVoteWitness = serde_json::from_str(&content)
                .context("Failed to parse private_vote witness JSON")?;

            let balance: u64 = w.balance.parse().context("Invalid balance")?;
            let randomness_balance = parse_field(&w.randomness_balance)?;
            let vote: u64 = w.vote.parse().context("Invalid vote")?;
            let randomness_vote = parse_field(&w.randomness_vote)?;
            let threshold: u64 = w.threshold.parse().context("Invalid threshold")?;

            let balance_commitment =
                PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
            let vote_commitment =
                PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);

            let circuit = PrivateVoteCircuit::new(
                balance,
                randomness_balance,
                vote,
                randomness_vote,
                threshold,
            );

            let public_inputs =
                vec![vec![balance_commitment, Fp::from(threshold), vote_commitment]];
            debug_circuit(&circuit, public_inputs, k, circuit_name)?
        }
        _ => {
            anyhow::bail!(
                "Unknown circuit: {}. Available: example, tx_privacy, state_mask, private_vote",
                circuit_name
            );
        }
    };

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&report)
                .context("Failed to serialize debug report")?;
            println!("{}", json);
        }
        _ => {
            println!("{}", report);
        }
    }

    Ok(())
}

// ─── Witness command ────────────────────────────────────────────────────────

fn run_witness(circuit_name: &str, witnesses_path: &PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;

    match circuit_name {
        "example" => {
            let w: ExampleWitness =
                serde_json::from_str(&content).context("Failed to parse example witness JSON")?;
            println!("Circuit: example (a + b = sum)");
            println!();
            println!("Private witnesses:");
            println!("  a   = {}", w.a);
            println!("  b   = {}", w.b);
            println!();
            println!("Public inputs:");
            println!("  sum = {}", w.sum);
        }
        "tx_privacy" => {
            let w: TxPrivacyWitness = serde_json::from_str(&content)
                .context("Failed to parse tx_privacy witness JSON")?;

            let balance_old: u64 = w.balance_old.parse().context("Invalid balance_old")?;
            let balance_new: u64 = w.balance_new.parse().context("Invalid balance_new")?;
            let randomness_old = parse_field(&w.randomness_old)?;
            let randomness_new = parse_field(&w.randomness_new)?;
            let amount: u64 = w.amount.parse().context("Invalid amount")?;

            println!("Circuit: tx_privacy");
            println!();
            println!("Private witnesses:");
            println!("  balance_old    = {} ({})", w.balance_old, balance_old);
            println!("  balance_new    = {} ({})", w.balance_new, balance_new);
            println!("  randomness_old = {}", w.randomness_old);
            println!("  randomness_new = {}", w.randomness_new);
            println!("  amount         = {} ({})", w.amount, amount);
            println!("  merkle_siblings: {} entries", w.merkle_siblings.len());
            println!();

            if w.merkle_siblings.len() == MERKLE_DEPTH {
                let merkle_siblings: Result<Vec<Fp>> =
                    w.merkle_siblings.iter().map(|s| parse_field(s)).collect();
                if let Ok(siblings) = merkle_siblings {
                    let commitment_old =
                        TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
                    let commitment_new =
                        TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
                    let merkle_root =
                        TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings);

                    println!("Derived public inputs:");
                    println!("  commitment_old = {:?}", commitment_old);
                    println!("  commitment_new = {:?}", commitment_new);
                    println!("  merkle_root    = {:?}", merkle_root);
                }
            }

            println!();
            println!("Validation:");
            println!(
                "  balance_old - amount = {} (expected balance_new = {})",
                balance_old.saturating_sub(amount),
                balance_new
            );
            if balance_old >= amount && balance_old - amount == balance_new {
                println!("  Balance check: PASS");
            } else {
                println!("  Balance check: FAIL");
            }
        }
        "state_mask" => {
            let w: StateMaskWitness = serde_json::from_str(&content)
                .context("Failed to parse state_mask witness JSON")?;

            let state_value: u64 = w.state_value.parse().context("Invalid state_value")?;
            let nonce = parse_field(&w.nonce)?;
            let range_min: u64 = w.range_min.parse().context("Invalid range_min")?;
            let range_max: u64 = w.range_max.parse().context("Invalid range_max")?;

            println!("Circuit: state_mask");
            println!();
            println!("Private witnesses:");
            println!("  state_value = {}", state_value);
            println!("  nonce       = {}", w.nonce);
            println!("  range_min   = {}", range_min);
            println!("  range_max   = {}", range_max);
            println!();

            let commitment = StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce);
            println!("Derived public inputs:");
            println!("  commitment = {:?}", commitment);
            println!();

            println!("Validation:");
            if state_value >= range_min && state_value <= range_max {
                println!("  value in [{}, {}]: PASS ({})", range_min, range_max, state_value);
            } else {
                println!("  value in [{}, {}]: FAIL (got {})", range_min, range_max, state_value);
            }
        }
        "private_vote" => {
            let w: PrivateVoteWitness = serde_json::from_str(&content)
                .context("Failed to parse private_vote witness JSON")?;

            let balance: u64 = w.balance.parse().context("Invalid balance")?;
            let randomness_balance = parse_field(&w.randomness_balance)?;
            let vote: u64 = w.vote.parse().context("Invalid vote")?;
            let randomness_vote = parse_field(&w.randomness_vote)?;
            let threshold: u64 = w.threshold.parse().context("Invalid threshold")?;

            println!("Circuit: private_vote");
            println!();
            println!("Private witnesses:");
            println!("  balance            = {}", balance);
            println!("  randomness_balance = {}", w.randomness_balance);
            println!("  vote               = {}", vote);
            println!("  randomness_vote    = {}", w.randomness_vote);
            println!("  threshold          = {}", threshold);
            println!();

            let balance_commitment =
                PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance);
            let vote_commitment =
                PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote);
            println!("Derived public inputs:");
            println!("  balance_commitment = {:?}", balance_commitment);
            println!("  threshold          = {}", threshold);
            println!("  vote_commitment    = {:?}", vote_commitment);
            println!();

            println!("Validation:");
            if vote <= 1 {
                println!("  vote is boolean: PASS ({})", vote);
            } else {
                println!("  vote is boolean: FAIL (got {})", vote);
            }
            if balance >= threshold {
                println!("  balance >= threshold: PASS ({} >= {})", balance, threshold);
            } else {
                println!("  balance >= threshold: FAIL ({} < {})", balance, threshold);
            }
        }
        _ => {
            anyhow::bail!(
                "Unknown circuit: {}. Available: example, tx_privacy, state_mask, private_vote",
                circuit_name
            );
        }
    }

    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { circuit, k } => {
            let k = k.unwrap_or_else(|| default_k(&circuit));
            println!("ZeroStyl Circuit Inspector");
            println!();
            run_inspect(&circuit, k)?;
        }
        Commands::Debug { circuit, witnesses, k, format } => {
            let k = k.unwrap_or_else(|| default_k(&circuit));
            println!("ZeroStyl Circuit Debugger");
            println!();
            run_debug(&circuit, &witnesses, k, &format)?;
        }
        Commands::Witness { circuit, witnesses } => {
            println!("ZeroStyl Witness Viewer");
            println!();
            run_witness(&circuit, &witnesses)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ─── Inspect tests ──────────────────────────────────────────────────

    #[test]
    fn test_inspect_example() {
        run_inspect("example", 4).unwrap();
    }

    #[test]
    fn test_inspect_tx_privacy() {
        run_inspect("tx_privacy", 14).unwrap();
    }

    #[test]
    fn test_inspect_state_mask() {
        run_inspect("state_mask", 10).unwrap();
    }

    #[test]
    fn test_inspect_private_vote() {
        run_inspect("private_vote", 11).unwrap();
    }

    #[test]
    fn test_inspect_unknown_circuit() {
        let result = run_inspect("nonexistent", 4);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Unknown circuit"));
    }

    // ─── Debug tests ────────────────────────────────────────────────────

    #[test]
    fn test_debug_example_satisfied() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"a": "2", "b": "3", "sum": "5"}}"#).unwrap();
        run_debug("example", &file.path().to_path_buf(), 4, "text").unwrap();
    }

    #[test]
    fn test_debug_example_violated() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"a": "2", "b": "3", "sum": "99"}}"#).unwrap();
        // Should succeed (returns report with failures, doesn't error)
        run_debug("example", &file.path().to_path_buf(), 4, "text").unwrap();
    }

    #[test]
    fn test_debug_example_json_format() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"a": "2", "b": "3", "sum": "5"}}"#).unwrap();
        run_debug("example", &file.path().to_path_buf(), 4, "json").unwrap();
    }

    #[test]
    fn test_debug_unknown_circuit() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{}}"#).unwrap();
        let result = run_debug("nonexistent", &file.path().to_path_buf(), 4, "text");
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_missing_witnesses_file() {
        let result = run_debug("example", &PathBuf::from("/nonexistent.json"), 4, "text");
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not valid json").unwrap();
        let result = run_debug("example", &file.path().to_path_buf(), 4, "text");
        assert!(result.is_err());
    }

    // ─── Witness display tests ──────────────────────────────────────────

    #[test]
    fn test_witness_example() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"a": "10", "b": "20", "sum": "30"}}"#).unwrap();
        run_witness("example", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_state_mask() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"state_value": "42", "nonce": "123", "range_min": "0", "range_max": "255"}"#;
        writeln!(file, "{}", json).unwrap();
        run_witness("state_mask", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_private_vote() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"balance": "100", "randomness_balance": "42", "vote": "1", "randomness_vote": "84", "threshold": "50"}"#;
        writeln!(file, "{}", json).unwrap();
        run_witness("private_vote", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_unknown_circuit() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{}}"#).unwrap();
        let result = run_witness("nonexistent", &file.path().to_path_buf());
        assert!(result.is_err());
    }

    // ─── Parse field tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_field_decimal() {
        let fp = parse_field("42").unwrap();
        assert_eq!(fp, Fp::from(42u64));
    }

    #[test]
    fn test_parse_field_zero() {
        let fp = parse_field("0").unwrap();
        assert_eq!(fp, Fp::from(0u64));
    }

    #[test]
    fn test_parse_field_invalid() {
        assert!(parse_field("not_a_number").is_err());
    }

    #[test]
    fn test_parse_field_hex() {
        // 42 in hex is 0x2a
        let fp = parse_field("0x2a").unwrap();
        assert_eq!(fp, Fp::from(42u64));
    }

    #[test]
    fn test_parse_field_hex_zero() {
        let fp = parse_field("0x00").unwrap();
        assert_eq!(fp, Fp::from(0u64));
    }

    #[test]
    fn test_parse_field_large_decimal() {
        let fp = parse_field("18446744073709551615").unwrap(); // u64::MAX
        assert_eq!(fp, Fp::from(u64::MAX));
    }

    #[test]
    fn test_parse_field_empty_hex() {
        // "0x" with no hex digits parses as zero
        let fp = parse_field("0x").unwrap();
        assert_eq!(fp, Fp::from(0u64));
    }

    #[test]
    fn test_parse_field_invalid_hex() {
        // Invalid hex characters
        assert!(parse_field("0xZZZZ").is_err());
    }

    // ─── Witness display: tx_privacy ────────────────────────────────────

    #[test]
    fn test_witness_tx_privacy() {
        let mut file = NamedTempFile::new().unwrap();
        let siblings: Vec<String> = (0..32).map(|i| format!("{}", i + 100)).collect();
        let json = serde_json::json!({
            "balance_old": "1000",
            "balance_new": "700",
            "randomness_old": "42",
            "randomness_new": "84",
            "amount": "300",
            "merkle_siblings": siblings,
        });
        writeln!(file, "{}", json).unwrap();
        run_witness("tx_privacy", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_tx_privacy_wrong_balance() {
        let mut file = NamedTempFile::new().unwrap();
        let siblings: Vec<String> = (0..32).map(|i| format!("{}", i + 100)).collect();
        // balance_old - amount != balance_new
        let json = serde_json::json!({
            "balance_old": "1000",
            "balance_new": "500",
            "randomness_old": "42",
            "randomness_new": "84",
            "amount": "300",
            "merkle_siblings": siblings,
        });
        writeln!(file, "{}", json).unwrap();
        // Should still display without error (validation is informational)
        run_witness("tx_privacy", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_state_mask_failing_validation() {
        let mut file = NamedTempFile::new().unwrap();
        // state_value outside range → should show FAIL
        let json = r#"{"state_value": "300", "nonce": "1", "range_min": "0", "range_max": "255"}"#;
        writeln!(file, "{}", json).unwrap();
        run_witness("state_mask", &file.path().to_path_buf()).unwrap();
    }

    // ─── Default k tests ────────────────────────────────────────────────

    #[test]
    fn test_default_k_values() {
        assert_eq!(default_k("example"), 4);
        assert_eq!(default_k("tx_privacy"), 14);
        assert_eq!(default_k("state_mask"), 10);
        assert_eq!(default_k("private_vote"), 11);
        assert_eq!(default_k("unknown"), 10);
    }
}
