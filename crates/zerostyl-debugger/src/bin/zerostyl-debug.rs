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
use zerostyl_debugger::{debug_circuit, inspect_circuit, DebugReport};

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

    /// Show the expected witness JSON format for a circuit
    Schema {
        /// Circuit name (example, tx_privacy, state_mask, private_vote)
        #[arg(short, long)]
        circuit: String,
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

#[derive(Debug, Deserialize, Default)]
struct StateMaskDebugOverrides {
    commitment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StateMaskWitness {
    state_value: String,
    nonce: String,
    range_min: String,
    range_max: String,
    #[serde(rename = "_debug", default)]
    debug: StateMaskDebugOverrides,
}

#[derive(Debug, Deserialize, Default)]
struct TxPrivacyDebugOverrides {
    commitment_old: Option<String>,
    commitment_new: Option<String>,
    merkle_root: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TxPrivacyWitness {
    balance_old: String,
    balance_new: String,
    randomness_old: String,
    randomness_new: String,
    amount: String,
    merkle_siblings: Vec<String>,
    #[serde(rename = "_debug", default)]
    debug: TxPrivacyDebugOverrides,
}

#[derive(Debug, Deserialize, Default)]
struct PrivateVoteDebugOverrides {
    balance_commitment: Option<String>,
    vote_commitment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrivateVoteWitness {
    balance: String,
    randomness_balance: String,
    vote: String,
    randomness_vote: String,
    threshold: String,
    #[serde(rename = "_debug", default)]
    debug: PrivateVoteDebugOverrides,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

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

fn parse_witness_json<T: serde::de::DeserializeOwned>(
    content: &str,
    circuit_name: &str,
) -> Result<T> {
    serde_json::from_str(content).map_err(|e| {
        anyhow::anyhow!(
            "Invalid witness JSON for '{}': {}\n\nRun `zerostyl-debug schema --circuit {}` to see the expected format.",
            circuit_name,
            e,
            circuit_name
        )
    })
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

/// Return a circuit-specific hint for a gate failure, if one is known.
fn circuit_hint(circuit_name: &str, gate_name: &str) -> Option<&'static str> {
    match (circuit_name, gate_name) {
        (_, "commitment") => Some(
            "value + randomness must equal the commitment. \
             If using _debug.commitment, ensure the override matches what you want to test.",
        ),
        ("state_mask" | "private_vote", "bit_check") => {
            Some("each bit in the range proof must be 0 or 1 (boolean constraint)")
        }
        ("state_mask" | "private_vote", "bit_decompose") => Some(
            "the bit decomposition accumulation is inconsistent — \
             verify bits correctly encode (value - range_min)",
        ),
        ("tx_privacy", "balance_check") => Some(
            "balance_old - amount must equal balance_new — \
             check your transfer amounts are consistent",
        ),
        ("tx_privacy", "merkle") => Some(
            "the Merkle path accumulation failed — \
             verify the sibling values match the expected tree",
        ),
        ("private_vote", "vote_boolean") => {
            Some("vote must be 0 (NO) or 1 (YES) — received a non-boolean value")
        }
        ("private_vote", "vote_commit") => {
            Some("vote + randomness_vote must equal the vote_commitment")
        }
        ("example", "add") => Some("a + b must equal sum"),
        _ => None,
    }
}

/// Enrich a debug report with circuit-specific hints for each failure.
fn enrich_hints(report: &mut DebugReport, circuit_name: &str) {
    for failure in &mut report.failures {
        if let Some(hint) = circuit_hint(circuit_name, &failure.gate_name) {
            failure.hint = format!("{} → {}", failure.hint, hint);
        }
    }
}

// ─── Schema command ──────────────────────────────────────────────────────────

fn run_schema(circuit_name: &str) -> Result<()> {
    match circuit_name {
        "example" => {
            println!("Circuit: example (a + b = sum)");
            println!();
            println!("JSON fields:");
            println!("  a    string  required  First operand (u64 decimal or 0x hex)");
            println!("  b    string  required  Second operand (u64 decimal or 0x hex)");
            println!("  sum  string  required  Expected sum — used as public input");
            println!();
            println!("Public inputs: [sum]");
            println!();
            println!("Gates:");
            println!("  add — s * (a + b - sum) == 0");
            println!();
            println!("Example:");
            println!(r#"  {{"a": "2", "b": "3", "sum": "5"}}"#);
        }
        "state_mask" => {
            println!("Circuit: state_mask (Range Proof)");
            println!();
            println!("JSON fields:");
            println!(
                "  state_value  string  required  Secret value to prove is in [range_min, range_max] (u64)"
            );
            println!(
                "  nonce        string  required  Commitment randomness (u64 decimal or 0x hex)"
            );
            println!("  range_min    string  required  Range lower bound, inclusive (u64)");
            println!("  range_max    string  required  Range upper bound, inclusive (u64, max span = 255)");
            println!();
            println!("Optional _debug overrides:");
            println!(
                "  _debug.commitment  string  Override the commitment cell to force a gate failure"
            );
            println!("                             The same value is used as the public input.");
            println!();
            println!("Public inputs derived: [commitment = state_value + nonce]");
            println!();
            println!("Gates:");
            println!("  commitment    — state_value + nonce == commitment");
            println!("  bit_check     — each bit is boolean: bit * (bit - 1) == 0");
            println!("  bit_decompose — accumulation: acc + bit * 2^i == acc_next");
            println!();
            println!("Examples:");
            println!(
                r#"  Valid:   {{"state_value": "42", "nonce": "123", "range_min": "0", "range_max": "255"}}"#
            );
            println!(
                r#"  Broken:  add {{"_debug": {{"commitment": "999"}}}} → commitment gate fails"#
            );
        }
        "tx_privacy" => {
            println!("Circuit: tx_privacy (Private Transfer)");
            println!();
            println!("JSON fields:");
            println!("  balance_old      string    required  Sender balance before transfer (u64)");
            println!("  balance_new      string    required  Sender balance after transfer (u64)");
            println!(
                "  randomness_old   string    required  Commitment randomness for old balance"
            );
            println!(
                "  randomness_new   string    required  Commitment randomness for new balance"
            );
            println!("  amount           string    required  Transfer amount (u64)");
            println!(
                "  merkle_siblings  string[]  required  Merkle path siblings (exactly {} values)",
                MERKLE_DEPTH
            );
            println!();
            println!("Optional _debug overrides:");
            println!("  _debug.commitment_old  string  Override commitment_old cell");
            println!("  _debug.commitment_new  string  Override commitment_new cell");
            println!("  _debug.merkle_root     string  Override merkle_root public input");
            println!();
            println!("Public inputs derived: [commitment_old, commitment_new, merkle_root]");
            println!();
            println!("Gates:");
            println!("  commitment    — balance + randomness == commitment");
            println!("  balance_check — balance_old - amount == balance_new");
            println!(
                "  merkle        — current + sibling == next (repeated {} times)",
                MERKLE_DEPTH
            );
            println!();
            println!("Note: inconsistent balance_old/amount/balance_new (without _debug)");
            println!("      triggers the 'balance_check' gate failure automatically.");
        }
        "private_vote" => {
            println!("Circuit: private_vote (Anonymous Voting)");
            println!();
            println!("JSON fields:");
            println!("  balance            string  required  Voter token balance (u64)");
            println!("  randomness_balance string  required  Commitment randomness for balance");
            println!(
                "  vote               string  required  Vote value: 0 (NO) or 1 (YES); use 2 to test vote_boolean gate"
            );
            println!("  randomness_vote    string  required  Commitment randomness for vote");
            println!(
                "  threshold          string  required  Minimum balance required to vote (u64)"
            );
            println!();
            println!("Optional _debug overrides:");
            println!("  _debug.balance_commitment  string  Override balance commitment cell");
            println!("  _debug.vote_commitment     string  Override vote commitment cell");
            println!();
            println!("Public inputs derived: [balance_commitment, threshold, vote_commitment]");
            println!();
            println!("Gates:");
            println!("  commitment    — balance + randomness_balance == balance_commitment");
            println!("  vote_boolean  — vote * (vote - 1) == 0");
            println!("  vote_commit   — vote + randomness_vote == vote_commitment");
            println!("  bit_check     — each eligibility bit is boolean");
            println!("  bit_decompose — bit decomposition of (balance - threshold)");
            println!();
            println!(
                "Note: vote=2 triggers 'vote_boolean' gate failure without any _debug override."
            );
        }
        _ => {
            anyhow::bail!(
                "Unknown circuit: '{}'. Available: example, tx_privacy, state_mask, private_vote",
                circuit_name
            );
        }
    }
    Ok(())
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
                "Unknown circuit: '{}'. Available: example, tx_privacy, state_mask, private_vote",
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

    let mut report = match circuit_name {
        "example" => {
            let w: ExampleWitness = parse_witness_json(&content, "example")?;
            let a = parse_field(&w.a).context("field 'a'")?;
            let b = parse_field(&w.b).context("field 'b'")?;
            let sum = parse_field(&w.sum).context("field 'sum'")?;
            let circuit = ExampleCircuit { a: Value::known(a), b: Value::known(b) };
            debug_circuit(&circuit, vec![vec![sum]], k, circuit_name)?
        }
        "state_mask" => {
            let w: StateMaskWitness = parse_witness_json(&content, "state_mask")?;
            let state_value: u64 =
                w.state_value.parse().context("field 'state_value': expected u64")?;
            let nonce = parse_field(&w.nonce).context("field 'nonce'")?;
            let range_min: u64 = w.range_min.parse().context("field 'range_min': expected u64")?;
            let range_max: u64 = w.range_max.parse().context("field 'range_max': expected u64")?;

            let commitment_override = w
                .debug
                .commitment
                .as_deref()
                .map(parse_field)
                .transpose()
                .context("field '_debug.commitment'")?;

            let circuit = StateMaskCircuit::from_raw(
                state_value,
                nonce,
                range_min,
                range_max,
                commitment_override,
            );
            let commitment = commitment_override.unwrap_or_else(|| {
                StateMaskCircuit::compute_commitment(Fp::from(state_value), nonce)
            });
            debug_circuit(&circuit, vec![vec![commitment]], k, circuit_name)?
        }
        "tx_privacy" => {
            let w: TxPrivacyWitness = parse_witness_json(&content, "tx_privacy")?;
            let balance_old: u64 =
                w.balance_old.parse().context("field 'balance_old': expected u64")?;
            let balance_new: u64 =
                w.balance_new.parse().context("field 'balance_new': expected u64")?;
            let randomness_old =
                parse_field(&w.randomness_old).context("field 'randomness_old'")?;
            let randomness_new =
                parse_field(&w.randomness_new).context("field 'randomness_new'")?;
            let amount: u64 = w.amount.parse().context("field 'amount': expected u64")?;

            if w.merkle_siblings.len() != MERKLE_DEPTH {
                anyhow::bail!(
                    "Expected {} Merkle siblings, got {}",
                    MERKLE_DEPTH,
                    w.merkle_siblings.len()
                );
            }
            let merkle_siblings: Result<Vec<Fp>> =
                w.merkle_siblings.iter().map(|s| parse_field(s)).collect();
            let merkle_siblings = merkle_siblings.context("field 'merkle_siblings'")?;

            let commitment_old_override = w
                .debug
                .commitment_old
                .as_deref()
                .map(parse_field)
                .transpose()
                .context("field '_debug.commitment_old'")?;
            let commitment_new_override = w
                .debug
                .commitment_new
                .as_deref()
                .map(parse_field)
                .transpose()
                .context("field '_debug.commitment_new'")?;
            let merkle_root_override = w
                .debug
                .merkle_root
                .as_deref()
                .map(parse_field)
                .transpose()
                .context("field '_debug.merkle_root'")?;

            let circuit = TxPrivacyCircuit::from_raw(
                balance_old,
                balance_new,
                randomness_old,
                randomness_new,
                amount,
                merkle_siblings.clone(),
                commitment_old_override,
                commitment_new_override,
            );
            let commitment_old = commitment_old_override.unwrap_or_else(|| {
                TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old)
            });
            let commitment_new = commitment_new_override.unwrap_or_else(|| {
                TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new)
            });
            let merkle_root = merkle_root_override.unwrap_or_else(|| {
                TxPrivacyCircuit::compute_merkle_root(commitment_old, &merkle_siblings)
            });
            debug_circuit(
                &circuit,
                vec![vec![commitment_old, commitment_new, merkle_root]],
                k,
                circuit_name,
            )?
        }
        "private_vote" => {
            let w: PrivateVoteWitness = parse_witness_json(&content, "private_vote")?;
            let balance: u64 = w.balance.parse().context("field 'balance': expected u64")?;
            let randomness_balance =
                parse_field(&w.randomness_balance).context("field 'randomness_balance'")?;
            let vote: u64 = w.vote.parse().context("field 'vote': expected u64")?;
            let randomness_vote =
                parse_field(&w.randomness_vote).context("field 'randomness_vote'")?;
            let threshold: u64 = w.threshold.parse().context("field 'threshold': expected u64")?;

            let balance_commitment_override = w
                .debug
                .balance_commitment
                .as_deref()
                .map(parse_field)
                .transpose()
                .context("field '_debug.balance_commitment'")?;
            let vote_commitment_override = w
                .debug
                .vote_commitment
                .as_deref()
                .map(parse_field)
                .transpose()
                .context("field '_debug.vote_commitment'")?;

            let circuit = PrivateVoteCircuit::from_raw(
                balance,
                randomness_balance,
                vote,
                randomness_vote,
                threshold,
                balance_commitment_override,
                vote_commitment_override,
            );
            let balance_commitment = balance_commitment_override.unwrap_or_else(|| {
                PrivateVoteCircuit::compute_commitment(Fp::from(balance), randomness_balance)
            });
            let vote_commitment = vote_commitment_override.unwrap_or_else(|| {
                PrivateVoteCircuit::compute_commitment(Fp::from(vote), randomness_vote)
            });
            debug_circuit(
                &circuit,
                vec![vec![balance_commitment, Fp::from(threshold), vote_commitment]],
                k,
                circuit_name,
            )?
        }
        _ => {
            anyhow::bail!(
                "Unknown circuit: '{}'. Available: example, tx_privacy, state_mask, private_vote",
                circuit_name
            );
        }
    };

    enrich_hints(&mut report, circuit_name);

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&report)
                .context("Failed to serialize debug report")?;
            println!("{}", json);
        }
        _ => println!("{}", report),
    }

    Ok(())
}

// ─── Witness command ────────────────────────────────────────────────────────

fn run_witness(circuit_name: &str, witnesses_path: &PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(witnesses_path)
        .context(format!("Failed to read witnesses file: {:?}", witnesses_path))?;

    match circuit_name {
        "example" => {
            let w: ExampleWitness = parse_witness_json(&content, "example")?;
            println!("Circuit: example (a + b = sum)");
            println!();
            println!("Private witnesses:");
            println!("  a   = {}", w.a);
            println!("  b   = {}", w.b);
            println!();
            println!("Public inputs:");
            println!("  sum = {}", w.sum);
        }
        "state_mask" => {
            let w: StateMaskWitness = parse_witness_json(&content, "state_mask")?;
            let state_value: u64 =
                w.state_value.parse().context("field 'state_value': expected u64")?;
            let nonce = parse_field(&w.nonce).context("field 'nonce'")?;
            let range_min: u64 = w.range_min.parse().context("field 'range_min': expected u64")?;
            let range_max: u64 = w.range_max.parse().context("field 'range_max': expected u64")?;

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
                println!(
                    "  value in [{}, {}]: FAIL (got {}) — use `debug` to find the failing constraint",
                    range_min, range_max, state_value
                );
            }
        }
        "tx_privacy" => {
            let w: TxPrivacyWitness = parse_witness_json(&content, "tx_privacy")?;
            let balance_old: u64 =
                w.balance_old.parse().context("field 'balance_old': expected u64")?;
            let balance_new: u64 =
                w.balance_new.parse().context("field 'balance_new': expected u64")?;
            let randomness_old =
                parse_field(&w.randomness_old).context("field 'randomness_old'")?;
            let randomness_new =
                parse_field(&w.randomness_new).context("field 'randomness_new'")?;
            let amount: u64 = w.amount.parse().context("field 'amount': expected u64")?;

            println!("Circuit: tx_privacy");
            println!();
            println!("Private witnesses:");
            println!("  balance_old    = {}", balance_old);
            println!("  balance_new    = {}", balance_new);
            println!("  randomness_old = {}", w.randomness_old);
            println!("  randomness_new = {}", w.randomness_new);
            println!("  amount         = {}", amount);
            println!("  merkle_siblings: {} entries", w.merkle_siblings.len());
            println!();

            if w.merkle_siblings.len() == MERKLE_DEPTH {
                let siblings: Result<Vec<Fp>> =
                    w.merkle_siblings.iter().map(|s| parse_field(s)).collect();
                if let Ok(siblings) = siblings {
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
            if balance_old >= amount && balance_old - amount == balance_new {
                println!("  balance check: PASS ({} - {} = {})", balance_old, amount, balance_new);
            } else {
                println!(
                    "  balance check: FAIL ({} - {} ≠ {}) — use `debug` to surface balance_check gate",
                    balance_old, amount, balance_new
                );
            }
        }
        "private_vote" => {
            let w: PrivateVoteWitness = parse_witness_json(&content, "private_vote")?;
            let balance: u64 = w.balance.parse().context("field 'balance': expected u64")?;
            let randomness_balance =
                parse_field(&w.randomness_balance).context("field 'randomness_balance'")?;
            let vote: u64 = w.vote.parse().context("field 'vote': expected u64")?;
            let randomness_vote =
                parse_field(&w.randomness_vote).context("field 'randomness_vote'")?;
            let threshold: u64 = w.threshold.parse().context("field 'threshold': expected u64")?;

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
                println!(
                    "  vote is boolean: FAIL (got {}) — use `debug` to surface vote_boolean gate",
                    vote
                );
            }
            if balance >= threshold {
                println!("  balance >= threshold: PASS ({} >= {})", balance, threshold);
            } else {
                println!("  balance >= threshold: FAIL ({} < {})", balance, threshold);
            }
        }
        _ => {
            anyhow::bail!(
                "Unknown circuit: '{}'. Available: example, tx_privacy, state_mask, private_vote",
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
        Commands::Schema { circuit } => {
            run_schema(&circuit)?;
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
        assert!(format!("{}", result.unwrap_err()).contains("Unknown circuit"));
    }

    // ─── Schema tests ───────────────────────────────────────────────────

    #[test]
    fn test_schema_example() {
        run_schema("example").unwrap();
    }

    #[test]
    fn test_schema_state_mask() {
        run_schema("state_mask").unwrap();
    }

    #[test]
    fn test_schema_tx_privacy() {
        run_schema("tx_privacy").unwrap();
    }

    #[test]
    fn test_schema_private_vote() {
        run_schema("private_vote").unwrap();
    }

    #[test]
    fn test_schema_unknown() {
        let result = run_schema("nonexistent");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Unknown circuit"));
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
        run_debug("example", &file.path().to_path_buf(), 4, "text").unwrap();
    }

    #[test]
    fn test_debug_example_json_format() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"a": "2", "b": "3", "sum": "5"}}"#).unwrap();
        run_debug("example", &file.path().to_path_buf(), 4, "json").unwrap();
    }

    #[test]
    fn test_debug_state_mask_satisfied() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{"state_value": "42", "nonce": "123", "range_min": "0", "range_max": "255"}}"#
        )
        .unwrap();
        run_debug("state_mask", &file.path().to_path_buf(), 10, "text").unwrap();
    }

    #[test]
    fn test_debug_state_mask_wrong_commitment() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"state_value": "42", "nonce": "123", "range_min": "0", "range_max": "255", "_debug": {"commitment": "999"}}"#;
        writeln!(file, "{}", json).unwrap();
        run_debug("state_mask", &file.path().to_path_buf(), 10, "text").unwrap();
    }

    #[test]
    fn test_debug_state_mask_out_of_range_value() {
        // from_raw() accepts value=300, no panic — MockProver runs
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{"state_value": "300", "nonce": "1", "range_min": "0", "range_max": "255"}}"#
        )
        .unwrap();
        run_debug("state_mask", &file.path().to_path_buf(), 10, "text").unwrap();
    }

    #[test]
    fn test_debug_private_vote_satisfied() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"balance": "100", "randomness_balance": "42", "vote": "1", "randomness_vote": "84", "threshold": "50"}"#;
        writeln!(file, "{}", json).unwrap();
        run_debug("private_vote", &file.path().to_path_buf(), 11, "text").unwrap();
    }

    #[test]
    fn test_debug_private_vote_wrong_vote() {
        // vote=2 → vote_boolean gate fails
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"balance": "100", "randomness_balance": "42", "vote": "2", "randomness_vote": "84", "threshold": "50"}"#;
        writeln!(file, "{}", json).unwrap();
        run_debug("private_vote", &file.path().to_path_buf(), 11, "text").unwrap();
    }

    #[test]
    fn test_debug_tx_privacy_wrong_balance() {
        // balance_old - amount ≠ balance_new → balance_check gate fails
        let mut file = NamedTempFile::new().unwrap();
        let siblings: Vec<String> = (0..32).map(|i| format!("{}", i + 100)).collect();
        let json = serde_json::json!({
            "balance_old": "1000",
            "balance_new": "800",
            "randomness_old": "42",
            "randomness_new": "84",
            "amount": "300",
            "merkle_siblings": siblings,
        });
        writeln!(file, "{}", json).unwrap();
        run_debug("tx_privacy", &file.path().to_path_buf(), 14, "text").unwrap();
    }

    #[test]
    fn test_debug_unknown_circuit() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{}}"#).unwrap();
        let result = run_debug("nonexistent", &file.path().to_path_buf(), 4, "text");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Unknown circuit"));
    }

    #[test]
    fn test_debug_missing_witnesses_file() {
        let result = run_debug("example", &PathBuf::from("/nonexistent.json"), 4, "text");
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_invalid_json_shows_schema_tip() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not valid json").unwrap();
        let result = run_debug("state_mask", &file.path().to_path_buf(), 10, "text");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("zerostyl-debug schema"), "Error should suggest running schema");
    }

    // ─── Witness display tests ──────────────────────────────────────────

    #[test]
    fn test_witness_example() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"a": "10", "b": "20", "sum": "30"}}"#).unwrap();
        run_witness("example", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_state_mask_valid() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"state_value": "42", "nonce": "123", "range_min": "0", "range_max": "255"}"#;
        writeln!(file, "{}", json).unwrap();
        run_witness("state_mask", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_state_mask_out_of_range() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"state_value": "300", "nonce": "1", "range_min": "0", "range_max": "255"}"#;
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
    fn test_witness_private_vote_wrong_vote() {
        let mut file = NamedTempFile::new().unwrap();
        let json = r#"{"balance": "100", "randomness_balance": "42", "vote": "2", "randomness_vote": "84", "threshold": "50"}"#;
        writeln!(file, "{}", json).unwrap();
        run_witness("private_vote", &file.path().to_path_buf()).unwrap();
    }

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
        let json = serde_json::json!({
            "balance_old": "1000",
            "balance_new": "500",
            "randomness_old": "42",
            "randomness_new": "84",
            "amount": "300",
            "merkle_siblings": siblings,
        });
        writeln!(file, "{}", json).unwrap();
        run_witness("tx_privacy", &file.path().to_path_buf()).unwrap();
    }

    #[test]
    fn test_witness_unknown_circuit() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{}}"#).unwrap();
        let result = run_witness("nonexistent", &file.path().to_path_buf());
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Unknown circuit"));
    }

    // ─── parse_field tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_field_decimal() {
        assert_eq!(parse_field("42").unwrap(), Fp::from(42u64));
    }

    #[test]
    fn test_parse_field_zero() {
        assert_eq!(parse_field("0").unwrap(), Fp::from(0u64));
    }

    #[test]
    fn test_parse_field_invalid() {
        assert!(parse_field("not_a_number").is_err());
    }

    #[test]
    fn test_parse_field_hex() {
        assert_eq!(parse_field("0x2a").unwrap(), Fp::from(42u64));
    }

    #[test]
    fn test_parse_field_hex_zero() {
        assert_eq!(parse_field("0x00").unwrap(), Fp::from(0u64));
    }

    #[test]
    fn test_parse_field_large_decimal() {
        assert_eq!(parse_field("18446744073709551615").unwrap(), Fp::from(u64::MAX));
    }

    #[test]
    fn test_parse_field_empty_hex() {
        assert_eq!(parse_field("0x").unwrap(), Fp::from(0u64));
    }

    #[test]
    fn test_parse_field_invalid_hex() {
        assert!(parse_field("0xZZZZ").is_err());
    }

    // ─── default_k tests ────────────────────────────────────────────────

    #[test]
    fn test_default_k_values() {
        assert_eq!(default_k("example"), 4);
        assert_eq!(default_k("tx_privacy"), 14);
        assert_eq!(default_k("state_mask"), 10);
        assert_eq!(default_k("private_vote"), 11);
        assert_eq!(default_k("unknown"), 10);
    }

    // ─── circuit_hint tests ─────────────────────────────────────────────

    #[test]
    fn test_circuit_hint_known_gates() {
        assert!(circuit_hint("state_mask", "commitment").is_some());
        assert!(circuit_hint("tx_privacy", "balance_check").is_some());
        assert!(circuit_hint("private_vote", "vote_boolean").is_some());
        assert!(circuit_hint("state_mask", "bit_check").is_some());
        assert!(circuit_hint("private_vote", "vote_commit").is_some());
    }

    #[test]
    fn test_circuit_hint_unknown_gate() {
        assert!(circuit_hint("state_mask", "nonexistent_gate").is_none());
        assert!(circuit_hint("unknown_circuit", "commitment").is_some()); // wildcard match
    }
}
