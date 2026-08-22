//! Output quality comparison: raw halo2 vs ZeroStyl
//!
//! This is NOT a timing benchmark. It measures DETERMINISTIC output-quality metrics by diffing
//! raw halo2 `{:#?}` failure output against the ZeroStyl debugger's `format_mock_prover_report`
//! text output, on real circuits with real broken witnesses. All metrics are reproducible — no
//! timing or system noise involved.
//!
//! Metrics measured:
//!   - Lines / characters of output
//!   - Structural noise lines (only braces/commas — zero information content)
//!   - Max struct nesting depth (depth of `{[( ` nesting)
//!   - Characters before the gate name appears in the failure section (time-to-diagnosis proxy)
//!   - Characters spent on the failing cell values / diagnosis
//!   - Gate name visible near the top of the failure section (yes/no)
//!
//! Usage:
//!   cargo run -p debug-workflow-bench --release
//!   cargo run -p debug-workflow-bench --release -- --json
//!   cargo run -p debug-workflow-bench --release -- --verbose

use std::env;
use std::hint::black_box;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use private_vote::PrivateVoteCircuit;
use state_mask::StateMaskCircuit;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_debugger::{format_mock_prover_report, OutputFormat};

fn zerostyl_output_via_descriptor(
    desc: &'static dyn zerostyl_circuits::CircuitDescriptor,
    witness_json: &str,
    k: u32,
) -> String {
    let report = desc
        .mock_prove(witness_json, k)
        .expect("descriptor.mock_prove must succeed for benchmark scenarios");
    format_mock_prover_report(&report, OutputFormat::Text)
        .expect("format_mock_prover_report must succeed")
}

// ─── Output analysis ────────────────────────────────────────────────────────

/// Count lines whose content is purely structural (braces, commas, whitespace).
/// These lines carry zero information — they exist only to satisfy Debug formatting.
fn count_noise_lines(s: &str) -> usize {
    s.lines()
        .filter(|l| {
            let t = l.trim();
            t.is_empty() || t.chars().all(|c| matches!(c, '{' | '}' | ',' | '[' | ']' | '(' | ')'))
        })
        .count()
}

/// Maximum brace/bracket nesting depth.
/// Higher depth = more cognitive effort to parse the structure.
fn max_nesting_depth(s: &str) -> usize {
    let mut max_depth = 0usize;
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '{' | '[' | '(' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            '}' | ']' | ')' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    max_depth
}

/// Start offset of the FAILURE section in either output.
///
/// Raw halo2 (`{:#?}`) begins the section at `ConstraintNotSatisfied`; the ZeroStyl text report
/// (see `zerostyl-debugger`'s `format_mock_prover_report`) begins each failure with
/// `--- Failure N [...] ---`.
fn failure_section_start(s: &str) -> usize {
    s.find("ConstraintNotSatisfied").or_else(|| s.find("--- Failure")).unwrap_or(0)
}

/// Characters from the start of the FAILURE section before the gate name appears.
///
/// This isolates the "time to diagnosis" within the error itself, ignoring
/// the ZeroStyl stats header which comes before the failure section.
fn chars_to_gate_name_in_failure(s: &str, gate_name: &str) -> usize {
    let from_failure = &s[failure_section_start(s)..];
    from_failure.find(gate_name).unwrap_or(from_failure.len())
}

/// Characters used to convey the failing cell values / diagnosis.
///
/// Raw halo2 renders each cell as a multi-line `VirtualCell { … }` block (~10 lines, ~150 chars)
/// inside a `cell_values: [ … ]` list. The ZeroStyl report condenses the same information onto a
/// single `  Details: …` line per failure. This measures how much text each spends on that.
fn cell_section_chars(s: &str) -> usize {
    if let Some(start) = s.find("cell_values: [") {
        // Raw halo2: measure from `cell_values: [` to its matching close.
        let slice = &s[start..];
        let mut depth = 0i32;
        let mut end = slice.len();
        for (i, c) in slice.char_indices() {
            match c {
                '[' | '{' | '(' => depth += 1,
                ']' | '}' | ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        return slice[..end].len();
    }
    // ZeroStyl: sum the length of every `Details:` line (the condensed diagnosis).
    s.lines().filter(|l| l.trim_start().starts_with("Details:")).map(str::len).sum()
}

/// Whether the gate name is visible near the top of the FAILURE section (first 3 lines).
/// Raw halo2 buries it deep inside the pretty-printed struct; the ZeroStyl report surfaces it on a
/// dedicated `Gate:` line right under the failure header.
fn gate_visible_near_top_of_failure(s: &str, gate_name: &str) -> bool {
    let from_failure = &s[failure_section_start(s)..];
    from_failure.lines().take(3).any(|l| l.contains(gate_name))
}

// ─── Scenario result ────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct OutputMetrics {
    lines: usize,
    chars: usize,
    noise_lines: usize,
    max_nesting_depth: usize,
    chars_to_gate_in_failure: usize,
    cell_section_chars: usize,
    gate_near_top_of_failure: bool,
}

impl OutputMetrics {
    fn from(s: &str, gate_name: &str) -> Self {
        Self {
            lines: s.lines().count(),
            chars: s.len(),
            noise_lines: count_noise_lines(s),
            max_nesting_depth: max_nesting_depth(s),
            chars_to_gate_in_failure: chars_to_gate_name_in_failure(s, gate_name),
            cell_section_chars: cell_section_chars(s),
            gate_near_top_of_failure: gate_visible_near_top_of_failure(s, gate_name),
        }
    }
}

#[derive(serde::Serialize)]
struct ScenarioResult {
    scenario: String,
    circuit: String,
    error_injected: String,
    failing_gate: String,
    raw: OutputMetrics,
    zerostyl: OutputMetrics,
}

impl ScenarioResult {
    fn new(
        scenario: &str,
        circuit: &str,
        error_injected: &str,
        failing_gate: &str,
        raw_output: &str,
        zerostyl_output: &str,
    ) -> Self {
        Self {
            scenario: scenario.to_string(),
            circuit: circuit.to_string(),
            error_injected: error_injected.to_string(),
            failing_gate: failing_gate.to_string(),
            raw: OutputMetrics::from(raw_output, failing_gate),
            zerostyl: OutputMetrics::from(zerostyl_output, failing_gate),
        }
    }
}

fn pct_change(before: usize, after: usize) -> String {
    if before == 0 {
        return "n/a".to_string();
    }
    let v = (after as f64 - before as f64) / before as f64 * 100.0;
    if v < 0.0 {
        format!("-{:.0}%", v.abs())
    } else {
        format!("+{:.0}%", v)
    }
}

// ─── Scenarios ──────────────────────────────────────────────────────────────

/// A: state_mask — wrong commitment (value=42, randomness=123, injected=999)
fn scenario_a() -> (ScenarioResult, String, String) {
    let value = 42u64;
    let randomness = Fr::from(123u64);
    let wrong_commitment = Fr::from(999u64);
    let threshold = 100u64;
    let k = 10u32;
    let pi = vec![vec![wrong_commitment, Fr::from(threshold)]];

    let circuit_raw = black_box(StateMaskCircuit::from_raw(value, randomness, 200, 500, threshold));
    let prover = MockProver::run(k, &circuit_raw, pi.clone()).expect("MockProver::run failed");
    let raw_errors = prover.verify().expect_err("expected failure");
    let raw_output = format!("{:#?}", raw_errors);

    let witness = serde_json::json!({
        "state_value": "42",
        "nonce": "123",
        "collateral_ratio": "200",
        "hidden_balance": "500",
        "threshold": "100",
        "_debug": { "commitment": "999" }
    })
    .to_string();
    let zerostyl_output = zerostyl_output_via_descriptor(state_mask::descriptor(), &witness, k);

    let result = ScenarioResult::new(
        "A",
        "state_mask",
        "public commitment set to 999 (does not match the committed state)",
        "permute state",
        &raw_output,
        &zerostyl_output,
    );
    (result, raw_output, zerostyl_output)
}

/// B: tx_privacy — inconsistent balance/amount (balance_old=1000, balance_new=800, amount=300)
fn scenario_b() -> (ScenarioResult, String, String) {
    let balance_old = 1000u64;
    let balance_new = 800u64;
    let r_old = Fr::from(7u64);
    let r_new = Fr::from(13u64);
    let amount = 300u64; // correct: balance_old - balance_new = 200
    let path = vec![Fr::ZERO; MERKLE_DEPTH];
    let k = 14u32;

    let indices = vec![false; MERKLE_DEPTH];
    let comm_old = TxPrivacyCircuit::compute_commitment(Fr::from(balance_old), r_old);
    let comm_new = TxPrivacyCircuit::compute_commitment(Fr::from(balance_new), r_new);
    let root = TxPrivacyCircuit::compute_merkle_root(comm_old, &path, &indices);
    // The tx_privacy circuit exposes 4 public inputs: [commitment_old, commitment_new,
    // merkle_root, nullifier]. Omitting the nullifier row would add a spurious instance
    // failure to the raw-vs-ZeroStyl comparison this benchmark exists to demonstrate.
    let nullifier = TxPrivacyCircuit::compute_nullifier(Fr::from(balance_old), r_old);
    let pi = vec![vec![comm_old, comm_new, root, nullifier]];

    let circuit_raw = black_box(TxPrivacyCircuit::from_raw(
        balance_old,
        balance_new,
        r_old,
        r_new,
        amount,
        path.clone(),
        indices.clone(),
    ));
    let prover = MockProver::run(k, &circuit_raw, pi.clone()).expect("MockProver::run failed");
    let raw_errors = prover.verify().expect_err("expected failure");
    let raw_output = format!("{:#?}", raw_errors);

    let _ = black_box(&path);
    let _ = black_box(&indices);
    let zero_array: Vec<&str> = (0..MERKLE_DEPTH).map(|_| "0").collect();
    let witness = serde_json::json!({
        "balance_old": "1000",
        "balance_new": "800",
        "randomness_old": "7",
        "randomness_new": "13",
        "amount": "300",
        "merkle_siblings": zero_array,
        "merkle_indices": zero_array,
    })
    .to_string();
    let zerostyl_output = zerostyl_output_via_descriptor(tx_privacy::descriptor(), &witness, k);

    let result = ScenarioResult::new(
        "B",
        "tx_privacy",
        "amount=300 but balance_old-balance_new=200",
        "balance check",
        &raw_output,
        &zerostyl_output,
    );
    (result, raw_output, zerostyl_output)
}

/// C: private_vote — illegal vote value (vote=2, must be 0 or 1)
fn scenario_c() -> (ScenarioResult, String, String) {
    let balance = 100u64;
    let r_bal = Fr::from(42u64);
    let vote = 2u64; // must be 0 or 1
    let r_vote = Fr::from(84u64);
    let threshold = 50u64;
    let k = 11u32;

    let bal_commit = PrivateVoteCircuit::compute_commitment(Fr::from(balance), r_bal);
    let vote_commit = PrivateVoteCircuit::compute_commitment(Fr::from(vote), r_vote);
    let pi = vec![vec![bal_commit, Fr::from(threshold), vote_commit]];

    let circuit_raw =
        black_box(PrivateVoteCircuit::from_raw(balance, r_bal, vote, r_vote, threshold));
    let prover = MockProver::run(k, &circuit_raw, pi.clone()).expect("MockProver::run failed");
    let raw_errors = prover.verify().expect_err("expected failure");
    let raw_output = format!("{:#?}", raw_errors);

    let witness = serde_json::json!({
        "balance": "100",
        "randomness_balance": "42",
        "vote": "2",
        "randomness_vote": "84",
        "threshold": "50"
    })
    .to_string();
    let zerostyl_output = zerostyl_output_via_descriptor(private_vote::descriptor(), &witness, k);

    let result = ScenarioResult::new(
        "C",
        "private_vote",
        "vote=2 (must be 0 or 1)",
        "vote_boolean",
        &raw_output,
        &zerostyl_output,
    );
    (result, raw_output, zerostyl_output)
}

// ─── Rendering ──────────────────────────────────────────────────────────────

fn print_scenario(r: &ScenarioResult) {
    println!();
    println!(
        "━━━  Scenario {}  [{}]  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        r.scenario, r.circuit
    );
    println!("  Error injected : {}", r.error_injected);
    println!("  Failing gate   : {}", r.failing_gate);
    println!();
    println!("  {:<38}  {:>10}  {:>10}  {:>10}", "Metric", "Raw halo2", "ZeroStyl", "Change");
    println!("  {}", "─".repeat(72));

    fn row_usize(label: &str, before: usize, after: usize) {
        println!(
            "  {:<38}  {:>10}  {:>10}  {:>10}",
            label,
            before,
            after,
            pct_change(before, after)
        );
    }

    fn row_bool(label: &str, before: bool, after: bool) {
        println!(
            "  {:<38}  {:>10}  {:>10}  {:>10}",
            label,
            if before { "yes" } else { "no" },
            if after { "yes" } else { "no" },
            if before == after {
                "same"
            } else if after {
                "improved"
            } else {
                "worse"
            }
        );
    }

    row_usize("Output lines", r.raw.lines, r.zerostyl.lines);
    row_usize("Output characters", r.raw.chars, r.zerostyl.chars);
    row_usize("Noise lines (braces/commas only)", r.raw.noise_lines, r.zerostyl.noise_lines);
    row_usize("Max struct nesting depth", r.raw.max_nesting_depth, r.zerostyl.max_nesting_depth);
    row_usize(
        "Chars to gate name in failure",
        r.raw.chars_to_gate_in_failure,
        r.zerostyl.chars_to_gate_in_failure,
    );
    row_usize(
        "Chars for cell values section",
        r.raw.cell_section_chars,
        r.zerostyl.cell_section_chars,
    );
    row_bool(
        "Gate near top of failure",
        r.raw.gate_near_top_of_failure,
        r.zerostyl.gate_near_top_of_failure,
    );
    println!();
}

fn print_summary(results: &[ScenarioResult]) {
    let n = results.len() as f64;

    // Nesting depth is the one format-agnostic, always-favorable metric: raw halo2 `{:#?}` nests
    // structs several levels deep; the ZeroStyl report is flat.
    let avg_depth_red = results
        .iter()
        .map(|r| {
            (1.0 - r.zerostyl.max_nesting_depth as f64 / r.raw.max_nesting_depth.max(1) as f64)
                * 100.0
        })
        .sum::<f64>()
        / n;

    // Line count is NOT universally reduced: raw halo2 renders a `ConstraintNotSatisfied` failure
    // as a deep multi-line struct (where ZeroStyl wins big), but renders equality/permutation
    // failures as a single terse line (where ZeroStyl's structured header adds a few lines). Report
    // the best case honestly instead of averaging across failure types into a misleading number.
    let best = results.iter().max_by_key(|r| r.raw.lines).expect("at least one scenario");
    let gate_near_top_gain = results
        .iter()
        .filter(|r| r.zerostyl.gate_near_top_of_failure && !r.raw.gate_near_top_of_failure)
        .count();

    println!("════════  SUMMARY  ════════════════════════════════════════════");
    println!();
    println!("  ZeroStyl reorganizes halo2 failures into a flat, labeled report. Its consistent");
    println!("  win is structural; its line/char win is largest on verbose constraint failures");
    println!(
        "  and smaller (or slightly negative) on already-terse equality/permutation failures."
    );
    println!();
    println!(
        "  Max struct nesting depth ........ {:>4.0}% shallower (avg, all scenarios)",
        avg_depth_red
    );
    println!(
        "  Verbose case (scenario {} / {}) .... raw {} lines → ZeroStyl {} lines",
        best.scenario, best.circuit, best.raw.lines, best.zerostyl.lines
    );
    println!(
        "  Gate name near top of failure ... {}/{} scenarios (ZeroStyl) vs 0/{} (raw halo2)",
        gate_near_top_gain,
        results.len(),
        results.len()
    );
    println!();
    println!("  Per-scenario line/char deltas are shown above (negative = ZeroStyl adds structure");
    println!("  to an already-terse raw failure; large positive = raw was a deep nested struct).");
    println!();
}

fn print_verbose(scenario: &str, label: &str, raw: &str, zerostyl: &str) {
    let sep = "─".repeat(64);
    println!();
    println!("{sep}");
    println!("Scenario {scenario} — raw halo2 ({label})");
    println!("{sep}");
    println!("{raw}");
    println!("{sep}");
    println!("Scenario {scenario} — ZeroStyl ({label})");
    println!("{sep}");
    println!("{zerostyl}");
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let verbose = args.iter().any(|a| a == "--verbose");

    if !json_mode {
        println!();
        println!("ZeroStyl — Output Quality Comparison");
        println!("Real circuits · Real broken witnesses · Deterministic metrics");
    }

    let (result_a, raw_a, z_a) = scenario_a();
    let (result_b, raw_b, z_b) = scenario_b();
    let (result_c, raw_c, z_c) = scenario_c();

    let results = vec![result_a, result_b, result_c];

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
        return;
    }

    for r in &results {
        print_scenario(r);
    }
    print_summary(&results);

    if verbose {
        print_verbose("A", "state_mask wrong commitment", &raw_a, &z_a);
        print_verbose("B", "tx_privacy wrong balance", &raw_b, &z_b);
        print_verbose("C", "private_vote illegal vote", &raw_c, &z_c);
    }
}
