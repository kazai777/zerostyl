//! Output quality comparison: raw halo2 vs ZeroStyl
//!
//! This is NOT a timing benchmark (use `cargo bench -p zerostyl-debugger` for that).
//! This tool measures DETERMINISTIC output quality metrics on real circuits with real
//! broken witnesses. All metrics are reproducible — no timing or system noise involved.
//!
//! Metrics measured:
//!   - Lines of output
//!   - Structural noise lines (only braces/commas — zero information content)
//!   - Max struct nesting depth (depth of `{[( ` nesting)
//!   - Characters before the gate name appears (time-to-diagnosis proxy)
//!   - Average characters per cell value reference
//!   - Gate name visible at top level (yes/no)
//!
//! Usage:
//!   cargo run -p debug-workflow-bench --release
//!   cargo run -p debug-workflow-bench --release -- --json
//!   cargo run -p debug-workflow-bench --release -- --verbose

use std::env;
use std::hint::black_box;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use private_vote::PrivateVoteCircuit;
use state_mask::StateMaskCircuit;
use tx_privacy::{TxPrivacyCircuit, MERKLE_DEPTH};
use zerostyl_debugger::debug_circuit;

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

/// Characters from the start of the FAILURE section before the gate name appears.
///
/// For raw halo2 the failure section starts at `ConstraintNotSatisfied {`.
/// For ZeroStyl it starts at `FAILED:`.
///
/// This isolates the "time to diagnosis" within the error itself, ignoring
/// the ZeroStyl stats header which comes before the failure section.
fn chars_to_gate_name_in_failure(s: &str, gate_name: &str) -> usize {
    let failure_start = s.find("ConstraintNotSatisfied").or_else(|| s.find("FAILED:")).unwrap_or(0);
    let from_failure = &s[failure_start..];
    from_failure.find(gate_name).unwrap_or(from_failure.len())
}

/// Total characters used to represent ALL cell values in the error output.
///
/// For raw halo2, each cell value is a multi-line `VirtualCell { … }` block
/// spanning ~10 lines and ~150 characters.
/// For ZeroStyl, each cell value is a single line like `- advice[0] row 0 = 0x2a`.
///
/// Measures the entire cell-values section: from `cell_values: [` (raw) or
/// `Cell values:` (ZeroStyl) to the closing bracket/next section.
fn cell_section_chars(s: &str) -> usize {
    // Find start of cell values section
    let start = s.find("cell_values: [").or_else(|| s.find("Cell values:")).unwrap_or(0);
    let slice = &s[start..];

    // Find end: for raw, the closing `],` after the list;
    // for ZeroStyl, the next blank line or `Hint:` line
    let end = slice
        .find("\n  Hint:")
        .or_else(|| {
            // For raw halo2: find the `],` that closes the cell_values list
            // Count opening brackets to find the matching close
            let mut depth = 0i32;
            let mut pos = 0;
            for (i, c) in slice.char_indices() {
                match c {
                    '[' | '{' | '(' => depth += 1,
                    ']' | '}' | ')' => {
                        depth -= 1;
                        if depth == 0 {
                            pos = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if pos > 0 {
                Some(pos)
            } else {
                None
            }
        })
        .unwrap_or(slice.len());

    slice[..end].len()
}

/// Whether the gate name is visible in the first 5 lines of the FAILURE section.
/// Raw halo2 buries it deep in a struct; ZeroStyl surfaces it on the first failure line.
fn gate_visible_in_failure_first_line(s: &str, gate_name: &str) -> bool {
    let failure_start = s.find("ConstraintNotSatisfied").or_else(|| s.find("FAILED:")).unwrap_or(0);
    let from_failure = &s[failure_start..];
    from_failure.lines().next().map(|l| l.contains(gate_name)).unwrap_or(false)
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
    gate_on_failure_first_line: bool,
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
            gate_on_failure_first_line: gate_visible_in_failure_first_line(s, gate_name),
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
    let randomness = Fp::from(123u64);
    let commitment_override = Fp::from(999u64); // correct: 42+123=165
    let k = 10u32;
    let pi = vec![vec![commitment_override]];

    let circuit_raw =
        black_box(StateMaskCircuit::from_raw(value, randomness, 0, 255, Some(commitment_override)));
    let prover = MockProver::run(k, &circuit_raw, pi.clone()).expect("MockProver::run failed");
    let raw_errors = prover.verify().expect_err("expected failure");
    let raw_output = format!("{:#?}", raw_errors);

    let circuit_z =
        black_box(StateMaskCircuit::from_raw(value, randomness, 0, 255, Some(commitment_override)));
    let report = debug_circuit(&circuit_z, pi, k, "state_mask").expect("debug_circuit failed");
    let zerostyl_output = format!("{}", report);

    let result = ScenarioResult::new(
        "A",
        "state_mask",
        "commitment=999 (correct: value+randomness=165)",
        "commitment",
        &raw_output,
        &zerostyl_output,
    );
    (result, raw_output, zerostyl_output)
}

/// B: tx_privacy — inconsistent balance/amount (balance_old=1000, balance_new=800, amount=300)
fn scenario_b() -> (ScenarioResult, String, String) {
    let balance_old = 1000u64;
    let balance_new = 800u64;
    let r_old = Fp::from(7u64);
    let r_new = Fp::from(13u64);
    let amount = 300u64; // correct: balance_old - balance_new = 200
    let path = vec![Fp::ZERO; MERKLE_DEPTH];
    let k = 14u32;

    let comm_old = TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), r_old);
    let comm_new = TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), r_new);
    let root = TxPrivacyCircuit::compute_merkle_root(comm_old, &path);
    let pi = vec![vec![comm_old, comm_new, root]];

    let circuit_raw = black_box(TxPrivacyCircuit::from_raw(
        balance_old,
        balance_new,
        r_old,
        r_new,
        amount,
        path.clone(),
        None,
        None,
    ));
    let prover = MockProver::run(k, &circuit_raw, pi.clone()).expect("MockProver::run failed");
    let raw_errors = prover.verify().expect_err("expected failure");
    let raw_output = format!("{:#?}", raw_errors);

    let circuit_z = black_box(TxPrivacyCircuit::from_raw(
        balance_old,
        balance_new,
        r_old,
        r_new,
        amount,
        path,
        None,
        None,
    ));
    let report = debug_circuit(&circuit_z, pi, k, "tx_privacy").expect("debug_circuit failed");
    let zerostyl_output = format!("{}", report);

    let result = ScenarioResult::new(
        "B",
        "tx_privacy",
        "amount=300 but balance_old-balance_new=200",
        "balance_check",
        &raw_output,
        &zerostyl_output,
    );
    (result, raw_output, zerostyl_output)
}

/// C: private_vote — illegal vote value (vote=2, must be 0 or 1)
fn scenario_c() -> (ScenarioResult, String, String) {
    let balance = 100u64;
    let r_bal = Fp::from(42u64);
    let vote = 2u64; // must be 0 or 1
    let r_vote = Fp::from(84u64);
    let threshold = 50u64;
    let k = 11u32;

    let bal_commit = PrivateVoteCircuit::compute_commitment(Fp::from(balance), r_bal);
    let vote_commit = PrivateVoteCircuit::compute_commitment(Fp::from(vote), r_vote);
    let pi = vec![vec![bal_commit, Fp::from(threshold), vote_commit]];

    let circuit_raw = black_box(PrivateVoteCircuit::from_raw(
        balance, r_bal, vote, r_vote, threshold, None, None,
    ));
    let prover = MockProver::run(k, &circuit_raw, pi.clone()).expect("MockProver::run failed");
    let raw_errors = prover.verify().expect_err("expected failure");
    let raw_output = format!("{:#?}", raw_errors);

    let circuit_z = black_box(PrivateVoteCircuit::from_raw(
        balance, r_bal, vote, r_vote, threshold, None, None,
    ));
    let report = debug_circuit(&circuit_z, pi, k, "private_vote").expect("debug_circuit failed");
    let zerostyl_output = format!("{}", report);

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
        "Gate on first failure line",
        r.raw.gate_on_failure_first_line,
        r.zerostyl.gate_on_failure_first_line,
    );
    println!();
}

fn print_summary(results: &[ScenarioResult]) {
    let n = results.len() as f64;

    let avg_line_red = results
        .iter()
        .map(|r| (1.0 - r.zerostyl.lines as f64 / r.raw.lines as f64) * 100.0)
        .sum::<f64>()
        / n;
    let avg_noise_red = results
        .iter()
        .map(|r| (1.0 - r.zerostyl.noise_lines as f64 / r.raw.noise_lines.max(1) as f64) * 100.0)
        .sum::<f64>()
        / n;
    let avg_depth_red = results
        .iter()
        .map(|r| {
            (1.0 - r.zerostyl.max_nesting_depth as f64 / r.raw.max_nesting_depth.max(1) as f64)
                * 100.0
        })
        .sum::<f64>()
        / n;
    let avg_gate_chars_red = results
        .iter()
        .map(|r| {
            (1.0 - r.zerostyl.chars_to_gate_in_failure as f64
                / r.raw.chars_to_gate_in_failure.max(1) as f64)
                * 100.0
        })
        .sum::<f64>()
        / n;
    let avg_cell_section_red = results
        .iter()
        .map(|r| {
            (1.0 - r.zerostyl.cell_section_chars as f64 / r.raw.cell_section_chars.max(1) as f64)
                * 100.0
        })
        .sum::<f64>()
        / n;
    let gate_on_first_line_gain = results
        .iter()
        .filter(|r| r.zerostyl.gate_on_failure_first_line && !r.raw.gate_on_failure_first_line)
        .count();

    println!("════════  SUMMARY  ════════════════════════════════════════════");
    println!();
    println!("  {:<40}  {:>8}", "Metric", "Avg reduction");
    println!("  {}", "─".repeat(52));
    println!("  {:<40}  {:>7.0}%", "Output lines", avg_line_red);
    println!("  {:<40}  {:>7.0}%", "Noise lines (zero-info formatting)", avg_noise_red);
    println!("  {:<40}  {:>7.0}%", "Max struct nesting depth", avg_depth_red);
    println!("  {:<40}  {:>7.0}%", "Chars to gate name in failure", avg_gate_chars_red);
    println!("  {:<40}  {:>7.0}%", "Chars for cell values section", avg_cell_section_red);
    println!();
    println!(
        "  Gate on first failure line: {}/{} (ZeroStyl) vs 0/{} (raw halo2)",
        gate_on_first_line_gain,
        results.len(),
        results.len()
    );
    println!();
    println!("  For timing results: cargo bench -p zerostyl-debugger");
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
        println!();
        println!("For timing: cargo bench -p zerostyl-debugger");
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
