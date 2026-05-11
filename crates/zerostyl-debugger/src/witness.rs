//! Human-readable rendering of [`MockProverReport`].

use std::fmt::Write as _;

use anyhow::Result;
use zerostyl_circuits::{FailureKind, MockProverReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("unknown output format '{other}' (expected 'text' or 'json')"),
        }
    }
}

pub fn format_mock_prover_report(report: &MockProverReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => {
            Ok(serde_json::to_string_pretty(report)
                .map_err(|e| anyhow::anyhow!("serializing report: {e}"))?)
        }
        OutputFormat::Text => Ok(render_text(report)),
    }
}

fn render_text(report: &MockProverReport) -> String {
    let mut out = String::new();
    writeln!(out, "=== Debug Report: {} ===", report.circuit_name).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "Circuit: {}  k={}", report.circuit_name, report.k).unwrap();
    writeln!(out).unwrap();

    if report.satisfied {
        writeln!(out, "Result: ALL CONSTRAINTS SATISFIED").unwrap();
        return out;
    }

    writeln!(out, "Result: {} FAILURE(S)", report.failures.len()).unwrap();
    writeln!(out).unwrap();

    for (i, f) in report.failures.iter().enumerate() {
        writeln!(out, "--- Failure {} [{}] ---", i + 1, render_kind(f.kind)).unwrap();
        if let Some(g) = &f.gate_name {
            writeln!(out, "  Gate:   {g}").unwrap();
        }
        if let Some(r) = &f.region {
            writeln!(out, "  Region: {r}").unwrap();
        }
        if let Some(row) = f.row {
            writeln!(out, "  Row:    {row}").unwrap();
        }
        if let Some(c) = &f.column {
            writeln!(out, "  Column: {c}").unwrap();
        }
        writeln!(out, "  Details: {}", f.details).unwrap();
        writeln!(out).unwrap();
    }
    out
}

fn render_kind(k: FailureKind) -> &'static str {
    match k {
        FailureKind::ConstraintNotSatisfied => "constraint",
        FailureKind::Permutation => "permutation",
        FailureKind::InstanceCellMismatch => "instance",
        FailureKind::Lookup => "lookup",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerostyl_circuits::FailureEntry;

    fn satisfied() -> MockProverReport {
        MockProverReport {
            circuit_name: "demo".into(),
            k: 4,
            satisfied: true,
            failures: vec![],
        }
    }

    fn one_failure() -> MockProverReport {
        MockProverReport {
            circuit_name: "demo".into(),
            k: 4,
            satisfied: false,
            failures: vec![FailureEntry {
                kind: FailureKind::ConstraintNotSatisfied,
                gate_name: Some("add".into()),
                region: Some("main".into()),
                row: Some(2),
                column: None,
                details: "a + b != sum".into(),
            }],
        }
    }

    #[test]
    fn text_satisfied_says_all_satisfied() {
        let s = format_mock_prover_report(&satisfied(), OutputFormat::Text).unwrap();
        assert!(s.contains("ALL CONSTRAINTS SATISFIED"));
    }

    #[test]
    fn text_failed_lists_each_failure() {
        let s = format_mock_prover_report(&one_failure(), OutputFormat::Text).unwrap();
        assert!(s.contains("Result: 1 FAILURE(S)"));
        assert!(s.contains("Gate:   add"));
        assert!(s.contains("Row:    2"));
        assert!(s.contains("a + b != sum"));
    }

    #[test]
    fn json_format_is_valid() {
        let s = format_mock_prover_report(&one_failure(), OutputFormat::Json).unwrap();
        let parsed: MockProverReport = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.circuit_name, "demo");
        assert!(!parsed.satisfied);
    }

    #[test]
    fn output_format_parse_invalid() {
        assert!(OutputFormat::parse("xml").is_err());
    }
}
