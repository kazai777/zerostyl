//! Human-readable rendering of [`CircuitIntrospection`].

use std::fmt::Write as _;

use zerostyl_circuits::CircuitIntrospection;

pub fn format_introspection(intro: &CircuitIntrospection) -> String {
    let mut out = String::new();
    let rows = 1usize << intro.k;
    writeln!(out, "Circuit: {}", intro.circuit_name).unwrap();
    writeln!(out, "  k: {} (2^k = {} rows)", intro.k, rows).unwrap();
    writeln!(
        out,
        "  Columns: {} total",
        intro.num_advice_columns + intro.num_instance_columns + intro.num_fixed_columns
    )
    .unwrap();
    writeln!(out, "    advice:   {}", intro.num_advice_columns).unwrap();
    writeln!(out, "    instance: {}", intro.num_instance_columns).unwrap();
    writeln!(out, "    fixed:    {}", intro.num_fixed_columns).unwrap();
    writeln!(out, "  Selectors:   {}", intro.num_selectors).unwrap();
    writeln!(out, "  Max degree:  {}", intro.max_constraint_degree).unwrap();

    if intro.gates.is_empty() {
        writeln!(out, "  Gates:       (not enumerated — see descriptor for richer metadata)")
            .unwrap();
    } else {
        writeln!(out, "  Gates: {}", intro.gates.len()).unwrap();
        for g in &intro.gates {
            writeln!(
                out,
                "    - {} ({} constraint(s), max degree {})",
                g.name, g.constraint_count, g.max_degree
            )
            .unwrap();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerostyl_circuits::GateInfo;

    fn make_intro(gates: Vec<GateInfo>) -> CircuitIntrospection {
        CircuitIntrospection {
            circuit_name: "demo".into(),
            k: 4,
            num_advice_columns: 1,
            num_fixed_columns: 0,
            num_instance_columns: 1,
            num_selectors: 1,
            max_constraint_degree: 2,
            gates,
            columns: vec![],
        }
    }

    #[test]
    fn renders_circuit_header() {
        let s = format_introspection(&make_intro(vec![]));
        assert!(s.contains("Circuit: demo"));
        assert!(s.contains("k: 4 (2^k = 16 rows)"));
    }

    #[test]
    fn renders_empty_gates_placeholder() {
        let s = format_introspection(&make_intro(vec![]));
        assert!(s.contains("not enumerated"));
    }

    #[test]
    fn renders_gates_when_present() {
        let intro =
            make_intro(vec![GateInfo { name: "add".into(), constraint_count: 1, max_degree: 2 }]);
        let s = format_introspection(&intro);
        assert!(s.contains("Gates: 1"));
        assert!(s.contains("- add (1 constraint(s), max degree 2)"));
    }
}
