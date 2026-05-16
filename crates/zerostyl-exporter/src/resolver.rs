use crate::error::{ExporterError, Result};
use crate::parser::{AttrSpec, CommitScheme, Constraint, ZkPrivateAttr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAttr {
    pub param_name: String,
    pub param_type: String,
    pub bindings: Vec<GadgetBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GadgetBinding {
    /// `PoseidonCommitmentChip::commit(value, nonce_var) == commitment`
    PoseidonCommit { nonce_var: String },
    /// `RangeProofChip::check_range_bounded(value, low, high, num_bits)`
    Range { low: String, high: String, inclusive: bool, num_bits: usize },
    /// `ComparisonChip::assert_<op>(value, other, num_bits)`
    Comparison { op: ComparisonOp, other: String, num_bits: usize },
    /// `MerkleTreeChip::verify_membership(value, root_var, siblings_var, indices_var, depth)`
    MerkleMember { root_var: String, siblings_var: String, indices_var: String, depth: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOp {
    Gte,
    Gt,
    Lte,
    Lt,
    Eq,
}

/// Convention shared across the four M1 circuits.
pub const MERKLE_DEPTH: usize = 32;

pub fn resolve(attr: &ZkPrivateAttr) -> Result<ResolvedAttr> {
    let num_bits = num_bits_of(&attr.param_type)?;
    let mut bindings = Vec::with_capacity(attr.specs.len());
    for spec in &attr.specs {
        bindings.push(resolve_spec(spec, &attr.param_name, num_bits));
    }
    Ok(ResolvedAttr {
        param_name: attr.param_name.clone(),
        param_type: attr.param_type.clone(),
        bindings,
    })
}

pub fn resolve_all(attrs: &[ZkPrivateAttr]) -> Result<Vec<ResolvedAttr>> {
    attrs.iter().map(resolve).collect()
}

fn resolve_spec(spec: &AttrSpec, param_name: &str, num_bits: usize) -> GadgetBinding {
    match spec {
        AttrSpec::Commit(CommitScheme::Poseidon) => {
            GadgetBinding::PoseidonCommit { nonce_var: format!("{param_name}_nonce") }
        }
        AttrSpec::Range(r) => GadgetBinding::Range {
            low: r.low.clone(),
            high: r.high.clone(),
            inclusive: r.inclusive,
            num_bits,
        },
        AttrSpec::Constraint(c) => {
            let (op, other) = comparison_parts(c);
            GadgetBinding::Comparison { op, other, num_bits }
        }
        AttrSpec::MerkleMember(m) => GadgetBinding::MerkleMember {
            root_var: m.root_var.clone(),
            siblings_var: m.siblings_var.clone(),
            indices_var: m.indices_var.clone(),
            depth: MERKLE_DEPTH,
        },
    }
}

fn comparison_parts(c: &Constraint) -> (ComparisonOp, String) {
    match c {
        Constraint::Gte(o) => (ComparisonOp::Gte, o.clone()),
        Constraint::Gt(o) => (ComparisonOp::Gt, o.clone()),
        Constraint::Lte(o) => (ComparisonOp::Lte, o.clone()),
        Constraint::Lt(o) => (ComparisonOp::Lt, o.clone()),
        Constraint::Eq(o) => (ComparisonOp::Eq, o.clone()),
    }
}

fn num_bits_of(ty: &str) -> Result<usize> {
    let t = strip_path(ty.trim());
    match t {
        "u8" => Ok(8),
        "u16" => Ok(16),
        "u32" => Ok(32),
        "u64" => Ok(64),
        "u128" => Ok(128),
        "U256" => Ok(256),
        "bool" => Ok(1),
        other => Err(ExporterError::Parse(format!(
            "cannot infer bit width for type '{other}' (supported: u8/u16/u32/u64/u128/U256/bool)"
        ))),
    }
}

/// Strip leading path segments (e.g. `alloy_primitives :: U256` -> `U256`).
fn strip_path(ty: &str) -> &str {
    let cleaned = ty.split("::").last().unwrap_or(ty);
    cleaned.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AttrSpec, CommitScheme, Constraint, MerkleMemberSpec, RangeSpec};

    fn attr(param_name: &str, param_type: &str, specs: Vec<AttrSpec>) -> ZkPrivateAttr {
        ZkPrivateAttr { param_name: param_name.into(), param_type: param_type.into(), specs }
    }

    #[test]
    fn poseidon_commit_yields_nonce_var_by_convention() {
        let a = attr("collateral", "U256", vec![AttrSpec::Commit(CommitScheme::Poseidon)]);
        let r = resolve(&a).unwrap();
        assert_eq!(r.bindings.len(), 1);
        assert_eq!(
            r.bindings[0],
            GadgetBinding::PoseidonCommit { nonce_var: "collateral_nonce".into() }
        );
    }

    #[test]
    fn range_carries_num_bits_from_u64_type() {
        let a = attr(
            "x",
            "u64",
            vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "100".into(),
                inclusive: false,
            })],
        );
        let r = resolve(&a).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Range {
                low: "0".into(),
                high: "100".into(),
                inclusive: false,
                num_bits: 64,
            }
        );
    }

    #[test]
    fn range_carries_num_bits_for_u256() {
        let a = attr(
            "x",
            "U256",
            vec![AttrSpec::Range(RangeSpec {
                low: "1000".into(),
                high: "u128::MAX".into(),
                inclusive: true,
            })],
        );
        let r = resolve(&a).unwrap();
        match &r.bindings[0] {
            GadgetBinding::Range { num_bits, inclusive, high, .. } => {
                assert_eq!(*num_bits, 256);
                assert!(*inclusive);
                assert!(high.contains("u128"));
            }
            other => panic!("expected Range, got {other:?}"),
        }
    }

    #[test]
    fn comparison_gte_resolves() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))]);
        let r = resolve(&a).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Comparison {
                op: ComparisonOp::Gte,
                other: "threshold".into(),
                num_bits: 64,
            }
        );
    }

    #[test]
    fn comparison_lt_resolves() {
        let a = attr("x", "u32", vec![AttrSpec::Constraint(Constraint::Lt("max".into()))]);
        let r = resolve(&a).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Comparison { op: ComparisonOp::Lt, other: "max".into(), num_bits: 32 }
        );
    }

    #[test]
    fn merkle_member_hardcodes_depth_32() {
        let a = attr(
            "leaf",
            "U256",
            vec![AttrSpec::MerkleMember(MerkleMemberSpec {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
                indices_var: "indices".into(),
            })],
        );
        let r = resolve(&a).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::MerkleMember {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
                indices_var: "indices".into(),
                depth: 32,
            }
        );
    }

    #[test]
    fn multiple_specs_compose() {
        let a = attr(
            "collateral",
            "U256",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Range(RangeSpec {
                    low: "1000".into(),
                    high: "u128::MAX".into(),
                    inclusive: true,
                }),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        );
        let r = resolve(&a).unwrap();
        assert_eq!(r.bindings.len(), 3);
        assert!(matches!(r.bindings[0], GadgetBinding::PoseidonCommit { .. }));
        assert!(matches!(r.bindings[1], GadgetBinding::Range { num_bits: 256, .. }));
        assert!(matches!(
            r.bindings[2],
            GadgetBinding::Comparison { op: ComparisonOp::Gte, num_bits: 256, .. }
        ));
    }

    #[test]
    fn unknown_type_fails() {
        let a = attr("x", "MyCustomType", vec![AttrSpec::Commit(CommitScheme::Poseidon)]);
        let err = resolve(&a).unwrap_err();
        assert!(format!("{err}").contains("MyCustomType"));
    }

    #[test]
    fn path_qualified_type_resolves() {
        let a = attr(
            "x",
            "alloy_primitives :: U256",
            vec![AttrSpec::Constraint(Constraint::Gte("y".into()))],
        );
        let r = resolve(&a).unwrap();
        assert!(matches!(r.bindings[0], GadgetBinding::Comparison { num_bits: 256, .. }));
    }

    #[test]
    fn bool_type_resolves_to_1_bit() {
        let a = attr("flag", "bool", vec![AttrSpec::Constraint(Constraint::Eq("1".into()))]);
        let r = resolve(&a).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Comparison { op: ComparisonOp::Eq, other: "1".into(), num_bits: 1 }
        );
    }

    #[test]
    fn resolve_all_preserves_order() {
        let attrs = vec![
            attr("a", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)]),
            attr(
                "b",
                "U256",
                vec![AttrSpec::Range(RangeSpec {
                    low: "0".into(),
                    high: "100".into(),
                    inclusive: true,
                })],
            ),
        ];
        let resolved = resolve_all(&attrs).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].param_name, "a");
        assert_eq!(resolved[1].param_name, "b");
    }

    #[test]
    fn resolve_all_propagates_first_error() {
        let attrs = vec![
            attr("a", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)]),
            attr("b", "Unknown", vec![AttrSpec::Commit(CommitScheme::Poseidon)]),
        ];
        let err = resolve_all(&attrs).unwrap_err();
        assert!(format!("{err}").contains("Unknown"));
    }
}
