use quote::ToTokens;
use syn::{Attribute, Expr, ExprBinary, ExprCall, ExprRange, FnArg, ItemFn, Lit, RangeLimits};

use crate::error::{ExporterError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkPrivateAttr {
    pub param_name: String,
    pub param_type: String,
    pub specs: Vec<AttrSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrSpec {
    Commit(CommitScheme),
    Range(RangeSpec),
    Constraint(Constraint),
    MerkleMember(MerkleMemberSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitScheme {
    Poseidon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeSpec {
    pub low: String,
    pub high: String,
    pub inclusive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    Gte(String),
    Gt(String),
    Lte(String),
    Lt(String),
    Eq(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleMemberSpec {
    pub root_var: String,
    pub siblings_var: String,
}

pub fn parse_fn(item_fn: &ItemFn) -> Result<Vec<ZkPrivateAttr>> {
    let mut out = Vec::new();
    for arg in &item_fn.sig.inputs {
        let FnArg::Typed(typed) = arg else {
            continue;
        };
        let zk_attrs: Vec<&Attribute> =
            typed.attrs.iter().filter(|a| a.path().is_ident("zk_private")).collect();
        if zk_attrs.is_empty() {
            continue;
        }
        let param_name = pat_ident(&typed.pat).ok_or_else(|| {
            ExporterError::Parse(format!(
                "#[zk_private] only supports named identifier params; got pattern: {}",
                typed.pat.to_token_stream()
            ))
        })?;
        let param_type = typed.ty.to_token_stream().to_string();
        let specs = parse_zk_private_attrs(&zk_attrs)?;
        out.push(ZkPrivateAttr { param_name, param_type, specs });
    }
    Ok(out)
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    if let syn::Pat::Ident(p) = pat {
        Some(p.ident.to_string())
    } else {
        None
    }
}

fn parse_zk_private_attrs(attrs: &[&Attribute]) -> Result<Vec<AttrSpec>> {
    let mut specs = Vec::new();
    for attr in attrs {
        let result = attr.parse_nested_meta(|meta| {
            let key = meta
                .path
                .get_ident()
                .ok_or_else(|| meta.error("expected identifier key inside #[zk_private(...)]"))?
                .to_string();
            let value = meta.value()?;
            let lit: Lit = value.parse()?;
            let Lit::Str(s) = lit else {
                return Err(meta.error("expected string literal value"));
            };
            let raw = s.value();
            match key.as_str() {
                "commit" => match raw.as_str() {
                    "poseidon" => specs.push(AttrSpec::Commit(CommitScheme::Poseidon)),
                    other => {
                        return Err(meta.error(format!("unknown commit scheme '{other}'")));
                    }
                },
                "range" => {
                    let parsed = parse_range(&raw).map_err(|e| meta.error(e.to_string()))?;
                    specs.push(AttrSpec::Range(parsed));
                }
                "constraint" => {
                    if raw.trim_start().starts_with("merkle_member") {
                        let parsed =
                            parse_merkle_member(&raw).map_err(|e| meta.error(e.to_string()))?;
                        specs.push(AttrSpec::MerkleMember(parsed));
                    } else {
                        let parsed =
                            parse_constraint(&raw).map_err(|e| meta.error(e.to_string()))?;
                        specs.push(AttrSpec::Constraint(parsed));
                    }
                }
                other => {
                    return Err(meta.error(format!(
                        "unknown #[zk_private] attribute key '{other}' (expected: commit, range, constraint)"
                    )));
                }
            }
            Ok(())
        });
        result.map_err(|e: syn::Error| ExporterError::Parse(e.to_string()))?;
    }
    Ok(specs)
}

fn parse_range(raw: &str) -> Result<RangeSpec> {
    let expr: ExprRange = syn::parse_str(raw)
        .map_err(|e| ExporterError::Parse(format!("invalid range '{raw}': {e}")))?;
    let low = expr
        .start
        .as_ref()
        .ok_or_else(|| ExporterError::Parse(format!("range '{raw}' must have a lower bound")))?
        .to_token_stream()
        .to_string();
    let high = expr
        .end
        .as_ref()
        .ok_or_else(|| ExporterError::Parse(format!("range '{raw}' must have an upper bound")))?
        .to_token_stream()
        .to_string();
    let inclusive = matches!(expr.limits, RangeLimits::Closed(_));
    Ok(RangeSpec { low, high, inclusive })
}

fn parse_constraint(raw: &str) -> Result<Constraint> {
    let expr: Expr = syn::parse_str(raw)
        .map_err(|e| ExporterError::Parse(format!("invalid constraint '{raw}': {e}")))?;
    let Expr::Binary(ExprBinary { left, op, right, .. }) = expr else {
        return Err(ExporterError::Parse(format!(
            "constraint '{raw}' must be a binary expression (LHS op RHS)"
        )));
    };
    let lhs = left.to_token_stream().to_string();
    if lhs.trim() != "value" {
        return Err(ExporterError::Parse(format!(
            "constraint LHS must be 'value' (the annotated param); got '{lhs}'"
        )));
    }
    let rhs = right.to_token_stream().to_string();
    match op {
        syn::BinOp::Ge(_) => Ok(Constraint::Gte(rhs)),
        syn::BinOp::Gt(_) => Ok(Constraint::Gt(rhs)),
        syn::BinOp::Le(_) => Ok(Constraint::Lte(rhs)),
        syn::BinOp::Lt(_) => Ok(Constraint::Lt(rhs)),
        syn::BinOp::Eq(_) => Ok(Constraint::Eq(rhs)),
        _ => Err(ExporterError::Parse(format!(
            "constraint '{raw}': unsupported operator (use >=, >, <=, <, ==)"
        ))),
    }
}

fn parse_merkle_member(raw: &str) -> Result<MerkleMemberSpec> {
    let expr: ExprCall = syn::parse_str(raw)
        .map_err(|e| ExporterError::Parse(format!("invalid merkle_member call '{raw}': {e}")))?;
    let func_name = expr.func.to_token_stream().to_string();
    if func_name.trim() != "merkle_member" {
        return Err(ExporterError::Parse(format!(
            "expected 'merkle_member' function, got '{func_name}'"
        )));
    }
    if expr.args.len() != 3 {
        return Err(ExporterError::Parse(format!(
            "merkle_member expects 3 args (value, root, siblings); got {}",
            expr.args.len()
        )));
    }
    let args: Vec<String> = expr.args.iter().map(|a| a.to_token_stream().to_string()).collect();
    if args[0].trim() != "value" {
        return Err(ExporterError::Parse(format!(
            "merkle_member first arg must be 'value'; got '{}'",
            args[0]
        )));
    }
    Ok(MerkleMemberSpec { root_var: args[1].clone(), siblings_var: args[2].clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_item(s: &str) -> ItemFn {
        syn::parse_str(s).expect("valid Rust syntax")
    }

    #[test]
    fn extracts_commit_and_range_typed() {
        let item = parse_item(
            r#"
                fn deposit(
                    #[zk_private(commit = "poseidon", range = "1000..=10000")]
                    collateral: U256,
                ) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs[0].param_name, "collateral");
        assert_eq!(attrs[0].specs.len(), 2);
        assert_eq!(attrs[0].specs[0], AttrSpec::Commit(CommitScheme::Poseidon));
        match &attrs[0].specs[1] {
            AttrSpec::Range(r) => {
                assert_eq!(r.low, "1000");
                assert_eq!(r.high, "10000");
                assert!(r.inclusive);
            }
            other => panic!("expected Range, got {other:?}"),
        }
    }

    #[test]
    fn range_half_open() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(range = "0..100")] x: u64) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        match &attrs[0].specs[0] {
            AttrSpec::Range(r) => {
                assert_eq!(r.low, "0");
                assert_eq!(r.high, "100");
                assert!(!r.inclusive);
            }
            other => panic!("expected Range, got {other:?}"),
        }
    }

    #[test]
    fn range_with_path_expr_upper_bound() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(range = "1000..=u128::MAX")] x: u64) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        match &attrs[0].specs[0] {
            AttrSpec::Range(r) => {
                assert_eq!(r.low, "1000");
                assert!(r.high.contains("u128"));
                assert!(r.high.contains("MAX"));
                assert!(r.inclusive);
            }
            other => panic!("expected Range, got {other:?}"),
        }
    }

    #[test]
    fn range_missing_upper_fails() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(range = "1000..")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        assert!(format!("{err}").contains("upper bound"));
    }

    #[test]
    fn constraint_gte_typed() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(constraint = "value >= threshold")] x: u64) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs[0].specs[0], AttrSpec::Constraint(Constraint::Gte("threshold".into())));
    }

    #[test]
    fn constraint_lt_typed() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(constraint = "value < max")] x: u64) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs[0].specs[0], AttrSpec::Constraint(Constraint::Lt("max".into())));
    }

    #[test]
    fn constraint_eq_with_function_call_rhs() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(constraint = "value == hash(other, nonce)")] x: u64) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        match &attrs[0].specs[0] {
            AttrSpec::Constraint(Constraint::Eq(rhs)) => {
                assert!(rhs.contains("hash"));
                assert!(rhs.contains("other"));
                assert!(rhs.contains("nonce"));
            }
            other => panic!("expected Eq, got {other:?}"),
        }
    }

    #[test]
    fn constraint_with_non_value_lhs_fails() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(constraint = "threshold >= value")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        assert!(format!("{err}").contains("LHS"));
    }

    #[test]
    fn constraint_unsupported_operator_fails() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(constraint = "value + 1")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("operator") || msg.contains("LHS"));
    }

    #[test]
    fn merkle_member_typed() {
        let item = parse_item(
            r#"
                fn foo(
                    #[zk_private(constraint = "merkle_member(value, root, siblings)")]
                    x: u64,
                ) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(
            attrs[0].specs[0],
            AttrSpec::MerkleMember(MerkleMemberSpec {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
            })
        );
    }

    #[test]
    fn merkle_member_wrong_first_arg_fails() {
        let item = parse_item(
            r#"
                fn foo(
                    #[zk_private(constraint = "merkle_member(other, root, siblings)")]
                    x: u64,
                ) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        assert!(format!("{err}").contains("value"));
    }

    #[test]
    fn merkle_member_wrong_arity_fails() {
        let item = parse_item(
            r#"
                fn foo(
                    #[zk_private(constraint = "merkle_member(value, root)")]
                    x: u64,
                ) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        assert!(format!("{err}").contains("3"));
    }

    #[test]
    fn multiple_constraints_compose() {
        let item = parse_item(
            r#"
                fn foo(
                    #[zk_private(
                        constraint = "value >= threshold",
                        constraint = "value < max"
                    )]
                    x: u64,
                ) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs[0].specs.len(), 2);
        assert!(
            matches!(&attrs[0].specs[0], AttrSpec::Constraint(Constraint::Gte(s)) if s == "threshold")
        );
        assert!(
            matches!(&attrs[0].specs[1], AttrSpec::Constraint(Constraint::Lt(s)) if s == "max")
        );
    }

    #[test]
    fn ignores_params_without_attribute() {
        let item = parse_item("fn foo(a: u64, b: u64) {}");
        let attrs = parse_fn(&item).unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn rejects_unknown_attribute_key() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(foobar = "anything")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        assert!(format!("{err}").contains("foobar"));
    }

    #[test]
    fn rejects_unknown_commit_scheme() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(commit = "blake3")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        assert!(format!("{err}").contains("blake3"));
    }

    #[test]
    fn extracts_multiple_params_with_attribute() {
        let item = parse_item(
            r#"
                fn foo(
                    a: u64,
                    #[zk_private(commit = "poseidon")] b: u64,
                    c: u64,
                    #[zk_private(range = "0..100")] d: u64,
                ) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].param_name, "b");
        assert_eq!(attrs[1].param_name, "d");
    }

    #[test]
    fn empty_attribute_body_yields_no_specs() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private()] x: u64) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs.len(), 1);
        assert!(attrs[0].specs.is_empty());
    }
}
