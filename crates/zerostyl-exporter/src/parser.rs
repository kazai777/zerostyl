use quote::ToTokens;
use syn::{Attribute, FnArg, ItemFn, Lit};

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
    Range(String),
    Constraint(String),
    MerkleMember(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitScheme {
    Poseidon,
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
                "range" => specs.push(AttrSpec::Range(raw)),
                "constraint" => {
                    if raw.trim_start().starts_with("merkle_member") {
                        specs.push(AttrSpec::MerkleMember(raw));
                    } else {
                        specs.push(AttrSpec::Constraint(raw));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_item(s: &str) -> ItemFn {
        syn::parse_str(s).expect("valid Rust syntax")
    }

    #[test]
    fn extracts_zk_private_param_with_commit_and_range() {
        let item = parse_item(
            r#"
                fn deposit(
                    amount: U256,
                    #[zk_private(commit = "poseidon", range = "1000..=10000")]
                    collateral: U256,
                ) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].param_name, "collateral");
        assert!(attrs[0].param_type.contains("U256"));
        assert_eq!(
            attrs[0].specs,
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Range("1000..=10000".to_string()),
            ]
        );
    }

    #[test]
    fn ignores_params_without_attribute() {
        let item = parse_item("fn foo(a: u64, b: u64) {}");
        let attrs = parse_fn(&item).unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn supports_multiple_constraints() {
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
        assert!(matches!(&attrs[0].specs[0], AttrSpec::Constraint(s) if s == "value >= threshold"));
        assert!(matches!(&attrs[0].specs[1], AttrSpec::Constraint(s) if s == "value < max"));
    }

    #[test]
    fn detects_merkle_member_constraint() {
        let item = parse_item(
            r#"
                fn foo(
                    #[zk_private(constraint = "merkle_member(value, root, siblings)")]
                    x: u64,
                ) {}
            "#,
        );
        let attrs = parse_fn(&item).unwrap();
        match &attrs[0].specs[0] {
            AttrSpec::MerkleMember(s) => assert!(s.contains("merkle_member")),
            other => panic!("expected MerkleMember, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_attribute_key() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(foobar = "anything")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("foobar"), "expected msg to mention 'foobar', got: {msg}");
    }

    #[test]
    fn rejects_unknown_commit_scheme() {
        let item = parse_item(
            r#"
                fn foo(#[zk_private(commit = "blake3")] x: u64) {}
            "#,
        );
        let err = parse_fn(&item).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("blake3"));
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
