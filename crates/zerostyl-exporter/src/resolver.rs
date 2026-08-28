use syn::ItemFn;

use crate::error::{ExporterError, Result};
use crate::parser::{
    parse_fn, parse_signature, AttrSpec, CommitScheme, Constraint, FnParam, ZkPrivateAttr,
};

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
    Comparison { op: ComparisonOp, other: String, operand: OperandBinding, num_bits: usize },
    /// `MerkleTreeChip::verify_membership(value, root_var, siblings_var, indices_var, depth)`
    MerkleMember { root_var: String, siblings_var: String, indices_var: String, depth: usize },
}

/// How a constraint operand is bound in the generated circuit.
///
/// Every operand must land in exactly one of these buckets: an operand that stays unclassified
/// would be assigned as a free witness the prover picks, so `collateral >= threshold` would prove
/// `collateral >= <whatever the prover chose>` rather than the statement the contract call makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandBinding {
    /// Another `#[zk_private]` parameter: stays a private witness, anchored by its own commitment.
    PrivateWitness,
    /// A plain (non-annotated) function parameter: bound to an instance cell, and forwarded by the
    /// transformed contract from its argument of the same name.
    PublicInput { ty: String },
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

/// One cell of the circuit's single instance column, in canonical order.
///
/// This is the one source of truth the circuit, the descriptor, `abi.json`, and the transformed
/// contract all derive their public inputs from — they cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicInput {
    /// Poseidon commitment of an annotated parameter (`{param}_commitment`).
    Commitment { param: String },
    /// A public function parameter used by a constraint, bound to an instance cell.
    Param { name: String, ty: String },
    /// The Merkle root recomputed from the membership path.
    MerkleRoot { root_var: String },
}

impl PublicInput {
    /// Name of this cell in `abi.json` and in the transformed contract's signature.
    pub fn name(&self) -> String {
        match self {
            PublicInput::Commitment { param } => format!("{param}_commitment"),
            PublicInput::Param { name, .. } => name.clone(),
            PublicInput::MerkleRoot { root_var } => root_var.clone(),
        }
    }
}

/// Order in which a parameter's bindings contribute instance cells.
pub fn binding_priority(b: &GadgetBinding) -> u8 {
    match b {
        GadgetBinding::PoseidonCommit { .. } => 0,
        GadgetBinding::Range { .. } => 1,
        GadgetBinding::Comparison { .. } => 2,
        GadgetBinding::MerkleMember { .. } => 3,
    }
}

/// Canonical instance layout: per annotated parameter in declaration order, bindings sorted by
/// [`binding_priority`], deduplicated by name (a public parameter used by two constraints is bound
/// once).
pub fn public_input_layout(attrs: &[ResolvedAttr]) -> Vec<PublicInput> {
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut out = Vec::new();
    let mut push = |pi: PublicInput, out: &mut Vec<PublicInput>| {
        if seen.insert(pi.name()) {
            out.push(pi);
        }
    };
    for attr in attrs {
        let mut sorted = attr.bindings.clone();
        sorted.sort_by_key(binding_priority);
        for b in &sorted {
            match b {
                GadgetBinding::PoseidonCommit { .. } => {
                    push(PublicInput::Commitment { param: attr.param_name.clone() }, &mut out);
                }
                GadgetBinding::Comparison {
                    other,
                    operand: OperandBinding::PublicInput { ty },
                    ..
                } => {
                    push(PublicInput::Param { name: other.clone(), ty: ty.clone() }, &mut out);
                }
                // The Merkle membership exposes its recomputed root so the verifier checks the path
                // against a root it supplies (see codegen::emit_merkle).
                GadgetBinding::MerkleMember { root_var, .. } => {
                    push(PublicInput::MerkleRoot { root_var: root_var.clone() }, &mut out);
                }
                GadgetBinding::Comparison { .. } | GadgetBinding::Range { .. } => {}
            }
        }
    }
    out
}

/// Parse and resolve an annotated function in one step.
pub fn resolve_fn(item_fn: &ItemFn) -> Result<Vec<ResolvedAttr>> {
    let attrs = parse_fn(item_fn)?;
    let params = parse_signature(item_fn)?;
    resolve_all(&attrs, &params)
}

pub fn resolve(attr: &ZkPrivateAttr, params: &[FnParam]) -> Result<ResolvedAttr> {
    let num_bits = num_bits_of(&attr.param_type)?;
    let mut bindings = Vec::with_capacity(attr.specs.len());
    for spec in &attr.specs {
        bindings.push(resolve_spec(spec, &attr.param_name, num_bits, params)?);
    }
    Ok(ResolvedAttr {
        param_name: attr.param_name.clone(),
        param_type: attr.param_type.clone(),
        bindings,
    })
}

pub fn resolve_all(attrs: &[ZkPrivateAttr], params: &[FnParam]) -> Result<Vec<ResolvedAttr>> {
    let resolved: Vec<ResolvedAttr> =
        attrs.iter().map(|a| resolve(a, params)).collect::<Result<_>>()?;
    validate_generated_names(&resolved, params)?;
    Ok(resolved)
}

fn resolve_spec(
    spec: &AttrSpec,
    param_name: &str,
    num_bits: usize,
    params: &[FnParam],
) -> Result<GadgetBinding> {
    Ok(match spec {
        AttrSpec::Commit(CommitScheme::Poseidon) => {
            GadgetBinding::PoseidonCommit { nonce_var: format!("{param_name}_nonce") }
        }
        AttrSpec::Range(r) => {
            validate_range_bound(param_name, "lower", &r.low)?;
            validate_range_bound(param_name, "upper", &r.high)?;
            GadgetBinding::Range {
                low: r.low.clone(),
                high: r.high.clone(),
                inclusive: r.inclusive,
                num_bits,
            }
        }
        AttrSpec::Constraint(c) => {
            let (op, other) = comparison_parts(c);
            let other = other.trim().to_string();
            let operand = classify_operand(&other, param_name, num_bits, params)?;
            GadgetBinding::Comparison { op, other, operand, num_bits }
        }
        AttrSpec::MerkleMember(m) => GadgetBinding::MerkleMember {
            root_var: m.root_var.clone(),
            siblings_var: m.siblings_var.clone(),
            indices_var: m.indices_var.clone(),
            depth: MERKLE_DEPTH,
        },
    })
}

/// Decide how a constraint's right-hand operand is bound, rejecting anything that cannot be tied
/// to a value the verifier sees.
fn classify_operand(
    other: &str,
    owner: &str,
    num_bits: usize,
    params: &[FnParam],
) -> Result<OperandBinding> {
    let trimmed = other.trim();
    if !is_simple_ident(trimmed) {
        // A literal is a value nobody binds: the gadgets have no constant-load path, so it would be
        // assigned as an ordinary (prover-chosen) advice cell.
        if trimmed.parse::<u128>().is_ok() || syn::parse_str::<syn::LitInt>(trimmed).is_ok() {
            return Err(ExporterError::Parse(format!(
                "constraint operand '{trimmed}' on '{owner}' is a literal constant; constants \
                 cannot currently be bound to a cell the verifier checks — express the bound with \
                 `range = \"low..=high\"`, or pass it as a function parameter"
            )));
        }
        return Err(ExporterError::Parse(format!(
            "constraint operand '{trimmed}' on '{owner}' does not resolve to a value: it must be a \
             plain identifier naming a parameter of the same function (derived expressions and \
             calls are not supported)"
        )));
    }
    if trimmed == owner {
        return Err(ExporterError::Parse(format!(
            "constraint operand '{trimmed}' on '{owner}' refers to the annotated parameter itself"
        )));
    }
    let param = params.iter().find(|p| p.name == trimmed).ok_or_else(|| {
        ExporterError::Parse(format!(
            "constraint operand '{trimmed}' on '{owner}' names no parameter of the function; every \
             operand must be a parameter so the proof binds it"
        ))
    })?;

    let other_bits = num_bits_of(&param.ty).map_err(|e| {
        ExporterError::Parse(format!("constraint operand '{trimmed}' on '{owner}': {e}"))
    })?;
    if other_bits != num_bits {
        return Err(ExporterError::Parse(format!(
            "constraint operand '{trimmed}' has type '{}' ({other_bits} bits) but '{owner}' is \
             {num_bits} bits; comparison operands must share a bit width (the gadget range-checks \
             both at the same width)",
            param.ty.trim()
        )));
    }

    if param.is_private {
        Ok(OperandBinding::PrivateWitness)
    } else {
        Ok(OperandBinding::PublicInput { ty: param.ty.clone() })
    }
}

/// Names the codegen synthesizes must not clash with names the source already uses.
fn validate_generated_names(attrs: &[ResolvedAttr], params: &[FnParam]) -> Result<()> {
    let taken = |name: &str| params.iter().any(|p| p.name == name);
    let mut generated = std::collections::BTreeSet::<String>::new();
    let mut claim = |name: String, what: &str| -> Result<()> {
        if !generated.insert(name.clone()) {
            return Err(ExporterError::Parse(format!(
                "name collision: '{name}' ({what}) is generated twice"
            )));
        }
        Ok(())
    };

    for attr in attrs {
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    if taken(nonce_var) {
                        return Err(ExporterError::Parse(format!(
                            "name collision: the commitment nonce witness for '{}' is called \
                             '{nonce_var}', which is already a function parameter",
                            attr.param_name
                        )));
                    }
                    claim(nonce_var.clone(), "commitment nonce")?;
                    let commitment = format!("{}_commitment", attr.param_name);
                    if taken(&commitment) {
                        return Err(ExporterError::Parse(format!(
                            "name collision: '{commitment}' is a function parameter, but the \
                             transformed contract generates an argument of that name for '{}'",
                            attr.param_name
                        )));
                    }
                    claim(commitment, "commitment argument")?;
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    for (var, what) in [
                        (root_var, "merkle root"),
                        (siblings_var, "merkle siblings"),
                        (indices_var, "merkle path indices"),
                    ] {
                        if taken(var) {
                            return Err(ExporterError::Parse(format!(
                                "name collision: '{var}' ({what} of '{}') is already a function \
                                 parameter; merkle_member variables name witness fields the \
                                 codegen creates",
                                attr.param_name
                            )));
                        }
                        claim(var.clone(), what)?;
                    }
                }
                GadgetBinding::Comparison { .. } | GadgetBinding::Range { .. } => {}
            }
        }
    }
    Ok(())
}

/// Range bounds become `Fr::from((<bound>) as u64)` in the generated circuit, so a literal that
/// does not fit in a `u64` would silently wrap into a different field element.
fn validate_range_bound(param_name: &str, which: &str, bound: &str) -> Result<()> {
    let trimmed = bound.trim();
    let Ok(lit) = syn::parse_str::<syn::LitInt>(trimmed) else {
        // Not a literal (e.g. `u128::MAX`, a const path): nothing to check at generation time.
        return Ok(());
    };
    if lit.base10_parse::<u64>().is_err() {
        return Err(ExporterError::Parse(format!(
            "range {which} bound '{trimmed}' on '{param_name}' does not fit in a u64; range bounds \
             are cast to u64 before being mapped into the BN254 scalar field"
        )));
    }
    Ok(())
}

fn is_simple_ident(s: &str) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty()
        && trimmed.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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

    fn private(name: &str, ty: &str) -> FnParam {
        FnParam { name: name.into(), ty: ty.into(), is_private: true }
    }

    fn public(name: &str, ty: &str) -> FnParam {
        FnParam { name: name.into(), ty: ty.into(), is_private: false }
    }

    /// Resolve a single attr against a signature that declares it (plus `extra` params).
    fn resolve_one(a: &ZkPrivateAttr, extra: Vec<FnParam>) -> Result<ResolvedAttr> {
        let mut params = vec![private(&a.param_name, &a.param_type)];
        params.extend(extra);
        resolve(a, &params)
    }

    fn item(src: &str) -> syn::ItemFn {
        syn::parse_str(src).expect("valid Rust syntax")
    }

    #[test]
    fn poseidon_commit_yields_nonce_var_by_convention() {
        let a = attr("collateral", "U256", vec![AttrSpec::Commit(CommitScheme::Poseidon)]);
        let r = resolve_one(&a, vec![]).unwrap();
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
        let r = resolve_one(&a, vec![]).unwrap();
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
        let r = resolve_one(&a, vec![]).unwrap();
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
    fn range_literal_bound_beyond_u64_is_rejected() {
        // The generated circuit casts range bounds to u64; a wider literal would wrap silently.
        let a = attr(
            "x",
            "U256",
            vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "340282366920938463463374607431768211455".into(),
                inclusive: true,
            })],
        );
        let err = resolve_one(&a, vec![]).unwrap_err();
        assert!(format!("{err}").contains("does not fit in a u64"));
    }

    #[test]
    fn comparison_against_public_param_is_a_public_input() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))]);
        let r = resolve_one(&a, vec![public("threshold", "u64")]).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Comparison {
                op: ComparisonOp::Gte,
                other: "threshold".into(),
                operand: OperandBinding::PublicInput { ty: "u64".into() },
                num_bits: 64,
            }
        );
    }

    #[test]
    fn comparison_against_another_private_param_stays_a_witness() {
        let a = attr("x", "u32", vec![AttrSpec::Constraint(Constraint::Lt("max".into()))]);
        let r = resolve_one(&a, vec![private("max", "u32")]).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Comparison {
                op: ComparisonOp::Lt,
                other: "max".into(),
                operand: OperandBinding::PrivateWitness,
                num_bits: 32,
            }
        );
    }

    #[test]
    fn comparison_against_unknown_variable_is_rejected() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("nowhere".into()))]);
        let err = resolve_one(&a, vec![]).unwrap_err();
        assert!(format!("{err}").contains("names no parameter"));
    }

    #[test]
    fn comparison_against_constant_is_rejected() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("100".into()))]);
        let err = resolve_one(&a, vec![]).unwrap_err();
        assert!(format!("{err}").contains("literal constant"));
    }

    #[test]
    fn comparison_against_derived_expression_is_rejected() {
        let a = attr(
            "x",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Eq("hash (other , nonce)".into()))],
        );
        let err = resolve_one(&a, vec![public("other", "u64")]).unwrap_err();
        assert!(format!("{err}").contains("does not resolve to a value"));
    }

    #[test]
    fn comparison_against_itself_is_rejected() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("x".into()))]);
        let err = resolve_one(&a, vec![]).unwrap_err();
        assert!(format!("{err}").contains("itself"));
    }

    #[test]
    fn comparison_with_mismatched_operand_width_is_rejected() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))]);
        let err = resolve_one(&a, vec![public("threshold", "U256")]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("bit width"), "got: {msg}");
    }

    #[test]
    fn comparison_with_unmappable_operand_type_is_rejected() {
        let a = attr("x", "u64", vec![AttrSpec::Constraint(Constraint::Gte("weird".into()))]);
        let err = resolve_one(&a, vec![public("weird", "MyCustomType")]).unwrap_err();
        assert!(format!("{err}").contains("MyCustomType"));
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
        let r = resolve_one(&a, vec![]).unwrap();
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
        let r = resolve_one(&a, vec![public("threshold", "U256")]).unwrap();
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
        let err = resolve_one(&a, vec![]).unwrap_err();
        assert!(format!("{err}").contains("MyCustomType"));
    }

    #[test]
    fn path_qualified_type_resolves() {
        let a = attr(
            "x",
            "alloy_primitives :: U256",
            vec![AttrSpec::Constraint(Constraint::Gte("y".into()))],
        );
        let r = resolve_one(&a, vec![public("y", "U256")]).unwrap();
        assert!(matches!(r.bindings[0], GadgetBinding::Comparison { num_bits: 256, .. }));
    }

    #[test]
    fn bool_type_resolves_to_1_bit() {
        let a = attr("flag", "bool", vec![AttrSpec::Constraint(Constraint::Eq("expected".into()))]);
        let r = resolve_one(&a, vec![public("expected", "bool")]).unwrap();
        assert_eq!(
            r.bindings[0],
            GadgetBinding::Comparison {
                op: ComparisonOp::Eq,
                other: "expected".into(),
                operand: OperandBinding::PublicInput { ty: "bool".into() },
                num_bits: 1,
            }
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
        let params = vec![private("a", "u64"), private("b", "U256")];
        let resolved = resolve_all(&attrs, &params).unwrap();
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
        let params = vec![private("a", "u64"), private("b", "Unknown")];
        let err = resolve_all(&attrs, &params).unwrap_err();
        assert!(format!("{err}").contains("Unknown"));
    }

    #[test]
    fn nonce_witness_colliding_with_a_parameter_is_rejected() {
        let attrs = vec![attr("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let params = vec![private("x", "u64"), public("x_nonce", "u64")];
        let err = resolve_all(&attrs, &params).unwrap_err();
        assert!(format!("{err}").contains("name collision"));
    }

    #[test]
    fn commitment_argument_colliding_with_a_parameter_is_rejected() {
        let attrs = vec![attr("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let params = vec![private("x", "u64"), public("x_commitment", "u64")];
        let err = resolve_all(&attrs, &params).unwrap_err();
        assert!(format!("{err}").contains("name collision"));
    }

    #[test]
    fn merkle_variable_colliding_with_a_parameter_is_rejected() {
        let attrs = vec![attr(
            "leaf",
            "U256",
            vec![AttrSpec::MerkleMember(MerkleMemberSpec {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
                indices_var: "indices".into(),
            })],
        )];
        let params = vec![private("leaf", "U256"), public("root", "u64")];
        let err = resolve_all(&attrs, &params).unwrap_err();
        assert!(format!("{err}").contains("name collision"));
    }

    #[test]
    fn resolve_fn_binds_a_public_parameter_operand() {
        let f = item(
            r#"
                fn deposit(
                    #[zk_private(commit = "poseidon", constraint = "value >= threshold")]
                    collateral: u64,
                    threshold: u64,
                ) -> bool { true }
            "#,
        );
        let resolved = resolve_fn(&f).unwrap();
        let layout = public_input_layout(&resolved);
        let names: Vec<String> = layout.iter().map(PublicInput::name).collect();
        assert_eq!(names, vec!["collateral_commitment", "threshold"]);
    }

    #[test]
    fn public_input_layout_deduplicates_a_shared_operand() {
        let f = item(
            r#"
                fn f(
                    #[zk_private(commit = "poseidon", constraint = "value >= floor")] a: u64,
                    #[zk_private(commit = "poseidon", constraint = "value >= floor")] b: u64,
                    floor: u64,
                ) -> bool { true }
            "#,
        );
        let resolved = resolve_fn(&f).unwrap();
        let names: Vec<String> =
            public_input_layout(&resolved).iter().map(PublicInput::name).collect();
        assert_eq!(names, vec!["a_commitment", "floor", "b_commitment"]);
    }

    #[test]
    fn public_input_layout_orders_commitment_before_merkle_root() {
        let f = item(
            r#"
                fn claim(
                    #[zk_private(
                        commit = "poseidon",
                        constraint = "merkle_member(value, root, siblings, indices)"
                    )]
                    leaf: U256,
                ) -> bool { true }
            "#,
        );
        let resolved = resolve_fn(&f).unwrap();
        let names: Vec<String> =
            public_input_layout(&resolved).iter().map(PublicInput::name).collect();
        assert_eq!(names, vec!["leaf_commitment", "root"]);
    }
}
