use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::error::{ExporterError, Result};
use crate::resolver::{ComparisonOp, GadgetBinding, ResolvedAttr};

pub fn emit_circuit(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<String> {
    validate_supported(attrs)?;
    enforce_single_poseidon(attrs)?;

    let chips = collect_chip_usage(attrs);
    let circuit_ident = format_ident!("{}Circuit", to_pascal_case(circuit_name));
    let config_ident = format_ident!("{}Config", circuit_ident);

    let imports = emit_imports(&chips);
    let witness_fields = emit_witness_fields(attrs);
    let config_fields = emit_config_fields(&chips);
    let configure_body = emit_configure_body(&chips);
    let synthesize_body = emit_synthesize_body(&chips, attrs)?;

    let tokens = quote! {
        #imports

        #[derive(Clone, Debug, Default)]
        pub struct #circuit_ident {
            #( pub #witness_fields, )*
        }

        #[derive(Debug, Clone)]
        pub struct #config_ident {
            #( #config_fields, )*
            instance: Column<Instance>,
        }

        impl Circuit<Fp> for #circuit_ident {
            type Config = #config_ident;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                #configure_body
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> std::result::Result<(), Error> {
                #synthesize_body
            }
        }
    };

    Ok(tokens.to_string())
}

#[derive(Default)]
struct ChipUsage {
    poseidon: bool,
    range: bool,
    comparison: bool,
}

fn collect_chip_usage(attrs: &[ResolvedAttr]) -> ChipUsage {
    let mut u = ChipUsage::default();
    for attr in attrs {
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { .. } => u.poseidon = true,
                GadgetBinding::Range { .. } => u.range = true,
                GadgetBinding::Comparison { .. } => u.comparison = true,
                GadgetBinding::MerkleMember { .. } => {}
            }
        }
    }
    u
}

fn validate_supported(attrs: &[ResolvedAttr]) -> Result<()> {
    for attr in attrs {
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { .. }
                | GadgetBinding::Range { .. }
                | GadgetBinding::Comparison { .. } => {}
                GadgetBinding::MerkleMember { .. } => {
                    return Err(ExporterError::Parse(
                        "codegen for MerkleMember not yet implemented".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn enforce_single_poseidon(attrs: &[ResolvedAttr]) -> Result<()> {
    let count = attrs
        .iter()
        .flat_map(|a| a.bindings.iter())
        .filter(|b| matches!(b, GadgetBinding::PoseidonCommit { .. }))
        .count();
    if count > 1 {
        return Err(ExporterError::Parse(format!(
            "codegen currently supports at most one PoseidonCommit per circuit; got {count}"
        )));
    }
    Ok(())
}

fn emit_imports(chips: &ChipUsage) -> TokenStream {
    let mut gadget_items = Vec::new();
    if chips.poseidon {
        gadget_items.push(quote! { PoseidonCommitmentChip });
        gadget_items.push(quote! { PoseidonCommitmentConfig });
    }
    if chips.range {
        gadget_items.push(quote! { RangeProofChip });
        gadget_items.push(quote! { RangeProofConfig });
    }
    if chips.comparison {
        gadget_items.push(quote! { ComparisonChip });
        gadget_items.push(quote! { ComparisonConfig });
    }
    quote! {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
        };
        use halo2curves::pasta::Fp;
        use zerostyl_compiler::gadgets::{ #( #gadget_items ),* };
    }
}

fn emit_witness_fields(attrs: &[ResolvedAttr]) -> Vec<TokenStream> {
    let mut seen = std::collections::BTreeSet::new();
    let mut fields = Vec::new();
    let add = |name: &str,
               fields: &mut Vec<TokenStream>,
               seen: &mut std::collections::BTreeSet<String>| {
        if seen.insert(name.to_string()) {
            let ident = format_ident!("{}", name);
            fields.push(quote! { #ident: Value<Fp> });
        }
    };
    for attr in attrs {
        add(&attr.param_name, &mut fields, &mut seen);
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    add(nonce_var, &mut fields, &mut seen);
                }
                GadgetBinding::Comparison { other, .. } => {
                    if is_simple_ident(other) {
                        add(other, &mut fields, &mut seen);
                    }
                }
                GadgetBinding::Range { .. } | GadgetBinding::MerkleMember { .. } => {}
            }
        }
    }
    fields
}

fn emit_config_fields(chips: &ChipUsage) -> Vec<TokenStream> {
    let mut fields = Vec::new();
    if chips.poseidon {
        fields.push(quote! { poseidon_config: PoseidonCommitmentConfig });
    }
    if chips.range {
        fields.push(quote! { range_config: RangeProofConfig });
    }
    if chips.comparison {
        fields.push(quote! { comparison_config: ComparisonConfig });
    }
    fields
}

fn emit_configure_body(chips: &ChipUsage) -> TokenStream {
    let mut stmts = Vec::<TokenStream>::new();
    let mut struct_fields = Vec::<TokenStream>::new();
    if chips.poseidon {
        stmts.push(quote! { let poseidon_config = PoseidonCommitmentChip::configure(meta); });
        struct_fields.push(quote! { poseidon_config });
    }
    if chips.range {
        stmts.push(quote! { let range_config = RangeProofChip::configure(meta); });
        struct_fields.push(quote! { range_config });
    }
    if chips.comparison {
        stmts.push(quote! { let comparison_config = ComparisonChip::configure(meta); });
        struct_fields.push(quote! { comparison_config });
    }
    stmts.push(quote! {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
    });
    struct_fields.push(quote! { instance });
    quote! {
        #( #stmts )*
        Self::Config { #( #struct_fields ),* }
    }
}

fn emit_synthesize_body(chips: &ChipUsage, attrs: &[ResolvedAttr]) -> Result<TokenStream> {
    let mut stmts = Vec::<TokenStream>::new();

    if chips.poseidon {
        stmts.push(quote! {
            let poseidon_chip = PoseidonCommitmentChip::construct(config.poseidon_config);
        });
    }
    if chips.range {
        stmts.push(quote! {
            let range_chip = RangeProofChip::construct(config.range_config);
        });
    }
    if chips.comparison {
        stmts.push(quote! {
            let comparison_chip = ComparisonChip::construct(config.comparison_config);
        });
    }

    let mut instance_idx: usize = 0;

    for attr in attrs {
        let value_ident = format_ident!("{}", attr.param_name);
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    stmts.extend(emit_poseidon(
                        &attr.param_name,
                        &value_ident,
                        nonce_var,
                        instance_idx,
                    ));
                    instance_idx += 1;
                }
                GadgetBinding::Range { low, high, inclusive, num_bits } => {
                    stmts.extend(emit_range(
                        &attr.param_name,
                        &value_ident,
                        low,
                        high,
                        *inclusive,
                        *num_bits,
                    )?);
                }
                GadgetBinding::Comparison { op, other, num_bits } => {
                    stmts.extend(emit_comparison(
                        &attr.param_name,
                        &value_ident,
                        *op,
                        other,
                        *num_bits,
                    )?);
                }
                GadgetBinding::MerkleMember { .. } => unreachable!("guarded by validate_supported"),
            }
        }
    }

    stmts.push(quote! { Ok(()) });
    Ok(quote! { #( #stmts )* })
}

fn emit_poseidon(
    param_name: &str,
    value_ident: &syn::Ident,
    nonce_var: &str,
    instance_idx: usize,
) -> Vec<TokenStream> {
    let nonce_ident = format_ident!("{}", nonce_var);
    let value_cell = format_ident!("{}_poseidon_value", param_name);
    let nonce_cell = format_ident!("{}_poseidon_nonce", param_name);
    let commitment = format_ident!("{}_commitment", param_name);
    let commitment_ref = format_ident!("{}_commitment_ref", param_name);
    let load_value_label = format!("load {param_name} for poseidon");
    let load_nonce_label = format!("load {nonce_var} for poseidon");
    let commit_label = format!("commit {param_name}");
    vec![
        quote! {
            let #value_cell = poseidon_chip.load_private(
                layouter.namespace(|| #load_value_label),
                self.#value_ident,
                0,
            )?;
            let #nonce_cell = poseidon_chip.load_private(
                layouter.namespace(|| #load_nonce_label),
                self.#nonce_ident,
                1,
            )?;
            let #commitment = poseidon_chip.commit(
                layouter.namespace(|| #commit_label),
                #value_cell.clone(),
                #nonce_cell,
            )?;
            let #commitment_ref = #commitment.cell();
        },
        quote! {
            layouter.constrain_instance(#commitment_ref, config.instance, #instance_idx)?;
        },
    ]
}

fn emit_range(
    param_name: &str,
    value_ident: &syn::Ident,
    low: &str,
    high: &str,
    inclusive: bool,
    num_bits: usize,
) -> Result<Vec<TokenStream>> {
    let cell = format_ident!("{}_range_value", param_name);
    let load_label = format!("load {param_name} for range");
    let check_label = format!("range check {param_name}");
    let low_expr: syn::Expr =
        syn::parse_str(low).map_err(|e| ExporterError::Parse(format!("range low '{low}': {e}")))?;
    let high_expr: syn::Expr = syn::parse_str(high)
        .map_err(|e| ExporterError::Parse(format!("range high '{high}': {e}")))?;
    let high_call = if inclusive {
        quote! { Fp::from((#high_expr) as u64) }
    } else {
        quote! { Fp::from(((#high_expr) as u64) - 1) }
    };
    Ok(vec![quote! {
        let #cell = range_chip.load_value(
            layouter.namespace(|| #load_label),
            self.#value_ident,
        )?;
        range_chip.check_range_bounded(
            layouter.namespace(|| #check_label),
            #cell,
            Fp::from((#low_expr) as u64),
            #high_call,
            #num_bits,
        )?;
    }])
}

fn emit_comparison(
    param_name: &str,
    value_ident: &syn::Ident,
    op: ComparisonOp,
    other: &str,
    num_bits: usize,
) -> Result<Vec<TokenStream>> {
    let value_cell = format_ident!("{}_cmp_value", param_name);
    let load_value_label = format!("load {param_name} for comparison");
    let cmp_label = format!("{} {} {}", param_name, op_symbol(op), other);
    let method = op_method(op)?;
    let method_ident = format_ident!("{}", method);

    let (load_other_stmts, other_cell_token) = if is_simple_ident(other) {
        let other_ident = format_ident!("{}", other);
        let other_cell = format_ident!("{}_cmp_value", other);
        let load_other_label = format!("load {other} for comparison");
        (
            vec![quote! {
                let #other_cell = comparison_chip.load_value(
                    layouter.namespace(|| #load_other_label),
                    self.#other_ident,
                )?;
            }],
            quote! { #other_cell },
        )
    } else {
        return Err(ExporterError::Parse(format!(
            "comparison RHS must currently be a simple identifier (other fn param); got '{other}'"
        )));
    };

    let mut stmts = vec![quote! {
        let #value_cell = comparison_chip.load_value(
            layouter.namespace(|| #load_value_label),
            self.#value_ident,
        )?;
    }];
    stmts.extend(load_other_stmts);
    stmts.push(quote! {
        comparison_chip.#method_ident(
            layouter.namespace(|| #cmp_label),
            #value_cell,
            #other_cell_token,
            #num_bits,
        )?;
    });
    Ok(stmts)
}

fn op_method(op: ComparisonOp) -> Result<&'static str> {
    match op {
        ComparisonOp::Gt => Ok("assert_gt"),
        ComparisonOp::Gte => Ok("assert_ge"),
        ComparisonOp::Lt => Ok("assert_lt"),
        ComparisonOp::Lte => Ok("assert_le"),
        ComparisonOp::Eq => Err(ExporterError::Parse(
            "equality comparison not supported by ComparisonChip; use a different gadget".into(),
        )),
    }
}

fn op_symbol(op: ComparisonOp) -> &'static str {
    match op {
        ComparisonOp::Gt => ">",
        ComparisonOp::Gte => ">=",
        ComparisonOp::Lt => "<",
        ComparisonOp::Lte => "<=",
        ComparisonOp::Eq => "==",
    }
}

fn is_simple_ident(s: &str) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty()
        && trimmed.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn to_pascal_case(s: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for c in s.chars() {
        if c == '_' {
            capitalize = true;
        } else if capitalize {
            out.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AttrSpec, CommitScheme, Constraint, RangeSpec};
    use crate::resolver::resolve;

    fn resolved(name: &str, ty: &str, specs: Vec<AttrSpec>) -> ResolvedAttr {
        let parsed =
            crate::parser::ZkPrivateAttr { param_name: name.into(), param_type: ty.into(), specs };
        resolve(&parsed).unwrap()
    }

    fn parse_as_file(src: &str) -> syn::File {
        syn::parse_str(src)
            .unwrap_or_else(|e| panic!("generated code does not parse as Rust:\n{src}\nerror: {e}"))
    }

    #[test]
    fn pascal_case_basic() {
        assert_eq!(to_pascal_case("deposit"), "Deposit");
        assert_eq!(to_pascal_case("private_lending"), "PrivateLending");
        assert_eq!(to_pascal_case("zk_swap_v2"), "ZkSwapV2");
    }

    #[test]
    fn poseidon_only_circuit_parses() {
        let attrs =
            vec![resolved("collateral", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_circuit("deposit", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("PoseidonCommitmentChip"));
        assert!(!src.contains("RangeProofChip"));
    }

    #[test]
    fn range_only_circuit_parses() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "100".into(),
                inclusive: true,
            })],
        )];
        let src = emit_circuit("foo", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("RangeProofChip"));
        assert!(src.contains("check_range_bounded"));
        assert!(src.contains("Fp :: from ((0) as u64)") || src.contains("Fp::from((0) as u64)"));
    }

    #[test]
    fn range_exclusive_subtracts_one() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "100".into(),
                inclusive: false,
            })],
        )];
        let src = emit_circuit("foo", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("as u64) - 1"));
    }

    #[test]
    fn comparison_circuit_parses_and_calls_assert_ge() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))],
        )];
        let src = emit_circuit("foo", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("ComparisonChip"));
        assert!(src.contains("assert_ge"));
        assert!(src.contains("threshold"));
    }

    #[test]
    fn comparison_methods_per_op() {
        for (op, method) in [
            (Constraint::Gt("y".into()), "assert_gt"),
            (Constraint::Gte("y".into()), "assert_ge"),
            (Constraint::Lt("y".into()), "assert_lt"),
            (Constraint::Lte("y".into()), "assert_le"),
        ] {
            let attrs = vec![resolved("x", "u64", vec![AttrSpec::Constraint(op)])];
            let src = emit_circuit("foo", &attrs).unwrap();
            assert!(src.contains(method), "missing {method} in:\n{src}");
        }
    }

    #[test]
    fn comparison_eq_rejected() {
        let attrs =
            vec![resolved("x", "u64", vec![AttrSpec::Constraint(Constraint::Eq("y".into()))])];
        let err = emit_circuit("foo", &attrs).unwrap_err();
        assert!(format!("{err}").contains("equality"));
    }

    #[test]
    fn comparison_other_added_as_witness() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))],
        )];
        let src = emit_circuit("foo", &attrs).unwrap();
        // both x and threshold should appear as struct fields
        assert!(src.contains("x : Value < Fp >") || src.contains("x: Value<Fp>"));
        assert!(src.contains("threshold : Value < Fp >") || src.contains("threshold: Value<Fp>"));
    }

    #[test]
    fn multi_gadget_composition_parses() {
        let attrs = vec![resolved(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Range(RangeSpec {
                    low: "1000".into(),
                    high: "10000".into(),
                    inclusive: true,
                }),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        )];
        let src = emit_circuit("deposit", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("PoseidonCommitmentChip"));
        assert!(src.contains("RangeProofChip"));
        assert!(src.contains("ComparisonChip"));
        assert!(src.contains("poseidon_config"));
        assert!(src.contains("range_config"));
        assert!(src.contains("comparison_config"));
        assert!(src.contains("DepositCircuit"));
    }

    #[test]
    fn merkle_member_still_rejected() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::MerkleMember(crate::parser::MerkleMemberSpec {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
            })],
        )];
        let err = emit_circuit("foo", &attrs).unwrap_err();
        assert!(format!("{err}").contains("MerkleMember"));
    }

    #[test]
    fn rejects_multiple_poseidon_commits() {
        let attrs = vec![
            resolved("a", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)]),
            resolved("b", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)]),
        ];
        let err = emit_circuit("foo", &attrs).unwrap_err();
        assert!(format!("{err}").contains("at most one PoseidonCommit"));
    }

    #[test]
    fn witness_dedup_keeps_single_field_per_name() {
        // x is referenced twice (as the annotated param and as the param itself); should appear once.
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![
                AttrSpec::Range(RangeSpec { low: "0".into(), high: "100".into(), inclusive: true }),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        )];
        let src = emit_circuit("foo", &attrs).unwrap();
        // count occurrences of "x : Value" or "x: Value"
        let count = src.matches("x : Value").count() + src.matches("x: Value").count();
        assert_eq!(count, 1, "x should appear once as a witness field, got {count}:\n{src}");
    }
}
