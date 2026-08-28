use std::collections::BTreeSet;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::error::{ExporterError, Result};
use crate::resolver::{
    binding_priority, public_input_layout, ComparisonOp, GadgetBinding, OperandBinding,
    PublicInput, ResolvedAttr, MERKLE_DEPTH,
};

/// Map each canonical public input to its index in the circuit's instance column.
fn instance_indices(attrs: &[ResolvedAttr]) -> std::collections::BTreeMap<String, usize> {
    public_input_layout(attrs).iter().enumerate().map(|(i, pi)| (pi.name(), i)).collect()
}

pub fn emit_circuit(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<String> {
    enforce_single_poseidon(attrs)?;
    validate_merkle_pairing(attrs)?;

    let chips = collect_chip_usage(attrs);
    let circuit_ident = format_ident!("{}Circuit", to_pascal_case(circuit_name));
    let config_ident = format_ident!("{}Config", circuit_ident);

    let imports = emit_imports(&chips);
    let depth_const = if chips.merkle {
        quote! { pub const MERKLE_DEPTH: usize = 32; }
    } else {
        quote! {}
    };

    let witness_fields = emit_witness_fields(attrs);
    let config_fields = emit_config_fields(&chips);
    let configure_body = emit_configure_body(&chips);
    let synthesize_body = emit_synthesize_body(&chips, attrs)?;
    let (struct_derive, default_impl) = emit_struct_derive(attrs, &circuit_ident);

    let tokens = quote! {
        #![allow(clippy::all, dead_code)]

        #imports

        #depth_const

        #struct_derive
        pub struct #circuit_ident {
            #( pub #witness_fields, )*
        }

        #default_impl

        #[derive(Debug, Clone)]
        pub struct #config_ident {
            #( #config_fields, )*
            instance: Column<Instance>,
        }

        impl Circuit<Fr> for #circuit_ident {
            type Config = #config_ident;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
                #configure_body
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fr>,
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
    merkle: bool,
}

fn collect_chip_usage(attrs: &[ResolvedAttr]) -> ChipUsage {
    let mut u = ChipUsage::default();
    for attr in attrs {
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { .. } => u.poseidon = true,
                GadgetBinding::Range { .. } => u.range = true,
                GadgetBinding::Comparison { .. } => {
                    u.comparison = true;
                    // Comparison operands must be range-checked before asserting (assert_*
                    // reduces to a range check on their difference, sound only for in-range
                    // operands), so a standalone range chip is always required alongside it.
                    u.range = true;
                }
                GadgetBinding::MerkleMember { .. } => u.merkle = true,
            }
        }
    }
    u
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

fn validate_merkle_pairing(attrs: &[ResolvedAttr]) -> Result<()> {
    for attr in attrs {
        let has_merkle =
            attr.bindings.iter().any(|b| matches!(b, GadgetBinding::MerkleMember { .. }));
        let has_poseidon =
            attr.bindings.iter().any(|b| matches!(b, GadgetBinding::PoseidonCommit { .. }));
        if has_merkle && !has_poseidon {
            return Err(ExporterError::Parse(format!(
                "MerkleMember on '{}' requires a PoseidonCommit on the same param (the commitment becomes the leaf)",
                attr.param_name
            )));
        }
    }
    Ok(())
}

/// Every `#[zk_private]` parameter must carry a `commit = "poseidon"` binding.
///
/// Without a commitment the value has no public anchor: the range/comparison statements would be
/// about a witness tied to nothing observable on-chain, and the transformed contract would still
/// expose a `{param}_commitment: B256` argument that binds no proof — a soundness footgun. The
/// commitment is what ties the private value to a public input the verifier checks.
fn validate_commit_present(attrs: &[ResolvedAttr]) -> Result<()> {
    for attr in attrs {
        let has_poseidon =
            attr.bindings.iter().any(|b| matches!(b, GadgetBinding::PoseidonCommit { .. }));
        if !has_poseidon {
            return Err(ExporterError::Parse(format!(
                "#[zk_private] parameter '{}' must include `commit = \"poseidon\"`: without a \
                 commitment its constraints bind no public input and the transformed contract's \
                 `{}_commitment` argument would be meaningless",
                attr.param_name, attr.param_name
            )));
        }
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
    if chips.merkle {
        gadget_items.push(quote! { MerkleTreeChip });
        gadget_items.push(quote! { MerkleTreeConfig });
    }
    quote! {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
        };
        use halo2curves::bn256::Fr;
        use zerostyl_compiler::gadgets::{ #( #gadget_items ),* };
    }
}

enum FieldKind {
    Scalar,
    VecScalar,
}

fn emit_witness_fields(attrs: &[ResolvedAttr]) -> Vec<TokenStream> {
    let mut seen = std::collections::BTreeMap::<String, FieldKind>::new();
    let mut ordered: Vec<(String, FieldKind)> = Vec::new();
    let add = |name: &str,
               kind: FieldKind,
               seen: &mut std::collections::BTreeMap<String, FieldKind>,
               ordered: &mut Vec<(String, FieldKind)>| {
        if !seen.contains_key(name) {
            ordered.push((
                name.to_string(),
                match kind {
                    FieldKind::Scalar => FieldKind::Scalar,
                    FieldKind::VecScalar => FieldKind::VecScalar,
                },
            ));
            seen.insert(name.to_string(), kind);
        }
    };
    for attr in attrs {
        add(&attr.param_name, FieldKind::Scalar, &mut seen, &mut ordered);
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    add(nonce_var, FieldKind::Scalar, &mut seen, &mut ordered);
                }
                GadgetBinding::Comparison { other, .. } => {
                    add(other, FieldKind::Scalar, &mut seen, &mut ordered);
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    add(root_var, FieldKind::Scalar, &mut seen, &mut ordered);
                    add(siblings_var, FieldKind::VecScalar, &mut seen, &mut ordered);
                    add(indices_var, FieldKind::VecScalar, &mut seen, &mut ordered);
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }
    ordered
        .into_iter()
        .map(|(name, kind)| {
            let ident = format_ident!("{}", name);
            match kind {
                FieldKind::Scalar => quote! { #ident: Value<Fr> },
                FieldKind::VecScalar => quote! { #ident: Vec<Value<Fr>> },
            }
        })
        .collect()
}

fn emit_struct_derive(
    attrs: &[ResolvedAttr],
    circuit_ident: &syn::Ident,
) -> (TokenStream, TokenStream) {
    let has_vec = attrs
        .iter()
        .any(|a| a.bindings.iter().any(|b| matches!(b, GadgetBinding::MerkleMember { .. })));
    if !has_vec {
        return (quote! { #[derive(Clone, Debug, Default)] }, quote! {});
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut inits = Vec::<TokenStream>::new();
    let push_scalar = |name: &str,
                       inits: &mut Vec<TokenStream>,
                       seen: &mut std::collections::BTreeSet<String>| {
        if seen.insert(name.to_string()) {
            let ident = format_ident!("{}", name);
            inits.push(quote! { #ident: Value::unknown() });
        }
    };
    let push_vec = |name: &str,
                    inits: &mut Vec<TokenStream>,
                    seen: &mut std::collections::BTreeSet<String>| {
        if seen.insert(name.to_string()) {
            let ident = format_ident!("{}", name);
            inits.push(quote! { #ident: vec![Value::unknown(); MERKLE_DEPTH] });
        }
    };
    for attr in attrs {
        push_scalar(&attr.param_name, &mut inits, &mut seen);
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    push_scalar(nonce_var, &mut inits, &mut seen);
                }
                GadgetBinding::Comparison { other, .. } => {
                    push_scalar(other, &mut inits, &mut seen);
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    push_scalar(root_var, &mut inits, &mut seen);
                    push_vec(siblings_var, &mut inits, &mut seen);
                    push_vec(indices_var, &mut inits, &mut seen);
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }

    let default_impl = quote! {
        impl Default for #circuit_ident {
            fn default() -> Self {
                Self { #( #inits, )* }
            }
        }
    };
    (quote! { #[derive(Clone, Debug)] }, default_impl)
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
    if chips.merkle {
        fields.push(quote! { merkle_config: MerkleTreeConfig });
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
    if chips.merkle {
        stmts.push(quote! { let merkle_config = MerkleTreeChip::configure(meta); });
        struct_fields.push(quote! { merkle_config });
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
    if chips.merkle {
        stmts.push(quote! {
            let merkle_chip = MerkleTreeChip::construct(config.merkle_config.clone());
        });
    }

    // --- Load pass ---
    // Load each private value into a SINGLE canonical advice cell, then reuse that exact cell
    // (each chip copy_advices it into its own region) across the commitment, range, and
    // comparison gadgets. Loading a fresh cell per gadget would leave the range/comparison
    // statements about free witnesses decoupled from the committed value — a soundness hole.
    // Mirrors the hand-written state_mask circuit.
    let mut loaded: BTreeSet<String> = BTreeSet::new();
    for attr in attrs {
        let param = &attr.param_name;
        let value_cell = format_ident!("{}_value", param);
        let value_field = format_ident!("{}", param);
        let load_label = format!("load {param}");
        // Load through whichever chip will constrain the value, so the canonical cell lives in
        // an equality-enabled column; the other gadgets copy from it.
        let loader = if attr_has_range(attr) {
            quote! { range_chip.load_value(layouter.namespace(|| #load_label), self.#value_field)? }
        } else if attr_has_comparison(attr) {
            quote! {
                comparison_chip.load_value(layouter.namespace(|| #load_label), self.#value_field)?
            }
        } else {
            quote! {
                poseidon_chip.load_private(layouter.namespace(|| #load_label), self.#value_field, 0)?
            }
        };
        stmts.push(quote! { let #value_cell = #loader; });
        loaded.insert(param.clone());

        if let Some(nonce_var) = attr_poseidon_nonce(attr) {
            let nonce_cell = format_ident!("{}_nonce_cell", param);
            let nonce_field = format_ident!("{}", nonce_var);
            let load_nonce_label = format!("load {nonce_var}");
            stmts.push(quote! {
                let #nonce_cell = poseidon_chip.load_private(
                    layouter.namespace(|| #load_nonce_label),
                    self.#nonce_field,
                    1,
                )?;
            });
        }
    }
    // Load any comparison right-hand-side operand that is not itself a loaded private value.
    for attr in attrs {
        for b in &attr.bindings {
            if let GadgetBinding::Comparison { other, .. } = b {
                if !is_simple_ident(other) {
                    return Err(ExporterError::Parse(format!(
                        "comparison RHS must currently be a simple identifier (other fn param); got '{other}'"
                    )));
                }
                if loaded.insert(other.clone()) {
                    let other_cell = format_ident!("{}_value", other);
                    let other_field = format_ident!("{}", other);
                    let load_label = format!("load {other}");
                    stmts.push(quote! {
                        let #other_cell = comparison_chip.load_value(
                            layouter.namespace(|| #load_label),
                            self.#other_field,
                        )?;
                    });
                }
            }
        }
    }

    // --- Constrain pass ---
    let indices = instance_indices(attrs);
    let idx_of = |name: &str| -> Result<usize> {
        indices.get(name).copied().ok_or_else(|| {
            ExporterError::Other(format!("internal: '{name}' missing from the public input layout"))
        })
    };
    // A public operand shared by several constraints is bound to its instance cell once.
    let mut bound_public: BTreeSet<String> = BTreeSet::new();
    for attr in attrs {
        let mut sorted = attr.bindings.clone();
        sorted.sort_by_key(binding_priority);
        for b in &sorted {
            match b {
                GadgetBinding::PoseidonCommit { .. } => {
                    let idx = idx_of(&format!("{}_commitment", attr.param_name))?;
                    stmts.extend(emit_poseidon(&attr.param_name, idx));
                }
                GadgetBinding::Range { low, high, inclusive, num_bits } => {
                    stmts.extend(emit_range(&attr.param_name, low, high, *inclusive, *num_bits)?);
                }
                GadgetBinding::Comparison { op, other, operand, num_bits } => {
                    let instance_idx = match operand {
                        OperandBinding::PublicInput { .. } => {
                            if bound_public.insert(other.clone()) {
                                Some(idx_of(other)?)
                            } else {
                                None
                            }
                        }
                        OperandBinding::PrivateWitness => None,
                    };
                    stmts.extend(emit_comparison(
                        &attr.param_name,
                        *op,
                        other,
                        *num_bits,
                        instance_idx,
                    )?);
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    let idx = idx_of(root_var)?;
                    stmts.extend(emit_merkle(&attr.param_name, siblings_var, indices_var, idx)?);
                }
            }
        }
    }

    stmts.push(quote! { Ok(()) });
    Ok(quote! { #( #stmts )* })
}

fn attr_has_range(attr: &ResolvedAttr) -> bool {
    attr.bindings.iter().any(|b| matches!(b, GadgetBinding::Range { .. }))
}

fn attr_has_comparison(attr: &ResolvedAttr) -> bool {
    attr.bindings.iter().any(|b| matches!(b, GadgetBinding::Comparison { .. }))
}

fn attr_poseidon_nonce(attr: &ResolvedAttr) -> Option<&str> {
    attr.bindings.iter().find_map(|b| match b {
        GadgetBinding::PoseidonCommit { nonce_var } => Some(nonce_var.as_str()),
        _ => None,
    })
}

fn emit_poseidon(param_name: &str, instance_idx: usize) -> Vec<TokenStream> {
    // Reuses the canonical `{param}_value` cell loaded in the load pass, so the commitment binds
    // the same witness the range/comparison gadgets constrain.
    let value_cell = format_ident!("{}_value", param_name);
    let nonce_cell = format_ident!("{}_nonce_cell", param_name);
    let commitment = format_ident!("{}_commitment", param_name);
    let commitment_ref = format_ident!("{}_commitment_ref", param_name);
    let commit_label = format!("commit {param_name}");
    vec![
        quote! {
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
    low: &str,
    high: &str,
    inclusive: bool,
    num_bits: usize,
) -> Result<Vec<TokenStream>> {
    // Reuses the canonical `{param}_value` cell; check_range_bounded copy_advices it, tying the
    // range statement to the committed value.
    let value_cell = format_ident!("{}_value", param_name);
    let check_label = format!("range check {param_name}");
    let low_expr: syn::Expr =
        syn::parse_str(low).map_err(|e| ExporterError::Parse(format!("range low '{low}': {e}")))?;
    let high_expr: syn::Expr = syn::parse_str(high)
        .map_err(|e| ExporterError::Parse(format!("range high '{high}': {e}")))?;
    let high_call = if inclusive {
        quote! { Fr::from((#high_expr) as u64) }
    } else {
        quote! { Fr::from(((#high_expr) as u64) - 1) }
    };
    Ok(vec![quote! {
        range_chip.check_range_bounded(
            layouter.namespace(|| #check_label),
            #value_cell.clone(),
            Fr::from((#low_expr) as u64),
            #high_call,
            #num_bits,
        )?;
    }])
}

/// `instance_idx` is `Some` when the operand names a public function parameter: its canonical cell
/// is then copied into the instance column, so the proof is about the value the contract passes and
/// not about a witness the prover picked.
fn emit_comparison(
    param_name: &str,
    op: ComparisonOp,
    other: &str,
    num_bits: usize,
    instance_idx: Option<usize>,
) -> Result<Vec<TokenStream>> {
    if !is_simple_ident(other) {
        return Err(ExporterError::Parse(format!(
            "comparison RHS must currently be a simple identifier (other fn param); got '{other}'"
        )));
    }
    // Both operands are the canonical cells loaded in the load pass.
    let value_cell = format_ident!("{}_value", param_name);
    let other_cell = format_ident!("{}_value", other);
    let method_ident = format_ident!("{}", op_method(op)?);
    let cmp_label = format!("{} {} {}", param_name, op_symbol(op), other);
    let lhs_range_label = format!("range check {param_name} (comparison operand)");
    let rhs_range_label = format!("range check {other} (comparison operand)");
    // assert_* reduces `a OP b` to a range check on their difference, which is only sound when
    // both operands are already in [0, 2^num_bits) — otherwise a witness near the field modulus
    // wraps and passes a comparison it should fail. Range-check both operands first (state_mask
    // does the same). copy_advice inside check_range/assert_* ties these to the committed value.
    let mut out = vec![quote! {
        range_chip.check_range(
            layouter.namespace(|| #lhs_range_label),
            #value_cell.clone(),
            #num_bits,
        )?;
        range_chip.check_range(
            layouter.namespace(|| #rhs_range_label),
            #other_cell.clone(),
            #num_bits,
        )?;
        comparison_chip.#method_ident(
            layouter.namespace(|| #cmp_label),
            #value_cell.clone(),
            #other_cell.clone(),
            #num_bits,
        )?;
    }];
    if let Some(idx) = instance_idx {
        out.push(quote! {
            layouter.constrain_instance(#other_cell.cell(), config.instance, #idx)?;
        });
    }
    Ok(out)
}

fn emit_merkle(
    param_name: &str,
    siblings_var: &str,
    indices_var: &str,
    instance_idx: usize,
) -> Result<Vec<TokenStream>> {
    if !is_simple_ident(siblings_var) || !is_simple_ident(indices_var) {
        return Err(ExporterError::Parse(format!(
            "merkle_member siblings and indices must be simple identifiers; got '{siblings_var}', '{indices_var}'"
        )));
    }
    let siblings_ident = format_ident!("{}", siblings_var);
    let indices_ident = format_ident!("{}", indices_var);
    let siblings_cells = format_ident!("{}_sibling_cells", param_name);
    let indices_cells = format_ident!("{}_index_cells", param_name);
    let commitment = format_ident!("{}_commitment", param_name);
    let computed_root = format_ident!("{}_computed_root", param_name);
    let load_sibling_label = format!("load {param_name} merkle sibling");
    let load_index_label = format!("load {param_name} merkle index");
    let verify_label = format!("verify {param_name} merkle membership");
    Ok(vec![quote! {
        let #siblings_cells: Vec<_> = self
            .#siblings_ident
            .iter()
            .enumerate()
            .map(|(i, s)| {
                merkle_chip.load_sibling(
                    layouter.namespace(|| format!("{} {}", #load_sibling_label, i)),
                    *s,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let #indices_cells: Vec<_> = self
            .#indices_ident
            .iter()
            .enumerate()
            .map(|(i, idx)| {
                merkle_chip.load_path_index(
                    layouter.namespace(|| format!("{} {}", #load_index_label, i)),
                    *idx,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let #computed_root = merkle_chip.verify_membership(
            layouter.namespace(|| #verify_label),
            #commitment.clone(),
            &#siblings_cells,
            &#indices_cells,
        )?;
        // Bind the root recomputed from the Merkle path to a public input. Without this the
        // circuit only proves membership in *some* tree; pinning the computed root to a public
        // instance forces it to equal the root the verifier supplies, so a wrong path (wrong
        // siblings/indices) fails verification.
        layouter.constrain_instance(#computed_root.cell(), config.instance, #instance_idx)?;
    }])
}

fn op_method(op: ComparisonOp) -> Result<&'static str> {
    match op {
        ComparisonOp::Gt => Ok("assert_gt"),
        ComparisonOp::Gte => Ok("assert_gte"),
        ComparisonOp::Lt => Ok("assert_lt"),
        ComparisonOp::Lte => Ok("assert_lte"),
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

pub fn emit_descriptor(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<String> {
    enforce_single_poseidon(attrs)?;
    validate_merkle_pairing(attrs)?;

    let pascal = to_pascal_case(circuit_name);
    let circuit_ident = format_ident!("{}Circuit", pascal);
    let descriptor_ident = format_ident!("{}Descriptor", pascal);
    let circuit_name_lit = circuit_name.to_string();
    let description_lit =
        format!("Auto-generated descriptor for the '{circuit_name}' privacy-aware circuit.");

    let witness_fields_init = emit_witness_schema_fields(attrs)?;
    let public_inputs_init = emit_public_inputs_schema_fields(attrs)?;
    let num_witness = count_witness_fields(attrs);
    let num_public = public_input_layout(attrs).len();
    let chips = collect_chip_usage(attrs);

    let witness_json_fields = emit_witness_json_fields(attrs);
    let build_inputs_body = emit_build_inputs_body(attrs, &circuit_ident);

    let merkle_const = if chips.merkle {
        quote! { const MERKLE_DEPTH: usize = 32; }
    } else {
        quote! {}
    };

    let tokens = quote! {
        #![allow(clippy::all, dead_code)]

        use std::path::Path;
        use std::sync::OnceLock;

        use halo2_proofs::{
            circuit::Value,
            dev::{MockProver, VerifyFailure},
            plonk::{Circuit, ConstraintSystem},
        };
        use halo2curves::bn256::Fr;
        use serde::{Deserialize, Serialize};
        use zerostyl_circuits::{
            CircuitDescriptor, CircuitError, CircuitIntrospection, FailureEntry, FailureKind,
            FieldType, FieldVisibility, MockProverReport, ProofArtifact, PublicInputField,
            PublicInputsSchema, Result as CResult, WitnessField, WitnessSchema,
        };
        use zerostyl_compiler::codegen::{keys::KeyMetadata, prover::NativeProver};
        use zerostyl_compiler::gadgets::PoseidonCommitmentChip;

        use super::circuit::#circuit_ident;

        const NAME: &str = #circuit_name_lit;
        const VERSION: &str = "1.0.0";
        const DESCRIPTION: &str = #description_lit;
        const DEFAULT_K: u32 = 10;
        const NUM_PUBLIC_INPUTS: usize = #num_public;
        const NUM_PRIVATE_WITNESSES: usize = #num_witness;

        #merkle_const

        #[derive(Debug, Deserialize)]
        struct WitnessJson {
            #( #witness_json_fields, )*
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct PublicInputsJson {
            inputs: Vec<Vec<String>>,
        }

        struct ParsedInputs {
            circuit: #circuit_ident,
            public_inputs: Vec<Vec<Fr>>,
        }

        fn parse_u64(s: &str, field: &str) -> CResult<u64> {
            s.parse::<u64>().map_err(|_| {
                CircuitError::InvalidWitness(format!("field '{field}': expected u64, got '{s}'"))
            })
        }

        fn parse_field(s: &str) -> CResult<Fr> {
            use halo2curves::group::ff::PrimeField;
            if let Some(hex_str) = s.strip_prefix("0x") {
                let bytes = hex::decode(hex_str)
                    .map_err(|e| CircuitError::InvalidWitness(format!("invalid hex '{s}': {e}")))?;
                let mut repr = [0u8; 32];
                let len = bytes.len().min(32);
                repr[..len].copy_from_slice(&bytes[..len]);
                Option::from(Fr::from_repr(repr)).ok_or_else(|| {
                    CircuitError::InvalidWitness(format!("invalid field element '{s}'"))
                })
            } else {
                Ok(Fr::from(parse_u64(s, "field")?))
            }
        }

        fn parse_witness(json: &str) -> CResult<WitnessJson> {
            serde_json::from_str(json)
                .map_err(|e| CircuitError::InvalidWitness(format!("{NAME} witness JSON: {e}")))
        }

        fn build_inputs(w: &WitnessJson) -> CResult<ParsedInputs> {
            #build_inputs_body
        }

        fn encode_public_inputs(inputs: &[Vec<Fr>]) -> String {
            use halo2curves::group::ff::PrimeField;
            let rows: Vec<Vec<String>> = inputs
                .iter()
                .map(|row| {
                    row.iter().map(|fp| format!("0x{}", hex::encode(fp.to_repr()))).collect()
                })
                .collect();
            serde_json::to_string_pretty(&PublicInputsJson { inputs: rows })
                .expect("PublicInputsJson serialization is infallible")
        }

        fn decode_public_inputs(json: &str) -> CResult<Vec<Vec<Fr>>> {
            let parsed: PublicInputsJson = serde_json::from_str(json)?;
            parsed
                .inputs
                .iter()
                .map(|row| row.iter().map(|s| parse_field(s)).collect())
                .collect()
        }

        fn convert_failure(f: &VerifyFailure) -> FailureEntry {
            let details = format!("{f}");
            match f {
                VerifyFailure::ConstraintNotSatisfied { constraint, location, .. } => {
                    FailureEntry {
                        kind: FailureKind::ConstraintNotSatisfied,
                        gate_name: Some(format!("{constraint}")),
                        region: Some(format!("{location}")),
                        row: None,
                        column: None,
                        details,
                    }
                }
                VerifyFailure::CellNotAssigned { gate, gate_offset, column, .. } => FailureEntry {
                    kind: FailureKind::ConstraintNotSatisfied,
                    gate_name: Some(format!("{gate}")),
                    region: None,
                    row: Some(*gate_offset),
                    column: Some(format!("{column:?}")),
                    details,
                },
                VerifyFailure::InstanceCellNotAssigned { gate, column, row, .. } => {
                    FailureEntry {
                        kind: FailureKind::InstanceCellMismatch,
                        gate_name: Some(format!("{gate}")),
                        region: None,
                        row: Some(*row),
                        column: Some(format!("{column:?}")),
                        details,
                    }
                }
                VerifyFailure::ConstraintPoisoned { constraint } => FailureEntry {
                    kind: FailureKind::ConstraintNotSatisfied,
                    gate_name: Some(format!("{constraint}")),
                    region: None,
                    row: None,
                    column: None,
                    details,
                },
                VerifyFailure::Lookup { lookup_index, location, .. } => FailureEntry {
                    kind: FailureKind::Lookup,
                    gate_name: Some(format!("lookup[{lookup_index}]")),
                    region: Some(format!("{location}")),
                    row: None,
                    column: None,
                    details,
                },
                VerifyFailure::Permutation { column, location } => FailureEntry {
                    kind: FailureKind::Permutation,
                    gate_name: None,
                    region: Some(format!("{location}")),
                    row: None,
                    column: Some(format!("{column}")),
                    details,
                },
                _ => FailureEntry {
                    kind: FailureKind::ConstraintNotSatisfied,
                    gate_name: None,
                    region: None,
                    row: None,
                    column: None,
                    details,
                },
            }
        }

        fn parse_usize_field(debug_str: &str, name: &str) -> usize {
            let needle = format!("{name}: ");
            if let Some(start) = debug_str.find(&needle) {
                let after = &debug_str[start + needle.len()..];
                let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                after[..end].parse().unwrap_or(0)
            } else {
                0
            }
        }

        fn witness_schema_static() -> &'static WitnessSchema {
            static S: OnceLock<WitnessSchema> = OnceLock::new();
            S.get_or_init(|| WitnessSchema {
                fields: vec![ #( #witness_fields_init ),* ],
            })
        }

        fn public_inputs_schema_static() -> &'static PublicInputsSchema {
            static S: OnceLock<PublicInputsSchema> = OnceLock::new();
            S.get_or_init(|| PublicInputsSchema {
                fields: vec![ #( #public_inputs_init ),* ],
            })
        }

        pub struct #descriptor_ident;

        pub fn descriptor() -> &'static dyn CircuitDescriptor {
            static D: #descriptor_ident = #descriptor_ident;
            &D
        }

        impl CircuitDescriptor for #descriptor_ident {
            fn name(&self) -> &'static str { NAME }
            fn version(&self) -> &'static str { VERSION }
            fn description(&self) -> &'static str { DESCRIPTION }
            fn default_k(&self) -> u32 { DEFAULT_K }
            fn num_public_inputs(&self) -> usize { NUM_PUBLIC_INPUTS }
            fn num_private_witnesses(&self) -> usize { NUM_PRIVATE_WITNESSES }
            fn witness_schema(&self) -> &'static WitnessSchema { witness_schema_static() }
            fn public_inputs_schema(&self) -> &'static PublicInputsSchema {
                public_inputs_schema_static()
            }

            fn prove(
                &self,
                witness_json: &str,
                k: u32,
                cache_dir: &Path,
            ) -> CResult<ProofArtifact> {
                let w = parse_witness(witness_json)?;
                let ParsedInputs { circuit, public_inputs } = build_inputs(&w)?;
                let mut prover = NativeProver::with_cache_dir(circuit, k, cache_dir)
                    .map_err(|e| CircuitError::ProveFailed(e.to_string()))?;
                prover
                    .setup(KeyMetadata {
                        circuit_name: NAME.to_string(),
                        k,
                        num_public_inputs: NUM_PUBLIC_INPUTS,
                        num_private_witnesses: NUM_PRIVATE_WITNESSES,
                    })
                    .map_err(|e| CircuitError::ProveFailed(e.to_string()))?;
                let proof_bytes = prover
                    .generate_proof(&public_inputs)
                    .map_err(|e| CircuitError::ProveFailed(e.to_string()))?;
                Ok(ProofArtifact::new(proof_bytes, encode_public_inputs(&public_inputs)))
            }

            fn verify(
                &self,
                proof: &[u8],
                public_inputs_json: &str,
                k: u32,
                cache_dir: &Path,
            ) -> CResult<bool> {
                let public_inputs = decode_public_inputs(public_inputs_json)?;
                let circuit = #circuit_ident::default();
                let mut prover = NativeProver::with_cache_dir(circuit, k, cache_dir)
                    .map_err(|e| CircuitError::VerifyFailed(e.to_string()))?;
                prover
                    .setup(KeyMetadata {
                        circuit_name: NAME.to_string(),
                        k,
                        num_public_inputs: NUM_PUBLIC_INPUTS,
                        num_private_witnesses: NUM_PRIVATE_WITNESSES,
                    })
                    .map_err(|e| CircuitError::VerifyFailed(e.to_string()))?;
                prover
                    .verify_proof(proof, &public_inputs)
                    .map_err(|e| CircuitError::VerifyFailed(e.to_string()))
            }

            fn mock_prove(&self, witness_json: &str, k: u32) -> CResult<MockProverReport> {
                let w = parse_witness(witness_json)?;
                let ParsedInputs { circuit, public_inputs } = build_inputs(&w)?;
                let prover = MockProver::run(k, &circuit, public_inputs).map_err(|e| {
                    CircuitError::Other(format!("MockProver setup failed: {e:?}"))
                })?;
                let (satisfied, failures) = match prover.verify() {
                    Ok(()) => (true, Vec::new()),
                    Err(errs) => (false, errs.iter().map(convert_failure).collect()),
                };
                Ok(MockProverReport {
                    circuit_name: NAME.to_string(),
                    k,
                    satisfied,
                    failures,
                })
            }

            fn inspect(&self) -> CResult<CircuitIntrospection> {
                let mut cs = ConstraintSystem::<Fr>::default();
                let _ = #circuit_ident::configure(&mut cs);
                let debug = format!("{:?}", cs.pinned());
                Ok(CircuitIntrospection {
                    circuit_name: NAME.to_string(),
                    k: DEFAULT_K,
                    num_advice_columns: parse_usize_field(&debug, "num_advice_columns"),
                    num_fixed_columns: parse_usize_field(&debug, "num_fixed_columns"),
                    num_instance_columns: parse_usize_field(&debug, "num_instance_columns"),
                    num_selectors: parse_usize_field(&debug, "num_selectors"),
                    max_constraint_degree: cs.degree(),
                    gates: Vec::new(),
                    columns: Vec::new(),
                })
            }
        }
    };

    Ok(tokens.to_string())
}

/// Return-value shape supported by the transformed entry point.
enum TransformedRet {
    Bool,
    ResultBool,
}

/// One `#[zk_private]` parameter after transformation.
struct TransformedPrivate {
    /// Original parameter name in the source function.
    original: String,
    /// On-chain commitment parameter name (`{original}_commitment`).
    commitment: String,
    /// Merkle root parameter name, when the param carries a `MerkleMember` binding.
    root_var: Option<String>,
    /// Whether the param carries a `PoseidonCommit` binding (drives the
    /// nullifier/event flow — a commitment without one is not bound by the proof).
    has_poseidon: bool,
}

/// Format bytes as a Rust array-literal body: `0x12, 0x34, …`.
fn byte_array_literal(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(", ")
}

/// Solidity-visible type of a public input in the transformed contract's signature.
fn public_input_param_type(pi: &PublicInput) -> String {
    match pi {
        // Commitments and Merkle roots are already field elements in little-endian byte form.
        PublicInput::Commitment { .. } | PublicInput::MerkleRoot { .. } => "B256".to_string(),
        // A public function parameter keeps the type it has in the source signature.
        PublicInput::Param { ty, .. } => ty.trim().to_string(),
    }
}

/// Expression converting a public input to the 32-byte little-endian field representation
/// (`Fr::to_repr()`) the verifier consumes.
fn public_input_repr_expr(pi: &PublicInput) -> Result<String> {
    let name = pi.name();
    let ty = match pi {
        PublicInput::Commitment { .. } | PublicInput::MerkleRoot { .. } => {
            return Ok(format!("{name}.0"))
        }
        PublicInput::Param { ty, .. } => ty.split("::").last().unwrap_or(ty).trim().to_string(),
    };
    let bytes = match ty.as_str() {
        "u8" => 1,
        "u16" => 2,
        "u32" => 4,
        "u64" => 8,
        "u128" => 16,
        "bool" => {
            return Ok(format!("{{ let mut repr = [0u8; 32]; repr[0] = {name} as u8; repr }}"))
        }
        "U256" => return Ok(format!("{name}.to_le_bytes::<32>()")),
        other => {
            return Err(ExporterError::Parse(format!(
                "cannot encode public input '{name}' of type '{other}' as a field element \
                 (supported: u8/u16/u32/u64/u128/bool/U256)"
            )))
        }
    };
    Ok(format!(
        "{{ let mut repr = [0u8; 32]; repr[..{bytes}].copy_from_slice(&{name}.to_le_bytes()); repr }}"
    ))
}

fn reserve_param_name(seen: &mut Vec<String>, name: &str) -> Result<()> {
    if seen.iter().any(|n| n == name) {
        return Err(ExporterError::Parse(format!(
            "transformed contract parameter name collision: `{name}` (note: `host` and `proof` \
             are reserved, and each merkle root variable becomes a parameter)"
        )));
    }
    seen.push(name.to_string());
    Ok(())
}

pub fn emit_transformed_contract(
    circuit_name: &str,
    item_fn: &syn::ItemFn,
    attrs: &[ResolvedAttr],
) -> Result<String> {
    use std::collections::HashMap;
    use std::fmt::Write as _;

    // A transformed contract exposes each private param as its on-chain commitment, so every
    // private param must actually carry one. (A commit-less private param is a valid off-chain
    // circuit but cannot be represented on-chain.)
    validate_commit_present(attrs)?;

    let fn_name = item_fn.sig.ident.to_string();
    let pascal = to_pascal_case(&fn_name);
    let host_trait = format!("{pascal}Host");
    let contract_struct = format!("{pascal}Contract");

    // ── Return shape ────────────────────────────────────────────────────────
    let ret = match &item_fn.sig.output {
        syn::ReturnType::Default => {
            return Err(ExporterError::Parse(
                "transformed contract requires a `bool` or `Result<bool, Vec<u8>>` return type"
                    .into(),
            ));
        }
        syn::ReturnType::Type(_, ty) => {
            let normalized = quote!(#ty).to_string().replace(' ', "");
            match normalized.as_str() {
                "bool" => TransformedRet::Bool,
                "Result<bool,Vec<u8>>" => TransformedRet::ResultBool,
                other => {
                    return Err(ExporterError::Parse(format!(
                        "unsupported return type `{other}` in transformed contract; \
                         use `bool` or `Result<bool, Vec<u8>>`"
                    )));
                }
            }
        }
    };
    let (ok_expr, fail_expr) = match ret {
        TransformedRet::Bool => ("true", "false"),
        TransformedRet::ResultBool => ("Ok(true)", "Ok(false)"),
    };
    let ret_str = {
        let output = &item_fn.sig.output;
        quote!(#output).to_string()
    };

    // ── Signature transformation ────────────────────────────────────────────
    let by_name: HashMap<&str, &ResolvedAttr> =
        attrs.iter().map(|a| (a.param_name.as_str(), a)).collect();

    let mut sig_params: Vec<String> = Vec::new(); // without `host`/`proof`
    let mut wrapper_params: Vec<String> = Vec::new(); // for the Stylus module
    let mut call_args: Vec<String> = Vec::new();
    let mut seen_names: Vec<String> = vec!["host".to_string(), "proof".to_string()];
    let mut privates: Vec<TransformedPrivate> = Vec::new();

    for input in item_fn.sig.inputs.iter() {
        let typed = match input {
            syn::FnArg::Typed(t) => t,
            syn::FnArg::Receiver(_) => {
                return Err(ExporterError::Parse(
                    "transformed contract does not support `self` receivers".into(),
                ));
            }
        };
        let is_zk = typed.attrs.iter().any(|a| a.path().is_ident("zk_private"));
        if is_zk {
            let name = match typed.pat.as_ref() {
                syn::Pat::Ident(p) => p.ident.to_string(),
                _ => {
                    return Err(ExporterError::Parse(
                        "transformed contract requires named identifier params on private inputs"
                            .into(),
                    ));
                }
            };
            let commitment = format!("{name}_commitment");
            let attr = by_name.get(name.as_str());
            let has_poseidon = attr.is_some_and(|a| {
                a.bindings.iter().any(|b| matches!(b, GadgetBinding::PoseidonCommit { .. }))
            });
            let root_var = attr.and_then(|a| {
                a.bindings.iter().find_map(|b| match b {
                    GadgetBinding::MerkleMember { root_var, .. } => Some(root_var.clone()),
                    _ => None,
                })
            });
            reserve_param_name(&mut seen_names, &commitment)?;
            sig_params.push(format!("{commitment}: B256"));
            wrapper_params.push(format!("{commitment}: B256"));
            call_args.push(commitment.clone());
            if let Some(root) = &root_var {
                reserve_param_name(&mut seen_names, root)?;
                sig_params.push(format!("{root}: B256"));
                wrapper_params.push(format!("{root}: B256"));
                call_args.push(root.clone());
            }
            privates.push(TransformedPrivate {
                original: name,
                commitment,
                root_var,
                has_poseidon,
            });
        } else {
            let pat = &typed.pat;
            let ty = &typed.ty;
            let name = quote!(#pat).to_string();
            let ty_str = quote!(#ty).to_string();
            reserve_param_name(&mut seen_names, &name)?;
            sig_params.push(format!("{name}: {ty_str}"));
            wrapper_params.push(format!("{name}: {ty_str}"));
            call_args.push(name);
        }
    }

    if privates.is_empty() {
        return Err(ExporterError::Parse(
            "emit_transformed_contract: no #[zk_private] param found; nothing to transform".into(),
        ));
    }

    // ── Public inputs (instance order) + attestation docs ───────────────────
    let layout = public_input_layout(attrs);
    let public_input_names: Vec<String> = layout.iter().map(PublicInput::name).collect();
    let index_of = |name: &str| -> usize {
        public_input_names.iter().position(|n| n == name).expect("name is in the layout")
    };

    let mut attestations: Vec<String> = Vec::new();
    for attr in attrs {
        let mut bindings = attr.bindings.clone();
        bindings.sort_by_key(binding_priority);
        for binding in &bindings {
            match binding {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    let name = format!("{}_commitment", attr.param_name);
                    let idx = index_of(&name);
                    attestations.push(format!(
                        "- `{p}_commitment` = Poseidon({p}, {nonce}) — public input {idx}",
                        p = attr.param_name,
                        nonce = nonce_var,
                    ));
                }
                GadgetBinding::Range { low, high, inclusive, .. } => {
                    let dots = if *inclusive { "..=" } else { ".." };
                    attestations.push(format!("- `{}` ∈ {low}{dots}{high}", attr.param_name));
                }
                GadgetBinding::Comparison { op, other, operand, .. } => match operand {
                    OperandBinding::PublicInput { .. } => {
                        let idx = index_of(other);
                        attestations.push(format!(
                            "- `{p}` {sym} `{other}` — public input {idx}, taken from this \
                             function's `{other}` argument, so the proof holds for the value the \
                             caller passed and no other",
                            p = attr.param_name,
                            sym = op_symbol(*op),
                        ));
                    }
                    OperandBinding::PrivateWitness => {
                        attestations.push(format!(
                            "- `{p}` {sym} `{other}` — `{other}` is another `#[zk_private]` \
                             parameter, anchored by its own commitment",
                            p = attr.param_name,
                            sym = op_symbol(*op),
                        ));
                    }
                },
                GadgetBinding::MerkleMember { root_var, depth, .. } => {
                    let idx = index_of(root_var);
                    attestations.push(format!(
                        "- `{p}_commitment` is a leaf of the Merkle tree rooted at `{root_var}` \
                         (depth {depth}) — public input {idx}",
                        p = attr.param_name,
                    ));
                }
            }
        }
    }

    // ── Generation-time constants from zerostyl-runtime ─────────────────────
    let signature = zerostyl_runtime::ZeroStylPrivacyTransaction::SIGNATURE;
    let topic0 = byte_array_literal(&zerostyl_runtime::ZeroStylPrivacyTransaction::topic0());
    let circuit_id = byte_array_literal(
        zerostyl_runtime::BytecodeFingerprint::of(circuit_name.as_bytes()).as_bytes(),
    );

    // ── File assembly ───────────────────────────────────────────────────────
    let mut out = String::new();
    let w = &mut out;

    writeln!(w, "#![allow(dead_code, unused_variables, unexpected_cfgs)]").unwrap();
    writeln!(w, "//! Privacy-transformed ABI for the `{circuit_name}` circuit.").unwrap();
    writeln!(w, "//!").unwrap();
    writeln!(w, "//! Each `#[zk_private]` parameter of the source function is replaced by its")
        .unwrap();
    writeln!(w, "//! commitment (`B256`), and a trailing `proof: Bytes` carries the halo2 KZG")
        .unwrap();
    writeln!(w, "//! proof. The proof attests, without revealing the private values (see").unwrap();
    writeln!(w, "//! `circuit.rs`):").unwrap();
    writeln!(w, "//!").unwrap();
    for line in &attestations {
        writeln!(w, "//! {line}").unwrap();
    }
    writeln!(w, "//!").unwrap();
    writeln!(w, "//! Public inputs are 32-byte **little-endian** field representations").unwrap();
    writeln!(w, "//! (`Fr::to_repr()`), in the order listed above.").unwrap();
    writeln!(w, "//!").unwrap();
    writeln!(w, "//! # Verification model").unwrap();
    writeln!(w, "//!").unwrap();
    writeln!(w, "//! Proofs are NOT cryptographically verified on-chain: Arbitrum Stylus caps")
        .unwrap();
    writeln!(
        w,
        "//! deployable contracts at 24 KB Brotli-compressed, while the halo2 KZG verifier"
    )
    .unwrap();
    writeln!(w, "//! alone exceeds 90 KB. This module implements a hash-guard flow instead —")
        .unwrap();
    writeln!(w, "//! keccak256 proof hash, one-shot nullifier registry, standardized").unwrap();
    writeln!(
        w,
        "//! `ZeroStylPrivacyTransaction` event — and exposes [`{host_trait}::verify_proof`]"
    )
    .unwrap();
    writeln!(w, "//! as the hook where real verification plugs in (host-side via").unwrap();
    writeln!(w, "//! `zerostyl-verifier`, or on-chain once a verifier fits the size budget).")
        .unwrap();
    writeln!(w).unwrap();
    writeln!(w, "use alloy_primitives::{{keccak256, B256, Bytes}};").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "/// Canonical privacy-transaction event signature").unwrap();
    writeln!(w, "/// (`zerostyl_runtime::ZeroStylPrivacyTransaction::SIGNATURE`).").unwrap();
    writeln!(w, "pub const ZEROSTYL_PRIVACY_TX_SIGNATURE: &str = \"{signature}\";").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "/// keccak256 of [`ZEROSTYL_PRIVACY_TX_SIGNATURE`] — the EVM log topic0 that")
        .unwrap();
    writeln!(w, "/// indexers filter on. Precomputed at generation time.").unwrap();
    writeln!(w, "pub const ZEROSTYL_PRIVACY_TX_TOPIC0: [u8; 32] = [{topic0}];").unwrap();
    writeln!(w).unwrap();
    writeln!(
        w,
        "/// keccak256 of the circuit name `\"{circuit_name}\"` — identifies which circuit"
    )
    .unwrap();
    writeln!(w, "/// produced a proof (`zerostyl_runtime::BytecodeFingerprint`). Production")
        .unwrap();
    writeln!(w, "/// deployments should fingerprint the deployed verifier bytecode instead of the")
        .unwrap();
    writeln!(w, "/// name.").unwrap();
    writeln!(w, "pub const CIRCUIT_ID: [u8; 32] = [{circuit_id}];").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "const NULLIFIER_DOMAIN: [u8; 21] = *b\"zerostyl.nullifier.v1\";").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "/// Mirror of `zerostyl_runtime::events::ZeroStylPrivacyTransaction`.").unwrap();
    writeln!(w, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
    writeln!(w, "pub struct PrivacyTransactionRecord {{").unwrap();
    writeln!(w, "    pub circuit: B256,").unwrap();
    writeln!(w, "    pub nullifier: B256,").unwrap();
    writeln!(w, "    pub commitment: B256,").unwrap();
    writeln!(w, "    pub merkle_root: B256,").unwrap();
    writeln!(w, "    pub proof_hash: B256,").unwrap();
    writeln!(w, "    pub timestamp: u64,").unwrap();
    writeln!(w, "}}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "/// Hooks the embedding contract provides: nullifier storage, clock, event sink,")
        .unwrap();
    writeln!(w, "/// and the proof-verification hook.").unwrap();
    writeln!(w, "pub trait {host_trait} {{").unwrap();
    writeln!(w, "    /// Whether `nullifier` was already consumed by an accepted submission.")
        .unwrap();
    writeln!(w, "    fn is_nullifier_used(&self, nullifier: B256) -> bool;").unwrap();
    writeln!(w, "    /// Persist `nullifier` as consumed.").unwrap();
    writeln!(w, "    fn mark_nullifier_used(&mut self, nullifier: B256);").unwrap();
    writeln!(w, "    /// Current block timestamp, in seconds.").unwrap();
    writeln!(w, "    fn block_timestamp(&self) -> u64;").unwrap();
    writeln!(w, "    /// Emit the standardized privacy-transaction event").unwrap();
    writeln!(w, "    /// (topic0 = [`ZEROSTYL_PRIVACY_TX_TOPIC0`]).").unwrap();
    writeln!(w, "    fn emit_privacy_transaction(&mut self, record: &PrivacyTransactionRecord);")
        .unwrap();
    writeln!(w, "    /// Proof-verification hook. `public_inputs` are 32-byte little-endian field")
        .unwrap();
    writeln!(w, "    /// representations in circuit order.").unwrap();
    writeln!(w, "    ///").unwrap();
    writeln!(w, "    /// Fails closed by default: returns `false` so an unconfigured contract")
        .unwrap();
    writeln!(w, "    /// rejects every submission rather than accepting unverified proofs. You")
        .unwrap();
    writeln!(w, "    /// MUST override this to call a real verifier (e.g. `zerostyl-verifier`)")
        .unwrap();
    writeln!(w, "    /// before the contract accepts anything.").unwrap();
    writeln!(w, "    fn verify_proof(&self, proof: &[u8], public_inputs: &[[u8; 32]]) -> bool {{")
        .unwrap();
    writeln!(w, "        let _ = (proof, public_inputs);").unwrap();
    writeln!(w, "        false").unwrap();
    writeln!(w, "    }}").unwrap();
    writeln!(w, "}}").unwrap();
    writeln!(w).unwrap();

    // public_inputs()
    let pi_doc = if public_input_names.is_empty() {
        "This circuit exposes no public inputs.".to_string()
    } else {
        format!(
            "Public inputs in circuit order: {}.",
            public_input_names
                .iter()
                .enumerate()
                .map(|(i, n)| format!("`[{i}]` = `{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let pi_params = layout
        .iter()
        .map(|pi| format!("{}: {}", pi.name(), public_input_param_type(pi)))
        .collect::<Vec<_>>()
        .join(", ");
    let pi_exprs =
        layout.iter().map(public_input_repr_expr).collect::<Result<Vec<_>>>()?.join(", ");
    writeln!(w, "/// {pi_doc}").unwrap();
    writeln!(w, "/// Values are forwarded as 32-byte little-endian field representations.")
        .unwrap();
    writeln!(w, "pub fn public_inputs({pi_params}) -> [[u8; 32]; {}] {{", public_input_names.len())
        .unwrap();
    writeln!(w, "    [{pi_exprs}]").unwrap();
    writeln!(w, "}}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "/// Per-commitment idempotence key: `keccak256(NULLIFIER_DOMAIN ‖ commitment)`.")
        .unwrap();
    writeln!(w, "///").unwrap();
    writeln!(w, "/// Derived from the commitment ALONE (not the proof bytes), so a commitment can")
        .unwrap();
    writeln!(w, "/// be accepted only once — re-proving the same statement yields a fresh,")
        .unwrap();
    writeln!(w, "/// transcript-randomized proof but the same key, and the replay guard still")
        .unwrap();
    writeln!(w, "/// fires. This matches the contracts/state_mask_verifier model. It is a replay")
        .unwrap();
    writeln!(w, "/// guard over public data, NOT an unlinkable nullifier — a production circuit")
        .unwrap();
    writeln!(w, "/// should expose a real nullifier as a dedicated public input.").unwrap();
    writeln!(w, "pub fn derive_nullifier(commitment: B256) -> B256 {{").unwrap();
    writeln!(w, "    let mut buf = [0u8; 21 + 32];").unwrap();
    writeln!(w, "    buf[..21].copy_from_slice(&NULLIFIER_DOMAIN);").unwrap();
    writeln!(w, "    buf[21..].copy_from_slice(commitment.as_slice());").unwrap();
    writeln!(w, "    keccak256(buf)").unwrap();
    writeln!(w, "}}").unwrap();
    writeln!(w).unwrap();

    // The transformed entry point.
    let vis = {
        let v = &item_fn.vis;
        let s = quote!(#v).to_string();
        if s.is_empty() {
            s
        } else {
            format!("{s} ")
        }
    };
    let poseidon_params: Vec<&TransformedPrivate> =
        privates.iter().filter(|p| p.has_poseidon).collect();
    writeln!(w, "/// Privacy-transformed entry point for `{fn_name}`.").unwrap();
    writeln!(w, "///").unwrap();
    writeln!(w, "/// All guards run before any state change: empty proof, zero commitment, the")
        .unwrap();
    writeln!(w, "/// [`{host_trait}::verify_proof`] hook, and nullifier replay are rejected")
        .unwrap();
    writeln!(w, "/// atomically. On acceptance every nullifier is marked used and one record per")
        .unwrap();
    writeln!(w, "/// private parameter is emitted.").unwrap();
    writeln!(
        w,
        "{vis}fn {fn_name}(host: &mut impl {host_trait}, {} proof: Bytes) {ret_str} {{",
        if sig_params.is_empty() { String::new() } else { format!("{}, ", sig_params.join(", ")) }
    )
    .unwrap();
    writeln!(w, "    if proof.is_empty() {{").unwrap();
    writeln!(w, "        return {fail_expr};").unwrap();
    writeln!(w, "    }}").unwrap();
    for p in &privates {
        writeln!(w, "    if {} == B256::ZERO {{", p.commitment).unwrap();
        writeln!(w, "        return {fail_expr};").unwrap();
        writeln!(w, "    }}").unwrap();
    }
    writeln!(
        w,
        "    if !host.verify_proof(&proof, &public_inputs({})) {{",
        public_input_names.join(", ")
    )
    .unwrap();
    writeln!(w, "        return {fail_expr};").unwrap();
    writeln!(w, "    }}").unwrap();
    if !poseidon_params.is_empty() {
        writeln!(w, "    let proof_hash = keccak256(&proof);").unwrap();
        for p in &poseidon_params {
            writeln!(w, "    let {}_nullifier = derive_nullifier({});", p.original, p.commitment)
                .unwrap();
        }
        for p in &poseidon_params {
            writeln!(w, "    if host.is_nullifier_used({}_nullifier) {{", p.original).unwrap();
            writeln!(w, "        return {fail_expr};").unwrap();
            writeln!(w, "    }}").unwrap();
        }
        for p in &poseidon_params {
            writeln!(w, "    host.mark_nullifier_used({}_nullifier);", p.original).unwrap();
        }
        writeln!(w, "    let timestamp = host.block_timestamp();").unwrap();
        for p in &poseidon_params {
            let merkle_root = match &p.root_var {
                Some(root) => root.clone(),
                None => "B256::ZERO".to_string(),
            };
            writeln!(w, "    host.emit_privacy_transaction(&PrivacyTransactionRecord {{").unwrap();
            writeln!(w, "        circuit: B256::new(CIRCUIT_ID),").unwrap();
            writeln!(w, "        nullifier: {}_nullifier,", p.original).unwrap();
            writeln!(w, "        commitment: {},", p.commitment).unwrap();
            writeln!(w, "        merkle_root: {merkle_root},").unwrap();
            writeln!(w, "        proof_hash,").unwrap();
            writeln!(w, "        timestamp,").unwrap();
            writeln!(w, "    }});").unwrap();
        }
    }
    writeln!(w, "    {ok_expr}").unwrap();
    writeln!(w, "}}").unwrap();
    writeln!(w).unwrap();

    // Reference Stylus embedding (parse-checked only; the feature is never enabled).
    writeln!(w, "/// Reference Stylus embedding — copy into a dedicated contract crate.").unwrap();
    writeln!(w, "///").unwrap();
    writeln!(w, "/// Gated behind a feature this workspace never enables: `stylus-sdk` only")
        .unwrap();
    writeln!(w, "/// compiles for the Stylus WASM target. The module is parse-checked and")
        .unwrap();
    writeln!(w, "/// snapshot-locked, not type-checked. To deploy it, create a contract crate")
        .unwrap();
    writeln!(
        w,
        "/// (stylus-sdk = \"0.9.0\", alloy-primitives = \"=0.8.20\"; see `contracts/` for"
    )
    .unwrap();
    writeln!(w, "/// the layout) and move this module there.").unwrap();
    writeln!(w, "#[cfg(feature = \"zerostyl-stylus-contract\")]").unwrap();
    writeln!(w, "pub mod stylus_contract {{").unwrap();
    writeln!(w, "    use super::*;").unwrap();
    writeln!(
        w,
        "    use stylus_sdk::{{alloy_primitives::U256, alloy_sol_types::sol, evm, prelude::*}};"
    )
    .unwrap();
    writeln!(w).unwrap();
    writeln!(w, "    sol! {{").unwrap();
    writeln!(w, "        /// Standardized privacy-transaction event; signature matches").unwrap();
    writeln!(w, "        /// [`ZEROSTYL_PRIVACY_TX_SIGNATURE`].").unwrap();
    writeln!(w, "        event ZeroStylPrivacyTransaction(").unwrap();
    writeln!(w, "            bytes32 indexed circuit,").unwrap();
    writeln!(w, "            bytes32 indexed nullifier,").unwrap();
    writeln!(w, "            bytes32 indexed commitment,").unwrap();
    writeln!(w, "            bytes32 merkle_root,").unwrap();
    writeln!(w, "            bytes32 proof_hash,").unwrap();
    writeln!(w, "            uint256 timestamp").unwrap();
    writeln!(w, "        );").unwrap();
    writeln!(w, "    }}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "    sol_storage! {{").unwrap();
    writeln!(w, "        #[entrypoint]").unwrap();
    writeln!(w, "        pub struct {contract_struct} {{").unwrap();
    writeln!(w, "            /// One-shot nullifier registry.").unwrap();
    writeln!(w, "            mapping(bytes32 => bool) used_nullifiers;").unwrap();
    writeln!(w, "        }}").unwrap();
    writeln!(w, "    }}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "    impl super::{host_trait} for {contract_struct} {{").unwrap();
    writeln!(w, "        fn is_nullifier_used(&self, nullifier: B256) -> bool {{").unwrap();
    writeln!(w, "            self.used_nullifiers.get(nullifier)").unwrap();
    writeln!(w, "        }}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "        fn mark_nullifier_used(&mut self, nullifier: B256) {{").unwrap();
    writeln!(w, "            self.used_nullifiers.setter(nullifier).set(true);").unwrap();
    writeln!(w, "        }}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "        fn block_timestamp(&self) -> u64 {{").unwrap();
    writeln!(w, "            self.vm().block_timestamp()").unwrap();
    writeln!(w, "        }}").unwrap();
    writeln!(w).unwrap();
    writeln!(
        w,
        "        fn emit_privacy_transaction(&mut self, record: &PrivacyTransactionRecord) {{"
    )
    .unwrap();
    writeln!(w, "            #[allow(deprecated)]").unwrap();
    writeln!(w, "            evm::log(ZeroStylPrivacyTransaction {{").unwrap();
    writeln!(w, "                circuit: record.circuit,").unwrap();
    writeln!(w, "                nullifier: record.nullifier,").unwrap();
    writeln!(w, "                commitment: record.commitment,").unwrap();
    writeln!(w, "                merkle_root: record.merkle_root,").unwrap();
    writeln!(w, "                proof_hash: record.proof_hash,").unwrap();
    writeln!(w, "                timestamp: U256::from(record.timestamp),").unwrap();
    writeln!(w, "            }});").unwrap();
    writeln!(w, "        }}").unwrap();
    writeln!(w, "    }}").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "    #[public]").unwrap();
    writeln!(w, "    impl {contract_struct} {{").unwrap();
    writeln!(
        w,
        "        pub fn {fn_name}(&mut self, {} proof: stylus_sdk::abi::Bytes) {ret_str} {{",
        if wrapper_params.is_empty() {
            String::new()
        } else {
            format!("{}, ", wrapper_params.join(", "))
        }
    )
    .unwrap();
    writeln!(
        w,
        "            super::{fn_name}(self, {} proof.0.into())",
        if call_args.is_empty() { String::new() } else { format!("{}, ", call_args.join(", ")) }
    )
    .unwrap();
    writeln!(w, "        }}").unwrap();
    writeln!(w, "    }}").unwrap();
    writeln!(w, "}}").unwrap();

    Ok(out)
}

fn emit_witness_json_fields(attrs: &[ResolvedAttr]) -> Vec<TokenStream> {
    let mut seen = std::collections::BTreeMap::<String, FieldKind>::new();
    let mut ordered: Vec<(String, FieldKind)> = Vec::new();
    let mut add = |name: &str, kind: FieldKind| {
        if !seen.contains_key(name) {
            ordered.push((
                name.to_string(),
                match kind {
                    FieldKind::Scalar => FieldKind::Scalar,
                    FieldKind::VecScalar => FieldKind::VecScalar,
                },
            ));
            seen.insert(name.to_string(), kind);
        }
    };
    for attr in attrs {
        add(&attr.param_name, FieldKind::Scalar);
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    add(nonce_var, FieldKind::Scalar);
                }
                GadgetBinding::Comparison { other, .. } => {
                    add(other, FieldKind::Scalar);
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    add(root_var, FieldKind::Scalar);
                    add(siblings_var, FieldKind::VecScalar);
                    add(indices_var, FieldKind::VecScalar);
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }
    ordered
        .into_iter()
        .map(|(name, kind)| {
            let ident = format_ident!("{}", name);
            match kind {
                FieldKind::Scalar => quote! { #ident: String },
                FieldKind::VecScalar => quote! { #ident: Vec<String> },
            }
        })
        .collect()
}

fn emit_build_inputs_body(attrs: &[ResolvedAttr], circuit_ident: &syn::Ident) -> TokenStream {
    let mut seen = std::collections::BTreeSet::new();
    let mut scalar_parses = Vec::<TokenStream>::new();
    let mut vec_parses = Vec::<TokenStream>::new();
    let mut commitments = Vec::<TokenStream>::new();
    let mut circuit_inits = Vec::<TokenStream>::new();
    let mut public_input_terms = Vec::<TokenStream>::new();

    let push_scalar = |name: &str,
                       seen: &mut std::collections::BTreeSet<String>,
                       scalar_parses: &mut Vec<TokenStream>,
                       circuit_inits: &mut Vec<TokenStream>| {
        if seen.insert(name.to_string()) {
            let ident = format_ident!("{}", name);
            let label = name.to_string();
            scalar_parses.push(quote! {
                let #ident = parse_field(&w.#ident).map_err(|e| match e {
                    CircuitError::InvalidWitness(msg) => {
                        CircuitError::InvalidWitness(format!("{}: {}", #label, msg))
                    }
                    other => other,
                })?;
            });
            circuit_inits.push(quote! { #ident: Value::known(#ident) });
        }
    };
    let push_vec = |name: &str,
                    seen: &mut std::collections::BTreeSet<String>,
                    vec_parses: &mut Vec<TokenStream>,
                    circuit_inits: &mut Vec<TokenStream>| {
        if seen.insert(name.to_string()) {
            let ident = format_ident!("{}", name);
            vec_parses.push(quote! {
                let #ident: Vec<Fr> = w.#ident.iter()
                    .map(|s| parse_field(s))
                    .collect::<CResult<_>>()?;
            });
            circuit_inits.push(quote! {
                #ident: #ident.iter().map(|v| Value::known(*v)).collect()
            });
        }
    };

    for attr in attrs {
        push_scalar(&attr.param_name, &mut seen, &mut scalar_parses, &mut circuit_inits);
        let mut sorted = attr.bindings.clone();
        sorted.sort_by_key(binding_priority);
        for b in &sorted {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    push_scalar(nonce_var, &mut seen, &mut scalar_parses, &mut circuit_inits);
                    let value_ident = format_ident!("{}", attr.param_name);
                    let nonce_ident = format_ident!("{}", nonce_var);
                    let commitment_ident = format_ident!("{}_commitment", attr.param_name);
                    commitments.push(quote! {
                        let #commitment_ident = PoseidonCommitmentChip::hash_outside_circuit(
                            #value_ident,
                            #nonce_ident,
                        );
                    });
                }
                GadgetBinding::Comparison { other, .. } => {
                    push_scalar(other, &mut seen, &mut scalar_parses, &mut circuit_inits);
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    push_scalar(root_var, &mut seen, &mut scalar_parses, &mut circuit_inits);
                    push_vec(siblings_var, &mut seen, &mut vec_parses, &mut circuit_inits);
                    push_vec(indices_var, &mut seen, &mut vec_parses, &mut circuit_inits);
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }

    // Build the instance vector from the canonical layout, so the values handed to the
    // prover/verifier are exactly the cells `emit_synthesize_body` constrained.
    for entry in public_input_layout(attrs) {
        let ident = format_ident!("{}", entry.name());
        public_input_terms.push(quote! { #ident });
    }

    let public_inputs_expr = if public_input_terms.is_empty() {
        quote! { Vec::new() }
    } else {
        quote! { vec![vec![ #( #public_input_terms ),* ]] }
    };

    quote! {
        #( #scalar_parses )*
        #( #vec_parses )*
        #( #commitments )*
        let circuit = #circuit_ident {
            #( #circuit_inits, )*
        };
        let public_inputs = #public_inputs_expr;
        Ok(ParsedInputs { circuit, public_inputs })
    }
}

/// Number of witness fields the schema marks private — the value `NUM_PRIVATE_WITNESSES` carries.
///
/// Public comparison operands and Merkle roots travel in the witness document (the prover assigns
/// their cell) but are bound to the instance column, so they are counted as public inputs, not
/// private witnesses. Mirrors the visibility `emit_witness_schema_fields` assigns.
fn count_witness_fields(attrs: &[ResolvedAttr]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    let mut public = std::collections::BTreeSet::new();
    for attr in attrs {
        seen.insert(attr.param_name.clone());
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    seen.insert(nonce_var.clone());
                }
                GadgetBinding::Comparison { other, operand, .. } => {
                    if seen.insert(other.clone())
                        && matches!(operand, OperandBinding::PublicInput { .. })
                    {
                        public.insert(other.clone());
                    }
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    if seen.insert(root_var.clone()) {
                        public.insert(root_var.clone());
                    }
                    seen.insert(siblings_var.clone());
                    seen.insert(indices_var.clone());
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }
    seen.len() - public.len()
}

fn field_type_token(ty: &str) -> Result<TokenStream> {
    let cleaned = ty.split("::").last().unwrap_or(ty).trim();
    match cleaned {
        "u8" | "u16" | "u32" | "u64" => Ok(quote! { FieldType::U64 }),
        "u128" => Ok(quote! { FieldType::U128 }),
        "bool" => Ok(quote! { FieldType::Bool }),
        "U256" => Ok(quote! { FieldType::Fp }),
        other => Err(ExporterError::Parse(format!(
            "cannot map type '{other}' to FieldType (supported: u8/u16/u32/u64/u128/bool/U256)"
        ))),
    }
}

fn emit_witness_schema_fields(attrs: &[ResolvedAttr]) -> Result<Vec<TokenStream>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for attr in attrs {
        if seen.insert(attr.param_name.clone()) {
            let name = &attr.param_name;
            let kind = field_type_token(&attr.param_type)?;
            out.push(quote! {
                WitnessField {
                    name: #name.into(),
                    kind: #kind,
                    visibility: FieldVisibility::Private,
                    description: None,
                }
            });
        }
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    if seen.insert(nonce_var.clone()) {
                        out.push(quote! {
                            WitnessField {
                                name: #nonce_var.into(),
                                kind: FieldType::Fp,
                                visibility: FieldVisibility::Private,
                                description: None,
                            }
                        });
                    }
                }
                // A public operand still travels in the witness document (the prover assigns the
                // cell) but is flagged public: the cell is copied into the instance column.
                GadgetBinding::Comparison { other, operand, .. } => {
                    if seen.insert(other.clone()) {
                        let (kind, visibility) = match operand {
                            OperandBinding::PublicInput { ty } => {
                                (field_type_token(ty)?, quote! { FieldVisibility::Public })
                            }
                            OperandBinding::PrivateWitness => (
                                field_type_token(&attr.param_type)?,
                                quote! { FieldVisibility::Private },
                            ),
                        };
                        out.push(quote! {
                            WitnessField {
                                name: #other.into(),
                                kind: #kind,
                                visibility: #visibility,
                                description: None,
                            }
                        });
                    }
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    // The root the prover supplies is checked against the recomputed one, which is
                    // an instance cell — so it is a public input, not a private witness.
                    if seen.insert(root_var.clone()) {
                        out.push(quote! {
                            WitnessField {
                                name: #root_var.into(),
                                kind: FieldType::Fp,
                                visibility: FieldVisibility::Public,
                                description: None,
                            }
                        });
                    }
                    let depth = MERKLE_DEPTH;
                    if seen.insert(siblings_var.clone()) {
                        out.push(quote! {
                            WitnessField {
                                name: #siblings_var.into(),
                                kind: FieldType::Array {
                                    kind: Box::new(FieldType::Fp),
                                    len: #depth,
                                },
                                visibility: FieldVisibility::Private,
                                description: None,
                            }
                        });
                    }
                    if seen.insert(indices_var.clone()) {
                        out.push(quote! {
                            WitnessField {
                                name: #indices_var.into(),
                                kind: FieldType::Array {
                                    kind: Box::new(FieldType::Bool),
                                    len: #depth,
                                },
                                visibility: FieldVisibility::Private,
                                description: None,
                            }
                        });
                    }
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }
    Ok(out)
}

fn emit_public_inputs_schema_fields(attrs: &[ResolvedAttr]) -> Result<Vec<TokenStream>> {
    let mut out = Vec::new();
    for entry in public_input_layout(attrs) {
        let name = entry.name();
        let kind = match &entry {
            PublicInput::Commitment { .. } | PublicInput::MerkleRoot { .. } => {
                quote! { FieldType::Fp }
            }
            PublicInput::Param { ty, .. } => field_type_token(ty)?,
        };
        out.push(quote! {
            PublicInputField {
                name: #name.into(),
                kind: #kind,
                description: None,
            }
        });
    }
    Ok(out)
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
    use crate::parser::{AttrSpec, CommitScheme, Constraint, FnParam, MerkleMemberSpec, RangeSpec};
    use crate::resolver::resolve;

    fn constraint_operand(c: &Constraint) -> &str {
        match c {
            Constraint::Gte(o)
            | Constraint::Gt(o)
            | Constraint::Lte(o)
            | Constraint::Lt(o)
            | Constraint::Eq(o) => o,
        }
    }

    /// Resolve one annotated param against a synthetic signature where every constraint operand is
    /// a *public* parameter of the same type.
    fn resolved(name: &str, ty: &str, specs: Vec<AttrSpec>) -> ResolvedAttr {
        resolved_with(name, ty, specs, false)
    }

    /// Same, but the constraint operands are themselves `#[zk_private]` params.
    fn resolved_private_operand(name: &str, ty: &str, specs: Vec<AttrSpec>) -> ResolvedAttr {
        resolved_with(name, ty, specs, true)
    }

    fn resolved_with(
        name: &str,
        ty: &str,
        specs: Vec<AttrSpec>,
        operand_is_private: bool,
    ) -> ResolvedAttr {
        let parsed =
            crate::parser::ZkPrivateAttr { param_name: name.into(), param_type: ty.into(), specs };
        let mut params = vec![FnParam { name: name.into(), ty: ty.into(), is_private: true }];
        for spec in &parsed.specs {
            if let AttrSpec::Constraint(c) = spec {
                let operand = constraint_operand(c);
                if operand != name && !params.iter().any(|p| p.name == operand) {
                    params.push(FnParam {
                        name: operand.into(),
                        ty: ty.into(),
                        is_private: operand_is_private,
                    });
                }
            }
        }
        resolve(&parsed, &params).unwrap()
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
        assert!(!src.contains("MerkleTreeChip"));
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
    fn comparison_circuit_parses_and_calls_assert_gte() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Constraint(Constraint::Gte("threshold".into()))],
        )];
        let src = emit_circuit("foo", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("ComparisonChip"));
        assert!(src.contains("assert_gte"));
        assert!(src.contains("threshold"));
    }

    /// A constraint operand naming a *public* function parameter must be copied into the instance
    /// column. Otherwise the prover picks `threshold` freely and proves `collateral >= <anything>`
    /// while the contract's `threshold` argument binds nothing.
    #[test]
    fn public_comparison_operand_is_constrained_to_an_instance_cell() {
        let attrs = vec![resolved(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        )];
        let src = emit_circuit("deposit", &attrs).unwrap();
        parse_as_file(&src);
        let normalized = src.replace(' ', "");
        assert!(
            normalized
                .contains("constrain_instance(threshold_value.cell(),config.instance,1usize)"),
            "threshold must be bound to instance cell 1; got:\n{src}"
        );
        // …and the commitment keeps cell 0.
        assert!(normalized
            .contains("constrain_instance(collateral_commitment_ref,config.instance,0usize)"));
    }

    #[test]
    fn private_comparison_operand_is_not_constrained_to_an_instance_cell() {
        let attrs = vec![resolved_private_operand(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Constraint(Constraint::Gte("floor".into())),
            ],
        )];
        let src = emit_circuit("deposit", &attrs).unwrap();
        parse_as_file(&src);
        assert!(!src.replace(' ', "").contains("constrain_instance(floor_value.cell()"));
    }

    #[test]
    fn comparison_methods_per_op() {
        for (op, method) in [
            (Constraint::Gt("y".into()), "assert_gt"),
            (Constraint::Gte("y".into()), "assert_gte"),
            (Constraint::Lt("y".into()), "assert_lt"),
            (Constraint::Lte("y".into()), "assert_lte"),
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
        assert!(src.contains("x : Value < Fr >") || src.contains("x: Value<Fr>"));
        assert!(src.contains("threshold : Value < Fr >") || src.contains("threshold: Value<Fr>"));
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
        assert!(src.contains("DepositCircuit"));
    }

    /// Soundness lock: a param carrying commitment + range + comparison must be loaded into a
    /// SINGLE canonical cell that all gadgets reuse (copy_advice ties them together). Loading a
    /// fresh cell per gadget would leave the range/comparison about free witnesses decoupled from
    /// the committed value — forgeable. See emit_synthesize_body.
    #[test]
    fn multi_gadget_composition_binds_one_cell_per_value() {
        let attrs = vec![resolved(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Range(RangeSpec {
                    low: "0".into(),
                    high: "1000".into(),
                    inclusive: false,
                }),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        )];
        let src = emit_circuit("deposit", &attrs).unwrap();
        parse_as_file(&src);
        // The value is loaded exactly once (not once per gadget) …
        assert_eq!(
            src.matches("self . collateral)").count() + src.matches("self.collateral)").count(),
            1,
            "collateral must be loaded into a single cell, not reloaded per gadget"
        );
        // … and the old per-gadget decoupled cell names must be gone.
        assert!(!src.contains("collateral_range_value"));
        assert!(!src.contains("collateral_cmp_value"));
        assert!(!src.contains("collateral_poseidon_value"));
        // The canonical cell is reused (cloned) across gadgets.
        assert!(
            src.contains("collateral_value . clone ()") || src.contains("collateral_value.clone()")
        );
        // Comparison operands are range-checked before the assertion (wraparound guard).
        assert!(src.contains("comparison operand"));
        assert!(src.contains("assert_gte"));
    }

    #[test]
    fn merkle_with_poseidon_parses() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
            ],
        )];
        let src = emit_circuit("tx", &attrs).unwrap();
        parse_as_file(&src);
        assert!(src.contains("MerkleTreeChip"));
        assert!(src.contains("verify_membership"));
        assert!(src.contains("load_sibling"));
        assert!(src.contains("load_path_index"));
        assert!(src.contains("MERKLE_DEPTH"));
    }

    #[test]
    fn merkle_witnesses_are_vec_typed() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
            ],
        )];
        let src = emit_circuit("tx", &attrs).unwrap();
        let parsed = parse_as_file(&src);
        let struct_item = parsed
            .items
            .iter()
            .find_map(|i| if let syn::Item::Struct(s) = i { Some(s) } else { None })
            .expect("circuit struct");
        let field_types: Vec<String> = struct_item
            .fields
            .iter()
            .map(|f| {
                let name = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                let ty = quote::ToTokens::to_token_stream(&f.ty).to_string();
                format!("{name}={ty}")
            })
            .collect();
        assert!(
            field_types.iter().any(|s| s.starts_with("siblings=") && s.contains("Vec")),
            "siblings should be Vec-typed; fields = {field_types:?}"
        );
        assert!(
            field_types.iter().any(|s| s.starts_with("indices=") && s.contains("Vec")),
            "indices should be Vec-typed; fields = {field_types:?}"
        );
    }

    #[test]
    fn merkle_emits_custom_default_impl() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
            ],
        )];
        let src = emit_circuit("tx", &attrs).unwrap();
        assert!(src.contains("impl Default for TxCircuit"));
        assert!(
            src.contains("vec ! [Value :: unknown () ; MERKLE_DEPTH]")
                || src.contains("vec![Value::unknown(); MERKLE_DEPTH]")
        );
        assert!(!src.contains("Default ,") && !src.contains(", Default"));
    }

    #[test]
    fn merkle_without_poseidon_rejected() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![AttrSpec::MerkleMember(MerkleMemberSpec {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
                indices_var: "indices".into(),
            })],
        )];
        let err = emit_circuit("tx", &attrs).unwrap_err();
        assert!(format!("{err}").contains("PoseidonCommit"));
    }

    #[test]
    fn bindings_reordered_so_poseidon_runs_first() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
                AttrSpec::Commit(CommitScheme::Poseidon),
            ],
        )];
        let src = emit_circuit("tx", &attrs).unwrap();
        let poseidon_pos = src
            .find("poseidon_chip . commit")
            .or_else(|| src.find("poseidon_chip.commit"))
            .unwrap();
        let merkle_pos = src.find("verify_membership").unwrap();
        assert!(poseidon_pos < merkle_pos, "expected poseidon commit before merkle verify");
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
    fn no_merkle_still_uses_derive_default() {
        let attrs = vec![resolved("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_circuit("foo", &attrs).unwrap();
        assert!(
            src.contains("# [derive (Clone , Debug , Default)]")
                || src.contains("#[derive(Clone, Debug, Default)]")
        );
        assert!(!src.contains("impl Default for"));
    }

    #[test]
    fn descriptor_parses_as_valid_rust() {
        let attrs =
            vec![resolved("collateral", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_descriptor("deposit", &attrs).unwrap();
        parse_as_file(&src);
    }

    #[test]
    fn descriptor_struct_and_factory_present() {
        let attrs = vec![resolved("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_descriptor("foo", &attrs).unwrap();
        assert!(src.contains("struct FooDescriptor"));
        assert!(src.contains("pub fn descriptor"));
        assert!(
            src.contains("& 'static dyn CircuitDescriptor")
                || src.contains("&'static dyn CircuitDescriptor")
        );
    }

    #[test]
    fn descriptor_metadata_uses_circuit_name() {
        let attrs = vec![resolved("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_descriptor("private_lending", &attrs).unwrap();
        assert!(src.contains("\"private_lending\""));
        assert!(src.contains("PrivateLendingDescriptor"));
        assert!(
            src.contains("super :: circuit :: PrivateLendingCircuit")
                || src.contains("super::circuit::PrivateLendingCircuit")
        );
    }

    #[test]
    fn descriptor_witness_schema_lists_each_witness() {
        let attrs = vec![resolved(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        )];
        let src = emit_descriptor("deposit", &attrs).unwrap();
        assert!(src.contains("\"collateral\""));
        assert!(src.contains("\"collateral_nonce\""));
        assert!(src.contains("\"threshold\""));
        assert!(
            src.contains("FieldVisibility :: Private") || src.contains("FieldVisibility::Private")
        );
    }

    #[test]
    fn descriptor_public_inputs_one_per_poseidon_commit() {
        let attrs = vec![resolved("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_descriptor("foo", &attrs).unwrap();
        assert!(src.contains("\"x_commitment\""));
    }

    #[test]
    fn descriptor_public_inputs_include_a_public_comparison_operand() {
        let attrs = vec![resolved(
            "collateral",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::Constraint(Constraint::Gte("threshold".into())),
            ],
        )];
        let src = emit_descriptor("deposit", &attrs).unwrap();
        parse_as_file(&src);
        let normalized = src.replace(' ', "");
        assert!(normalized.contains("NUM_PUBLIC_INPUTS:usize=2usize"));
        // `threshold` is a public input, so only `collateral` and its nonce are private.
        assert!(normalized.contains("NUM_PRIVATE_WITNESSES:usize=2usize"));
        // The instance vector is [commitment, threshold], matching the circuit's cell indices.
        assert!(
            normalized.contains("letpublic_inputs=vec![vec![collateral_commitment,threshold]];"),
            "descriptor must feed threshold to the prover as a public input; got:\n{src}"
        );
        assert!(normalized.contains("FieldVisibility::Public"));
    }

    #[test]
    fn descriptor_no_poseidon_means_no_public_inputs() {
        let attrs = vec![resolved(
            "x",
            "u64",
            vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "100".into(),
                inclusive: true,
            })],
        )];
        let src = emit_descriptor("foo", &attrs).unwrap();
        assert!(!src.contains("_commitment"));
        assert!(
            src.contains("NUM_PUBLIC_INPUTS : usize = 0usize")
                || src.contains("NUM_PUBLIC_INPUTS: usize = 0usize")
        );
    }

    #[test]
    fn descriptor_merkle_emits_array_field_type() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
            ],
        )];
        let src = emit_descriptor("tx", &attrs).unwrap();
        assert!(src.contains("FieldType :: Array") || src.contains("FieldType::Array"));
        assert!(src.contains("\"siblings\""));
        assert!(src.contains("\"indices\""));
        assert!(src.contains("32usize") || src.contains("len : 32"));
    }

    #[test]
    fn descriptor_merkle_root_is_public_and_not_counted_as_private() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![
                AttrSpec::Commit(CommitScheme::Poseidon),
                AttrSpec::MerkleMember(MerkleMemberSpec {
                    root_var: "root".into(),
                    siblings_var: "siblings".into(),
                    indices_var: "indices".into(),
                }),
            ],
        )];
        let src = emit_descriptor("tx", &attrs).unwrap();
        parse_as_file(&src);
        let normalized = src.replace(' ', "");
        assert!(normalized.contains(
            "WitnessField{name:\"root\".into(),kind:FieldType::Fp,visibility:FieldVisibility::Public,"
        ));
        // leaf, leaf_nonce, siblings, indices — the root is a public input.
        assert!(normalized.contains("NUM_PRIVATE_WITNESSES:usize=4usize"));
        assert!(normalized.contains("NUM_PUBLIC_INPUTS:usize=2usize"));
    }

    #[test]
    fn descriptor_emits_full_prove_verify_mock_inspect_pipeline() {
        let attrs = vec![resolved("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_descriptor("foo", &attrs).unwrap();
        assert!(src.contains("NativeProver"), "prove/verify should delegate to NativeProver");
        assert!(src.contains("MockProver :: run") || src.contains("MockProver::run"));
        assert!(
            src.contains("ConstraintSystem :: < Fr >") || src.contains("ConstraintSystem::<Fr>")
        );
        assert!(src.contains("hash_outside_circuit"));
        assert!(src.contains("WitnessJson"));
        assert!(src.contains("ParsedInputs"));
        assert!(src.contains("build_inputs"));
        assert!(src.contains("parse_witness"));
        assert!(src.contains("encode_public_inputs"));
        assert!(src.contains("decode_public_inputs"));
    }

    #[test]
    fn descriptor_rejects_merkle_without_poseidon() {
        let attrs = vec![resolved(
            "leaf",
            "u64",
            vec![AttrSpec::MerkleMember(MerkleMemberSpec {
                root_var: "root".into(),
                siblings_var: "siblings".into(),
                indices_var: "indices".into(),
            })],
        )];
        let err = emit_descriptor("tx", &attrs).unwrap_err();
        assert!(format!("{err}").contains("PoseidonCommit"));
    }

    fn parse_fn_source(src: &str) -> syn::ItemFn {
        syn::parse_str(src).unwrap_or_else(|e| panic!("fn source does not parse: {e}\n{src}"))
    }

    /// Resolve the fn's own `#[zk_private]` attrs and emit, naming the circuit
    /// after the fn — mirrors the `transform_contract` pipeline.
    fn emit_transformed(item_fn: &syn::ItemFn) -> Result<String> {
        let resolved = crate::resolver::resolve_fn(item_fn)?;
        emit_transformed_contract(&item_fn.sig.ident.to_string(), item_fn, &resolved)
    }

    fn find_fn(file: syn::File, name: &str) -> syn::ItemFn {
        file.items
            .into_iter()
            .find_map(|i| match i {
                syn::Item::Fn(f) if f.sig.ident == name => Some(f),
                _ => None,
            })
            .unwrap_or_else(|| panic!("fn `{name}` present in generated file"))
    }

    #[test]
    fn transformed_contract_replaces_private_param_with_commitment() {
        let item_fn = parse_fn_source(
            r#"
            pub fn deposit(
                amount: U256,
                #[zk_private(commit = "poseidon")] collateral: U256,
                threshold: U256,
            ) -> Result<bool, Vec<u8>> {
                Ok(true)
            }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        parse_as_file(&src);
        assert!(src.contains("amount: U256"));
        assert!(src.contains("collateral_commitment: B256"));
        assert!(src.contains("threshold: U256"));
        assert!(src.contains("proof: Bytes"));
        assert!(src.contains("host: &mut impl DepositHost"));
        // The attribute itself must be stripped (the docs may mention it).
        assert!(!src.contains("#[zk_private("));
        assert!(!src.contains("todo!"));
    }

    #[test]
    fn transformed_contract_emits_import_header() {
        let item_fn = parse_fn_source(
            r#"
            pub fn f(#[zk_private(commit = "poseidon")] x: u64) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        assert!(src.contains("use alloy_primitives::{keccak256, B256, Bytes};"));
    }

    #[test]
    fn transformed_contract_preserves_param_order() {
        let item_fn = parse_fn_source(
            r#"
            pub fn order(
                a: u64,
                #[zk_private(commit = "poseidon")] b: u64,
                c: u64,
                #[zk_private(commit = "poseidon")] d: u64,
                e: u64,
            ) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        let f = find_fn(parse_as_file(&src), "order");
        let names: Vec<String> = f
            .sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(t) => match t.pat.as_ref() {
                    syn::Pat::Ident(p) => Some(p.ident.to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["host", "a", "b_commitment", "c", "d_commitment", "e", "proof"]);
    }

    #[test]
    fn transformed_contract_rejects_fn_without_private_params() {
        let item_fn = parse_fn_source(r#"pub fn plain(x: u64) -> bool { true }"#);
        let err = emit_transformed(&item_fn).unwrap_err();
        assert!(format!("{err}").contains("no #[zk_private]"));
    }

    #[test]
    fn transformed_contract_preserves_return_type_and_visibility() {
        let item_fn = parse_fn_source(
            r#"
            pub(crate) fn returns_result(
                #[zk_private(commit = "poseidon")] x: U256,
            ) -> Result<bool, Vec<u8>> {
                Ok(true)
            }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        assert!(src.contains("pub (crate)"));
        assert!(src.contains("Result < bool , Vec < u8 > >"));
        assert!(src.contains("return Ok(false);"));
        assert!(src.contains("    Ok(true)\n"));
    }

    #[test]
    fn transformed_contract_inlines_runtime_event_constants() {
        let item_fn = parse_fn_source(
            r#"
            pub fn f(#[zk_private(commit = "poseidon")] x: u64) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        // The signature string and precomputed topic0/circuit-id literals must come
        // from zerostyl-runtime, so contracts and indexers agree by construction.
        assert!(src.contains(zerostyl_runtime::ZeroStylPrivacyTransaction::SIGNATURE));
        let topic0 = byte_array_literal(&zerostyl_runtime::ZeroStylPrivacyTransaction::topic0());
        assert!(src.contains(&topic0));
        let circuit_id =
            byte_array_literal(zerostyl_runtime::BytecodeFingerprint::of(b"f").as_bytes());
        assert!(src.contains(&circuit_id));
    }

    #[test]
    fn transformed_contract_body_guards_and_emits() {
        let item_fn = parse_fn_source(
            r#"
            pub fn deposit(#[zk_private(commit = "poseidon")] collateral: u64) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        parse_as_file(&src);
        assert!(src.contains("if proof.is_empty()"));
        assert!(src.contains("if collateral_commitment == B256::ZERO"));
        assert!(src.contains("host.verify_proof(&proof, &public_inputs(collateral_commitment))"));
        assert!(src.contains("host.is_nullifier_used(collateral_nullifier)"));
        assert!(src.contains("host.mark_nullifier_used(collateral_nullifier);"));
        assert!(src.contains("host.emit_privacy_transaction(&PrivacyTransactionRecord {"));
        assert!(src.contains("pub trait DepositHost"));
        assert!(src.contains("#[cfg(feature = \"zerostyl-stylus-contract\")]"));
        assert!(src.contains("sol_storage!"));
    }

    #[test]
    fn transformed_contract_merkle_adds_root_param() {
        let item_fn = parse_fn_source(
            r#"
            pub fn claim(
                #[zk_private(
                    commit = "poseidon",
                    constraint = "merkle_member(value, root, siblings, indices)"
                )]
                leaf: U256,
            ) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        parse_as_file(&src);
        assert!(src.contains("leaf_commitment: B256, root: B256"));
        assert!(src
            .contains("pub fn public_inputs(leaf_commitment: B256, root: B256) -> [[u8; 32]; 2]"));
        assert!(src.contains("merkle_root: root,"));
    }

    /// The contract must hand the verifier the very `threshold` it was called with, so the proof
    /// and the call are the same statement.
    #[test]
    fn transformed_contract_forwards_public_operand_to_the_verifier() {
        let item_fn = parse_fn_source(
            r#"
            pub fn deposit(
                #[zk_private(commit = "poseidon", constraint = "value >= threshold")]
                collateral: u64,
                threshold: u64,
            ) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        parse_as_file(&src);
        assert!(src.contains(
            "pub fn public_inputs(collateral_commitment: B256, threshold: u64) -> [[u8; 32]; 2]"
        ));
        // u64 -> 32-byte little-endian field representation.
        assert!(src.contains("repr[..8].copy_from_slice(&threshold.to_le_bytes());"));
        assert!(src.contains(
            "host.verify_proof(&proof, &public_inputs(collateral_commitment, threshold))"
        ));
        assert!(src.contains("public input 1, taken from this function's `threshold` argument"));
    }

    #[test]
    fn transformed_contract_encodes_u256_public_operand_little_endian() {
        let item_fn = parse_fn_source(
            r#"
            pub fn deposit(
                #[zk_private(commit = "poseidon", constraint = "value >= threshold")]
                collateral: U256,
                threshold: U256,
            ) -> bool { true }
            "#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        parse_as_file(&src);
        assert!(src.contains("threshold.to_le_bytes::<32>()"));
    }

    #[test]
    fn transformed_contract_rejects_root_name_collision() {
        let item_fn = parse_fn_source(
            r#"
            pub fn claim(
                #[zk_private(
                    commit = "poseidon",
                    constraint = "merkle_member(value, root, siblings, indices)"
                )]
                leaf: U256,
                root: U256,
            ) -> bool { true }
            "#,
        );
        let err = emit_transformed(&item_fn).unwrap_err();
        assert!(format!("{err}").contains("collision"));
    }

    #[test]
    fn transformed_contract_rejects_reserved_param_names() {
        let item_fn = parse_fn_source(
            r#"
            pub fn f(#[zk_private(commit = "poseidon")] x: u64, proof: u64) -> bool { true }
            "#,
        );
        let err = emit_transformed(&item_fn).unwrap_err();
        assert!(format!("{err}").contains("collision"));
    }

    #[test]
    fn transformed_contract_rejects_unsupported_return_type() {
        let item_fn = parse_fn_source(
            r#"
            pub fn f(#[zk_private(commit = "poseidon")] x: u64) -> u64 { 0 }
            "#,
        );
        let err = emit_transformed(&item_fn).unwrap_err();
        assert!(format!("{err}").contains("unsupported return type"));
    }

    #[test]
    fn transformed_contract_sol_event_matches_runtime_signature() {
        // The `sol!` event in the (feature-gated, never-compiled) stylus module must stay in sync
        // with zerostyl_runtime's canonical SIGNATURE, or a deployed contract would emit an event
        // whose topic0 differs from the one indexers filter on. Reconstruct the canonical
        // signature from the emitted sol! field types and compare.
        let item_fn = parse_fn_source(
            r#"pub fn f(#[zk_private(commit = "poseidon")] x: u64) -> bool { true }"#,
        );
        let src = emit_transformed(&item_fn).unwrap();
        let start = src.find("event ZeroStylPrivacyTransaction(").unwrap();
        let body = &src[start..];
        let inner = &body[body.find('(').unwrap() + 1..body.find(')').unwrap()];
        let types: Vec<&str> =
            inner.split(',').map(|field| field.split_whitespace().next().unwrap()).collect();
        let reconstructed = format!("ZeroStylPrivacyTransaction({})", types.join(","));
        assert_eq!(reconstructed, zerostyl_runtime::ZeroStylPrivacyTransaction::SIGNATURE);
    }

    #[test]
    fn transformed_contract_rejects_commitless_private_param() {
        // A range-only private param has no commitment, so its on-chain `_commitment` argument
        // would bind no proof — reject it at the contract-transform layer.
        let item_fn = parse_fn_source(
            r#"
            pub fn f(#[zk_private(range = "0..100")] age: u64) -> bool { true }
            "#,
        );
        let err = emit_transformed(&item_fn).unwrap_err();
        assert!(format!("{err}").contains("commit = \"poseidon\""));
    }
}
