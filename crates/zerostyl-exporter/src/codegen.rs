use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::error::{ExporterError, Result};
use crate::resolver::{ComparisonOp, GadgetBinding, ResolvedAttr, MERKLE_DEPTH};

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
    merkle: bool,
}

fn collect_chip_usage(attrs: &[ResolvedAttr]) -> ChipUsage {
    let mut u = ChipUsage::default();
    for attr in attrs {
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { .. } => u.poseidon = true,
                GadgetBinding::Range { .. } => u.range = true,
                GadgetBinding::Comparison { .. } => u.comparison = true,
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
        use halo2curves::pasta::Fp;
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
                    if is_simple_ident(other) {
                        add(other, FieldKind::Scalar, &mut seen, &mut ordered);
                    }
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
                FieldKind::Scalar => quote! { #ident: Value<Fp> },
                FieldKind::VecScalar => quote! { #ident: Vec<Value<Fp>> },
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
                    if is_simple_ident(other) {
                        push_scalar(other, &mut inits, &mut seen);
                    }
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

fn binding_priority(b: &GadgetBinding) -> u8 {
    match b {
        GadgetBinding::PoseidonCommit { .. } => 0,
        GadgetBinding::Range { .. } => 1,
        GadgetBinding::Comparison { .. } => 2,
        GadgetBinding::MerkleMember { .. } => 3,
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

    let mut instance_idx: usize = 0;

    for attr in attrs {
        let value_ident = format_ident!("{}", attr.param_name);
        let mut sorted = attr.bindings.clone();
        sorted.sort_by_key(binding_priority);
        for b in &sorted {
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
                GadgetBinding::MerkleMember { siblings_var, indices_var, .. } => {
                    stmts.extend(emit_merkle(&attr.param_name, siblings_var, indices_var)?);
                }
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

fn emit_merkle(
    param_name: &str,
    siblings_var: &str,
    indices_var: &str,
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
    }])
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
    let public_inputs_init = emit_public_inputs_schema_fields(attrs);
    let num_witness = count_witness_fields(attrs);
    let num_public = count_poseidon_commits(attrs);
    let unused_circuit = if num_public == 0 && num_witness == 0 {
        // Reference the type so the import is never dead even on empty circuits.
        quote! { let _ = std::marker::PhantomData::<#circuit_ident>; }
    } else {
        quote! {}
    };

    let tokens = quote! {
        use std::path::Path;
        use std::sync::OnceLock;

        use zerostyl_circuits::{
            CircuitDescriptor, CircuitError, CircuitIntrospection, FieldType, FieldVisibility,
            MockProverReport, ProofArtifact, PublicInputField, PublicInputsSchema,
            Result as CResult, WitnessField, WitnessSchema,
        };

        use super::circuit::#circuit_ident;

        pub struct #descriptor_ident;

        pub fn descriptor() -> &'static dyn CircuitDescriptor {
            static D: #descriptor_ident = #descriptor_ident;
            #unused_circuit
            &D
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

        impl CircuitDescriptor for #descriptor_ident {
            fn name(&self) -> &'static str { #circuit_name_lit }
            fn version(&self) -> &'static str { "1.0.0" }
            fn description(&self) -> &'static str { #description_lit }
            fn default_k(&self) -> u32 { 10 }
            fn num_public_inputs(&self) -> usize { #num_public }
            fn num_private_witnesses(&self) -> usize { #num_witness }
            fn witness_schema(&self) -> &'static WitnessSchema { witness_schema_static() }
            fn public_inputs_schema(&self) -> &'static PublicInputsSchema {
                public_inputs_schema_static()
            }

            fn prove(
                &self,
                _witness_json: &str,
                _k: u32,
                _cache_dir: &Path,
            ) -> CResult<ProofArtifact> {
                Err(CircuitError::Other(
                    "prove() pending — implementation lands in a follow-up commit".into(),
                ))
            }

            fn verify(
                &self,
                _proof: &[u8],
                _public_inputs_json: &str,
                _k: u32,
                _cache_dir: &Path,
            ) -> CResult<bool> {
                Err(CircuitError::Other(
                    "verify() pending — implementation lands in a follow-up commit".into(),
                ))
            }

            fn mock_prove(&self, _witness_json: &str, _k: u32) -> CResult<MockProverReport> {
                Err(CircuitError::Other(
                    "mock_prove() pending — implementation lands in a follow-up commit".into(),
                ))
            }

            fn inspect(&self) -> CResult<CircuitIntrospection> {
                Err(CircuitError::Other(
                    "inspect() pending — implementation lands in a follow-up commit".into(),
                ))
            }
        }
    };

    Ok(tokens.to_string())
}

fn count_witness_fields(attrs: &[ResolvedAttr]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for attr in attrs {
        seen.insert(attr.param_name.clone());
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { nonce_var } => {
                    seen.insert(nonce_var.clone());
                }
                GadgetBinding::Comparison { other, .. } => {
                    if is_simple_ident(other) {
                        seen.insert(other.clone());
                    }
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    seen.insert(root_var.clone());
                    seen.insert(siblings_var.clone());
                    seen.insert(indices_var.clone());
                }
                GadgetBinding::Range { .. } => {}
            }
        }
    }
    seen.len()
}

fn count_poseidon_commits(attrs: &[ResolvedAttr]) -> usize {
    attrs
        .iter()
        .flat_map(|a| a.bindings.iter())
        .filter(|b| matches!(b, GadgetBinding::PoseidonCommit { .. }))
        .count()
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
                GadgetBinding::Comparison { other, .. } => {
                    if is_simple_ident(other) && seen.insert(other.clone()) {
                        let kind = field_type_token(&attr.param_type)?;
                        out.push(quote! {
                            WitnessField {
                                name: #other.into(),
                                kind: #kind,
                                visibility: FieldVisibility::Private,
                                description: None,
                            }
                        });
                    }
                }
                GadgetBinding::MerkleMember { root_var, siblings_var, indices_var, .. } => {
                    if seen.insert(root_var.clone()) {
                        out.push(quote! {
                            WitnessField {
                                name: #root_var.into(),
                                kind: FieldType::Fp,
                                visibility: FieldVisibility::Private,
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

fn emit_public_inputs_schema_fields(attrs: &[ResolvedAttr]) -> Vec<TokenStream> {
    let mut out = Vec::new();
    for attr in attrs {
        for b in &attr.bindings {
            if matches!(b, GadgetBinding::PoseidonCommit { .. }) {
                let name = format!("{}_commitment", attr.param_name);
                out.push(quote! {
                    PublicInputField {
                        name: #name.into(),
                        kind: FieldType::Fp,
                        description: None,
                    }
                });
            }
        }
    }
    out
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
    use crate::parser::{AttrSpec, CommitScheme, Constraint, MerkleMemberSpec, RangeSpec};
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
        assert!(src.contains("DepositCircuit"));
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
            src.contains("num_public_inputs (& self) -> usize { 0usize }")
                || src.contains("num_public_inputs(&self) -> usize { 0usize }")
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
    fn descriptor_methods_stubbed_with_error() {
        let attrs = vec![resolved("x", "u64", vec![AttrSpec::Commit(CommitScheme::Poseidon)])];
        let src = emit_descriptor("foo", &attrs).unwrap();
        let stub_count = src.matches("CircuitError :: Other").count()
            + src.matches("CircuitError::Other").count();
        assert!(stub_count >= 4, "expected ≥4 stubbed methods, got {stub_count}");
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
}
