use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::error::{ExporterError, Result};
use crate::resolver::{GadgetBinding, ResolvedAttr};

pub fn emit_circuit(circuit_name: &str, attrs: &[ResolvedAttr]) -> Result<String> {
    validate_supported(attrs)?;
    enforce_single_poseidon(attrs)?;

    let circuit_ident = format_ident!("{}Circuit", to_pascal_case(circuit_name));
    let config_ident = format_ident!("{}Config", circuit_ident);

    let witness_fields = emit_witness_fields(attrs);
    let configure_body = emit_configure_body();
    let synthesize_body = emit_synthesize_body(attrs);

    let tokens = quote! {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
        };
        use halo2curves::pasta::Fp;
        use zerostyl_compiler::gadgets::{
            PoseidonCommitmentChip, PoseidonCommitmentConfig,
        };

        #[derive(Clone, Debug, Default)]
        pub struct #circuit_ident {
            #( pub #witness_fields, )*
        }

        #[derive(Debug, Clone)]
        pub struct #config_ident {
            poseidon_config: PoseidonCommitmentConfig,
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

fn validate_supported(attrs: &[ResolvedAttr]) -> Result<()> {
    for attr in attrs {
        for b in &attr.bindings {
            match b {
                GadgetBinding::PoseidonCommit { .. } => {}
                other => {
                    return Err(ExporterError::Parse(format!(
                        "codegen for {} not yet implemented (currently: PoseidonCommit only)",
                        binding_kind(other)
                    )));
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

fn binding_kind(b: &GadgetBinding) -> &'static str {
    match b {
        GadgetBinding::PoseidonCommit { .. } => "PoseidonCommit",
        GadgetBinding::Range { .. } => "Range",
        GadgetBinding::Comparison { .. } => "Comparison",
        GadgetBinding::MerkleMember { .. } => "MerkleMember",
    }
}

fn emit_witness_fields(attrs: &[ResolvedAttr]) -> Vec<TokenStream> {
    let mut fields = Vec::new();
    for attr in attrs {
        let param_ident = format_ident!("{}", attr.param_name);
        fields.push(quote! { #param_ident: Value<Fp> });
        for b in &attr.bindings {
            if let GadgetBinding::PoseidonCommit { nonce_var } = b {
                let nonce_ident = format_ident!("{}", nonce_var);
                fields.push(quote! { #nonce_ident: Value<Fp> });
            }
        }
    }
    fields
}

fn emit_configure_body() -> TokenStream {
    quote! {
        let poseidon_config = PoseidonCommitmentChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::Config { poseidon_config, instance }
    }
}

fn emit_synthesize_body(attrs: &[ResolvedAttr]) -> TokenStream {
    let mut stmts: Vec<TokenStream> = Vec::new();
    stmts.push(quote! {
        let poseidon_chip = PoseidonCommitmentChip::construct(config.poseidon_config);
    });

    let mut instance_idx: usize = 0;
    for attr in attrs {
        let value_ident = format_ident!("{}", attr.param_name);
        let value_cell_ident = format_ident!("{}_cell", attr.param_name);
        let load_value_label = format!("load {}", attr.param_name);
        stmts.push(quote! {
            let #value_cell_ident = poseidon_chip.load_private(
                layouter.namespace(|| #load_value_label),
                self.#value_ident,
                0,
            )?;
        });

        for b in &attr.bindings {
            if let GadgetBinding::PoseidonCommit { nonce_var } = b {
                let nonce_ident = format_ident!("{}", nonce_var);
                let nonce_cell_ident = format_ident!("{}_cell", nonce_var);
                let commitment_ident = format_ident!("{}_commitment", attr.param_name);
                let load_nonce_label = format!("load {}", nonce_var);
                let commit_label = format!("commit {}", attr.param_name);
                stmts.push(quote! {
                    let #nonce_cell_ident = poseidon_chip.load_private(
                        layouter.namespace(|| #load_nonce_label),
                        self.#nonce_ident,
                        1,
                    )?;
                    let #commitment_ident = poseidon_chip.commit(
                        layouter.namespace(|| #commit_label),
                        #value_cell_ident.clone(),
                        #nonce_cell_ident,
                    )?;
                    layouter.constrain_instance(
                        #commitment_ident.cell(),
                        config.instance,
                        #instance_idx,
                    )?;
                });
                instance_idx += 1;
            }
        }
    }

    stmts.push(quote! { Ok(()) });
    quote! { #( #stmts )* }
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
    use crate::parser::{AttrSpec, CommitScheme};
    use crate::resolver::resolve;

    fn poseidon_attr(name: &str, ty: &str) -> ResolvedAttr {
        let parsed = crate::parser::ZkPrivateAttr {
            param_name: name.into(),
            param_type: ty.into(),
            specs: vec![AttrSpec::Commit(CommitScheme::Poseidon)],
        };
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
    fn emit_poseidon_only_parses() {
        let attrs = vec![poseidon_attr("collateral", "u64")];
        let src = emit_circuit("deposit", &attrs).unwrap();
        parse_as_file(&src);
    }

    #[test]
    fn emit_poseidon_struct_has_value_and_nonce() {
        let attrs = vec![poseidon_attr("collateral", "u64")];
        let src = emit_circuit("deposit", &attrs).unwrap();
        assert!(src.contains("DepositCircuit"));
        assert!(src.contains("collateral"));
        assert!(src.contains("collateral_nonce"));
        assert!(src.contains("Value < Fp >") || src.contains("Value<Fp>"));
    }

    #[test]
    fn emit_poseidon_calls_chip_construct_and_commit() {
        let attrs = vec![poseidon_attr("collateral", "u64")];
        let src = emit_circuit("deposit", &attrs).unwrap();
        assert!(src.contains("PoseidonCommitmentChip"));
        assert!(src.contains("construct"));
        assert!(src.contains("load_private"));
        assert!(src.contains("commit"));
        assert!(src.contains("constrain_instance"));
    }

    #[test]
    fn emit_imports_halo2_and_gadget() {
        let attrs = vec![poseidon_attr("x", "u64")];
        let src = emit_circuit("foo", &attrs).unwrap();
        assert!(src.contains("halo2_proofs"));
        assert!(
            src.contains("halo2curves :: pasta :: Fp") || src.contains("halo2curves::pasta::Fp")
        );
        assert!(
            src.contains("zerostyl_compiler :: gadgets")
                || src.contains("zerostyl_compiler::gadgets")
        );
    }

    #[test]
    fn emit_config_struct_has_poseidon_and_instance_fields() {
        let attrs = vec![poseidon_attr("x", "u64")];
        let src = emit_circuit("foo", &attrs).unwrap();
        assert!(src.contains("FooCircuitConfig"));
        assert!(src.contains("poseidon_config"));
        assert!(src.contains("instance"));
    }

    #[test]
    fn emit_impl_circuit_includes_required_methods() {
        let attrs = vec![poseidon_attr("x", "u64")];
        let src = emit_circuit("foo", &attrs).unwrap();
        assert!(src.contains("fn without_witnesses"));
        assert!(src.contains("fn configure"));
        assert!(src.contains("fn synthesize"));
        assert!(src.contains("SimpleFloorPlanner"));
    }

    #[test]
    fn rejects_range_binding_for_now() {
        use crate::parser::{RangeSpec, ZkPrivateAttr};
        let parsed = ZkPrivateAttr {
            param_name: "x".into(),
            param_type: "u64".into(),
            specs: vec![AttrSpec::Range(RangeSpec {
                low: "0".into(),
                high: "100".into(),
                inclusive: true,
            })],
        };
        let resolved = resolve(&parsed).unwrap();
        let err = emit_circuit("foo", &[resolved]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Range"), "expected Range in error, got: {msg}");
    }

    #[test]
    fn rejects_multiple_poseidon_commits() {
        let attrs = vec![poseidon_attr("a", "u64"), poseidon_attr("b", "u64")];
        let err = emit_circuit("foo", &attrs).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at most one PoseidonCommit"));
    }
}
