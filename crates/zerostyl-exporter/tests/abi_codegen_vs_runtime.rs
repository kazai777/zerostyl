//! Cross-check that the codegen-time AbiSchema (built from ResolvedAttr without
//! compilation) matches the runtime AbiSchema (built from the compiled
//! descriptor via from_descriptor). Locks the two paths together.

use std::fs;
use std::path::PathBuf;

use syn::ItemFn;
use zerostyl_exporter::{
    from_attrs, from_descriptor, parser::parse_fn, resolver::resolve_all, schema::AbiSchema,
};

#[test]
fn from_attrs_matches_from_descriptor_for_zk_private_demo() {
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/zk_private_demo/contract_source.rs")
        .canonicalize()
        .expect("contract_source.rs path resolves");
    let source = fs::read_to_string(&source_path).expect("contract_source.rs readable");

    let file: syn::File = syn::parse_str(&source).expect("source parses as Rust file");
    let item_fn: ItemFn = file
        .items
        .into_iter()
        .find_map(|i| if let syn::Item::Fn(f) = i { Some(f) } else { None })
        .expect("fn present in source");

    let attrs = parse_fn(&item_fn).expect("parse_fn succeeds");
    let resolved = resolve_all(&attrs).expect("resolve_all succeeds");
    let codegen_time: AbiSchema = from_attrs("deposit", &resolved).expect("from_attrs succeeds");

    let runtime: AbiSchema = from_descriptor(zk_private_demo::descriptor());

    assert_eq!(codegen_time, runtime, "codegen-time AbiSchema must match runtime AbiSchema");
}
