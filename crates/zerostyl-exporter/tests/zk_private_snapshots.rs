//! Set `REGEN_ZK_PRIVATE_SNAPSHOTS=1` to overwrite the committed snapshot files
//! instead of asserting equality — use after intentional codegen changes.

use std::fs;
use std::path::PathBuf;

use syn::ItemFn;
use zerostyl_exporter::{
    emit_abi_json, emit_circuit, emit_descriptor, emit_transformed_contract, parser::parse_fn,
    resolver::resolve_all,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn snapshots_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots")
}

fn pretty(src: &str) -> String {
    let file: syn::File = syn::parse_str(src).expect("emit_* output must parse as a Rust file");
    prettyplease::unparse(&file)
}

fn extract_fn(source: &str) -> ItemFn {
    let file: syn::File = syn::parse_str(source).expect("fixture source parses as Rust");
    for item in file.items {
        if let syn::Item::Fn(f) = item {
            return f;
        }
    }
    panic!("no fn found in fixture");
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn snapshot_for(fixture: &str, circuit_name: &str) {
    let source = fs::read_to_string(fixtures_dir().join(format!("{fixture}.rs.in")))
        .expect("fixture readable");
    let item_fn = extract_fn(&source);
    let attrs = parse_fn(&item_fn).expect("parse_fn");
    let resolved = resolve_all(&attrs).expect("resolve_all");

    let circuit_src = pretty(&emit_circuit(circuit_name, &resolved).expect("emit_circuit"));
    let descriptor_src =
        pretty(&emit_descriptor(circuit_name, &resolved).expect("emit_descriptor"));
    let transformed_src =
        pretty(&emit_transformed_contract(&item_fn).expect("emit_transformed_contract"));
    let abi_json = format!("{}\n", emit_abi_json(circuit_name, &resolved).expect("emit_abi_json"));

    let dir = snapshots_dir();
    let entries: [(PathBuf, &str); 4] = [
        (dir.join(format!("{fixture}_circuit.snap.rs")), &circuit_src),
        (dir.join(format!("{fixture}_descriptor.snap.rs")), &descriptor_src),
        (dir.join(format!("{fixture}_transformed.snap.rs")), &transformed_src),
        (dir.join(format!("{fixture}_abi.snap.json")), &abi_json),
    ];

    if std::env::var("REGEN_ZK_PRIVATE_SNAPSHOTS").is_ok() {
        for (path, content) in &entries {
            fs::write(path, content).expect("write snapshot");
        }
        return;
    }

    for (path, expected) in &entries {
        let on_disk = fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "snapshot {} missing: {e} — run `REGEN_ZK_PRIVATE_SNAPSHOTS=1 cargo test -p zerostyl-exporter zk_private_snapshots`",
                path.display()
            )
        });
        assert_eq!(
            normalize(&on_disk),
            normalize(expected),
            "{} is out of sync; run `REGEN_ZK_PRIVATE_SNAPSHOTS=1 cargo test -p zerostyl-exporter zk_private_snapshots`",
            path.display()
        );
    }
}

#[test]
fn zk_private_merkle_snapshots_in_sync() {
    snapshot_for("zk_private_merkle", "claim");
}

#[test]
fn zk_private_range_snapshots_in_sync() {
    snapshot_for("zk_private_range", "deposit");
}
