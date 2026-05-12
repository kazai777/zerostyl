//! Schema snapshot tests for the four bundled descriptors.
//!
//! Locks in the JSON shape of each circuit's `witness_schema()` and
//! `public_inputs_schema()`. A failing test means the schema changed —
//! either fix the regression or, if intentional, re-bless the snapshot:
//!
//! ```bash
//! UPDATE_SNAPSHOTS=1 cargo test -p zerostyl-cli --test snapshots
//! ```

use std::path::PathBuf;

use zerostyl_circuits::CircuitDescriptor;

fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("snapshots")
}

/// Normalize line endings so snapshots are stable across Windows (CRLF) and Unix (LF).
fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n").trim().to_string()
}

fn check_snapshot(desc: &'static dyn CircuitDescriptor) {
    let combined = serde_json::json!({
        "witness_schema": desc.witness_schema(),
        "public_inputs_schema": desc.public_inputs_schema(),
    });
    let actual = serde_json::to_string_pretty(&combined).expect("serialize schema");
    let name = desc.name();
    let snap_path = snapshot_dir().join(format!("{name}_schema.snap.json"));
    let update = std::env::var("UPDATE_SNAPSHOTS").is_ok();

    match std::fs::read_to_string(&snap_path) {
        Ok(expected) if !update => {
            assert_eq!(
                normalize(&actual),
                normalize(&expected),
                "Schema snapshot mismatch for '{name}'.\n\
                 Run `UPDATE_SNAPSHOTS=1 cargo test -p zerostyl-cli --test snapshots` to re-bless if intentional."
            );
        }
        _ => {
            std::fs::create_dir_all(snapshot_dir()).expect("create snapshots dir");
            std::fs::write(&snap_path, &actual).expect("write snapshot");
            eprintln!("[snapshot] wrote {snap_path:?}");
        }
    }
}

#[test]
fn example_schema_snapshot() {
    check_snapshot(example_demo::descriptor());
}

#[test]
fn state_mask_schema_snapshot() {
    check_snapshot(state_mask::descriptor());
}

#[test]
fn tx_privacy_schema_snapshot() {
    check_snapshot(tx_privacy::descriptor());
}

#[test]
fn private_vote_schema_snapshot() {
    check_snapshot(private_vote::descriptor());
}
