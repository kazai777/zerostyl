use std::path::PathBuf;

use zerostyl_circuits::CircuitDescriptor;
use zerostyl_exporter::from_descriptor;

fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("snapshots")
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n").trim().to_string()
}

fn check_snapshot(desc: &'static dyn CircuitDescriptor) {
    let abi = from_descriptor(desc);
    let actual = serde_json::to_string_pretty(&abi).expect("serialize abi schema");
    let name = desc.name();
    let snap_path = snapshot_dir().join(format!("{name}_abi.snap.json"));
    let update = std::env::var("UPDATE_SNAPSHOTS").is_ok();

    match std::fs::read_to_string(&snap_path) {
        Ok(expected) if !update => {
            assert_eq!(
                normalize(&actual),
                normalize(&expected),
                "AbiSchema snapshot mismatch for '{name}'.\n\
                 Run `UPDATE_SNAPSHOTS=1 cargo test -p zerostyl-exporter --test snapshots` to re-bless if intentional."
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
fn example_abi_snapshot() {
    check_snapshot(example_demo::descriptor());
}

#[test]
fn state_mask_abi_snapshot() {
    check_snapshot(state_mask::descriptor());
}

#[test]
fn tx_privacy_abi_snapshot() {
    check_snapshot(tx_privacy::descriptor());
}

#[test]
fn private_vote_abi_snapshot() {
    check_snapshot(private_vote::descriptor());
}
