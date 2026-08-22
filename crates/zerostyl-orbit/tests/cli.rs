//! CLI integration tests, driving the compiled `zerostyl-orbit` binary.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zerostyl-orbit"))
}

#[test]
fn list_shows_builtin_profiles() {
    let out = bin().arg("list").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("arbitrum-sepolia"));
    assert!(stdout.contains("my-orbit-chain"));
}

#[test]
fn show_builtin_emits_toml() {
    let out = bin().args(["show", "--chain", "arbitrum-one"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("chain_id = 42161"));
    assert!(stdout.contains("[limits]"));
}

#[test]
fn show_unknown_chain_fails() {
    let out = bin().args(["show", "--chain", "nope"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn init_writes_template_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.toml");

    let out = bin().args(["init", "--output"]).arg(&path).output().unwrap();
    assert!(out.status.success());
    assert!(path.exists());
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("my-orbit-chain"));

    // Second run must refuse to overwrite.
    let out2 = bin().args(["init", "--output"]).arg(&path).output().unwrap();
    assert!(!out2.status.success());
}

#[test]
fn check_reports_deployability_for_a_measured_file() {
    let dir = tempfile::tempdir().unwrap();
    // A small, incompressible-ish artifact well under the 24 KB cap.
    let wasm = dir.path().join("tiny.wasm");
    std::fs::write(&wasm, vec![0u8; 4096]).unwrap();

    let out = bin()
        .args(["check", "--chain", "arbitrum-sepolia", "--wasm"])
        .arg(&wasm)
        .args(["--proving-system", "halo2_kzg"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("DEPLOYABLE"));
    assert!(stdout.contains("ecPairing"));
}

#[test]
fn check_rejects_unknown_proving_system() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = dir.path().join("tiny.wasm");
    std::fs::write(&wasm, vec![0u8; 16]).unwrap();
    let out = bin()
        .args(["check", "--chain", "arbitrum-one", "--wasm"])
        .arg(&wasm)
        .args(["--proving-system", "groth16"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn matrix_covers_all_builtins() {
    let dir = tempfile::tempdir().unwrap();
    let wasm = dir.path().join("art.wasm");
    std::fs::write(&wasm, vec![7u8; 8192]).unwrap();

    let out = bin().args(["matrix", "--wasm"]).arg(&wasm).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for name in ["arbitrum-one", "arbitrum-nova", "arbitrum-sepolia", "my-orbit-chain"] {
        assert!(stdout.contains(name), "matrix output missing {name}");
    }
}
