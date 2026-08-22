//! End-to-end SDK tests against the `zk_private_demo` circuit.

use std::path::PathBuf;

use zerostyl_sdk::{load_abi_file, WitnessBuilder, ZeroStyl};

fn demo_abi_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/zk_private_demo/abi.json")
}

fn demo_client() -> ZeroStyl {
    let mut client = ZeroStyl::new().expect("client");
    client.register(zk_private_demo::descriptor()).expect("register");
    client
}

fn demo_witness() -> WitnessBuilder {
    WitnessBuilder::new()
        .set_u64("collateral", 500_000)
        .set_u64("collateral_nonce", 42)
        .set_u64("threshold", 100_000)
}

#[test]
fn registry_lists_registered_circuit() {
    let client = demo_client();
    assert_eq!(client.circuits(), vec!["deposit"]);
    assert!(client.circuit("nope").is_err());
}

#[test]
fn abi_matches_exported_abi_json() {
    let client = demo_client();
    let from_descriptor = client.circuit("deposit").unwrap().abi();
    let from_disk = load_abi_file(&demo_abi_path()).expect("abi.json loads");
    assert_eq!(from_descriptor, from_disk);
}

#[test]
fn witness_builder_satisfies_mock_prover() {
    let client = demo_client();
    let circuit = client.circuit("deposit").unwrap();
    let witness =
        demo_witness().build_checked(circuit.descriptor().witness_schema()).expect("schema check");
    let report = circuit.mock_prove(&witness).expect("mock_prove runs");
    assert!(report.satisfied, "constraints unsatisfied: {:?}", report.failures);
}

#[test]
fn mock_prover_rejects_violated_constraint() {
    // threshold above collateral violates `collateral >= threshold`.
    let client = demo_client();
    let circuit = client.circuit("deposit").unwrap();
    let witness = WitnessBuilder::new()
        .set_u64("collateral", 10)
        .set_u64("collateral_nonce", 42)
        .set_u64("threshold", 100_000)
        .build();
    let result = circuit.mock_prove(&witness);
    let unsatisfied = match result {
        Ok(report) => !report.satisfied,
        Err(_) => true,
    };
    assert!(unsatisfied, "violated constraint must not satisfy the mock prover");
}

#[test]
fn public_inputs_roundtrip_via_wire_format() {
    let columns = vec![vec![[0x11u8; 32], [0x22u8; 32]]];
    let json = zerostyl_sdk::encode_public_inputs(&columns);
    assert_eq!(zerostyl_sdk::decode_public_inputs(&json).unwrap(), columns);
}

#[test]
fn seal_open_roundtrip_and_foreign_circuit_rejection() {
    let client = demo_client();
    let circuit = client.circuit("deposit").unwrap();
    let artifact = zerostyl_sdk::ProofArtifact::new(vec![0xab; 64], "{}".into());

    let sealed = circuit.seal(&artifact);
    assert_eq!(circuit.open(&sealed).unwrap(), artifact.bytes);

    // Corrupt the circuit id: open must refuse the envelope.
    let mut foreign = sealed.clone();
    foreign[4] ^= 0xff;
    let err = circuit.open(&foreign).unwrap_err();
    assert!(format!("{err}").contains("another circuit"));
}

#[test]
fn circuit_id_is_keccak_of_name() {
    let client = demo_client();
    let circuit = client.circuit("deposit").unwrap();
    assert_eq!(circuit.circuit_id(), *zerostyl_sdk::BytecodeFingerprint::of(b"deposit").as_bytes());
}

/// Full KZG prove + verify through the SDK. Ignored by default: params
/// generation for k=10 takes tens of seconds. Run with:
/// `cargo test -p zerostyl-sdk -- --ignored`
#[test]
#[ignore]
fn real_prove_and_verify_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut client = ZeroStyl::with_cache_dir(dir.path()).expect("client");
    client.register(zk_private_demo::descriptor()).expect("register");
    let circuit = client.circuit("deposit").unwrap();

    let witness = demo_witness().build();
    let artifact = circuit.prove(&witness).expect("prove");
    assert!(circuit.verify(&artifact.bytes, &artifact.public_inputs_json).expect("verify"));

    // Tampered proof must be rejected (verification returns false or errors).
    let mut tampered = artifact.bytes.clone();
    tampered[0] ^= 0xff;
    let accepted = circuit.verify(&tampered, &artifact.public_inputs_json).unwrap_or(false);
    assert!(!accepted, "tampered proof must not verify");
}
