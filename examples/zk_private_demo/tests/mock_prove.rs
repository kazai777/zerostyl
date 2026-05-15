use zerostyl_circuits::{register_circuit, Registry};
use zk_private_demo::descriptor;

const K: u32 = 10;

#[test]
fn descriptor_registers_via_register_circuit_macro() {
    let registry = Registry::new();
    register_circuit!(registry, zk_private_demo).expect("register_circuit! succeeds");
    let retrieved = registry.get("deposit").expect("descriptor must be retrievable by name");
    assert_eq!(retrieved.name(), "deposit");
}

#[test]
fn mock_prove_satisfied_with_valid_witness() {
    let witness = r#"{
        "collateral": "1000",
        "threshold": "500",
        "collateral_nonce": "42"
    }"#;
    let report = descriptor().mock_prove(witness, K).expect("mock_prove succeeds");
    assert!(report.satisfied, "expected satisfied report, got: {report:?}");
    assert!(report.failures.is_empty(), "expected no failures, got: {:?}", report.failures);
    assert_eq!(report.circuit_name, "deposit");
    assert_eq!(report.k, K);
}

#[test]
fn mock_prove_fails_when_collateral_below_threshold() {
    let witness = r#"{
        "collateral": "100",
        "threshold": "500",
        "collateral_nonce": "42"
    }"#;
    let report = descriptor().mock_prove(witness, K).expect("mock_prove returns a report");
    assert!(!report.satisfied, "comparison should reject collateral < threshold");
    assert!(!report.failures.is_empty());
}

#[test]
fn descriptor_metadata_matches_codegen() {
    let d = descriptor();
    assert_eq!(d.name(), "deposit");
    assert_eq!(d.version(), "1.0.0");
    assert_eq!(d.num_public_inputs(), 1);
    assert_eq!(d.num_private_witnesses(), 3);

    let witness_schema = d.witness_schema();
    assert_eq!(witness_schema.fields.len(), 3);
    let names: Vec<&str> = witness_schema.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"collateral"));
    assert!(names.contains(&"threshold"));
    assert!(names.contains(&"collateral_nonce"));

    let pub_schema = d.public_inputs_schema();
    assert_eq!(pub_schema.fields.len(), 1);
    assert!(pub_schema.fields[0].name.contains("commitment"));
}

#[test]
fn inspect_reports_constraint_system_shape() {
    let intro = descriptor().inspect().expect("inspect succeeds");
    assert_eq!(intro.circuit_name, "deposit");
    assert!(intro.num_advice_columns > 0, "expected at least one advice column");
    assert!(intro.max_constraint_degree >= 1);
}
