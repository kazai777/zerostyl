//! Integration tests for core types in zerostyl-runtime

use zerostyl_runtime::{CircuitConfig, Commitment, ZkProof};

#[test]
fn test_zkproof_creation() {
    let proof_bytes = vec![1, 2, 3, 4, 5];
    let proof = ZkProof::new(proof_bytes.clone());

    assert_eq!(proof.size(), 5);
    assert_eq!(proof.as_bytes(), &proof_bytes[..]);
}

#[test]
fn test_zkproof_into_bytes() {
    let proof_bytes = vec![10, 20, 30, 40];
    let proof = ZkProof::new(proof_bytes.clone());

    let recovered_bytes = proof.into_bytes();
    assert_eq!(recovered_bytes, proof_bytes);
}

#[test]
fn test_zkproof_serialization() {
    let proof_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let proof = ZkProof::new(proof_bytes);

    let json = serde_json::to_string(&proof).expect("Failed to serialize proof");

    let deserialized: ZkProof = serde_json::from_str(&json).expect("Failed to deserialize proof");

    assert_eq!(deserialized.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_zkproof_clone() {
    let proof_bytes = vec![1, 2, 3];
    let proof1 = ZkProof::new(proof_bytes);
    let proof2 = proof1.clone();

    assert_eq!(proof1.as_bytes(), proof2.as_bytes());
}

#[test]
fn test_commitment_creation() {
    let value = vec![100, 200];
    let randomness = vec![50, 75];

    let commitment = Commitment::new(value.clone(), randomness.clone());

    assert_eq!(commitment.value(), &value[..]);
    assert_eq!(commitment.randomness(), &randomness[..]);
}

#[test]
fn test_commitment_serialization() {
    let commitment = Commitment::new(vec![1, 2, 3], vec![4, 5, 6]);

    let json = serde_json::to_string(&commitment).expect("Failed to serialize commitment");
    let deserialized: Commitment =
        serde_json::from_str(&json).expect("Failed to deserialize commitment");

    assert_eq!(deserialized.value(), commitment.value());
    assert_eq!(deserialized.randomness(), commitment.randomness());
}

#[test]
fn test_commitment_clone() {
    let commitment1 = Commitment::new(vec![10, 20], vec![30, 40]);
    let commitment2 = commitment1.clone();

    assert_eq!(commitment1.value(), commitment2.value());
    assert_eq!(commitment1.randomness(), commitment2.randomness());
}

#[test]
fn test_circuit_config_minimal() {
    let config = CircuitConfig::minimal(17);

    assert_eq!(config.k(), 17);
    assert_eq!(config.num_rows(), 131_072); // 2^17
    assert!(config.custom_params().is_empty());
}

#[test]
fn test_circuit_config_with_params() {
    let params = vec![
        ("max_transfers".to_string(), "10".to_string()),
        ("batch_size".to_string(), "5".to_string()),
    ];
    let config = CircuitConfig::new(20, params.clone());

    assert_eq!(config.k(), 20);
    assert_eq!(config.num_rows(), 1_048_576); // 2^20
    assert_eq!(config.custom_params().len(), 2);
    assert_eq!(config.custom_params()[0].0, "max_transfers");
    assert_eq!(config.custom_params()[0].1, "10");
}

#[test]
fn test_circuit_config_add_param() {
    let mut config = CircuitConfig::minimal(15);

    config.add_param("timeout".to_string(), "30".to_string());
    assert_eq!(config.custom_params().len(), 1);
    assert_eq!(config.custom_params()[0].0, "timeout");
}

#[test]
fn test_circuit_config_serialization() {
    let config = CircuitConfig::new(18, vec![("privacy_level".to_string(), "high".to_string())]);

    let json = serde_json::to_string(&config).expect("Failed to serialize config");
    let deserialized: CircuitConfig =
        serde_json::from_str(&json).expect("Failed to deserialize config");

    assert_eq!(deserialized.k(), 18);
    assert_eq!(deserialized.custom_params().len(), 1);
}

#[test]
fn test_circuit_config_clone() {
    let config1 = CircuitConfig::minimal(16);
    let config2 = config1.clone();

    assert_eq!(config1.k(), config2.k());
    assert_eq!(config1.num_rows(), config2.num_rows());
}
