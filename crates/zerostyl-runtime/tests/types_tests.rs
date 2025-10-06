//! Integration tests for core types in zerostyl-runtime

use zerostyl_runtime::{CircuitConfig, Commitment, CustomGate, HashType, LookupTable, ZkProof};

#[test]
fn test_zkproof_creation() {
    let proof_bytes = vec![0; 64]; // Minimum 32 bytes
    let proof = ZkProof::new(proof_bytes.clone()).unwrap();

    assert_eq!(proof.size(), 64);
    assert_eq!(proof.as_bytes(), &proof_bytes[..]);
}

#[test]
fn test_zkproof_into_bytes() {
    let proof_bytes = vec![0; 64]; // Minimum 32 bytes
    let proof = ZkProof::new(proof_bytes.clone()).unwrap();

    let recovered_bytes = proof.into_bytes();
    assert_eq!(recovered_bytes, proof_bytes);
}

#[test]
fn test_zkproof_serialization() {
    let proof_bytes = vec![0xDE; 64];
    let proof = ZkProof::new(proof_bytes).unwrap();

    let json = serde_json::to_string(&proof).expect("Failed to serialize proof");

    let deserialized: ZkProof = serde_json::from_str(&json).expect("Failed to deserialize proof");

    assert_eq!(deserialized.as_bytes().len(), 64);
}

#[test]
fn test_zkproof_clone() {
    let proof_bytes = vec![0; 64];
    let proof1 = ZkProof::new(proof_bytes).unwrap();
    let proof2 = proof1.clone();

    assert_eq!(proof1.as_bytes(), proof2.as_bytes());
}

#[test]
fn test_commitment_creation() {
    let value = vec![100, 200];
    let randomness = vec![0; 32]; // Minimum 32 bytes

    let commitment =
        Commitment::new(value.clone(), randomness.clone(), HashType::Pedersen).unwrap();

    assert_eq!(commitment.value(), &value[..]);
    assert_eq!(commitment.randomness(), &randomness[..]);
    assert_eq!(commitment.hash_type(), HashType::Pedersen);
}

#[test]
fn test_commitment_serialization() {
    let commitment = Commitment::new(vec![1, 2, 3], vec![0; 32], HashType::Poseidon).unwrap();

    let json = serde_json::to_string(&commitment).expect("Failed to serialize commitment");
    let deserialized: Commitment =
        serde_json::from_str(&json).expect("Failed to deserialize commitment");

    assert_eq!(deserialized.value(), commitment.value());
    assert_eq!(deserialized.randomness(), commitment.randomness());
    assert_eq!(deserialized.hash_type(), commitment.hash_type());
}

#[test]
fn test_commitment_clone() {
    let commitment1 = Commitment::new(vec![10, 20], vec![0; 32], HashType::Pedersen).unwrap();
    let commitment2 = commitment1.clone();

    assert_eq!(commitment1.value(), commitment2.value());
    assert_eq!(commitment1.randomness(), commitment2.randomness());
    assert_eq!(commitment1.hash_type(), commitment2.hash_type());
}

#[test]
fn test_circuit_config_minimal() {
    let config = CircuitConfig::minimal(17).unwrap();

    assert_eq!(config.k(), 17);
    assert_eq!(config.num_rows(), 131_072); // 2^17
    assert!(config.custom_params().is_empty());
}

#[test]
fn test_circuit_config_with_params() {
    let config =
        CircuitConfig::new(20, vec![LookupTable::Pedersen], vec![CustomGate::PedersenHash])
            .unwrap();

    assert_eq!(config.k(), 20);
    assert_eq!(config.num_rows(), 1_048_576); // 2^20
    assert_eq!(config.lookup_tables().len(), 1);
    assert_eq!(config.custom_gates().len(), 1);
}

#[test]
fn test_circuit_config_add_param() {
    let mut config = CircuitConfig::minimal(15).unwrap();

    config.add_param("timeout".to_string(), "30".to_string());
    assert_eq!(config.custom_params().len(), 1);
    assert_eq!(config.custom_params().get("timeout"), Some(&"30".to_string()));
}

#[test]
fn test_circuit_config_serialization() {
    let mut config = CircuitConfig::minimal(18).unwrap();
    config.add_param("privacy_level".to_string(), "high".to_string());

    let json = serde_json::to_string(&config).expect("Failed to serialize config");
    let deserialized: CircuitConfig =
        serde_json::from_str(&json).expect("Failed to deserialize config");

    assert_eq!(deserialized.k(), 18);
    assert_eq!(deserialized.custom_params().len(), 1);
}

#[test]
fn test_circuit_config_clone() {
    let config1 = CircuitConfig::minimal(16).unwrap();
    let config2 = config1.clone();

    assert_eq!(config1.k(), config2.k());
    assert_eq!(config1.num_rows(), config2.num_rows());
}
