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

#[test]
fn test_zkproof_too_small_error() {
    let small_proof = vec![0; 16]; // Less than MIN_PROOF_SIZE (32)
    let result = ZkProof::new(small_proof);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Proof too small"));
    assert!(err_msg.contains("16 bytes"));
}

#[test]
fn test_zkproof_exactly_minimum_size() {
    let proof = ZkProof::new(vec![0; 32]).unwrap(); // Exactly MIN_PROOF_SIZE
    assert_eq!(proof.size(), 32);
}

#[test]
fn test_commitment_empty_value_error() {
    let empty_value = vec![];
    let randomness = vec![0; 32];
    let result = Commitment::new(empty_value, randomness, HashType::Pedersen);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("value cannot be empty"));
}

#[test]
fn test_commitment_empty_randomness_error() {
    let value = vec![1, 2, 3];
    let empty_randomness = vec![];
    let result = Commitment::new(value, empty_randomness, HashType::Pedersen);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("non-empty randomness"));
}

#[test]
fn test_commitment_short_randomness_error() {
    let value = vec![1, 2, 3];
    let short_randomness = vec![0; 16]; // Less than MIN_RANDOMNESS_SIZE (32)
    let result = Commitment::new(value, short_randomness, HashType::Poseidon);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Randomness too short"));
    assert!(err_msg.contains("16 bytes"));
}

#[test]
fn test_commitment_exactly_minimum_randomness() {
    let value = vec![100];
    let randomness = vec![0; 32]; // Exactly MIN_RANDOMNESS_SIZE
    let commitment = Commitment::new(value, randomness, HashType::Pedersen).unwrap();
    assert_eq!(commitment.randomness().len(), 32);
}

#[test]
fn test_circuit_config_k_too_small_error() {
    let result = CircuitConfig::minimal(3); // k < MIN_K (4)

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("must be >= 4"));
}

#[test]
fn test_circuit_config_k_too_large_error() {
    let result = CircuitConfig::minimal(29); // k > MAX_K (28)

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("too large"));
    assert!(err_msg.contains("max 28"));
}

#[test]
fn test_circuit_config_k_boundary_min() {
    let config = CircuitConfig::minimal(4).unwrap(); // Exactly MIN_K
    assert_eq!(config.k(), 4);
    assert_eq!(config.num_rows(), 16); // 2^4
}

#[test]
fn test_circuit_config_k_boundary_max() {
    let config = CircuitConfig::minimal(28).unwrap(); // Exactly MAX_K
    assert_eq!(config.k(), 28);
    assert_eq!(config.num_rows(), 268_435_456); // 2^28
}

#[test]
fn test_circuit_config_new_with_tables_and_gates() {
    let config = CircuitConfig::new(
        15,
        vec![LookupTable::Sha256, LookupTable::Pedersen],
        vec![CustomGate::MerklePathGate, CustomGate::PedersenHash],
    )
    .unwrap();

    assert_eq!(config.lookup_tables().len(), 2);
    assert_eq!(config.custom_gates().len(), 2);
    assert_eq!(config.lookup_tables()[0], LookupTable::Sha256);
    assert_eq!(config.custom_gates()[0], CustomGate::MerklePathGate);
}

#[test]
fn test_circuit_config_new_k_validation() {
    let result = CircuitConfig::new(2, vec![], vec![]); // k < MIN_K
    assert!(result.is_err());

    let result2 = CircuitConfig::new(30, vec![], vec![]); // k > MAX_K
    assert!(result2.is_err());
}

#[test]
fn test_hashtype_variants() {
    let pedersen = HashType::Pedersen;
    let poseidon = HashType::Poseidon;

    assert_ne!(pedersen, poseidon);
    assert_eq!(pedersen, HashType::Pedersen);
    assert_eq!(poseidon, HashType::Poseidon);
}

#[test]
fn test_lookup_table_variants() {
    let sha = LookupTable::Sha256;
    let ped = LookupTable::Pedersen;

    assert_ne!(sha, ped);
    assert_eq!(sha, LookupTable::Sha256);
}

#[test]
fn test_custom_gate_variants() {
    let gate1 = CustomGate::PedersenHash;
    let gate2 = CustomGate::MerklePathGate;

    assert_ne!(gate1, gate2);
    assert_eq!(gate1, CustomGate::PedersenHash);
}
