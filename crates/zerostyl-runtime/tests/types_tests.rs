//! Integration tests for core types in zerostyl-runtime

use zerostyl_runtime::{
    CircuitConfig, CommitmentHash, MerklePath, MerkleRoot, RangeProofConfig, ZkProof,
};

// --- ZkProof ---

#[test]
fn test_zkproof_creation() {
    let proof_bytes = vec![0u8; 64];
    let proof = ZkProof::new(proof_bytes.clone()).unwrap();

    assert_eq!(proof.size(), 64);
    assert_eq!(proof.as_bytes(), &proof_bytes[..]);
}

#[test]
fn test_zkproof_into_bytes() {
    let proof_bytes = vec![0xAB; 64];
    let proof = ZkProof::new(proof_bytes.clone()).unwrap();

    assert_eq!(proof.into_bytes(), proof_bytes);
}

#[test]
fn test_zkproof_serialization_roundtrip() {
    let proof = ZkProof::new(vec![0xDE; 64]).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let deserialized: ZkProof = serde_json::from_str(&json).unwrap();

    assert_eq!(proof, deserialized);
}

#[test]
fn test_zkproof_too_small() {
    let result = ZkProof::new(vec![0; 16]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Proof too small"));
}

#[test]
fn test_zkproof_exactly_minimum_size() {
    let proof = ZkProof::new(vec![0; ZkProof::MIN_PROOF_SIZE]).unwrap();
    assert_eq!(proof.size(), 32);
}

#[test]
fn test_zkproof_equality() {
    let p1 = ZkProof::new(vec![0; 64]).unwrap();
    let p2 = ZkProof::new(vec![0; 64]).unwrap();
    let p3 = ZkProof::new(vec![1; 64]).unwrap();

    assert_eq!(p1, p2);
    assert_ne!(p1, p3);
}

// --- CommitmentHash ---

#[test]
fn test_commitment_hash_creation() {
    let bytes = [0xAB; 32];
    let commitment = CommitmentHash::new(bytes);
    assert_eq!(commitment.as_bytes(), &bytes);
}

#[test]
fn test_commitment_hash_zero() {
    let zero = CommitmentHash::zero();
    assert_eq!(zero.as_bytes(), &[0u8; 32]);
}

#[test]
fn test_commitment_hash_equality() {
    let c1 = CommitmentHash::new([1; 32]);
    let c2 = CommitmentHash::new([1; 32]);
    let c3 = CommitmentHash::new([2; 32]);

    assert_eq!(c1, c2);
    assert_ne!(c1, c3);
}

#[test]
fn test_commitment_hash_copy() {
    let c1 = CommitmentHash::new([0xFF; 32]);
    let c2 = c1; // Copy
    assert_eq!(c1, c2);
}

#[test]
fn test_commitment_hash_serialization_roundtrip() {
    let commitment = CommitmentHash::new([0x42; 32]);
    let json = serde_json::to_string(&commitment).unwrap();
    let deserialized: CommitmentHash = serde_json::from_str(&json).unwrap();

    assert_eq!(commitment, deserialized);
}

// --- MerkleRoot ---

#[test]
fn test_merkle_root_creation() {
    let bytes = [0xCD; 32];
    let root = MerkleRoot::new(bytes);
    assert_eq!(root.as_bytes(), &bytes);
}

#[test]
fn test_merkle_root_equality() {
    let r1 = MerkleRoot::new([1; 32]);
    let r2 = MerkleRoot::new([1; 32]);
    let r3 = MerkleRoot::new([2; 32]);

    assert_eq!(r1, r2);
    assert_ne!(r1, r3);
}

#[test]
fn test_merkle_root_serialization_roundtrip() {
    let root = MerkleRoot::new([0xEF; 32]);
    let json = serde_json::to_string(&root).unwrap();
    let deserialized: MerkleRoot = serde_json::from_str(&json).unwrap();

    assert_eq!(root, deserialized);
}

// --- MerklePath ---

#[test]
fn test_merkle_path_default_depth() {
    let siblings = vec![[0u8; 32]; MerklePath::DEFAULT_DEPTH];
    let indices = vec![false; MerklePath::DEFAULT_DEPTH];
    let path = MerklePath::new(siblings, indices).unwrap();

    assert_eq!(path.depth(), 32);
}

#[test]
fn test_merkle_path_small_depth() {
    let siblings = vec![[1u8; 32]; 4];
    let indices = vec![true, false, true, false];
    let path = MerklePath::new(siblings, indices).unwrap();

    assert_eq!(path.depth(), 4);
    assert_eq!(path.indices(), &[true, false, true, false]);
}

#[test]
fn test_merkle_path_rejects_empty() {
    let result = MerklePath::new(vec![], vec![]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

#[test]
fn test_merkle_path_rejects_length_mismatch() {
    let result = MerklePath::new(vec![[0; 32]; 5], vec![false; 3]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("length mismatch"));
}

#[test]
fn test_merkle_path_rejects_exceeding_max_depth() {
    let depth = MerklePath::MAX_DEPTH + 1;
    let result = MerklePath::new(vec![[0; 32]; depth], vec![false; depth]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
}

#[test]
fn test_merkle_path_max_depth_accepted() {
    let depth = MerklePath::MAX_DEPTH;
    let path = MerklePath::new(vec![[0; 32]; depth], vec![false; depth]).unwrap();
    assert_eq!(path.depth(), 64);
}

#[test]
fn test_merkle_path_serialization_roundtrip() {
    let siblings = vec![[0xAA; 32]; 8];
    let indices = vec![true, false, true, false, true, false, true, false];
    let path = MerklePath::new(siblings, indices).unwrap();

    let json = serde_json::to_string(&path).unwrap();
    let deserialized: MerklePath = serde_json::from_str(&json).unwrap();

    assert_eq!(path, deserialized);
}

// --- RangeProofConfig ---

#[test]
fn test_range_proof_config_64bit() {
    let config = RangeProofConfig::new(64).unwrap();
    assert_eq!(config.num_bits(), 64);
    assert_eq!(config.max_value(), u64::MAX as u128);
}

#[test]
fn test_range_proof_config_all_supported_widths() {
    for &bits in &RangeProofConfig::SUPPORTED_BITS {
        let config = RangeProofConfig::new(bits).unwrap();
        assert_eq!(config.num_bits(), bits);
        assert_eq!(config.max_value(), (1u128 << bits) - 1);
    }
}

#[test]
fn test_range_proof_config_rejects_unsupported_width() {
    let result = RangeProofConfig::new(12);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported"));
}

#[test]
fn test_range_proof_config_rejects_zero() {
    let result = RangeProofConfig::new(0);
    assert!(result.is_err());
}

#[test]
fn test_range_proof_config_serialization_roundtrip() {
    let config = RangeProofConfig::new(32).unwrap();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: RangeProofConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config, deserialized);
}

// --- CircuitConfig ---

#[test]
fn test_circuit_config_minimal() {
    let config = CircuitConfig::minimal(17).unwrap();
    assert_eq!(config.k(), 17);
    assert_eq!(config.num_rows(), 131_072);
    assert_eq!(config.num_advice_columns(), 1);
    assert_eq!(config.num_instance_columns(), 1);
    assert_eq!(config.num_fixed_columns(), 0);
}

#[test]
fn test_circuit_config_new_with_columns() {
    let config = CircuitConfig::new(20, 5, 2, 3).unwrap();
    assert_eq!(config.k(), 20);
    assert_eq!(config.num_advice_columns(), 5);
    assert_eq!(config.num_instance_columns(), 2);
    assert_eq!(config.num_fixed_columns(), 3);
}

#[test]
fn test_circuit_config_k_too_small() {
    let result = CircuitConfig::minimal(3);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must be >= 4"));
}

#[test]
fn test_circuit_config_k_too_large() {
    let result = CircuitConfig::minimal(29);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too large"));
}

#[test]
fn test_circuit_config_k_boundary_min() {
    let config = CircuitConfig::minimal(CircuitConfig::MIN_K).unwrap();
    assert_eq!(config.k(), 4);
    assert_eq!(config.num_rows(), 16);
}

#[test]
fn test_circuit_config_k_boundary_max() {
    let config = CircuitConfig::minimal(CircuitConfig::MAX_K).unwrap();
    assert_eq!(config.k(), 28);
    assert_eq!(config.num_rows(), 268_435_456);
}

#[test]
fn test_circuit_config_new_k_validation() {
    let result = CircuitConfig::new(2, 1, 1, 0);
    assert!(result.is_err());

    let result2 = CircuitConfig::new(30, 1, 1, 0);
    assert!(result2.is_err());
}

#[test]
fn test_circuit_config_serialization_roundtrip() {
    let config = CircuitConfig::new(18, 4, 2, 1).unwrap();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: CircuitConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config, deserialized);
}

#[test]
fn test_circuit_config_equality() {
    let c1 = CircuitConfig::minimal(15).unwrap();
    let c2 = CircuitConfig::minimal(15).unwrap();
    let c3 = CircuitConfig::minimal(16).unwrap();

    assert_eq!(c1, c2);
    assert_ne!(c1, c3);
}