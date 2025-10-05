//! ZeroStyl Runtime
//!
//! Shared runtime utilities and core types for the ZeroStyl toolkit.
//! This crate provides common data structures and error handling used across
//! all ZeroStyl components.

pub mod error;
pub mod types;

// Re-export core types for convenience
pub use error::{Result, ZeroStylError};
pub use types::{CircuitConfig, Commitment, ZkProof};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkproof_basic_constructor() {
        let proof = ZkProof::new(vec![]);
        assert_eq!(proof.size(), 0);
    }

    #[test]
    fn test_commitment_debug_trait() {
        let commitment = Commitment::new(vec![1], vec![2]);
        let debug_str = format!("{:?}", commitment);
        assert!(debug_str.contains("Commitment"));
    }

    #[test]
    fn test_circuit_config_debug_trait() {
        let config = CircuitConfig::minimal(10);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("CircuitConfig"));
    }

    #[test]
    fn test_zkproof_equality() {
        let proof1 = ZkProof::new(vec![1, 2, 3]);
        let proof2 = ZkProof::new(vec![1, 2, 3]);
        let proof3 = ZkProof::new(vec![4, 5, 6]);

        assert_eq!(proof1, proof2);
        assert_ne!(proof1, proof3);
    }

    #[test]
    fn test_commitment_equality() {
        let comm1 = Commitment::new(vec![1], vec![2]);
        let comm2 = Commitment::new(vec![1], vec![2]);
        let comm3 = Commitment::new(vec![3], vec![4]);

        assert_eq!(comm1, comm2);
        assert_ne!(comm1, comm3);
    }

    #[test]
    fn test_circuit_config_equality() {
        let config1 = CircuitConfig::minimal(15);
        let config2 = CircuitConfig::minimal(15);
        let config3 = CircuitConfig::minimal(16);

        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }
}
