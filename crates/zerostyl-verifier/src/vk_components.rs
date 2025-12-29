//! VK Components - Custom serialization for no_std verification

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use halo2curves::group::ff::PrimeField;
use halo2curves::group::GroupEncoding;
use halo2curves::pasta::{EqAffine, Fp};
use serde::{Deserialize, Serialize};

/// Serializable VK components extracted from halo2 VerifyingKey
///
/// This contains only the essential data needed for verification,
/// optimized for no_std and minimal size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkComponents {
    /// Domain parameter k (n = 2^k)
    pub k: u32,

    /// Extended domain parameter (used for gate evaluation)
    pub extended_k: u32,

    /// Domain generator omega
    pub omega: Vec<u8>,

    /// Number of fixed columns
    pub num_fixed_columns: usize,

    /// Number of advice columns
    pub num_advice_columns: usize,

    /// Number of instance columns
    pub num_instance_columns: usize,

    /// Number of selectors
    pub num_selectors: usize,

    /// Fixed commitments (serialized as compressed affine points)
    /// Each point is 64 bytes (32 bytes x + 32 bytes y)
    pub fixed_commitments: Vec<Vec<u8>>,

    /// Permutation commitments (serialized as compressed affine points)
    /// Each point is 64 bytes (32 bytes x + 32 bytes y)
    pub permutation_commitments: Vec<Vec<u8>>,

    /// Permutation column indices
    /// Format: (column_index, column_type) where column_type: 0=Advice, 1=Instance, 2=Fixed
    pub permutation_columns: Vec<(usize, u8)>,
}

impl VkComponents {
    /// Serialize VK components to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize VK components from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get domain size (n = 2^k)
    pub fn domain_size(&self) -> usize {
        1 << self.k
    }

    /// Get extended domain size
    pub fn extended_domain_size(&self) -> usize {
        1 << self.extended_k
    }

    /// Deserialize omega as Fp
    pub fn get_omega(&self) -> Result<Fp, &'static str> {
        if self.omega.len() != 32 {
            return Err("Invalid omega length");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.omega);
        Option::from(Fp::from_repr(bytes)).ok_or("Failed to deserialize omega")
    }

    /// Deserialize a fixed commitment
    pub fn get_fixed_commitment(&self, index: usize) -> Result<EqAffine, &'static str> {
        if index >= self.fixed_commitments.len() {
            return Err("Fixed commitment index out of bounds");
        }

        let bytes = &self.fixed_commitments[index];
        deserialize_affine_point(bytes)
    }

    /// Deserialize a permutation commitment
    pub fn get_permutation_commitment(&self, index: usize) -> Result<EqAffine, &'static str> {
        if index >= self.permutation_commitments.len() {
            return Err("Permutation commitment index out of bounds");
        }

        let bytes = &self.permutation_commitments[index];
        deserialize_affine_point(bytes)
    }

    /// Get all fixed commitments
    pub fn get_all_fixed_commitments(&self) -> Result<Vec<EqAffine>, &'static str> {
        self.fixed_commitments.iter().map(|bytes| deserialize_affine_point(bytes)).collect()
    }

    /// Get all permutation commitments
    pub fn get_all_permutation_commitments(&self) -> Result<Vec<EqAffine>, &'static str> {
        self.permutation_commitments.iter().map(|bytes| deserialize_affine_point(bytes)).collect()
    }
}

/// Serialize an affine point to bytes (compressed format, 32 bytes)
pub fn serialize_affine_point(point: &EqAffine) -> Vec<u8> {
    point.to_bytes().as_ref().to_vec()
}

/// Deserialize an affine point from bytes
fn deserialize_affine_point(bytes: &[u8]) -> Result<EqAffine, &'static str> {
    if bytes.len() != 32 {
        return Err("Invalid affine point length (expected 32 bytes compressed)");
    }

    let mut fixed_bytes = [0u8; 32];
    fixed_bytes.copy_from_slice(bytes);

    Option::from(EqAffine::from_bytes(&fixed_bytes)).ok_or("Failed to deserialize affine point")
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::group::{Curve, Group};
    use halo2curves::pasta::Eq;

    #[test]
    fn test_affine_point_serialization() {
        let point = Eq::generator().to_affine();
        let bytes = serialize_affine_point(&point);
        assert_eq!(bytes.len(), 32); // Compressed format
        let recovered = deserialize_affine_point(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_vk_components_serialization() {
        let vk = VkComponents {
            k: 10,
            extended_k: 11,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![vec![0u8; 32], vec![1u8; 32]],
            permutation_commitments: vec![
                vec![2u8; 32],
                vec![3u8; 32],
                vec![4u8; 32],
                vec![5u8; 32],
            ],
            permutation_columns: vec![(0, 0), (1, 0), (2, 0), (0, 1)],
        };

        let bytes = vk.to_bytes().unwrap();
        let recovered = VkComponents::from_bytes(&bytes).unwrap();

        assert_eq!(vk.k, recovered.k);
        assert_eq!(vk.num_advice_columns, recovered.num_advice_columns);
        assert_eq!(vk.fixed_commitments.len(), recovered.fixed_commitments.len());
    }
}
