//! VK Components - Serialization for no_std verification

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use halo2curves::group::ff::PrimeField;
use halo2curves::group::GroupEncoding;
use halo2curves::pasta::{EqAffine, Fp};
use serde::{Deserialize, Serialize};

/// Serializable VK components extracted from halo2 VerifyingKey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkComponents {
    /// Domain parameter k (n = 2^k)
    pub k: u32,
    /// Extended domain parameter
    pub extended_k: u32,
    /// Domain generator omega (32 bytes)
    pub omega: Vec<u8>,
    pub num_fixed_columns: usize,
    pub num_advice_columns: usize,
    pub num_instance_columns: usize,
    pub num_selectors: usize,
    /// Fixed commitments (32 bytes each, compressed)
    pub fixed_commitments: Vec<Vec<u8>>,
    /// Permutation commitments (32 bytes each, compressed)
    pub permutation_commitments: Vec<Vec<u8>>,
    /// Permutation columns: (index, type) where type: 0=Advice, 1=Instance, 2=Fixed
    pub permutation_columns: Vec<(usize, u8)>,
}

impl VkComponents {
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    pub fn domain_size(&self) -> usize {
        1 << self.k
    }

    pub fn extended_domain_size(&self) -> usize {
        1 << self.extended_k
    }

    pub fn get_omega(&self) -> Result<Fp, &'static str> {
        if self.omega.len() != 32 {
            return Err("Invalid omega length");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.omega);
        Option::from(Fp::from_repr(bytes)).ok_or("Failed to deserialize omega")
    }

    pub fn get_fixed_commitment(&self, index: usize) -> Result<EqAffine, &'static str> {
        if index >= self.fixed_commitments.len() {
            return Err("Fixed commitment index out of bounds");
        }
        deserialize_affine_point(&self.fixed_commitments[index])
    }

    pub fn get_permutation_commitment(&self, index: usize) -> Result<EqAffine, &'static str> {
        if index >= self.permutation_commitments.len() {
            return Err("Permutation commitment index out of bounds");
        }
        deserialize_affine_point(&self.permutation_commitments[index])
    }

    pub fn get_all_fixed_commitments(&self) -> Result<Vec<EqAffine>, &'static str> {
        self.fixed_commitments.iter().map(|b| deserialize_affine_point(b)).collect()
    }

    pub fn get_all_permutation_commitments(&self) -> Result<Vec<EqAffine>, &'static str> {
        self.permutation_commitments.iter().map(|b| deserialize_affine_point(b)).collect()
    }
}

pub fn serialize_affine_point(point: &EqAffine) -> Vec<u8> {
    point.to_bytes().as_ref().to_vec()
}

fn deserialize_affine_point(bytes: &[u8]) -> Result<EqAffine, &'static str> {
    if bytes.len() != 32 {
        return Err("Invalid affine point length");
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

    #[test]
    fn test_domain_size() {
        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![],
            permutation_commitments: vec![],
            permutation_columns: vec![],
        };

        assert_eq!(vk.domain_size(), 1024); // 2^10
        assert_eq!(vk.extended_domain_size(), 8192); // 2^13
    }

    #[test]
    fn test_get_omega_valid() {
        let omega_value = Fp::from(42);
        let omega_bytes = omega_value.to_repr();

        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: omega_bytes.as_ref().to_vec(),
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![],
            permutation_commitments: vec![],
            permutation_columns: vec![],
        };

        let result = vk.get_omega();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), omega_value);
    }

    #[test]
    fn test_get_omega_invalid_length() {
        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 16], // Wrong length, should be 32
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![],
            permutation_commitments: vec![],
            permutation_columns: vec![],
        };

        let result = vk.get_omega();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid omega length");
    }

    #[test]
    fn test_get_fixed_commitment_valid() {
        let point = Eq::generator().to_affine();
        let point_bytes = serialize_affine_point(&point);

        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![point_bytes.clone(), point_bytes.clone()],
            permutation_commitments: vec![],
            permutation_columns: vec![],
        };

        let result = vk.get_fixed_commitment(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), point);
    }

    #[test]
    fn test_get_fixed_commitment_out_of_bounds() {
        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![vec![0u8; 32]],
            permutation_commitments: vec![],
            permutation_columns: vec![],
        };

        let result = vk.get_fixed_commitment(5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Fixed commitment index out of bounds");
    }

    #[test]
    fn test_get_permutation_commitment_valid() {
        let point = Eq::generator().to_affine();
        let point_bytes = serialize_affine_point(&point);

        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![],
            permutation_commitments: vec![point_bytes.clone(), point_bytes.clone()],
            permutation_columns: vec![],
        };

        let result = vk.get_permutation_commitment(1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), point);
    }

    #[test]
    fn test_get_permutation_commitment_out_of_bounds() {
        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![],
            permutation_commitments: vec![vec![0u8; 32]],
            permutation_columns: vec![],
        };

        let result = vk.get_permutation_commitment(10);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Permutation commitment index out of bounds");
    }

    #[test]
    fn test_get_all_fixed_commitments() {
        let point1 = Eq::generator().to_affine();
        let point2 = (Eq::generator() * Fp::from(2)).to_affine();

        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![
                serialize_affine_point(&point1),
                serialize_affine_point(&point2),
            ],
            permutation_commitments: vec![],
            permutation_columns: vec![],
        };

        let result = vk.get_all_fixed_commitments();
        assert!(result.is_ok());
        let points = result.unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0], point1);
        assert_eq!(points[1], point2);
    }

    #[test]
    fn test_get_all_permutation_commitments() {
        let point1 = Eq::generator().to_affine();
        let point2 = (Eq::generator() * Fp::from(2)).to_affine();

        let vk = VkComponents {
            k: 10,
            extended_k: 13,
            omega: vec![1u8; 32],
            num_fixed_columns: 2,
            num_advice_columns: 3,
            num_instance_columns: 1,
            num_selectors: 3,
            fixed_commitments: vec![],
            permutation_commitments: vec![
                serialize_affine_point(&point1),
                serialize_affine_point(&point2),
            ],
            permutation_columns: vec![],
        };

        let result = vk.get_all_permutation_commitments();
        assert!(result.is_ok());
        let points = result.unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0], point1);
        assert_eq!(points[1], point2);
    }

    #[test]
    fn test_deserialize_affine_point_invalid_length() {
        let result = deserialize_affine_point(&[1u8; 16]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid affine point length");
    }
}
