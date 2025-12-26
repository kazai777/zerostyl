//! Proving and Verification Key Management
//!
//! Handles generation and caching of proving/verification keys for halo2 circuits.
//! Note: halo2_proofs 0.3 doesn't support stable key serialization, so we cache
//! params and regenerate keys as needed.

use anyhow::{Context, Result};
use halo2_proofs::{
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::commitment::Params,
};
use halo2curves::pasta::{EqAffine, Fp};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub circuit_name: String,
    pub k: u32,
    pub num_public_inputs: usize,
    pub num_private_witnesses: usize,
}

pub struct KeyManager {
    cache_dir: PathBuf,
}

impl KeyManager {
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        fs::create_dir_all(&cache_dir).context("Failed to create key cache directory")?;

        Ok(Self { cache_dir })
    }

    pub fn params_path(&self, k: u32) -> PathBuf {
        self.cache_dir.join(format!("params_k{}.bin", k))
    }

    pub fn metadata_path(&self, circuit_name: &str, k: u32) -> PathBuf {
        self.cache_dir.join(format!("{}_k{}_metadata.json", circuit_name, k))
    }

    pub fn generate_params(&self, k: u32) -> Result<Params<EqAffine>> {
        let params_path = self.params_path(k);

        if params_path.exists() {
            println!("Loading cached IPA parameters for k={}...", k);
            return self.load_params(k);
        }

        println!("Generating IPA parameters for k={}... (this may take a while)", k);
        let params = Params::<EqAffine>::new(k);

        self.save_params(&params, k)?;

        Ok(params)
    }

    fn save_params(&self, params: &Params<EqAffine>, k: u32) -> Result<()> {
        let path = self.params_path(k);
        let mut file = fs::File::create(&path)
            .context(format!("Failed to create params file at {:?}", path))?;

        params.write(&mut file).context("Failed to write params")?;

        println!("Saved IPA parameters to {:?}", path);
        Ok(())
    }

    pub fn load_params(&self, k: u32) -> Result<Params<EqAffine>> {
        let path = self.params_path(k);
        let mut file =
            fs::File::open(&path).context(format!("Failed to open params file at {:?}", path))?;

        Params::<EqAffine>::read(&mut file).context("Failed to deserialize params")
    }

    pub fn generate_keys<C>(
        &self,
        circuit: &C,
        k: u32,
        metadata: KeyMetadata,
    ) -> Result<(ProvingKey<EqAffine>, VerifyingKey<EqAffine>)>
    where
        C: Circuit<Fp>,
    {
        let params = self.generate_params(k)?;

        println!(
            "Generating proving and verification keys for circuit '{}'...",
            metadata.circuit_name
        );

        let vk = keygen_vk(&params, circuit).context("Failed to generate verification key")?;

        let pk =
            keygen_pk(&params, vk.clone(), circuit).context("Failed to generate proving key")?;

        self.save_metadata(&metadata)?;

        Ok((pk, vk))
    }

    fn save_metadata(&self, metadata: &KeyMetadata) -> Result<()> {
        let meta_path = self.metadata_path(&metadata.circuit_name, metadata.k);

        let metadata_json =
            serde_json::to_string_pretty(metadata).context("Failed to serialize metadata")?;
        fs::write(&meta_path, metadata_json).context("Failed to write metadata file")?;

        println!("Saved metadata to {:?}", meta_path);

        Ok(())
    }

    pub fn load_metadata(&self, circuit_name: &str, k: u32) -> Result<KeyMetadata> {
        let meta_path = self.metadata_path(circuit_name, k);
        let content = fs::read_to_string(&meta_path)
            .context(format!("Failed to read metadata file at {:?}", meta_path))?;

        serde_json::from_str(&content).context("Failed to deserialize metadata")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_manager_paths() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        assert_eq!(manager.params_path(10), temp_dir.path().join("params_k10.bin"));

        assert_eq!(
            manager.metadata_path("test_circuit", 10),
            temp_dir.path().join("test_circuit_k10_metadata.json")
        );
    }

    #[test]
    fn test_params_generation_and_loading() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        let k = 4;
        let params = manager.generate_params(k).unwrap();
        assert_eq!(params.k(), k);

        let loaded_params = manager.load_params(k).unwrap();
        assert_eq!(loaded_params.k(), k);
    }

    #[test]
    fn test_metadata_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: "test".to_string(),
            k: 10,
            num_public_inputs: 3,
            num_private_witnesses: 5,
        };

        manager.save_metadata(&metadata).unwrap();

        let loaded = manager.load_metadata("test", 10).unwrap();
        assert_eq!(loaded.circuit_name, metadata.circuit_name);
        assert_eq!(loaded.k, metadata.k);
        assert_eq!(loaded.num_public_inputs, metadata.num_public_inputs);
        assert_eq!(loaded.num_private_witnesses, metadata.num_private_witnesses);
    }

    #[test]
    fn test_load_nonexistent_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        let result = manager.load_metadata("nonexistent", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_params() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        // Try to load params that haven't been generated yet
        let result = manager.load_params(20);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_metadata_serialization() {
        let metadata = KeyMetadata {
            circuit_name: "test_circuit".to_string(),
            k: 12,
            num_public_inputs: 5,
            num_private_witnesses: 10,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: KeyMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.circuit_name, metadata.circuit_name);
        assert_eq!(deserialized.k, metadata.k);
        assert_eq!(deserialized.num_public_inputs, metadata.num_public_inputs);
        assert_eq!(deserialized.num_private_witnesses, metadata.num_private_witnesses);
    }

    #[test]
    fn test_params_caching() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        let k = 5;

        // Generate params first time
        let params1 = manager.generate_params(k).unwrap();

        // Load params (should use cached version)
        let params2 = manager.load_params(k).unwrap();

        assert_eq!(params1.k(), params2.k());
    }

    #[test]
    fn test_multiple_k_values() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        for k in [4, 5, 6, 7] {
            let params = manager.generate_params(k).unwrap();
            assert_eq!(params.k(), k);
        }
    }

    #[test]
    fn test_key_manager_cache_dir_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache_path = temp_dir.path().join("custom_cache");

        let manager = KeyManager::new(&cache_path).unwrap();
        assert!(cache_path.exists());

        // Verify we can generate params in the new directory
        let params = manager.generate_params(4).unwrap();
        assert_eq!(params.k(), 4);
    }

    #[test]
    fn test_metadata_with_different_circuits() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(temp_dir.path()).unwrap();

        let metadata1 = KeyMetadata {
            circuit_name: "circuit1".to_string(),
            k: 10,
            num_public_inputs: 2,
            num_private_witnesses: 4,
        };

        let metadata2 = KeyMetadata {
            circuit_name: "circuit2".to_string(),
            k: 10,
            num_public_inputs: 3,
            num_private_witnesses: 6,
        };

        manager.save_metadata(&metadata1).unwrap();
        manager.save_metadata(&metadata2).unwrap();

        let loaded1 = manager.load_metadata("circuit1", 10).unwrap();
        let loaded2 = manager.load_metadata("circuit2", 10).unwrap();

        assert_eq!(loaded1.circuit_name, "circuit1");
        assert_eq!(loaded2.circuit_name, "circuit2");
        assert_eq!(loaded1.num_private_witnesses, 4);
        assert_eq!(loaded2.num_private_witnesses, 6);
    }
}
