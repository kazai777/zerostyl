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
}
