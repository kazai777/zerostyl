//! Native Prover for halo2 Circuits
//!
//! Provides off-chain proof generation using the full halo2_proofs library.
//! Proofs are generated natively (not in WASM) for optimal performance.

use super::keys::{KeyManager, KeyMetadata};
use anyhow::{Context, Result};
use halo2_proofs::{
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::pasta::{EqAffine, Fp};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofData {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<String>>,
}

pub struct NativeProver<C: Circuit<Fp>> {
    circuit: C,
    k: u32,
    key_manager: KeyManager,
    proving_key: Option<ProvingKey<EqAffine>>,
    verifying_key: Option<VerifyingKey<EqAffine>>,
    params: Option<Params<EqAffine>>,
}

impl<C: Circuit<Fp> + Clone> NativeProver<C> {
    pub fn new(circuit: C, _circuit_name: String, k: u32) -> Result<Self> {
        let cache_dir = std::env::current_dir()?.join(".zerostyl_cache");
        let key_manager = KeyManager::new(&cache_dir)?;

        Ok(Self { circuit, k, key_manager, proving_key: None, verifying_key: None, params: None })
    }

    pub fn with_cache_dir<P: AsRef<Path>>(circuit: C, k: u32, cache_dir: P) -> Result<Self> {
        let key_manager = KeyManager::new(cache_dir)?;

        Ok(Self { circuit, k, key_manager, proving_key: None, verifying_key: None, params: None })
    }

    pub fn setup(&mut self, metadata: KeyMetadata) -> Result<()> {
        let params = self.key_manager.generate_params(self.k)?;

        let (pk, vk) = self.key_manager.generate_keys(&self.circuit, self.k, metadata)?;

        self.params = Some(params);
        self.proving_key = Some(pk);
        self.verifying_key = Some(vk);

        Ok(())
    }

    pub fn generate_proof(&self, public_inputs: &[Vec<Fp>]) -> Result<Vec<u8>> {
        let pk = self
            .proving_key
            .as_ref()
            .context("Proving key not loaded. Call setup() or load_keys() first.")?;

        let params = self
            .params
            .as_ref()
            .context("Parameters not loaded. Call setup() or load_keys() first.")?;

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        let instances_slice: &[&[Fp]] = &instances;

        create_proof(
            params,
            pk,
            std::slice::from_ref(&self.circuit),
            &[instances_slice],
            OsRng,
            &mut transcript,
        )
        .context("Failed to create proof")?;

        Ok(transcript.finalize())
    }

    pub fn verify_proof(&self, proof: &[u8], public_inputs: &[Vec<Fp>]) -> Result<bool> {
        use halo2_proofs::plonk::SingleVerifier;

        let vk = self
            .verifying_key
            .as_ref()
            .context("Verification key not loaded. Call setup() first.")?;

        let params = self.params.as_ref().context("Parameters not loaded. Call setup() first.")?;

        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);

        let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        let instances_slice: &[&[Fp]] = &instances;

        let strategy = SingleVerifier::new(params);

        verify_proof(params, vk, strategy, &[instances_slice], &mut transcript)
            .map(|_| true)
            .or_else(|_| Ok(false))
    }

    pub fn proving_key(&self) -> Option<&ProvingKey<EqAffine>> {
        self.proving_key.as_ref()
    }

    pub fn verifying_key(&self) -> Option<&VerifyingKey<EqAffine>> {
        self.verifying_key.as_ref()
    }
}

pub fn field_to_string(f: &Fp) -> String {
    format!("{:?}", f)
}

pub fn string_to_field(s: &str) -> Result<Fp> {
    use halo2curves::group::ff::PrimeField;

    if let Some(hex_str) = s.strip_prefix("0x") {
        let bytes = hex::decode(hex_str).context("Invalid hex string")?;
        let mut repr = <Fp as PrimeField>::Repr::default();
        let len = bytes.len().min(repr.as_ref().len());
        repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
        Option::from(Fp::from_repr(repr)).ok_or_else(|| anyhow::anyhow!("Invalid field element"))
    } else {
        let val: u64 = s.parse().context("Invalid field element string")?;
        Ok(Fp::from(val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
        poly::Rotation,
    };
    use tempfile::TempDir;

    #[derive(Clone, Debug)]
    struct SimpleCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
    }

    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct SimpleConfig {
        advice: Column<Advice>,
        instance: Column<Instance>,
        selector: Selector,
    }

    impl Circuit<Fp> for SimpleCircuit {
        type Config = SimpleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { a: Value::unknown(), b: Value::unknown() }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = meta.advice_column();
            let instance = meta.instance_column();
            let selector = meta.selector();

            meta.enable_equality(advice);
            meta.enable_equality(instance);

            meta.create_gate("add", |meta| {
                let s = meta.query_selector(selector);
                let a = meta.query_advice(advice, Rotation::cur());
                let b = meta.query_advice(advice, Rotation::next());
                let sum = meta.query_instance(instance, Rotation::cur());

                vec![s * (a + b - sum)]
            });

            SimpleConfig { advice, instance, selector }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "add",
                |mut region| {
                    config.selector.enable(&mut region, 0)?;

                    region.assign_advice(|| "a", config.advice, 0, || self.a)?;
                    region.assign_advice(|| "b", config.advice, 1, || self.b)?;

                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_prover_setup() {
        let temp_dir = TempDir::new().unwrap();
        let circuit = SimpleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let mut prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: "simple".to_string(),
            k: 4,
            num_public_inputs: 1,
            num_private_witnesses: 2,
        };

        prover.setup(metadata).unwrap();

        assert!(prover.proving_key().is_some());
        assert!(prover.verifying_key().is_some());
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let temp_dir = TempDir::new().unwrap();
        let circuit = SimpleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let mut prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: "simple".to_string(),
            k: 4,
            num_public_inputs: 1,
            num_private_witnesses: 2,
        };

        prover.setup(metadata).unwrap();

        let public_inputs = vec![vec![Fp::from(5)]];
        let proof = prover.generate_proof(&public_inputs).unwrap();

        assert!(!proof.is_empty());

        let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_proof_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let circuit = SimpleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let mut prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: "simple".to_string(),
            k: 4,
            num_public_inputs: 1,
            num_private_witnesses: 2,
        };

        prover.setup(metadata).unwrap();

        let public_inputs = vec![vec![Fp::from(5)]];
        let proof = prover.generate_proof(&public_inputs).unwrap();

        let wrong_inputs = vec![vec![Fp::from(10)]];
        let is_valid = prover.verify_proof(&proof, &wrong_inputs).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_field_serialization() {
        let field = Fp::from(12345);
        let s = field_to_string(&field);
        assert!(!s.is_empty());

        let parsed = string_to_field("12345").unwrap();
        assert_eq!(parsed, field);
    }
}
