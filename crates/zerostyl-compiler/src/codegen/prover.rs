//! Native Prover for halo2-KZG circuits on BN254.
//!
//! Off-chain proof generation using halo2_proofs (PSE fork). Produces KZG-BN254
//! proofs with a Keccak-256 Fiat-Shamir transcript for downstream EVM/Stylus
//! verifier compatibility.

use anyhow::{Context, Result};
use halo2_proofs::{
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::keys::{KeyManager, KeyMetadata};

type ProofTranscriptWrite =
    halo2_proofs::transcript::Keccak256Write<Vec<u8>, G1Affine, Challenge255<G1Affine>>;
type ProofTranscriptRead<'a> =
    halo2_proofs::transcript::Keccak256Read<&'a [u8], G1Affine, Challenge255<G1Affine>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofData {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<String>>,
}

pub struct NativeProver<C: Circuit<Fr>> {
    circuit: C,
    k: u32,
    key_manager: KeyManager,
    proving_key: Option<ProvingKey<G1Affine>>,
    verifying_key: Option<VerifyingKey<G1Affine>>,
    params: Option<ParamsKZG<Bn256>>,
}

impl<C: Circuit<Fr> + Clone> NativeProver<C> {
    pub fn new(circuit: C, k: u32) -> Result<Self> {
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

    pub fn generate_proof(&self, public_inputs: &[Vec<Fr>]) -> Result<Vec<u8>> {
        let pk = self
            .proving_key
            .as_ref()
            .context("Proving key not loaded. Call setup() or load_keys() first.")?;

        let params = self
            .params
            .as_ref()
            .context("Parameters not loaded. Call setup() or load_keys() first.")?;

        let mut transcript = ProofTranscriptWrite::init(vec![]);

        let instances: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        let instances_slice: &[&[Fr]] = &instances;

        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
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

    pub fn verify_proof(&self, proof: &[u8], public_inputs: &[Vec<Fr>]) -> Result<bool> {
        let vk = self
            .verifying_key
            .as_ref()
            .context("Verification key not loaded. Call setup() first.")?;

        let params = self.params.as_ref().context("Parameters not loaded. Call setup() first.")?;

        let mut transcript = ProofTranscriptRead::init(proof);

        let instances: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        let instances_slice: &[&[Fr]] = &instances;

        let strategy = SingleStrategy::new(params);

        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            params,
            vk,
            strategy,
            &[instances_slice],
            &mut transcript,
        )
        .map(|_| true)
        .or_else(|_| Ok(false))
    }

    pub fn proving_key(&self) -> Option<&ProvingKey<G1Affine>> {
        self.proving_key.as_ref()
    }

    pub fn verifying_key(&self) -> Option<&VerifyingKey<G1Affine>> {
        self.verifying_key.as_ref()
    }
}

pub fn field_to_string(f: &Fr) -> String {
    format!("{:?}", f)
}

pub fn string_to_field(s: &str) -> Result<Fr> {
    use halo2curves::group::ff::PrimeField;

    if let Some(hex_str) = s.strip_prefix("0x") {
        let bytes = hex::decode(hex_str).context("Invalid hex string")?;
        let mut repr = <Fr as PrimeField>::Repr::default();
        let len = bytes.len().min(repr.as_ref().len());
        repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
        Option::from(Fr::from_repr(repr)).ok_or_else(|| anyhow::anyhow!("Invalid field element"))
    } else {
        let val: u64 = s.parse().context("Invalid field element string")?;
        Ok(Fr::from(val))
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
        a: Value<Fr>,
        b: Value<Fr>,
    }

    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct SimpleConfig {
        advice: Column<Advice>,
        instance: Column<Instance>,
        selector: Selector,
    }

    impl Circuit<Fr> for SimpleCircuit {
        type Config = SimpleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { a: Value::unknown(), b: Value::unknown() }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
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
            mut layouter: impl Layouter<Fr>,
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
        let circuit = SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

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
        let circuit = SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

        let mut prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: "simple".to_string(),
            k: 4,
            num_public_inputs: 1,
            num_private_witnesses: 2,
        };

        prover.setup(metadata).unwrap();

        let public_inputs = vec![vec![Fr::from(5)]];
        let proof = prover.generate_proof(&public_inputs).unwrap();

        assert!(!proof.is_empty());

        let is_valid = prover.verify_proof(&proof, &public_inputs).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_proof_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let circuit = SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

        let mut prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let metadata = KeyMetadata {
            circuit_name: "simple".to_string(),
            k: 4,
            num_public_inputs: 1,
            num_private_witnesses: 2,
        };

        prover.setup(metadata).unwrap();

        let public_inputs = vec![vec![Fr::from(5)]];
        let proof = prover.generate_proof(&public_inputs).unwrap();

        let wrong_inputs = vec![vec![Fr::from(10)]];
        let is_valid = prover.verify_proof(&proof, &wrong_inputs).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_field_serialization() {
        let field = Fr::from(12345);
        let s = field_to_string(&field);
        assert!(!s.is_empty());

        let parsed = string_to_field("12345").unwrap();
        assert_eq!(parsed, field);
    }

    #[test]
    fn test_string_to_field_hex() {
        let result = string_to_field("0x1a").unwrap();
        assert_eq!(result, Fr::from(26));

        let result2 = string_to_field("0xFF").unwrap();
        assert_eq!(result2, Fr::from(255));
    }

    #[test]
    fn test_string_to_field_decimal() {
        let result = string_to_field("42").unwrap();
        assert_eq!(result, Fr::from(42));

        let result2 = string_to_field("999").unwrap();
        assert_eq!(result2, Fr::from(999));
    }

    #[test]
    fn test_string_to_field_zero() {
        let result = string_to_field("0").unwrap();
        assert_eq!(result, Fr::from(0));

        let result2 = string_to_field("0x00").unwrap();
        assert_eq!(result2, Fr::from(0));
    }

    #[test]
    fn test_string_to_field_invalid() {
        assert!(string_to_field("invalid").is_err());
        assert!(string_to_field("").is_err());
        assert!(string_to_field("0xGG").is_err());
        assert!(string_to_field("0x0").is_err());
    }

    #[test]
    fn test_field_to_string_not_empty() {
        let values = vec![0u64, 1, 42, 255, 1000, 999999];
        for val in values {
            let field = Fr::from(val);
            let s = field_to_string(&field);
            assert!(!s.is_empty(), "String should not be empty for value {}", val);
        }
    }

    #[test]
    fn test_prover_without_setup() {
        let temp_dir = TempDir::new().unwrap();
        let circuit = SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

        let prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let public_inputs = vec![vec![Fr::from(5)]];
        let result = prover.generate_proof(&public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_prover_different_k_values() {
        for k in [4, 5, 6] {
            let temp_dir = TempDir::new().unwrap();
            let circuit =
                SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

            let mut prover = NativeProver::with_cache_dir(circuit, k, temp_dir.path()).unwrap();

            let metadata = KeyMetadata {
                circuit_name: format!("simple_k{}", k),
                k,
                num_public_inputs: 1,
                num_private_witnesses: 2,
            };

            prover.setup(metadata).unwrap();
            assert!(prover.proving_key().is_some());
        }
    }

    #[test]
    fn test_prover_new() {
        let circuit = SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };
        let prover = NativeProver::new(circuit, 4).unwrap();
        assert!(prover.proving_key().is_none());
        assert!(prover.verifying_key().is_none());
    }

    #[test]
    fn test_prover_verify_without_setup() {
        let temp_dir = TempDir::new().unwrap();
        let circuit = SimpleCircuit { a: Value::known(Fr::from(2)), b: Value::known(Fr::from(3)) };

        let prover = NativeProver::with_cache_dir(circuit, 4, temp_dir.path()).unwrap();

        let public_inputs = vec![vec![Fr::from(5)]];
        let fake_proof = vec![0u8; 100];
        let result = prover.verify_proof(&fake_proof, &public_inputs);
        assert!(result.is_err());
    }
}
