//! No-std WASM-compatible verifier using halo2_proofs
//!
//! This module provides a thin wrapper around halo2_proofs::verify_proof()
//! for use in Arbitrum Stylus contracts.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use halo2_proofs::{
    plonk::{verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use halo2curves::pasta::{EqAffine, Fp};

pub type VerifyError = Vec<u8>;
pub type Result<T> = core::result::Result<T, VerifyError>;

/// Verify a proof with provided VK and params (useful for testing)
pub fn verify_with_vk_and_params(
    proof_bytes: &[u8],
    public_inputs: &[Vec<Fp>],
    vk: &VerifyingKey<EqAffine>,
    params: &Params<EqAffine>,
) -> Result<bool> {
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof_bytes);

    let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();
    let instances_slice: &[&[Fp]] = &instances;
    let strategy = SingleVerifier::new(params);

    match verify_proof(params, vk, strategy, &[instances_slice], &mut transcript) {
        Ok(_) => Ok(true),
        Err(e) => {
            #[cfg(feature = "std")]
            {
                let error_msg = format!("Verification failed: {:?}", e);
                Err(error_msg.into_bytes())
            }
            #[cfg(not(feature = "std"))]
            {
                let _ = e;
                Err(Vec::from(b"Verification failed"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{
            create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error,
            Selector,
        },
        poly::Rotation,
        transcript::{Blake2bWrite, Challenge255},
    };
    use rand::rngs::OsRng;

    #[derive(Clone, Debug)]
    struct TestCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
    }

    #[derive(Clone, Debug)]
    struct TestConfig {
        advice: Column<Advice>,
        selector: Selector,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { a: Value::unknown(), b: Value::unknown() }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = meta.advice_column();
            let selector = meta.selector();

            meta.create_gate("dummy", |meta| {
                let s = meta.query_selector(selector);
                let a = meta.query_advice(advice, Rotation::cur());
                let b = meta.query_advice(advice, Rotation::next());

                vec![s * (a.clone() * b.clone() - a * b)]
            });

            TestConfig { advice, selector }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> core::result::Result<(), Error> {
            layouter.assign_region(
                || "dummy",
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
    fn test_verify_with_real_proof() {
        let k = 4;

        let circuit = TestCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let params = Params::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("VK generation failed");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("PK generation failed");

        let public_inputs: Vec<Vec<Fp>> = vec![];

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();

        create_proof(&params, &pk, &[circuit], &[instances.as_slice()], OsRng, &mut transcript)
            .expect("Proof generation failed");

        let proof_bytes = transcript.finalize();

        let result = verify_with_vk_and_params(&proof_bytes, &public_inputs, &vk, &params);
        if let Err(e) = &result {
            eprintln!("Verification error: {}", String::from_utf8_lossy(e));
        }
        assert!(result.is_ok(), "Verification failed: {:?}", result);
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_with_wrong_inputs() {
        let k = 4;

        let circuit = TestCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };

        let params = Params::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("VK generation failed");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("PK generation failed");

        let public_inputs: Vec<Vec<Fp>> = vec![];

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();

        create_proof(&params, &pk, &[circuit], &[instances.as_slice()], OsRng, &mut transcript)
            .expect("Proof generation failed");

        let proof_bytes = transcript.finalize();

        let wrong_inputs = vec![vec![Fp::from(999)]];
        let result = verify_with_vk_and_params(&proof_bytes, &wrong_inputs, &vk, &params);

        assert!(result.is_err() || !result.unwrap());
    }
}
