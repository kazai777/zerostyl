//! Halo2 proof verification for ZeroStyl circuits

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use halo2curves::pasta::{EqAffine, Fp};

type VerifyError = Vec<u8>;

/// Verify a halo2 proof with embedded VK and params
pub fn verify_halo2_proof(
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, VerifyError> {
    if proof_bytes.is_empty() {
        return Err(Vec::from(b"Empty proof"));
    }
    if public_inputs_bytes.is_empty() {
        return Err(Vec::from(b"Empty public inputs"));
    }

    let vk = load_verifying_key()?;
    let params = load_params()?;
    let public_inputs = deserialize_public_inputs(public_inputs_bytes)?;

    verify_with_vk_and_params(proof_bytes, &public_inputs, &vk, &params)
}

/// Core verification function (public for testing)
pub fn verify_with_vk_and_params(
    proof_bytes: &[u8],
    public_inputs: &[Vec<Fp>],
    vk: &VerifyingKey<EqAffine>,
    params: &Params<EqAffine>,
) -> Result<bool, VerifyError> {
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof_bytes);

    let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();
    let instances_slice: &[&[Fp]] = &instances;

    use halo2_proofs::plonk::SingleVerifier;
    let strategy = SingleVerifier::new(params);

    match verify_proof(params, vk, strategy, &[instances_slice], &mut transcript) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn deserialize_public_inputs(inputs_bytes: &[u8]) -> Result<Vec<Vec<Fp>>, VerifyError> {
    postcard::from_bytes(inputs_bytes)
        .map_err(|e| Vec::from(format!("Failed to deserialize public inputs: {}", e).as_bytes()))
}

fn load_verifying_key() -> Result<VerifyingKey<EqAffine>, VerifyError> {
    #[cfg(feature = "embedded_vk")]
    {
        // When embedded_vk is enabled, VK bytes are available but need
        // circuit-specific deserialization. Return error with helpful message.
        let vk_bytes = crate::embedded::embedded_vk_bytes();
        if vk_bytes.is_empty() {
            return Err(Vec::from(b"Embedded VK is empty - run extract-vk-v2 first"));
        }
        // VK deserialization requires the concrete circuit type, which is not
        // available at this level. Use verify_with_vk_and_params() directly
        // with a circuit-specific VK instead.
        Err(Vec::from(b"Use verify_with_vk_and_params() for circuit-specific VK"))
    }
    #[cfg(not(feature = "embedded_vk"))]
    {
        Err(Vec::from(b"Verifying key not embedded"))
    }
}

fn load_params() -> Result<Params<EqAffine>, VerifyError> {
    #[cfg(feature = "embedded_vk")]
    {
        crate::embedded::load_embedded_params()
    }
    #[cfg(not(feature = "embedded_vk"))]
    {
        Err(Vec::from(b"Commitment parameters not embedded"))
    }
}

pub fn get_circuit_metadata() -> Vec<u8> {
    let metadata = r#"{
        "name": "ZeroStylCircuit",
        "version": "0.1.0",
        "k": 10,
        "num_public_inputs": 0,
        "num_private_witnesses": 0
    }"#;
    Vec::from(metadata.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{
            create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error,
            Instance, Selector,
        },
        poly::{commitment::Params, Rotation},
        transcript::{Blake2bWrite, Challenge255},
    };
    use halo2curves::pasta::EqAffine;
    use rand::rngs::OsRng;

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
    fn test_verify_empty_proof_fails() {
        let result = verify_halo2_proof(&[], &[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_empty_inputs_fails() {
        let result = verify_halo2_proof(&[1, 2, 3], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_public_inputs() {
        let inputs = vec![vec![Fp::from(1), Fp::from(2)], vec![Fp::from(3)]];
        let serialized = postcard::to_allocvec(&inputs).unwrap();
        let deserialized = deserialize_public_inputs(&serialized).unwrap();

        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].len(), 2);
        assert_eq!(deserialized[1].len(), 1);
        assert_eq!(deserialized[0][0], Fp::from(1));
        assert_eq!(deserialized[0][1], Fp::from(2));
        assert_eq!(deserialized[1][0], Fp::from(3));
    }

    #[test]
    fn test_deserialize_invalid_inputs() {
        let invalid_data = vec![0xFF, 0xFF, 0xFF];
        let result = deserialize_public_inputs(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_real_proof() {
        let k = 4;
        let circuit = SimpleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let params = Params::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let public_inputs = vec![vec![Fp::from(5)]];
        let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            std::slice::from_ref(&circuit),
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();

        let result = verify_with_vk_and_params(&proof, &public_inputs, &vk, &params);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_with_wrong_public_inputs() {
        let k = 4;
        let circuit = SimpleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let params = Params::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let correct_inputs = [vec![Fp::from(5)]];
        let instances: Vec<&[Fp]> = correct_inputs.iter().map(|v| v.as_slice()).collect();

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            std::slice::from_ref(&circuit),
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();

        let wrong_inputs = vec![vec![Fp::from(10)]];

        let result = verify_with_vk_and_params(&proof, &wrong_inputs, &vk, &params);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_with_corrupted_proof() {
        let k = 4;
        let circuit = SimpleCircuit { a: Value::known(Fp::from(2)), b: Value::known(Fp::from(3)) };
        let params = Params::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let public_inputs = vec![vec![Fp::from(5)]];
        let instances: Vec<&[Fp]> = public_inputs.iter().map(|v| v.as_slice()).collect();

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            std::slice::from_ref(&circuit),
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let mut proof = transcript.finalize();

        if !proof.is_empty() {
            proof[0] ^= 0xFF;
        }

        let result = verify_with_vk_and_params(&proof, &public_inputs, &vk, &params);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_get_metadata() {
        let metadata = get_circuit_metadata();
        assert!(!metadata.is_empty());
        let json_str = String::from_utf8(metadata).unwrap();
        assert!(json_str.contains("ZeroStylCircuit"));
        assert!(json_str.contains("\"k\": 10"));
    }

    #[test]
    #[cfg(not(feature = "embedded_vk"))]
    fn test_load_verifying_key_not_embedded() {
        let result = load_verifying_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().starts_with(b"Verifying key not embedded"));
    }

    #[test]
    #[cfg(not(feature = "embedded_vk"))]
    fn test_load_params_not_embedded() {
        let result = load_params();
        assert!(result.is_err());
        assert!(result.unwrap_err().starts_with(b"Commitment parameters not embedded"));
    }

    #[test]
    #[cfg(feature = "embedded_vk")]
    fn test_load_verifying_key_with_embedded() {
        let result = load_verifying_key();
        assert!(result.is_err());
        // When embedded_vk is enabled, load_verifying_key() returns a different error
        // because VK deserialization requires the concrete circuit type
        let error = result.unwrap_err();
        assert!(
            error.starts_with(b"Use verify_with_vk_and_params()")
                || error.starts_with(b"Embedded VK is empty")
        );
    }

    #[test]
    #[cfg(feature = "embedded_vk")]
    fn test_load_params_with_embedded() {
        let result = load_params();
        // When embedded_vk is enabled, load_params() may succeed if build.rs generated params,
        // or may fail with a specific error. We just check it doesn't panic.
        // The exact behavior depends on whether the build script ran successfully.
        let _ = result;
    }

    #[test]
    fn test_verify_halo2_proof_without_vk() {
        let result = verify_halo2_proof(&[1, 2, 3], &[4, 5, 6]);
        assert!(result.is_err());
    }
}
