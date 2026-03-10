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

/// Deserialize public inputs from postcard-encoded bytes.
pub(crate) fn deserialize_public_inputs(inputs_bytes: &[u8]) -> Result<Vec<Vec<Fp>>, VerifyError> {
    postcard::from_bytes(inputs_bytes)
        .map_err(|e| Vec::from(format!("Failed to deserialize public inputs: {}", e).as_bytes()))
}

fn load_verifying_key() -> Result<VerifyingKey<EqAffine>, VerifyError> {
    #[cfg(feature = "embedded_vk")]
    {
        crate::embedded::load_embedded_vk()
    }
    #[cfg(not(feature = "embedded_vk"))]
    {
        Err(Vec::from(b"Verifying key not embedded. Enable embedded_vk feature."))
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

/// Returns JSON metadata describing the reference circuit configuration.
pub fn get_circuit_metadata() -> Vec<u8> {
    let metadata = r#"{
        "name": "ReferenceCircuit",
        "version": "0.1.0",
        "k": 4,
        "num_public_inputs": 1,
        "num_private_witnesses": 2
    }"#;
    Vec::from(metadata.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_circuit::ReferenceCircuit;
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk},
        poly::commitment::Params,
        transcript::{Blake2bWrite, Challenge255},
    };
    use halo2curves::pasta::EqAffine;
    use rand::rngs::OsRng;

    fn generate_test_proof(
        a: u64,
        b: u64,
        public_sum: u64,
    ) -> (Vec<u8>, Vec<Vec<Fp>>, VerifyingKey<EqAffine>, Params<EqAffine>) {
        let k = 4;
        let circuit = ReferenceCircuit {
            a: halo2_proofs::circuit::Value::known(Fp::from(a)),
            b: halo2_proofs::circuit::Value::known(Fp::from(b)),
        };
        let params = Params::<EqAffine>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("VK generation failed");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("PK generation failed");

        let public_inputs = vec![vec![Fp::from(public_sum)]];
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
        .expect("Proof generation failed");
        let proof = transcript.finalize();

        (proof, public_inputs, vk, params)
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
        let (proof, public_inputs, vk, params) = generate_test_proof(2, 3, 5);

        let result = verify_with_vk_and_params(&proof, &public_inputs, &vk, &params);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_with_wrong_public_inputs() {
        let (proof, _, vk, params) = generate_test_proof(2, 3, 5);

        let wrong_inputs = vec![vec![Fp::from(10)]];
        let result = verify_with_vk_and_params(&proof, &wrong_inputs, &vk, &params);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_with_corrupted_proof() {
        let (mut proof, public_inputs, vk, params) = generate_test_proof(2, 3, 5);

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
        assert!(json_str.contains("ReferenceCircuit"));
        assert!(json_str.contains("\"k\": 4"));
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
        assert!(result.is_ok(), "Should succeed with embedded VK: {:?}", result.err());
    }

    #[test]
    #[cfg(feature = "embedded_vk")]
    fn test_load_params_with_embedded() {
        let result = load_params();
        assert!(result.is_ok(), "Should succeed with embedded params: {:?}", result.err());
    }

    #[test]
    fn test_verify_halo2_proof_without_vk() {
        let result = verify_halo2_proof(&[1, 2, 3], &[4, 5, 6]);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "embedded_vk")]
    fn test_verify_halo2_proof_end_to_end() {
        let (proof, public_inputs, _, _) = generate_test_proof(2, 3, 5);

        let public_inputs_bytes = postcard::to_allocvec(&public_inputs).unwrap();
        let result = verify_halo2_proof(&proof, &public_inputs_bytes);
        assert!(result.is_ok(), "End-to-end verification failed: {:?}", result.err());
        assert!(result.unwrap(), "Valid proof should verify as true");
    }

    #[test]
    #[cfg(feature = "embedded_vk")]
    fn test_verify_halo2_proof_wrong_inputs() {
        let (proof, _, _, _) = generate_test_proof(2, 3, 5);

        let wrong_inputs = vec![vec![Fp::from(999)]];
        let wrong_inputs_bytes = postcard::to_allocvec(&wrong_inputs).unwrap();
        let result = verify_halo2_proof(&proof, &wrong_inputs_bytes);
        assert!(result.is_ok(), "Verification should not error: {:?}", result.err());
        assert!(!result.unwrap(), "Wrong inputs should verify as false");
    }
}
