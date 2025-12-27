//! WASM verifier for ZeroStyl circuits on Arbitrum Stylus

pub mod verifier;

pub fn verify(proof: &[u8], public_inputs: &[u8]) -> Result<bool, Vec<u8>> {
    verifier::verify_halo2_proof(proof, public_inputs)
}

pub fn get_metadata() -> Vec<u8> {
    verifier::get_circuit_metadata()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_empty_proof() {
        let result = verify(&[], &[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_empty_inputs() {
        let result = verify(&[1, 2, 3], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_metadata() {
        let metadata = get_metadata();
        assert!(!metadata.is_empty());
        let json_str = String::from_utf8(metadata).unwrap();
        assert!(json_str.contains("ZeroStylCircuit"));
    }
}
