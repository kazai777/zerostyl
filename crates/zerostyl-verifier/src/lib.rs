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
    #[test]
    fn test_verifier_compiles() {
        assert!(true);
    }
}
