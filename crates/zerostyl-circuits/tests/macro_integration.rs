//! Integration test: prove the `register_circuit!` macro works on a user-style
//! crate that exposes a public `descriptor()` function.

use std::path::Path;
use std::sync::OnceLock;

use zerostyl_circuits::{
    register_circuit, CircuitDescriptor, CircuitIntrospection, MockProverReport, ProofArtifact,
    PublicInputsSchema, Registry, Result, WitnessSchema,
};

mod my_user_circuit {
    use super::*;

    pub struct UserDescriptor;

    fn empty_witness() -> &'static WitnessSchema {
        static S: OnceLock<WitnessSchema> = OnceLock::new();
        S.get_or_init(|| WitnessSchema { fields: vec![] })
    }
    fn empty_public() -> &'static PublicInputsSchema {
        static S: OnceLock<PublicInputsSchema> = OnceLock::new();
        S.get_or_init(|| PublicInputsSchema { fields: vec![] })
    }

    impl CircuitDescriptor for UserDescriptor {
        fn name(&self) -> &'static str {
            "user_circuit"
        }
        fn version(&self) -> &'static str {
            "0.1.0"
        }
        fn description(&self) -> &'static str {
            "User-supplied test circuit"
        }
        fn default_k(&self) -> u32 {
            4
        }
        fn num_public_inputs(&self) -> usize {
            0
        }
        fn num_private_witnesses(&self) -> usize {
            0
        }
        fn witness_schema(&self) -> &'static WitnessSchema {
            empty_witness()
        }
        fn public_inputs_schema(&self) -> &'static PublicInputsSchema {
            empty_public()
        }
        fn prove(&self, _: &str, _: u32, _: &Path) -> Result<ProofArtifact> {
            unimplemented!()
        }
        fn verify(&self, _: &[u8], _: &str, _: u32, _: &Path) -> Result<bool> {
            unimplemented!()
        }
        fn mock_prove(&self, _: &str, _: u32) -> Result<MockProverReport> {
            unimplemented!()
        }
        fn inspect(&self) -> Result<CircuitIntrospection> {
            unimplemented!()
        }
    }

    pub fn descriptor() -> &'static dyn CircuitDescriptor {
        static D: UserDescriptor = UserDescriptor;
        &D
    }
}

#[test]
fn macro_registers_user_circuit() {
    let reg = Registry::new();
    register_circuit!(reg, my_user_circuit).unwrap();
    assert_eq!(reg.list(), vec!["user_circuit"]);
}

#[test]
fn macro_propagates_duplicate_error() {
    let reg = Registry::new();
    register_circuit!(reg, my_user_circuit).unwrap();
    let second = register_circuit!(reg, my_user_circuit);
    assert!(second.is_err());
}
