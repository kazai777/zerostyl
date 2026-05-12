use std::path::Path;

use crate::{
    error::Result,
    proof::ProofArtifact,
    report::{CircuitIntrospection, MockProverReport},
    schema::{PublicInputsSchema, WitnessSchema},
};

/// Plug a circuit into the ZeroStyl toolkit.
///
/// Implementors live in their own crate (typically `examples/<circuit>/src/descriptor.rs`)
/// and expose `pub fn descriptor() -> &'static dyn CircuitDescriptor`. The CLI, debugger,
/// exporter and SDK generators all consume circuits through this trait — never directly.
///
/// The trait is intentionally dyn-safe: signatures use concrete types only (no `Self`
/// in return, no generics on methods, no associated types). It is also free of
/// `halo2curves::pasta::Fp` so a future STARK descriptor can implement it unchanged.
pub trait CircuitDescriptor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn default_k(&self) -> u32;
    fn num_public_inputs(&self) -> usize;
    fn num_private_witnesses(&self) -> usize;

    fn witness_schema(&self) -> &'static WitnessSchema;
    fn public_inputs_schema(&self) -> &'static PublicInputsSchema;

    fn prove(&self, witness_json: &str, k: u32, cache_dir: &Path) -> Result<ProofArtifact>;

    fn verify(
        &self,
        proof: &[u8],
        public_inputs_json: &str,
        k: u32,
        cache_dir: &Path,
    ) -> Result<bool>;

    fn mock_prove(&self, witness_json: &str, k: u32) -> Result<MockProverReport>;

    fn inspect(&self) -> Result<CircuitIntrospection>;
}
