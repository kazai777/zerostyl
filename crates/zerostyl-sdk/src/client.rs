//! The [`ZeroStyl`] client and per-circuit handles.

use std::path::{Path, PathBuf};

use zerostyl_circuits::{
    AbiSchema, CanonicalProof, CircuitDescriptor, CircuitIntrospection, MockProverReport,
    ProofArtifact, Registry,
};
use zerostyl_runtime::BytecodeFingerprint;

use crate::error::{Result, SdkError};

/// Default directory for cached KZG params, shared with the prover and CLI.
pub use zerostyl_runtime::DEFAULT_CACHE_DIR;

/// Client owning a circuit [`Registry`] and the key-cache directory.
pub struct ZeroStyl {
    registry: Registry,
    cache_dir: PathBuf,
}

impl ZeroStyl {
    /// Create a client with the default cache directory (`.zerostyl_cache`).
    pub fn new() -> Result<Self> {
        Ok(Self { registry: Registry::new(), cache_dir: PathBuf::from(DEFAULT_CACHE_DIR) })
    }

    /// Create a client with an explicit params-cache directory.
    pub fn with_cache_dir(cache_dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self { registry: Registry::new(), cache_dir: cache_dir.as_ref().to_path_buf() })
    }

    /// Register a circuit descriptor. Fails if the name is already taken.
    pub fn register(&mut self, descriptor: &'static dyn CircuitDescriptor) -> Result<()> {
        self.registry.register(descriptor)?;
        Ok(())
    }

    /// Names of all registered circuits.
    pub fn circuits(&self) -> Vec<&'static str> {
        self.registry.list()
    }

    /// Handle to a registered circuit.
    pub fn circuit(&self, name: &str) -> Result<CircuitHandle<'_>> {
        let descriptor = self.registry.get(name)?;
        Ok(CircuitHandle { descriptor, cache_dir: &self.cache_dir })
    }
}

/// Proving/verification interface for one registered circuit.
pub struct CircuitHandle<'a> {
    descriptor: &'static dyn CircuitDescriptor,
    cache_dir: &'a Path,
}

impl CircuitHandle<'_> {
    /// The underlying descriptor.
    pub fn descriptor(&self) -> &'static dyn CircuitDescriptor {
        self.descriptor
    }

    /// The circuit's ABI schema (same document the exporter writes).
    pub fn abi(&self) -> AbiSchema {
        AbiSchema::from_descriptor(self.descriptor)
    }

    /// keccak256 fingerprint of the circuit **name** — a routing/identification tag, not a
    /// security binding. Two circuits sharing a name (e.g. an upgraded "deposit" v2) share this
    /// id, so it does not by itself prevent cross-circuit proof reuse; for that, bind to the
    /// verifying key. Used by [`seal`](Self::seal) / [`open`](Self::open) and mirrors the
    /// generated contract's `CIRCUIT_ID` and the on-chain event's `circuit` field.
    pub fn circuit_id(&self) -> [u8; 32] {
        *BytecodeFingerprint::of(self.descriptor.name().as_bytes()).as_bytes()
    }

    /// Generate a proof with the circuit's default `k`.
    pub fn prove(&self, witness_json: &str) -> Result<ProofArtifact> {
        self.prove_with_k(witness_json, self.descriptor.default_k())
    }

    /// Generate a proof with an explicit `k`.
    pub fn prove_with_k(&self, witness_json: &str, k: u32) -> Result<ProofArtifact> {
        Ok(self.descriptor.prove(witness_json, k, self.cache_dir)?)
    }

    /// Verify a proof with the circuit's default `k`.
    pub fn verify(&self, proof: &[u8], public_inputs_json: &str) -> Result<bool> {
        self.verify_with_k(proof, public_inputs_json, self.descriptor.default_k())
    }

    /// Verify a proof with an explicit `k`.
    pub fn verify_with_k(&self, proof: &[u8], public_inputs_json: &str, k: u32) -> Result<bool> {
        Ok(self.descriptor.verify(proof, public_inputs_json, k, self.cache_dir)?)
    }

    /// Run the mock prover (constraint satisfaction without a real proof).
    pub fn mock_prove(&self, witness_json: &str) -> Result<MockProverReport> {
        Ok(self.descriptor.mock_prove(witness_json, self.descriptor.default_k())?)
    }

    /// Static circuit structure (columns, gates, degrees).
    pub fn inspect(&self) -> Result<CircuitIntrospection> {
        Ok(self.descriptor.inspect()?)
    }

    /// Wrap raw proof bytes in the [`CanonicalProof`] envelope, stamped with
    /// this circuit's [`circuit_id`](Self::circuit_id).
    ///
    /// The envelope is for **off-chain** storage and transport (it lets a reader identify which
    /// circuit a proof belongs to before verifying). On-chain verifiers and
    /// [`verify`](Self::verify) expect the **raw** proof bytes (`artifact.bytes`), not the
    /// envelope — [`open`](Self::open) it back to raw bytes before submitting on-chain.
    pub fn seal(&self, artifact: &ProofArtifact) -> Vec<u8> {
        CanonicalProof::new(self.circuit_id(), artifact.bytes.clone()).encode()
    }

    /// Decode a [`CanonicalProof`] envelope and return the raw proof bytes,
    /// rejecting proofs stamped for a different circuit.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        let decoded =
            CanonicalProof::decode(sealed).map_err(|e| SdkError::ProofFormat(e.to_string()))?;
        if decoded.circuit_id != self.circuit_id() {
            return Err(SdkError::ProofFormat(format!(
                "proof was sealed for another circuit (expected id 0x{}, found 0x{})",
                hex::encode(self.circuit_id()),
                hex::encode(decoded.circuit_id),
            )));
        }
        Ok(decoded.payload)
    }
}
