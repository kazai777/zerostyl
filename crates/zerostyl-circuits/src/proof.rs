use serde::{Deserialize, Serialize};

/// Output of a successful proof generation.
///
/// `public_inputs_json` is the canonical JSON encoding written next to
/// `bytes` on disk (one per circuit), so verification can be reproduced
/// without re-deriving inputs from the witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub bytes: Vec<u8>,
    pub public_inputs_json: String,
}

impl ProofArtifact {
    pub fn new(bytes: Vec<u8>, public_inputs_json: String) -> Self {
        Self { bytes, public_inputs_json }
    }
}
