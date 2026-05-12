use serde::{Deserialize, Serialize};

/// Minimal ABI metadata exposed by every circuit.
///
/// Enriched by the ABI exporter (M3 bloc A) with function signatures,
/// commitment params, and SDK targets. Kept lean here so this crate
/// stays free of generator-specific concerns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiMetadata {
    pub circuit_name: String,
    pub version: String,
}
