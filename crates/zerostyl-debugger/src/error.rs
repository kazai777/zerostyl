//! Error types for the ZeroStyl debugger.

use thiserror::Error;

/// Errors that can occur during circuit debugging.
#[derive(Debug, Error)]
pub enum DebugError {
    #[error("Circuit error: {0}")]
    CircuitError(String),

    #[error("Witness error: {0}")]
    WitnessError(String),

    #[error("MockProver error: {0}")]
    MockProverError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, DebugError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_error_display() {
        let err = DebugError::CircuitError("gate mismatch".to_string());
        assert_eq!(err.to_string(), "Circuit error: gate mismatch");
    }

    #[test]
    fn test_witness_error_display() {
        let err = DebugError::WitnessError("unassigned cell".to_string());
        assert_eq!(err.to_string(), "Witness error: unassigned cell");
    }

    #[test]
    fn test_mock_prover_error_display() {
        let err = DebugError::MockProverError("synthesis failed".to_string());
        assert_eq!(err.to_string(), "MockProver error: synthesis failed");
    }

    #[test]
    fn test_serialization_error_display() {
        let err = DebugError::SerializationError("invalid JSON".to_string());
        assert_eq!(err.to_string(), "Serialization error: invalid JSON");
    }

    #[test]
    fn test_result_type() {
        let ok: Result<u32> = Ok(42);
        assert!(ok.is_ok());

        let err: Result<u32> = Err(DebugError::CircuitError("fail".to_string()));
        assert!(err.is_err());
    }
}
