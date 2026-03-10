//! WASM Code Generation for ZeroStyl Circuits
//!
//! Generates a Rust crate from CircuitIR, compiles it to WebAssembly
//! via `cargo build --target wasm32-unknown-unknown`, and returns the
//! resulting `.wasm` bytes for Arbitrum Stylus deployment.

pub mod keys;
pub mod prover;
pub mod wasm_builder;

use crate::codegen::wasm_builder::WasmBuilder;
use crate::{CircuitIR, CompilerError, Result};

/// WASM code generator that transforms a `CircuitIR` into a compilable Rust crate
/// and builds it to WebAssembly for Arbitrum Stylus deployment.
#[derive(Debug, Clone)]
pub struct WasmCodegen {
    circuit_ir: CircuitIR,
    config: CodegenConfig,
}

/// Configuration for WASM code generation.
#[derive(Debug, Clone)]
pub struct CodegenConfig {
    /// Optimize the output WASM for size (uses `wasm-opt -Oz` if available).
    pub optimize_size: bool,
    /// Maximum allowed WASM size in bytes (warning emitted if exceeded).
    pub max_size_bytes: usize,
    /// Include debug symbols in the output.
    pub debug_symbols: bool,
    /// Target Stylus SDK version.
    pub stylus_version: String,
}

impl Default for CodegenConfig {
    fn default() -> Self {
        Self {
            optimize_size: true,
            max_size_bytes: 150_000,
            debug_symbols: false,
            stylus_version: "0.9.0".to_string(),
        }
    }
}

/// Metadata describing a compiled circuit, embedded in the generated WASM.
#[derive(Debug, Clone)]
pub struct CircuitMetadata {
    /// Circuit name.
    pub name: String,
    /// Number of private witnesses.
    pub num_witnesses: usize,
    /// Number of public inputs.
    pub num_public_inputs: usize,
    /// Circuit size parameter (rows = 2^k).
    pub k_param: u32,
    /// Compiler version that generated this circuit.
    pub compiler_version: String,
}

impl WasmCodegen {
    /// Create a new WASM code generator with default configuration.
    pub fn new(circuit_ir: CircuitIR) -> Self {
        Self { circuit_ir, config: CodegenConfig::default() }
    }

    /// Create a new WASM code generator with custom configuration.
    pub fn with_config(circuit_ir: CircuitIR, config: CodegenConfig) -> Self {
        Self { circuit_ir, config }
    }

    /// Returns a reference to the circuit intermediate representation.
    pub fn circuit_ir(&self) -> &CircuitIR {
        &self.circuit_ir
    }

    /// Returns a reference to the codegen configuration.
    pub fn config(&self) -> &CodegenConfig {
        &self.config
    }

    /// Compile the circuit to WASM by generating a temporary Rust crate
    /// and building it with `cargo build --target wasm32-unknown-unknown --release`.
    pub fn compile(&self) -> Result<Vec<u8>> {
        let temp_dir =
            std::env::temp_dir().join(format!("zerostyl_codegen_{}", self.circuit_ir.name));

        // Clean up any previous run
        let _ = std::fs::remove_dir_all(&temp_dir);

        let src_dir = temp_dir.join("src");
        std::fs::create_dir_all(&src_dir)
            .map_err(|e| CompilerError::Other(format!("Failed to create temp directory: {}", e)))?;

        // Write generated source files
        std::fs::write(temp_dir.join("Cargo.toml"), self.generate_cargo_toml())
            .map_err(|e| CompilerError::Other(format!("Failed to write Cargo.toml: {}", e)))?;

        std::fs::write(src_dir.join("lib.rs"), self.generate_lib_rs())
            .map_err(|e| CompilerError::Other(format!("Failed to write lib.rs: {}", e)))?;

        // Build using WasmBuilder
        let builder = WasmBuilder::new(&temp_dir).with_optimization(self.config.optimize_size);
        let wasm_bytes = builder.build();

        // Clean up temp directory regardless of build result
        let _ = std::fs::remove_dir_all(&temp_dir);

        let wasm_bytes = wasm_bytes?;

        if wasm_bytes.len() > self.config.max_size_bytes {
            eprintln!(
                "Warning: WASM size {} bytes exceeds target {} bytes",
                wasm_bytes.len(),
                self.config.max_size_bytes
            );
        }

        Ok(wasm_bytes)
    }

    /// Generate the Cargo.toml for the temporary verifier crate.
    ///
    /// NOTE: The generated crate is `no_std` and does not include `halo2_proofs`
    /// as a dependency because full halo2 verification in WASM requires a
    /// significant binary size (~2MB+) which exceeds Arbitrum Stylus contract
    /// size limits. Real on-chain verification should use a precompile-based
    /// approach or a custom verifier compiled separately. The generated `verify()`
    /// function is a placeholder that returns an error code.
    pub fn generate_cargo_toml(&self) -> String {
        r#"[package]
name = "zerostyl-verifier"
version = "0.1.0"
edition = "2021"

# NOTE: halo2_proofs is intentionally not included as a dependency.
# Full halo2 verification in WASM exceeds Stylus contract size limits (~24KB).
# On-chain proof verification should use a dedicated verifier contract or
# precompile. This crate provides circuit metadata and a placeholder verify().

[lib]
crate-type = ["cdylib"]

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#
        .to_string()
    }

    /// Generate the lib.rs source for the temporary verifier crate.
    ///
    /// Produces a minimal `#![no_std]` crate with circuit metadata constants,
    /// a `verify()` FFI export (returns -2 "not implemented"), and a
    /// `get_circuit_metadata()` export returning embedded JSON.
    pub fn generate_lib_rs(&self) -> String {
        let metadata = self.build_metadata();
        let metadata_json = format!(
            r#"{{"name":"{}","num_witnesses":{},"num_public_inputs":{},"k_param":{},"compiler_version":"{}"}}"#,
            metadata.name,
            metadata.num_witnesses,
            metadata.num_public_inputs,
            metadata.k_param,
            metadata.compiler_version,
        );
        let metadata_json_escaped = metadata_json.replace('"', "\\\"");

        format!(
            r#"#![no_std]
#![no_main]

// ZeroStyl Generated Verifier — Circuit: {name}

const CIRCUIT_NAME: &str = "{name}";
const CIRCUIT_K: u32 = {k};
const NUM_WITNESSES: usize = {num_witnesses};
const NUM_PUBLIC_INPUTS: usize = {num_public_inputs};
const COMPILER_VERSION: &str = "{compiler_version}";

static METADATA_JSON: &[u8] = b"{metadata_json}\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {{
    loop {{}}
}}

/// Verify a ZK proof.
///
/// # Return codes
/// - `0`: proof is valid
/// - `-1`: proof verification failed (invalid proof)
/// - `-2`: verification not implemented (placeholder)
///
/// # Current status
/// This is a placeholder. Full halo2 verification requires embedding the
/// verification key and a WASM-compatible verifier, which exceeds Stylus
/// contract size limits. Use an off-chain verifier or a dedicated on-chain
/// verifier contract for production proof verification.
#[no_mangle]
pub extern "C" fn verify(
    _proof_ptr: *const u8,
    _proof_len: u32,
    _inputs_ptr: *const u8,
    _inputs_len: u32,
) -> i32 {{
    // Error code -2: verification not implemented
    // Distinct from -1 (invalid proof) so callers can distinguish
    // "not yet supported" from "proof rejected".
    -2
}}

/// Get circuit metadata as a pointer to a null-terminated JSON byte string.
#[no_mangle]
pub extern "C" fn get_circuit_metadata() -> *const u8 {{
    METADATA_JSON.as_ptr()
}}
"#,
            name = metadata.name,
            k = metadata.k_param,
            num_witnesses = metadata.num_witnesses,
            num_public_inputs = metadata.num_public_inputs,
            compiler_version = metadata.compiler_version,
            metadata_json = metadata_json_escaped,
        )
    }

    /// Extract circuit metadata from the CircuitIR.
    pub fn build_metadata(&self) -> CircuitMetadata {
        CircuitMetadata {
            name: self.circuit_ir.name.clone(),
            num_witnesses: self.circuit_ir.private_witnesses.len(),
            num_public_inputs: self.circuit_ir.public_inputs.len(),
            k_param: self.circuit_ir.circuit_config.k(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Estimate the output WASM size in bytes based on circuit complexity.
    pub fn estimate_size(&self) -> usize {
        let mut size = 5_000;
        size += self.circuit_ir.private_witnesses.len() * 1_000;
        size += self.circuit_ir.public_inputs.len() * 500;
        size += self.circuit_ir.inter_field_constraints.len() * 2_000;
        size += (2_usize.pow(self.circuit_ir.circuit_config.k()) / 1000) * 100;
        size
    }
}

/// Validate WASM bytes: checks magic number, version, and runs `wasmparser` validation.
pub fn validate_wasm(wasm_bytes: &[u8]) -> Result<()> {
    if wasm_bytes.len() < 4 {
        return Err(CompilerError::Other("WASM too short".to_string()));
    }

    if wasm_bytes[0..4] != [0x00, 0x61, 0x73, 0x6d] {
        return Err(CompilerError::Other("Invalid WASM magic number".to_string()));
    }

    if wasm_bytes.len() < 8 {
        return Err(CompilerError::Other("WASM too short".to_string()));
    }

    if wasm_bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        return Err(CompilerError::Other("Unsupported WASM version".to_string()));
    }

    wasmparser::validate(wasm_bytes)
        .map(|_| ())
        .map_err(|e| CompilerError::Other(format!("WASM validation failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ZkField, ZkType};
    use zerostyl_runtime::CircuitConfig;

    fn create_test_circuit_ir() -> CircuitIR {
        CircuitIR {
            name: "TestCircuit".to_string(),
            private_witnesses: vec![ZkField {
                name: "secret_value".to_string(),
                field_type: ZkType::U64,
                constraints: vec![],
            }],
            public_inputs: vec![ZkField {
                name: "public_commitment".to_string(),
                field_type: ZkType::Bytes32,
                constraints: vec![],
            }],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        }
    }

    #[test]
    fn test_codegen_initialization() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir.clone());

        assert_eq!(codegen.circuit_ir().name, "TestCircuit");
        assert!(codegen.config().optimize_size);
        assert_eq!(codegen.config().max_size_bytes, 150_000);
    }

    #[test]
    fn test_codegen_with_custom_config() {
        let circuit_ir = create_test_circuit_ir();
        let config = CodegenConfig {
            optimize_size: false,
            max_size_bytes: 200_000,
            debug_symbols: true,
            stylus_version: "0.9.0".to_string(),
        };

        let codegen = WasmCodegen::with_config(circuit_ir, config);

        assert!(!codegen.config().optimize_size);
        assert_eq!(codegen.config().max_size_bytes, 200_000);
        assert!(codegen.config().debug_symbols);
    }

    #[test]
    fn test_codegen_config_default() {
        let config = CodegenConfig::default();
        assert!(config.optimize_size);
        assert_eq!(config.max_size_bytes, 150_000);
        assert!(!config.debug_symbols);
        assert_eq!(config.stylus_version, "0.9.0");
    }

    #[test]
    fn test_circuit_metadata() {
        let metadata = CircuitMetadata {
            name: "TestCircuit".to_string(),
            num_witnesses: 10,
            num_public_inputs: 3,
            k_param: 17,
            compiler_version: "0.1.0".to_string(),
        };

        assert_eq!(metadata.name, "TestCircuit");
        assert_eq!(metadata.num_witnesses, 10);
        assert_eq!(metadata.num_public_inputs, 3);
        assert_eq!(metadata.k_param, 17);
    }

    #[test]
    fn test_validate_wasm_invalid_magic() {
        let invalid_wasm = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00];
        let result = validate_wasm(&invalid_wasm);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic number"));
    }

    #[test]
    fn test_validate_wasm_too_short() {
        let invalid_wasm = vec![0x00, 0x61];
        let result = validate_wasm(&invalid_wasm);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_wasm_wrong_version() {
        let invalid_wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00];
        let result = validate_wasm(&invalid_wasm);

        assert!(result.is_err());
    }

    #[test]
    fn test_estimate_size() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);

        let estimated = codegen.estimate_size();

        assert!(estimated > 5_000, "Estimate too low: {}", estimated);
        assert!(estimated < 50_000, "Estimate too high: {}", estimated);
    }

    #[test]
    fn test_estimate_size_scales_with_witnesses() {
        let base_circuit = CircuitIR {
            name: "Base".to_string(),
            private_witnesses: vec![],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        };

        let with_witnesses = CircuitIR {
            name: "WithWitnesses".to_string(),
            private_witnesses: vec![
                ZkField { name: "w1".to_string(), field_type: ZkType::U64, constraints: vec![] },
                ZkField { name: "w2".to_string(), field_type: ZkType::U64, constraints: vec![] },
            ],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        };

        let base_size = WasmCodegen::new(base_circuit).estimate_size();
        let witness_size = WasmCodegen::new(with_witnesses).estimate_size();

        assert!(witness_size > base_size, "Size should increase with witnesses");
    }

    #[test]
    fn test_estimate_size_scales_with_k() {
        let k10_circuit = CircuitIR {
            name: "K10".to_string(),
            private_witnesses: vec![],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(10).unwrap(),
        };

        let k17_circuit = CircuitIR {
            name: "K17".to_string(),
            private_witnesses: vec![],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        };

        let k10_size = WasmCodegen::new(k10_circuit).estimate_size();
        let k17_size = WasmCodegen::new(k17_circuit).estimate_size();

        assert!(k17_size > k10_size, "Size should increase with k parameter");
    }

    // =========================================================================
    // Source generation tests
    // =========================================================================

    #[test]
    fn test_generate_lib_rs_contains_circuit_name() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("TestCircuit"), "Source should contain circuit name");
        assert!(
            source.contains(r#"const CIRCUIT_NAME: &str = "TestCircuit""#),
            "Source should have CIRCUIT_NAME constant"
        );
    }

    #[test]
    fn test_generate_lib_rs_contains_metadata_constants() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("const CIRCUIT_K: u32 = 17;"));
        assert!(source.contains("const NUM_WITNESSES: usize = 1;"));
        assert!(source.contains("const NUM_PUBLIC_INPUTS: usize = 1;"));
        assert!(source.contains("const COMPILER_VERSION: &str ="));
    }

    #[test]
    fn test_generate_lib_rs_has_no_std() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("#![no_std]"), "Source must be no_std");
        assert!(source.contains("#[panic_handler]"), "Source must have panic handler");
    }

    #[test]
    fn test_generate_lib_rs_has_exports() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("pub extern \"C\" fn verify("), "Source must export verify");
        assert!(
            source.contains("pub extern \"C\" fn get_circuit_metadata()"),
            "Source must export get_circuit_metadata"
        );
        assert!(source.contains("#[no_mangle]"), "Exports must be #[no_mangle]");
    }

    #[test]
    fn test_generate_lib_rs_metadata_json() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("METADATA_JSON"), "Source must have METADATA_JSON");
        assert!(source.contains("TestCircuit"), "Metadata must contain circuit name");
        assert!(source.contains("num_witnesses"), "Metadata must contain witness count");
        assert!(source.contains("k_param"), "Metadata must contain k parameter");
    }

    #[test]
    fn test_generate_cargo_toml_valid() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let toml = codegen.generate_cargo_toml();

        assert!(toml.contains(r#"name = "zerostyl-verifier""#), "Must have correct crate name");
        assert!(toml.contains(r#"crate-type = ["cdylib"]"#), "Must be cdylib");
        assert!(toml.contains("[profile.release]"), "Must have release profile");
        assert!(toml.contains(r#"opt-level = "z""#), "Must optimize for size");
        assert!(toml.contains("panic = \"abort\""), "Must use panic abort");
    }

    #[test]
    fn test_build_metadata() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let metadata = codegen.build_metadata();

        assert_eq!(metadata.name, "TestCircuit");
        assert_eq!(metadata.num_witnesses, 1);
        assert_eq!(metadata.num_public_inputs, 1);
        assert_eq!(metadata.k_param, 17);
        assert_eq!(metadata.compiler_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_generate_lib_rs_multiple_witnesses() {
        let circuit_ir = CircuitIR {
            name: "MultiWitnessCircuit".to_string(),
            private_witnesses: vec![
                ZkField { name: "w1".to_string(), field_type: ZkType::U64, constraints: vec![] },
                ZkField { name: "w2".to_string(), field_type: ZkType::U64, constraints: vec![] },
                ZkField { name: "w3".to_string(), field_type: ZkType::U64, constraints: vec![] },
            ],
            public_inputs: vec![ZkField {
                name: "p1".to_string(),
                field_type: ZkType::Bytes32,
                constraints: vec![],
            }],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        };

        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("const NUM_WITNESSES: usize = 3;"));
        assert!(source.contains("const NUM_PUBLIC_INPUTS: usize = 1;"));
        assert!(source.contains("MultiWitnessCircuit"));
    }

    #[test]
    fn test_generate_lib_rs_empty_circuit() {
        let circuit_ir = CircuitIR {
            name: "EmptyCircuit".to_string(),
            private_witnesses: vec![],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        };

        let codegen = WasmCodegen::new(circuit_ir);
        let source = codegen.generate_lib_rs();

        assert!(source.contains("const NUM_WITNESSES: usize = 0;"));
        assert!(source.contains("const NUM_PUBLIC_INPUTS: usize = 0;"));
        assert!(source.contains("EmptyCircuit"));
    }

    #[test]
    #[ignore] // Requires wasm32-unknown-unknown target installed
    fn test_compile_produces_valid_wasm() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::with_config(
            circuit_ir,
            CodegenConfig { optimize_size: false, ..CodegenConfig::default() },
        );

        let wasm_bytes = codegen.compile().expect("Compilation should succeed");

        assert!(!wasm_bytes.is_empty(), "WASM output should not be empty");
        assert_eq!(&wasm_bytes[0..4], &[0x00, 0x61, 0x73, 0x6d], "Should have WASM magic number");
        validate_wasm(&wasm_bytes).expect("Generated WASM should be valid");
    }
}
