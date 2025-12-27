//! WASM Code Generation for ZeroStyl Circuits
//!
//! Generates WebAssembly bytecode from CircuitIR for Arbitrum Stylus deployment.

pub mod keys;
pub mod prover;
pub mod wasm_builder;

use crate::{CircuitIR, CompilerError, Result};
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, ImportSection, Module,
    TypeSection, ValType,
};

extern crate serde_json;

#[derive(Debug, Clone)]
pub struct WasmCodegen {
    circuit_ir: CircuitIR,
    config: CodegenConfig,
}

#[derive(Debug, Clone)]
pub struct CodegenConfig {
    pub optimize_size: bool,
    pub max_size_bytes: usize,
    pub debug_symbols: bool,
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

#[derive(Debug, Clone)]
pub struct CircuitMetadata {
    pub name: String,
    pub num_witnesses: usize,
    pub num_public_inputs: usize,
    pub k_param: u32,
    pub compiler_version: String,
}

impl WasmCodegen {
    pub fn new(circuit_ir: CircuitIR) -> Self {
        Self { circuit_ir, config: CodegenConfig::default() }
    }

    pub fn with_config(circuit_ir: CircuitIR, config: CodegenConfig) -> Self {
        Self { circuit_ir, config }
    }

    pub fn circuit_ir(&self) -> &CircuitIR {
        &self.circuit_ir
    }

    pub fn config(&self) -> &CodegenConfig {
        &self.config
    }

    pub fn compile(&self) -> Result<Vec<u8>> {
        let mut module = Module::new();

        let mut types = TypeSection::new();
        self.add_type_definitions(&mut types);
        module.section(&types);

        let mut imports = ImportSection::new();
        self.add_stylus_imports(&mut imports);
        module.section(&imports);

        let mut functions = FunctionSection::new();
        self.add_function_declarations(&mut functions);
        module.section(&functions);

        let mut exports = ExportSection::new();
        self.add_exports(&mut exports);
        module.section(&exports);

        let mut code = CodeSection::new();
        self.add_function_implementations(&mut code)?;
        module.section(&code);

        self.add_metadata_section(&mut module);

        let wasm_bytes = module.finish();

        if wasm_bytes.len() > self.config.max_size_bytes {
            eprintln!(
                "Warning: WASM size {} bytes exceeds target {} bytes",
                wasm_bytes.len(),
                self.config.max_size_bytes
            );
        }

        Ok(wasm_bytes)
    }

    fn add_type_definitions(&self, types: &mut TypeSection) {
        // prove(witnesses_ptr, witnesses_len, inputs_ptr, inputs_len) -> proof_ptr
        types.ty().function(
            vec![ValType::I32, ValType::I32, ValType::I32, ValType::I32],
            vec![ValType::I32],
        );

        // verify(proof_ptr, proof_len, inputs_ptr, inputs_len) -> bool
        types.ty().function(
            vec![ValType::I32, ValType::I32, ValType::I32, ValType::I32],
            vec![ValType::I32],
        );

        // get_circuit_metadata() -> metadata_ptr
        types.ty().function(vec![], vec![ValType::I32]);
    }

    fn add_stylus_imports(&self, imports: &mut ImportSection) {
        use wasm_encoder::{EntityType, MemoryType};

        imports.import(
            "env",
            "memory",
            EntityType::Memory(MemoryType {
                minimum: 1,
                maximum: Some(256),
                memory64: false,
                shared: false,
                page_size_log2: None,
            }),
        );
    }

    fn add_function_declarations(&self, functions: &mut FunctionSection) {
        functions.function(0); // prove
        functions.function(1); // verify
        functions.function(2); // get_circuit_metadata
    }

    fn add_exports(&self, exports: &mut ExportSection) {
        exports.export("prove", ExportKind::Func, 0);
        exports.export("verify", ExportKind::Func, 1);
        exports.export("get_circuit_metadata", ExportKind::Func, 2);
    }

    fn add_function_implementations(&self, code: &mut CodeSection) -> Result<()> {
        code.function(&self.generate_prove_function()?);
        code.function(&self.generate_verify_function()?);
        code.function(&self.generate_metadata_function());
        Ok(())
    }

    fn generate_prove_function(&self) -> Result<Function> {
        let mut func = Function::new(vec![]);

        // TODO: Implement halo2 proof generation
        use wasm_encoder::Instruction;
        func.instruction(&Instruction::I32Const(0));
        func.instruction(&Instruction::End);

        Ok(func)
    }

    fn generate_verify_function(&self) -> Result<Function> {
        let mut func = Function::new(vec![]);

        // TODO: Implement halo2 proof verification
        use wasm_encoder::Instruction;
        func.instruction(&Instruction::I32Const(0));
        func.instruction(&Instruction::End);

        Ok(func)
    }

    fn generate_metadata_function(&self) -> Function {
        let mut func = Function::new(vec![]);

        // TODO: Serialize CircuitMetadata to JSON
        use wasm_encoder::Instruction;
        func.instruction(&Instruction::I32Const(0));
        func.instruction(&Instruction::End);

        func
    }

    fn add_metadata_section(&self, module: &mut Module) {
        let metadata = CircuitMetadata {
            name: self.circuit_ir.name.clone(),
            num_witnesses: self.circuit_ir.private_witnesses.len(),
            num_public_inputs: self.circuit_ir.public_inputs.len(),
            k_param: self.circuit_ir.circuit_config.k(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let metadata_json = serde_json::json!({
            "name": metadata.name,
            "num_witnesses": metadata.num_witnesses,
            "num_public_inputs": metadata.num_public_inputs,
            "k_param": metadata.k_param,
            "compiler_version": metadata.compiler_version,
        });

        module.section(&wasm_encoder::CustomSection {
            name: "zerostyl_metadata".into(),
            data: metadata_json.to_string().into_bytes().into(),
        });
    }

    pub fn estimate_size(&self) -> usize {
        let mut size = 5_000;
        size += self.circuit_ir.private_witnesses.len() * 1_000;
        size += self.circuit_ir.public_inputs.len() * 500;
        size += self.circuit_ir.inter_field_constraints.len() * 2_000;
        size += (2_usize.pow(self.circuit_ir.circuit_config.k()) / 1000) * 100;
        size
    }
}

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
    fn test_empty_circuit_generates_valid_wasm() {
        let circuit_ir = CircuitIR {
            name: "EmptyCircuit".to_string(),
            private_witnesses: vec![],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(17).unwrap(),
        };

        let codegen = WasmCodegen::new(circuit_ir);
        let wasm_bytes = codegen.compile().expect("Compilation should succeed");

        // Should have WASM magic number
        assert!(wasm_bytes.len() >= 8, "WASM too short: {} bytes", wasm_bytes.len());
    }

    #[test]
    fn test_wasm_bytecode_has_magic_number() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let wasm_bytes = codegen.compile().expect("Compilation should succeed");

        // Check WASM magic number: "\0asm" (0x00 0x61 0x73 0x6d)
        assert_eq!(&wasm_bytes[0..4], &[0x00, 0x61, 0x73, 0x6d], "Invalid WASM magic number");

        // Check WASM version: 1 (0x01 0x00 0x00 0x00)
        assert_eq!(&wasm_bytes[4..8], &[0x01, 0x00, 0x00, 0x00], "Invalid WASM version");
    }

    #[test]
    fn test_wasm_size_reasonable() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let wasm_bytes = codegen.compile().expect("Compilation should succeed");

        // Should be reasonably sized (not empty, not huge)
        assert!(wasm_bytes.len() > 100, "WASM too small");
        assert!(wasm_bytes.len() < 1_000_000, "WASM too large: {} bytes", wasm_bytes.len());
    }

    #[test]
    fn test_validate_wasm_success() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);
        let wasm_bytes = codegen.compile().expect("Compilation should succeed");

        // Should pass validation
        validate_wasm(&wasm_bytes).expect("WASM should be valid");
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
    fn test_estimate_size() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir);

        let estimated = codegen.estimate_size();

        // Should have a reasonable estimate (> 5KB for base, + witnesses, etc.)
        assert!(estimated > 5_000, "Estimate too low: {}", estimated);
        assert!(estimated < 50_000, "Estimate too high: {}", estimated);
    }

    #[test]
    fn test_metadata_embedded_in_wasm() {
        let circuit_ir = create_test_circuit_ir();
        let codegen = WasmCodegen::new(circuit_ir.clone());
        let wasm_bytes = codegen.compile().expect("Compilation should succeed");

        // Parse WASM to check for metadata section
        // Note: This is a basic check - full parsing would use wasmparser
        let wasm_str = String::from_utf8_lossy(&wasm_bytes);

        // Should contain circuit name somewhere in metadata
        assert!(
            wasm_str.contains("TestCircuit") || wasm_str.contains("zerostyl"),
            "Metadata not found in WASM"
        );
    }

    #[test]
    fn test_compile_multiple_witnesses() {
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
        let wasm_bytes = codegen.compile().expect("Should compile");

        validate_wasm(&wasm_bytes).expect("Should be valid WASM");
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
    fn test_validate_wasm_wrong_version() {
        // Valid magic but wrong version
        let invalid_wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00];
        let result = validate_wasm(&invalid_wasm);

        // Should fail validation due to unsupported version
        assert!(result.is_err());
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

    #[test]
    fn test_compile_with_large_k() {
        let circuit_ir = CircuitIR {
            name: "LargeK".to_string(),
            private_witnesses: vec![ZkField {
                name: "w".to_string(),
                field_type: ZkType::U64,
                constraints: vec![],
            }],
            public_inputs: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(20).unwrap(),
        };

        let codegen = WasmCodegen::new(circuit_ir);
        let wasm_bytes = codegen.compile().expect("Should compile with large k");

        validate_wasm(&wasm_bytes).expect("Should be valid WASM");
    }
}
