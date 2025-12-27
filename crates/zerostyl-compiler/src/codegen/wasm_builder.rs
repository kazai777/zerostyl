//! Rust to WASM compilation for zerostyl-verifier

use crate::{CompilerError, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct WasmBuilder {
    verifier_crate_path: PathBuf,
    target: String,
    optimize: bool,
}

impl WasmBuilder {
    pub fn new<P: AsRef<Path>>(verifier_crate_path: P) -> Self {
        Self {
            verifier_crate_path: verifier_crate_path.as_ref().to_path_buf(),
            target: "wasm32-unknown-unknown".to_string(),
            optimize: true,
        }
    }

    pub fn with_target(mut self, target: String) -> Self {
        self.target = target;
        self
    }

    pub fn with_optimization(mut self, optimize: bool) -> Self {
        self.optimize = optimize;
        self
    }

    pub fn build(&self) -> Result<Vec<u8>> {
        let manifest_path = self.verifier_crate_path.join("Cargo.toml");
        if !manifest_path.exists() {
            return Err(CompilerError::Other(format!(
                "Verifier crate not found at {:?}",
                self.verifier_crate_path
            )));
        }

        let mut command = Command::new("cargo");
        command
            .arg("build")
            .arg("--target")
            .arg(&self.target)
            .arg("--release")
            .arg("--manifest-path")
            .arg(&manifest_path)
            .arg("--quiet");

        let output = command.output().map_err(|e| {
            CompilerError::Other(format!("Failed to execute cargo build: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CompilerError::Other(format!("Cargo build failed:\n{}", stderr)));
        }

        let wasm_path = self.get_wasm_output_path();
        let wasm_bytes = std::fs::read(&wasm_path).map_err(|e| {
            CompilerError::Other(format!("Failed to read WASM file at {:?}: {}", wasm_path, e))
        })?;

        if self.optimize {
            self.optimize_wasm(&wasm_bytes)
        } else {
            Ok(wasm_bytes)
        }
    }

    fn get_wasm_output_path(&self) -> PathBuf {
        self.verifier_crate_path
            .join("target")
            .join(&self.target)
            .join("release")
            .join("zerostyl_verifier.wasm")
    }

    fn optimize_wasm(&self, wasm_bytes: &[u8]) -> Result<Vec<u8>> {
        let wasm_opt_available = Command::new("wasm-opt")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if !wasm_opt_available {
            eprintln!("Warning: wasm-opt not found. Skipping optimization.");
            eprintln!("Install binaryen: https://github.com/WebAssembly/binaryen");
            return Ok(wasm_bytes.to_vec());
        }

        let temp_input = std::env::temp_dir().join("zerostyl_verifier_input.wasm");
        let temp_output = std::env::temp_dir().join("zerostyl_verifier_output.wasm");

        std::fs::write(&temp_input, wasm_bytes).map_err(|e| {
            CompilerError::Other(format!("Failed to write temp WASM file: {}", e))
        })?;

        let output = Command::new("wasm-opt")
            .arg("-Oz")
            .arg("--strip-debug")
            .arg("--strip-producers")
            .arg(&temp_input)
            .arg("-o")
            .arg(&temp_output)
            .output()
            .map_err(|e| CompilerError::Other(format!("Failed to run wasm-opt: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: wasm-opt failed: {}", stderr);
            return Ok(wasm_bytes.to_vec());
        }

        let optimized = std::fs::read(&temp_output).map_err(|e| {
            CompilerError::Other(format!("Failed to read optimized WASM: {}", e))
        })?;

        let _ = std::fs::remove_file(&temp_input);
        let _ = std::fs::remove_file(&temp_output);

        println!(
            "WASM optimization: {} bytes → {} bytes ({:.1}% reduction)",
            wasm_bytes.len(),
            optimized.len(),
            (1.0 - (optimized.len() as f64 / wasm_bytes.len() as f64)) * 100.0
        );

        Ok(optimized)
    }

    pub fn build_with_metadata(&self) -> Result<WasmBuildOutput> {
        let wasm_bytes = self.build()?;
        Ok(WasmBuildOutput {
            wasm_bytes: wasm_bytes.clone(),
            size_bytes: wasm_bytes.len(),
            optimized: self.optimize,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WasmBuildOutput {
    pub wasm_bytes: Vec<u8>,
    pub size_bytes: usize,
    pub optimized: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_builder_creation() {
        let builder = WasmBuilder::new("crates/zerostyl-verifier");
        assert_eq!(builder.target, "wasm32-unknown-unknown");
        assert!(builder.optimize);
    }

    #[test]
    fn test_wasm_builder_with_custom_settings() {
        let builder = WasmBuilder::new("crates/zerostyl-verifier")
            .with_target("wasm32-wasi".to_string())
            .with_optimization(false);

        assert_eq!(builder.target, "wasm32-wasi");
        assert!(!builder.optimize);
    }

    #[test]
    fn test_get_wasm_output_path() {
        let builder = WasmBuilder::new("crates/zerostyl-verifier");
        let path = builder.get_wasm_output_path();

        assert!(path.to_string_lossy().contains("zerostyl_verifier.wasm"));
        assert!(path.to_string_lossy().contains("wasm32-unknown-unknown"));
    }
}
