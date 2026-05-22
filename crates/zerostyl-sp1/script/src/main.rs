use anyhow::{anyhow, Context, Result};
use sp1_sdk::{Prover, ProverClient, SP1Stdin};
use std::path::PathBuf;
use zerostyl_verifier::vk_components::VkComponents;

const ELF_PATH: &str =
    "../program/elf/riscv32im-succinct-zkvm-elf/release/zerostyl-sp1-program";

#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    let elf = load_elf()?;

    let vk = sample_vk_components();
    let proof_bytes: Vec<u8> = vec![0u8; 64];
    let inputs_bytes: Vec<u8> = vec![0u8; 32];

    let vk_bytes = postcard::to_allocvec(&vk).context("encode VkComponents")?;

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(vk_bytes);
    stdin.write_vec(proof_bytes.clone());
    stdin.write_vec(inputs_bytes.clone());

    let client = ProverClient::from_env().await;
    let (mut public_values, _report) = client
        .execute(elf.into(), stdin)
        .await
        .map_err(|e| anyhow!("execute: {e}"))?;

    let echoed_k: u32 = public_values.read();
    let echoed_proof_len: u32 = public_values.read();
    let echoed_inputs_len: u32 = public_values.read();

    if echoed_k != vk.k {
        return Err(anyhow!("k mismatch: guest={echoed_k} host={}", vk.k));
    }
    if echoed_proof_len as usize != proof_bytes.len() {
        return Err(anyhow!(
            "proof_bytes length mismatch: guest={echoed_proof_len} host={}",
            proof_bytes.len()
        ));
    }
    if echoed_inputs_len as usize != inputs_bytes.len() {
        return Err(anyhow!(
            "inputs_bytes length mismatch: guest={echoed_inputs_len} host={}",
            inputs_bytes.len()
        ));
    }

    println!(
        "pipe ok: k={echoed_k} proof_len={echoed_proof_len} inputs_len={echoed_inputs_len}"
    );
    Ok(())
}

fn load_elf() -> Result<Vec<u8>> {
    let candidates = [
        PathBuf::from(ELF_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ELF_PATH),
    ];
    for path in &candidates {
        if path.exists() {
            return std::fs::read(path).with_context(|| format!("read {}", path.display()));
        }
    }
    Err(anyhow!(
        "guest ELF not found. Run `cargo prove build` inside crates/zerostyl-sp1/program first."
    ))
}

fn sample_vk_components() -> VkComponents {
    VkComponents {
        k: 4,
        extended_k: 7,
        omega: vec![0u8; 32],
        num_fixed_columns: 1,
        num_advice_columns: 1,
        num_instance_columns: 1,
        num_selectors: 1,
        fixed_commitments: vec![vec![0u8; 32]],
        permutation_commitments: vec![vec![0u8; 32]],
        permutation_columns: vec![(0, 0)],
    }
}
