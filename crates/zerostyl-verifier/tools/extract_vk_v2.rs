//! VK extraction tool using debug output parsing
//! Workaround for halo2_proofs 0.3 not exposing VK fields publicly

#![allow(dead_code, clippy::implicit_saturating_sub)]

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{keygen_vk, Circuit, Column, ConstraintSystem, Error},
    plonk::{Advice, Instance, Selector},
    poly::{commitment::Params, Rotation},
};
use halo2curves::group::ff::PrimeField;
use halo2curves::pasta::{EqAffine, Fp};
use regex::Regex;
use std::fs::File;
use std::io::Write;

use zerostyl_verifier::vk_components::VkComponents;

const MERKLE_DEPTH: usize = 32;

#[derive(Clone, Debug)]
struct TxPrivacyConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    s_commitment: Selector,
    s_balance_check: Selector,
    s_merkle: Selector,
}

#[derive(Clone, Debug, Default)]
struct TxPrivacyCircuit {
    balance_old: Value<Fp>,
    balance_new: Value<Fp>,
    randomness_old: Value<Fp>,
    randomness_new: Value<Fp>,
    amount: Value<Fp>,
    merkle_path: Vec<Value<Fp>>,
}

impl Circuit<Fp> for TxPrivacyCircuit {
    type Config = TxPrivacyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();

        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        let s_commitment = meta.selector();
        let s_balance_check = meta.selector();
        let s_merkle = meta.selector();

        meta.create_gate("commitment", |meta| {
            let s = meta.query_selector(s_commitment);
            let balance = meta.query_advice(advice[0], Rotation::cur());
            let randomness = meta.query_advice(advice[1], Rotation::cur());
            let commitment = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (balance + randomness - commitment)]
        });

        meta.create_gate("balance_check", |meta| {
            let s = meta.query_selector(s_balance_check);
            let balance_old = meta.query_advice(advice[0], Rotation::cur());
            let balance_new = meta.query_advice(advice[1], Rotation::cur());
            let amount = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (balance_old - amount - balance_new)]
        });

        meta.create_gate("merkle", |meta| {
            let s = meta.query_selector(s_merkle);
            let current = meta.query_advice(advice[0], Rotation::cur());
            let sibling = meta.query_advice(advice[1], Rotation::cur());
            let next = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (current + sibling - next)]
        });

        TxPrivacyConfig { advice, instance, s_commitment, s_balance_check, s_merkle }
    }

    fn synthesize(&self, _config: Self::Config, _layouter: impl Layouter<Fp>) -> Result<(), Error> {
        Ok(())
    }
}

/// Parse VK commitments from debug output
/// This is a workaround since halo2_proofs 0.3 doesn't expose VK fields
fn parse_commitments_from_debug(debug_str: &str, section_name: &str) -> Vec<Vec<u8>> {
    let re = Regex::new(r"\(0x([0-9a-f]+), 0x([0-9a-f]+)\)").unwrap();

    // Find section
    let marker = format!("{}: [", section_name);
    let start = debug_str.find(&marker).unwrap_or(0);
    let section = &debug_str[start..];
    let end = section.find("],").or(section.find(']')).unwrap_or(section.len());
    let section_str = &section[..end];

    // Extract (x, y) pairs and use x-coordinate as compressed format
    re.captures_iter(section_str)
        .map(|cap| {
            let x_hex = &cap[1];
            hex_to_bytes(x_hex, 32)
        })
        .collect()
}

fn hex_to_bytes(hex: &str, target_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; target_len];
    let hex_clean = hex.trim_start_matches("0x");

    // Parse from right to left to handle varying lengths
    let mut byte_idx = target_len - 1;
    let mut chars: Vec<char> = hex_clean.chars().collect();

    while !chars.is_empty() && byte_idx > 0 {
        let len = chars.len();
        let start = if len >= 2 { len - 2 } else { 0 };
        let byte_str: String = chars.drain(start..).collect();
        bytes[byte_idx] = u8::from_str_radix(&byte_str, 16).unwrap_or(0);
        if byte_idx == 0 {
            break;
        }
        byte_idx -= 1;
    }

    bytes
}

fn main() -> std::io::Result<()> {
    println!("ZeroStyl VK Extractor v2 (Debug Parser)\n");

    let k = 10;

    println!("Generating params and VK...");
    let params = Params::<EqAffine>::new(k);

    let circuit = TxPrivacyCircuit {
        balance_old: Value::unknown(),
        balance_new: Value::unknown(),
        randomness_old: Value::unknown(),
        randomness_new: Value::unknown(),
        amount: Value::unknown(),
        merkle_path: vec![Value::unknown(); MERKLE_DEPTH],
    };

    let vk = keygen_vk(&params, &circuit).expect("VK generation failed");
    println!("✓ VK generated\n");

    // Get pinned VK and its debug representation
    let pinned = vk.pinned();
    let debug_output = format!("{:#?}", pinned);

    println!("Parsing VK components from debug output...");

    // Write debug output for reference
    let mut debug_file = File::create("vk_pinned_debug.txt")?;
    writeln!(debug_file, "{}", debug_output)?;
    println!("✓ Debug output saved to vk_pinned_debug.txt");

    // Extract domain info
    let domain = vk.get_domain();
    let omega = domain.get_omega();
    let omega_bytes = omega.to_repr().as_ref().to_vec();

    // Parse commitments
    let fixed_commitments = parse_commitments_from_debug(&debug_output, "fixed_commitments");
    println!("✓ Parsed {} fixed commitments", fixed_commitments.len());

    let permutation_commitments = parse_commitments_from_debug(&debug_output, "commitments");
    println!("✓ Parsed {} permutation commitments", permutation_commitments.len());

    // Create VK components
    let vk_components = VkComponents {
        k,
        extended_k: k + 1,
        omega: omega_bytes,
        num_fixed_columns: 2,
        num_advice_columns: 3,
        num_instance_columns: 1,
        num_selectors: 3,
        fixed_commitments,
        permutation_commitments,
        permutation_columns: vec![(0, 0), (1, 0), (2, 0), (0, 1)],
    };

    // Serialize
    let vk_bytes = vk_components.to_bytes().expect("Failed to serialize VK");
    println!("\n✓ VK components serialized: {} bytes\n", vk_bytes.len());

    // Write to file
    let output_path = "vk_components.rs";
    let mut file = File::create(output_path)?;

    writeln!(file, "// VK Components for tx_privacy circuit (k={})", k)?;
    writeln!(file, "// Auto-generated by extract-vk-v2 tool\n")?;
    writeln!(file, "pub const VK_BYTES: &[u8] = &{:?};", vk_bytes)?;
    writeln!(file, "pub const K: u32 = {};", k)?;

    println!("✓ VK components written to {}", output_path);
    println!("\nNext: Copy VK_BYTES to build.rs for embedding");

    Ok(())
}
