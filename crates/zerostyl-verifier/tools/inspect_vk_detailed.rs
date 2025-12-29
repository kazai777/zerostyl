//! Detailed VK structure analysis to understand serialization requirements

#![allow(dead_code, clippy::empty_line_after_doc_comments)]

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{keygen_vk, Circuit, Column, ConstraintSystem, Error},
    plonk::{Advice, Instance, Selector},
    poly::{commitment::Params, Rotation},
};
use halo2curves::pasta::{EqAffine, Fp};
use std::fs::File;
use std::io::Write as IoWrite;

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

fn main() -> std::io::Result<()> {
    println!("VK Detailed Inspector - Understanding PinnedVerificationKey\n");

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

    // Get pinned VK
    let pinned = vk.pinned();

    println!("=== PinnedVerificationKey Analysis ===\n");

    println!("Note: PinnedVerificationKey does not implement Serialize");
    println!("We need to implement custom serialization based on its structure\n");

    // Print debug representation (limited)
    let debug_str = format!("{:?}", pinned);
    println!("Debug representation (first 1000 chars):");
    println!("{}", &debug_str.chars().take(1000).collect::<String>());
    if debug_str.len() > 1000 {
        println!("... ({} more chars)", debug_str.len() - 1000);
    }
    println!();

    // Write full debug to file for analysis
    let mut debug_file = File::create("vk_debug.txt")?;
    writeln!(debug_file, "{:#?}", pinned)?;
    println!("✓ Full debug output written to vk_debug.txt");

    println!("\n=== Next Steps ===");
    println!("1. Examine vk_debug.txt to understand PinnedVerificationKey structure");
    println!("2. Implement custom VkComponents struct based on this structure");
    println!("3. Create manual serialization/deserialization for no_std");

    Ok(())
}
