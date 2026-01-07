//! ZeroStyl Compiler Demo
//!
//! Demonstrates the full compiler pipeline:
//! 1. Parse Rust code with #[zk_private] annotations
//! 2. Transform to CircuitIR (intermediate representation)
//! 3. Build a halo2 circuit from the IR
//! 4. Verify the circuit with MockProver

use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use zerostyl_compiler::{parse_contract, transform_to_ir, CircuitBuilder};

fn main() {
    println!("\n=== ZeroStyl Compiler Demo ===\n");

    let rust_code = r#"
        struct PrivateTransfer {
            #[zk_private]
            sender_balance: u64,

            #[zk_private]
            amount: u64,

            #[zk_private]
            recipient_balance: u64,
        }
    "#;

    println!("STEP 1: Input Rust code with #[zk_private] annotations");
    println!("─────────────────────────────────────────────────────");
    println!("{}", rust_code);

    println!("STEP 2: Parse contract");
    println!("──────────────────────");
    let parsed = parse_contract(rust_code).expect("Failed to parse contract");
    println!("  Contract name: {}", parsed.contract_name);
    println!("  Private fields found: {}", parsed.private_fields.len());
    for field in &parsed.private_fields {
        println!("    - {} : {}", field.name, field.field_type);
    }
    println!();

    println!("STEP 3: Transform to CircuitIR");
    println!("──────────────────────────────");
    let ir = transform_to_ir(parsed).expect("Failed to transform to IR");
    println!("  Circuit name: {}", ir.name);
    println!("  Private witnesses: {}", ir.private_witnesses.len());
    for witness in &ir.private_witnesses {
        println!("    - {} : {:?}", witness.name, witness.field_type);
    }
    println!("  Circuit config k: {} ({} rows)", ir.circuit_config.k(), 1 << ir.circuit_config.k());
    println!();

    println!("STEP 4: Build halo2 circuit");
    println!("───────────────────────────");
    let circuit = CircuitBuilder::new(ir)
        .build::<Fp>()
        .with_witnesses(vec![
            Fp::from(1000), // sender_balance
            Fp::from(300),  // amount
            Fp::from(500),  // recipient_balance
        ])
        .expect("Failed to set witnesses");

    println!("  Circuit built successfully!");
    println!("  Witnesses: {}", circuit.num_witnesses());
    println!("  Public inputs: {}", circuit.num_public_inputs());
    println!();

    println!("STEP 5: Verify circuit constraints");
    println!("──────────────────────────────────");
    let k = 10;
    let public_inputs: Vec<Fp> = vec![];

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).expect("MockProver failed");
    prover.verify().expect("Circuit verification failed");

    println!("  MockProver: All constraints satisfied!");
    println!();

    println!("COMPILER PIPELINE COMPLETE");
    println!("══════════════════════════");
    println!("  Input:  Rust code with #[zk_private] annotations");
    println!("  Output: Verified halo2 zk-SNARK circuit");
    println!();
    println!("The ZeroStyl compiler transforms privacy-annotated Rust code");
    println!("into zero-knowledge circuits that can be verified on Arbitrum Stylus.");
    println!();
}
