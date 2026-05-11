use anyhow::Result;
use zerostyl_circuits::{register_circuit, Registry};

fn main() -> Result<()> {
    let registry = Registry::new();
    register_circuit!(registry, example_demo)?;
    register_circuit!(registry, state_mask)?;
    register_circuit!(registry, tx_privacy)?;
    register_circuit!(registry, private_vote)?;
    zerostyl_cli::run(&registry)
}
