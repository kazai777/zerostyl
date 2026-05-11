use anyhow::Result;
use zerostyl_circuits::Registry;

fn main() -> Result<()> {
    let registry = Registry::new();
    for d in [
        example_demo::descriptor(),
        state_mask::descriptor(),
        tx_privacy::descriptor(),
        private_vote::descriptor(),
    ] {
        registry.register(d).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    zerostyl_cli::run(&registry)
}
