// Read as text by the exporter's sync test, never compiled — no proc-macro is
// registered for `#[zk_private]` on fn params in this crate.

pub fn deposit(
    #[zk_private(
        commit = "poseidon",
        range = "0..1000000",
        constraint = "value >= threshold"
    )]
    collateral: u64,
    threshold: u64,
) -> bool {
    let _ = (collateral, threshold);
    true
}
