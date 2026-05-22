// Vendored from halo2_gadgets v0.3.1 (hash.rs) and poseidon-circuit (pow5.rs)
// to support PSE halo2 + BN254 with 57 (odd) partial_rounds. Treated as a
// frozen upstream; lints are silenced rather than chasing style drift.
#[allow(clippy::all, dead_code)]
mod hash;
#[allow(clippy::all, dead_code)]
mod pow5;
mod traits;

pub use hash::{Hash, Sponge, Word};
pub use pow5::{Pow5Chip, Pow5Config, StateWord};
pub use traits::{PaddedWord, PermuteChip, PoseidonInstructions, PoseidonSpongeInstructions, Var};
