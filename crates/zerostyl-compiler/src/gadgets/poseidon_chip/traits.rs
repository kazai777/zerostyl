// Vendored from zcash/halo2 (halo2_gadgets/src/poseidon.rs and utilities.rs),
// MIT OR Apache-2.0. The upstream crate halo2_gadgets v0.3.1/0.4.0 doesn't
// compile against the PSE halo2_proofs fork (`meta.lookup` signature diverges
// in sinsemilla/ecc modules), and has no feature to skip those modules. So we
// vendor only the Poseidon-chip-related infrastructure we actually need.

use std::fmt;

use halo2_poseidon::{Absorbing, Domain, Spec, Squeezing, State};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Chip, Layouter, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2curves::group::ff::Field;

pub trait Var<F: Field>: Clone + fmt::Debug + From<AssignedCell<F, F>> {
    fn cell(&self) -> Cell;
    fn value(&self) -> Value<F>;
}

impl<F: Field> Var<F> for AssignedCell<F, F> {
    fn cell(&self) -> Cell {
        AssignedCell::cell(self)
    }

    fn value(&self) -> Value<F> {
        self.value().cloned()
    }
}

#[derive(Clone, Debug)]
pub enum PaddedWord<F: Field> {
    Message(AssignedCell<F, F>),
    Padding(F),
}

pub trait PermuteChip<F: Field, S: Spec<F, T, RATE>, const T: usize, const RATE: usize>:
    Chip<F> + Clone + fmt::Debug + PoseidonInstructions<F, S, T, RATE>
{
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config;
    fn construct(config: Self::Config) -> Self;
}

pub trait PoseidonInstructions<F: Field, S: Spec<F, T, RATE>, const T: usize, const RATE: usize>:
    Chip<F>
{
    type Word: Clone
        + fmt::Debug
        + From<AssignedCell<F, F>>
        + Into<AssignedCell<F, F>>
        + Send
        + Sync;

    fn permute(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, T>,
    ) -> Result<State<Self::Word, T>, Error>;
}

pub trait PoseidonSpongeInstructions<
    F: Field,
    S: Spec<F, T, RATE>,
    D: Domain<F, RATE>,
    const T: usize,
    const RATE: usize,
>: PoseidonInstructions<F, S, T, RATE>
{
    fn initial_state(&self, layouter: &mut impl Layouter<F>)
        -> Result<State<Self::Word, T>, Error>;

    fn add_input(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, T>,
        input: &Absorbing<PaddedWord<F>, RATE>,
    ) -> Result<State<Self::Word, T>, Error>;

    fn get_output(state: &State<Self::Word, T>) -> Squeezing<Self::Word, RATE>;
}
