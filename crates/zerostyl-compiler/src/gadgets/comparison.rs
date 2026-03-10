//! Comparison chip for proving ordering between field elements.
//!
//! Proves that `a > b`, `a >= b`, `a < b`, or `a <= b` by reducing each comparison
//! to a range check on the difference:
//!
//! - `a >= b  ⟺  a - b ∈ [0, 2^N)`
//! - `a > b   ⟺  a - b - 1 ∈ [0, 2^N)`
//! - `a < b   ⟺  b > a`
//! - `a <= b  ⟺  b >= a`
//!
//! The difference is constrained by a custom gate, then range-checked
//! using [`RangeProofChip`].
//!
//! # Preconditions
//!
//! Both operands **must** be pre-range-checked to `[0, 2^num_bits)` before
//! calling any comparison method. Without this guarantee, field arithmetic
//! wraps modulo `p` and the comparison is **unsound**. For example, if `a`
//! is actually `p - 1` (a valid field element), `a - b` overflows into a
//! small positive value, making the range check pass even though `a < b`
//! in the integer sense.

use super::range::{RangeProofChip, RangeProofConfig};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

/// Configuration for the comparison chip.
#[derive(Debug, Clone)]
pub struct ComparisonConfig {
    range_config: RangeProofConfig,
    left_col: Column<Advice>,
    right_col: Column<Advice>,
    diff_col: Column<Advice>,
    gte_selector: Selector,
    gt_selector: Selector,
}

/// Comparison chip: proves ordering relationships between field elements.
///
/// Uses [`RangeProofChip`] internally to range-check differences.
pub struct ComparisonChip {
    config: ComparisonConfig,
}

impl ComparisonChip {
    /// Configures the comparison chip.
    ///
    /// Allocates 3 advice columns for difference computation, 2 selectors
    /// for the `>=` and `>` gates, plus the columns required by [`RangeProofChip`].
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> ComparisonConfig {
        let range_config = RangeProofChip::configure(meta);

        let left_col = meta.advice_column();
        let right_col = meta.advice_column();
        let diff_col = meta.advice_column();
        meta.enable_equality(left_col);
        meta.enable_equality(right_col);
        meta.enable_equality(diff_col);

        let gte_selector = meta.selector();
        let gt_selector = meta.selector();

        // diff = left - right (for >=)
        meta.create_gate("comparison gte diff", |meta| {
            let s = meta.query_selector(gte_selector);
            let left = meta.query_advice(left_col, Rotation::cur());
            let right = meta.query_advice(right_col, Rotation::cur());
            let diff = meta.query_advice(diff_col, Rotation::cur());
            vec![s * (left - right - diff)]
        });

        // diff = left - right - 1 (for >)
        meta.create_gate("comparison gt diff", |meta| {
            let s = meta.query_selector(gt_selector);
            let left = meta.query_advice(left_col, Rotation::cur());
            let right = meta.query_advice(right_col, Rotation::cur());
            let diff = meta.query_advice(diff_col, Rotation::cur());
            vec![s * (left - right - Expression::Constant(Fp::one()) - diff)]
        });

        ComparisonConfig { range_config, left_col, right_col, diff_col, gte_selector, gt_selector }
    }

    /// Constructs the chip from configuration.
    #[must_use]
    pub fn construct(config: ComparisonConfig) -> Self {
        Self { config }
    }

    /// Proves that `left > right`.
    ///
    /// Constrains `left - right - 1 ∈ [0, 2^num_bits)`, which holds iff `left > right`
    /// (assuming both values and their difference fit in `num_bits` bits).
    ///
    /// # Preconditions
    ///
    /// Both `left` and `right` must be in `[0, 2^num_bits)`. The caller is
    /// responsible for range-checking both operands before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails.
    pub fn assert_gt(
        &self,
        mut layouter: impl Layouter<Fp>,
        left: AssignedCell<Fp, Fp>,
        right: AssignedCell<Fp, Fp>,
        num_bits: usize,
    ) -> Result<(), Error> {
        let diff = layouter.assign_region(
            || "compute left - right - 1",
            |mut region| {
                self.config.gt_selector.enable(&mut region, 0)?;
                left.copy_advice(|| "left", &mut region, self.config.left_col, 0)?;
                right.copy_advice(|| "right", &mut region, self.config.right_col, 0)?;
                let diff_val = left
                    .value()
                    .copied()
                    .zip(right.value().copied())
                    .map(|(l, r)| l - r - Fp::one());
                region.assign_advice(|| "diff", self.config.diff_col, 0, || diff_val)
            },
        )?;

        let range_chip = RangeProofChip::construct(self.config.range_config.clone());
        range_chip.check_range(layouter.namespace(|| "range check gt diff"), diff, num_bits)
    }

    /// Proves that `left >= right`.
    ///
    /// Constrains `left - right ∈ [0, 2^num_bits)`, which holds iff `left >= right`
    /// (assuming both values and their difference fit in `num_bits` bits).
    ///
    /// # Preconditions
    ///
    /// Both `left` and `right` must be in `[0, 2^num_bits)`. The caller is
    /// responsible for range-checking both operands before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails.
    pub fn assert_gte(
        &self,
        mut layouter: impl Layouter<Fp>,
        left: AssignedCell<Fp, Fp>,
        right: AssignedCell<Fp, Fp>,
        num_bits: usize,
    ) -> Result<(), Error> {
        let diff = layouter.assign_region(
            || "compute left - right",
            |mut region| {
                self.config.gte_selector.enable(&mut region, 0)?;
                left.copy_advice(|| "left", &mut region, self.config.left_col, 0)?;
                right.copy_advice(|| "right", &mut region, self.config.right_col, 0)?;
                let diff_val =
                    left.value().copied().zip(right.value().copied()).map(|(l, r)| l - r);
                region.assign_advice(|| "diff", self.config.diff_col, 0, || diff_val)
            },
        )?;

        let range_chip = RangeProofChip::construct(self.config.range_config.clone());
        range_chip.check_range(layouter.namespace(|| "range check gte diff"), diff, num_bits)
    }

    /// Proves that `left < right`.
    ///
    /// Equivalent to proving `right > left`.
    ///
    /// # Preconditions
    ///
    /// Both `left` and `right` must be in `[0, 2^num_bits)`. The caller is
    /// responsible for range-checking both operands before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails.
    pub fn assert_lt(
        &self,
        layouter: impl Layouter<Fp>,
        left: AssignedCell<Fp, Fp>,
        right: AssignedCell<Fp, Fp>,
        num_bits: usize,
    ) -> Result<(), Error> {
        self.assert_gt(layouter, right, left, num_bits)
    }

    /// Proves that `left <= right`.
    ///
    /// Equivalent to proving `right >= left`.
    ///
    /// # Preconditions
    ///
    /// Both `left` and `right` must be in `[0, 2^num_bits)`. The caller is
    /// responsible for range-checking both operands before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails.
    pub fn assert_lte(
        &self,
        layouter: impl Layouter<Fp>,
        left: AssignedCell<Fp, Fp>,
        right: AssignedCell<Fp, Fp>,
        num_bits: usize,
    ) -> Result<(), Error> {
        self.assert_gte(layouter, right, left, num_bits)
    }

    /// Loads a value into an advice cell.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the assignment fails.
    pub fn load_value(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "load comparison value",
            |mut region| {
                region.assign_advice(|| "comparison value", self.config.left_col, 0, || value)
            },
        )
    }

    /// Returns a reference to the chip configuration.
    #[must_use]
    pub fn config(&self) -> &ComparisonConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    #[derive(Clone)]
    enum ComparisonOp {
        Gt,
        Gte,
        Lt,
        Lte,
    }

    #[derive(Clone)]
    struct ComparisonTestCircuit {
        left: Value<Fp>,
        right: Value<Fp>,
        num_bits: usize,
        op: ComparisonOp,
    }

    impl Circuit<Fp> for ComparisonTestCircuit {
        type Config = ComparisonConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                left: Value::unknown(),
                right: Value::unknown(),
                num_bits: self.num_bits,
                op: self.op.clone(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> ComparisonConfig {
            ComparisonChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: ComparisonConfig,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = ComparisonChip::construct(config);
            let left_cell = chip.load_value(layouter.namespace(|| "load left"), self.left)?;
            let right_cell = chip.load_value(layouter.namespace(|| "load right"), self.right)?;
            match self.op {
                ComparisonOp::Gt => chip.assert_gt(
                    layouter.namespace(|| "gt"),
                    left_cell,
                    right_cell,
                    self.num_bits,
                ),
                ComparisonOp::Gte => chip.assert_gte(
                    layouter.namespace(|| "gte"),
                    left_cell,
                    right_cell,
                    self.num_bits,
                ),
                ComparisonOp::Lt => chip.assert_lt(
                    layouter.namespace(|| "lt"),
                    left_cell,
                    right_cell,
                    self.num_bits,
                ),
                ComparisonOp::Lte => chip.assert_lte(
                    layouter.namespace(|| "lte"),
                    left_cell,
                    right_cell,
                    self.num_bits,
                ),
            }
        }
    }

    fn run_comparison(left: u64, right: u64, num_bits: usize, op: ComparisonOp) -> bool {
        let circuit = ComparisonTestCircuit {
            left: Value::known(Fp::from(left)),
            right: Value::known(Fp::from(right)),
            num_bits,
            op,
        };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.verify().is_ok()
    }

    // --- Greater than ---

    #[test]
    fn test_gt_valid() {
        assert!(run_comparison(100, 50, 64, ComparisonOp::Gt));
    }

    #[test]
    fn test_gt_equal_rejected() {
        assert!(!run_comparison(100, 100, 64, ComparisonOp::Gt));
    }

    #[test]
    fn test_gt_less_rejected() {
        assert!(!run_comparison(50, 100, 64, ComparisonOp::Gt));
    }

    #[test]
    fn test_gt_by_one() {
        assert!(run_comparison(1, 0, 64, ComparisonOp::Gt));
    }

    #[test]
    fn test_gt_large_values() {
        assert!(run_comparison(u64::MAX, u64::MAX - 1, 64, ComparisonOp::Gt));
    }

    // --- Greater than or equal ---

    #[test]
    fn test_gte_valid() {
        assert!(run_comparison(100, 50, 64, ComparisonOp::Gte));
    }

    #[test]
    fn test_gte_equal_valid() {
        assert!(run_comparison(100, 100, 64, ComparisonOp::Gte));
    }

    #[test]
    fn test_gte_less_rejected() {
        assert!(!run_comparison(50, 100, 64, ComparisonOp::Gte));
    }

    #[test]
    fn test_gte_zero() {
        assert!(run_comparison(0, 0, 64, ComparisonOp::Gte));
    }

    // --- Less than ---

    #[test]
    fn test_lt_valid() {
        assert!(run_comparison(50, 100, 64, ComparisonOp::Lt));
    }

    #[test]
    fn test_lt_equal_rejected() {
        assert!(!run_comparison(100, 100, 64, ComparisonOp::Lt));
    }

    #[test]
    fn test_lt_greater_rejected() {
        assert!(!run_comparison(100, 50, 64, ComparisonOp::Lt));
    }

    // --- Less than or equal ---

    #[test]
    fn test_lte_valid() {
        assert!(run_comparison(50, 100, 64, ComparisonOp::Lte));
    }

    #[test]
    fn test_lte_equal_valid() {
        assert!(run_comparison(100, 100, 64, ComparisonOp::Lte));
    }

    #[test]
    fn test_lte_greater_rejected() {
        assert!(!run_comparison(100, 50, 64, ComparisonOp::Lte));
    }
}
