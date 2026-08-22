//! Range proof chip via bit decomposition.
//!
//! Proves that a value lies within `[0, 2^num_bits)` by decomposing it into individual bits
//! and constraining each bit to be boolean. Supports configurable bit widths: 8, 16, 32, 64.
//!
//! # How it works
//!
//! For a value `v` with `num_bits = N`:
//! 1. Decompose `v` into bits `b_0, b_1, ..., b_{N-1}`
//! 2. Constrain each bit: `b_i * (1 - b_i) = 0` (boolean)
//! 3. Constrain reconstruction: `sum(b_i * 2^i) = v`
//!
//! For bounded range `[min, max]`:
//! - Prove `v - min ∈ [0, 2^N)` AND `max - v ∈ [0, 2^N)`

#[cfg(not(test))]
use alloc::{format, vec, vec::Vec};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use halo2curves::ff::{Field, PrimeField};

/// Configuration for the range proof chip.
#[derive(Debug, Clone)]
pub struct RangeProofConfig {
    value_col: Column<Advice>,
    bits_col: Column<Advice>,
    bool_selector: Selector,
    recompose_selector: Selector,
    init_selector: Selector,
    bounded_diff_selector: Selector,
    bounded_diff_reverse_selector: Selector,
    fixed_col: Column<Fixed>,
}

/// Range proof chip: proves `value ∈ [0, 2^num_bits)` via bit decomposition.
pub struct RangeProofChip {
    config: RangeProofConfig,
}

impl RangeProofChip {
    /// Configures the range proof chip.
    ///
    /// Allocates 2 advice columns and 2 selectors for boolean and recomposition gates.
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> RangeProofConfig {
        let value_col = meta.advice_column();
        let bits_col = meta.advice_column();
        meta.enable_equality(value_col);
        meta.enable_equality(bits_col);

        let bool_selector = meta.selector();
        let recompose_selector = meta.selector();
        let init_selector = meta.selector();
        let bounded_diff_selector = meta.selector();
        let bounded_diff_reverse_selector = meta.selector();
        let fixed_col = meta.fixed_column();

        // Boolean constraint: bit * (1 - bit) == 0
        meta.create_gate("range bit boolean", |meta| {
            let s = meta.query_selector(bool_selector);
            let bit = meta.query_advice(bits_col, Rotation::cur());
            vec![s * (bit.clone() * (halo2_proofs::plonk::Expression::Constant(Fr::ONE) - bit))]
        });

        // Recomposition constraint: accumulated - value == 0
        // We use value_col[cur] for the running accumulator and bits_col[cur] for the current bit.
        // accumulated_new = accumulated_old * 2 + bit
        // At the end, accumulated == value
        meta.create_gate("range recompose", |meta| {
            let s = meta.query_selector(recompose_selector);
            let acc_prev = meta.query_advice(value_col, Rotation::cur());
            let acc_next = meta.query_advice(value_col, Rotation::next());
            let bit = meta.query_advice(bits_col, Rotation::cur());
            // acc_next = acc_prev * 2 + bit
            vec![
                s * (acc_next
                    - (acc_prev * halo2_proofs::plonk::Expression::Constant(Fr::from(2u64)) + bit)),
            ]
        });

        // Initial accumulator constraint: the running accumulator on row 0 must be zero.
        // Without this, a malicious prover could assign a non-zero `acc_init` and, since the
        // recompose gate only links consecutive rows, make the final accumulator equal any
        // value while still satisfying `acc_final == value`. That would let arbitrary field
        // elements pass the range check. Pinning row 0 to zero closes that soundness hole.
        meta.create_gate("range init zero", |meta| {
            let s = meta.query_selector(init_selector);
            let acc_init = meta.query_advice(value_col, Rotation::cur());
            vec![s * acc_init]
        });

        // Bounded diff constraint: value - constant - diff == 0
        // Used for: diff = value - min (proving value >= min)
        meta.create_gate("bounded diff", |meta| {
            let s = meta.query_selector(bounded_diff_selector);
            let value = meta.query_advice(value_col, Rotation::cur());
            let constant = meta.query_fixed(fixed_col, Rotation::cur());
            let diff = meta.query_advice(bits_col, Rotation::cur());
            vec![s * (value - constant - diff)]
        });

        // Bounded diff reverse constraint: constant - value - diff == 0
        // Used for: diff = max - value (proving value <= max)
        meta.create_gate("bounded diff reverse", |meta| {
            let s = meta.query_selector(bounded_diff_reverse_selector);
            let value = meta.query_advice(value_col, Rotation::cur());
            let constant = meta.query_fixed(fixed_col, Rotation::cur());
            let diff = meta.query_advice(bits_col, Rotation::cur());
            vec![s * (constant - value - diff)]
        });

        RangeProofConfig {
            value_col,
            bits_col,
            bool_selector,
            recompose_selector,
            init_selector,
            bounded_diff_selector,
            bounded_diff_reverse_selector,
            fixed_col,
        }
    }

    /// Constructs the chip from configuration.
    #[must_use]
    pub fn construct(config: RangeProofConfig) -> Self {
        Self { config }
    }

    /// Proves that `value ∈ [0, 2^num_bits)`.
    ///
    /// Decomposes the value into `num_bits` bits (MSB first), constrains each to be boolean,
    /// and constrains the recomposition to equal the original value.
    ///
    /// # Arguments
    ///
    /// * `value` — The value to range-check (already assigned)
    /// * `num_bits` — Number of bits (8, 16, 32, or 64)
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails.
    pub fn check_range(
        &self,
        mut layouter: impl Layouter<Fr>,
        value: AssignedCell<Fr, Fr>,
        num_bits: usize,
    ) -> Result<(), Error> {
        if num_bits == 0 || num_bits > 64 {
            return Err(Error::Synthesis);
        }
        layouter.assign_region(
            || format!("range check {} bits", num_bits),
            |mut region| {
                // Extract the value for bit decomposition (MSB first)
                let value_fp = value.value().copied();

                // Row 0: initial accumulator = 0, pinned by the "range init zero" gate so a
                // malicious prover cannot seed the accumulator with a non-zero offset.
                self.config.init_selector.enable(&mut region, 0)?;
                region.assign_advice(
                    || "acc init",
                    self.config.value_col,
                    0,
                    || Value::known(Fr::ZERO),
                )?;

                // Decompose into bits (MSB to LSB)
                let bits: Vec<Value<Fr>> = (0..num_bits)
                    .rev()
                    .map(|i| {
                        value_fp.map(|v| {
                            let v_bytes = v.to_repr();
                            let byte_idx = i / 8;
                            let bit_idx = i % 8;
                            if byte_idx < v_bytes.as_ref().len()
                                && (v_bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1
                            {
                                Fr::ONE
                            } else {
                                Fr::ZERO
                            }
                        })
                    })
                    .collect();

                // Assign bits and accumulators
                let mut acc = Value::known(Fr::ZERO);
                let mut last_acc_cell = None;
                for (row, bit_val) in bits.iter().enumerate() {
                    self.config.bool_selector.enable(&mut region, row)?;
                    self.config.recompose_selector.enable(&mut region, row)?;

                    region.assign_advice(
                        || format!("bit {}", row),
                        self.config.bits_col,
                        row,
                        || *bit_val,
                    )?;

                    acc = acc.zip(*bit_val).map(|(a, b)| a * Fr::from(2u64) + b);

                    last_acc_cell = Some(region.assign_advice(
                        || format!("acc {}", row + 1),
                        self.config.value_col,
                        row + 1,
                        || acc,
                    )?);
                }

                // Copy the original value into this region and constrain equal to final acc
                let value_copy = value.copy_advice(
                    || "original value",
                    &mut region,
                    self.config.bits_col,
                    num_bits,
                )?;

                region.constrain_equal(last_acc_cell.unwrap().cell(), value_copy.cell())?;

                Ok(())
            },
        )
    }

    /// Proves that `value ∈ [min, max]`.
    ///
    /// Works by proving:
    /// - `value - min ∈ [0, 2^num_bits)` (value >= min)
    /// - `max - value ∈ [0, 2^num_bits)` (value <= max)
    ///
    /// The caller must ensure that `max - min < 2^num_bits`.
    ///
    /// # Arguments
    ///
    /// * `value` — The value to bound-check (already assigned)
    /// * `min` — Minimum bound (inclusive)
    /// * `max` — Maximum bound (inclusive)
    /// * `num_bits` — Number of bits for the range check
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails.
    pub fn check_range_bounded(
        &self,
        mut layouter: impl Layouter<Fr>,
        value: AssignedCell<Fr, Fr>,
        min: Fr,
        max: Fr,
        num_bits: usize,
    ) -> Result<(), Error> {
        // value_minus_min = value - min (constrained by "bounded diff" gate)
        let value_minus_min = layouter.assign_region(
            || "compute value - min",
            |mut region| {
                self.config.bounded_diff_selector.enable(&mut region, 0)?;
                let v = value.copy_advice(|| "value", &mut region, self.config.value_col, 0)?;
                region.assign_fixed(
                    || "min constant",
                    self.config.fixed_col,
                    0,
                    || Value::known(min),
                )?;
                let diff_val = v.value().copied().map(|v| v - min);
                region.assign_advice(|| "value - min", self.config.bits_col, 0, || diff_val)
            },
        )?;

        // max_minus_value = max - value (constrained by "bounded diff reverse" gate)
        let max_minus_value = layouter.assign_region(
            || "compute max - value",
            |mut region| {
                self.config.bounded_diff_reverse_selector.enable(&mut region, 0)?;
                let v = value.copy_advice(|| "value", &mut region, self.config.value_col, 0)?;
                region.assign_fixed(
                    || "max constant",
                    self.config.fixed_col,
                    0,
                    || Value::known(max),
                )?;
                let diff_val = v.value().copied().map(|v| max - v);
                region.assign_advice(|| "max - value", self.config.bits_col, 0, || diff_val)
            },
        )?;

        // Range check both differences
        self.check_range(
            layouter.namespace(|| "range check value - min"),
            value_minus_min,
            num_bits,
        )?;

        self.check_range(
            layouter.namespace(|| "range check max - value"),
            max_minus_value,
            num_bits,
        )?;

        Ok(())
    }

    /// Loads a value into an advice cell.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the assignment fails.
    pub fn load_value(
        &self,
        mut layouter: impl Layouter<Fr>,
        value: Value<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "load range value",
            |mut region| region.assign_advice(|| "range value", self.config.value_col, 0, || value),
        )
    }

    /// Returns a reference to the chip configuration.
    #[must_use]
    pub fn config(&self) -> &RangeProofConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    #[derive(Clone)]
    struct RangeTestCircuit {
        value: Value<Fr>,
        num_bits: usize,
    }

    impl Circuit<Fr> for RangeTestCircuit {
        type Config = RangeProofConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { value: Value::unknown(), num_bits: self.num_bits }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> RangeProofConfig {
            RangeProofChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: RangeProofConfig,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = RangeProofChip::construct(config);
            let value_cell = chip.load_value(layouter.namespace(|| "load value"), self.value)?;
            chip.check_range(layouter.namespace(|| "range check"), value_cell, self.num_bits)
        }
    }

    #[derive(Clone)]
    struct BoundedRangeTestCircuit {
        value: Value<Fr>,
        min: Fr,
        max: Fr,
        num_bits: usize,
    }

    impl Circuit<Fr> for BoundedRangeTestCircuit {
        type Config = RangeProofConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { value: Value::unknown(), min: self.min, max: self.max, num_bits: self.num_bits }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> RangeProofConfig {
            RangeProofChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: RangeProofConfig,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = RangeProofChip::construct(config);
            let value_cell = chip.load_value(layouter.namespace(|| "load value"), self.value)?;
            chip.check_range_bounded(
                layouter.namespace(|| "bounded range check"),
                value_cell,
                self.min,
                self.max,
                self.num_bits,
            )
        }
    }

    #[test]
    fn test_range_8bit_valid() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::from(255u64)), num_bits: 8 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_range_8bit_zero() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::ZERO), num_bits: 8 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_range_8bit_overflow_rejected() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::from(256u64)), num_bits: 8 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_range_16bit_valid() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::from(65535u64)), num_bits: 16 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_range_32bit_valid() {
        let circuit =
            RangeTestCircuit { value: Value::known(Fr::from(u32::MAX as u64)), num_bits: 32 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_range_64bit_valid() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::from(u64::MAX)), num_bits: 64 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_range_64bit_large_value() {
        let circuit =
            RangeTestCircuit { value: Value::known(Fr::from(1_000_000_000_000u64)), num_bits: 64 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_bounded_range_valid() {
        let circuit = BoundedRangeTestCircuit {
            value: Value::known(Fr::from(200u64)),
            min: Fr::from(150u64),
            max: Fr::from(300u64),
            num_bits: 16,
        };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_bounded_range_at_min() {
        let circuit = BoundedRangeTestCircuit {
            value: Value::known(Fr::from(150u64)),
            min: Fr::from(150u64),
            max: Fr::from(300u64),
            num_bits: 16,
        };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_bounded_range_at_max() {
        let circuit = BoundedRangeTestCircuit {
            value: Value::known(Fr::from(300u64)),
            min: Fr::from(150u64),
            max: Fr::from(300u64),
            num_bits: 16,
        };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_bounded_range_below_min_rejected() {
        let circuit = BoundedRangeTestCircuit {
            value: Value::known(Fr::from(149u64)),
            min: Fr::from(150u64),
            max: Fr::from(300u64),
            num_bits: 16,
        };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_bounded_range_above_max_rejected() {
        let circuit = BoundedRangeTestCircuit {
            value: Value::known(Fr::from(301u64)),
            min: Fr::from(150u64),
            max: Fr::from(300u64),
            num_bits: 16,
        };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    // FINAL-N2: check_range validates num_bits parameter
    #[test]
    fn test_check_range_zero_bits_returns_error() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::from(0u64)), num_bits: 0 };
        let k = 10;
        let result = MockProver::run(k, &circuit, vec![]);
        assert!(result.is_err(), "check_range(0 bits) must return Err, not panic");
    }

    #[test]
    fn test_check_range_too_many_bits_returns_error() {
        let circuit = RangeTestCircuit { value: Value::known(Fr::from(42u64)), num_bits: 65 };
        let k = 10;
        let result = MockProver::run(k, &circuit, vec![]);
        assert!(result.is_err(), "check_range(65 bits) must return Err");
    }

    /// Adversarial circuit that replicates the range-check region layout but seeds the running
    /// accumulator on row 0 with a non-zero value. It picks `acc_init` so that the honest
    /// boolean bit witnesses of `value`'s low `num_bits` bits still recompose to `value` at the
    /// end (`acc_init * 2^num_bits + low_bits == value`). Before the "range init zero" gate was
    /// added, this let any out-of-range field element satisfy the range check. Used to lock in
    /// the soundness fix.
    #[derive(Clone)]
    struct ForgedAccInitCircuit {
        value: Fr,
        num_bits: usize,
    }

    impl Circuit<Fr> for ForgedAccInitCircuit {
        type Config = RangeProofConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { value: self.value, num_bits: self.num_bits }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> RangeProofConfig {
            RangeProofChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: RangeProofConfig,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "forged range check",
                |mut region| {
                    let n = self.num_bits;
                    let repr = self.value.to_repr();
                    let low_bits: Vec<u64> =
                        (0..n).map(|i| u64::from((repr.as_ref()[i / 8] >> (i % 8)) & 1)).collect();
                    let low_val: Fr = low_bits.iter().enumerate().fold(Fr::ZERO, |acc, (i, b)| {
                        acc + Fr::from(*b) * Fr::from(2u64).pow([i as u64])
                    });
                    // acc_init = (value - low_val) / 2^n  ⇒  acc_final == value.
                    let pow = Fr::from(2u64).pow([n as u64]);
                    let acc_init = (self.value - low_val) * pow.invert().unwrap();

                    config.init_selector.enable(&mut region, 0)?;
                    region.assign_advice(
                        || "forged acc init",
                        config.value_col,
                        0,
                        || Value::known(acc_init),
                    )?;

                    let mut acc = acc_init;
                    let mut last = None;
                    for (row, i) in (0..n).rev().enumerate() {
                        config.bool_selector.enable(&mut region, row)?;
                        config.recompose_selector.enable(&mut region, row)?;
                        let bit = Fr::from(low_bits[i]);
                        region.assign_advice(
                            || "bit",
                            config.bits_col,
                            row,
                            || Value::known(bit),
                        )?;
                        acc = acc * Fr::from(2u64) + bit;
                        last = Some(region.assign_advice(
                            || "acc",
                            config.value_col,
                            row + 1,
                            || Value::known(acc),
                        )?);
                    }

                    let value_cell = region.assign_advice(
                        || "value",
                        config.bits_col,
                        n,
                        || Value::known(self.value),
                    )?;
                    region.constrain_equal(last.unwrap().cell(), value_cell.cell())?;
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_forged_acc_init_out_of_range_rejected() {
        // 256 is out of [0, 2^8); the forged accumulator seed makes recomposition + boolean
        // gates pass, so only the "range init zero" gate can catch it.
        let circuit = ForgedAccInitCircuit { value: Fr::from(256u64), num_bits: 8 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "forged non-zero acc_init must be rejected by the range init gate"
        );
    }

    #[test]
    fn test_forged_acc_init_large_value_rejected() {
        // A far out-of-range value (2^40 into an 8-bit check) must also be rejected.
        let circuit = ForgedAccInitCircuit { value: Fr::from(1u64 << 40), num_bits: 8 };
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "forged acc_init must be rejected for large values");
    }
}
