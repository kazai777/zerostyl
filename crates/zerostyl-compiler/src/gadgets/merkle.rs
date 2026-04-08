//! Poseidon-based Merkle tree membership proof chip.
//!
//! Verifies that a leaf belongs to a Merkle tree by hashing up the path
//! from leaf to root using Poseidon. Each level computes:
//!
//! ```text
//! node = Poseidon(left, right)
//! ```
//!
//! where `(left, right)` is determined by the path index bit at that level.
//! Supports configurable depth (default 32, matching Tornado Cash / Semaphore).

use super::poseidon_commitment::{PoseidonCommitmentChip, PoseidonCommitmentConfig};
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

/// Configuration for the Merkle tree chip.
///
/// Wraps a [`PoseidonCommitmentConfig`] and adds columns/selectors
/// for the swap logic (choosing left/right child based on path index).
#[derive(Debug, Clone)]
pub struct MerkleTreeConfig {
    poseidon_config: PoseidonCommitmentConfig,
    swap_selector: Selector,
    swap_advice: Column<Advice>,
}

impl MerkleTreeConfig {
    /// Returns the underlying Poseidon config.
    #[must_use]
    pub fn poseidon_config(&self) -> &PoseidonCommitmentConfig {
        &self.poseidon_config
    }
}

/// Poseidon-based Merkle tree membership proof chip.
///
/// Verifies a Merkle path from leaf to root. For each level `i`:
/// 1. If `path_index[i] == 0`: `node = Poseidon(current, sibling[i])`
/// 2. If `path_index[i] == 1`: `node = Poseidon(sibling[i], current)`
///
/// The path index bit is constrained to be boolean.
pub struct MerkleTreeChip {
    config: MerkleTreeConfig,
}

impl MerkleTreeChip {
    /// Configures the Merkle tree chip.
    ///
    /// Allocates the Poseidon columns plus one extra advice column and selector
    /// for the swap logic.
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> MerkleTreeConfig {
        let poseidon_config = PoseidonCommitmentChip::configure(meta);
        let swap_advice = meta.advice_column();
        meta.enable_equality(swap_advice);
        let swap_selector = meta.selector();

        let state = poseidon_config.state_columns();
        let state_0 = state[0];
        let state_1 = state[1];

        // Boolean constraint: index * (1 - index) == 0
        meta.create_gate("merkle path index boolean", |meta| {
            let s = meta.query_selector(swap_selector);
            let index = meta.query_advice(swap_advice, Rotation::cur());
            vec![s * (index.clone() * (Expression::Constant(Fp::one()) - index))]
        });

        // Swap constraint left: if index=0 then left=current, if index=1 then left=sibling
        // (1 - index) * (left - current) + index * (left - sibling) == 0
        meta.create_gate("merkle swap left", |meta| {
            let s = meta.query_selector(swap_selector);
            let index = meta.query_advice(swap_advice, Rotation::cur());
            let current = meta.query_advice(state_0, Rotation::cur());
            let sibling = meta.query_advice(state_1, Rotation::cur());
            let left = meta.query_advice(state_0, Rotation::next());
            let one = Expression::Constant(Fp::one());
            vec![
                s * ((one.clone() - index.clone()) * (left.clone() - current)
                    + index * (left - sibling)),
            ]
        });

        // Swap constraint right: if index=0 then right=sibling, if index=1 then right=current
        // (1 - index) * (right - sibling) + index * (right - current) == 0
        meta.create_gate("merkle swap right", |meta| {
            let s = meta.query_selector(swap_selector);
            let index = meta.query_advice(swap_advice, Rotation::cur());
            let current = meta.query_advice(state_0, Rotation::cur());
            let sibling = meta.query_advice(state_1, Rotation::cur());
            let right = meta.query_advice(state_1, Rotation::next());
            let one = Expression::Constant(Fp::one());
            vec![
                s * ((one.clone() - index.clone()) * (right.clone() - sibling)
                    + index * (right - current)),
            ]
        });

        MerkleTreeConfig { poseidon_config, swap_selector, swap_advice }
    }

    /// Constructs the chip from configuration.
    #[must_use]
    pub fn construct(config: MerkleTreeConfig) -> Self {
        Self { config }
    }

    /// Verifies a Merkle path and returns the computed root.
    ///
    /// # Arguments
    ///
    /// * `leaf` — The leaf value (already assigned)
    /// * `siblings` — Sibling hashes at each level (bottom to top)
    /// * `path_indices` — Path direction at each level (0 = left, 1 = right)
    ///
    /// The depth is determined by `siblings.len()`, which must equal `path_indices.len()`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if synthesis fails or if the path lengths don't match.
    pub fn verify_membership(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf: AssignedCell<Fp, Fp>,
        siblings: &[AssignedCell<Fp, Fp>],
        path_indices: &[AssignedCell<Fp, Fp>],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        if siblings.len() != path_indices.len() {
            return Err(Error::Synthesis);
        }

        let poseidon_chip = PoseidonCommitmentChip::construct(self.config.poseidon_config.clone());
        let mut current = leaf;

        for (i, (sibling, index)) in siblings.iter().zip(path_indices.iter()).enumerate() {
            // Combined boolean check + constrained swap in a single region.
            // Row 0: current (state[0]), sibling (state[1]), index (swap_advice)
            // Row 1: left (state[0]), right (state[1])
            // Gates enforce:
            //   - index * (1 - index) == 0  (boolean)
            //   - (1-index)*(left-current) + index*(left-sibling) == 0  (swap left)
            //   - (1-index)*(right-sibling) + index*(right-current) == 0  (swap right)
            let (left, right) = layouter.assign_region(
                || format!("merkle swap level {}", i),
                |mut region| {
                    let state = self.config.poseidon_config.state_columns();

                    // Enable boolean + swap constraints at row 0 (single selector)
                    self.config.swap_selector.enable(&mut region, 0)?;

                    // Row 0: copy current, sibling, and index
                    current.copy_advice(|| "current node", &mut region, state[0], 0)?;
                    sibling.copy_advice(|| "sibling", &mut region, state[1], 0)?;
                    index.copy_advice(|| "path index", &mut region, self.config.swap_advice, 0)?;

                    // Compute swapped values
                    let index_val = index.value().copied();
                    let current_val = current.value().copied();
                    let sibling_val = sibling.value().copied();

                    let left_val = index_val
                        .zip(current_val)
                        .zip(sibling_val)
                        .map(|((idx, cur), sib)| if idx == Fp::zero() { cur } else { sib });

                    let right_val = index_val
                        .zip(current_val)
                        .zip(sibling_val)
                        .map(|((idx, cur), sib)| if idx == Fp::zero() { sib } else { cur });

                    // Row 1: assign left and right (constrained by swap gates)
                    let left_cell =
                        region.assign_advice(|| "left input", state[0], 1, || left_val)?;
                    let right_cell =
                        region.assign_advice(|| "right input", state[1], 1, || right_val)?;

                    Ok((left_cell, right_cell))
                },
            )?;

            current = poseidon_chip.hash_two(
                layouter.namespace(|| format!("merkle hash level {}", i)),
                left,
                right,
            )?;
        }

        Ok(current)
    }

    /// Loads a sibling value into an advice cell.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the assignment fails.
    pub fn load_sibling(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "load sibling",
            |mut region| {
                region.assign_advice(
                    || "sibling value",
                    self.config.poseidon_config.state_columns()[2],
                    0,
                    || value,
                )
            },
        )
    }

    /// Loads a path index (0 or 1) into an advice cell.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the assignment fails.
    pub fn load_path_index(
        &self,
        mut layouter: impl Layouter<Fp>,
        index: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "load path index",
            |mut region| {
                region.assign_advice(|| "path index value", self.config.swap_advice, 0, || index)
            },
        )
    }

    /// Computes the Merkle root outside the circuit (for witness generation).
    ///
    /// # Arguments
    ///
    /// * `leaf` — Leaf value
    /// * `siblings` — Sibling hashes (bottom to top)
    /// * `indices` — Path directions (false = left child, true = right child)
    #[must_use]
    pub fn compute_root_outside_circuit(leaf: Fp, siblings: &[Fp], indices: &[bool]) -> Fp {
        assert_eq!(siblings.len(), indices.len());
        let mut current = leaf;
        for (sibling, &is_right) in siblings.iter().zip(indices.iter()) {
            let (left, right) = if is_right { (*sibling, current) } else { (current, *sibling) };
            current = poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
                .hash([left, right]);
        }
        current
    }

    /// Returns a reference to the chip configuration.
    #[must_use]
    pub fn config(&self) -> &MerkleTreeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, Instance},
    };

    const TEST_DEPTH: usize = 4;

    #[derive(Clone)]
    struct MerkleTestCircuit {
        leaf: Value<Fp>,
        siblings: Vec<Value<Fp>>,
        path_indices: Vec<Value<Fp>>,
    }

    #[derive(Debug, Clone)]
    struct MerkleTestConfig {
        merkle: MerkleTreeConfig,
        instance: Column<Instance>,
    }

    impl Circuit<Fp> for MerkleTestCircuit {
        type Config = MerkleTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                leaf: Value::unknown(),
                siblings: vec![Value::unknown(); self.siblings.len()],
                path_indices: vec![Value::unknown(); self.path_indices.len()],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> MerkleTestConfig {
            let merkle = MerkleTreeChip::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);

            MerkleTestConfig { merkle, instance }
        }

        fn synthesize(
            &self,
            config: MerkleTestConfig,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = MerkleTreeChip::construct(config.merkle.clone());
            let poseidon_chip =
                PoseidonCommitmentChip::construct(config.merkle.poseidon_config().clone());

            let leaf_cell =
                poseidon_chip.load_private(layouter.namespace(|| "load leaf"), self.leaf, 0)?;

            let sibling_cells: Vec<AssignedCell<Fp, Fp>> = self
                .siblings
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    chip.load_sibling(layouter.namespace(|| format!("load sibling {}", i)), *s)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let index_cells: Vec<AssignedCell<Fp, Fp>> = self
                .path_indices
                .iter()
                .enumerate()
                .map(|(i, idx)| {
                    chip.load_path_index(layouter.namespace(|| format!("load index {}", i)), *idx)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let computed_root = chip.verify_membership(
                layouter.namespace(|| "merkle verify"),
                leaf_cell,
                &sibling_cells,
                &index_cells,
            )?;

            layouter.constrain_instance(computed_root.cell(), config.instance, 0)?;

            Ok(())
        }
    }

    fn make_test_data(depth: usize) -> (Fp, Vec<Fp>, Vec<bool>, Fp) {
        let leaf = Fp::from(42u64);
        let siblings: Vec<Fp> = (0..depth).map(|i| Fp::from((i + 100) as u64)).collect();
        let indices: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();
        let root = MerkleTreeChip::compute_root_outside_circuit(leaf, &siblings, &indices);
        (leaf, siblings, indices, root)
    }

    #[test]
    fn test_merkle_valid_path_depth_4() {
        let (leaf, siblings, indices, expected_root) = make_test_data(TEST_DEPTH);

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![vec![expected_root]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_merkle_wrong_root_rejected() {
        let (leaf, siblings, indices, _) = make_test_data(TEST_DEPTH);
        let wrong_root = Fp::from(999u64);

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![vec![wrong_root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_merkle_modified_sibling_rejected() {
        let (leaf, mut siblings, indices, expected_root) = make_test_data(TEST_DEPTH);
        siblings[1] = Fp::from(999u64); // Tamper with sibling

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![vec![expected_root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_merkle_depth_1() {
        let (leaf, siblings, indices, root) = make_test_data(1);

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![vec![root]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_merkle_depth_32() {
        let (leaf, siblings, indices, root) = make_test_data(32);

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        let k = 14; // Needs more rows for 32 levels of Poseidon
        let prover = MockProver::run(k, &circuit, vec![vec![root]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_merkle_non_boolean_index_rejected() {
        let (leaf, siblings, indices, root) = make_test_data(TEST_DEPTH);

        let mut fp_indices: Vec<Value<Fp>> =
            indices.iter().map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() })).collect();
        fp_indices[0] = Value::known(Fp::from(2u64)); // Not boolean!

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: fp_indices,
        };

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_compute_root_outside_circuit_deterministic() {
        let (leaf, siblings, indices, root1) = make_test_data(TEST_DEPTH);
        let root2 = MerkleTreeChip::compute_root_outside_circuit(leaf, &siblings, &indices);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_adversarial_swap_rejected() {
        let (leaf, siblings, indices, expected_root) = make_test_data(TEST_DEPTH);

        // Flip the first path index (0 → 1)
        let mut tampered_indices = indices.clone();
        tampered_indices[0] = !tampered_indices[0];

        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: tampered_indices
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        // Use the original root — the tampered path should produce a different root
        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![vec![expected_root]]).unwrap();
        assert!(prover.verify().is_err(), "Circuit must reject when path index is flipped");
    }

    #[test]
    fn test_merkle_mismatched_lengths_returns_error() {
        let (leaf, siblings, indices, expected_root) = make_test_data(TEST_DEPTH);

        // 4 siblings but only 3 indices — mismatched lengths
        let circuit = MerkleTestCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            path_indices: indices[..TEST_DEPTH - 1]
                .iter()
                .map(|&b| Value::known(if b { Fp::one() } else { Fp::zero() }))
                .collect(),
        };

        let k = 10;
        let result = MockProver::run(k, &circuit, vec![vec![expected_root]]);
        assert!(
            result.is_err(),
            "verify_membership must return Err for mismatched siblings/indices lengths"
        );
    }
}
