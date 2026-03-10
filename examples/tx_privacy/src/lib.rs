//! Transaction Privacy Circuit
//!
//! Implements zero-knowledge proofs for private token transfers using:
//! - Poseidon hash commitments: `commitment = Poseidon(balance, randomness)`
//! - Poseidon-based Merkle tree membership proofs (depth 32)
//! - Range proofs via bit decomposition (64-bit)
//!
//! ## Circuit Overview
//!
//! Public Inputs:
//! - `commitment_old`: `Poseidon(balance_old, randomness_old)`
//! - `commitment_new`: `Poseidon(balance_new, randomness_new)`
//! - `merkle_root`: Root of the account Merkle tree
//!
//! Private Witnesses:
//! - `balance_old`, `balance_new`: Account balances
//! - `randomness_old`, `randomness_new`: Commitment randomness
//! - `amount`: Transfer amount
//! - `merkle_siblings`: Merkle path sibling hashes (depth 32)
//! - `merkle_indices`: Merkle path direction bits (depth 32)
//!
//! Constraints:
//! 1. `commitment_old == Poseidon(balance_old, randomness_old)`
//! 2. `commitment_new == Poseidon(balance_new, randomness_new)`
//! 3. `balance_old - amount == balance_new`
//! 4. `MerkleVerify(commitment_old, siblings, indices) == merkle_root`
//! 5. `amount ∈ [0, 2^64)`

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;
use zerostyl_compiler::gadgets::{
    MerkleTreeChip, MerkleTreeConfig, PoseidonCommitmentChip, RangeProofChip, RangeProofConfig,
};

/// Standard Merkle tree depth (supports ~4 billion leaves).
pub const MERKLE_DEPTH: usize = 32;

/// Configuration for the transaction privacy circuit.
#[derive(Debug, Clone)]
pub struct TxPrivacyConfig {
    merkle_config: MerkleTreeConfig,
    range_config: RangeProofConfig,
    balance_advice: [Column<Advice>; 3],
    balance_selector: Selector,
    instance: Column<Instance>,
}

/// Zero-knowledge circuit for private token transfers.
///
/// Proves that a transfer of `amount` from `balance_old` to `balance_new`
/// is valid, that the sender's commitment is in the Merkle tree, and that
/// all commitments use proper Poseidon hashes.
#[derive(Clone, Debug)]
pub struct TxPrivacyCircuit {
    pub balance_old: Value<Fp>,
    pub balance_new: Value<Fp>,
    pub randomness_old: Value<Fp>,
    pub randomness_new: Value<Fp>,
    pub amount: Value<Fp>,
    pub merkle_siblings: Vec<Value<Fp>>,
    pub merkle_indices: Vec<Value<Fp>>,
}

impl Default for TxPrivacyCircuit {
    fn default() -> Self {
        Self {
            balance_old: Value::unknown(),
            balance_new: Value::unknown(),
            randomness_old: Value::unknown(),
            randomness_new: Value::unknown(),
            amount: Value::unknown(),
            merkle_siblings: vec![Value::unknown(); MERKLE_DEPTH],
            merkle_indices: vec![Value::unknown(); MERKLE_DEPTH],
        }
    }
}

impl TxPrivacyCircuit {
    /// Creates a new circuit with validated inputs.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `merkle_siblings.len() != MERKLE_DEPTH`
    /// - `merkle_indices.len() != MERKLE_DEPTH`
    /// - `balance_new > balance_old`
    /// - `amount != balance_old - balance_new`
    pub fn new(
        balance_old: u64,
        balance_new: u64,
        randomness_old: Fp,
        randomness_new: Fp,
        amount: u64,
        merkle_siblings: Vec<Fp>,
        merkle_indices: Vec<bool>,
    ) -> Self {
        assert_eq!(
            merkle_siblings.len(),
            MERKLE_DEPTH,
            "Merkle siblings must have depth {}",
            MERKLE_DEPTH
        );
        assert_eq!(
            merkle_indices.len(),
            MERKLE_DEPTH,
            "Merkle indices must have depth {}",
            MERKLE_DEPTH
        );
        assert!(balance_new <= balance_old, "Invalid balance transition");
        assert_eq!(balance_old - balance_new, amount, "Amount must equal balance difference");

        Self {
            balance_old: Value::known(Fp::from(balance_old)),
            balance_new: Value::known(Fp::from(balance_new)),
            randomness_old: Value::known(randomness_old),
            randomness_new: Value::known(randomness_new),
            amount: Value::known(Fp::from(amount)),
            merkle_siblings: merkle_siblings.into_iter().map(Value::known).collect(),
            merkle_indices: merkle_indices
                .iter()
                .map(|&b| Value::known(if b { Fp::from(1u64) } else { Fp::from(0u64) }))
                .collect(),
        }
    }

    /// Computes a Poseidon commitment: `Poseidon(balance, randomness)`.
    #[must_use]
    pub fn compute_commitment(balance: Fp, randomness: Fp) -> Fp {
        PoseidonCommitmentChip::hash_outside_circuit(balance, randomness)
    }

    /// Computes the Merkle root outside the circuit (for witness generation).
    #[must_use]
    pub fn compute_merkle_root(leaf: Fp, siblings: &[Fp], indices: &[bool]) -> Fp {
        MerkleTreeChip::compute_root_outside_circuit(leaf, siblings, indices)
    }
}

impl Circuit<Fp> for TxPrivacyCircuit {
    type Config = TxPrivacyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            balance_old: Value::unknown(),
            balance_new: Value::unknown(),
            randomness_old: Value::unknown(),
            randomness_new: Value::unknown(),
            amount: Value::unknown(),
            merkle_siblings: vec![Value::unknown(); self.merkle_siblings.len()],
            merkle_indices: vec![Value::unknown(); self.merkle_indices.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> TxPrivacyConfig {
        let merkle_config = MerkleTreeChip::configure(meta);
        let range_config = RangeProofChip::configure(meta);

        let balance_advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for col in &balance_advice {
            meta.enable_equality(*col);
        }

        let balance_selector = meta.selector();
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // balance_old - amount - balance_new = 0
        meta.create_gate("balance check", |meta| {
            let s = meta.query_selector(balance_selector);
            let bal_old = meta.query_advice(balance_advice[0], Rotation::cur());
            let bal_new = meta.query_advice(balance_advice[1], Rotation::cur());
            let amount = meta.query_advice(balance_advice[2], Rotation::cur());
            vec![s * (bal_old - amount - bal_new)]
        });

        TxPrivacyConfig { merkle_config, range_config, balance_advice, balance_selector, instance }
    }

    fn synthesize(
        &self,
        config: TxPrivacyConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip =
            PoseidonCommitmentChip::construct(config.merkle_config.poseidon_config().clone());
        let merkle_chip = MerkleTreeChip::construct(config.merkle_config.clone());
        let range_chip = RangeProofChip::construct(config.range_config.clone());

        // Load private witnesses
        let balance_old_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load balance_old"),
            self.balance_old,
            0,
        )?;
        let randomness_old_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load randomness_old"),
            self.randomness_old,
            1,
        )?;
        let balance_new_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load balance_new"),
            self.balance_new,
            0,
        )?;
        let randomness_new_cell = poseidon_chip.load_private(
            layouter.namespace(|| "load randomness_new"),
            self.randomness_new,
            1,
        )?;
        let amount_cell =
            poseidon_chip.load_private(layouter.namespace(|| "load amount"), self.amount, 2)?;

        // 1. commitment_old = Poseidon(balance_old, randomness_old)
        let commitment_old = poseidon_chip.commit(
            layouter.namespace(|| "commitment_old"),
            balance_old_cell.clone(),
            randomness_old_cell,
        )?;

        // 2. commitment_new = Poseidon(balance_new, randomness_new)
        let commitment_new = poseidon_chip.commit(
            layouter.namespace(|| "commitment_new"),
            balance_new_cell.clone(),
            randomness_new_cell,
        )?;

        // 3. Balance check: balance_old - amount = balance_new
        layouter.assign_region(
            || "balance check",
            |mut region| {
                config.balance_selector.enable(&mut region, 0)?;
                balance_old_cell.copy_advice(
                    || "balance_old",
                    &mut region,
                    config.balance_advice[0],
                    0,
                )?;
                balance_new_cell.copy_advice(
                    || "balance_new",
                    &mut region,
                    config.balance_advice[1],
                    0,
                )?;
                amount_cell.copy_advice(|| "amount", &mut region, config.balance_advice[2], 0)?;
                Ok(())
            },
        )?;

        // 4. Range check: amount ∈ [0, 2^64)
        range_chip.check_range(layouter.namespace(|| "range check amount"), amount_cell, 64)?;

        // 5. Load Merkle siblings and indices
        let sibling_cells: Vec<AssignedCell<Fp, Fp>> = self
            .merkle_siblings
            .iter()
            .enumerate()
            .map(|(i, s)| {
                merkle_chip.load_sibling(layouter.namespace(|| format!("load sibling {}", i)), *s)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let index_cells: Vec<AssignedCell<Fp, Fp>> = self
            .merkle_indices
            .iter()
            .enumerate()
            .map(|(i, idx)| {
                merkle_chip
                    .load_path_index(layouter.namespace(|| format!("load index {}", i)), *idx)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 6. Verify Merkle membership — save cell before consuming commitment_old
        let commitment_old_cell = commitment_old.cell();

        let computed_root = merkle_chip.verify_membership(
            layouter.namespace(|| "merkle verify"),
            commitment_old,
            &sibling_cells,
            &index_cells,
        )?;

        // 7. Expose public inputs
        layouter.constrain_instance(commitment_old_cell, config.instance, 0)?;
        layouter.constrain_instance(commitment_new.cell(), config.instance, 1)?;
        layouter.constrain_instance(computed_root.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    const TEST_DEPTH: usize = 4;
    const TEST_K: u32 = 10;

    fn make_test_data(
        balance_old: u64,
        balance_new: u64,
        amount: u64,
        depth: usize,
    ) -> (TxPrivacyCircuit, Vec<Fp>) {
        let randomness_old = Fp::from(42u64);
        let randomness_new = Fp::from(84u64);
        let siblings: Vec<Fp> = (0..depth).map(|i| Fp::from((i + 100) as u64)).collect();
        let indices: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();

        let commitment_old =
            TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), randomness_old);
        let commitment_new =
            TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
        let merkle_root =
            TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

        let circuit = TxPrivacyCircuit {
            balance_old: Value::known(Fp::from(balance_old)),
            balance_new: Value::known(Fp::from(balance_new)),
            randomness_old: Value::known(randomness_old),
            randomness_new: Value::known(randomness_new),
            amount: Value::known(Fp::from(amount)),
            merkle_siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            merkle_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::from(1u64) } else { Fp::from(0u64) }))
                .collect(),
        };

        (circuit, vec![commitment_old, commitment_new, merkle_root])
    }

    #[test]
    fn test_tx_privacy_circuit_valid() {
        let (circuit, public_inputs) = make_test_data(1000, 700, 300, TEST_DEPTH);
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_tx_privacy_wrong_commitment_rejected() {
        let (circuit, mut public_inputs) = make_test_data(1000, 700, 300, TEST_DEPTH);
        public_inputs[0] = Fp::from(999u64);
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_tx_privacy_wrong_merkle_root_rejected() {
        let (circuit, mut public_inputs) = make_test_data(1000, 700, 300, TEST_DEPTH);
        public_inputs[2] = Fp::from(999u64);
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_tx_privacy_wrong_balance_rejected() {
        let randomness_old = Fp::from(42u64);
        let randomness_new = Fp::from(84u64);
        let siblings: Vec<Fp> = (0..TEST_DEPTH).map(|i| Fp::from((i + 100) as u64)).collect();
        let indices: Vec<bool> = (0..TEST_DEPTH).map(|i| i % 2 == 0).collect();

        // balance_old(1000) - amount(300) = 700 ≠ balance_new(600)
        let commitment_old =
            TxPrivacyCircuit::compute_commitment(Fp::from(1000u64), randomness_old);
        let commitment_new = TxPrivacyCircuit::compute_commitment(Fp::from(600u64), randomness_new);
        let merkle_root =
            TxPrivacyCircuit::compute_merkle_root(commitment_old, &siblings, &indices);

        let circuit = TxPrivacyCircuit {
            balance_old: Value::known(Fp::from(1000u64)),
            balance_new: Value::known(Fp::from(600u64)),
            randomness_old: Value::known(randomness_old),
            randomness_new: Value::known(randomness_new),
            amount: Value::known(Fp::from(300u64)),
            merkle_siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            merkle_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::from(1u64) } else { Fp::from(0u64) }))
                .collect(),
        };

        let public_inputs = vec![commitment_old, commitment_new, merkle_root];
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    #[should_panic(expected = "Invalid balance transition")]
    fn test_tx_privacy_circuit_invalid_balance() {
        let _ = TxPrivacyCircuit::new(
            700,
            1000,
            Fp::from(42u64),
            Fp::from(84u64),
            300,
            vec![Fp::from(0u64); MERKLE_DEPTH],
            vec![false; MERKLE_DEPTH],
        );
    }

    #[test]
    #[should_panic(expected = "Amount must equal balance difference")]
    fn test_tx_privacy_circuit_invalid_amount() {
        let _ = TxPrivacyCircuit::new(
            1000,
            700,
            Fp::from(42u64),
            Fp::from(84u64),
            100,
            vec![Fp::from(0u64); MERKLE_DEPTH],
            vec![false; MERKLE_DEPTH],
        );
    }

    #[test]
    fn test_tx_privacy_zero_amount_transfer() {
        let (circuit, public_inputs) = make_test_data(1000, 1000, 0, TEST_DEPTH);
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_tx_privacy_full_balance_transfer() {
        let (circuit, public_inputs) = make_test_data(1000, 0, 1000, TEST_DEPTH);
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_commitment_computation() {
        let balance = Fp::from(1000u64);
        let randomness = Fp::from(42u64);
        let commitment = TxPrivacyCircuit::compute_commitment(balance, randomness);
        // Poseidon hash is NOT simple addition
        assert_ne!(commitment, Fp::from(1042u64));
        // Deterministic
        assert_eq!(commitment, TxPrivacyCircuit::compute_commitment(balance, randomness));
    }

    #[test]
    fn test_compute_merkle_root() {
        let leaf = Fp::from(100u64);
        let siblings = vec![Fp::from(1u64), Fp::from(2u64)];
        let indices = vec![false, true];
        let root = TxPrivacyCircuit::compute_merkle_root(leaf, &siblings, &indices);
        // Deterministic
        assert_eq!(root, TxPrivacyCircuit::compute_merkle_root(leaf, &siblings, &indices));
    }

    #[test]
    fn test_circuit_default() {
        let circuit = TxPrivacyCircuit::default();
        assert_eq!(circuit.merkle_siblings.len(), MERKLE_DEPTH);
        assert_eq!(circuit.merkle_indices.len(), MERKLE_DEPTH);
    }

    #[test]
    fn test_merkle_depth_constant() {
        assert_eq!(MERKLE_DEPTH, 32);
    }

    #[test]
    #[should_panic(expected = "Merkle siblings must have depth")]
    fn test_invalid_merkle_path_length() {
        let _ = TxPrivacyCircuit::new(
            1000,
            700,
            Fp::from(42u64),
            Fp::from(84u64),
            300,
            vec![Fp::from(0u64); 10],
            vec![false; 10],
        );
    }

    #[test]
    fn test_tx_privacy_wrong_randomness_rejected() {
        let balance_old = 1000u64;
        let balance_new = 700u64;
        let amount = 300u64;
        let randomness_old = Fp::from(42u64);
        let wrong_randomness_old = Fp::from(999u64); // Different from what circuit uses
        let randomness_new = Fp::from(84u64);
        let siblings: Vec<Fp> = (0..TEST_DEPTH).map(|i| Fp::from((i + 100) as u64)).collect();
        let indices: Vec<bool> = (0..TEST_DEPTH).map(|i| i % 2 == 0).collect();

        // Compute public inputs with the WRONG randomness
        let wrong_commitment_old =
            TxPrivacyCircuit::compute_commitment(Fp::from(balance_old), wrong_randomness_old);
        let commitment_new =
            TxPrivacyCircuit::compute_commitment(Fp::from(balance_new), randomness_new);
        let merkle_root =
            TxPrivacyCircuit::compute_merkle_root(wrong_commitment_old, &siblings, &indices);

        // Circuit uses the CORRECT randomness internally
        let circuit = TxPrivacyCircuit {
            balance_old: Value::known(Fp::from(balance_old)),
            balance_new: Value::known(Fp::from(balance_new)),
            randomness_old: Value::known(randomness_old), // Correct randomness
            randomness_new: Value::known(randomness_new),
            amount: Value::known(Fp::from(amount)),
            merkle_siblings: siblings.iter().map(|s| Value::known(*s)).collect(),
            merkle_indices: indices
                .iter()
                .map(|&b| Value::known(if b { Fp::from(1u64) } else { Fp::from(0u64) }))
                .collect(),
        };

        // Public inputs use wrong_commitment_old (from wrong randomness)
        let public_inputs = vec![wrong_commitment_old, commitment_new, merkle_root];
        let prover = MockProver::run(TEST_K, &circuit, vec![public_inputs]).unwrap();
        assert!(
            prover.verify().is_err(),
            "Circuit must reject when randomness doesn't match commitment"
        );
    }
}
