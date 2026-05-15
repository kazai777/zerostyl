#![allow(clippy::all, dead_code)]
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::pasta::Fp;
use zerostyl_compiler::gadgets::{
    PoseidonCommitmentChip, PoseidonCommitmentConfig, MerkleTreeChip, MerkleTreeConfig,
};
pub const MERKLE_DEPTH: usize = 32;
#[derive(Clone, Debug)]
pub struct ClaimCircuit {
    pub leaf: Value<Fp>,
    pub leaf_nonce: Value<Fp>,
    pub root: Value<Fp>,
    pub siblings: Vec<Value<Fp>>,
    pub indices: Vec<Value<Fp>>,
}
impl Default for ClaimCircuit {
    fn default() -> Self {
        Self {
            leaf: Value::unknown(),
            leaf_nonce: Value::unknown(),
            root: Value::unknown(),
            siblings: vec![Value::unknown(); MERKLE_DEPTH],
            indices: vec![Value::unknown(); MERKLE_DEPTH],
        }
    }
}
#[derive(Debug, Clone)]
pub struct ClaimCircuitConfig {
    poseidon_config: PoseidonCommitmentConfig,
    merkle_config: MerkleTreeConfig,
    instance: Column<Instance>,
}
impl Circuit<Fp> for ClaimCircuit {
    type Config = ClaimCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let poseidon_config = PoseidonCommitmentChip::configure(meta);
        let merkle_config = MerkleTreeChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::Config {
            poseidon_config,
            merkle_config,
            instance,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> std::result::Result<(), Error> {
        let poseidon_chip = PoseidonCommitmentChip::construct(config.poseidon_config);
        let merkle_chip = MerkleTreeChip::construct(config.merkle_config.clone());
        let leaf_poseidon_value = poseidon_chip
            .load_private(
                layouter.namespace(|| "load leaf for poseidon"),
                self.leaf,
                0,
            )?;
        let leaf_poseidon_nonce = poseidon_chip
            .load_private(
                layouter.namespace(|| "load leaf_nonce for poseidon"),
                self.leaf_nonce,
                1,
            )?;
        let leaf_commitment = poseidon_chip
            .commit(
                layouter.namespace(|| "commit leaf"),
                leaf_poseidon_value.clone(),
                leaf_poseidon_nonce,
            )?;
        let leaf_commitment_ref = leaf_commitment.cell();
        layouter.constrain_instance(leaf_commitment_ref, config.instance, 0usize)?;
        let leaf_sibling_cells: Vec<_> = self
            .siblings
            .iter()
            .enumerate()
            .map(|(i, s)| {
                merkle_chip
                    .load_sibling(
                        layouter
                            .namespace(|| {
                                format!("{} {}", "load leaf merkle sibling", i)
                            }),
                        *s,
                    )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let leaf_index_cells: Vec<_> = self
            .indices
            .iter()
            .enumerate()
            .map(|(i, idx)| {
                merkle_chip
                    .load_path_index(
                        layouter
                            .namespace(|| format!("{} {}", "load leaf merkle index", i)),
                        *idx,
                    )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let leaf_computed_root = merkle_chip
            .verify_membership(
                layouter.namespace(|| "verify leaf merkle membership"),
                leaf_commitment.clone(),
                &leaf_sibling_cells,
                &leaf_index_cells,
            )?;
        Ok(())
    }
}
