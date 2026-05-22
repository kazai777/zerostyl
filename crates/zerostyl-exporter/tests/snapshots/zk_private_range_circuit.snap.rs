#![allow(clippy::all, dead_code)]
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::bn256::Fr;
use zerostyl_compiler::gadgets::{
    PoseidonCommitmentChip, PoseidonCommitmentConfig, RangeProofChip, RangeProofConfig,
};
#[derive(Clone, Debug, Default)]
pub struct DepositCircuit {
    pub amount: Value<Fr>,
    pub amount_nonce: Value<Fr>,
}
#[derive(Debug, Clone)]
pub struct DepositCircuitConfig {
    poseidon_config: PoseidonCommitmentConfig,
    range_config: RangeProofConfig,
    instance: Column<Instance>,
}
impl Circuit<Fr> for DepositCircuit {
    type Config = DepositCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poseidon_config = PoseidonCommitmentChip::configure(meta);
        let range_config = RangeProofChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::Config { poseidon_config, range_config, instance }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> std::result::Result<(), Error> {
        let poseidon_chip = PoseidonCommitmentChip::construct(config.poseidon_config);
        let range_chip = RangeProofChip::construct(config.range_config);
        let amount_poseidon_value = poseidon_chip.load_private(
            layouter.namespace(|| "load amount for poseidon"),
            self.amount,
            0,
        )?;
        let amount_poseidon_nonce = poseidon_chip.load_private(
            layouter.namespace(|| "load amount_nonce for poseidon"),
            self.amount_nonce,
            1,
        )?;
        let amount_commitment = poseidon_chip.commit(
            layouter.namespace(|| "commit amount"),
            amount_poseidon_value.clone(),
            amount_poseidon_nonce,
        )?;
        let amount_commitment_ref = amount_commitment.cell();
        layouter.constrain_instance(amount_commitment_ref, config.instance, 0usize)?;
        let amount_range_value =
            range_chip.load_value(layouter.namespace(|| "load amount for range"), self.amount)?;
        range_chip.check_range_bounded(
            layouter.namespace(|| "range check amount"),
            amount_range_value,
            Fr::from((1000) as u64),
            Fr::from((100000) as u64),
            256usize,
        )?;
        Ok(())
    }
}
