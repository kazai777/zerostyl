//! Build-time generation of the embedded KZG parameters and verifying key.
//!
//! Two things are baked into the crate here and written to `$OUT_DIR/embedded_keys.rs`:
//!
//! 1. `PARAMS_BYTES` — the KZG commitment parameters (SRS). They are produced from a
//!    **deterministic** seeded RNG so every build yields the exact same SRS. This is what lets a
//!    proof produced against these parameters verify in a different build of the verifier. It is a
//!    development/test setup, NOT a secure trusted-setup ceremony — a production deployment must
//!    swap in SRS from a real Powers-of-Tau ceremony (the toxic waste of a seeded RNG is public).
//!
//! 2. `VK_BYTES` — the serialized verifying key for the reference circuit. halo2_proofs 0.3.0
//!    (PSE fork) *does* support VK serialization via `VerifyingKey::write`/`read` with
//!    `SerdeFormat`, so we serialize the VK once here and the runtime deserializes it with
//!    `from_bytes` instead of calling the expensive `keygen_vk` on every verification.
//!
//! The reference circuit below is duplicated from `src/reference_circuit.rs`. A runtime drift
//! guard (`embedded::tests::embedded_vk_matches_runtime_keygen`) re-derives the VK from the real
//! circuit and asserts it matches `VK_BYTES`, so any divergence fails the test suite.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::{commitment::Params, kzg::commitment::ParamsKZG, Rotation},
    SerdeFormat,
};
use halo2curves::bn256::{Bn256, Fr};
use rand::SeedableRng;
use std::fs;
use std::io::Write;
use std::path::Path;

// Shared with the prover (zerostyl-compiler's KeyManager) via zerostyl-runtime so a proof produced
// off-chain verifies against these embedded parameters. Reproducible dev setup, not a ceremony.
use zerostyl_runtime::DEV_SRS_SEED;

const K: u32 = 4;

#[derive(Clone, Default)]
struct ReferenceCircuit {
    a: Value<Fr>,
    b: Value<Fr>,
}

#[derive(Clone)]
struct ReferenceConfig {
    advice: Column<Advice>,
    #[allow(dead_code)]
    instance: Column<Instance>,
    selector: Selector,
}

impl Circuit<Fr> for ReferenceCircuit {
    type Config = ReferenceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(advice);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());
            let sum = meta.query_instance(instance, Rotation::cur());
            vec![s * (a + b - sum)]
        });

        ReferenceConfig { advice, instance, selector }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "add",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.advice, 0, || self.a)?;
                region.assign_advice(|| "b", config.advice, 1, || self.b)?;
                Ok(())
            },
        )
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Deterministic SRS: same seed → same parameters on every build (and same as the prover).
    let mut rng = rand::rngs::StdRng::seed_from_u64(DEV_SRS_SEED);
    let params = ParamsKZG::<Bn256>::setup(K, &mut rng);

    let mut params_bytes = Vec::new();
    params.write(&mut params_bytes).expect("Failed to serialize params");

    // Serialize the verifying key so the runtime never has to call keygen_vk.
    let vk = keygen_vk(&params, &ReferenceCircuit::default()).expect("keygen_vk failed");
    let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("embedded_keys.rs");
    let mut f = fs::File::create(dest_path).expect("Failed to create output file");

    writeln!(f, "pub const PARAMS_BYTES: &[u8] = &{:?};", params_bytes).unwrap();
    writeln!(f, "pub const VK_BYTES: &[u8] = &{:?};", vk_bytes).unwrap();
    writeln!(f, "pub const K: u32 = {};", K).unwrap();

    // The real state_mask circuit (k=10): same deterministic SRS as the prover, so a proof from
    // `zerostyl-prove` verifies against these bytes. Only generated when the feature is on.
    #[cfg(feature = "state_mask_vk")]
    {
        use state_mask::StateMaskCircuit;

        const STATE_MASK_K: u32 = 10;
        let mut sm_rng = rand::rngs::StdRng::seed_from_u64(DEV_SRS_SEED);
        let sm_params = ParamsKZG::<Bn256>::setup(STATE_MASK_K, &mut sm_rng);

        let mut sm_params_bytes = Vec::new();
        sm_params.write(&mut sm_params_bytes).expect("Failed to serialize state_mask params");

        let sm_vk = keygen_vk(&sm_params, &StateMaskCircuit::default())
            .expect("state_mask keygen_vk failed");
        let sm_vk_bytes = sm_vk.to_bytes(SerdeFormat::RawBytes);

        writeln!(f, "pub const STATE_MASK_PARAMS_BYTES: &[u8] = &{:?};", sm_params_bytes).unwrap();
        writeln!(f, "pub const STATE_MASK_VK_BYTES: &[u8] = &{:?};", sm_vk_bytes).unwrap();
        writeln!(f, "pub const STATE_MASK_K: u32 = {};", STATE_MASK_K).unwrap();
    }
}
