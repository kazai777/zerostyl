use anyhow::{anyhow, Context, Result};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
    },
    transcript::{Challenge255, Keccak256Write, TranscriptWriterBuffer},
    SerdeFormat,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;
use sp1_sdk::{Prover, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tiny_keccak::{Hasher, Keccak};
use zerostyl_verifier::reference_circuit::{ReferenceCircuit, REFERENCE_K};

const CIRCUIT_KIND_REFERENCE: u16 = 0;

const ELF_PATH: &str =
    "../program/elf/riscv32im-succinct-zkvm-elf/release/zerostyl-sp1-program";

#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    let elf = load_elf()?;
    let job = generate_reference_proof()?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&CIRCUIT_KIND_REFERENCE);
    stdin.write_vec(job.params_bytes);
    stdin.write_vec(job.vk_bytes.clone());
    stdin.write_vec(job.proof_bytes);
    stdin.write_vec(job.inputs_bytes.clone());

    let client = ProverClient::from_env().await;
    let (mut public_values, report) = client
        .execute(elf.into(), stdin)
        .await
        .map_err(|e| anyhow!("execute: {e}"))?;

    let mut got_vk_hash = [0u8; 32];
    let mut got_inputs_hash = [0u8; 32];
    public_values.read_slice(&mut got_vk_hash);
    public_values.read_slice(&mut got_inputs_hash);

    let expected_vk_hash = keccak(&job.vk_bytes);
    let expected_inputs_hash = keccak(&job.inputs_bytes);

    if got_vk_hash != expected_vk_hash {
        return Err(anyhow!("vk_hash mismatch: guest={got_vk_hash:?} host={expected_vk_hash:?}"));
    }
    if got_inputs_hash != expected_inputs_hash {
        return Err(anyhow!(
            "inputs_hash mismatch: guest={got_inputs_hash:?} host={expected_inputs_hash:?}"
        ));
    }

    println!(
        "verify ok | cycles={} | vk_hash=0x{} | inputs_hash=0x{}",
        report.total_instruction_count(),
        hex(&got_vk_hash),
        hex(&got_inputs_hash),
    );
    Ok(())
}

struct ProofJob {
    params_bytes: Vec<u8>,
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    inputs_bytes: Vec<u8>,
}

fn generate_reference_proof() -> Result<ProofJob> {
    use halo2_proofs::circuit::Value;

    let a = Fr::from(2);
    let b = Fr::from(3);
    let sum = a + b;

    let circuit = ReferenceCircuit { a: Value::known(a), b: Value::known(b) };
    let inputs: Vec<Vec<Fr>> = vec![vec![sum]];

    let params = ParamsKZG::<Bn256>::setup(REFERENCE_K, OsRng);
    let vk = keygen_vk(&params, &ReferenceCircuit::default()).context("keygen_vk")?;
    let pk = keygen_pk(&params, vk.clone(), &ReferenceCircuit::default()).context("keygen_pk")?;

    let instances: Vec<&[Fr]> = inputs.iter().map(|v| v.as_slice()).collect();

    let mut transcript =
        Keccak256Write::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&instances[..]],
        OsRng,
        &mut transcript,
    )
    .context("create_proof")?;
    let proof_bytes = transcript.finalize();

    let mut params_bytes = Vec::new();
    params.write(&mut params_bytes).context("write params")?;
    let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
    let inputs_bytes = postcard::to_allocvec(&inputs).context("encode inputs")?;

    Ok(ProofJob { params_bytes, vk_bytes, proof_bytes, inputs_bytes })
}

fn load_elf() -> Result<Vec<u8>> {
    let candidates = [
        PathBuf::from(ELF_PATH),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ELF_PATH),
    ];
    for path in &candidates {
        if path.exists() {
            return std::fs::read(path).with_context(|| format!("read {}", path.display()));
        }
    }
    Err(anyhow!(
        "guest ELF not found. Run `cargo prove build` inside crates/zerostyl-sp1/program first."
    ))
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(bytes);
    h.finalize(&mut out);
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
