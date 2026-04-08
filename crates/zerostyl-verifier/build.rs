use halo2_proofs::poly::commitment::Params;
use halo2curves::pasta::EqAffine;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Must match reference_circuit::REFERENCE_K
    let k = 4;

    println!("Generating IPA parameters for k={}...", k);
    let params = Params::<EqAffine>::new(k);

    let mut params_bytes = Vec::new();
    params.write(&mut params_bytes).expect("Failed to serialize params");

    // Note: halo2_proofs 0.3.2 does not support VK serialization.
    // VK is regenerated at runtime via keygen_vk + ReferenceCircuit.

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("embedded_keys.rs");

    let mut f = fs::File::create(dest_path).expect("Failed to create output file");

    writeln!(f, "pub const PARAMS_BYTES: &[u8] = &{:?};", params_bytes).unwrap();
    writeln!(f, "pub const K: u32 = {};", k).unwrap();

    println!("Generated embedded keys: Params={} bytes, k={}", params_bytes.len(), k);
}
