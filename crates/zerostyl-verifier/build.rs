use halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2curves::bn256::Bn256;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let k = 4;

    let params = ParamsKZG::<Bn256>::setup(k, rand::rngs::OsRng);

    let mut params_bytes = Vec::new();
    params.write(&mut params_bytes).expect("Failed to serialize params");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("embedded_keys.rs");

    let mut f = fs::File::create(dest_path).expect("Failed to create output file");

    writeln!(f, "pub const PARAMS_BYTES: &[u8] = &{:?};", params_bytes).unwrap();
    writeln!(f, "pub const K: u32 = {};", k).unwrap();
}
