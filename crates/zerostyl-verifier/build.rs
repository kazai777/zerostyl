use halo2_proofs::poly::commitment::Params;
use halo2curves::pasta::EqAffine;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let k = 10; // Circuit size parameter

    println!("Generating IPA parameters for k={}...", k);
    let params = Params::<EqAffine>::new(k);

    let mut params_bytes = Vec::new();
    params.write(&mut params_bytes).expect("Failed to serialize params");

    let vk_bytes = if Path::new("vk_components.rs").exists() {
        let vk_file_content = fs::read_to_string("vk_components.rs")
            .expect("Failed to read vk_components.rs - run extract-vk-v2 first");

        if let Some(start) = vk_file_content.find("VK_BYTES: &[u8] = &[") {
            let start_idx = start + "VK_BYTES: &[u8] = &[".len();
            if let Some(end) = vk_file_content[start_idx..].find("];") {
                let bytes_str = &vk_file_content[start_idx..start_idx + end];
                let bytes: Vec<u8> =
                    bytes_str.split(',').filter_map(|s| s.trim().parse().ok()).collect();
                println!("Loaded VK from vk_components.rs: {} bytes", bytes.len());
                bytes
            } else {
                eprintln!("Warning: Could not parse VK bytes, using empty placeholder");
                vec![]
            }
        } else {
            eprintln!("Warning: Could not find VK_BYTES in vk_components.rs");
            vec![]
        }
    } else {
        eprintln!("Warning: vk_components.rs not found - run extract-vk-v2 first");
        eprintln!("Using empty placeholder for VK");
        vec![]
    };

    // Write to generated file
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("embedded_keys.rs");

    let mut f = fs::File::create(dest_path).expect("Failed to create output file");

    writeln!(f, "pub const VK_BYTES: &[u8] = &{:?};", vk_bytes).unwrap();

    writeln!(f, "pub const PARAMS_BYTES: &[u8] = &{:?};", params_bytes).unwrap();

    writeln!(f, "pub const K: u32 = {};", k).unwrap();

    println!(
        "Generated embedded keys: VK={} bytes, Params={} bytes",
        vk_bytes.len(),
        params_bytes.len()
    );
}
