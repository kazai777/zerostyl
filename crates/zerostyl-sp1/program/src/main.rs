#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use serde::Deserialize;

sp1_zkvm::entrypoint!(main);

#[derive(Deserialize)]
struct VkComponents {
    k: u32,
    extended_k: u32,
    omega: Vec<u8>,
    num_fixed_columns: usize,
    num_advice_columns: usize,
    num_instance_columns: usize,
    num_selectors: usize,
    fixed_commitments: Vec<Vec<u8>>,
    permutation_commitments: Vec<Vec<u8>>,
    permutation_columns: Vec<(usize, u8)>,
}

pub fn main() {
    let vk_bytes = sp1_zkvm::io::read_vec();
    let proof_bytes = sp1_zkvm::io::read_vec();
    let inputs_bytes = sp1_zkvm::io::read_vec();

    let vk: VkComponents =
        postcard::from_bytes(&vk_bytes).expect("decode VkComponents from postcard");

    assert!(vk.extended_k >= vk.k, "extended_k must be >= k");
    assert!(vk.k > 0 && vk.k <= 26, "k must be in (0, 26]");
    assert!(vk.omega.len() == 32, "omega must be 32 bytes");
    assert!(!vk.fixed_commitments.is_empty(), "fixed_commitments empty");

    sp1_zkvm::io::commit(&vk.k);
    sp1_zkvm::io::commit(&(proof_bytes.len() as u32));
    sp1_zkvm::io::commit(&(inputs_bytes.len() as u32));
}
