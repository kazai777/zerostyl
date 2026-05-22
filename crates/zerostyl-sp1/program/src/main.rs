#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let x = sp1_zkvm::io::read::<u32>();
    let y = x.wrapping_mul(2);
    sp1_zkvm::io::commit(&y);
}
