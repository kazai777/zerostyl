#[cfg(not(test))]
use alloc::vec::Vec;
use halo2_poseidon::{Mds, Spec};
use halo2curves::bn256::Fr;
use halo2curves::group::ff::Field;

use super::constants::{MDS, MDS_INV, ROUND_CONSTANTS};

#[derive(Debug)]
pub struct Bn254P128Pow5T3;

impl Spec<Fr, 3, 2> for Bn254P128Pow5T3 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        57
    }

    fn sbox(val: Fr) -> Fr {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!("MDS is provided by the vendored constants, not regenerated")
    }

    fn constants() -> (Vec<[Fr; 3]>, Mds<Fr, 3>, Mds<Fr, 3>) {
        (ROUND_CONSTANTS.to_vec(), *MDS, *MDS_INV)
    }
}
