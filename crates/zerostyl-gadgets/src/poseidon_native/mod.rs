mod constants;
mod spec;

use halo2_poseidon::{ConstantLength, Hash};
use halo2curves::bn256::Fr;

pub use spec::Bn254P128Pow5T3;

pub fn hash(left: Fr, right: Fr) -> Fr {
    Hash::<Fr, Bn254P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = Fr::from(6);
        let b = Fr::from(42);
        assert_eq!(hash(a, b), hash(a, b));
    }

    #[test]
    fn order_sensitive() {
        let a = Fr::from(6);
        let b = Fr::from(42);
        assert_ne!(hash(a, b), hash(b, a));
    }

    #[test]
    fn different_inputs_different_outputs() {
        assert_ne!(hash(Fr::from(0), Fr::from(0)), hash(Fr::from(0), Fr::from(1)));
    }
}
