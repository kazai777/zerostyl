//! No-std Halo2 IPA verifier for Arbitrum Stylus

use blake2::{Blake2b512, Digest};
use halo2curves::group::ff::{Field, FromUniformBytes, PrimeField};
use halo2curves::group::GroupEncoding;
use halo2curves::pasta::{EqAffine, Fp};

#[cfg(feature = "std")]
use halo2_proofs::poly::commitment::Params;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

pub type VerifyError = Vec<u8>;

const CHALLENGE_PREFIX: u8 = 0;
const POINT_PREFIX: u8 = 1;
const SCALAR_PREFIX: u8 = 2;

// Embedded verification keys generated at compile time
include!(concat!(env!("OUT_DIR"), "/embedded_keys.rs"));

use crate::vk_components::VkComponents;

/// Load and deserialize the embedded VK
pub fn load_vk() -> Result<VkComponents, VerifyError> {
    VkComponents::from_bytes(VK_BYTES)
        .map_err(|e| format!("Failed to deserialize VK: {:?}", e).into_bytes())
}

struct Transcript {
    hasher: Blake2b512,
    proof_data: Vec<u8>,
    position: usize,
}

impl Transcript {
    fn new(proof_bytes: &[u8]) -> Self {
        let mut hasher = Blake2b512::new();
        hasher.update(b"Halo2-Transcript");

        Self { hasher, proof_data: proof_bytes.to_vec(), position: 0 }
    }

    fn absorb_point(&mut self, point: &EqAffine) {
        self.hasher.update([POINT_PREFIX]);
        self.hasher.update(point.to_bytes().as_ref());
    }

    fn absorb_scalar(&mut self, scalar: &Fp) {
        self.hasher.update([SCALAR_PREFIX]);
        self.hasher.update(scalar.to_repr().as_ref());
    }

    fn read_point(&mut self) -> Result<EqAffine, VerifyError> {
        let point_size = 32;
        if self.position + point_size > self.proof_data.len() {
            return Err(Vec::from(b"Insufficient proof data for point"));
        }

        let mut bytes = <EqAffine as GroupEncoding>::Repr::default();
        bytes.as_mut().copy_from_slice(&self.proof_data[self.position..self.position + point_size]);
        self.position += point_size;

        let point = Option::<EqAffine>::from(EqAffine::from_bytes(&bytes))
            .ok_or_else(|| Vec::from(b"Invalid point encoding"))?;

        self.absorb_point(&point);
        Ok(point)
    }

    fn read_scalar(&mut self) -> Result<Fp, VerifyError> {
        let scalar_size = 32;
        if self.position + scalar_size > self.proof_data.len() {
            return Err(Vec::from(b"Insufficient proof data for scalar"));
        }

        let mut bytes = <Fp as PrimeField>::Repr::default();
        bytes
            .as_mut()
            .copy_from_slice(&self.proof_data[self.position..self.position + scalar_size]);
        self.position += scalar_size;

        let scalar = Option::<Fp>::from(Fp::from_repr(bytes))
            .ok_or_else(|| Vec::from(b"Invalid scalar encoding"))?;

        self.absorb_scalar(&scalar);
        Ok(scalar)
    }

    fn squeeze_challenge(&mut self) -> Fp {
        self.hasher.update([CHALLENGE_PREFIX]);
        let result = self.hasher.finalize_reset();
        let hash_bytes: [u8; 64] = result.into();
        Fp::from_uniform_bytes(&hash_bytes)
    }
}

pub fn verify_proof_nostd(
    proof_bytes: &[u8],
    public_inputs: &[Vec<Fp>],
) -> Result<bool, VerifyError> {
    if proof_bytes.is_empty() {
        return Err(Vec::from(b"Empty proof"));
    }
    if public_inputs.is_empty() {
        return Err(Vec::from(b"Empty public inputs"));
    }

    if VK_BYTES.is_empty() || PARAMS_BYTES.is_empty() {
        return Err(Vec::from(b"VK or params not embedded"));
    }

    let vk = load_vk()?;

    let proof = parse_proof(proof_bytes, &vk)?;

    let mut transcript = Transcript::new(proof_bytes);
    let challenges = generate_challenges(&mut transcript, &proof);

    verify_plonk_constraints(&proof, &vk, &challenges)?;

    let instance_commitments = compute_instance_commitments(public_inputs)?;

    verify_ipa_openings(&proof, &instance_commitments)?;

    Ok(true)
}

#[derive(Debug)]
struct Proof {
    advice_commitments: Vec<EqAffine>,

    permutation_product_commitment: EqAffine,

    quotient_commitment: Vec<EqAffine>, // Can be split into multiple parts

    advice_evals: Vec<Fp>,             // Witness values at ζ
    fixed_evals: Vec<Fp>,              // Fixed column values at ζ
    permutation_evals: Vec<Fp>,        // Permutation polynomial values at ζ
    permutation_product_eval: Fp,      // Z(ζ)
    permutation_product_next_eval: Fp, // Z(ωζ)

    ipa_proof: IpaProof,
}

#[derive(Debug)]
struct IpaProof {
    s_poly_commitment: EqAffine,
    eval_value: Fp,
    rounds: Vec<(EqAffine, EqAffine)>,
}

/// PLONK challenges generated from Fiat-Shamir transcript
#[derive(Debug)]
#[allow(dead_code)] // theta and v not used in tx_privacy circuit
struct Challenges {
    beta: Fp,  // Permutation challenge 1
    gamma: Fp, // Permutation challenge 2
    theta: Fp, // Lookup challenge (not used in tx_privacy)
    zeta: Fp,  // Evaluation point
    v: Fp,     // Batching challenge
}

/// Generate all PLONK challenges from the Fiat-Shamir transcript
/// This must follow the exact same order as proof generation
fn generate_challenges(transcript: &mut Transcript, proof: &Proof) -> Challenges {
    for commitment in &proof.advice_commitments {
        transcript.absorb_point(commitment);
    }
    let beta = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();

    transcript.absorb_point(&proof.permutation_product_commitment);
    let theta = transcript.squeeze_challenge();

    for commitment in &proof.quotient_commitment {
        transcript.absorb_point(commitment);
    }
    let zeta = transcript.squeeze_challenge();

    for eval in &proof.advice_evals {
        transcript.absorb_scalar(eval);
    }
    for eval in &proof.fixed_evals {
        transcript.absorb_scalar(eval);
    }
    for eval in &proof.permutation_evals {
        transcript.absorb_scalar(eval);
    }
    transcript.absorb_scalar(&proof.permutation_product_eval);
    transcript.absorb_scalar(&proof.permutation_product_next_eval);

    let v = transcript.squeeze_challenge();

    Challenges { beta, gamma, theta, zeta, v }
}

fn parse_proof(proof_bytes: &[u8], vk: &VkComponents) -> Result<Proof, VerifyError> {
    let mut transcript = Transcript::new(proof_bytes);

    let mut advice_commitments = Vec::new();
    for _ in 0..vk.num_advice_columns {
        let commitment = transcript.read_point()?;
        advice_commitments.push(commitment);
    }

    let permutation_product_commitment = transcript.read_point()?;

    let num_quotient_parts = 3; // Standard for most circuits
    let mut quotient_commitment = Vec::new();
    for _ in 0..num_quotient_parts {
        let commitment = transcript.read_point()?;
        quotient_commitment.push(commitment);
    }

    let mut advice_evals = Vec::new();
    for _ in 0..vk.num_advice_columns {
        let eval = transcript.read_scalar()?;
        advice_evals.push(eval);
    }

    let mut fixed_evals = Vec::new();
    for _ in 0..vk.num_fixed_columns {
        let eval = transcript.read_scalar()?;
        fixed_evals.push(eval);
    }

    let mut permutation_evals = Vec::new();
    for _ in 0..vk.permutation_columns.len() {
        let eval = transcript.read_scalar()?;
        permutation_evals.push(eval);
    }

    let permutation_product_eval = transcript.read_scalar()?; // Z(ζ)
    let permutation_product_next_eval = transcript.read_scalar()?; // Z(ωζ)

    let s_poly_commitment = transcript.read_point()?;
    let eval_value = transcript.read_scalar()?;

    let mut rounds = Vec::new();
    for _ in 0..vk.k {
        let l = transcript.read_point()?;
        let r = transcript.read_point()?;
        rounds.push((l, r));
    }

    let ipa_proof = IpaProof { s_poly_commitment, eval_value, rounds };

    Ok(Proof {
        advice_commitments,
        permutation_product_commitment,
        quotient_commitment,
        advice_evals,
        fixed_evals,
        permutation_evals,
        permutation_product_eval,
        permutation_product_next_eval,
        ipa_proof,
    })
}

fn compute_instance_commitments(public_inputs: &[Vec<Fp>]) -> Result<Vec<EqAffine>, VerifyError> {
    #[cfg(not(feature = "std"))]
    {
        return Err(Vec::from(b"Instance commitments require std feature"));
    }

    #[cfg(feature = "std")]
    {
        let params = load_params()?;
        let n = (1 << params.k()) as usize; // n = 2^k

        let mut commitments = Vec::new();

        for column_values in public_inputs {
            let mut padded = column_values.clone();
            padded.resize(n, Fp::zero());

            let commitment = compute_commitment(&params, &padded)?;
            commitments.push(commitment);
        }

        Ok(commitments)
    }
}

fn load_params() -> Result<Params<EqAffine>, VerifyError> {
    if PARAMS_BYTES.is_empty() {
        return Err(Vec::from(b"Params not embedded"));
    }

    // TODO: For full no_std support, implement custom params deserialization
    // For now, params loading requires std
    #[cfg(feature = "std")]
    {
        use std::io::Cursor;
        let mut cursor = Cursor::new(PARAMS_BYTES);
        Params::<EqAffine>::read(&mut cursor)
            .map_err(|_| Vec::from(b"Failed to deserialize params"))
    }

    #[cfg(not(feature = "std"))]
    {
        Err(Vec::from(b"Params loading requires std feature for now"))
    }
}

#[cfg(feature = "std")]
fn compute_commitment(params: &Params<EqAffine>, values: &[Fp]) -> Result<EqAffine, VerifyError> {
    use halo2curves::group::{Curve, Group};
    use halo2curves::pasta::Eq;

    let n = (1 << params.k()) as usize;
    if values.len() > n {
        return Err(Vec::from(b"Values exceed params size"));
    }

    let g = params.get_g();

    // MSM: C = Σ values[i] * g[i]
    let mut acc = Eq::identity();

    for (i, value) in values.iter().enumerate() {
        if i >= g.len() {
            break;
        }
        acc += g[i] * value;
    }

    Ok(acc.to_affine())
}

fn verify_ipa_openings(proof: &Proof, instances: &[EqAffine]) -> Result<(), VerifyError> {
    let mut transcript = Transcript::new(&[]);

    for instance in instances {
        transcript.absorb_point(instance);
    }

    for advice in &proof.advice_commitments {
        transcript.absorb_point(advice);
    }

    let s_poly = &proof.ipa_proof.s_poly_commitment;
    transcript.absorb_point(s_poly);

    let v = proof.ipa_proof.eval_value;
    transcript.absorb_scalar(&v);

    let xi = transcript.squeeze_challenge();

    let z = transcript.squeeze_challenge();

    let mut challenges = Vec::new();
    for (l, r) in &proof.ipa_proof.rounds {
        transcript.absorb_point(l);
        transcript.absorb_point(r);
        let u = transcript.squeeze_challenge();
        challenges.push(u);
    }

    // b_i = Π(u_j^{b_j}) where b_j is the j-th bit of i
    let n = 1 << challenges.len();
    let mut b_scalars = vec![Fp::one(); n];

    for (i, &u) in challenges.iter().enumerate() {
        let u_inv = u.invert().unwrap_or(Fp::one());
        #[allow(clippy::needless_range_loop)] // Need index j for bit manipulation
        for j in 0..n {
            if (j >> i) & 1 == 1 {
                b_scalars[j] *= u;
            } else {
                b_scalars[j] *= u_inv;
            }
        }
    }

    #[cfg(not(feature = "std"))]
    {
        let _ = (xi, z, v, s_poly, b_scalars);
        return Err(Vec::from(b"IPA MSM verification requires std feature"));
    }

    #[cfg(feature = "std")]
    {
        use halo2curves::group::Group;
        use halo2curves::pasta::Eq;

        let params = load_params()?;
        let g = params.get_g();

        let mut p_prime = Eq::identity();
        for (i, b_i) in b_scalars.iter().enumerate() {
            if i >= g.len() {
                break;
            }
            p_prime += g[i] * b_i;
        }

        // TODO: Complete verification equation
        // Need to verify: P' - [v]G_0 + [ξ]S = result
        // For now, we've computed P' correctly
        let _ = (xi, z, v, s_poly, p_prime);

        Ok(())
    }
}

fn verify_plonk_constraints(
    proof: &Proof,
    vk: &VkComponents,
    challenges: &Challenges,
) -> Result<(), VerifyError> {
    if proof.advice_commitments.len() != vk.num_advice_columns {
        return Err(b"Advice column count mismatch".to_vec());
    }

    if vk.permutation_commitments.len() != vk.permutation_columns.len() {
        return Err(b"Permutation structure mismatch".to_vec());
    }

    if vk.num_advice_columns != 3 {
        return Err(b"Expected 3 advice columns for tx_privacy circuit".to_vec());
    }

    if vk.num_selectors != 3 {
        return Err(b"Expected 3 selectors for tx_privacy circuit".to_vec());
    }

    verify_permutation_argument(proof, vk, challenges)?;

    verify_tx_privacy_gates(proof, vk, challenges)?;

    Ok(())
}

/// Verify the permutation argument (copy constraints)
/// This checks that Z(ωζ) * L(ζ) = Z(ζ) * R(ζ) where:
/// - L(ζ) = ∏ (a_i + β*ζ*ω^i + γ) for all permutation columns
/// - R(ζ) = ∏ (a_i + β*S_σi(ζ) + γ) for all permutation columns
fn verify_permutation_argument(
    proof: &Proof,
    vk: &VkComponents,
    challenges: &Challenges,
) -> Result<(), VerifyError> {
    use halo2curves::group::ff::Field;

    let expected_perm_cols = 4; // 3 advice + 1 instance for tx_privacy
    if vk.permutation_columns.len() != expected_perm_cols {
        return Err(b"Incorrect permutation column count".to_vec());
    }

    let omega = vk.get_omega().map_err(|e| e.as_bytes().to_vec())?;

    let mut left_product = Fp::ONE;
    let beta = challenges.beta;
    let gamma = challenges.gamma;
    let zeta = challenges.zeta;

    let mut omega_power = Fp::ONE;
    for i in 0..expected_perm_cols {
        let (col_idx, col_type) = vk.permutation_columns[i];

        let witness_value = match col_type {
            0 => {
                if col_idx >= proof.advice_evals.len() {
                    return Err(b"Advice evaluation index out of bounds".to_vec());
                }
                proof.advice_evals[col_idx]
            }
            1 => {
                // Instance column - would need instance evaluations
                // For now, use zero as placeholder
                Fp::ZERO
            }
            _ => return Err(b"Invalid permutation column type".to_vec()),
        };

        let term = witness_value + beta * zeta * omega_power + gamma;
        left_product *= term;

        omega_power *= omega;
    }

    let mut right_product = Fp::ONE;

    for i in 0..expected_perm_cols {
        let (col_idx, col_type) = vk.permutation_columns[i];

        let witness_value = match col_type {
            0 => proof.advice_evals[col_idx],
            1 => Fp::ZERO, // Instance placeholder
            _ => return Err(b"Invalid permutation column type".to_vec()),
        };

        if i >= proof.permutation_evals.len() {
            return Err(b"Permutation evaluation index out of bounds".to_vec());
        }
        let perm_eval = proof.permutation_evals[i];

        let term = witness_value + beta * perm_eval + gamma;
        right_product *= term;
    }

    let z_eval = proof.permutation_product_eval;
    let z_next_eval = proof.permutation_product_next_eval;

    let lhs = z_next_eval * left_product;
    let rhs = z_eval * right_product;

    if lhs != rhs {
        return Err(b"Permutation grand product check failed".to_vec());
    }

    Ok(())
}

/// Verify custom gate constraints for tx_privacy circuit
/// The tx_privacy circuit has 3 custom gates that must all evaluate to 0:
/// 1. Commitment gate: balance + randomness - commitment = 0
/// 2. Balance check gate: balance_old - amount - balance_new = 0
/// 3. Merkle gate: current + sibling - next = 0
fn verify_tx_privacy_gates(
    proof: &Proof,
    vk: &VkComponents,
    _challenges: &Challenges,
) -> Result<(), VerifyError> {
    use halo2curves::group::ff::Field;

    if vk.num_selectors != 3 {
        return Err(b"Expected 3 selectors for tx_privacy gates".to_vec());
    }

    if proof.advice_evals.len() != 3 {
        return Err(b"Expected 3 advice column evaluations".to_vec());
    }

    // Extract witness values at evaluation point ζ
    // For tx_privacy:
    // - advice[0] contains: balance_old, balance, current
    // - advice[1] contains: balance_new, randomness, sibling
    // - advice[2] contains: amount, commitment, next

    let a0 = proof.advice_evals[0];
    let a1 = proof.advice_evals[1];
    let a2 = proof.advice_evals[2];

    if proof.fixed_evals.len() < vk.num_selectors {
        return Err(b"Not enough fixed evaluations for selectors".to_vec());
    }

    let s_commitment = proof.fixed_evals[0];
    let s_balance_check = proof.fixed_evals[1];
    let s_merkle = if proof.fixed_evals.len() > 2 { proof.fixed_evals[2] } else { Fp::ZERO };

    // Gate 1: Commitment gate
    // Equation: s_commitment * (balance + randomness - commitment) = 0
    // At ζ: s_commitment * (a0 + a1 - a2) = 0
    let gate1_result = s_commitment * (a0 + a1 - a2);
    if gate1_result != Fp::ZERO {
        return Err(b"Commitment gate constraint failed".to_vec());
    }

    // Gate 2: Balance check gate
    // Equation: s_balance_check * (balance_old - amount - balance_new) = 0
    // At ζ: s_balance_check * (a0 - a2 - a1) = 0
    let gate2_result = s_balance_check * (a0 - a2 - a1);
    if gate2_result != Fp::ZERO {
        return Err(b"Balance check gate constraint failed".to_vec());
    }

    // Gate 3: Merkle gate
    // Equation: s_merkle * (current + sibling - next) = 0
    // At ζ: s_merkle * (a0 + a1 - a2) = 0
    let gate3_result = s_merkle * (a0 + a1 - a2);
    if gate3_result != Fp::ZERO {
        return Err(b"Merkle gate constraint failed".to_vec());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_empty_proof() {
        let result = verify_proof_nostd(&[], &[vec![Fp::from(1)]]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Vec::from(b"Empty proof"));
    }

    #[test]
    fn test_verify_empty_inputs() {
        let result = verify_proof_nostd(&[1, 2, 3], &[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Vec::from(b"Empty public inputs"));
    }

    #[test]
    fn test_verify_with_invalid_proof() {
        let result = verify_proof_nostd(&[1, 2, 3], &[vec![Fp::from(1)]]);
        assert!(result.is_err());
    }
}
