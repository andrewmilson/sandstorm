use std::iter::zip;

use binary::PoseidonInstance;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
pub mod params;
pub mod periodic;
use self::params::MDS_MATRIX;
use self::params::NUM_FULL_ROUNDS;
use self::params::NUM_PARTIAL_ROUNDS;
use self::params::PARTIAL_ROUND_KEYS;
use self::params::ROUND_KEYS;
use crate::utils::Mat3x3;
use ark_ff::Field;
use num_bigint::BigUint;
use std::ops::Mul;

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: PoseidonInstance,
    pub input0: Fp,
    pub input1: Fp,
    pub input2: Fp,
    pub output0: Fp,
    pub output1: Fp,
    pub output2: Fp,
}

impl InstanceTrace {
    pub fn new(instance: PoseidonInstance) -> Self {
        let input0 = Fp::from(BigUint::from(instance.input0));
        let input1 = Fp::from(BigUint::from(instance.input1));
        let input2 = Fp::from(BigUint::from(instance.input2));

        let [output0, output1, output2] = permute([input0, input1, input2]);

        Self {
            instance,
            input0,
            input1,
            input2,
            output0,
            output1,
            output2,
        }
    }
}

/// Computes the Poseidon hash using StarkWare's parameters. Source:
/// <https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/starkadperm_x5_256_3.sage>
fn permute(input: [Fp; 3]) -> [Fp; 3] {
    let mut state = input;
    let mut round = 0;
    // first full rounds
    for _ in 0..NUM_FULL_ROUNDS / 2 {
        // round constants, nonlinear layer, matrix multiplication
        for (s, round_key) in zip(&mut state, ROUND_KEYS[round]) {
            *s = (*s + round_key).pow([3]);
        }
        state = Mat3x3(MDS_MATRIX) * state;
        round += 1;
    }
    // Middle partial rounds
    for _ in 0..NUM_PARTIAL_ROUNDS {
        // round constants, nonlinear layer, matrix multiplication
        for (s, round_key) in zip(&mut state, ROUND_KEYS[round]) {
            *s += round_key;
        }
        state[2] = state[2].pow([3]);
        state = Mat3x3(MDS_MATRIX) * state;
        round += 1;
    }
    // last full rounds
    for _ in 0..NUM_FULL_ROUNDS / 2 {
        // round constants, nonlinear layer, matrix multiplication
        for (s, round_key) in zip(&mut state, ROUND_KEYS[round]) {
            *s = (*s + round_key).pow([3]);
        }
        state = Mat3x3(MDS_MATRIX) * state;
        round += 1;
    }
    state
}

// Source: <https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/poseidonperm_x3_64_24_optimized.sage>
fn calc_optimized_partial_round_keys() -> [[Fp; 3]; NUM_PARTIAL_ROUNDS] {
    let mds_matrix_transpose = Mat3x3(MDS_MATRIX).transpose();
    let mds_matrix_transpose_inv = mds_matrix_transpose.inverse().unwrap();
    // Start moving round constants up
    // Calculate c_i' = M^(-1) * c_(i+1)
    // Split c_i': Add c_i'[0] AFTER the S-box, add the rest to c_i
    // I.e.: Store c_i'[0] for each of the partial rounds, and make c_i = c_i
    // + c_i' (where now c_i'[0] = 0) num_rounds = R_F + R_P
    // R_f = R_F / 2
    let mut res = PARTIAL_ROUND_KEYS;
    for i in (0..NUM_PARTIAL_ROUNDS - 1).rev() {
        println!("{i}");
        let c_i_prime = mds_matrix_transpose_inv * res[i + 1];
        res[i][1] += c_i_prime[1];
        res[i][2] += c_i_prime[2];
        res[i + 1] = [c_i_prime[0], Fp::ZERO, Fp::ZERO];
    }
    res
}

#[cfg(test)]
mod tests {
    use crate::poseidon::permute;
    use ark_ff::MontFp as Fp;
    use ark_ff::Field;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;

    #[test]
    fn zero_hash_matches_starkware_example() {
        // Example from https://github.com/starkware-industries/poseidon
        let expected = [
            Fp!("3446325744004048536138401612021367625846492093718951375866996507163446763827"),
            Fp!("1590252087433376791875644726012779423683501236913937337746052470473806035332"),
            Fp!("867921192302518434283879514999422690776342565400001269945778456016268852423"),
        ];

        assert_eq!(expected, permute([Fp::ZERO, Fp::ZERO, Fp::ZERO]));
    }
}
