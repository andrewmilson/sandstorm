use std::iter::zip;

use binary::PoseidonInstance;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
pub mod params;
pub mod periodic;
use ark_ff::Field;
use num_bigint::BigUint;

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
    for _ in 0..params::NUM_FULL_ROUNDS / 2 {
        // round constants, nonlinear layer, matrix multiplication
        for (s, round_key) in zip(&mut state, params::ROUND_KEYS[round]) {
            *s = (*s + round_key).pow([3]);
        }
        state = mds_mul(state);
        round += 1;
    }
    // Middle partial rounds
    for _ in 0..params::NUM_PARTIAL_ROUNDS {
        // round constants, nonlinear layer, matrix multiplication
        for (s, round_key) in zip(&mut state, params::ROUND_KEYS[round]) {
            *s += round_key;
        }
        state[2] = state[2].pow([3]);
        state = mds_mul(state);
        round += 1;
    }
    // last full rounds
    for _ in 0..params::NUM_FULL_ROUNDS / 2 {
        // round constants, nonlinear layer, matrix multiplication
        for (s, round_key) in zip(&mut state, params::ROUND_KEYS[round]) {
            *s = (*s + round_key).pow([3]);
        }
        state = mds_mul(state);
        round += 1;
    }
    state
}

/// Multiplies a vector by the MDS matrix
fn mds_mul(v: [Fp; 3]) -> [Fp; 3] {
    [
        v[0] * params::MDS_MATRIX[0][0]
            + v[1] * params::MDS_MATRIX[0][1]
            + v[2] * params::MDS_MATRIX[0][2],
        v[0] * params::MDS_MATRIX[1][0]
            + v[1] * params::MDS_MATRIX[1][1]
            + v[2] * params::MDS_MATRIX[1][2],
        v[0] * params::MDS_MATRIX[2][0]
            + v[1] * params::MDS_MATRIX[2][1]
            + v[2] * params::MDS_MATRIX[2][2],
    ]
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
