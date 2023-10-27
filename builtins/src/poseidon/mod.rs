//! Poseidon builtin. Reference implementation (used by StarkWare):
//! <https://github.com/CryptoExperts/poseidon>

use std::iter::zip;
use ark_ff::MontFp as Fp;
use binary::PoseidonInstance;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
pub mod params;
pub mod periodic;
use self::params::FULL_ROUND_KEYS_1ST_HALF;
use self::params::MDS_MATRIX;
use self::params::NUM_FULL_ROUNDS;
use self::params::NUM_PARTIAL_ROUNDS;
use self::params::PARTIAL_ROUND_KEYS;
use self::params::ROUND_KEYS;
use crate::poseidon::params::FULL_ROUND_KEYS_2ND_HALF;
use crate::poseidon::params::PARTIAL_ROUND_KEYS_OPTIMIZED;
use crate::utils::Mat3x3;
use ark_ff::Field;
use num_bigint::BigUint;
use ruint::aliases::U256;

pub fn poseidon_hash_single(x: Fp) -> Fp {
    let instance = PoseidonInstance {
        index: 0,
        input0: U256::from_limbs(x.0 .0),
        input1: U256::from(0),
        input2: U256::from(0),
    };
    let result = InstanceTrace::new(instance);

    result.output0
}

pub fn poseidon_hash(x: Fp, y: Fp) -> Fp {
    let instance = PoseidonInstance {
        index: 0,
        input0: U256::from_limbs(x.0 .0),
        input1: U256::from_limbs(y.0 .0),
        input2: U256::from(0),
    };
    let result = InstanceTrace::new(instance);

    result.output0
}

pub fn poseidon_hash_many(elements: Vec<Fp>) -> Fp {
    let instance = PoseidonInstance {
        index: 0,
        input0: U256::from(0),
        input1: U256::from(0),
        input2: U256::from(0),
    };
    let mut state = InstanceTrace::new(instance);

    let mut i = 0;
    loop {
        if i == elements.len() {
            let result = InstanceTrace::new(PoseidonInstance {
                index: state.instance.index,
                input0: U256::from_limbs((state.output0 + Fp::from(1)).0 .0),
                input1: U256::from_limbs(state.output1.0 .0),
                input2: U256::from_limbs(state.output2.0 .0),
            });
            return result.output0;
        } else if i == elements.len() - 1 {
            let result = InstanceTrace::new(PoseidonInstance {
                index: state.instance.index,
                input0: U256::from_limbs((state.output0 + elements[i]).0 .0),
                input1: U256::from_limbs((state.output1 + Fp::from(1)).0 .0),
                input2: U256::from_limbs(state.output2.0 .0),
            });
            return result.output0;
        } else {
            state = InstanceTrace::new(PoseidonInstance {
                index: state.instance.index,
                input0: U256::from_limbs((state.output0 + elements[i]).0 .0),
                input1: U256::from_limbs((state.output1 + elements[i + 1]).0 .0),
                input2: U256::from_limbs(state.output2.0 .0),
            });
        }
        i += 2;
    }
}

/// Stores the states within a full round
#[derive(Clone, Copy, Debug)]
pub struct FullRoundStates {
    /// State after adding round keys
    pub after_add_round_keys: [Fp; 3],
    /// State after applying the S-Box function
    pub after_apply_s_box: [Fp; 3],
    /// State after multiplication by the MDS matrix
    pub after_mds_mul: [Fp; 3],
}

/// Stores the states within a partial round
#[derive(Clone, Copy, Debug)]
pub struct PartialRoundStates {
    /// State after adding round keys
    pub after_add_round_key: Fp,
}

#[derive(Clone, Debug)]
pub struct PartialRoundsState {
    pub margin_full_to_partial0: Fp,
    pub margin_full_to_partial1: Fp,
    pub margin_full_to_partial2: Fp,
}

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: PoseidonInstance,
    pub input0: Fp,
    pub input1: Fp,
    pub input2: Fp,
    pub output0: Fp,
    pub output1: Fp,
    pub output2: Fp,
    pub full_round_states_1st_half: Vec<FullRoundStates>,
    pub full_round_states_2nd_half: Vec<FullRoundStates>,
    pub partial_round_states: Vec<PartialRoundStates>,
    // pub partial_rounds_state: PartialRoundsState,
}

impl InstanceTrace {
    pub fn new(instance: PoseidonInstance) -> Self {
        let input0 = Fp::from(BigUint::from(instance.input0));
        let input1 = Fp::from(BigUint::from(instance.input1));
        let input2 = Fp::from(BigUint::from(instance.input2));

        let state = [input0, input1, input2];
        let full_round_states_1st_half =
            gen_half_full_round_states(state, FULL_ROUND_KEYS_1ST_HALF);

        // set state to last state of 1st full rounds (aka after the MDS multiplication)
        let mut state = full_round_states_1st_half.last().unwrap().after_mds_mul;

        let mut partial_round_states = Vec::new();
        for round_key in PARTIAL_ROUND_KEYS_OPTIMIZED {
            // Source: https://github.com/CryptoExperts/poseidon/blob/main/sage/poseidon_variant.sage#L127
            state[2] += round_key;
            partial_round_states.push(PartialRoundStates {
                after_add_round_key: state[2],
            });
            state[2] = state[2].pow([3]);
            state = Mat3x3(MDS_MATRIX) * state;
        }

        // modify first full round keys to optimized variant
        // TODO: this is a bit random having these constants here.
        // TODO: improve docs and document optimized version. Poseidon paper section B?
        let mut full_round_keys_2nd_half = FULL_ROUND_KEYS_2ND_HALF;
        full_round_keys_2nd_half[0] = [
            Fp!("2841653098167170594677968593255398661749780759922623066311132183067080032372"),
            Fp!("3013664908435951456462052676857400233978317167153628607151632758126998548956"),
            Fp!("1580909581709481477620907470438960344056357690169203419381231226301063390430"),
        ];

        let full_round_states_2nd_half =
            gen_half_full_round_states(state, full_round_keys_2nd_half);
        // set state to last state of the last round (aka after the MDS multiplication)
        let final_state = full_round_states_2nd_half.last().unwrap().after_mds_mul;
        assert_eq!(permute([input0, input1, input2]), final_state);
        let [output0, output1, output2] = final_state;

        Self {
            instance,
            input0,
            input1,
            input2,
            output0,
            output1,
            output2,
            full_round_states_1st_half,
            full_round_states_2nd_half,
            partial_round_states,
        }
    }
}

fn gen_half_full_round_states(
    mut state: [Fp; 3],
    round_keys: [[Fp; 3]; NUM_FULL_ROUNDS / 2],
) -> Vec<FullRoundStates> {
    let mut rounds = Vec::new();
    for rks in round_keys {
        // keep track of the state after adding round keys
        for (s, rk) in zip(&mut state, rks) {
            *s += rk;
        }
        let after_add_round_keys = state;

        // keep track of the state after applying the S-Box function
        for s in &mut state {
            *s = s.pow([3]);
        }
        let after_apply_s_box = state;

        // keep track of the state after multiplying my the MDS matrix
        state = Mat3x3(MDS_MATRIX) * state;
        let after_mds_mul = state;

        // append round
        rounds.push(FullRoundStates {
            after_add_round_keys,
            after_apply_s_box,
            after_mds_mul,
        })
    }
    rounds
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

/// Computes the Poseidon hash using StarkWare's parameters. Source:
/// <https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/starkadperm_x5_256_3.sage>
// TODO: docs for optimized version
fn _permute_optimized(input: [Fp; 3]) -> [Fp; 3] {
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

    // partial rounds - initial constants addition
    for (s, round_key) in zip(&mut state, ROUND_KEYS[round]) {
        *s += round_key
    }
    todo!();

    // // last full rounds
    // for _ in 0..NUM_FULL_ROUNDS / 2 {
    //     // round constants, nonlinear layer, matrix multiplication
    //     for (s, round_key) in zip(&mut state, ROUND_KEYS[round]) {
    //         *s = (*s + round_key).pow([3]);
    //     }
    //     state = Mat3x3(MDS_MATRIX) * state;
    //     round += 1;
    // }
    // state
}

// This is mentioned in section B of the Poseidon paper. Sources:
// * <https://eprint.iacr.org/2019/458.pdf>
// * <https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/poseidonperm_x3_64_24_optimized.sage>
// * <https://github.com/CryptoExperts/poseidon/blob/main/sage/poseidon_variant.sage#L3>
// TODO: consider removing
fn _calc_optimized_partial_round_keys() -> [[Fp; 3]; NUM_PARTIAL_ROUNDS] {
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
        let c_i_prime = mds_matrix_transpose_inv * res[i + 1];
        res[i][1] += c_i_prime[1];
        res[i][2] += c_i_prime[2];
        res[i + 1] = [c_i_prime[0], Fp::ZERO, Fp::ZERO];
    }
    todo!()
}

#[cfg(test)]
mod tests {
    use crate::poseidon::{permute, poseidon_hash_many};
    use ark_ff::BigInt;
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

    #[test]
    fn poseidon_hash_many_3_example() {
        let elements = vec![Fp!("0"), Fp!("0"), Fp!("0")];

        let expected = BigInt::new([
            14465169880788163794,
            3725699649495491964,
            13957675534445258432,
            241034705846384105,
        ]);

        assert_eq!(expected, poseidon_hash_many(elements).0);
    }

    #[test]
    fn poseidon_hash_many_4_example() {
        let elements = vec![Fp!("0"), Fp!("0"), Fp!("0"), Fp!("0")];

        let expected = BigInt::new([
            8177194887955547932,
            6869494578799689646,
            3880460167861838970,
            331313552213051804,
        ]);

        assert_eq!(expected, poseidon_hash_many(elements).0);
    }

    #[test]
    fn poseidon_hash_many_5_example() {
        let elements = vec![Fp!("0"), Fp!("0"), Fp!("0"), Fp!("0"), Fp!("0")];

        let expected = BigInt::new([
            14872330746557636911,
            10787657887407825984,
            8559225264217750252,
            304103888309894648,
        ]);

        assert_eq!(expected, poseidon_hash_many(elements).0);
    }

    #[test]
    fn poseidon_hash_many_9_example() {
        let elements = vec![
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
            Fp!("0"),
        ];

        let expected = BigInt::new([
            6218683884595264045,
            16033324973008454317,
            15358347862863079556,
            557108717180864526,
        ]);

        assert_eq!(expected, poseidon_hash_many(elements).0);
    }
}
