// TODO: make an interface for layouts
// pub trait Layout {
//     const CYCLE_HEIGHT: usize;
//     const PUBLIC_MEMORY_STEP: usize;
//     const MEMORY_STEP: usize;
//     const RANGE_CHECK_STEP: usize;
// }

use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;

pub mod layout6;
pub mod utils;

// Section 9.2 https://eprint.iacr.org/2021/1063.pdf
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct ExecutionInfo {
    pub initial_ap: Fp,
    pub initial_pc: Fp,
    pub final_ap: Fp,
    pub final_pc: Fp,
    pub range_check_min: usize,
    pub range_check_max: usize,
    pub public_memory: Vec<(usize, Fp)>,
    pub public_memory_padding_address: usize,
    pub public_memory_padding_value: Fp,
}
