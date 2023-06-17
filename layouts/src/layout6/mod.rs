//! Matches Layout 6 from StarkWare's open source verifier
//! <https://github.com/starkware-libs/starkex-contracts/blob/master/evm-verifier/solidity/contracts/cpu/layout6/CpuConstraintPoly.sol#L794>

mod air;
mod trace;

pub use air::AirConfig;
use builtins::{utils::curve::StarkwareCurve, pedersen};
pub use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
pub use trace::ExecutionTrace;
use ark_ec::models::short_weierstrass::SWCurveConfig;

// must be a power-of-two
pub const CYCLE_HEIGHT: usize = 16;
pub const PUBLIC_MEMORY_STEP: usize = 8;
pub const MEMORY_STEP: usize = 2;
pub const RANGE_CHECK_STEP: usize = 4;
pub const DILUTED_CHECK_STEP: usize = 8;

/// How many cycles per pedersen hash
pub const PEDERSEN_BUILTIN_RATIO: usize = 32;

/// How many cycles per 128 bit range check
pub const RANGE_CHECK_BUILTIN_RATIO: usize = 16;
pub const RANGE_CHECK_BUILTIN_PARTS: usize = 8;

pub const NUM_BASE_COLUMNS: usize = 9;
pub const NUM_EXTENSION_COLUMNS: usize = 1;

pub const DILUTED_CHECK_N_BITS: usize = 16;
pub const DILUTED_CHECK_SPACING: usize = 4;

pub const BITWISE_RATIO: usize = 64;

pub const ECDSA_BUILTIN_RATIO: usize = 2048;
pub const ECDSA_BUILTIN_REPETITIONS: usize = 1;
pub const EC_OP_BUILTIN_RATIO: usize = 1024;
pub const EC_OP_SCALAR_HEIGHT: usize = 256;
pub const EC_OP_N_BITS: usize = 252;
// TODO: take from curve config
pub const ECDSA_SIG_CONFIG_ALPHA: Fp = StarkwareCurve::COEFF_A;
pub const ECDSA_SIG_CONFIG_BETA: Fp = StarkwareCurve::COEFF_B;
pub const ECDSA_SIG_CONFIG_SHIFT_POINT_X: Fp = pedersen::constants::P0.x;
pub const ECDSA_SIG_CONFIG_SHIFT_POINT_Y: Fp = pedersen::constants::P0.y;

pub const POSEIDON_RATIO: usize = 32;
pub const POSEIDON_M: usize = 3;
pub const POSEIDON_ROUNDS_FULL: usize = 8;
pub const POSEIDON_ROUNDS_PARTIAL: usize = 83;
