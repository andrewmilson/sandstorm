//! Matches Layout 6 from StarkWare's open source verifier
//! <https://github.com/starkware-libs/starkex-contracts/blob/master/evm-verifier/solidity/contracts/cpu/layout6/CpuConstraintPoly.sol#L794>

mod air;
mod trace;

pub use air::AirConfig;
pub use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ark_ff::MontFp as Fp;
pub use trace::ExecutionTrace;
use ark_ff::Field;

// must be a power-of-two
pub const CYCLE_HEIGHT: usize = 16;
pub const PUBLIC_MEMORY_STEP: usize = 8;
pub const MEMORY_STEP: usize = 2;
pub const RANGE_CHECK_STEP: usize = 4;

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
pub const ECDSA_SIG_CONFIG_ALPHA: Fp = Fp::ONE;
pub const ECDSA_SIG_CONFIG_BETA: Fp =
    Fp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");
pub const ECDSA_SIG_CONFIG_SHIFT_POINT_X: Fp =
    Fp!("2089986280348253421170679821480865132823066470938446095505822317253594081284");
pub const ECDSA_SIG_CONFIG_SHIFT_POINT_Y: Fp =
    Fp!("1713931329540660377023406109199410414810705867260802078187082345529207694986");
