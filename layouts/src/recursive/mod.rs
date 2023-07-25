//! Matches `bitwise` layout from StarkWare's open source verifier
//! <https://github.com/starkware-libs/cairo-lang/blob/361fe32d5930db340ea78fe05aedfe706f6c9405/src/starkware/cairo/lang/instances.py#L157>

//TODO This is still the starknet layout and has to be updated to the recursive parameters.

pub mod air;
pub mod trace;

pub use air::AirConfig;
pub use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
pub use trace::ExecutionTrace;

// TODO Are these correct?
// must be a power-of-two
pub const CYCLE_HEIGHT: usize = 16;
pub const PUBLIC_MEMORY_STEP: usize = 8;
pub const MEMORY_STEP: usize = 2;
pub const RANGE_CHECK_STEP: usize = 4;
pub const DILUTED_CHECK_STEP: usize = 1; //TODO is that correct?

/// How many cycles per pedersen hash
pub const PEDERSEN_BUILTIN_RATIO: usize = 128;

/// How many cycles per 128 bit range check
pub const RANGE_CHECK_BUILTIN_RATIO: usize = 8;
pub const RANGE_CHECK_BUILTIN_PARTS: usize = 8;

pub const NUM_BASE_COLUMNS: usize = 9;
pub const NUM_EXTENSION_COLUMNS: usize = 1;

pub const DILUTED_CHECK_N_BITS: usize = 16;
pub const DILUTED_CHECK_SPACING: usize = 4;

pub const BITWISE_RATIO: usize = 8;
