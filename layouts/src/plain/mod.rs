//! Uses the mimimum set of constraints for proving cairo prorams (no builtins)
//! <https://github.com/starkware-libs/starkex-contracts/blob/master/evm-verifier/solidity/contracts/cpu/layout6/CpuConstraintPoly.sol#L794>

mod air;
mod trace;

pub use air::AirConfig;
pub use trace::ExecutionTrace;

// must be a power-of-two
pub const CYCLE_HEIGHT: usize = 16;
pub const PUBLIC_MEMORY_STEP: usize = 8;
pub const MEMORY_STEP: usize = 2;
pub const RANGE_CHECK_STEP: usize = 4;

pub const NUM_BASE_COLUMNS: usize = 5;
pub const NUM_EXTENSION_COLUMNS: usize = 1;
