#![feature(
    buf_read_has_data_left,
    allocator_api,
    array_chunks,
    slice_flatten,
    array_windows,
    slice_as_chunks
)]
pub mod air;
pub mod binary;
pub mod prover;
pub mod trace;
mod utils;

// use more performant global allocator
#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
