#![feature(
    buf_read_has_data_left,
    allocator_api,
    array_chunks,
    slice_flatten,
    array_windows
)]
mod air;
mod binary;
pub mod prover;
pub mod trace;
mod utils;
