#![feature(async_fn_in_trait, allocator_api)]

extern crate alloc;

pub mod prover;
use ark_ff::PrimeField;
pub use binary;
pub use layouts;
use layouts::CairoAirConfig;
use layouts::CairoExecutionTrace;
use ministark::Prover;

pub trait CairoProver: Prover
where
    <Self as Prover>::Fp: PrimeField,
    <Self as Prover>::AirConfig: CairoAirConfig,
    <Self as Prover>::Trace: CairoExecutionTrace,
{
}

impl<
        F: PrimeField,
        A: CairoAirConfig<Fp = F>,
        T: CairoExecutionTrace,
        P: Prover<Fp = F, AirConfig = A, Trace = T>,
    > CairoProver for P
{
}
