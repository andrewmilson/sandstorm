//! Claim prover and verifier compatible with Starkware's SHARed Prover (SHARP)

mod channel;
mod prover;
mod utils;
mod verifier;

use crate::base;
use ark_ff::PrimeField;
use binary::AirPublicInput;
use binary::CompiledProgram;
use layouts::CairoTrace;
use ministark::air::AirConfig;
use ministark_gpu::GpuFftField;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use sha2::Digest;
use std::ops::Deref;

/// Wrapper around a base Cairo claim that has a custom implementation of proof
/// generation and validation to match StarkWare's prover and verifier (SHARP)
pub struct CairoClaim<A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest>(
    base::CairoClaim<Fp, A, T, D>,
);

impl<A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest> CairoClaim<Fp, A, T, D> {
    pub fn new(program: CompiledProgram, air_public_input: AirPublicInput) -> Self {
        Self(base::CairoClaim::new(program, air_public_input))
    }
}

impl<A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest> Deref for CairoClaim<A, T, D> {
    type Target = base::CairoClaim<Fp, A, T, D>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
