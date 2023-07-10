//! Claim prover and verifier compatible with Starkware's SHARed Prover (SHARP)

pub mod channel;
pub mod input;
pub mod prover;
pub mod utils;
pub mod verifier;

use crate::base;
use binary::AirPublicInput;
use binary::CompiledProgram;
use layouts::CairoTrace;
use layouts::SharpAirConfig;
use ministark::air::AirConfig;
use ministark::challenges::Challenges;
use ministark::hints::Hints;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use sha2::Digest;
use std::ops::Deref;

/// Wrapper around a base Cairo claim that has a custom implementation of proof
/// generation and validation to match StarkWare's prover and verifier (SHARP)
pub struct CairoClaim<
    A: SharpAirConfig<Fp = Fp, Fq = Fp>,
    T: CairoTrace<Fp = Fp, Fq = Fp>,
    D: Digest,
>(base::CairoClaim<Fp, A, T, D>);

impl<A: SharpAirConfig<Fp = Fp, Fq = Fp>, T: CairoTrace<Fp = Fp, Fq = Fp>, D: Digest>
    CairoClaim<A, T, D>
{
    pub fn new(program: CompiledProgram<Fp>, air_public_input: AirPublicInput<Fp>) -> Self {
        Self(base::CairoClaim::new(program, air_public_input))
    }
}

impl<A: SharpAirConfig<Fp = Fp, Fq = Fp>, T: CairoTrace<Fp = Fp, Fq = Fp>, D: Digest> Deref
    for CairoClaim<A, T, D>
{
    type Target = base::CairoClaim<Fp, A, T, D>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
