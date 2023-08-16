#![feature(
    allocator_api,
    slice_flatten,
    array_windows,
    array_chunks,
    slice_as_chunks
)]

extern crate alloc;

use ark_ff::Field;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterStates;
use ministark::air::AirConfig;
use ministark::challenges::Challenges;
use ministark::hints::Hints;
use ministark::Trace;

pub mod plain;
pub mod recursive;
pub mod starknet;
pub mod utils;

pub trait CairoAirConfig: AirConfig {
    /// Public memory permutation challenges
    /// Output is of the form: (z, alpha)
    fn public_memory_challenges(challenges: &Challenges<Self::Fq>) -> (Self::Fq, Self::Fq);

    /// Public memory quotient
    // TODO: docs
    fn public_memory_quotient(hints: &Hints<Self::Fq>) -> Self::Fq;
}

#[derive(Debug)]
pub struct CairoWitness<F: Field> {
    air_private_input: AirPrivateInput,
    register_states: RegisterStates,
    memory: Memory<F>,
}

impl<F: Field> CairoWitness<F> {
    pub fn new(
        air_private_input: AirPrivateInput,
        register_states: RegisterStates,
        memory: Memory<F>,
    ) -> Self {
        Self {
            air_private_input,
            register_states,
            memory,
        }
    }
}

pub trait CairoTrace: Trace {
    fn new(
        program: CompiledProgram<Self::Fp>,
        public_input: AirPublicInput<Self::Fp>,
        witness: CairoWitness<Self::Fp>,
    ) -> Self;
}
