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
use binary::CairoAuxInput;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterStates;
use ministark::Trace;

pub mod plain;
pub mod starknet;
pub mod utils;

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
        program: CompiledProgram,
        public_input: AirPublicInput,
        witness: CairoWitness<Self::Fp>,
    ) -> Self;
}
