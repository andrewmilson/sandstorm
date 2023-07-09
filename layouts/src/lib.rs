#![feature(
    allocator_api,
    slice_flatten,
    array_windows,
    array_chunks,
    slice_as_chunks
)]

extern crate alloc;

use ark_ff::Field;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use binary::CairoAuxInput;
use binary::CompiledProgram;
use binary::Layout;
use binary::Memory;
use binary::MemoryEntry;
use binary::RegisterStates;
use binary::Segment;
use ministark::Trace;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;

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

    fn auxiliary_input(&self) -> CairoAuxInput<Self::Fp>;
}
