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
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterStates;
use ministark::air::AirConfig;
use ministark::Trace;

pub mod layout6;
pub mod plain;
pub mod utils;

// Section 9.2 https://eprint.iacr.org/2021/1063.pdf
// TODO: might need to have an execution info per layout
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct ExecutionInfo<Fp: Field> {
    pub initial_ap: Fp,
    pub initial_pc: Fp,
    pub final_ap: Fp,
    pub final_pc: Fp,
    pub range_check_min: usize,
    pub range_check_max: usize,
    pub public_memory: Vec<(usize, Fp)>,
    pub public_memory_padding_address: usize,
    pub public_memory_padding_value: Fp,
}

pub trait CairoAirConfig: AirConfig<PublicInputs = ExecutionInfo<<Self as AirConfig>::Fp>>
where
    Self::Fp: PrimeField,
{
}

impl<F: PrimeField, T: AirConfig<Fp = F, PublicInputs = ExecutionInfo<F>>> CairoAirConfig for T {}

pub trait CairoExecutionTrace: Trace {
    fn new(
        program: CompiledProgram,
        air_public_input: AirPublicInput,
        air_private_input: AirPrivateInput,
        memory: Memory<Self::Fp>,
        register_states: RegisterStates,
    ) -> Self;

    fn execution_info(&self) -> ExecutionInfo<Self::Fp>;
}
