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
use binary::MemoryEntry;
use binary::RegisterStates;
use binary::Segment;
use ministark::air::AirConfig;
use ministark::Trace;

pub mod layout6;
pub mod plain;
pub mod utils;

// Section 9.2 https://eprint.iacr.org/2021/1063.pdf
// TODO: might need to have an type info per layout
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct CairoAuxInput<F: Field> {
    pub log_n_steps: u32,
    pub layout_code: u64,
    pub initial_ap: F,
    pub initial_pc: F,
    pub final_ap: F,
    pub final_pc: F,
    pub range_check_min: u16,
    pub range_check_max: u16,
    pub public_memory_padding: MemoryEntry<F>,
    pub program_segment: Segment,
    pub execution_segment: Segment,
    pub output_segment: Option<Segment>,
    pub pedersen_segment: Option<Segment>,
    pub rc_segment: Option<Segment>,
    pub ecdsa_segment: Option<Segment>,
    pub bitwise_segment: Option<Segment>,
    pub ec_op_segment: Option<Segment>,
    pub poseidon_segment: Option<Segment>,
    // TODO: understand better
    // pub n_public_memory_pages: Option<u32>,
    pub public_memory: Vec<MemoryEntry<F>>,
}

// Only implemented for PrimeFields
pub trait CairoAirConfig: AirConfig<PublicInputs = CairoAuxInput<<Self as AirConfig>::Fp>> {}

impl<F: PrimeField, T: AirConfig<Fp = F, PublicInputs = CairoAuxInput<F>>> CairoAirConfig for T {}

pub trait CairoExecutionTrace: Trace {
    fn new(
        program: CompiledProgram,
        air_public_input: AirPublicInput,
        air_private_input: AirPrivateInput,
        memory: Memory<Self::Fp>,
        register_states: RegisterStates,
    ) -> Self;

    fn auxiliary_input(&self) -> CairoAuxInput<Self::Fp>;
}
