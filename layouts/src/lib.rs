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
use binary::Layout;
use binary::Memory;
use binary::MemoryEntry;
use binary::RegisterStates;
use binary::Segment;
use ministark::air::AirConfig;
use ministark::Trace;

pub mod plain;
pub mod starknet;
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

impl<F: Field> CairoAuxInput<F> {
    /// Serialise the auxiliary input so it can be injested by a SHARP verifier
    pub fn serialise_sharp(&self) -> Vec<F> {
        const OFFSET_LOG_N_STEPS: usize = 0;
        const OFFSET_RC_MIN: usize = 1;
        const OFFSET_RC_MAX: usize = 2;
        const OFFSET_LAYOUT_CODE: usize = 3;
        const OFFSET_PROGRAM_BEGIN_ADDR: usize = 4;
        const OFFSET_PROGRAM_STOP_PTR: usize = 5;
        const OFFSET_EXECUTION_BEGIN_ADDR: usize = 6;
        const OFFSET_EXECUTION_STOP_PTR: usize = 7;
        const OFFSET_OUTPUT_BEGIN_ADDR: usize = 8;
        const OFFSET_OUTPUT_STOP_PTR: usize = 9;
        const OFFSET_PEDERSEN_BEGIN_ADDR: usize = 10;
        const OFFSET_PEDERSEN_STOP_PTR: usize = 11;
        const OFFSET_RANGE_CHECK_BEGIN_ADDR: usize = 12;
        const OFFSET_RANGE_CHECK_STOP_PTR: usize = 13;

        const NUM_BASE_VALS: usize = OFFSET_RANGE_CHECK_STOP_PTR + 1;
        let mut base_vals = [None; NUM_BASE_VALS];
        base_vals[OFFSET_LOG_N_STEPS] = Some(self.log_n_steps.into());
        base_vals[OFFSET_RC_MIN] = Some(self.range_check_min.into());
        base_vals[OFFSET_RC_MAX] = Some(self.range_check_max.into());
        base_vals[OFFSET_LAYOUT_CODE] = Some(self.layout_code.into());
        base_vals[OFFSET_PROGRAM_BEGIN_ADDR] = Some(self.program_segment.begin_addr.into());
        base_vals[OFFSET_PROGRAM_STOP_PTR] = Some(self.program_segment.stop_ptr.into());
        base_vals[OFFSET_EXECUTION_BEGIN_ADDR] = Some(self.execution_segment.begin_addr.into());
        base_vals[OFFSET_EXECUTION_STOP_PTR] = Some(self.execution_segment.stop_ptr.into());
        base_vals[OFFSET_OUTPUT_BEGIN_ADDR] = self.output_segment.map(|s| s.begin_addr.into());
        base_vals[OFFSET_OUTPUT_STOP_PTR] = self.output_segment.map(|s| s.stop_ptr.into());
        base_vals[OFFSET_PEDERSEN_BEGIN_ADDR] = self.pedersen_segment.map(|s| s.begin_addr.into());
        base_vals[OFFSET_PEDERSEN_STOP_PTR] = self.pedersen_segment.map(|s| s.stop_ptr.into());
        base_vals[OFFSET_RANGE_CHECK_BEGIN_ADDR] = self.rc_segment.map(|s| s.begin_addr.into());
        base_vals[OFFSET_RANGE_CHECK_STOP_PTR] = self.rc_segment.map(|s| s.stop_ptr.into());

        match Layout::from_sharp_code(self.layout_code) {
            Layout::Starknet => {
                const OFFSET_ECDSA_BEGIN_ADDR: usize = 14;
                const OFFSET_ECDSA_STOP_PTR: usize = 15;
                const OFFSET_BITWISE_BEGIN_ADDR: usize = 16;
                const OFFSET_BITWISE_STOP_ADDR: usize = 17;
                const OFFSET_EC_OP_BEGIN_ADDR: usize = 18;
                const OFFSET_EC_OP_STOP_ADDR: usize = 19;
                const OFFSET_POSEIDON_BEGIN_ADDR: usize = 20;
                const OFFSET_POSEIDON_STOP_PTR: usize = 21;
                const OFFSET_PUBLIC_MEMORY_PADDING_ADDR: usize = 22;
                const OFFSET_PUBLIC_MEMORY_PADDING_VALUE: usize = 23;
                const OFFSET_N_PUBLIC_MEMORY_PAGES: usize = 24;
                const OFFSET_PUBLIC_MEMORY: usize = 25;

                // const NUM_VALS: usize = OFFSET_PUBLIC_MEMORY + 1;
                // let vals =
                // TODO:
                base_vals.map(|v| v.unwrap()).to_vec()
            }
            _ => unimplemented!(),
        }
    }
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
