use gpu_poly::GpuVec;
use gpu_poly::prelude::PageAlignedAllocator;
use ministark::Matrix;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use ministark::Trace;
use ark_ff::Zero;
use strum::IntoEnumIterator;
use crate::Flag;
use crate::binary::NUM_FLAGS;
use crate::binary::CompiledProgram;
use crate::binary::Memory;
use crate::binary::RegisterStates;
use cairo_rs::vm::trace::trace_entry::RelocatedTraceEntry as RegisterState;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub struct ExecutionTrace {
    flags_virtual_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
}

impl ExecutionTrace {
    fn new(memory: Memory, register_states: RegisterStates, program: CompiledProgram) -> Self {
        let num_cycles = register_states.len().next_power_of_two();

        let mut flags_virtual_column = Vec::new_in(PageAlignedAllocator);
        flags_virtual_column.resize(num_cycles * NUM_FLAGS, Fp::zero());

        for (i, RegisterState { pc, .. }) in register_states.iter().enumerate() {
            let word = memory[*pc].unwrap();
            assert!(!word.get_flag(Flag::Zero));

            // TODO: maybe bit sift all flags
            let flags_offset = i * NUM_FLAGS;
            let virtual_row = &mut flags_virtual_column[flags_offset..flags_offset + NUM_FLAGS];
            for flag in Flag::iter() {
                virtual_row[flag as usize] = word.get_flag_prefix(flag).into();
            }
        }

        let base_trace = Matrix::new(vec![flags_virtual_column.to_vec_in(PageAlignedAllocator)]);

        ExecutionTrace {
            flags_virtual_column,
            base_trace,
        }
    }

    pub fn from_file(program_path: &PathBuf, trace_path: &PathBuf, memory_path: &PathBuf) -> Self {
        let file = File::open(program_path).expect("program file not found");
        let reader = BufReader::new(file);
        let compiled_program: CompiledProgram = serde_json::from_reader(reader).unwrap();
        #[cfg(debug_assertions)]
        compiled_program.validate();

        let register_states = RegisterStates::from_file(trace_path);
        let memory = Memory::from_file(memory_path);

        Self::new(memory, register_states, compiled_program)
    }
}

impl Trace for ExecutionTrace {
    const NUM_BASE_COLUMNS: usize = 1;
    type Fp = Fp;
    type Fq = Fp;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }
}
