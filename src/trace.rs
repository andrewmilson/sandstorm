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
    flags_column: GpuVec<Fp>,
    npc_column: GpuVec<Fp>,
    range_check_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
}

impl ExecutionTrace {
    fn new(memory: Memory, register_states: RegisterStates, program: CompiledProgram) -> Self {
        let num_cycles = register_states.len().next_power_of_two();
        let cycle_height = 16;
        let trace_len = num_cycles * cycle_height;

        let mut flags_column = Vec::new_in(PageAlignedAllocator);
        flags_column.resize(trace_len, Fp::zero());

        let mut zeros_column = Vec::new_in(PageAlignedAllocator);
        zeros_column.resize(trace_len, Fp::zero());

        // TODO: npc?
        let mut npc_column = Vec::new_in(PageAlignedAllocator);
        npc_column.resize(trace_len, Fp::zero());

        let mut range_check_column = Vec::new_in(PageAlignedAllocator);
        range_check_column.resize(trace_len, Fp::zero());

        for (i, RegisterState { pc, .. }) in register_states.iter().enumerate() {
            let word = memory[*pc].unwrap();
            assert!(!word.get_flag(Flag::Zero));
            let trace_offset = i * cycle_height;

            // FLAGS
            let flags_virtual_row = &mut flags_column[trace_offset..trace_offset + cycle_height];
            for flag in Flag::iter() {
                flags_virtual_row[flag as usize] = word.get_flag_prefix(flag).into();
            }

            // NPC
            let npc_virtual_row = &mut npc_column[trace_offset..trace_offset + cycle_height];
            npc_virtual_row[Npc::FirstWord as usize] = word.into();

            // RANGE CHECK
            let rc_virtual_row = &mut range_check_column[trace_offset..trace_offset + cycle_height];
            println!(
                "W:{:064b}\nC:{:016b}{:016b}{:016b}{:016b}",
                u64::try_from(word.0).unwrap(),
                word.get_flag_prefix(Flag::DstReg),
                word.get_off_op1(),
                word.get_off_op0(),
                word.get_off_dst(),
            );
            rc_virtual_row[RangeCheck::OffDst as usize] = word.get_off_dst().into();
            rc_virtual_row[RangeCheck::OffOp1 as usize] = word.get_off_op1().into();
            rc_virtual_row[RangeCheck::OffOp0 as usize] = word.get_off_op0().into();
        }

        let base_trace = Matrix::new(vec![
            flags_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            npc_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            range_check_column.to_vec_in(PageAlignedAllocator),
        ]);

        ExecutionTrace {
            flags_column,
            npc_column,
            range_check_column,
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
    const NUM_BASE_COLUMNS: usize = 8;
    type Fp = Fp;
    type Fq = Fp;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }
}

// NPC? not sure what it means yet - next program counter?
enum Npc {
    // TODO: first word of each instruction?
    FirstWord = 1,
}

enum RangeCheck {
    OffDst = 0,
    OffOp1 = 4,
    OffOp0 = 8,
}
