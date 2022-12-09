use gpu_poly::GpuVec;
use gpu_poly::prelude::PageAlignedAllocator;
use ministark::Matrix;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use ministark::Trace;
use ark_ff::Zero;
use strum::IntoEnumIterator;
use crate::Flag;
use crate::FlagGroup;
use ark_ff::One;
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
    auxiliary_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
}

impl ExecutionTrace {
    fn new(mem: Memory, register_states: RegisterStates, program: CompiledProgram) -> Self {
        let num_program_cycles = register_states.len();
        let num_trace_cycles = register_states.len().next_power_of_two();
        let cycle_height = 16;
        let trace_len = num_trace_cycles * cycle_height;
        // let half_offset = 2isize.pow(15);
        // let half_offset = 2u32.pow(15);

        let mut flags_column = Vec::new_in(PageAlignedAllocator);
        flags_column.resize(trace_len, Fp::zero());

        let mut zeros_column = Vec::new_in(PageAlignedAllocator);
        zeros_column.resize(trace_len, Fp::zero());

        // TODO: npc?
        let mut npc_column = Vec::new_in(PageAlignedAllocator);
        npc_column.resize(trace_len, Fp::zero());

        let mut range_check_column = Vec::new_in(PageAlignedAllocator);
        range_check_column.resize(trace_len, Fp::zero());

        let mut auxiliary_column = Vec::new_in(PageAlignedAllocator);
        auxiliary_column.resize(trace_len, Fp::zero());

        for (i, &RegisterState { pc, ap, fp }) in register_states.iter().enumerate() {
            let trace_offset = i * cycle_height;
            let word = mem[pc].unwrap();
            assert!(!word.get_flag(Flag::Zero));
            let off_dst = (word.get_off_dst() as u64).into();
            let off_op0 = (word.get_off_op0() as u64).into();
            let off_op1 = (word.get_off_op1() as u64).into();
            let dst_addr = (word.get_dst_addr(ap, fp) as u64).into();
            let op0_addr = (word.get_op0_addr(ap, fp) as u64).into();
            let op1_addr = (word.get_op1_addr(pc, ap, fp, &mem) as u64).into();
            let dst = word.get_dst(ap, fp, &mem);
            let op0 = word.get_op0(ap, fp, &mem);
            let op1 = word.get_op1(pc, ap, fp, &mem);
            let res = word.get_res(pc, ap, fp, &mem);
            let tmp0 = word.get_tmp0(ap, fp, &mem);
            let tmp1 = word.get_tmp1(pc, ap, fp, &mem);

            // FLAGS
            let flags_virtual_row = &mut flags_column[trace_offset..trace_offset + cycle_height];
            for flag in Flag::iter() {
                flags_virtual_row[flag as usize] = word.get_flag_prefix(flag).into();
            }

            // NPC
            let npc_virtual_row = &mut npc_column[trace_offset..trace_offset + cycle_height];
            npc_virtual_row[Npc::Pc as usize] = (pc as u64).into();
            npc_virtual_row[Npc::MemOp0 as usize] = op0;
            npc_virtual_row[Npc::FirstWord as usize] = word.into();
            npc_virtual_row[Npc::MemOp0Addr as usize] = op0_addr;
            npc_virtual_row[Npc::MemDstAddr as usize] = dst_addr;
            npc_virtual_row[Npc::MemDst as usize] = dst;
            npc_virtual_row[Npc::MemOp1Addr as usize] = op1_addr;
            npc_virtual_row[Npc::MemOp1 as usize] = op1;

            // RANGE CHECK
            let rc_virtual_row = &mut range_check_column[trace_offset..trace_offset + cycle_height];
            rc_virtual_row[RangeCheck::OffDst as usize] = off_dst;
            rc_virtual_row[RangeCheck::Fp as usize] = (fp as u64).into();
            rc_virtual_row[RangeCheck::OffOp1 as usize] = off_op1;
            rc_virtual_row[RangeCheck::Op0MulOp1 as usize] = op0 * op1;
            rc_virtual_row[RangeCheck::OffOp0 as usize] = off_op0;
            rc_virtual_row[RangeCheck::Ap as usize] = (ap as u64).into();
            rc_virtual_row[RangeCheck::Res as usize] = res;

            // COL8 - TODO: better name
            let aux_virtual_row = &mut auxiliary_column[trace_offset..trace_offset + cycle_height];
            aux_virtual_row[Auxiliary::Tmp0 as usize] = tmp0;
            aux_virtual_row[Auxiliary::Tmp1 as usize] = tmp1;
        }

        let mut base_trace = Matrix::new(vec![
            flags_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            npc_column.to_vec_in(PageAlignedAllocator),
            zeros_column.to_vec_in(PageAlignedAllocator),
            range_check_column.to_vec_in(PageAlignedAllocator),
            auxiliary_column.to_vec_in(PageAlignedAllocator),
        ]);

        // pad the execution trace by duplicating the trace cells for the last cycle
        for column in base_trace.iter_mut() {
            let last_cycle_offset = (num_program_cycles - 1) * cycle_height;
            let (_, trace_suffix) = column.split_at_mut(last_cycle_offset);
            let (last_cycle, padding_rows) = trace_suffix.split_at_mut(cycle_height);
            let padding_cycles = padding_rows.chunks_mut(cycle_height);
            padding_cycles.for_each(|padding_cycle| padding_cycle.copy_from_slice(last_cycle))
        }

        ExecutionTrace {
            flags_column,
            npc_column,
            range_check_column,
            auxiliary_column,
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
    const NUM_BASE_COLUMNS: usize = 9;
    type Fp = Fp;
    type Fq = Fp;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }
}

// NPC? not sure what it means yet - next program counter?
// Trace column 5
enum Npc {
    // TODO: first word of each instruction?
    Pc = 0, // Program counter
    FirstWord = 1,
    MemOp0Addr = 4,
    MemOp0 = 5,
    // TODO: What kind of memory address? 8 - memory function?
    MemDstAddr = 8,
    MemDst = 9,
    MemOp1Addr = 12,
    MemOp1 = 13,
}

// Trace column 7
enum RangeCheck {
    OffDst = 0,
    Ap = 3, // Allocation pointer (ap)
    OffOp1 = 4,
    Op0MulOp1 = 7,
    OffOp0 = 8,
    Fp = 11, // Frame pointer (fp)
    Res = 15,
}

// Auxiliary column 8
enum Auxiliary {
    Tmp0 = 0,
    Tmp1 = 8,
}
