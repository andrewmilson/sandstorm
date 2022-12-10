use gpu_poly::GpuFftField;
use ministark::challenges::Challenges;
use strum_macros::EnumIter;
use gpu_poly::GpuVec;
use gpu_poly::prelude::PageAlignedAllocator;
use ministark::Matrix;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use ministark::StarkExtensionOf;
use ministark::Trace;
use ark_ff::Zero;
use ministark::constraints::AlgebraicExpression;
use ark_ff::Field;
use ark_ff::One;
use ministark::constraints::ExecutionTraceColumn;
use strum::IntoEnumIterator;
use crate::air::MemoryPermutation;
use crate::binary::CompiledProgram;
use crate::binary::Memory;
use crate::binary::RegisterState;
use crate::binary::RegisterStates;
use crate::binary::Word;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub const CYCLE_HEIGHT: usize = 16;

pub struct ExecutionTrace {
    pub public_memory: Vec<(usize, Word)>,
    pub initial_registers: RegisterState,
    pub final_registers: RegisterState,
    register_states: RegisterStates,
    program: CompiledProgram,
    mem: Memory,
    flags_column: GpuVec<Fp>,
    npc_column: GpuVec<Fp>,
    memory_column: GpuVec<Fp>,
    range_check_column: GpuVec<Fp>,
    auxiliary_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
}

impl ExecutionTrace {
    fn new(mem: Memory, register_states: RegisterStates, program: CompiledProgram) -> Self {
        let num_program_cycles = register_states.len();
        let num_trace_cycles = register_states.len().next_power_of_two();
        let trace_len = num_trace_cycles * CYCLE_HEIGHT;
        // let half_offset = 2isize.pow(15);
        // let half_offset = 2u32.pow(15);

        for (i, v) in mem.iter().enumerate() {
            if !v.is_some() {
                println!("FOK {i}");
            }
        }

        let public_memory = program.get_public_memory();

        let mut flags_column = Vec::new_in(PageAlignedAllocator);
        flags_column.resize(trace_len, Fp::zero());

        let mut zeros_column = Vec::new_in(PageAlignedAllocator);
        zeros_column.resize(trace_len, Fp::zero());

        // TODO: npc?
        let mut npc_column = Vec::new_in(PageAlignedAllocator);
        npc_column.resize(trace_len, Fp::zero());

        let mut memory_column = Vec::new_in(PageAlignedAllocator);
        memory_column.resize(trace_len, Fp::zero());

        let mut range_check_column = Vec::new_in(PageAlignedAllocator);
        range_check_column.resize(trace_len, Fp::zero());

        let mut auxiliary_column = Vec::new_in(PageAlignedAllocator);
        auxiliary_column.resize(trace_len, Fp::zero());

        println!("{}", register_states[0].pc);
        memory_column[0] = (register_states[0].pc as u64).into();
        memory_column[1] = mem[register_states[0].pc].unwrap().into();

        for (i, &RegisterState { pc, ap, fp }) in register_states.iter().enumerate() {
            let trace_offset = i * CYCLE_HEIGHT;
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

            println!("{:016b} ", pc);
            // println!("{:016b} ", word.get_off_dst() as u64);

            // FLAGS
            let flags_virtual_row = &mut flags_column[trace_offset..trace_offset + CYCLE_HEIGHT];
            for flag in Flag::iter() {
                flags_virtual_row[flag as usize] = word.get_flag_prefix(flag).into();
            }

            // NPC
            let npc_virtual_row = &mut npc_column[trace_offset..trace_offset + CYCLE_HEIGHT];
            npc_virtual_row[Npc::Pc as usize] = (pc as u64).into();
            npc_virtual_row[Npc::PubMemAddr as usize] = Fp::zero();
            npc_virtual_row[Npc::PubMemVal as usize] = Fp::zero();
            npc_virtual_row[Npc::MemOp0 as usize] = op0;
            npc_virtual_row[Npc::Instruction as usize] = word.into();
            npc_virtual_row[Npc::MemOp0Addr as usize] = op0_addr;
            npc_virtual_row[Npc::MemDstAddr as usize] = dst_addr;
            npc_virtual_row[Npc::MemDst as usize] = dst;
            npc_virtual_row[Npc::MemOp1Addr as usize] = op1_addr;
            npc_virtual_row[Npc::MemOp1 as usize] = op1;

            // MEMORY

            // RANGE CHECK
            let rc_virtual_row = &mut range_check_column[trace_offset..trace_offset + CYCLE_HEIGHT];
            rc_virtual_row[RangeCheck::OffDst as usize] = off_dst;
            rc_virtual_row[RangeCheck::Fp as usize] = (fp as u64).into();
            rc_virtual_row[RangeCheck::OffOp1 as usize] = off_op1;
            rc_virtual_row[RangeCheck::Op0MulOp1 as usize] = op0 * op1;
            rc_virtual_row[RangeCheck::OffOp0 as usize] = off_op0;
            rc_virtual_row[RangeCheck::Ap as usize] = (ap as u64).into();
            rc_virtual_row[RangeCheck::Res as usize] = res;

            // COL8 - TODO: better name
            let aux_virtual_row = &mut auxiliary_column[trace_offset..trace_offset + CYCLE_HEIGHT];
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
            memory_column.to_vec_in(PageAlignedAllocator),
            range_check_column.to_vec_in(PageAlignedAllocator),
            auxiliary_column.to_vec_in(PageAlignedAllocator),
        ]);

        // pad the execution trace by duplicating the trace cells for the last cycle
        for column in base_trace.iter_mut() {
            let last_cycle_offset = (num_program_cycles - 1) * CYCLE_HEIGHT;
            let (_, trace_suffix) = column.split_at_mut(last_cycle_offset);
            let (last_cycle, padding_rows) = trace_suffix.split_at_mut(CYCLE_HEIGHT);
            let padding_cycles = padding_rows.chunks_mut(CYCLE_HEIGHT);
            padding_cycles.for_each(|padding_cycle| padding_cycle.copy_from_slice(last_cycle))
        }

        let initial_registers = *register_states.first().unwrap();
        let final_registers = *register_states.last().unwrap();

        ExecutionTrace {
            public_memory,
            initial_registers,
            final_registers,
            flags_column,
            npc_column,
            memory_column,
            range_check_column,
            auxiliary_column,
            base_trace,
            mem,
            register_states,
            program,
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
    const NUM_EXTENSION_COLUMNS: usize = 1;
    type Fp = Fp;
    type Fq = Fp;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }

    fn build_extension_columns(&self, challenges: &Challenges<Fp>) -> Option<Matrix<Fp>> {
        let trace_len = self.base_trace.num_rows();
        let mut permutation_column = Vec::new_in(PageAlignedAllocator);
        permutation_column.resize(trace_len, Fp::zero());

        use MemoryPermutation::*;
        // permutation_column[0] = -challenges[Z];
        permutation_column[0] = Fp::one();
        // self.npc_column[Npc::Pc as usize]
        // + challenges[A] * self.npc_column[Npc::FirstWord as usize]
        // - challenges[Z];

        // for i in 0..trace_len / NUM_VIRTUAL_PERMURATION_COLUMNS {
        //     let trace_offset = i * NUM_VIRTUAL_PERMURATION_COLUMNS;
        //     let permutation_virtual_row = &mut permutation_column
        //         [trace_offset..trace_offset + NUM_VIRTUAL_PERMURATION_COLUMNS];
        //     // TODO:
        //     use MemoryPermutation::*;
        //     // permutation_virtual_row[Permutation::Memory as usize] = challenges[Z]
        // - ;     permutation_virtual_row[Permutation::RangeCheck as usize] =
        // Fp::zero(); }

        Some(Matrix::new(vec![permutation_column]))
    }
}

/// Cairo flag
/// https://eprint.iacr.org/2021/1063.pdf section 9
#[derive(Clone, Copy, EnumIter, PartialEq, Eq)]
pub enum Flag {
    // Group: [FlagGroup::DstReg]
    DstReg = 0,

    // Group: [FlagGroup::Op0]
    Op0Reg = 1,

    // Group: [FlagGroup::Op1Src]
    Op1Imm = 2,
    Op1Fp = 3,
    Op1Ap = 4,

    // Group: [FlagGroup::ResLogic]
    ResAdd = 5,
    ResMul = 6,

    // Group: [FlagGroup::PcUpdate]
    PcJumpAbs = 7,
    PcJumpRel = 8,
    PcJnz = 9,

    // Group: [FlagGroup::ApUpdate]
    ApAdd = 10,
    ApAdd1 = 11,

    // Group: [FlagGroup::Opcode]
    OpcodeCall = 12,
    OpcodeRet = 13,
    OpcodeAssertEq = 14,

    // 0 - padding to make flag cells a power-of-2
    Zero = 15,
}

impl ExecutionTraceColumn for Flag {
    fn index(&self) -> usize {
        0
    }

    fn offset<Fp: GpuFftField, Fq: StarkExtensionOf<Fp>>(
        &self,
        cycle_offset: isize,
    ) -> AlgebraicExpression<Fp, Fq> {
        use AlgebraicExpression::Trace;
        // Get the individual bit (as opposed to the bit prefix)
        let col = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset;
        let flag_offset = trace_offset + *self as isize;
        Trace(col, flag_offset) - (Trace(col, flag_offset + 1) + Trace(col, flag_offset + 1))
    }
}

// NPC? not sure what it means yet - next program counter?
// Trace column 5
// Perhaps control flow is a better name for this column
#[derive(Clone, Copy)]
pub enum Npc {
    // TODO: first word of each instruction?
    Pc = 0, // Program counter
    Instruction = 1,
    PubMemAddr = 2,
    PubMemVal = 3,
    MemOp0Addr = 4,
    MemOp0 = 5,
    // TODO: What kind of memory address? 8 - memory function?
    MemDstAddr = 8,
    MemDst = 9,
    // TODO: second value also PubMemAddr = 10?
    // TODO: second value also PubMemVal = 11?
    // = 11 TODO
    MemOp1Addr = 12,
    MemOp1 = 13,
}

impl ExecutionTraceColumn for Npc {
    fn index(&self) -> usize {
        5
    }

    fn offset<Fp: GpuFftField, Fq: StarkExtensionOf<Fp>>(
        &self,
        cycle_offset: isize,
    ) -> AlgebraicExpression<Fp, Fq> {
        let column = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset + *self as isize;
        AlgebraicExpression::Trace(column, trace_offset)
    }
}

// Trace column 6 - memory
#[derive(Clone, Copy)]
pub enum Mem {
    // TODO = 0,
    Address = 0,
    Value = 1,
}

impl ExecutionTraceColumn for Mem {
    fn index(&self) -> usize {
        6
    }

    fn offset<Fp: GpuFftField, Fq: StarkExtensionOf<Fp>>(
        &self,
        mem_offset: isize,
    ) -> AlgebraicExpression<Fp, Fq> {
        let column = self.index();
        let trace_offset = 2 as isize * mem_offset + *self as isize;
        AlgebraicExpression::Trace(column, trace_offset)
    }
}

// Trace column 7
#[derive(Clone, Copy)]
pub enum RangeCheck {
    OffDst = 0,
    Ap = 3, // Allocation pointer (ap)
    // TODO 2
    OffOp1 = 4,
    Op0MulOp1 = 7, // =op0*op1
    OffOp0 = 8,
    Fp = 11, // Frame pointer (fp)
    Res = 15,
}

impl ExecutionTraceColumn for RangeCheck {
    fn index(&self) -> usize {
        7
    }

    fn offset<Fp: GpuFftField, Fq: StarkExtensionOf<Fp>>(
        &self,
        cycle_offset: isize,
    ) -> AlgebraicExpression<Fp, Fq> {
        let column = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset + *self as isize;
        AlgebraicExpression::Trace(column, trace_offset)
    }
}

// Auxiliary column 8
#[derive(Clone, Copy)]
pub enum Auxiliary {
    Tmp0 = 0,
    Tmp1 = 8,
}

impl ExecutionTraceColumn for Auxiliary {
    fn index(&self) -> usize {
        8
    }

    fn offset<Fp: GpuFftField, Fq: StarkExtensionOf<Fp>>(
        &self,
        cycle_offset: isize,
    ) -> AlgebraicExpression<Fp, Fq> {
        let column = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset + *self as isize;
        AlgebraicExpression::Trace(column, trace_offset)
    }
}

// Trace column 6 - permutations
#[derive(Clone, Copy)]
pub enum Permutation {
    // TODO = 0,
    Memory = 0,
    RangeCheck = 1,
}

impl ExecutionTraceColumn for Permutation {
    fn index(&self) -> usize {
        9
    }

    fn offset<Fp: GpuFftField, Fq: StarkExtensionOf<Fp>>(
        &self,
        permutation_offset: isize,
    ) -> AlgebraicExpression<Fp, Fq> {
        let column = self.index();
        let trace_offset = match self {
            Permutation::Memory => 2 * permutation_offset + *self as isize,
            Permutation::RangeCheck => 4 * permutation_offset + *self as isize,
        };
        AlgebraicExpression::Trace(column, trace_offset)
    }
}

/// Computes the value of the public memory quotient:
///     numerator / (denominator * padding)
/// where:
///     numerator = (z - (0 + alpha * 0))^S,
///     denominator = \prod_i( z - (addr_i + alpha * value_i) ),
///     padding = (z - (padding_addr + alpha * padding_value))^(S - N),
///     N is the actual number of public memory cells,
///     and S is the num of cells allocated for the pub mem (include padding).
/// Sourced from https://github.com/starkware-libs/starkex-contracts
fn compute_public_memory_quotient(
    challenges: &Challenges<Fp>,
    trace_len: usize,
    num_padded_rows: usize,
    public_memory: &[(usize, Word)],
) -> Fp {
    use MemoryPermutation::*;
    // let numerator = challenges[Z].pow([trace_len as u64]);
    todo!()
}
