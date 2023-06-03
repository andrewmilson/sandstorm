use super::air::Auxiliary;
use super::air::Flag;
use super::air::MemoryPermutation;
use super::air::Npc;
use super::air::Permutation;
use super::air::RangeCheck;
use super::air::RangeCheckPermutation;
use super::CYCLE_HEIGHT;
use super::MEMORY_STEP;
use super::NUM_BASE_COLUMNS;
use super::NUM_EXTENSION_COLUMNS;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_STEP;
use crate::utils::get_ordered_memory_accesses;
use crate::utils::RangeCheckPool;
use crate::CairoExecutionTrace;
use crate::ExecutionInfo;
use alloc::vec;
use alloc::vec::Vec;
use ark_ff::batch_inversion;
use ark_ff::FftField;
use ark_ff::PrimeField;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterState;
use binary::RegisterStates;
use core::iter::zip;
use ministark::challenges::Challenges;
use ministark::utils::GpuAllocator;
use ministark::utils::GpuVec;
use ministark::Matrix;
use ministark::StarkExtensionOf;
use ministark::Trace;
use ministark::TraceInfo;
use ministark_gpu::GpuFftField;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::marker::PhantomData;
use strum::IntoEnumIterator;

pub struct ExecutionTrace<Fp, Fq> {
    pub air_public_input: AirPublicInput,
    pub public_memory_padding_address: u32,
    pub public_memory_padding_value: Fp,
    pub range_check_min: u16,
    pub range_check_max: u16,
    pub public_memory: Vec<(u32, Fp)>,
    pub initial_registers: RegisterState,
    pub final_registers: RegisterState,
    _register_states: RegisterStates,
    _program: CompiledProgram,
    _mem: Memory<Fp>,
    _flags_column: GpuVec<Fp>,
    npc_column: GpuVec<Fp>,
    memory_column: GpuVec<Fp>,
    range_check_column: GpuVec<Fp>,
    _auxiliary_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
    _marker: PhantomData<Fq>,
}

impl<Fp: GpuFftField + PrimeField, Fq: StarkExtensionOf<Fp>> CairoExecutionTrace
    for ExecutionTrace<Fp, Fq>
{
    fn new(
        program: CompiledProgram,
        air_public_input: AirPublicInput,
        _air_private_input: AirPrivateInput,
        mem: Memory<Fp>,
        register_states: RegisterStates,
    ) -> Self {
        let num_cycles = register_states.len();
        assert!(num_cycles.is_power_of_two());
        let trace_len = num_cycles * CYCLE_HEIGHT;
        assert!(trace_len >= TraceInfo::MIN_TRACE_LENGTH);
        let public_memory = program.get_public_memory();

        let mut flags_column = Vec::new_in(GpuAllocator);
        flags_column.resize(trace_len, Fp::zero());

        // set `padding_address == padding_value` to make filling the column easy
        // let public_memory_padding_address = public_memory_padding_address(&mem,
        // &register_states);
        let (public_memory_padding_address, public_memory_padding_value) =
            program.get_padding_address_and_value();
        let mut npc_column = Vec::new_in(GpuAllocator);
        npc_column.resize(trace_len, public_memory_padding_value);

        // fill memory gaps to make memory "continuous"
        // skip the memory at address 0 - this is a special memory address in Cairo
        // TODO: a little brittle. investigate more.
        let mut npc_gap_iter = npc_column.array_chunks_mut().skip(3).step_by(4);
        for (a, v) in mem.iter().enumerate().skip(1) {
            if v.is_none() {
                *npc_gap_iter.next().unwrap() = [(a as u64).into(), Fp::zero()];
            }
        }

        // add offsets to the range check pool
        let mut rc_pool = RangeCheckPool::new();
        for &RegisterState { pc, .. } in register_states.iter() {
            let word = mem[pc].unwrap();
            rc_pool.push(word.get_off_dst());
            rc_pool.push(word.get_off_op0());
            rc_pool.push(word.get_off_op1());
        }

        let (ordered_rc_vals, ordered_rc_padding_vals) = rc_pool.get_ordered_values_with_padding();
        let range_check_min = rc_pool.min().unwrap();
        let range_check_max = rc_pool.max().unwrap();
        let range_check_padding_value = Fp::from(range_check_max as u64);
        let mut ordered_rc_vals = ordered_rc_vals.into_iter();
        let mut ordered_rc_padding_vals = ordered_rc_padding_vals.into_iter();
        let mut range_check_column = Vec::new_in(GpuAllocator);
        range_check_column.resize(trace_len, range_check_padding_value);

        let mut auxiliary_column = Vec::new_in(GpuAllocator);
        auxiliary_column.resize(trace_len, Fp::zero());

        let (range_check_cycles, _) = range_check_column.as_chunks_mut::<CYCLE_HEIGHT>();
        let (auxiliary_cycles, _) = auxiliary_column.as_chunks_mut::<CYCLE_HEIGHT>();
        let (npc_cycles, _) = npc_column.as_chunks_mut::<CYCLE_HEIGHT>();
        let (flag_cycles, _) = flags_column.as_chunks_mut::<CYCLE_HEIGHT>();

        ark_std::cfg_iter_mut!(range_check_cycles)
            .zip(auxiliary_cycles)
            .zip(npc_cycles)
            .zip(flag_cycles)
            .zip(&*register_states)
            .for_each(
                |((((rc_cycle, aux_cycle), npc_cycle), flag_cycle), registers)| {
                    let &RegisterState { pc, ap, fp } = registers;
                    let word = mem[pc].unwrap();
                    debug_assert!(!word.get_flag(Flag::Zero.into()));

                    // range check all offset values
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
                    for flag in Flag::iter() {
                        flag_cycle[flag as usize] = word.get_flag_prefix(flag.into()).into();
                    }

                    // NPC
                    npc_cycle[Npc::Pc as usize] = (pc as u64).into();
                    npc_cycle[Npc::Instruction as usize] = word.into_felt();
                    npc_cycle[Npc::MemOp0Addr as usize] = op0_addr;
                    npc_cycle[Npc::MemOp0 as usize] = op0;
                    npc_cycle[Npc::MemDstAddr as usize] = dst_addr;
                    npc_cycle[Npc::MemDst as usize] = dst;
                    npc_cycle[Npc::MemOp1Addr as usize] = op1_addr;
                    npc_cycle[Npc::MemOp1 as usize] = op1;
                    for offset in (0..CYCLE_HEIGHT).step_by(PUBLIC_MEMORY_STEP) {
                        npc_cycle[offset + Npc::PubMemAddr as usize] = Fp::zero();
                        npc_cycle[offset + Npc::PubMemVal as usize] = Fp::zero();
                    }

                    // MEMORY
                    // handled after this loop

                    // RANGE CHECK
                    rc_cycle[RangeCheck::OffDst as usize] = off_dst;
                    rc_cycle[RangeCheck::Ap as usize] = (ap as u64).into();
                    rc_cycle[RangeCheck::OffOp1 as usize] = off_op1;
                    rc_cycle[RangeCheck::Op0MulOp1 as usize] = op0 * op1;
                    rc_cycle[RangeCheck::OffOp0 as usize] = off_op0;
                    rc_cycle[RangeCheck::Fp as usize] = (fp as u64).into();
                    rc_cycle[RangeCheck::Res as usize] = res;
                    // RangeCheck::Ordered and RangeCheck::Unused are handled after cycle padding

                    // COL8 - TODO: better name
                    aux_cycle[Auxiliary::Tmp0 as usize] = tmp0;
                    aux_cycle[Auxiliary::Tmp1 as usize] = tmp1;
                },
            );

        for cycle_offset in (0..trace_len).step_by(CYCLE_HEIGHT) {
            let rc_virtual_row = &mut range_check_column[cycle_offset..cycle_offset + CYCLE_HEIGHT];

            // overwrite the range check padding cell with remaining padding values
            // TODO: this might not be enough
            rc_virtual_row[RangeCheck::Unused as usize] =
                if let Some(val) = ordered_rc_padding_vals.next() {
                    // Last range check is currently unused so stuff in the padding values there
                    (val as u64).into()
                } else {
                    range_check_padding_value
                };

            // add remaining ordered range check values
            for offset in (0..CYCLE_HEIGHT).step_by(RANGE_CHECK_STEP) {
                rc_virtual_row[offset + RangeCheck::Ordered as usize] =
                    if let Some(val) = ordered_rc_vals.next() {
                        (val as u64).into()
                    } else {
                        range_check_padding_value
                    };
            }
        }

        // ensure range check values have been fully consumed
        assert!(ordered_rc_padding_vals.next().is_none());
        assert!(ordered_rc_vals.next().is_none());

        // generate the memory column by ordering memory accesses
        let memory_accesses: Vec<(Fp, Fp)> = npc_column
            .array_chunks()
            .map(|&[mem_addr, mem_val]| (mem_addr, mem_val))
            .collect();
        let ordered_memory_accesses =
            get_ordered_memory_accesses(trace_len, &memory_accesses, &program);
        let memory_column = ordered_memory_accesses
            .into_iter()
            .flat_map(|(a, v)| [a, v])
            .collect::<Vec<Fp>>()
            .to_vec_in(GpuAllocator);

        let base_trace = Matrix::new(vec![
            flags_column.to_vec_in(GpuAllocator),
            npc_column.to_vec_in(GpuAllocator),
            memory_column.to_vec_in(GpuAllocator),
            range_check_column.to_vec_in(GpuAllocator),
            auxiliary_column.to_vec_in(GpuAllocator),
        ]);

        let initial_registers = *register_states.first().unwrap();
        let final_registers = *register_states.last().unwrap();

        ExecutionTrace {
            air_public_input,
            public_memory_padding_address,
            public_memory_padding_value,
            range_check_min,
            range_check_max,
            public_memory,
            initial_registers,
            final_registers,
            npc_column,
            memory_column,
            range_check_column,
            base_trace,
            _flags_column: flags_column,
            _auxiliary_column: auxiliary_column,
            _mem: mem,
            _register_states: register_states,
            _program: program,
            _marker: PhantomData,
        }
    }

    fn execution_info(&self) -> ExecutionInfo<Self::Fp> {
        assert_eq!(self.initial_registers.ap, self.initial_registers.fp);
        assert_eq!(self.initial_registers.ap, self.final_registers.fp);
        ExecutionInfo {
            initial_ap: (self.initial_registers.ap as u64).into(),
            initial_pc: (self.initial_registers.pc as u64).into(),
            final_ap: (self.final_registers.ap as u64).into(),
            final_pc: (self.final_registers.pc as u64).into(),
            public_memory: self.public_memory.clone(),
            range_check_min: self.range_check_min,
            range_check_max: self.range_check_max,
            public_memory_padding_address: self.public_memory_padding_address,
            public_memory_padding_value: self.public_memory_padding_value,
            initial_pedersen_address: None,
            initial_rc_address: None,
            initial_ecdsa_address: None,
        }
    }
}

impl<Fp: GpuFftField + FftField, Fq: StarkExtensionOf<Fp>> Trace for ExecutionTrace<Fp, Fq> {
    const NUM_BASE_COLUMNS: usize = NUM_BASE_COLUMNS;
    const NUM_EXTENSION_COLUMNS: usize = NUM_EXTENSION_COLUMNS;
    type Fp = Fp;
    type Fq = Fq;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }

    fn build_extension_columns(&self, challenges: &Challenges<Fq>) -> Option<Matrix<Fq>> {
        // TODO: multithread
        // Generate memory permutation product
        // ===================================
        // see distinction between (a', v') and (a, v) in the Cairo paper.
        let z = challenges[MemoryPermutation::Z];
        let alpha = challenges[MemoryPermutation::A];
        let program_order_accesses = self.npc_column.array_chunks::<MEMORY_STEP>();
        let address_order_accesses = self.memory_column.array_chunks::<MEMORY_STEP>();
        let mut mem_perm_numerators = Vec::new();
        let mut mem_perm_denominators = Vec::new();
        let mut numerator_acc = Fq::one();
        let mut denominator_acc = Fq::one();
        for (&[a, v], &[a_prime, v_prime]) in program_order_accesses.zip(address_order_accesses) {
            numerator_acc *= z - (alpha * v + a);
            denominator_acc *= z - (alpha * v_prime + a_prime);
            mem_perm_numerators.push(numerator_acc);
            mem_perm_denominators.push(denominator_acc);
        }
        batch_inversion(&mut mem_perm_denominators);

        // Generate range check permutation product
        // ========================================
        let z = challenges[RangeCheckPermutation::Z];
        let range_check_chunks = self.range_check_column.array_chunks::<RANGE_CHECK_STEP>();
        let mut rc_perm_numerators = Vec::new();
        let mut rc_perm_denominators = Vec::new();
        let mut numerator_acc = Fq::one();
        let mut denominator_acc = Fq::one();
        for chunk in range_check_chunks {
            numerator_acc *= z - chunk[RangeCheck::OffDst as usize];
            denominator_acc *= z - chunk[RangeCheck::Ordered as usize];
            rc_perm_numerators.push(numerator_acc);
            rc_perm_denominators.push(denominator_acc);
        }
        batch_inversion(&mut rc_perm_denominators);
        debug_assert!((numerator_acc / denominator_acc).is_one());

        let mut permutation_column = Vec::new_in(GpuAllocator);
        permutation_column.resize(self.base_columns().num_rows(), Fq::zero());

        // Insert intermediate memory permutation results
        for (i, (n, d)) in zip(mem_perm_numerators, mem_perm_denominators).enumerate() {
            permutation_column[i * MEMORY_STEP + Permutation::Memory as usize] = n * d;
        }

        // Insert intermediate range check results
        for (i, (n, d)) in zip(rc_perm_numerators, rc_perm_denominators).enumerate() {
            permutation_column[i * RANGE_CHECK_STEP + Permutation::RangeCheck as usize] = n * d;
        }

        Some(Matrix::new(vec![permutation_column]))
    }
}