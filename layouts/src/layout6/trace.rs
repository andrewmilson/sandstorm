use super::air::Auxiliary;
use super::air::Flag;
use super::air::MemoryPermutation;
use super::air::Npc;
use super::air::RangeCheck;
use super::CYCLE_HEIGHT;
use super::NUM_BASE_COLUMNS;
use super::NUM_EXTENSION_COLUMNS;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_STEP;
use ark_ff::Zero;
use binary::EcdsaInstance;
use binary::PedersenInstance;
use binary::RangeCheckInstance;
use builtins::ecdsa;
use builtins::pedersen;
use ark_ff::One;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use builtins::range_check;
use num_bigint::BigUint;
use ruint::aliases::U256;
use crate::ExecutionInfo;
use crate::layout6::RANGE_CHECK_BUILTIN_PARTS;
use crate::layout6::RANGE_CHECK_BUILTIN_RATIO;
use crate::layout6::air::RangeCheckBuiltin;
use crate::utils::RangeCheckPool;
use super::air::Permutation;
use super::air::RangeCheckPermutation;
use super::MEMORY_STEP;
use crate::utils::get_ordered_memory_accesses;
use crate::CairoExecutionTrace;
use alloc::vec;
use alloc::vec::Vec;
use ark_ff::batch_inversion;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterState;
use binary::RegisterStates;
use core::iter::zip;
use ministark::challenges::Challenges;
use ministark::utils::GpuAllocator;
use ministark::utils::GpuVec;
use ministark::Matrix;
use ministark::Trace;
use ministark::TraceInfo;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use strum::IntoEnumIterator;

pub struct ExecutionTrace {
    pub public_memory_padding_address: u32,
    pub public_memory_padding_value: Fp,
    pub range_check_min: u16,
    pub range_check_max: u16,
    pub public_memory: Vec<(u32, Fp)>,
    pub initial_registers: RegisterState,
    pub final_registers: RegisterState,
    pub initial_pedersen_address: u32,
    pub initial_rc_address: u32,
    pub initial_ecdsa_address: u32,
    _register_states: RegisterStates,
    _program: CompiledProgram,
    _mem: Memory<Fp>,
    _flags_column: GpuVec<Fp>,
    npc_column: GpuVec<Fp>,
    memory_column: GpuVec<Fp>,
    range_check_column: GpuVec<Fp>,
    _auxiliary_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
}

impl CairoExecutionTrace for ExecutionTrace {
    fn new(
        program: CompiledProgram,
        air_public_input: AirPublicInput,
        air_private_input: AirPrivateInput,
        mem: Memory<Fp>,
        register_states: RegisterStates,
    ) -> Self {
        let num_cycles = register_states.len();
        assert!(num_cycles.is_power_of_two());
        let trace_len = num_cycles * CYCLE_HEIGHT;
        assert!(trace_len >= TraceInfo::MIN_TRACE_LENGTH);
        let public_memory = program.get_public_memory();

        println!("Num cycles: {}", num_cycles);
        println!("Trace len: {}", trace_len);

        let mut flags_column = Vec::new_in(GpuAllocator);
        flags_column.resize(trace_len, Fp::zero());

        // set `padding_address == padding_value` to make filling the column easy
        // let public_memory_padding_address = public_memory_padding_address(&mem,
        // &register_states);
        let (public_memory_padding_address, public_memory_padding_value) =
            program.get_padding_address_and_value();
        let mut npc_column = Vec::new_in(GpuAllocator);
        npc_column.resize(trace_len, public_memory_padding_value);

        // Keep trace of all 16-bit range check values
        let mut rc_pool = RangeCheckPool::new();

        // add offsets to the range check pool
        for &RegisterState { pc, .. } in register_states.iter() {
            let word = mem[pc].unwrap();
            rc_pool.push(word.get_off_dst());
            rc_pool.push(word.get_off_op0());
            rc_pool.push(word.get_off_op1());
        }

        // add 128-bit range check builtin parts to the range check pool
        let rc128_instances = air_private_input.range_check;
        let rc128_traces = rc128_instances
            .into_iter()
            .map(range_check::InstanceTrace::<RANGE_CHECK_BUILTIN_PARTS>::new)
            .collect::<Vec<_>>();
        for rc128_trace in &rc128_traces {
            for part in rc128_trace.parts {
                rc_pool.push(part);
            }
        }

        let (ordered_rc_vals, ordered_rc_padding_vals) = rc_pool.get_ordered_values_with_padding();
        let range_check_min = rc_pool.min().unwrap();
        let range_check_max = rc_pool.max().unwrap();
        let range_check_padding_value = Fp::from(range_check_max);
        let mut ordered_rc_padding_vals = ordered_rc_padding_vals.into_iter();
        println!("original len: {}", ordered_rc_padding_vals.len());
        let mut ordered_rc_vals = ordered_rc_vals.into_iter();
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

        // create dummy 128-bit range check values that are filled with 16-bit range
        // check padding values
        let rc128_dummy_traces = (rc128_traces.len()..num_cycles / RANGE_CHECK_BUILTIN_RATIO)
            .map(|index| {
                let mut value = U256::ZERO;
                for _ in 0..RANGE_CHECK_BUILTIN_PARTS {
                    let part = ordered_rc_padding_vals.next().unwrap_or(range_check_max);
                    value = (value << 16) + U256::from(part)
                }

                range_check::InstanceTrace::<RANGE_CHECK_BUILTIN_PARTS>::new(RangeCheckInstance {
                    index: index as u32,
                    value,
                })
            })
            .collect::<Vec<_>>();

        for cycle in 0..num_cycles {
            let cycle_offset = CYCLE_HEIGHT * cycle;
            let rc_virtual_row = &mut range_check_column[cycle_offset..cycle_offset + CYCLE_HEIGHT];

            // overwrite the range check padding cell with remaining padding values
            // odd cycles only (even cycles are used for 128 bit range check)
            if cycle % 2 == 1 {
                rc_virtual_row[RangeCheck::Unused as usize] =
                    if let Some(val) = ordered_rc_padding_vals.next() {
                        // Last range check is currently unused so stuff in the padding values there
                        val.into()
                    } else {
                        range_check_padding_value
                    };
            }

            // add ordered range check values
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

        // Generate trace for pedersen hash
        // ================================
        let mut pedersen_partial_xs_column = Vec::new_in(GpuAllocator);
        pedersen_partial_xs_column.resize(trace_len, Fp::zero());
        let mut pedersen_partial_ys_column = Vec::new_in(GpuAllocator);
        pedersen_partial_ys_column.resize(trace_len, Fp::zero());
        let mut pedersen_suffixes_column = Vec::new_in(GpuAllocator);
        pedersen_suffixes_column.resize(trace_len, Fp::zero());
        let mut pedersen_slopes_column = Vec::new_in(GpuAllocator);
        pedersen_slopes_column.resize(trace_len, Fp::zero());

        // The trace for each hash spans 512 rows
        let (pedersen_partial_xs_steps, _) = pedersen_partial_xs_column.as_chunks_mut::<512>();
        let (pedersen_partial_ys_steps, _) = pedersen_partial_ys_column.as_chunks_mut::<512>();
        let (pedersen_suffixes_steps, _) = pedersen_suffixes_column.as_chunks_mut::<512>();
        let (pedersen_slopes_steps, _) = pedersen_slopes_column.as_chunks_mut::<512>();
        let (pedersen_npc_steps, _) = npc_column.as_chunks_mut::<512>();

        // Create dummy instances if there are cells that need to be filled
        let pedersen_instances = air_private_input.pedersen;
        let num_pedersen_instances = pedersen_instances.len() as u32;
        let empty_pedersen_instances = (num_pedersen_instances..).map(PedersenInstance::new_empty);
        let pedersen_traces = pedersen_instances
            .into_iter()
            .chain(empty_pedersen_instances)
            .map(pedersen::InstanceTrace::new);

        let pedersen_memory_segment = air_public_input
            .memory_segments
            .pedersen
            .expect("layout6 requires a pedersen memory segment");
        let initial_pedersen_address = pedersen_memory_segment.begin_addr;

        // Load individual hash traces into the global execution trace
        ark_std::cfg_iter_mut!(pedersen_partial_xs_steps)
            .zip(pedersen_partial_ys_steps)
            .zip(pedersen_suffixes_steps)
            .zip(pedersen_slopes_steps)
            .zip(pedersen_npc_steps)
            .zip(pedersen_traces)
            .for_each(
                |(((((partial_xs, partial_ys), suffixes), slopes), npc), pedersen_trace)| {
                    let a_steps = pedersen_trace.a_steps;
                    let b_steps = pedersen_trace.b_steps;
                    let partial_steps = vec![a_steps, b_steps].concat();

                    for ((((suffix, partial_x), partial_y), slope), step) in
                        zip(suffixes, partial_xs)
                            .zip(partial_ys)
                            .zip(slopes)
                            .zip(partial_steps)
                    {
                        *suffix = step.suffix;
                        *partial_x = step.point.x;
                        *partial_y = step.point.y;
                        *slope = step.slope;
                    }

                    // add the hash to the memory pool
                    let instance = pedersen_trace.instance;
                    let (a_addr, b_addr, output_addr) = instance.mem_addr(initial_pedersen_address);
                    npc[Npc::PedersenInput0Addr as usize] = a_addr.into();
                    npc[Npc::PedersenInput0Val as usize] = Fp::from(BigUint::from(instance.a));
                    npc[Npc::PedersenInput1Addr as usize] = b_addr.into();
                    npc[Npc::PedersenInput1Val as usize] = Fp::from(BigUint::from(instance.b));
                    npc[Npc::PedersenOutputAddr as usize] = output_addr.into();
                    npc[Npc::PedersenOutputVal as usize] = pedersen_trace.output;
                },
            );

        // Generate trace for range check builtin
        // ======================================
        let (rc_range_check_steps, _) = range_check_column.as_chunks_mut::<256>();
        let (rc_npc_steps, _) = npc_column.as_chunks_mut::<256>();

        let rc_memory_segment = air_public_input
            .memory_segments
            .range_check
            .expect("layout6 requires a range check memory segment");
        let initial_rc_address = rc_memory_segment.begin_addr;

        let rc_offset = RangeCheckBuiltin::Rc16Component as usize;
        let rc_step = RANGE_CHECK_BUILTIN_RATIO * CYCLE_HEIGHT / RANGE_CHECK_BUILTIN_PARTS;

        ark_std::cfg_iter_mut!(rc_range_check_steps)
            .zip(rc_npc_steps)
            .zip(rc128_traces.into_iter().chain(rc128_dummy_traces))
            .for_each(|((range_check, npc), rc_trace)| {
                // add the 128-bit range check to the 16-bit range check pool
                let parts = rc_trace.parts;
                range_check[rc_offset] = parts[0].into();
                range_check[rc_offset + rc_step] = parts[1].into();
                range_check[rc_offset + rc_step * 2] = parts[2].into();
                range_check[rc_offset + rc_step * 3] = parts[3].into();
                range_check[rc_offset + rc_step * 4] = parts[4].into();
                range_check[rc_offset + rc_step * 5] = parts[5].into();
                range_check[rc_offset + rc_step * 6] = parts[6].into();
                range_check[rc_offset + rc_step * 7] = parts[7].into();

                // add the range check to the memory pool
                let instance = rc_trace.instance;
                let addr = instance.mem_addr(initial_rc_address);
                npc[Npc::RangeCheck128Addr as usize] = addr.into();
                npc[Npc::RangeCheck128Val as usize] = Fp::from(BigUint::from(instance.value));
            });

        // Generate trace for ECDSA builtin
        // ================================
        let ecdsa_memory_segment = air_public_input
            .memory_segments
            .ecdsa
            .expect("layout6 requires an ECDSA memory segment");
        let initial_ecdsa_address = ecdsa_memory_segment.begin_addr;

        // Create dummy instances if there are cells that need to be filled
        let ecdsa_instances = air_private_input.ecdsa;
        let num_ecdsa_instances = ecdsa_instances.len() as u32;
        let empty_ecdsa_instances = (num_ecdsa_instances..).map(EcdsaInstance::new_empty);
        let ecdsa_traces = ecdsa_instances
            .into_iter()
            .chain(empty_ecdsa_instances)
            .map(ecdsa::InstanceTrace::new);

        let (ecdsa_npc_steps, _) = npc_column.as_chunks_mut::<32768>();
        let (ecdsa_auxiliary_steps, _) = auxiliary_column.as_chunks_mut::<32768>();

        ark_std::cfg_iter_mut!(ecdsa_npc_steps)
            .zip(ecdsa_auxiliary_steps)
            .zip(ecdsa_traces)
            .for_each(|((npc, aux), ecdsa_trace)| {
                let instance = ecdsa_trace.instance;
                let pubkey = Fp::from(BigUint::from(instance.pubkey));
                let message = Fp::from(BigUint::from(instance.message));

                // TODO: tmp solution
                aux[Auxiliary::EcdsaPubKey as usize] = pubkey;
                aux[Auxiliary::EcdsaMessage as usize] = message;

                // add the instance to the memory pool
                let (pubkey_addr, message_addr) = instance.mem_addr(initial_ecdsa_address);
                npc[Npc::EcdsaPubKeyAddr as usize] = pubkey_addr.into();
                npc[Npc::EcdsaPubKeyVal as usize] = pubkey;
                npc[Npc::EcdsaMessageAddr as usize] = message_addr.into();
                npc[Npc::EcdsaMessageVal as usize] = message;
            });

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
            pedersen_partial_xs_column.to_vec_in(GpuAllocator),
            pedersen_partial_ys_column.to_vec_in(GpuAllocator),
            pedersen_suffixes_column.to_vec_in(GpuAllocator),
            pedersen_slopes_column.to_vec_in(GpuAllocator),
            npc_column.to_vec_in(GpuAllocator),
            memory_column.to_vec_in(GpuAllocator),
            range_check_column.to_vec_in(GpuAllocator),
            auxiliary_column.to_vec_in(GpuAllocator),
        ]);

        let initial_registers = *register_states.first().unwrap();
        let final_registers = *register_states.last().unwrap();

        ExecutionTrace {
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
            initial_pedersen_address,
            initial_rc_address,
            initial_ecdsa_address,
            _flags_column: flags_column,
            _auxiliary_column: auxiliary_column,
            _mem: mem,
            _register_states: register_states,
            _program: program,
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
            initial_pedersen_address: Some(self.initial_pedersen_address),
            initial_rc_address: Some(self.initial_rc_address),
            initial_ecdsa_address: Some(self.initial_ecdsa_address),
        }
    }
}

impl Trace for ExecutionTrace {
    const NUM_BASE_COLUMNS: usize = NUM_BASE_COLUMNS;
    const NUM_EXTENSION_COLUMNS: usize = NUM_EXTENSION_COLUMNS;
    type Fp = Fp;
    type Fq = Fp;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }

    fn build_extension_columns(&self, challenges: &Challenges<Fp>) -> Option<Matrix<Fp>> {
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
        let mut numerator_acc = Fp::one();
        let mut denominator_acc = Fp::one();
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
        let mut numerator_acc = Fp::one();
        let mut denominator_acc = Fp::one();
        for chunk in range_check_chunks {
            numerator_acc *= z - chunk[RangeCheck::OffDst as usize];
            denominator_acc *= z - chunk[RangeCheck::Ordered as usize];
            rc_perm_numerators.push(numerator_acc);
            rc_perm_denominators.push(denominator_acc);
        }
        batch_inversion(&mut rc_perm_denominators);
        debug_assert!((numerator_acc / denominator_acc).is_one());

        let mut permutation_column = Vec::new_in(GpuAllocator);
        permutation_column.resize(self.base_columns().num_rows(), Fp::zero());

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
