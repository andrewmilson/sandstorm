use super::air::Auxiliary;
use super::air::Flag;
use super::air::MemoryPermutation;
use super::air::Npc;
use super::air::RangeCheck;
use super::CYCLE_HEIGHT;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_STEP;
use ark_ff::BigInt;
use ark_ff::Zero;
use binary::BitwiseInstance;
use binary::MemoryEntry;
use ark_ff::PrimeField;
use binary::PedersenInstance;
use binary::PoseidonInstance;
use binary::RangeCheckInstance;
use builtins::bitwise;
use builtins::bitwise::dilute;
use builtins::ec_op;
use builtins::ecdsa;
use builtins::pedersen;
use ark_ff::One;
use binary::AirPublicInput;
use builtins::poseidon;
use builtins::range_check;
use num_bigint::BigUint;
use ruint::aliases::U256;
use crate::CairoWitness;
use crate::starknet::air::Poseidon;
use super::BITWISE_RATIO;
use super::DILUTED_CHECK_N_BITS;
use super::DILUTED_CHECK_SPACING;
use super::DILUTED_CHECK_STEP;
use super::ECDSA_BUILTIN_RATIO;
use super::EC_OP_BUILTIN_RATIO;
use super::EC_OP_SCALAR_HEIGHT;
use super::POSEIDON_RATIO;
use super::RANGE_CHECK_BUILTIN_PARTS;
use super::RANGE_CHECK_BUILTIN_RATIO;
use super::air::Bitwise;
use super::air::DilutedCheck;
use super::air::DilutedCheckAggregation;
use super::air::DilutedCheckPermutation;
use super::air::EcOp;
use super::air::Ecdsa;
use super::air::Pedersen;
use super::air::RangeCheckBuiltin;
use crate::utils::DilutedCheckPool;
use crate::utils::RangeCheckPool;
use super::air::Permutation;
use super::air::RangeCheckPermutation;
use ark_ff::Field;
use super::MEMORY_STEP;
use crate::utils::get_ordered_memory_accesses;
use crate::CairoTrace;
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
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use strum::IntoEnumIterator;

pub struct ExecutionTrace {
    pub air_public_input: AirPublicInput<Fp>,
    pub public_memory: Vec<MemoryEntry<Fp>>,
    pub padding_entry: MemoryEntry<Fp>,
    pub range_check_min: u16,
    pub range_check_max: u16,
    pub initial_registers: RegisterState,
    pub final_registers: RegisterState,
    pub initial_pedersen_address: u32,
    pub initial_rc_address: u32,
    pub initial_ecdsa_address: u32,
    pub initial_bitwise_address: u32,
    pub initial_ec_op_address: u32,
    pub program: CompiledProgram<Fp>,
    npc_column: GpuVec<Fp>,
    memory_column: GpuVec<Fp>,
    range_check_column: GpuVec<Fp>,
    base_trace: Matrix<Fp>,
    _register_states: RegisterStates,
    _memory: Memory<Fp>,
    _flags_column: GpuVec<Fp>,
    _auxiliary_column: GpuVec<Fp>,
}

impl CairoTrace for ExecutionTrace {
    fn new(
        program: CompiledProgram<Fp>,
        air_public_input: AirPublicInput<Fp>,
        witness: CairoWitness<Fp>,
    ) -> Self {
        let CairoWitness {
            air_private_input,
            register_states,
            memory,
        } = witness;

        let num_cycles = register_states.len();
        assert!(num_cycles.is_power_of_two());
        let trace_len = num_cycles * CYCLE_HEIGHT;
        let public_memory = air_public_input
            .public_memory
            .iter()
            .map(|e| MemoryEntry {
                address: e.address,
                value: Fp::from(BigUint::from(e.value)),
            })
            .collect::<Vec<MemoryEntry<Fp>>>();

        println!("Num cycles: {}", num_cycles);
        println!("Trace len: {}", trace_len);

        let mut flags_column = Vec::new_in(GpuAllocator);
        flags_column.resize(trace_len, Fp::zero());

        let padding_entry = air_public_input.public_memory_padding();
        let mut npc_column = Vec::new_in(GpuAllocator);
        npc_column.resize(trace_len, Fp::zero());
        {
            // default all memory items to our padding entry
            // TODO: this is a little hacky. not good
            let padding_address = padding_entry.address.into();
            let padding_value = padding_entry.value;
            for [address, value] in npc_column.array_chunks_mut() {
                *address = padding_address;
                *value = padding_value;
            }
        }

        // Keep trace of all 16-bit range check values
        let mut rc_pool = RangeCheckPool::new();

        // add offsets to the range check pool
        for &RegisterState { pc, .. } in register_states.iter() {
            let word = memory[pc].unwrap();
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
                    let insrtuction = memory[pc].unwrap();
                    let insrtuction_felt = insrtuction.into_felt();
                    debug_assert!(!insrtuction.get_flag(Flag::Zero.into()));

                    // range check all offset values
                    let off_dst = insrtuction.get_off_dst() as u32;
                    let off_op0 = insrtuction.get_off_op0() as u32;
                    let off_op1 = insrtuction.get_off_op1() as u32;
                    let dst_addr = insrtuction.get_dst_addr(ap, fp) as u32;
                    let op0_addr = insrtuction.get_op0_addr(ap, fp) as u32;
                    let op1_addr = insrtuction.get_op1_addr(pc, ap, fp, &memory) as u32;
                    let dst = insrtuction.get_dst(ap, fp, &memory);
                    let op0 = insrtuction.get_op0(ap, fp, &memory);
                    let op1 = insrtuction.get_op1(pc, ap, fp, &memory);
                    let res = insrtuction.get_res(pc, ap, fp, &memory);
                    let tmp0 = insrtuction.get_tmp0(ap, fp, &memory);
                    let tmp1 = insrtuction.get_tmp1(pc, ap, fp, &memory);

                    // FLAGS
                    for flag in Flag::iter() {
                        flag_cycle[flag as usize] = insrtuction.get_flag_prefix(flag.into()).into();
                    }

                    // NPC
                    npc_cycle[Npc::Pc as usize] = (pc as u64).into();
                    npc_cycle[Npc::Instruction as usize] = insrtuction_felt;
                    npc_cycle[Npc::MemOp0Addr as usize] = op0_addr.into();
                    npc_cycle[Npc::MemOp0 as usize] = op0;
                    npc_cycle[Npc::MemDstAddr as usize] = dst_addr.into();
                    npc_cycle[Npc::MemDst as usize] = dst;
                    npc_cycle[Npc::MemOp1Addr as usize] = op1_addr.into();
                    npc_cycle[Npc::MemOp1 as usize] = op1;
                    for offset in (0..CYCLE_HEIGHT).step_by(PUBLIC_MEMORY_STEP) {
                        npc_cycle[offset + Npc::PubMemAddr as usize] = Fp::zero();
                        npc_cycle[offset + Npc::PubMemVal as usize] = Fp::zero();
                    }

                    // MEMORY
                    // handled after this loop

                    // RANGE CHECK
                    rc_cycle[RangeCheck::OffDst as usize] = off_dst.into();
                    rc_cycle[RangeCheck::OffOp1 as usize] = off_op1.into();
                    rc_cycle[RangeCheck::OffOp0 as usize] = off_op0.into();
                    // RangeCheck::Ordered and RangeCheck::Unused are handled after cycle padding

                    // COL8 - TODO: better name
                    aux_cycle[Auxiliary::Tmp0 as usize] = tmp0;
                    aux_cycle[Auxiliary::Tmp1 as usize] = tmp1;
                    aux_cycle[Auxiliary::Ap as usize] = (ap as u64).into();
                    aux_cycle[Auxiliary::Fp as usize] = (fp as u64).into();
                    aux_cycle[Auxiliary::Op0MulOp1 as usize] = op0 * op1;
                    aux_cycle[Auxiliary::Res as usize] = res;
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

        // Diluted check
        // =============
        // due to how the range-check/diluted-check column is initiated we need to clear
        // all diluted check cells by setting them to `0`.
        let (dilution_check_steps, _) = range_check_column.as_chunks_mut::<DILUTED_CHECK_STEP>();
        ark_std::cfg_iter_mut!(dilution_check_steps).for_each(|dilution_check_step| {
            dilution_check_step[DilutedCheck::Unordered as usize] = Fp::ZERO;
            dilution_check_step[DilutedCheck::Ordered as usize] = Fp::ZERO;
        });

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

        // the trace for each hash spans 512 rows
        let (pedersen_partial_xs_steps, _) = pedersen_partial_xs_column.as_chunks_mut::<512>();
        let (pedersen_partial_ys_steps, _) = pedersen_partial_ys_column.as_chunks_mut::<512>();
        let (pedersen_suffixes_steps, _) = pedersen_suffixes_column.as_chunks_mut::<512>();
        let (pedersen_slopes_steps, _) = pedersen_slopes_column.as_chunks_mut::<512>();
        let (pedersen_npc_steps, _) = npc_column.as_chunks_mut::<512>();
        let (pedersen_aux_steps, _) = auxiliary_column.as_chunks_mut::<512>();

        // create dummy instances if there are cells that need to be filled
        let pedersen_instances = air_private_input.pedersen;
        let num_pedersen_instances = pedersen_instances.len() as u32;
        let empty_pedersen_instances = ark_std::cfg_into_iter!(num_pedersen_instances..u32::MAX)
            .map(PedersenInstance::new_empty);
        let pedersen_traces = ark_std::cfg_into_iter!(pedersen_instances)
            .chain(empty_pedersen_instances)
            .map(pedersen::InstanceTrace::new);

        let pedersen_memory_segment = air_public_input
            .memory_segments
            .pedersen
            .expect("layout requires a pedersen memory segment");
        let initial_pedersen_address = pedersen_memory_segment.begin_addr;

        // load individual hash traces into the global execution trace
        ark_std::cfg_iter_mut!(pedersen_partial_xs_steps)
            .zip(pedersen_partial_ys_steps)
            .zip(pedersen_suffixes_steps)
            .zip(pedersen_slopes_steps)
            .zip(pedersen_npc_steps)
            .zip(pedersen_aux_steps)
            .zip(pedersen_traces)
            .for_each(
                |((((((partial_xs, partial_ys), suffixes), slopes), npc), aux), pedersen_trace)| {
                    let a_steps = pedersen_trace.a_steps;
                    let b_steps = pedersen_trace.b_steps;
                    let partial_steps = [a_steps, b_steps].concat();

                    for ((((suffix, partial_x), partial_y), slope), step) in
                        zip(suffixes.iter_mut(), partial_xs.iter_mut())
                            .zip(partial_ys.iter_mut())
                            .zip(slopes.iter_mut())
                            .zip(partial_steps)
                    {
                        *suffix = step.suffix;
                        *partial_x = step.point.x;
                        *partial_y = step.point.y;
                        *slope = step.slope;
                    }

                    // load fields for unique bit decomposition checks into the trace
                    let (a_slopes, b_slopes) = slopes.split_at_mut(256);
                    let (a_aux, b_aux) = aux.split_at_mut(256);
                    a_slopes[Pedersen::Bit251AndBit196 as usize] =
                        pedersen_trace.a_bit251_and_bit196.into();
                    b_slopes[Pedersen::Bit251AndBit196 as usize] =
                        pedersen_trace.b_bit251_and_bit196.into();
                    a_aux[Pedersen::Bit251AndBit196AndBit192 as usize] =
                        pedersen_trace.a_bit251_and_bit196_and_bit192.into();
                    b_aux[Pedersen::Bit251AndBit196AndBit192 as usize] =
                        pedersen_trace.b_bit251_and_bit196_and_bit192.into();

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
        const RC_STEP_ROWS: usize = RANGE_CHECK_BUILTIN_RATIO * CYCLE_HEIGHT;
        let (rc_range_check_steps, _) = range_check_column.as_chunks_mut::<RC_STEP_ROWS>();
        let (rc_npc_steps, _) = npc_column.as_chunks_mut::<RC_STEP_ROWS>();

        let rc_memory_segment = air_public_input
            .memory_segments
            .range_check
            .expect("layout requires a range check memory segment");
        let initial_rc_address = rc_memory_segment.begin_addr;

        ark_std::cfg_iter_mut!(rc_range_check_steps)
            .zip(rc_npc_steps)
            .zip(ark_std::cfg_into_iter!(rc128_traces).chain(rc128_dummy_traces))
            .for_each(|((rc, npc), rc_trace)| {
                // add the 128-bit range check to the 16-bit range check pool
                let parts = rc_trace.parts;
                const RC_PART_ROWS: usize = RC_STEP_ROWS / RANGE_CHECK_BUILTIN_PARTS;
                rc[RangeCheckBuiltin::Rc16Component as usize] = parts[0].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS] = parts[1].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS * 2] = parts[2].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS * 3] = parts[3].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS * 4] = parts[4].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS * 5] = parts[5].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS * 6] = parts[6].into();
                rc[RangeCheckBuiltin::Rc16Component as usize + RC_PART_ROWS * 7] = parts[7].into();

                // TODO: could turn above into loop
                // for (dst, val) in zip(range_check.chunks_mut(RC_PART_ROWS), rc_trace.parts) {
                //     dst[RangeCheckBuiltin::Rc16Component as usize] = val.into();
                // }

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
            .expect("layout requires an ECDSA memory segment");
        let initial_ecdsa_address = ecdsa_memory_segment.begin_addr;

        // Create dummy instances if there are cells that need to be filled
        let ecdsa_instances = air_private_input.ecdsa;
        let num_ecdsa_instances = ecdsa_instances.len() as u32;
        let ecdsa_dummy_traces = ark_std::cfg_into_iter!(num_ecdsa_instances..u32::MAX)
            .map(ecdsa::InstanceTrace::new_dummy);
        let ecdsa_traces = ark_std::cfg_into_iter!(ecdsa_instances)
            .map(ecdsa::InstanceTrace::new)
            .chain(ecdsa_dummy_traces);

        const ECDSA_STEP_ROWS: usize = ECDSA_BUILTIN_RATIO * CYCLE_HEIGHT;
        assert_eq!(ECDSA_BUILTIN_RATIO, EC_OP_BUILTIN_RATIO * 2);
        let (ecdsa_npc_steps, _) = npc_column.as_chunks_mut::<ECDSA_STEP_ROWS>();
        let (ecdsa_auxiliary_steps, _) = auxiliary_column.as_chunks_mut::<ECDSA_STEP_ROWS>();

        ark_std::cfg_iter_mut!(ecdsa_npc_steps)
            .zip(ecdsa_auxiliary_steps)
            .zip(ecdsa_traces)
            .for_each(|((npc, aux), ecdsa_trace)| {
                let instance = ecdsa_trace.instance;
                let message = Fp::from(BigUint::from(instance.message));
                let pubkey = ecdsa_trace.pubkey;

                // load the EC operation steps into the trace
                // there are two EC ops per ECDSA instance
                // 1st is for public key scalar multiplication `r * Q`
                // 2nd is for `B` scalar multiplication `w * B` where `B = z * G + r * Q`
                let (aux_steps, _) = aux.as_chunks_mut::<64>();
                let (rq_aux_steps, wb_aux_steps) = aux_steps.split_at_mut(EC_OP_SCALAR_HEIGHT);
                assert_eq!(EC_OP_SCALAR_HEIGHT, rq_aux_steps.len());
                assert_eq!(EC_OP_SCALAR_HEIGHT, wb_aux_steps.len());

                // #1 load in public key scalar multiplication `r * Q`
                for ((aux_step, rq_step), pubkey_doubling_step) in
                    zip(rq_aux_steps, ecdsa_trace.rq_steps).zip(ecdsa_trace.pubkey_doubling_steps)
                {
                    aux_step[Ecdsa::PubkeyDoublingX as usize] = pubkey_doubling_step.point.x;
                    aux_step[Ecdsa::PubkeyDoublingY as usize] = pubkey_doubling_step.point.y;
                    aux_step[Ecdsa::PubkeyDoublingSlope as usize] = pubkey_doubling_step.slope;
                    aux_step[Ecdsa::PubkeyPartialSumX as usize] = rq_step.partial_sum.x;
                    aux_step[Ecdsa::PubkeyPartialSumY as usize] = rq_step.partial_sum.y;
                    aux_step[Ecdsa::PubkeyPartialSumSlope as usize] = rq_step.slope;
                    aux_step[Ecdsa::PubkeyPartialSumXDiffInv as usize] = rq_step.x_diff_inv;
                    aux_step[Ecdsa::RSuffix as usize] = rq_step.suffix;
                }

                // #2 load in `B` scalar multiplication `w * B` where `B = z * G + r * Q`
                for ((aux_step, wb_step), b_doubling_step) in
                    zip(wb_aux_steps, ecdsa_trace.wb_steps).zip(ecdsa_trace.b_doubling_steps)
                {
                    // TODO: need a better symbol for B and pubkey scalar mults since
                    // PubkeyDoublingX is used for pubkey mult and B mult.
                    aux_step[Ecdsa::PubkeyDoublingX as usize] = b_doubling_step.point.x;
                    aux_step[Ecdsa::PubkeyDoublingY as usize] = b_doubling_step.point.y;
                    aux_step[Ecdsa::PubkeyDoublingSlope as usize] = b_doubling_step.slope;
                    aux_step[Ecdsa::PubkeyPartialSumX as usize] = wb_step.partial_sum.x;
                    aux_step[Ecdsa::PubkeyPartialSumY as usize] = wb_step.partial_sum.y;
                    aux_step[Ecdsa::PubkeyPartialSumSlope as usize] = wb_step.slope;
                    aux_step[Ecdsa::PubkeyPartialSumXDiffInv as usize] = wb_step.x_diff_inv;
                    aux_step[Ecdsa::RSuffix as usize] = wb_step.suffix;
                }

                // load the scalar multiplication `z * G` into the trace
                // where `z` is the message hash and `G` is the curve generator point
                let (zg_aux_steps, _) = aux.as_chunks_mut::<128>();
                for (aux_step, zg_step) in zip(zg_aux_steps, ecdsa_trace.zg_steps) {
                    aux_step[Ecdsa::GeneratorPartialSumX as usize] = zg_step.partial_sum.x;
                    aux_step[Ecdsa::GeneratorPartialSumY as usize] = zg_step.partial_sum.y;
                    aux_step[Ecdsa::GeneratorPartialSumSlope as usize] = zg_step.slope;
                    aux_step[Ecdsa::GeneratorPartialSumXDiffInv as usize] = zg_step.x_diff_inv;
                    aux_step[Ecdsa::MessageSuffix as usize] = zg_step.suffix;
                }

                aux[Ecdsa::BSlope as usize] = ecdsa_trace.b_slope;
                aux[Ecdsa::BXDiffInv as usize] = ecdsa_trace.b_x_diff_inv;
                aux[Ecdsa::WInv as usize] = ecdsa_trace.w_inv;
                aux[Ecdsa::RInv as usize] = ecdsa_trace.r_inv;
                aux[Ecdsa::RPointSlope as usize] = ecdsa_trace.r_point_slope;
                aux[Ecdsa::RPointXDiffInv as usize] = ecdsa_trace.r_point_x_diff_inv;
                aux[Ecdsa::MessageInv as usize] = ecdsa_trace.message_inv;
                aux[Ecdsa::PubkeyXSquared as usize] = pubkey.x.square();

                // add the instance to the memory pool
                let (pubkey_addr, message_addr) = instance.mem_addr(initial_ecdsa_address);
                npc[Npc::EcdsaPubkeyAddr as usize] = pubkey_addr.into();
                npc[Npc::EcdsaPubkeyVal as usize] = pubkey.x;
                npc[Npc::EcdsaMessageAddr as usize] = message_addr.into();
                npc[Npc::EcdsaMessageVal as usize] = message;
            });

        // Generate trace for bitwise builtin
        // ==================================
        // TODO: clean up this section. make type for builtins that manages a lot of
        // this logic. everything is a sprawled mess
        let bitwise_memory_segment = air_public_input
            .memory_segments
            .bitwise
            .expect("layout requires a bitwise memory segment");
        let initial_bitwise_address = bitwise_memory_segment.begin_addr;

        // create dummy instances if there are cells that need to be filled
        let bitwise_instances = air_private_input.bitwise;
        let num_bitwise_instances = bitwise_instances.len() as u32;
        let bitwise_dummy_instances = (num_bitwise_instances..).map(BitwiseInstance::new_empty);
        let bitwise_traces = bitwise_instances
            .into_iter()
            .chain(bitwise_dummy_instances)
            .map(bitwise::InstanceTrace::<DILUTED_CHECK_SPACING>::new);

        const BITWISE_STEP_ROWS: usize = BITWISE_RATIO * CYCLE_HEIGHT;
        let (bitwise_npc_steps, _) = npc_column.as_chunks_mut::<BITWISE_STEP_ROWS>();
        let (bitwise_dilution_steps, _) = range_check_column.as_chunks_mut::<BITWISE_STEP_ROWS>();

        // TODO: how does fold work with par_iter? Does it kill parallelism?
        // might be better to map multiple pools and then fold into one if so.
        let diluted_check_pool = bitwise_npc_steps
            .iter_mut()
            .zip(bitwise_dilution_steps)
            .zip(bitwise_traces)
            .fold(
                DilutedCheckPool::<DILUTED_CHECK_N_BITS, DILUTED_CHECK_SPACING>::new(),
                |mut diluted_pool, ((npc, dilution), bitwise_trace)| {
                    let instance = bitwise_trace.instance;

                    {
                        // add shifts to ensure a unique unpacking
                        let x_and_y_v0 = bitwise_trace.x_and_y_partition.high.high[0];
                        let x_and_y_v1 = bitwise_trace.x_and_y_partition.high.high[1];
                        let x_and_y_v2 = bitwise_trace.x_and_y_partition.high.high[2];
                        let x_and_y_v3 = bitwise_trace.x_and_y_partition.high.high[3];
                        let v0 = x_and_y_v0 + bitwise_trace.x_xor_y_partition.high.high[0];
                        let v1 = x_and_y_v1 + bitwise_trace.x_xor_y_partition.high.high[1];
                        let v2 = x_and_y_v2 + bitwise_trace.x_xor_y_partition.high.high[2];
                        let v3 = x_and_y_v3 + bitwise_trace.x_xor_y_partition.high.high[3];
                        // only fails if the AIR will error
                        assert_eq!(v0, (v0 << 4) >> 4);
                        assert_eq!(v1, (v1 << 4) >> 4);
                        assert_eq!(v2, (v2 << 4) >> 4);
                        assert_eq!(v3, (v3 << 8) >> 8);
                        let s0 = v0 << 4;
                        let s1 = v1 << 4;
                        let s2 = v2 << 4;
                        let s3 = v3 << 8;
                        diluted_pool.push_diluted(U256::from(s0));
                        diluted_pool.push_diluted(U256::from(s1));
                        diluted_pool.push_diluted(U256::from(s2));
                        diluted_pool.push_diluted(U256::from(s3));
                        dilution[Bitwise::Bits16Chunk3Offset0ResShifted as usize] = s0.into();
                        dilution[Bitwise::Bits16Chunk3Offset1ResShifted as usize] = s1.into();
                        dilution[Bitwise::Bits16Chunk3Offset2ResShifted as usize] = s2.into();
                        dilution[Bitwise::Bits16Chunk3Offset3ResShifted as usize] = s3.into();
                    }

                    // NOTE: the order of these partitions matters
                    let partitions = [
                        bitwise_trace.x_partition,
                        bitwise_trace.y_partition,
                        bitwise_trace.x_and_y_partition,
                        bitwise_trace.x_xor_y_partition,
                    ];

                    // load diluted partitions into the execution trace
                    let (dilution_steps, _) = dilution.as_chunks_mut::<256>();
                    for (dilution_step, partition) in zip(dilution_steps, partitions) {
                        let chunk0 = partition.low.low;
                        dilution_step[Bitwise::Bits16Chunk0Offset0 as usize] = chunk0[0].into();
                        dilution_step[Bitwise::Bits16Chunk0Offset1 as usize] = chunk0[1].into();
                        dilution_step[Bitwise::Bits16Chunk0Offset2 as usize] = chunk0[2].into();
                        dilution_step[Bitwise::Bits16Chunk0Offset3 as usize] = chunk0[3].into();

                        let chunk1 = partition.low.high;
                        dilution_step[Bitwise::Bits16Chunk1Offset0 as usize] = chunk1[0].into();
                        dilution_step[Bitwise::Bits16Chunk1Offset1 as usize] = chunk1[1].into();
                        dilution_step[Bitwise::Bits16Chunk1Offset2 as usize] = chunk1[2].into();
                        dilution_step[Bitwise::Bits16Chunk1Offset3 as usize] = chunk1[3].into();

                        let chunk2 = partition.high.low;
                        dilution_step[Bitwise::Bits16Chunk2Offset0 as usize] = chunk2[0].into();
                        dilution_step[Bitwise::Bits16Chunk2Offset1 as usize] = chunk2[1].into();
                        dilution_step[Bitwise::Bits16Chunk2Offset2 as usize] = chunk2[2].into();
                        dilution_step[Bitwise::Bits16Chunk2Offset3 as usize] = chunk2[3].into();

                        let chunk3 = partition.high.high;
                        dilution_step[Bitwise::Bits16Chunk3Offset0 as usize] = chunk3[0].into();
                        dilution_step[Bitwise::Bits16Chunk3Offset1 as usize] = chunk3[1].into();
                        dilution_step[Bitwise::Bits16Chunk3Offset2 as usize] = chunk3[2].into();
                        dilution_step[Bitwise::Bits16Chunk3Offset3 as usize] = chunk3[3].into();

                        for v in [*chunk0, *chunk1, *chunk2, *chunk3].concat() {
                            diluted_pool.push_diluted(U256::from(v))
                        }
                    }

                    // load bitwise values into memory
                    let addr_step = BITWISE_RATIO * CYCLE_HEIGHT / 4;
                    let input_x_offset = Npc::BitwisePoolAddr as usize;
                    let input_y_offset = input_x_offset + addr_step;
                    let x_and_y_offset = input_y_offset + addr_step;
                    let x_xor_y_offset = x_and_y_offset + addr_step;
                    let x_or_y_offset = Npc::BitwiseXOrYAddr as usize;
                    let (input_x_addr, input_y_addr, x_and_y_addr, x_xor_y_addr, x_or_y_addr) =
                        instance.mem_addr(initial_bitwise_address);
                    npc[input_x_offset] = input_x_addr.into();
                    npc[input_x_offset + 1] = bitwise_trace.x;
                    npc[input_y_offset] = input_y_addr.into();
                    npc[input_y_offset + 1] = bitwise_trace.y;
                    npc[x_and_y_offset] = x_and_y_addr.into();
                    npc[x_and_y_offset + 1] = bitwise_trace.x_and_y;
                    npc[x_xor_y_offset] = x_xor_y_addr.into();
                    npc[x_xor_y_offset + 1] = bitwise_trace.x_xor_y;
                    npc[x_or_y_offset] = x_or_y_addr.into();
                    npc[x_or_y_offset + 1] = bitwise_trace.x_or_y;

                    // return the diluted pool
                    diluted_pool
                },
            );

        // make sure all diluted check values are encountered for
        const DILUTED_MIN: u128 = 0;
        const DILUTED_MAX: u128 = (1 << DILUTED_CHECK_N_BITS) - 1;
        let (ordered_diluted_vals, ordered_diluted_padding_vals) =
            diluted_check_pool.get_ordered_values_with_padding(DILUTED_MIN, DILUTED_MAX);
        let mut ordered_diluted_vals = ark_std::cfg_into_iter!(ordered_diluted_vals)
            .map(|v| BigInt(dilute::<DILUTED_CHECK_SPACING>(U256::from(v)).into_limbs()).into())
            .collect::<Vec<Fp>>()
            .into_iter();
        let mut ordered_diluted_padding_vals =
            ark_std::cfg_into_iter!(ordered_diluted_padding_vals)
                .map(|v| BigInt(dilute::<DILUTED_CHECK_SPACING>(U256::from(v)).into_limbs()).into())
                .collect::<Vec<Fp>>()
                .into_iter();

        // add diluted padding values
        // TODO: this is a strange way to do it. fix
        let (bitwise_dilution_chunks, _) = range_check_column.as_chunks_mut::<1024>();
        'outer: for bitwise_dilution_chunk in bitwise_dilution_chunks {
            for (i, dilution_step) in bitwise_dilution_chunk
                .array_chunks_mut::<DILUTED_CHECK_STEP>()
                .enumerate()
                .skip(1)
                .step_by(2)
            {
                let offset = i * DILUTED_CHECK_STEP + DilutedCheck::Unordered as usize;
                // NOTE: doing it this hacky way to ensure no conflict with the bitwise builtin
                // CONTEXT: each cycle spans 16 steps, there are two stacked dilutions per cycle
                if offset != Bitwise::Bits16Chunk3Offset0ResShifted as usize
                    && offset != Bitwise::Bits16Chunk3Offset1ResShifted as usize
                    && offset != Bitwise::Bits16Chunk3Offset2ResShifted as usize
                    && offset != Bitwise::Bits16Chunk3Offset3ResShifted as usize
                {
                    if let Some(padding_val) = ordered_diluted_padding_vals.next() {
                        dilution_step[DilutedCheck::Unordered as usize] = padding_val;
                    } else {
                        break 'outer;
                    }
                }
            }
        }

        // add ordered diluted check values
        let (diluted_check_steps, _) = range_check_column.as_chunks_mut::<DILUTED_CHECK_STEP>();
        let padding_offset = diluted_check_steps.len() - ordered_diluted_vals.len();
        for diluted_check_step in diluted_check_steps.iter_mut().skip(padding_offset) {
            diluted_check_step[DilutedCheck::Ordered as usize] =
                ordered_diluted_vals.next().unwrap();
        }

        // ensure dilution check values have been fully consumed
        assert!(ordered_diluted_padding_vals.next().is_none());
        assert!(ordered_diluted_vals.next().is_none());

        // Elliptic Curve operations builtin
        // =================================
        let ec_op_memory_segment = air_public_input
            .memory_segments
            .ec_op
            .expect("layout requires a EC op memory segment");
        let initial_ec_op_address = ec_op_memory_segment.begin_addr;

        // Create dummy instances if there are cells that need to be filled
        let ec_op_instances = air_private_input.ec_op;
        let num_ec_op_instances = ec_op_instances.len() as u32;
        let ec_op_dummy_traces = ark_std::cfg_into_iter!(num_ec_op_instances..u32::MAX)
            .map(ec_op::InstanceTrace::new_dummy);
        let ecdsa_traces = ark_std::cfg_into_iter!(ec_op_instances)
            .map(ec_op::InstanceTrace::new)
            .chain(ec_op_dummy_traces);

        const EC_OP_STEP_ROWS: usize = EC_OP_BUILTIN_RATIO * CYCLE_HEIGHT;
        let (ec_op_npc_steps, _) = npc_column.as_chunks_mut::<EC_OP_STEP_ROWS>();
        let (ec_op_auxiliary_steps, _) = auxiliary_column.as_chunks_mut::<EC_OP_STEP_ROWS>();

        ark_std::cfg_iter_mut!(ec_op_npc_steps)
            .zip(ec_op_auxiliary_steps)
            .zip(ecdsa_traces)
            .for_each(|((npc, aux), ec_op_trace)| {
                const DOUBLING_STEP_ROWS: usize = EC_OP_STEP_ROWS / EC_OP_SCALAR_HEIGHT;
                let (aux_steps, _) = aux.as_chunks_mut::<DOUBLING_STEP_ROWS>();

                // #1 load in the scalar multiplication `m * Q`
                for (i, ((aux_step, q_doubling_step), r_step)) in
                    zip(aux_steps, ec_op_trace.q_doubling_steps)
                        .zip(ec_op_trace.r_steps)
                        .enumerate()
                {
                    aux_step[EcOp::QDoublingX as usize] = q_doubling_step.point.x;
                    aux_step[EcOp::QDoublingY as usize] = q_doubling_step.point.y;
                    aux_step[EcOp::QDoublingSlope as usize] = q_doubling_step.slope;
                    aux_step[EcOp::RPartialSumX as usize] = r_step.partial_sum.x;
                    aux_step[EcOp::RPartialSumY as usize] = r_step.partial_sum.y;
                    aux_step[EcOp::MSuffix as usize] = r_step.suffix;
                    // don't add if last (these fields might be used by other builtins)
                    if i != EC_OP_SCALAR_HEIGHT - 1 {
                        aux_step[EcOp::RPartialSumSlope as usize] = r_step.slope;
                        aux_step[EcOp::RPartialSumXDiffInv as usize] = r_step.x_diff_inv;
                    }
                }

                // load fields for unique bit decomposition checks into the trace
                aux[EcOp::MBit251AndBit196 as usize] = ec_op_trace.m_bit251_and_bit196.into();
                aux[EcOp::MBit251AndBit196AndBit192 as usize] =
                    ec_op_trace.m_bit251_and_bit196_and_bit192.into();

                // load EC op values into memory
                let instance = ec_op_trace.instance;
                let (p_x_addr, p_y_addr, q_x_addr, q_y_addr, m_addr, r_x_addr, r_y_addr) =
                    instance.mem_addr(initial_ec_op_address);
                npc[Npc::EcOpPXAddr as usize] = p_x_addr.into();
                npc[Npc::EcOpPXVal as usize] = ec_op_trace.p.x;
                npc[Npc::EcOpPYAddr as usize] = p_y_addr.into();
                npc[Npc::EcOpPYVal as usize] = ec_op_trace.p.y;
                npc[Npc::EcOpQXAddr as usize] = q_x_addr.into();
                npc[Npc::EcOpQXVal as usize] = ec_op_trace.q.x;
                npc[Npc::EcOpQYAddr as usize] = q_y_addr.into();
                npc[Npc::EcOpQYVal as usize] = ec_op_trace.q.y;
                npc[Npc::EcOpMAddr as usize] = m_addr.into();
                npc[Npc::EcOpMVal as usize] = ec_op_trace.m;
                npc[Npc::EcOpRXAddr as usize] = r_x_addr.into();
                npc[Npc::EcOpRXVal as usize] = ec_op_trace.r.x;
                npc[Npc::EcOpRYAddr as usize] = r_y_addr.into();
                npc[Npc::EcOpRYVal as usize] = ec_op_trace.r.y;
            });

        // Poseidon builtin
        // ================
        let poseidon_memory_segment = air_public_input
            .memory_segments
            .poseidon
            .expect("layout requires a poseidon memory segment");
        let initial_poseidon_address = poseidon_memory_segment.begin_addr;

        // Create dummy instances if there are cells that need to be filled
        let poseidon_instances = air_private_input.poseidon;
        let num_poseidon_instances = poseidon_instances.len() as u32;
        let poseidon_dummy_instances = ark_std::cfg_into_iter!(num_poseidon_instances..u32::MAX)
            .map(PoseidonInstance::new_empty);
        let poseidon_traces = ark_std::cfg_into_iter!(poseidon_instances)
            .chain(poseidon_dummy_instances)
            .map(poseidon::InstanceTrace::new);

        const POSEIDON_STEP_ROWS: usize = POSEIDON_RATIO * CYCLE_HEIGHT;
        let (poseidon_npc_steps, _) = npc_column.as_chunks_mut::<POSEIDON_STEP_ROWS>();
        let (poseidon_rc_steps, _) = range_check_column.as_chunks_mut::<POSEIDON_STEP_ROWS>();
        let (poseidon_auxiliary_steps, _) = auxiliary_column.as_chunks_mut::<POSEIDON_STEP_ROWS>();

        ark_std::cfg_iter_mut!(poseidon_npc_steps)
            .zip(poseidon_rc_steps)
            .zip(poseidon_auxiliary_steps)
            .zip(poseidon_traces)
            .for_each(|(((npc, rc), aux), poseidon_trace)| {
                // load the poseidon rounds into the trace
                let (full_rounds, _) = aux.as_chunks_mut::<64>();

                // load in full rounds
                let full_round_states = [
                    poseidon_trace.full_round_states_1st_half,
                    poseidon_trace.full_round_states_2nd_half,
                ]
                .concat();
                for (full_round, round_state) in zip(full_rounds.iter_mut(), full_round_states) {
                    let (c0, state0_offset) = Poseidon::FullRoundsState0.col_and_shift();
                    let (c1, state1_offset) = Poseidon::FullRoundsState1.col_and_shift();
                    let (c2, state2_offset) = Poseidon::FullRoundsState2.col_and_shift();
                    let (c3, state0_sq_offset) = Poseidon::FullRoundsState0Squared.col_and_shift();
                    let (c4, state1_sq_offset) = Poseidon::FullRoundsState1Squared.col_and_shift();
                    let (c5, state2_sq_offset) = Poseidon::FullRoundsState2Squared.col_and_shift();
                    // ensure the columns are as expected
                    assert_eq!((c0, c1, c2, c3, c4, c5), (8, 8, 8, 8, 8, 8));

                    full_round[state0_offset as usize] = round_state.after_add_round_keys[0];
                    full_round[state1_offset as usize] = round_state.after_add_round_keys[1];
                    full_round[state2_offset as usize] = round_state.after_add_round_keys[2];

                    full_round[state0_sq_offset as usize] =
                        round_state.after_add_round_keys[0].square();
                    full_round[state1_sq_offset as usize] =
                        round_state.after_add_round_keys[1].square();
                    full_round[state2_sq_offset as usize] =
                        round_state.after_add_round_keys[2].square();
                }

                {
                    // TODO: remove
                    let partial_round_states = poseidon_trace.partial_round_states;

                    let (c0, state0_offset) = Poseidon::PartialRoundsState0.col_and_shift();
                    let (c1, state0_sq_offset) =
                        Poseidon::PartialRoundsState0Squared.col_and_shift();
                    assert_eq!((c0, c1), (7, 7));

                    // load in the first 64 partial rounds
                    let (partial_rounds0, _) = rc.as_chunks_mut::<8>();
                    for (round, state) in zip(partial_rounds0, &partial_round_states) {
                        round[state0_offset as usize] = state.after_add_round_key;
                        round[state0_sq_offset as usize] = state.after_add_round_key.square();
                    }

                    let (c0, state1_offset) = Poseidon::PartialRoundsState1.col_and_shift();
                    let (c1, state1_sq_offset) =
                        Poseidon::PartialRoundsState1Squared.col_and_shift();
                    assert_eq!((c0, c1), (8, 8));

                    // load in the last 22 partial rounds
                    let (partial_rounds1, _) = aux.as_chunks_mut::<16>();
                    for (round, state) in zip(partial_rounds1, &partial_round_states[64 - 3..]) {
                        round[state1_offset as usize] = state.after_add_round_key;
                        round[state1_sq_offset as usize] = state.after_add_round_key.square();
                    }
                }

                // load EC op values into memory
                let instance = poseidon_trace.instance;
                let (
                    input0_addr,
                    input1_addr,
                    input2_addr,
                    output0_addr,
                    output1_addr,
                    output2_addr,
                ) = instance.mem_addr(initial_poseidon_address);
                npc[Npc::PoseidonInput0Addr as usize] = input0_addr.into();
                npc[Npc::PoseidonInput0Val as usize] = poseidon_trace.input0;
                npc[Npc::PoseidonInput1Addr as usize] = input1_addr.into();
                npc[Npc::PoseidonInput1Val as usize] = poseidon_trace.input1;
                npc[Npc::PoseidonInput2Addr as usize] = input2_addr.into();
                npc[Npc::PoseidonInput2Val as usize] = poseidon_trace.input2;
                npc[Npc::PoseidonOutput0Addr as usize] = output0_addr.into();
                npc[Npc::PoseidonOutput0Val as usize] = poseidon_trace.output0;
                npc[Npc::PoseidonOutput1Addr as usize] = output1_addr.into();
                npc[Npc::PoseidonOutput1Val as usize] = poseidon_trace.output1;
                npc[Npc::PoseidonOutput2Addr as usize] = output2_addr.into();
                npc[Npc::PoseidonOutput2Val as usize] = poseidon_trace.output2;
            });

        // VM Memory
        // =========
        // generate the memory column by ordering memory accesses

        {
            // TODO: this is a bandaid hack. find better solution
            // goal is to find any gaps in memory and fill them in
            let mut sorted_memory_accesses: Vec<MemoryEntry<Fp>> = npc_column
                .array_chunks()
                .map(|&[address, value]| {
                    let address = u32::try_from(U256::from_limbs(address.into_bigint().0)).unwrap();
                    MemoryEntry { value, address }
                })
                .chain(public_memory.clone())
                .collect();
            sorted_memory_accesses.sort_unstable_by_key(|e| e.address);
            let mut padding_addrs = Vec::new();
            for [a, b] in sorted_memory_accesses.array_windows() {
                let a_addr = a.address;
                let b_addr = b.address;
                for padding_addr in a_addr.saturating_add(1)..b_addr {
                    padding_addrs.push(padding_addr)
                }
            }
            let mut padding_addrs = padding_addrs.into_iter();
            for npc_cycle in npc_column.array_chunks_mut::<CYCLE_HEIGHT>() {
                let addr = match padding_addrs.next() {
                    Some(v) => v,
                    None => break,
                };
                npc_cycle[Npc::UnusedAddr as usize] = addr.into();
                npc_cycle[Npc::UnusedVal as usize] = Fp::ZERO;
            }
            // ensure padding has been fully consumed
            assert!(padding_addrs.next().is_none());
        }

        let memory_accesses: Vec<MemoryEntry<Fp>> = npc_column
            .array_chunks()
            .map(|&[address_felt, value_felt]| MemoryEntry {
                address: U256::from_limbs(address_felt.into_bigint().0)
                    .try_into()
                    .unwrap(),
                value: value_felt,
            })
            .collect();
        let ordered_memory_accesses = get_ordered_memory_accesses::<PUBLIC_MEMORY_STEP, Fp>(
            trace_len,
            &memory_accesses,
            &public_memory,
            padding_entry,
        );
        let memory_column = ordered_memory_accesses
            .into_iter()
            .flat_map(|e| [e.address.into(), e.value])
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
            air_public_input,
            public_memory,
            padding_entry,
            range_check_min,
            range_check_max,
            initial_registers,
            final_registers,
            npc_column,
            memory_column,
            range_check_column,
            base_trace,
            initial_pedersen_address,
            initial_rc_address,
            initial_ecdsa_address,
            initial_bitwise_address,
            initial_ec_op_address,
            program,
            _flags_column: flags_column,
            _auxiliary_column: auxiliary_column,
            _memory: memory,
            _register_states: register_states,
        }
    }
}

impl Trace for ExecutionTrace {
    type Fp = Fp;
    type Fq = Fp;

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        &self.base_trace
    }

    fn build_extension_columns(&self, challenges: &Challenges<Fp>) -> Option<Matrix<Fp>> {
        // TODO: multithread
        // generate memory permutation product
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
        let mem_perm_denominators_inv = mem_perm_denominators;

        // generate range check permutation product
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
        assert!((numerator_acc / denominator_acc).is_one());
        batch_inversion(&mut rc_perm_denominators);
        let rc_perm_denominators_inv = rc_perm_denominators;

        // generate diluted check permutation product
        // ==========================================
        let z = challenges[DilutedCheckPermutation::Z];
        let diluted_check_chunks = self.range_check_column.array_chunks::<DILUTED_CHECK_STEP>();
        let mut dc_perm_numerators = Vec::new();
        let mut dc_perm_denominators = Vec::new();
        let mut numerator_acc = Fp::one();
        let mut denominator_acc = Fp::one();
        for chunk in diluted_check_chunks {
            numerator_acc *= z - chunk[DilutedCheck::Unordered as usize];
            denominator_acc *= z - chunk[DilutedCheck::Ordered as usize];
            dc_perm_numerators.push(numerator_acc);
            dc_perm_denominators.push(denominator_acc);
        }
        assert!((numerator_acc / denominator_acc).is_one());
        batch_inversion(&mut dc_perm_denominators);
        let dc_perm_denominators_inv = dc_perm_denominators;

        let mut permutation_column = Vec::new_in(GpuAllocator);
        permutation_column.resize(self.base_columns().num_rows(), Fp::zero());

        // insert intermediate memory permutation results
        for (i, (n, d_inv)) in zip(mem_perm_numerators, mem_perm_denominators_inv).enumerate() {
            permutation_column[i * MEMORY_STEP + Permutation::Memory as usize] = n * d_inv;
        }

        // insert intermediate range check results
        for (i, (n, d_inv)) in zip(rc_perm_numerators, rc_perm_denominators_inv).enumerate() {
            permutation_column[i * RANGE_CHECK_STEP + Permutation::RangeCheck as usize] = n * d_inv;
        }

        assert!(
            (dc_perm_numerators.last().unwrap() * dc_perm_denominators_inv.last().unwrap())
                .is_one()
        );

        // insert intermediate diluted check results
        for (i, (n, d_inv)) in zip(dc_perm_numerators, dc_perm_denominators_inv).enumerate() {
            permutation_column[i * DILUTED_CHECK_STEP + Permutation::DilutedCheck as usize] =
                n * d_inv;
        }

        // generate aggregation of diluted checks
        // ======================================
        let z = challenges[DilutedCheckAggregation::Z];
        let alpha = challenges[DilutedCheckAggregation::A];
        let (diluted_check_chunks, _) = self.range_check_column.as_chunks::<DILUTED_CHECK_STEP>();

        // insert initial value
        let initial = Fp::one();
        permutation_column[DilutedCheck::Aggregate as usize] = initial;

        // insert intermediate aggregation results
        let mut acc = initial;
        for (i, [prev_step, curr_step]) in zip(1.., diluted_check_chunks.array_windows()) {
            let prev = prev_step[DilutedCheck::Ordered as usize];
            let curr = curr_step[DilutedCheck::Ordered as usize];
            let u = curr - prev;
            acc = acc * (Fp::ONE + z * u) + alpha * u.square();
            permutation_column[i * DILUTED_CHECK_STEP + DilutedCheck::Aggregate as usize] = acc;
        }

        Some(Matrix::new(vec![permutation_column]))
    }
}
