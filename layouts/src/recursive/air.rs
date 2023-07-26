use super::BITWISE_RATIO;
use super::PEDERSEN_BUILTIN_RATIO;
use super::CYCLE_HEIGHT;
use super::MEMORY_STEP;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_BUILTIN_PARTS;
use super::RANGE_CHECK_BUILTIN_RATIO;
use super::RANGE_CHECK_STEP;
use super::DILUTED_CHECK_STEP;
use super::DILUTED_CHECK_N_BITS;
use super::DILUTED_CHECK_SPACING;
use crate::SharpAirConfig;
use crate::utils;
use crate::utils::compute_diluted_cumulative_value;
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use binary::AirPublicInput;
use builtins::pedersen;
use ministark::constraints::CompositionConstraint;
use ministark::constraints::CompositionItem;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_traits::One;
use core::ops::Add;
use core::ops::Mul;
use ark_ff::Field;
use ministark::challenges::Challenges;
use ministark::constraints::AlgebraicItem;
use ministark::constraints::Constraint;
use ministark::constraints::ExecutionTraceColumn;
use ministark::constraints::Hint;
use ministark::constraints::VerifierChallenge;
use ministark::expression::Expr;
use ministark::hints::Hints;
use ministark::utils::FieldVariant;
use num_bigint::BigUint;
use num_traits::Pow;
use num_traits::Zero;
use strum_macros::EnumIter;

pub struct AirConfig;

impl ministark::air::AirConfig for AirConfig {
    const NUM_BASE_COLUMNS: usize = 7;
    const NUM_EXTENSION_COLUMNS: usize = 3;
    type Fp = Fp;
    type Fq = Fp;
    type PublicInputs = AirPublicInput<Fp>;

    fn constraints(trace_len: usize) -> Vec<Constraint<FieldVariant<Fp, Fp>>> {
        use AlgebraicItem::*;
        use PublicInputHint::*;
        // TODO: figure out why this value
        let n = trace_len;
        let trace_domain = Radix2EvaluationDomain::<Fp>::new(n).unwrap();
        let g = trace_domain.group_gen();
        assert!(n >= CYCLE_HEIGHT, "must be a multiple of cycle height");
        // TODO: might be good to have more trace size assertions for builtins etc.
        // for example ECDSA requires a minimum trace size of 2048 for this layout.
        // NOTE: All this stuff is taken care by the runner of if you run properly
        // i.e correct params
        let x = Expr::from(X);
        let one = Expr::from(Constant(FieldVariant::Fp(Fp::ONE)));
        let two = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32))));
        let four = Expr::from(Constant(FieldVariant::Fp(Fp::from(4u32))));
        let offset_size = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32.pow(16)))));
        let half_offset_size = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32.pow(15)))));

        // cpu/decode/flag_op1_base_op0_0
        let cpu_decode_flag_op1_base_op0_0 =
            &one - (Flag::Op1Imm.curr() + Flag::Op1Ap.curr() + Flag::Op1Fp.curr());
        // cpu/decode/flag_res_op1_0
        let cpu_decode_flag_res_op1_0 =
            &one - (Flag::ResAdd.curr() + Flag::ResMul.curr() + Flag::PcJnz.curr());
        // cpu/decode/flag_pc_update_regular_0
        let cpu_decode_flag_pc_update_regular_0 =
            &one - (Flag::PcJumpAbs.curr() + Flag::PcJumpRel.curr() + Flag::PcJnz.curr());
        // cpu/decode/fp_update_regular_0
        let cpu_decode_fp_update_regular_0 =
            &one - (Flag::OpcodeCall.curr() + Flag::OpcodeRet.curr());

        // NOTE: npc_reg_0 = pc + instruction_size
        // NOTE: instruction_size = fOP1_IMM + 1
        let npc_reg_0 = Npc::Pc.curr() + Flag::Op1Imm.curr() + &one;

        let memory_address_diff_0 = Mem::Address.next() - Mem::Address.curr();

        let rc16_diff_0 = RangeCheck::Ordered.next() - RangeCheck::Ordered.curr();

        // TODO: builtins
        let pedersen_hash0_ec_subset_sum_b0 =
            Pedersen::Suffix.curr() - (Pedersen::Suffix.next() + Pedersen::Suffix.next());
        let pedersen_hash0_ec_subset_sum_b0_negate = &one - &pedersen_hash0_ec_subset_sum_b0;
        let rc_builtin_value0_0 = RangeCheckBuiltin::Rc16Component.offset(0);
        let rc_builtin_value1_0 =
            &rc_builtin_value0_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(1);
        let rc_builtin_value2_0 =
            &rc_builtin_value1_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(2);
        let rc_builtin_value3_0 =
            &rc_builtin_value2_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(3);
        let rc_builtin_value4_0 =
            &rc_builtin_value3_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(4);
        let rc_builtin_value5_0 =
            &rc_builtin_value4_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(5);
        let rc_builtin_value6_0 =
            &rc_builtin_value5_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(6);
        let rc_builtin_value7_0 =
            &rc_builtin_value6_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(7);

        // bits 0->127 (inclusive) of a bitwise number
        let bitwise_sum_var_0_0 = Bitwise::Bits16Chunk0Offset0.curr()
            + Bitwise::Bits16Chunk0Offset1.curr() * (&two).pow(1)
            + Bitwise::Bits16Chunk0Offset2.curr() * (&two).pow(2)
            + Bitwise::Bits16Chunk0Offset3.curr() * (&two).pow(3)
            + Bitwise::Bits16Chunk1Offset0.curr() * (&two).pow(64)
            + Bitwise::Bits16Chunk1Offset1.curr() * (&two).pow(65)
            + Bitwise::Bits16Chunk1Offset2.curr() * (&two).pow(66)
            + Bitwise::Bits16Chunk1Offset3.curr() * (&two).pow(67);
        // bits 128->255 (inclusive) of a bitwise number
        let bitwise_sum_var_8_0 = Bitwise::Bits16Chunk2Offset0.curr() * (&two).pow(128)
            + Bitwise::Bits16Chunk2Offset1.curr() * (&two).pow(129)
            + Bitwise::Bits16Chunk2Offset2.curr() * (&two).pow(130)
            + Bitwise::Bits16Chunk2Offset3.curr() * (&two).pow(131)
            + Bitwise::Bits16Chunk3Offset0.curr() * (&two).pow(192)
            + Bitwise::Bits16Chunk3Offset1.curr() * (&two).pow(193)
            + Bitwise::Bits16Chunk3Offset2.curr() * (&two).pow(194)
            + Bitwise::Bits16Chunk3Offset3.curr() * (&two).pow(195);

        // example for trace length n=64
        // =============================
        // x^(n/16)                 = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // x^(n/16) - c             = (x - c*ω_0)(x - c*ω_16)(x - c*ω_32)(x - c*ω_48)
        // x^(n/16) - ω^(n/16)      = (x - ω_1)(x - ω_17)(x - ω_33)(x - )
        // x^(n/16) - ω^(n/16)^(15) = (x - ω_15)(x - ω_31)(x - ω_47)(x - ω_6ω_493)
        let flag0_offset =
            FieldVariant::Fp(g.pow([(Flag::Zero as usize * n / CYCLE_HEIGHT) as u64]));
        let flag0_zerofier = X.pow(n / CYCLE_HEIGHT) - Constant(flag0_offset);
        let every_row_zerofier = X.pow(n) - &one;
        let every_row_zerofier_inv = &one / &every_row_zerofier;
        let flags_zerofier_inv = &flag0_zerofier * &every_row_zerofier_inv;

        // check decoded flag values are 0 or 1
        // NOTE: This expression is a bit confusing. The zerofier forces this constraint
        // to apply in all rows of the trace therefore it applies to all flags (not just
        // DstReg). Funnily enough any flag here would work (it just wouldn't be SHARP
        // compatible).
        let cpu_decode_opcode_rc_b =
            (Flag::DstReg.curr() * Flag::DstReg.curr() - Flag::DstReg.curr()) * &flags_zerofier_inv;

        // The first word of each instruction:
        // ┌─────────────────────────────────────────────────────────────────────────┐
        // │                     off_dst (biased representation)                     │
        // ├─────────────────────────────────────────────────────────────────────────┤
        // │                     off_op0 (biased representation)                     │
        // ├─────────────────────────────────────────────────────────────────────────┤
        // │                     off_op1 (biased representation)                     │
        // ├─────┬─────┬───────┬───────┬───────────┬────────┬───────────────────┬────┤
        // │ dst │ op0 │  op1  │  res  │    pc     │   ap   │      opcode       │ 0  │
        // │ reg │ reg │  src  │ logic │  update   │ update │                   │    │
        // ├─────┼─────┼───┬───┼───┬───┼───┬───┬───┼───┬────┼────┬────┬────┬────┼────┤
        // │  0  │  1  │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 10 │ 11 │ 12 │ 13 │ 14 │ 15 │
        // └─────┴─────┴───┴───┴───┴───┴───┴───┴───┴───┴────┴────┴────┴────┴────┴────┘
        let whole_flag_prefix = Expr::from(Trace(0, 0));
        // NOTE: Forces the `0` flag prefix to =0 in every cycle.
        let cpu_decode_opcode_rc_zero = &whole_flag_prefix / flag0_zerofier;

        // force constraint to apply every 16 trace rows (every cairo cycle)
        // e.g. (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48) for n=64
        let all_cycles_zerofier = X.pow(n / CYCLE_HEIGHT) - &one;
        let all_cycles_zerofier_inv = &one / all_cycles_zerofier;
        let cpu_decode_opcode_rc_input = (Npc::Instruction.curr()
            - (((&whole_flag_prefix * &offset_size + RangeCheck::OffOp1.curr()) * &offset_size
                + RangeCheck::OffOp0.curr())
                * &offset_size
                + RangeCheck::OffDst.curr()))
            * &all_cycles_zerofier_inv;

        // constraint for the Op1Src flag group - forces vals 000, 100, 010 or 001
        let cpu_decode_flag_op1_base_op0_bit = (&cpu_decode_flag_op1_base_op0_0
            * &cpu_decode_flag_op1_base_op0_0
            - &cpu_decode_flag_op1_base_op0_0)
            * &all_cycles_zerofier_inv;

        // forces only one or none of ResAdd, ResMul or PcJnz to be 1
        // TODO: Why the F is PcJnz in here? Res flag group is only bit 5 and 6
        // NOTE: looks like it's a handy optimization to calculate next_fp and next_ap
        let cpu_decode_flag_res_op1_bit = (&cpu_decode_flag_res_op1_0 * &cpu_decode_flag_res_op1_0
            - &cpu_decode_flag_res_op1_0)
            * &all_cycles_zerofier_inv;

        // constraint forces PcUpdate flag to be 000, 100, 010 or 001
        let cpu_decode_flag_pc_update_regular_bit = (&cpu_decode_flag_pc_update_regular_0
            * &cpu_decode_flag_pc_update_regular_0
            - &cpu_decode_flag_pc_update_regular_0)
            * &all_cycles_zerofier_inv;

        // forces max only OpcodeRet or OpcodeAssertEq to be 1
        // TODO: why OpcodeCall not included? that would make whole flag group
        let cpu_decode_fp_update_regular_bit = (&cpu_decode_fp_update_regular_0
            * &cpu_decode_fp_update_regular_0
            - &cpu_decode_fp_update_regular_0)
            * &all_cycles_zerofier_inv;

        // cpu/operands/mem_dst_addr
        // NOTE: Pseudo code from cairo whitepaper
        // ```
        // if dst_reg == 0:
        //     dst = m(ap + offdst)
        // else:
        //     dst = m(fp + offdst)
        // ```
        // NOTE: Trace(5, 8) dest mem address
        let cpu_operands_mem_dst_addr = (Npc::MemDstAddr.curr() + &half_offset_size
            - (Flag::DstReg.curr() * Auxiliary::Fp.curr()
                + (&one - Flag::DstReg.curr()) * Auxiliary::Ap.curr()
                + RangeCheck::OffDst.curr()))
            * &all_cycles_zerofier_inv;

        // whitepaper pseudocode
        // ```
        // # Compute op0.
        // if op0_reg == 0:
        //     op0 = m(-->>ap + offop0<<--)
        // else:
        //     op0 = m(-->>fp + offop0<<--)
        // ```
        // NOTE: StarkEx contracts as: cpu_operands_mem0_addr
        let cpu_operands_mem_op0_addr = (Npc::MemOp0Addr.curr() + &half_offset_size
            - (Flag::Op0Reg.curr() * Auxiliary::Fp.curr()
                + (&one - Flag::Op0Reg.curr()) * Auxiliary::Ap.curr()
                + RangeCheck::OffOp0.curr()))
            * &all_cycles_zerofier_inv;

        // NOTE: StarkEx contracts as: cpu_operands_mem1_addr
        let cpu_operands_mem_op1_addr = (Npc::MemOp1Addr.curr() + &half_offset_size
            - (Flag::Op1Imm.curr() * Npc::Pc.curr()
                + Flag::Op1Ap.curr() * Auxiliary::Ap.curr()
                + Flag::Op1Fp.curr() * Auxiliary::Fp.curr()
                + &cpu_decode_flag_op1_base_op0_0 * Npc::MemOp0.curr()
                + RangeCheck::OffOp1.curr()))
            * &all_cycles_zerofier_inv;

        // op1 * op0
        // NOTE: starkex cpu/operands/ops_mul
        let cpu_operands_ops_mul = (Auxiliary::Op0MulOp1.curr()
            - Npc::MemOp0.curr() * Npc::MemOp1.curr())
            * &all_cycles_zerofier_inv;

        // From cairo whitepaper
        // ```
        // # Compute res.
        // if pc_update == 4:
        //     if res_logic == 0 && opcode == 0 && ap_update != 1:
        //         res = Unused
        //     else:
        //         Undefined Behavior
        // else if pc_update = 0, 1 or 2:
        //     switch res_logic:
        //         case 0: res = op1
        //         case 1: res = op0 + op1
        //         case 2: res = op0 * op1
        //         default: Undefined Behavior
        // else: Undefined Behavior
        // ```
        // NOTE: this constraint only handles:
        // ```
        // else if pc_update = 0, 1 or 2:
        //   switch res_logic:
        //     case 0: res = op1
        //     case 1: res = op0 + op1
        //     case 2: res = op0 * op1
        // ```
        let cpu_operands_res = ((&one - Flag::PcJnz.curr()) * Auxiliary::Res.curr()
            - (Flag::ResAdd.curr() * (Npc::MemOp0.curr() + Npc::MemOp1.curr())
                + Flag::ResMul.curr() * Auxiliary::Op0MulOp1.curr()
                + &cpu_decode_flag_res_op1_0 * Npc::MemOp1.curr()))
            * &all_cycles_zerofier_inv;

        // example for trace length n=64
        // =============================
        // all_cycles_zerofier              = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // X - ω^(16*(n/16 - 1))            = x - ω^n/w^16 = x - 1/w_16 = x - w_48
        // (X - w_48) / all_cycles_zerofier = (x - ω_0)(x - ω_16)(x - ω_32)
        let last_cycle_zerofier = X - Constant(FieldVariant::Fp(
            g.pow([(CYCLE_HEIGHT * (n / CYCLE_HEIGHT - 1)) as u64]),
        ));
        let last_cycle_zerofier_inv = &one / &last_cycle_zerofier;
        let all_cycles_except_last_zerofier_inv = &last_cycle_zerofier * &all_cycles_zerofier_inv;

        // Updating the program counter
        // ============================
        // This is not as straight forward as the other constraints. Read section 9.5
        // Updating pc to understand.

        // from whitepaper `t0 = fPC_JNZ * dst`
        let cpu_update_registers_update_pc_tmp0 = (Auxiliary::Tmp0.curr()
            - Flag::PcJnz.curr() * Npc::MemDst.curr())
            * &all_cycles_except_last_zerofier_inv;

        // From the whitepaper "To verify that we make a regular update if dst = 0, we
        // need an auxiliary variable, v (to fill the trace in the case dst != 0, set v
        // = dst^(−1)): `fPC_JNZ * (dst * v − 1) * (next_pc − (pc + instruction_size)) =
        // 0` NOTE: if fPC_JNZ=1 then `res` is "unused" and repurposed as our
        // temporary variable `v`. The value assigned to v is `dst^(−1)`.
        // NOTE: `t1 = t0 * v`
        let cpu_update_registers_update_pc_tmp1 = (Auxiliary::Tmp1.curr()
            - Auxiliary::Tmp0.curr() * Auxiliary::Res.curr())
            * &all_cycles_except_last_zerofier_inv;

        // There are two constraints here bundled in one. The first is `t0 * (next_pc −
        // (pc + op1)) = 0` (ensures if dst != 0 a relative jump is made) and the second
        // is `(1−fPC_JNZ) * next_pc - (regular_update * (pc + instruction_size) +
        // fPC_JUMP_ABS * res + fPC_JUMP_REL * (pc + res)) = 0` (handles update except
        // for jnz). Note that due to the flag group constraints for PcUpdate if jnz=1
        // then the second constraint is trivially 0=0 and if jnz=0 then the first
        // constraint is trivially 0=0. For this reason we can bundle these constraints
        // into one.
        // TODO: fix padding bug
        let cpu_update_registers_update_pc_pc_cond_negative = ((&one - Flag::PcJnz.curr())
            * Npc::Pc.next()
            + Auxiliary::Tmp0.curr() * (Npc::Pc.next() - (Npc::Pc.curr() + Npc::MemOp1.curr()))
            - (&cpu_decode_flag_pc_update_regular_0 * &npc_reg_0
                + Flag::PcJumpAbs.curr() * Auxiliary::Res.curr()
                + Flag::PcJumpRel.curr() * (Npc::Pc.curr() + Auxiliary::Res.curr())))
            * &all_cycles_except_last_zerofier_inv;

        // ensure `if dst == 0: pc + instruction_size == next_pc`
        let cpu_update_registers_update_pc_pc_cond_positive =
            ((Auxiliary::Tmp1.curr() - Flag::PcJnz.curr()) * (Npc::Pc.next() - npc_reg_0))
                * &all_cycles_except_last_zerofier_inv;

        // Updating the allocation pointer
        // ===============================
        // TODO: seems fishy don't see how `next_ap = ap + fAP_ADD · res + fAP_ADD1 · 1
        // + fOPCODE_CALL · 2` meets the pseudo code in the whitepaper
        // Ok, it does kinda make sense. move the `opcode == 1` statement inside and
        // move the switch to the outside and it's more clear.
        let cpu_update_registers_update_ap_ap_update = (Auxiliary::Ap.next()
            - (Auxiliary::Ap.curr()
                + Flag::ApAdd.curr() * Auxiliary::Res.curr()
                + Flag::ApAdd1.curr()
                + Flag::OpcodeCall.curr() * &two))
            * &all_cycles_except_last_zerofier_inv;

        // Updating the frame pointer
        // ==========================
        // This handles all fp update except the `op0 == pc + instruction_size`, `res =
        // dst` and `dst == fp` assertions.
        // TODO: fix padding bug
        let cpu_update_registers_update_fp_fp_update = (Auxiliary::Fp.next()
            - (&cpu_decode_fp_update_regular_0 * Auxiliary::Fp.curr()
                + Flag::OpcodeRet.curr() * Npc::MemDst.curr()
                + Flag::OpcodeCall.curr() * (Auxiliary::Ap.curr() + &two)))
            * &all_cycles_except_last_zerofier_inv;

        // push registers to memory (see section 8.4 in the whitepaper).
        // These are essentially the assertions for assert `op0 == pc +
        // instruction_size` and `assert dst == fp`.
        let cpu_opcodes_call_push_fp = (Flag::OpcodeCall.curr()
            * (Npc::MemDst.curr() - Auxiliary::Fp.curr()))
            * &all_cycles_zerofier_inv;
        let cpu_opcodes_call_push_pc = (Flag::OpcodeCall.curr()
            * (Npc::MemOp0.curr() - (Npc::Pc.curr() + Flag::Op1Imm.curr() + &one)))
            * &all_cycles_zerofier_inv;

        // make sure all offsets are valid for the call opcode
        // ===================================================
        // checks `if opcode == OpcodeCall: assert off_dst = 2^15`
        // this is supplementary to the constraints above because
        // offsets are in the range [-2^15, 2^15) encoded using
        // biased representation
        let cpu_opcodes_call_off0 = (Flag::OpcodeCall.curr()
            * (RangeCheck::OffDst.curr() - &half_offset_size))
            * &all_cycles_zerofier_inv;
        // checks `if opcode == OpcodeCall: assert off_op0 = 2^15 + 1`
        // TODO: why +1?
        let cpu_opcodes_call_off1 = (Flag::OpcodeCall.curr()
            * (RangeCheck::OffOp0.curr() - (&half_offset_size + &one)))
            * &all_cycles_zerofier_inv;
        // TODO: I don't understand this one - Flag::OpcodeCall.curr() is 0 or 1. Why
        // not just replace `Flag::OpcodeCall.curr() + Flag::OpcodeCall.curr() +
        // &one + &one` with `4`
        let cpu_opcodes_call_flags = (Flag::OpcodeCall.curr()
            * (Flag::OpcodeCall.curr() + Flag::OpcodeCall.curr() + &one + &one
                - (Flag::DstReg.curr() + Flag::Op0Reg.curr() + &four)))
            * &all_cycles_zerofier_inv;
        // checks `if opcode == OpcodeRet: assert off_dst = 2^15 - 2`
        // TODO: why -2 🤯? Instruction size?
        let cpu_opcodes_ret_off0 = (Flag::OpcodeRet.curr()
            * (RangeCheck::OffDst.curr() + &two - &half_offset_size))
            * &all_cycles_zerofier_inv;
        // checks `if opcode == OpcodeRet: assert off_op1 = 2^15 - 1`
        // TODO: why -1?
        let cpu_opcodes_ret_off2 = (Flag::OpcodeRet.curr()
            * (RangeCheck::OffOp1.curr() + &one - &half_offset_size))
            * &all_cycles_zerofier_inv;
        // checks `if OpcodeRet: assert PcJumpAbs=1, DstReg=1, Op1Fp=1, ResLogic=0`
        let cpu_opcodes_ret_flags = (Flag::OpcodeRet.curr()
            * (Flag::PcJumpAbs.curr()
                + Flag::DstReg.curr()
                + Flag::Op1Fp.curr()
                + &cpu_decode_flag_res_op1_0
                - &four))
            * &all_cycles_zerofier_inv;
        // handles the "assert equal" instruction. Represents this pseudo code from the
        // whitepaper `assert res = dst`.
        let cpu_opcodes_assert_eq_assert_eq = (Flag::OpcodeAssertEq.curr()
            * (Npc::MemDst.curr() - Auxiliary::Res.curr()))
            * &all_cycles_zerofier_inv;

        let first_row_zerofier = &x - &one;
        let first_row_zerofier_inv = &one / first_row_zerofier;

        // boundary constraint expression for initial registers
        let initial_ap = (Auxiliary::Ap.curr() - InitialAp.hint()) * &first_row_zerofier_inv;
        let initial_fp = (Auxiliary::Fp.curr() - InitialAp.hint()) * &first_row_zerofier_inv;
        let initial_pc = (Npc::Pc.curr() - InitialPc.hint()) * &first_row_zerofier_inv;

        // boundary constraint expression for final registers
        let final_ap = (Auxiliary::Ap.curr() - FinalAp.hint()) * &last_cycle_zerofier_inv;
        let final_fp = (Auxiliary::Fp.curr() - InitialAp.hint()) * &last_cycle_zerofier_inv;
        let final_pc = (Npc::Pc.curr() - FinalPc.hint()) * &last_cycle_zerofier_inv;

        // examples for trace length n=8
        // =============================
        // x^(n/2) - 1             = (x - ω_0)(x - ω_2)(x - ω_4)(x - ω_6)
        // x - ω^(2*(n/2 - 1))     = x - ω^n/w^2 = x - 1/w_2 = x - w_6
        // (x - w_6) / x^(n/2) - 1 = (x - ω_0)(x - ω_2)(x - ω_4)
        let every_second_row_zerofier = X.pow(n / 2) - &one;
        let second_last_row_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([2 * (n as u64 / 2 - 1)])));
        let every_second_row_except_last_zerofier_inv =
            &second_last_row_zerofier / &every_second_row_zerofier;

        // Memory access constraints
        // =========================
        // All these constraints make more sense once you understand how the permutation
        // column is calculated (look at get_ordered_memory_accesses()). Sections 9.8
        // and 9.7 of the Cairo paper justify these constraints.
        // memory permutation boundary constraint
        let memory_multi_column_perm_perm_init0 = ((MemoryPermutation::Z.challenge()
            - (Mem::Address.curr() + MemoryPermutation::A.challenge() * Mem::Value.curr()))
            * Permutation::Memory.curr()
            + Npc::Pc.curr()
            + MemoryPermutation::A.challenge() * Npc::Instruction.curr()
            - MemoryPermutation::Z.challenge())
            * &first_row_zerofier_inv;
        // memory permutation transition constraint
        // NOTE: memory entries are stacked in the trace like so:
        // ┌─────┬───────────┬─────┐
        // │ ... │    ...    │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │ address 0 │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │  value 0  │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │ address 1 │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │  value 1  │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │    ...    │ ... │
        // └─────┴───────────┴─────┘
        let memory_multi_column_perm_perm_step0 = ((MemoryPermutation::Z.challenge()
            - (Mem::Address.next() + MemoryPermutation::A.challenge() * Mem::Value.next()))
            * Permutation::Memory.next()
            - (MemoryPermutation::Z.challenge()
                - (Npc::PubMemAddr.curr()
                    + MemoryPermutation::A.challenge() * Npc::PubMemVal.curr()))
                * Permutation::Memory.curr())
            * &every_second_row_except_last_zerofier_inv;
        // Check the last permutation value to verify public memory
        let memory_multi_column_perm_perm_last =
            (Permutation::Memory.curr() - MemoryQuotient.hint()) / &second_last_row_zerofier;
        // Constraint expression for memory/diff_is_bit
        // checks the address doesn't change or increases by 1
        // "Continuity" constraint in cairo whitepaper 9.7.2
        let memory_diff_is_bit = (&memory_address_diff_0 * &memory_address_diff_0
            - &memory_address_diff_0)
            * &every_second_row_except_last_zerofier_inv;
        // if the address stays the same then the value stays the same
        // "Single-valued" constraint in cairo whitepaper 9.7.2.
        // cairo uses nondeterministic read-only memory so if the address is the same
        // the value should also stay the same.
        let memory_is_func = ((&memory_address_diff_0 - &one)
            * (Mem::Value.curr() - Mem::Value.next()))
            * &every_second_row_except_last_zerofier_inv;
        // boundary condition stating the first memory address == 1
        let memory_initial_addr = (Mem::Address.curr() - &one) * &first_row_zerofier_inv;
        // applies every 8 rows
        // Read cairo whitepaper section 9.8 as to why the public memory cells are 0.
        // The high level is that the way public memory works is that the prover is
        // forced (with these constraints) to exclude the public memory from one of
        // the permutation products. This means the running permutation column
        // terminates with more-or-less the permutation of just the public input. The
        // verifier can relatively cheaply calculate this terminal. The constraint for
        // this terminal is `memory_multi_column_perm_perm_last`.
        let public_memory_addr_zero = Npc::PubMemAddr.curr() * &all_cycles_zerofier_inv;
        let public_memory_value_zero = Npc::PubMemVal.curr() * &all_cycles_zerofier_inv;

        // examples for trace length n=16
        // =====================================
        // x^(n/4) - 1              = (x - ω_0)(x - ω_4)(x - ω_8)(x - ω_12)
        // x - ω^(4*(n/4 - 1))      = x - ω^n/w^4 = x - 1/w_4 = x - w_12
        // (x - w_12) / x^(n/4) - 1 = (x - ω_0)(x - ω_4)(x - ω_8)
        let every_fourth_row_zerofier_inv = &one / (X.pow(n / 4) - &one);
        let fourth_last_row_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([4 * (n as u64 / 4 - 1)])));
        let every_fourth_row_except_last_zerofier_inv =
            &fourth_last_row_zerofier * &every_fourth_row_zerofier_inv;

        // Range check constraints
        // =======================
        // Look at memory to understand the general approach to permutation.
        // More info in section 9.9 of the Cairo paper.
        let rc16_perm_init0 = ((RangeCheckPermutation::Z.challenge() - RangeCheck::Ordered.curr())
            * Permutation::RangeCheck.curr()
            + RangeCheck::OffDst.curr()
            - RangeCheckPermutation::Z.challenge())
            * &first_row_zerofier_inv;
        let rc16_perm_step0 = ((RangeCheckPermutation::Z.challenge() - RangeCheck::Ordered.next())
            * Permutation::RangeCheck.next()
            - (RangeCheckPermutation::Z.challenge() - RangeCheck::OffOp1.curr())
                * Permutation::RangeCheck.curr())
            * &every_fourth_row_except_last_zerofier_inv;
        let rc16_perm_last =
            (Permutation::RangeCheck.curr() - RangeCheckProduct.hint()) / &fourth_last_row_zerofier;
        // Check the value increases by 0 or 1
        let rc16_diff_is_bit = (&rc16_diff_0 * &rc16_diff_0 - &rc16_diff_0)
            * &every_fourth_row_except_last_zerofier_inv;
        // Prover sends the minimim and maximum as a public input.
        // Verifier checks the RC min and max fall within [0, 2^16).
        let rc16_minimum =
            (RangeCheck::Ordered.curr() - RangeCheckMin.hint()) * &first_row_zerofier_inv;
        let rc16_maximum =
            (RangeCheck::Ordered.curr() - RangeCheckMax.hint()) / &fourth_last_row_zerofier;

        // Diluted Check constraints
        // =========================
        // A "dilution" is spreading out of the bits in a number.
        // Dilutions have two parameters (1) the number of bits they operate on and
        // (2) the spread of each bit. For example the the dilution of binary
        // digit 1111 to 0001000100010001 operates on 4 bits with a spread of 4.
        let diluted_check_permutation_init0 = ((DilutedCheckPermutation::Z.challenge()
            - DilutedCheck::Ordered.curr())
            * Permutation::DilutedCheck.curr()
            + DilutedCheck::Unordered.curr()
            - DilutedCheckPermutation::Z.challenge())
            * &first_row_zerofier_inv;

        // Diluted checks operate every row (16 times per cycle)
        let last_row_zerofier = X - Constant(FieldVariant::Fp(g.pow([n as u64 - 1])));
        let last_row_zerofier_inv = &one / &last_row_zerofier;
        let every_row_except_last_zerofier_inv = &last_row_zerofier * &one / &every_row_zerofier;
        // we have an out-of-order and in-order list of diluted values for this layout
        // (starknet). We want to check each list is a permutation of one another
        let diluted_check_permutation_step0 = ((DilutedCheckPermutation::Z.challenge()
            - DilutedCheck::Ordered.next())
            * Permutation::DilutedCheck.next()
            - (DilutedCheckPermutation::Z.challenge() - DilutedCheck::Unordered.next())
                * Permutation::DilutedCheck.curr())
            * &every_row_except_last_zerofier_inv;
        let diluted_check_permutation_last = (Permutation::DilutedCheck.curr()
            - DilutedCheckProduct.hint())
            * &last_row_zerofier_inv;

        // Initial aggregate value should be =1
        let diluted_check_init = (DilutedCheck::Aggregate.curr() - &one) * &first_row_zerofier_inv;

        // Check first, in-order, diluted value
        let diluted_check_first_element =
            (DilutedCheck::Ordered.curr() - DilutedCheckFirst.hint()) * &first_row_zerofier_inv;

        // TODO: add more docs
        // `diluted_diff` is related to `u` in `compute_diluted_cumulative_value`
        // Note that if there is no difference between the current and next ordered
        // diluted values then `diluted_diff == 0` and the previous aggregate value is
        // copied over
        let diluted_diff = DilutedCheck::Ordered.next() - DilutedCheck::Ordered.curr();
        let diluted_check_step = (DilutedCheck::Aggregate.next()
            - (DilutedCheck::Aggregate.curr()
                * (&one + DilutedCheckAggregation::Z.challenge() * &diluted_diff)
                + DilutedCheckAggregation::A.challenge() * &diluted_diff * diluted_diff))
            * &every_row_except_last_zerofier_inv;

        // Check the last cumulative value.
        // NOTE: This can be calculated efficiently by the verifier.
        let diluted_check_last = (DilutedCheck::Aggregate.curr()
            - DilutedCheckCumulativeValue.hint())
            * &last_row_zerofier_inv;

        // Pedersen builtin
        // ================
        // Each hash spans across 256 rows - that's one hash per 16 cairo steps.
        let every_256_row_zerofier_inv = &one / (X.pow(n / 256) - &one);
        // let every_256_row_zerofier_inv = &one / (X.pow(n / 256) - &one);

        // These first few pedersen constraints check that the number is in the range
        // ```text
        //  100000000000000000000000000000000000000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
        //  ^                                                       ^    ^
        // 251                                                     196  191
        // ```

        // Use knowledge of bits 251,196,192 to determine if there is a unique unpacking
        let pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                * (Pedersen::Suffix.curr() - (Pedersen::Suffix.next() + Pedersen::Suffix.next())))
                * &every_256_row_zerofier_inv;
        let shift191 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(191u32))));
        let pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                * (Pedersen::Suffix.offset(1) - Pedersen::Suffix.offset(192) * shift191))
                * &every_256_row_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192 =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                - Pedersen::Bit251AndBit196.curr()
                    * (Pedersen::Suffix.offset(192)
                        - (Pedersen::Suffix.offset(193) + Pedersen::Suffix.offset(193))))
                * &every_256_row_zerofier_inv;
        let shift3 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(3u32))));
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192 =
            (Pedersen::Bit251AndBit196.curr()
                * (Pedersen::Suffix.offset(772) - Pedersen::Suffix.offset(784) * shift3))
                * &every_256_row_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196 =
            (Pedersen::Bit251AndBit196.curr()
                - (Pedersen::Suffix.offset(1004)
                    - (Pedersen::Suffix.offset(1008) + Pedersen::Suffix.offset(1008)))
                    * (Pedersen::Suffix.offset(784)
                        - (Pedersen::Suffix.offset(788) + Pedersen::Suffix.offset(788))))
                * &every_256_row_zerofier_inv;
        // TODO: docs
        let shift54 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(54u32))));
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196 = ((Pedersen::Suffix
            .offset(1004)
            - (Pedersen::Suffix.offset(1008) + Pedersen::Suffix.offset(1008)))
            * (Pedersen::Suffix.offset(788) - Pedersen::Suffix.offset(1004) * shift54))
            * &every_256_row_zerofier_inv;

        // example for trace length n=512
        // =============================
        // x^(n/256) - ω^(255*n/256)    = (x-ω^255)(x-ω^511)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the last row in each group
        // TODO: come up with better names for these
        let pedersen_transition_zerofier_inv = (X.pow(n / 256)
            - Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            * &every_row_zerofier_inv;

        // Constraint operated on groups of 256 rows.
        // Each row shifts a large number to the right. E.g.
        // ```text
        // row0:   10101...10001 <- constraint applied
        // row1:    1010...11000 <- constraint applied
        // ...               ... <- constraint applied
        // row255:             0 <- constraint disabled
        // row256: 11101...10001 <- constraint applied
        // row257:  1110...01000 <- constraint applied
        // ...               ... <- constraint applied
        // row511:             0 <- constraint disabled
        // ...               ...
        // ```
        let pedersen_hash0_ec_subset_sum_booleanity_test = (&pedersen_hash0_ec_subset_sum_b0
            * (&pedersen_hash0_ec_subset_sum_b0 - &one))
            * &pedersen_transition_zerofier_inv;

        // example for trace length n=512
        // =============================
        // x^(n/256) - ω^(63*n/64)      = x^(n/256) - ω^(252*n/256)
        // x^(n/256) - ω^(255*n/256)    = (x-ω^252)(x-ω^508)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on the 252nd row of every 256 rows
        let pedersen_zero_suffix_zerofier_inv =
            &one / (X.pow(n / 256) - Constant(FieldVariant::Fp(g.pow([(63 * n / 64) as u64]))));

        // Note that with cairo's default field each element is 252 bits.
        // Therefore we are decomposing 252 bit numbers to do pedersen hash.
        // Since we have a column that right shifts a number each row we check that the
        // suffix of row 252 (of every 256 row group) equals 0 e.g.
        // ```text
        // row0:   10101...10001
        // row1:    1010...11000
        // ...               ...
        // row250:            10
        // row251:             1
        // row252:             0 <- check zero
        // row253:             0
        // row254:             0
        // row255:             0
        // row256: 11101...10001
        // row257:  1110...01000
        // ...               ...
        // row506:            11
        // row507:             1
        // row508:             0 <- check zero
        // row509:             0
        // ...               ...
        // ```
        // <https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html>
        let pedersen_hash0_ec_subset_sum_bit_extraction_end =
            Pedersen::Suffix.curr() * &pedersen_zero_suffix_zerofier_inv;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let pedersen_hash0_ec_subset_sum_zeros_tail = Pedersen::Suffix.curr()
            * (&one / (X.pow(n / 256) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256])))));

        // Create a periodic table comprising of the constant Pedersen points we need to
        // add together. The columns of this table are represented by polynomials that
        // evaluate to the `i`th row when evaluated on the `i`th power of the 512th root
        // of unity. e.g.
        //
        // let:
        // - `[P]_x` denotes the x-coordinate of an elliptic-curve point P
        // - P_1, P_2, P_3, P_4 be fixed elliptic curve points that parameterize the
        //   Pedersen hash function
        //
        // then our point table is:
        // ┌───────────┬────────────────────┬────────────────────┐
        // │     X     │       F_x(X)       │       F_y(X)       │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ω^0    │   [P_1 * 2^0]_x    │   [P_1 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ω^1    │   [P_1 * 2^1]_x    │   [P_1 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ...    │         ...        │         ...        │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^247   │  [P_1 * 2^247]_x   │  [P_1 * 2^247]_y   │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^248   │   [P_2 * 2^0]_x    │   [P_2 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^249   │   [P_2 * 2^1]_x    │   [P_2 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^250   │   [P_2 * 2^2]_x    │   [P_2 * 2^2]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^251   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^252   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^253   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^254   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^255   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^256   │   [P_3 * 2^0]_x    │   [P_3 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^257   │   [P_3 * 2^1]_x    │   [P_3 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ...    │         ...        │         ...        │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^503   │  [P_3 * 2^247]_x   │  [P_3 * 2^247]_y   │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^504   │   [P_4 * 2^0]_x    │   [P_4 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^505   │   [P_4 * 2^1]_x    │   [P_4 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^506   │   [P_4 * 2^2]_x    │   [P_4 * 2^2]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^507   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^508   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^509   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^510   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^511   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // └───────────┴────────────────────┴────────────────────┘
        let pedersen_x_coeffs = pedersen::periodic::HASH_POINTS_X_COEFFS.map(FieldVariant::Fp);
        let pedersen_y_coeffs = pedersen::periodic::HASH_POINTS_Y_COEFFS.map(FieldVariant::Fp);
        let pedersen_points_x = Polynomial::new(pedersen_x_coeffs.to_vec());
        let pedersen_points_y = Polynomial::new(pedersen_y_coeffs.to_vec());

        // TODO: double check if the value that's being evaluated is correct
        let pedersen_point_x = pedersen_points_x.horner_eval(X.pow(n / 512));
        let pedersen_point_y = pedersen_points_y.horner_eval(X.pow(n / 512));

        // let `P = (Px, Py)` be the point to be added (see above)
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let pedersen_hash0_ec_subset_sum_add_points_slope = (&pedersen_hash0_ec_subset_sum_b0
            * (Pedersen::PartialSumY.curr() - &pedersen_point_y)
            - Pedersen::Slope.curr() * (Pedersen::PartialSumX.curr() - &pedersen_point_x))
            * &pedersen_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Qx_next = m^2 - Qx - Px, m = dy/dx`
        // - `Qy_next = m*(Qx - Qx_next) - Qy, m = dy/dx`
        let pedersen_hash0_ec_subset_sum_add_points_x = (Pedersen::Slope.curr()
            * Pedersen::Slope.curr()
            - &pedersen_hash0_ec_subset_sum_b0
                * (Pedersen::PartialSumX.curr()
                    + &pedersen_point_x
                    + Pedersen::PartialSumX.next()))
            * &pedersen_transition_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_add_points_y = (&pedersen_hash0_ec_subset_sum_b0
            * (Pedersen::PartialSumY.curr() + Pedersen::PartialSumY.next())
            - Pedersen::Slope.curr()
                * (Pedersen::PartialSumX.curr() - Pedersen::PartialSumX.next()))
            * &pedersen_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let pedersen_hash0_ec_subset_sum_copy_point_x = (&pedersen_hash0_ec_subset_sum_b0_negate
            * (Pedersen::PartialSumX.next() - Pedersen::PartialSumX.curr()))
            * &pedersen_transition_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_copy_point_y = (&pedersen_hash0_ec_subset_sum_b0_negate
            * (Pedersen::PartialSumY.next() - Pedersen::PartialSumY.curr()))
            * &pedersen_transition_zerofier_inv;

        // example for trace length n=1024
        // =============================
        // x^(n/512) - ω^(n/2)                = x^(n/512) - ω^(256*n/512)
        // x^(n/512) - ω^(256*n/512)          = (x-ω^256)(x-ω^768)
        // x^(n/256) - 1                      = (x-ω_0)(x-ω_256)(x-ω_512)(x-ω_768)
        // (x-ω^256)(x-ω^768) / (x^(n/256)-1) = 1/(x-ω_0)(x-ω_512)
        // 1/(x^(n/512) - 1)                  = 1/(x-ω_0)(x-ω_512)
        // NOTE: By using `(x-ω^256)(x-ω^768) / (x^(n/256)-1)` rather than
        // `1/(x^(n/512) - 1)` we save an inversion operation since 1 / (x^(n/256)-1)
        // has been calculated already and as a result of how constraints are
        // evaluated it will be cached.
        // TODO: check all zerofiers are being multiplied or divided correctly
        let every_512_row_zerofier_inv = (X.pow(n / 512)
            - Constant(FieldVariant::Fp(g.pow([n as u64 / 2]))))
            * &every_256_row_zerofier_inv;

        // A single pedersen hash `H(a, b)` is computed every 512 cycles.
        // The constraints for each hash is split in two consecutive 256 row groups.
        // - 1st group computes `e0 = P0 + a_low * P1 + a_high * P2`
        // - 2nd group computes `e1 = e0 + B_low * P3 + B_high * P4`
        // We make sure the initial value of each group is loaded correctly:
        // - 1st group we check P0 (the shift point) is the first partial sum
        // - 2nd group we check e0 (processed `a`) is the first partial sum
        let pedersen_hash0_copy_point_x = (Pedersen::PartialSumX.offset(1024)
            - Pedersen::PartialSumX.offset(1020))
            * &every_512_row_zerofier_inv;
        let pedersen_hash0_copy_point_y = (Pedersen::PartialSumY.offset(1024)
            - Pedersen::PartialSumY.offset(1020))
            * &every_512_row_zerofier_inv;
        // TODO: introducing a new zerofier that's equivalent to the
        // previous one? double check every_512_row_zerofier
        let every_512_row_zerofier = X.pow(n / 512) - Constant(FieldVariant::Fp(Fp::ONE));
        let every_512_row_zerofier_inv = &one / &every_512_row_zerofier;
        let shift_point = pedersen::constants::P0;
        let pedersen_hash0_init_x = (Pedersen::PartialSumX.curr()
            - Constant(FieldVariant::Fp(shift_point.x)))
            * &every_512_row_zerofier_inv;
        let pedersen_hash0_init_y = (Pedersen::PartialSumY.curr()
            - Constant(FieldVariant::Fp(shift_point.y)))
            * &every_512_row_zerofier_inv;

        // TODO: fix naming
        let zerofier_512th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([512 * (n as u64 / 512 - 1)])));
        let every_512_rows_except_last_zerofier =
            &zerofier_512th_last_row * &every_512_row_zerofier_inv;

        // Link Input0 into the memory pool.
        let pedersen_input0_value0 =
            (Npc::PedersenInput0Val.curr() - Pedersen::Suffix.curr()) * &every_512_row_zerofier_inv;
        // Input0's next address should be the address directly
        // after the output address of the previous hash
        let pedersen_input0_addr = (Npc::PedersenInput0Addr.next()
            - (Npc::PedersenOutputAddr.curr() + &one))
            * &every_512_rows_except_last_zerofier;
        // Ensure the first pedersen address matches the hint
        let pedersen_init_addr =
            (Npc::PedersenInput0Addr.curr() - InitialPedersenAddr.hint()) * &first_row_zerofier_inv;

        // Link Input1 into the memory pool.
        // Input1's address should be the address directly after input0's address
        let pedersen_input1_value0 = (Npc::PedersenInput1Val.curr()
            - Pedersen::Suffix.offset(1024))
            * &every_512_row_zerofier_inv;
        let pedersen_input1_addr = (Npc::PedersenInput1Addr.curr()
            - (Npc::PedersenInput0Addr.curr() + &one))
            * &every_512_row_zerofier_inv;

        // Link pedersen output into the memory pool.
        // Output's address should be the address directly after input1's address.
        let pedersen_output_value0 = (Npc::PedersenOutputVal.curr()
            - Pedersen::PartialSumX.offset(2045))
            * &every_512_row_zerofier_inv;
        let pedersen_output_addr = (Npc::PedersenOutputAddr.curr()
            - (Npc::PedersenInput1Addr.curr() + &one))
            * &every_512_row_zerofier_inv;

        // 128bit Range check builtin
        // ===================

        // TODO: fix naming
        let every_128_rows_zerofier = X.pow(n / 256) - &one;
        let every_128_rows_zerofier_inv = &one / &every_128_rows_zerofier;
        let zerofier_128th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([128 * (n as u64 / 128 - 1)])));
        let every_128_rows_except_last_zerofier =
            &zerofier_128th_last_row * &every_128_rows_zerofier_inv;

        // Hook up range check with the memory pool
        // TODO Zerofier every 128_row_zerofier?
        let rc_builtin_value =
            (rc_builtin_value7_0 - Npc::RangeCheck128Val.curr()) * &every_128_rows_zerofier_inv;
        let rc_builtin_addr_step = (Npc::RangeCheck128Addr.next()
            - (Npc::RangeCheck128Addr.curr() + &one))
            * &every_128_rows_except_last_zerofier;

        let rc_builtin_init_addr =
            (Npc::RangeCheck128Addr.curr() - InitialRcAddr.hint()) * &first_row_zerofier_inv;

        // bitwise builtin
        // ===============

        // check the initial bitwise segment memory address
        // all addresses associated with bitwise checks are continuous
        let bitwise_init_var_pool_addr =
            (Npc::BitwisePoolAddr.curr() - InitialBitwiseAddr.hint()) * &first_row_zerofier_inv;

        // example for trace length n=1024
        // ================================
        // x^(n/128) - ω^(3*n/4)    = x^(n/128) - ω^(96*n/128)
        // x^(n/128) - ω^(96*n/128) = (x-ω^96)
        // x^(n/32) - 1            = (x-ω^0)(x-ω^32)(x-ω^64)(x-ω^96)
        // (x-ω^96)/(x^(n/32) - 1) = 1/((x-ω^0)(x-ω^32)(x-ω^64))
        // vanishes on every 128th row except the 3rd of every 4
        let every_32_row_zerofier = X.pow(n / 32) - &one;
        let every_32_row_zerofier_inv = &one / &every_32_row_zerofier;
        let bitwise_transition_zerofier_inv = (X.pow(n / 128)
            - Constant(FieldVariant::Fp(g.pow([(3 * n / 4) as u64]))))
            * &every_32_row_zerofier_inv;

        let all_bitwise_zerofier = X.pow(n / 128) - &one;
        let all_bitwise_zerofier_inv = &one / &all_bitwise_zerofier;

        // Checks memory address for four bitwise inputs
        // `x`, `y`, `x&y` and `x^y` are continuous
        let bitwise_step_var_pool_addr = (Npc::BitwisePoolAddr.next()
            - (Npc::BitwisePoolAddr.curr() + &one))
            * &bitwise_transition_zerofier_inv;
        // need to check one more address for `x|y`
        let bitwise_x_or_y_addr = (Npc::BitwiseXOrYAddr.curr()
            - (Npc::BitwisePoolAddr.offset(3) + &one))
            * &all_bitwise_zerofier_inv;

        let last_bitwise_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([128 * (n / 128 - 1) as u64])));
        let all_bitwise_except_last_zerofier_inv =
            &last_bitwise_zerofier * &all_bitwise_zerofier_inv;

        // check the next bitwise instance has the correct address
        let bitwise_next_var_pool_addr = (Npc::BitwisePoolAddr.offset(4)
            - (Npc::BitwiseXOrYAddr.curr() + &one))
            * &all_bitwise_except_last_zerofier_inv;

        // check all values `x`, `y`, `x&y` and `x^y` are partitioned
        // NOTE: not `x|y` since this is calculated trivially using `x&y` and `x^y`
        // Partitioning in this context is the process of breaking up our number into
        // strided bit chunks. Firstly the bottom 128 bits are handled by
        // `bitwise_sum_var_0_0` and the top 128 bits are handles by
        // `bitwise_sum_var_8_0`. Then each 128 bit chunk is broken up into two 64 bit
        // chunks. Each of these 64 bit chunks is broken up into four stridings of a
        // 16 bit integer. For example to break up the 64 bit binary integer `v`:
        // ```text
        //  v = 0b1100_1010_0110_1001_0101_0100_0100_0000_0100_0010_0001_0010_1111_0111_1100
        // s0 = 0b0000_0000_0000_0001_0001_0000_0000_0000_0000_0000_0001_0000_0001_0001_0000
        // s1 = 0b0000_0001_0001_0000_0000_0000_0000_0000_0000_0001_0000_0001_0001_0001_0000
        // s2 = 0b0001_0000_0001_0000_0001_0001_0001_0000_0001_0000_0000_0000_0001_0001_0001
        // s3 = 0b0001_0001_0000_0001_0000_0000_0000_0000_0000_0000_0000_0000_0001_0000_0001
        // ```
        // note that `v = s0 * 2^0 + s1 * 2^1 + s2 * 2^2 + s3 * 2^3`.
        let bitwise_partition = (&bitwise_sum_var_0_0 + &bitwise_sum_var_8_0
            - Npc::BitwisePoolVal.curr())
            * &every_256_row_zerofier_inv;

        // NOTE: `x | y = (x & y) + (x ^ y)`
        let bitwise_x_and_y_val = Npc::BitwisePoolVal.offset(2);
        let bitwise_x_xor_y_val = Npc::BitwisePoolVal.offset(3);
        let bitwise_or_is_and_plus_xor = (Npc::BitwiseXOrYVal.curr()
            - (bitwise_x_and_y_val + bitwise_x_xor_y_val))
            * &all_bitwise_zerofier_inv;

        // example for trace length n=2048
        // ===============================
        // x^(n/1024) - ω^(1*n/64))  = x^(n/1024) - ω^(16 * n / 1024))
        //                           = (x - ω^(16 * 1))(x - ω^(1024 + (16 * 1)))
        // x^(n/1024) - ω^(1*n/32))  = x^(n/1024) - ω^(32 * n / 1024))
        //                           = (x - ω^(16 * 2))(x - ω^(1024 + (16 * 2)))
        // x^(n/1024) - ω^(3*n/64))  = x^(n/1024) - ω^(48 * n / 1024))
        //                           = (x - ω^(16 * 3))(x - ω^(1024 + (16 * 3)))
        // x^(n/1024) - ω^(1*n/16))  = x^(n/1024) - ω^(64 * n / 1024))
        //                           = (x - ω^(16 * 4))(x - ω^(1024 + (16 * 4)))
        // x^(n/1024) - ω^(5*n/64))  = x^(n/1024) - ω^(80 * n / 1024))
        //                           = (x - ω^(16 * 5))(x - ω^(1024 + (16 * 5)))
        // x^(n/1024) - ω^(3*n/32))  = x^(n/1024) - ω^(96 * n / 1024))
        //                           = (x - ω^(16 * 6))(x - ω^(1024 + (16 * 6)))
        // x^(n/1024) - ω^(7*n/64))  = x^(n/1024) - ω^(112 * n / 1024))
        //                           = (x - ω^(16 * 7))(x - ω^(1024 + (16 * 7)))
        // x^(n/1024) - ω^(1*n/8))   = x^(n/1024) - ω^(128 * n / 1024))
        //                           = (x - ω^(16 * 8))(x - ω^(1024 + (16 * 8)))
        // x^(n/1024) - ω^(9*n/64))  = x^(n/1024) - ω^(144 * n / 1024))
        //                           = (x - ω^(16 * 9))(x - ω^(1024 + (16 * 9)))
        // x^(n/1024) - ω^(5*n/32))  = x^(n/1024) - ω^(160 * n / 1024))
        //                           = (x - ω^(16 * 10))(x - ω^(1024 + (16 * 10)))
        // x^(n/1024) - ω^(11*n/64)) = x^(n/1024) - ω^(176 * n / 1024))
        //                           = (x - ω^(16 * 11))(x - ω^(1024 + (16 * 11)))
        // x^(n/1024) - ω^(3*n/16))  = x^(n/1024) - ω^(192 * n / 1024))
        //                           = (x - ω^(16 * 12))(x - ω^(1024 + (16 * 12)))
        // x^(n/1024) - ω^(13*n/64)) = x^(n/1024) - ω^(208 * n / 1024))
        //                           = (x - ω^(16 * 13))(x - ω^(1024 + (16 * 13)))
        // x^(n/1024) - ω^(7*n/32))  = x^(n/1024) - ω^(224 * n / 1024))
        //                           = (x - ω^(16 * 14))(x - ω^(1024 + (16 * 14)))
        // x^(n/1024) - ω^(15*n/64)) = x^(n/1024) - ω^(240 * n / 1024))
        //                           = (x - ω^(16 * 15))(x - ω^(1024 + (16 * 15)))
        // NOTE: when you multiply all these together you get:
        // $\prod_{i=1}^{15}(x - ω^(16 * i))(x - ω^(1024 + (16 * i)))$
        // now multiply this product by $x^(n / 1024) - 1$
        // TODO: isn't this zerofier just equivalent to $x^(n / 16) - 1$?
        let every_16_bit_segment_zerofier = (X.pow(n / 128)
            - Constant(FieldVariant::Fp(g.pow([n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([n as u64 / 32]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([n as u64 / 16]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 32]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([n as u64 / 8]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([9 * n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 32]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([11 * n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 16]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([13 * n as u64 / 64]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 32]))))
            * (X.pow(n / 128) - Constant(FieldVariant::Fp(g.pow([15 * n as u64 / 64]))))
            * &all_bitwise_zerofier;
        let every_16_bit_segment_zerofier_inv = &one / every_16_bit_segment_zerofier;

        // NOTE: `x+y = (x^y) + (x&y) + (x&y)`
        // TODO: CHECK: only when x and y are sufficiently diluted?
        let x_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(0);
        let y_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(1);
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(3);
        let bitwise_addition_is_xor_with_and = (x_16_bit_segment + y_16_bit_segment
            - (x_xor_y_16_bit_segment + &x_and_y_16_bit_segment + x_and_y_16_bit_segment))
            * &every_16_bit_segment_zerofier_inv;

        // NOTE: with these constraints we force the last 4 bits of x&y and x^y to be 0
        // this is important since we are dealing with a 252bit field (not 256bit field)
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset0.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset0.offset(3);
        let bitwise_unique_unpacking192 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(4)
            - Bitwise::Bits16Chunk3Offset0ResShifted.curr())
            * &all_bitwise_zerofier_inv;
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset1.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset1.offset(3);
        let bitwise_unique_unpacking193 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(4)
            - Bitwise::Bits16Chunk3Offset1ResShifted.curr())
            * &all_bitwise_zerofier_inv;
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset2.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset2.offset(3);
        let bitwise_unique_unpacking194 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(4)
            - Bitwise::Bits16Chunk3Offset2ResShifted.curr())
            * &all_bitwise_zerofier_inv;
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset3.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset3.offset(3);
        let bitwise_unique_unpacking195 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(8)
            - Bitwise::Bits16Chunk3Offset3ResShifted.curr())
            * &all_bitwise_zerofier_inv;

        let _: &[&Expr<AlgebraicItem<FieldVariant<Self::Fp, Self::Fq>>>] = &[
            &cpu_decode_opcode_rc_b,
            &cpu_decode_opcode_rc_zero,
            &cpu_decode_opcode_rc_input,
            &cpu_decode_flag_op1_base_op0_bit,
            &cpu_decode_flag_res_op1_bit,
            &cpu_decode_flag_pc_update_regular_bit,
            &cpu_decode_fp_update_regular_bit,
            &cpu_operands_mem_dst_addr,
            &cpu_operands_mem_op0_addr,
            &cpu_operands_mem_op1_addr,
            &cpu_operands_ops_mul,
            &cpu_operands_res,
            &cpu_update_registers_update_pc_tmp0,
            &cpu_update_registers_update_pc_tmp1,
            &cpu_update_registers_update_pc_pc_cond_negative,
            &cpu_update_registers_update_pc_pc_cond_positive,
            &cpu_update_registers_update_ap_ap_update,
            &cpu_update_registers_update_fp_fp_update,
            &cpu_opcodes_call_push_fp,
            &cpu_opcodes_call_push_pc,
            &cpu_opcodes_call_off0,
            &cpu_opcodes_call_off1,
            &cpu_opcodes_call_flags,
            &cpu_opcodes_ret_off0,
            &cpu_opcodes_ret_off2,
            &cpu_opcodes_ret_flags,
            &cpu_opcodes_assert_eq_assert_eq,
            &initial_ap,
            &initial_fp,
            &initial_pc,
            &final_ap,
            &final_fp,
            &final_pc,
            &memory_multi_column_perm_perm_init0,
            &memory_multi_column_perm_perm_step0,
            &memory_multi_column_perm_perm_last,
            &memory_diff_is_bit,
            &memory_is_func,
            &memory_initial_addr,
            &public_memory_addr_zero,
            &public_memory_value_zero,
            &rc16_perm_init0,
            &rc16_perm_step0,
            &rc16_perm_last,
            &rc16_diff_is_bit,
            &rc16_minimum,
            &rc16_maximum,
            &diluted_check_permutation_init0,
            &diluted_check_permutation_step0,
            &diluted_check_permutation_last,
            &diluted_check_init,
            &diluted_check_first_element,
            &diluted_check_step,
            &diluted_check_last,
            &pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero,
            &pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196,
            &pedersen_hash0_ec_subset_sum_booleanity_test,
            &pedersen_hash0_ec_subset_sum_bit_extraction_end,
            &pedersen_hash0_ec_subset_sum_zeros_tail,
            &pedersen_hash0_ec_subset_sum_add_points_slope,
            &pedersen_hash0_ec_subset_sum_add_points_x,
            &pedersen_hash0_ec_subset_sum_add_points_y,
            &pedersen_hash0_ec_subset_sum_copy_point_x,
            &pedersen_hash0_ec_subset_sum_copy_point_y,
            &pedersen_hash0_copy_point_x,
            &pedersen_hash0_copy_point_y,
            &pedersen_hash0_init_x,
            &pedersen_hash0_init_y,
            &pedersen_input0_value0,
            &pedersen_input0_addr,
            &pedersen_init_addr,
            &pedersen_input1_value0,
            &pedersen_input1_addr,
            &pedersen_output_value0,
            &pedersen_output_addr,
            &rc_builtin_value,
            &rc_builtin_addr_step,
            &rc_builtin_init_addr,
            &bitwise_init_var_pool_addr,
            &bitwise_step_var_pool_addr,
            &bitwise_x_or_y_addr,
            &bitwise_next_var_pool_addr,
            &bitwise_partition,
            &bitwise_or_is_and_plus_xor,
            &bitwise_addition_is_xor_with_and,
            &bitwise_unique_unpacking192,
            &bitwise_unique_unpacking193,
            &bitwise_unique_unpacking194,
            &bitwise_unique_unpacking195,
        ];

        // NOTE: for composition OODs only seem to involve one random per constraint
        vec![
            cpu_decode_opcode_rc_b,
            cpu_decode_opcode_rc_zero,
            cpu_decode_opcode_rc_input,
            cpu_decode_flag_op1_base_op0_bit,
            cpu_decode_flag_res_op1_bit,
            cpu_decode_flag_pc_update_regular_bit,
            cpu_decode_fp_update_regular_bit,
            cpu_operands_mem_dst_addr,
            cpu_operands_mem_op0_addr,
            cpu_operands_mem_op1_addr,
            cpu_operands_ops_mul,
            cpu_operands_res,
            cpu_update_registers_update_pc_tmp0,
            cpu_update_registers_update_pc_tmp1,
            cpu_update_registers_update_pc_pc_cond_negative,
            cpu_update_registers_update_pc_pc_cond_positive,
            cpu_update_registers_update_ap_ap_update,
            cpu_update_registers_update_fp_fp_update,
            cpu_opcodes_call_push_fp,
            cpu_opcodes_call_push_pc,
            cpu_opcodes_call_off0,
            cpu_opcodes_call_off1,
            cpu_opcodes_call_flags,
            cpu_opcodes_ret_off0,
            cpu_opcodes_ret_off2,
            cpu_opcodes_ret_flags,
            cpu_opcodes_assert_eq_assert_eq,
            initial_ap,
            initial_fp,
            initial_pc,
            final_ap,
            final_fp,
            final_pc,
            memory_multi_column_perm_perm_init0,
            memory_multi_column_perm_perm_step0,
            memory_multi_column_perm_perm_last,
            memory_diff_is_bit,
            memory_is_func,
            memory_initial_addr,
            public_memory_addr_zero,
            public_memory_value_zero,
            rc16_perm_init0,
            rc16_perm_step0,
            rc16_perm_last,
            rc16_diff_is_bit,
            rc16_minimum,
            rc16_maximum,
            diluted_check_permutation_init0,
            diluted_check_permutation_step0,
            diluted_check_permutation_last,
            diluted_check_init,
            diluted_check_first_element,
            diluted_check_step,
            diluted_check_last,
            // pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero,
            // pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196,
            // pedersen_hash0_ec_subset_sum_booleanity_test,
            // pedersen_hash0_ec_subset_sum_bit_extraction_end,
            // pedersen_hash0_ec_subset_sum_zeros_tail,
            // pedersen_hash0_ec_subset_sum_add_points_slope,
            // pedersen_hash0_ec_subset_sum_add_points_x,
            // pedersen_hash0_ec_subset_sum_add_points_y,
            // pedersen_hash0_ec_subset_sum_copy_point_x,
            // pedersen_hash0_ec_subset_sum_copy_point_y,
            // pedersen_hash0_copy_point_x,
            // pedersen_hash0_copy_point_y,
            // pedersen_hash0_init_x,
            // pedersen_hash0_init_y,
            // pedersen_input0_value0,
            // pedersen_input0_addr,
            // pedersen_init_addr,
            // pedersen_input1_value0,
            // pedersen_input1_addr,
            // pedersen_output_value0,
            // pedersen_output_addr,
            rc_builtin_value,
            rc_builtin_addr_step,
            rc_builtin_init_addr,
            bitwise_init_var_pool_addr,
            bitwise_step_var_pool_addr,
            bitwise_x_or_y_addr,
            bitwise_next_var_pool_addr,
            bitwise_partition,
            bitwise_or_is_and_plus_xor,
            bitwise_addition_is_xor_with_and,
            bitwise_unique_unpacking192,
            bitwise_unique_unpacking193,
            bitwise_unique_unpacking194,
            bitwise_unique_unpacking195,
        ]
        .into_iter()
        .map(Constraint::new)
        .collect()
    }

    fn composition_constraint(
        _trace_len: usize,
        constraints: &[Constraint<FieldVariant<Self::Fp, Self::Fq>>],
    ) -> CompositionConstraint<FieldVariant<Self::Fp, Self::Fq>> {
        use CompositionItem::*;
        let alpha = Expr::Leaf(CompositionCoeff(0));
        let expr = constraints
            .iter()
            .enumerate()
            .map(|(i, constraint)| {
                let constraint = constraint.map_leaves(&mut |&leaf| Item(leaf));
                constraint * (&alpha).pow(i)
            })
            .sum::<Expr<CompositionItem<FieldVariant<Self::Fp, Self::Fq>>>>()
            .reuse_shared_nodes();
        CompositionConstraint::new(expr)
    }

    fn gen_hints(
        trace_len: usize,
        execution_info: &AirPublicInput<Self::Fp>,
        challenges: &Challenges<Self::Fq>,
    ) -> Hints<Self::Fq> {
        use PublicInputHint::*;

        let segments = execution_info.memory_segments;
        let pedersen_segment = segments.pedersen.expect("layout requires Pedersen");
        let rc_segment = segments.range_check.expect("layout requires range check");
        let bitwise_segment = segments.bitwise.expect("layout requires bitwise");

        let initial_perdersen_address = pedersen_segment.begin_addr.into();
        let initial_rc_address = rc_segment.begin_addr.into();
        let initial_bitwise_address = bitwise_segment.begin_addr.into();

        let memory_quotient =
            utils::compute_public_memory_quotient::<PUBLIC_MEMORY_STEP, Self::Fp, Self::Fq>(
                challenges[MemoryPermutation::Z],
                challenges[MemoryPermutation::A],
                trace_len,
                &execution_info.public_memory,
                execution_info.public_memory_padding(),
            );

        let diluted_cumulative_val = compute_diluted_cumulative_value::<
            Fp,
            Fp,
            DILUTED_CHECK_N_BITS,
            DILUTED_CHECK_SPACING,
        >(
            challenges[DilutedCheckAggregation::Z],
            challenges[DilutedCheckAggregation::A],
        );

        // TODO: add validation on the AirPublicInput struct
        // assert!(range_check_min <= range_check_max);
        let initial_ap = execution_info.initial_ap().into();
        let final_ap = execution_info.final_ap().into();
        let initial_pc = execution_info.initial_pc().into();
        let final_pc = execution_info.final_pc().into();

        Hints::new(vec![
            (InitialAp.index(), initial_ap),
            (InitialPc.index(), initial_pc),
            (FinalAp.index(), final_ap),
            (FinalPc.index(), final_pc),
            // TODO: this is a wrong value. Must fix
            (MemoryQuotient.index(), memory_quotient),
            (RangeCheckProduct.index(), Fp::ONE),
            (RangeCheckMin.index(), execution_info.rc_min.into()),
            (RangeCheckMax.index(), execution_info.rc_max.into()),
            (DilutedCheckProduct.index(), Fp::ONE),
            (DilutedCheckFirst.index(), Fp::ZERO),
            (DilutedCheckCumulativeValue.index(), diluted_cumulative_val),
            (InitialPedersenAddr.index(), initial_perdersen_address),
            (InitialRcAddr.index(), initial_rc_address),
            (InitialBitwiseAddr.index(), initial_bitwise_address),
        ])
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

impl From<Flag> for binary::Flag {
    fn from(value: Flag) -> Self {
        match value {
            Flag::DstReg => Self::DstReg,
            Flag::Op0Reg => Self::Op0Reg,
            Flag::Op1Imm => Self::Op1Imm,
            Flag::Op1Fp => Self::Op1Fp,
            Flag::Op1Ap => Self::Op1Ap,
            Flag::ResAdd => Self::ResAdd,
            Flag::ResMul => Self::ResMul,
            Flag::PcJumpAbs => Self::PcJumpAbs,
            Flag::PcJumpRel => Self::PcJumpRel,
            Flag::PcJnz => Self::PcJnz,
            Flag::ApAdd => Self::ApAdd,
            Flag::ApAdd1 => Self::ApAdd1,
            Flag::OpcodeCall => Self::OpcodeCall,
            Flag::OpcodeRet => Self::OpcodeRet,
            Flag::OpcodeAssertEq => Self::OpcodeAssertEq,
            Flag::Zero => Self::Zero,
        }
    }
}

impl ExecutionTraceColumn for Flag {
    fn index(&self) -> usize {
        0
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        use AlgebraicItem::Trace;
        // Get the individual bit (as opposed to the bit prefix)
        let col = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset;
        let flag_offset = trace_offset + *self as isize;
        Expr::from(Trace(col, flag_offset))
            - (Trace(col, flag_offset + 1) + Trace(col, flag_offset + 1))
    }
}

#[derive(Clone, Copy)]
pub enum RangeCheckBuiltin {
    Rc16Component = 12,
}

impl ExecutionTraceColumn for RangeCheckBuiltin {
    fn index(&self) -> usize {
        5
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = RANGE_CHECK_BUILTIN_RATIO * CYCLE_HEIGHT / RANGE_CHECK_BUILTIN_PARTS;
        let trace_offset = match self {
            Self::Rc16Component => step as isize * offset + *self as isize,
        };
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum Bitwise {
    // TODO: better names or just don't use this
    // for 1st chunk 64 bits
    Bits16Chunk0Offset0 = 0,
    Bits16Chunk0Offset1 = 2,
    Bits16Chunk0Offset2 = 4,
    Bits16Chunk0Offset3 = 6,
    // for 2nd chunk of 64 bits
    Bits16Chunk1Offset0 = 8,
    Bits16Chunk1Offset1 = 10,
    Bits16Chunk1Offset2 = 12,
    Bits16Chunk1Offset3 = 14,
    // for 3rd chunk of 64 bits
    Bits16Chunk2Offset0 = 16,
    Bits16Chunk2Offset1 = 18,
    Bits16Chunk2Offset2 = 20,
    Bits16Chunk2Offset3 = 22,
    // for 4th chunk of 64 bits
    Bits16Chunk3Offset0 = 24,
    Bits16Chunk3Offset1 = 26,
    Bits16Chunk3Offset2 = 28,
    Bits16Chunk3Offset3 = 30,
    // these fields hold shifted values to ensure
    // that there has been a unique unpacking
    // NOTE: 8/8 = 1
    // NOTE: 0 = 2^5 * 0
    Bits16Chunk3Offset0ResShifted = 1,
    // NOTE: 520/8 = 65
    // NOTE: 64 = 2^5 * 2
    Bits16Chunk3Offset1ResShifted = 65,
    // NOTE: 264/8 = 33
    // NOTE: 64 = 2^5 * 1
    Bits16Chunk3Offset2ResShifted = 33,
    // NOTE: 776/8 = 97
    // NOTE: 64 = 2^5 * 3
    Bits16Chunk3Offset3ResShifted = 97,
}

impl ExecutionTraceColumn for Bitwise {
    fn index(&self) -> usize {
        match self {
            Self::Bits16Chunk0Offset0
            | Self::Bits16Chunk0Offset1
            | Self::Bits16Chunk0Offset2
            | Self::Bits16Chunk0Offset3
            | Self::Bits16Chunk1Offset0
            | Self::Bits16Chunk1Offset1
            | Self::Bits16Chunk1Offset2
            | Self::Bits16Chunk1Offset3
            | Self::Bits16Chunk2Offset0
            | Self::Bits16Chunk2Offset1
            | Self::Bits16Chunk2Offset2
            | Self::Bits16Chunk2Offset3
            | Self::Bits16Chunk3Offset0
            | Self::Bits16Chunk3Offset1
            | Self::Bits16Chunk3Offset2
            | Self::Bits16Chunk3Offset3
            | Self::Bits16Chunk3Offset0ResShifted
            | Self::Bits16Chunk3Offset1ResShifted
            | Self::Bits16Chunk3Offset2ResShifted
            | Self::Bits16Chunk3Offset3ResShifted => 1,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::Bits16Chunk0Offset0
            | Self::Bits16Chunk0Offset1
            | Self::Bits16Chunk0Offset2
            | Self::Bits16Chunk0Offset3
            | Self::Bits16Chunk1Offset0
            | Self::Bits16Chunk1Offset1
            | Self::Bits16Chunk1Offset2
            | Self::Bits16Chunk1Offset3
            | Self::Bits16Chunk2Offset0
            | Self::Bits16Chunk2Offset1
            | Self::Bits16Chunk2Offset2
            | Self::Bits16Chunk2Offset3
            | Self::Bits16Chunk3Offset0
            | Self::Bits16Chunk3Offset1
            | Self::Bits16Chunk3Offset2
            | Self::Bits16Chunk3Offset3 => 32,
            Self::Bits16Chunk3Offset0ResShifted
            | Self::Bits16Chunk3Offset1ResShifted
            | Self::Bits16Chunk3Offset2ResShifted
            | Self::Bits16Chunk3Offset3ResShifted => 128,
        };
        AlgebraicItem::Trace(column, offset * step + *self as isize).into()
    }
}

#[derive(Clone, Copy)]
pub enum Pedersen {
    PartialSumX = 1,
    PartialSumY = 3,
    Suffix = 0,
    Slope = 2,
    Bit251AndBit196AndBit192 = 7,
    Bit251AndBit196 = 1022,
}

impl ExecutionTraceColumn for Pedersen {
    fn index(&self) -> usize {
        match self {
            Self::PartialSumX | Self::PartialSumY => 5,
            Self::Suffix | Self::Slope => 6,
            Self::Bit251AndBit196AndBit192 | Self::Bit251AndBit196 => 6,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Self::Suffix | Self::Slope => offset + *self as isize,
            Self::PartialSumX | Self::PartialSumY => 4 * offset + *self as isize,
            Self::Bit251AndBit196AndBit192 | Self::Bit251AndBit196 => {
                (PEDERSEN_BUILTIN_RATIO * CYCLE_HEIGHT) as isize * offset + *self as isize
            }
        };
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// NPC? not sure what it means yet - next program counter?
// Trace column 3
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

    PedersenInput0Addr = 10,
    PedersenInput0Val = 11,

    // 1034 % 16 = 10
    // 1035 % 16 = 11
    PedersenInput1Addr = 1034,
    PedersenInput1Val = 1035,

    // 522 % 16 = 10
    // 523 % 16 = 11
    PedersenOutputAddr = 522,
    PedersenOutputVal = 523,

    // 74 % 16 = 10
    // 75 % 16 = 11
    RangeCheck128Addr = 74,
    RangeCheck128Val = 75,

    // 26 % 16 = 10
    // 27 % 16 = 11
    BitwisePoolAddr = 26,
    BitwisePoolVal = 27,

    // 42 % 16 = 10
    // 43 % 16 = 11
    BitwiseXOrYAddr = 42,
    BitwiseXOrYVal = 43,

    MemDstAddr = 8,
    MemDst = 9,
    // NOTE: cycle cells 10 and 11 is occupied by PubMemAddr since the public memory step is 8.
    // This means it applies twice (2, 3) then (8+2, 8+3) within a single 16 row cycle.
    MemOp1Addr = 12,
    MemOp1 = 13,

    UnusedAddr = 14,
    UnusedVal = 15,
}

impl ExecutionTraceColumn for Npc {
    fn index(&self) -> usize {
        3
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let step = match self {
            Self::PubMemAddr | Self::PubMemVal => PUBLIC_MEMORY_STEP,
            Self::PedersenInput0Addr
            | Self::PedersenInput0Val
            | Self::PedersenInput1Addr
            | Self::PedersenInput1Val
            | Self::PedersenOutputAddr
            | Self::PedersenOutputVal => CYCLE_HEIGHT * PEDERSEN_BUILTIN_RATIO,
            Self::RangeCheck128Addr | Self::RangeCheck128Val => {
                CYCLE_HEIGHT * RANGE_CHECK_BUILTIN_RATIO
            }
            Self::Pc
            | Self::Instruction
            | Self::MemOp0Addr
            | Self::MemOp0
            | Self::MemDstAddr
            | Self::MemDst
            | Self::MemOp1Addr
            | Self::UnusedAddr
            | Self::UnusedVal
            | Self::MemOp1 => CYCLE_HEIGHT,
            Self::BitwisePoolAddr | Self::BitwisePoolVal => BITWISE_RATIO * CYCLE_HEIGHT / 4,
            Self::BitwiseXOrYAddr | Self::BitwiseXOrYVal => BITWISE_RATIO * CYCLE_HEIGHT,
        } as isize;
        let column = self.index();
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

impl SharpAirConfig for AirConfig {
    fn public_memory_challenges(challenges: &Challenges<Self::Fq>) -> (Self::Fq, Self::Fq) {
        (
            challenges[MemoryPermutation::Z],
            challenges[MemoryPermutation::A],
        )
    }

    fn public_memory_quotient(hints: &Hints<Self::Fq>) -> Self::Fq {
        hints[PublicInputHint::MemoryQuotient]
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
        4
    }

    fn offset<T>(&self, mem_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = MEMORY_STEP as isize * mem_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum DilutedCheck {
    Unordered,
    Ordered,
    Aggregate,
}

impl DilutedCheck {
    /// Output is of the form (col_idx, row_shift)
    pub const fn col_and_shift(&self) -> (usize, isize) {
        match self {
            Self::Unordered => (1, 0),
            Self::Ordered => (2, 0),
            Self::Aggregate => (7, 0),
        }
    }
}

impl ExecutionTraceColumn for DilutedCheck {
    fn index(&self) -> usize {
        self.col_and_shift().0
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let (col, shift) = self.col_and_shift();
        AlgebraicItem::Trace(col, DILUTED_CHECK_STEP as isize * offset + shift).into()
    }
}

// Trace column 5
#[derive(Clone, Copy)]
pub enum RangeCheck {
    OffDst = 0,
    Ordered = 2, // Stores ordered values for the range check
    OffOp1 = 4,
    // Ordered = 6 - trace step is 4
    OffOp0 = 8,
    // Ordered = 10 - trace step is 4
    // This cell alternates cycle to cycle between:
    // - Being used for the 128 bit range checks builtin - even cycles
    // - Filled with padding to fill any gaps - odd cycles
    Unused = 12,
    // Ordered = 14 - trace step is 4
}

impl ExecutionTraceColumn for RangeCheck {
    fn index(&self) -> usize {
        5
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        let step = match self {
            RangeCheck::Ordered => RANGE_CHECK_STEP,
            _ => CYCLE_HEIGHT,
        } as isize;
        let column = self.index();
        let trace_offset = step * cycle_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// Auxiliary column 8
#[derive(Clone, Copy)]
pub enum Auxiliary {
    Ap = 1, // Allocation pointer (ap)
    Tmp0 = 3,
    Op0MulOp1 = 5, // =op0*op1
    Fp = 9,        // Frame pointer (fp)
    Tmp1 = 11,
    Res = 13,
}

impl ExecutionTraceColumn for Auxiliary {
    fn index(&self) -> usize {
        6
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::Ap | Self::Fp | Self::Tmp0 | Self::Tmp1 | Self::Op0MulOp1 | Self::Res => {
                CYCLE_HEIGHT
            }
        } as isize;
        let trace_offset = step * cycle_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// Trace column 9 and 8 - permutations
#[derive(Clone, Copy)]
pub enum Permutation {
    Memory,
    RangeCheck,
    DilutedCheck,
}

impl Permutation {
    /// Output is of the form (col_idx, row_shift)
    pub const fn col_and_shift(&self) -> (usize, isize) {
        match self {
            Self::Memory => (9, 0),
            Self::DilutedCheck => (8, 0),
            Self::RangeCheck => (9, 1),
        }
    }
}

impl ExecutionTraceColumn for Permutation {
    fn index(&self) -> usize {
        let (col_idx, _) = self.col_and_shift();
        col_idx
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let (column, shift) = self.col_and_shift();
        let trace_offset = match self {
            Self::Memory => MEMORY_STEP as isize * offset + shift as isize,
            Self::RangeCheck => 4 * offset + shift as isize,
            Self::DilutedCheck => offset + shift as isize, // TODO this is probably 2 * offset
        };
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum PublicInputHint {
    InitialAp,
    InitialPc,
    FinalAp,
    FinalPc,
    MemoryQuotient, // TODO
    RangeCheckProduct,
    RangeCheckMin,
    RangeCheckMax,
    DilutedCheckProduct,
    DilutedCheckFirst,
    DilutedCheckCumulativeValue,
    InitialPedersenAddr,
    InitialRcAddr,
    InitialBitwiseAddr,
}

impl Hint for PublicInputHint {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic memory permutation challenges
/// Note section 9.7.2 from Cairo whitepaper
/// (z − (address + α * value))
#[derive(Clone, Copy)]
pub enum MemoryPermutation {
    Z = 0, // =z
    A = 1, // =α
}

impl VerifierChallenge for MemoryPermutation {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic range check permutation challenges
/// Note section 9.7.2 from Cairo whitepaper
/// (z − value)
#[derive(Clone, Copy)]
pub enum RangeCheckPermutation {
    Z = 2, // =z
}

impl VerifierChallenge for RangeCheckPermutation {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic diluted check permutation challenges
#[derive(Clone, Copy)]
pub enum DilutedCheckPermutation {
    Z = 3, // =z
}

impl VerifierChallenge for DilutedCheckPermutation {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic diluted check aggregation challenges
#[derive(Clone, Copy)]
pub enum DilutedCheckAggregation {
    Z = 4, // =z
    A = 5, // =α
}

impl VerifierChallenge for DilutedCheckAggregation {
    fn index(&self) -> usize {
        *self as usize
    }
}

struct Polynomial<T>(Vec<T>);

impl<T: Clone + One + Zero + Mul<Output = T> + Add<Output = T>> Polynomial<T> {
    fn new(coeffs: Vec<T>) -> Self {
        assert!(!coeffs.is_empty());
        assert!(!coeffs.iter().all(|v| v.is_zero()));
        Polynomial(coeffs)
    }

    fn horner_eval(&self, point: Expr<AlgebraicItem<T>>) -> Expr<AlgebraicItem<T>> {
        self.0.iter().rfold(
            Expr::Leaf(AlgebraicItem::Constant(T::zero())),
            move |result, coeff| result * &point + AlgebraicItem::Constant(coeff.clone()),
        )
    }
}
