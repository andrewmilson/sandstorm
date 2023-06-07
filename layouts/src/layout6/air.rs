use super::BITWISE_RATIO;
use super::CYCLE_HEIGHT;
use super::ECDSA_BUILTIN_RATIO;
use super::EC_OP_BUILTIN_RATIO;
use super::EC_OP_SCALAR_HEIGHT;
use super::MEMORY_STEP;
use super::PEDERSEN_BUILTIN_RATIO;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_BUILTIN_PARTS;
use super::RANGE_CHECK_BUILTIN_RATIO;
use super::RANGE_CHECK_STEP;
use crate::layout6::ECDSA_SIG_CONFIG_ALPHA;
use crate::layout6::ECDSA_SIG_CONFIG_BETA;
use crate::utils;
use crate::ExecutionInfo;
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use builtins::ecdsa;
use builtins::pedersen;
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
    const NUM_BASE_COLUMNS: usize = 9;
    const NUM_EXTENSION_COLUMNS: usize = 1;
    type Fp = Fp;
    type Fq = Fp;
    type PublicInputs = ExecutionInfo<Fp>;

    fn constraints(trace_len: usize) -> Vec<Constraint<FieldVariant<Fp, Fp>>> {
        use AlgebraicItem::*;
        use PublicInputHint::*;
        // TODO: figure out why this value
        let n = trace_len;
        let trace_domain = Radix2EvaluationDomain::<Fp>::new(n).unwrap();
        let g = trace_domain.group_gen();
        assert!(n >= CYCLE_HEIGHT, "must be a multiple of cycle height");
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
        let ecdsa_sig0_doubling_key_x_squared: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Ecdsa::PubkeyDoublingX.curr() * Ecdsa::PubkeyDoublingX.curr();
        let ecdsa_sig0_exponentiate_generator_b0 = Ecdsa::MessageSuffix.curr()
            - (Ecdsa::MessageSuffix.next() + Ecdsa::MessageSuffix.next());
        let ecdsa_sig0_exponentiate_generator_b0_neg = &one - &ecdsa_sig0_exponentiate_generator_b0;
        let ecdsa_sig0_exponentiate_key_b0 =
            Ecdsa::RSuffix.curr() - (Ecdsa::RSuffix.next() + Ecdsa::RSuffix.next());
        let ecdsa_sig0_exponentiate_key_b0_neg = &one - &ecdsa_sig0_exponentiate_key_b0;

        // bits 0->127 (inclusive) of a bitwise number
        let bitwise_sum_var_0_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Bitwise::Bits16Chunk0Offset0.curr()
                + Bitwise::Bits16Chunk0Offset1.curr() * (&two).pow(1)
                + Bitwise::Bits16Chunk0Offset2.curr() * (&two).pow(2)
                + Bitwise::Bits16Chunk0Offset3.curr() * (&two).pow(3)
                + Bitwise::Bits16Chunk1Offset0.curr() * (&two).pow(64)
                + Bitwise::Bits16Chunk1Offset1.curr() * (&two).pow(65)
                + Bitwise::Bits16Chunk1Offset2.curr() * (&two).pow(66)
                + Bitwise::Bits16Chunk1Offset3.curr() * (&two).pow(67);
        // bits 128->255 (inclusive) of a bitwise number
        let bitwise_sum_var_8_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Bitwise::Bits16Chunk2Offset0.curr() * (&two).pow(129)
                + Bitwise::Bits16Chunk2Offset1.curr() * (&two).pow(130)
                + Bitwise::Bits16Chunk2Offset2.curr() * (&two).pow(131)
                + Bitwise::Bits16Chunk2Offset3.curr() * (&two).pow(132)
                + Bitwise::Bits16Chunk3Offset0.curr() * (&two).pow(193)
                + Bitwise::Bits16Chunk3Offset1.curr() * (&two).pow(194)
                + Bitwise::Bits16Chunk3Offset2.curr() * (&two).pow(195)
                + Bitwise::Bits16Chunk3Offset3.curr() * (&two).pow(196);

        // example for trace length n=64
        // =============================
        // x^(n/16)                 = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // x^(n/16) - c             = (x - c*ω_0)(x - c*ω_16)(x - c*ω_32)(x - c*ω_48)
        // x^(n/16) - ω^(n/16)      = (x - ω_1)(x - ω_17)(x - ω_33)(x - )
        // x^(n/16) - ω^(n/16)^(15) = (x - ω_15)(x - ω_31)(x - ω_47)(x - ω_6ω_493)
        let flag0_offset =
            FieldVariant::Fp(g.pow([(Flag::Zero as usize * n / CYCLE_HEIGHT) as u64]));
        let flag0_zerofier = X.pow(n / CYCLE_HEIGHT) - Constant(flag0_offset);
        let flags_zerofier_inv = &flag0_zerofier / (X.pow(n) - &one);

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
            - (Flag::DstReg.curr() * RangeCheck::Fp.curr()
                + (&one - Flag::DstReg.curr()) * RangeCheck::Ap.curr()
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
            - (Flag::Op0Reg.curr() * RangeCheck::Fp.curr()
                + (&one - Flag::Op0Reg.curr()) * RangeCheck::Ap.curr()
                + RangeCheck::OffOp0.curr()))
            * &all_cycles_zerofier_inv;

        // NOTE: StarkEx contracts as: cpu_operands_mem1_addr
        let cpu_operands_mem_op1_addr = (Npc::MemOp1Addr.curr() + &half_offset_size
            - (Flag::Op1Imm.curr() * Npc::Pc.curr()
                + Flag::Op1Ap.curr() * RangeCheck::Ap.curr()
                + Flag::Op1Fp.curr() * RangeCheck::Fp.curr()
                + &cpu_decode_flag_op1_base_op0_0 * Npc::MemOp0.curr()
                + RangeCheck::OffOp1.curr()))
            * &all_cycles_zerofier_inv;

        // op1 * op0
        // NOTE: starkex cpu/operands/ops_mul
        let cpu_operands_ops_mul = (RangeCheck::Op0MulOp1.curr()
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
        let cpu_operands_res = ((&one - Flag::PcJnz.curr()) * RangeCheck::Res.curr()
            - (Flag::ResAdd.curr() * (Npc::MemOp0.curr() + Npc::MemOp1.curr())
                + Flag::ResMul.curr() * RangeCheck::Op0MulOp1.curr()
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
            - Auxiliary::Tmp0.curr() * RangeCheck::Res.curr())
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
                + Flag::PcJumpAbs.curr() * RangeCheck::Res.curr()
                + Flag::PcJumpRel.curr() * (Npc::Pc.curr() + RangeCheck::Res.curr())))
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
        let cpu_update_registers_update_ap_ap_update = (RangeCheck::Ap.next()
            - (RangeCheck::Ap.curr()
                + Flag::ApAdd.curr() * RangeCheck::Res.curr()
                + Flag::ApAdd1.curr()
                + Flag::OpcodeCall.curr() * &two))
            * &all_cycles_except_last_zerofier_inv;

        // Updating the frame pointer
        // ==========================
        // This handles all fp update except the `op0 == pc + instruction_size`, `res =
        // dst` and `dst == fp` assertions.
        // TODO: fix padding bug
        let cpu_update_registers_update_fp_fp_update = (RangeCheck::Fp.next()
            - (&cpu_decode_fp_update_regular_0 * RangeCheck::Fp.curr()
                + Flag::OpcodeRet.curr() * Npc::MemDst.curr()
                + Flag::OpcodeCall.curr() * (RangeCheck::Ap.curr() + &two)))
            * &all_cycles_except_last_zerofier_inv;

        // push registers to memory (see section 8.4 in the whitepaper).
        // These are essentially the assertions for assert `op0 == pc +
        // instruction_size` and `assert dst == fp`.
        let cpu_opcodes_call_push_fp = (Flag::OpcodeCall.curr()
            * (Npc::MemDst.curr() - RangeCheck::Fp.curr()))
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
            * (Npc::MemDst.curr() - RangeCheck::Res.curr()))
            * &all_cycles_zerofier_inv;

        let first_row_zerofier = &x - &one;
        let first_row_zerofier_inv = &one / first_row_zerofier;

        // boundary constraint expression for initial registers
        let initial_ap = (RangeCheck::Ap.curr() - InitialAp.hint()) * &first_row_zerofier_inv;
        let initial_fp = (RangeCheck::Fp.curr() - InitialAp.hint()) * &first_row_zerofier_inv;
        let initial_pc = (Npc::Pc.curr() - InitialPc.hint()) * &first_row_zerofier_inv;

        // boundary constraint expression for final registers
        let final_ap = (RangeCheck::Ap.curr() - FinalAp.hint()) * &last_cycle_zerofier_inv;
        let final_fp = (RangeCheck::Fp.curr() - InitialAp.hint()) * &last_cycle_zerofier_inv;
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
            (Permutation::Memory.curr() - MemoryProduct.hint()) / &second_last_row_zerofier;
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
        let every_eighth_row_zerofier = X.pow(n / 8) - &one;
        let every_eighth_row_zerofier_inv = &one / &every_eighth_row_zerofier;
        // Read cairo whitepaper section 9.8 as to why the public memory cells are 0.
        // The high level is that the way public memory works is that the prover is
        // forced (with these constraints) to exclude the public memory from one of
        // the permutation products. This means the running permutation column
        // terminates with more-or-less the permutation of just the public input. The
        // verifier can relatively cheaply calculate this terminal. The constraint for
        // this terminal is `memory_multi_column_perm_perm_last`.
        let public_memory_addr_zero = Npc::PubMemAddr.curr() * &every_eighth_row_zerofier_inv;
        let public_memory_value_zero = Npc::PubMemVal.curr() * &every_eighth_row_zerofier_inv;

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

        // Diluted checks operate every 8 rows (twice per cycle)
        let zerofier_8th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([512 * (n as u64 / 512 - 1)])));
        let zerofier_8th_last_row_inv = &one / &zerofier_8th_last_row;
        let every_8_row_zerofier = X.pow(8) - &one;
        let every_8_row_zerofier_inv = &one / &every_8_row_zerofier;
        let every_8_rows_except_last_zerofier_inv =
            &zerofier_8th_last_row * &every_8_row_zerofier_inv;

        // we have an out-of-order and in-order list of diluted values for this layout
        // (layout6). We want to check each list is a permutation of one another
        let diluted_check_permutation_step0 = ((DilutedCheckPermutation::Z.challenge()
            - DilutedCheck::Ordered.next())
            * Permutation::DilutedCheck.next()
            - (DilutedCheckPermutation::Z.challenge() - DilutedCheck::Unordered.curr())
                * Permutation::DilutedCheck.curr())
            * &every_8_rows_except_last_zerofier_inv;
        let diluted_check_permutation_last = (Permutation::DilutedCheck.curr()
            - DilutedCheckProduct.hint())
            * &zerofier_8th_last_row_inv;

        // Initial aggregate value should be =1
        let diluted_check_init = DilutedCheck::Aggregate.curr() * &first_row_zerofier_inv;

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
            * &every_8_rows_except_last_zerofier_inv;

        // Check the last cumulative value.
        // NOTE: This can be calculated efficiently by the verifier.
        let diluted_check_last = (DilutedCheck::Aggregate.curr()
            - DilutedCheckCumulativeValue.hint())
            * &zerofier_8th_last_row_inv;

        // Pedersen builtin
        // ================
        // Each hash spans across 256 rows - that's one hash per 16 cairo steps.
        let every_256_row_zerofier_inv = &one / (X.pow(n / 256) - &one);

        // These first few pedersen constraints check that the number is in the range
        // ```text
        //  100000000000000000000000000000000000000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
        //  ^                                                       ^    ^
        // 251                                                     196  191
        // ```

        // Use knowledge of bits 251,196,192 to determine if there is overflow
        let pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                * (Pedersen::Suffix.curr() - (Pedersen::Suffix.next() + Pedersen::Suffix.next())))
                * &every_256_row_zerofier_inv;
        let shift191 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(191u32))));
        let pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                * (Pedersen::Suffix.next() - Pedersen::Suffix.offset(192) * shift191))
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
                * (Pedersen::Suffix.offset(193) - Pedersen::Suffix.offset(196) * shift3))
                * &every_256_row_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196 =
            (Pedersen::Bit251AndBit196.curr()
                - (Pedersen::Suffix.offset(251)
                    - (Pedersen::Suffix.offset(252) + Pedersen::Suffix.offset(252)))
                    * (Pedersen::Suffix.offset(196)
                        - (Pedersen::Suffix.offset(197) + Pedersen::Suffix.offset(197))))
                * &every_256_row_zerofier_inv;
        // TODO: docs
        let shift54 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(54u32))));
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196 = ((Pedersen::Suffix
            .offset(251)
            - (Pedersen::Suffix.offset(252) + Pedersen::Suffix.offset(252)))
            * (Pedersen::Suffix.offset(197) - Pedersen::Suffix.offset(251) * shift54))
            * &every_256_row_zerofier_inv;

        // example for trace length n=512
        // =============================
        // X^(n/256) - ω^(255*n/256)    = (x-ω^255)(x-ω^511)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the last row in each group
        // TODO: come up with better names for these
        let pedersen_transition_zerofier_inv = (X.pow(n / 256)
            * Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            * &all_cycles_zerofier_inv;

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
        // X^(n/256) - ω^(63*n/64)      = X^(n/256) - ω^(252*n/256)
        // X^(n/256) - ω^(255*n/256)    = (x-ω^252)(x-ω^508)
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
        // │   ω^252   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^253   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^254   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^255   │         0          │         0          │
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
        // │   ω^508   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^509   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^510   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^511   │         0          │         0          │
        // └───────────┴────────────────────┴────────────────────┘
        let (pedersen_x_coeffs, pedersen_y_coeffs) = pedersen::constant_points_poly();
        let pedersen_points_x = Polynomial::new(pedersen_x_coeffs);
        let pedersen_points_y = Polynomial::new(pedersen_y_coeffs);

        // TODO: double check if the value that's being evaluated is correct
        let pedersen_point_x = pedersen_points_x.eval(X.pow(n / 512));
        let pedersen_point_y = pedersen_points_y.eval(X.pow(n / 512));

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
        // X^(n/512) - ω^(n/2)                = X^(n/512) - ω^(256*n/512)
        // X^(n/512) - ω^(256*n/512)          = (x-ω^256)(x-ω^768)
        // x^(n/256) - 1                      = (x-ω_0)(x-ω_256)(x-ω_512)(x-ω_768)
        // (x-ω^256)(x-ω^768) / (X^(n/256)-1) = 1/(x-ω_0)(x-ω_512)
        // 1/(X^(n/512) - 1)                  = 1/(x-ω_0)(x-ω_512)
        // NOTE: By using `(x-ω^256)(x-ω^768) / (X^(n/256)-1)` rather than
        // `1/(X^(n/512) - 1)` we save an inversion operation since 1 / (X^(n/256)-1)
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
        let pedersen_hash0_copy_point_x = (Pedersen::PartialSumX.offset(256)
            - Pedersen::PartialSumX.offset(255))
            * &every_512_row_zerofier_inv;
        let pedersen_hash0_copy_point_y = (Pedersen::PartialSumY.offset(256)
            - Pedersen::PartialSumY.offset(255))
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
        let pedersen_input1_value0 = (Npc::PedersenInput1Val.curr() - Pedersen::Suffix.offset(256))
            * &every_512_row_zerofier_inv;
        let pedersen_input1_addr = (Npc::PedersenInput1Addr.curr()
            - (Npc::PedersenInput0Addr.curr() + &one))
            * &every_512_row_zerofier_inv;

        // Link pedersen output into the memory pool.
        // Output's address should be the address directly after input1's address.
        let pedersen_output_value0 = (Npc::PedersenOutputVal.curr()
            - Pedersen::PartialSumX.offset(511))
            * &every_512_row_zerofier_inv;
        let pedersen_output_addr = (Npc::PedersenOutputAddr.curr()
            - (Npc::PedersenInput1Addr.curr() + &one))
            * &every_512_row_zerofier_inv;

        // 128bit Range check builtin
        // ===================

        // TODO: fix naming
        let zerofier_256th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([256 * (n as u64 / 256 - 1)])));
        let every_256_rows_except_last_zerofier =
            &zerofier_256th_last_row * &every_256_row_zerofier_inv;

        // Hook up range check with the memory pool
        let rc_builtin_value =
            (rc_builtin_value7_0 - Npc::RangeCheck128Val.curr()) * &every_256_row_zerofier_inv;
        let rc_builtin_addr_step = (Npc::RangeCheck128Addr.next()
            - (Npc::RangeCheck128Addr.curr() + &one))
            * &every_256_rows_except_last_zerofier;

        let rc_builtin_init_addr =
            (Npc::RangeCheck128Addr.curr() - InitialRcAddr.hint()) * &first_row_zerofier_inv;

        // Signature constraints for ECDSA
        // ===============================

        // example for trace length n=32768
        // ================================
        // X^(n/16384) - ω^(255*n/256)     = X^(n/16384) - ω^(16320*n/16384)
        // X^(n/16384) - ω^(16320*n/16384) = (x-ω^16320)(x-ω^32704)
        //                                 = (x-ω^(64*255))(x-ω^(64*511))
        let every_64_row_zerofier = X.pow(n / 64) - &one;
        // vanishes on every 64 steps except the 255th of every 256
        let ec_op_transition_zerofier_inv = (X.pow(n / 16384)
            - Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            / &every_64_row_zerofier;

        // ecdsa/signature0/doubling_key/slope
        // TODO: figure out

        // These constraint maps to the curve point doubling equation:
        // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
        // ```text
        // curve eq: y^2 = x^3 + a*x + b
        // P = (x_p, y_p)
        // R = P + P = (x_r, x_y)
        // slope = (3*x_p^2 + a) / (2*y_p)
        // R_x = slope^2 - 2*x_p
        // R_y = slope*(x_p - x_r) - y_p
        // ```
        let ecdsa_sig_config_alpha = Constant(FieldVariant::Fp(ECDSA_SIG_CONFIG_ALPHA));
        // This constraint is checking `0 = (3*x_p^2 + a) - 2*y_p * slope`
        let ecdsa_signature0_doubling_key_slope = (&ecdsa_sig0_doubling_key_x_squared
            + &ecdsa_sig0_doubling_key_x_squared
            + &ecdsa_sig0_doubling_key_x_squared
            + ecdsa_sig_config_alpha
            - (Ecdsa::PubkeyDoublingY.curr() + Ecdsa::PubkeyDoublingY.curr())
                * Ecdsa::PubkeyDoublingSlope.curr())
            * &ec_op_transition_zerofier_inv;
        // This constraint checks `R_x = slope^2 - 2*x_p` => `0 = slope^2 - 2*x_p - R_x`
        let ecdsa_signature0_doubling_key_x = (Ecdsa::PubkeyDoublingSlope.curr()
            * Ecdsa::PubkeyDoublingSlope.curr()
            - (Ecdsa::PubkeyDoublingX.curr()
                + Ecdsa::PubkeyDoublingX.curr()
                + Ecdsa::PubkeyDoublingX.next()))
            * &ec_op_transition_zerofier_inv;
        // This constraint checks `R_y = slope*(x_p - x_r) - y_p` =>
        // `0 = y_p + R_y - slope*(x_p - x_r)`.
        let ecdsa_signature0_doubling_key_y = (Ecdsa::PubkeyDoublingY.curr()
            + Ecdsa::PubkeyDoublingY.next()
            - Ecdsa::PubkeyDoublingSlope.curr()
                * (Ecdsa::PubkeyDoublingX.curr() - Ecdsa::PubkeyDoublingX.next()))
            * &ec_op_transition_zerofier_inv;

        // example for trace length n=65536
        // ================================
        // X^(n/32768) - ω^(255*n/256)     = X^(n/32768) - ω^(32640*n/32768)
        // X^(n/32768) - ω^(32640*n/32768) = (x-ω^32640)(x-ω^65408)
        //                                 = (x-ω^(128*255))(x-ω^(128*511))
        let every_128_row_zerofier = X.pow(n / 128) - &one;
        // vanishes on every 128 steps except the 255th of every 256
        let ecdsa_transition_zerofier_inv = (X.pow(n / 32768)
            - Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            / &every_128_row_zerofier;

        // Constraint operates 256 times in steps of 128 rows
        // Each row shifts the message hash to the right. E.g.
        // ```text
        // row(128 * 0 + 38):     10101...10001 <- constraint applied
        // row(128 * 1 + 38):      1010...11000 <- constraint applied
        // ...                                  <- constraint applied
        // row(128 * 255 + 38):               0 <- constraint disabled
        // row(128 * 256 + 38):   11101...10001 <- constraint applied
        // row(128 * 257 + 38):    1110...01000 <- constraint applied
        // ...                                  <- constraint applied
        // row(128 * 511 + 38):               0 <- constraint disabled
        // ...
        // ```
        let ecdsa_signature0_exponentiate_generator_booleanity_test =
            (&ecdsa_sig0_exponentiate_generator_b0
                * (&ecdsa_sig0_exponentiate_generator_b0 - &one))
                * &ecdsa_transition_zerofier_inv;

        // example for trace length n=65536
        // =============================
        // X^(n/32768) - ω^(251*n/256)     = X^(n/32768) - ω^(32128*n/32768)
        // X^(n/32768) - ω^(32128*n/32768) = (x-ω^(32768*0+32128))(x-ω^(32768*1+32128))
        // vanishes on the 251st row of every 256 rows
        let ecdsa_zero_suffix_zerofier =
            X.pow(n / 32768) - Constant(FieldVariant::Fp(g.pow([(251 * n / 256) as u64])));

        // Note that with cairo's default field each element is 252 bits.
        // For Cairo's ECDSA we allow the message hash to be a 251 bit number.
        // Since we have a column that right shifts a number each row we check that the
        // suffix of row 251 (of every 256 row group) equals 0 e.g.
        // ```text
        // row(128 * 0 + 38):   10101...10001 <- NOTE: 1st ECDSA instance start
        // row(128 * 1 + 38):    1010...11000
        // ...
        // row(128 * 249 + 38):            10
        // row(128 * 250 + 38):             1
        // row(128 * 251 + 38):             0 <- check zero
        // row(128 * 252 + 38):             0
        // row(128 * 253 + 38):             0
        // row(128 * 254 + 38):             0
        // row(128 * 255 + 38):             0
        // row(128 * 256 + 38): 11101...10001 <- NOTE: 2nd ECDSA instance start
        // row(128 * 257 + 38):  1110...01000
        // ...
        // row(128 * 505 + 38):            11
        // row(128 * 506 + 38):             1
        // row(128 * 507 + 38):             0 <- check zero
        // row(128 * 508 + 38):             0
        // ...
        // ```
        let ecdsa_signature0_exponentiate_generator_bit_extraction_end =
            Ecdsa::MessageSuffix.curr() / &ecdsa_zero_suffix_zerofier;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let ecdsa_signature0_exponentiate_generator_zeros_tail = Ecdsa::MessageSuffix.curr()
            / (X.pow(n / 32768) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256]))));

        // TODO: double check
        // Create a periodic table comprising of the ECDSA generator points we need to
        // add together. The columns of this table are represented by polynomials that
        // evaluate to the `i`th row when evaluated on the `i`th power of the 256th
        // root of unity. e.g.
        //
        // let:
        // - `G` be the fixed generator point of Starkware's ECDSA curve
        // - `[G]_x` denotes the x-coordinate of an elliptic-curve point P
        //
        // then our point table is:
        // ┌───────────┬──────────────────┬──────────────────┐
        // │     X     │      F_x(X)      │      F_y(X)      │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ω^0    │   [G * 2^0]_x    │   [G * 2^0]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ω^1    │   [G * 2^1]_x    │   [G * 2^1]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ...    │         ...      │         ...      │
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^255   │  [G * 2^255]_x   │  [G * 2^255]_y   │
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^256   │   [G * 2^0]_x    │   [G * 2^0]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^257   │   [G * 2^1]_x    │   [G * 2^1]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ...    │         ...      │         ...      │
        // └───────────┴──────────────────┴──────────────────┘
        let (ecdsa_generator_x_coeffs, ecdsa_generator_y_coeffs) = ecdsa::generator_points_poly();
        let ecdsa_generator_points_x = Polynomial::new(ecdsa_generator_x_coeffs);
        let ecdsa_generator_points_y = Polynomial::new(ecdsa_generator_y_coeffs);

        // TODO: double check if the value that's being evaluated is correct
        let ecdsa_generator_point_x = ecdsa_generator_points_x.eval(X.pow(n / 32768));
        let ecdsa_generator_point_y = ecdsa_generator_points_y.eval(X.pow(n / 32768));

        // let `P = (Px, Py)` be the point to be added (see above)
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let ecdsa_signature0_exponentiate_generator_add_points_slope =
            (&ecdsa_sig0_exponentiate_generator_b0
                * (Ecdsa::GeneratorPartialSumY.curr() - &ecdsa_generator_point_y)
                - Ecdsa::GeneratorPartialSumSlope.curr()
                    * (Ecdsa::GeneratorPartialSumX.curr() - &ecdsa_generator_point_x))
                * &ecdsa_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Qx_next = m^2 - Qx - Px, m = dy/dx`
        // - `Qy_next = m*(Qx - Qx_next) - Qy, m = dy/dx`
        let ecdsa_signature0_exponentiate_generator_add_points_x =
            (Ecdsa::GeneratorPartialSumSlope.curr() * Ecdsa::GeneratorPartialSumSlope.curr()
                - &ecdsa_sig0_exponentiate_generator_b0
                    * (Ecdsa::GeneratorPartialSumX.curr()
                        + &ecdsa_generator_point_x
                        + Ecdsa::GeneratorPartialSumX.next()))
                * &ecdsa_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_generator_add_points_y =
            (&ecdsa_sig0_exponentiate_generator_b0
                * (Ecdsa::GeneratorPartialSumY.curr() + Ecdsa::GeneratorPartialSumY.next())
                - Ecdsa::GeneratorPartialSumSlope.curr()
                    * (Ecdsa::GeneratorPartialSumX.curr() - Ecdsa::GeneratorPartialSumX.next()))
                * &ecdsa_transition_zerofier_inv;
        // constraint checks that the cell contains 1/(Qx - Gx)
        // Why this constraint? it checks that the Qx and Gx are not equal
        let ecdsa_signature0_exponentiate_generator_add_points_x_diff_inv =
            (Ecdsa::GeneratorPartialSumXDiffInv.curr()
                * (Ecdsa::GeneratorPartialSumX.curr() - &ecdsa_generator_point_x)
                - &one)
                * &ecdsa_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let ecdsa_signature0_exponentiate_generator_copy_point_x =
            (&ecdsa_sig0_exponentiate_generator_b0_neg
                * (Ecdsa::GeneratorPartialSumX.next() - Ecdsa::GeneratorPartialSumX.curr()))
                * &ecdsa_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_generator_copy_point_y =
            (&ecdsa_sig0_exponentiate_generator_b0_neg
                * (Ecdsa::GeneratorPartialSumY.next() - Ecdsa::GeneratorPartialSumY.curr()))
                * &ecdsa_transition_zerofier_inv;

        // NOTE: exponentiate key, exponentiate generator and pedersen are almost
        // identical TODO: try DRY this code. Come up with the right
        // abstractions first though

        // Constraint operates 256 times in steps of 64 rows
        // Each row shifts the signature's `r` value to the right. E.g.
        // ```text
        // row(64 * 0 + 12):     10101...10001 <- constraint applied
        // row(64 * 1 + 12):      1010...11000 <- constraint applied
        // ...                                 <- constraint applied
        // row(64 * 255 + 12):               0 <- constraint disabled
        // row(64 * 256 + 12):   11101...10001 <- constraint applied
        // row(64 * 257 + 12):    1110...01000 <- constraint applied
        // ...                                 <- constraint applied
        // row(64 * 511 + 12):               0 <- constraint disabled
        // ...
        // ```
        let ecdsa_signature0_exponentiate_key_booleanity_test = (&ecdsa_sig0_exponentiate_key_b0
            * (&ecdsa_sig0_exponentiate_key_b0 - &one))
            * &ec_op_transition_zerofier_inv;

        let ec_op_zero_suffix_zerofier =
            X.pow(n / 16384) - Constant(FieldVariant::Fp(g.pow([(251 * n / 256) as u64])));

        // Note that with cairo's default field each element is 252 bits.
        // For Cairo's ECDSA we allow the signature's `r` value to be a 251 bit number.
        // Since we have a column that right shifts a number every 64 rows we check that
        // the suffix of row 64*251 (of every 256 row group) equals 0 e.g.
        // ```text
        // row(64 * 0 + 38):   10101...10001 <- NOTE: 1st ECDSA instance start
        // row(64 * 1 + 38):    1010...11000
        // ...
        // row(64 * 249 + 38):            10
        // row(64 * 250 + 38):             1
        // row(64 * 251 + 38):             0 <- check zero
        // row(64 * 252 + 38):             0
        // row(64 * 253 + 38):             0
        // row(64 * 254 + 38):             0
        // row(64 * 255 + 38):             0
        // row(64 * 256 + 38): 11101...10001 <- NOTE: 2nd ECDSA instance start
        // row(64 * 257 + 38):  1110...01000
        // ...
        // row(64 * 505 + 38):            11
        // row(64 * 506 + 38):             1
        // row(64 * 507 + 38):             0 <- check zero
        // row(64 * 508 + 38):             0
        // ...
        // ```
        let ecdsa_signature0_exponentiate_key_bit_extraction_end =
            Ecdsa::RSuffix.curr() / &ec_op_zero_suffix_zerofier;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let ecdsa_signature0_exponentiate_key_zeros_tail = Ecdsa::RSuffix.curr()
            / (X.pow(n / 16384) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256]))));

        // let `P = (Px, Py)` be the doubled pubkey point to be added
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let ecdsa_signature0_exponentiate_key_add_points_slope = (&ecdsa_sig0_exponentiate_key_b0
            * (Ecdsa::PubkeyPartialSumY.curr() - Ecdsa::PubkeyDoublingY.curr())
            - Ecdsa::PubkeyPartialSumSlope.curr()
                * (Ecdsa::PubkeyPartialSumX.curr() - Ecdsa::PubkeyDoublingX.curr()))
            * &ec_op_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Qx_next = m^2 - Qx - Px, m = dy/dx`
        // - `Qy_next = m*(Qx - Qx_next) - Qy, m = dy/dx`
        let ecdsa_signature0_exponentiate_key_add_points_x = (Ecdsa::PubkeyPartialSumSlope.curr()
            * Ecdsa::PubkeyPartialSumSlope.curr()
            - &ecdsa_sig0_exponentiate_key_b0
                * (Ecdsa::PubkeyPartialSumX.curr()
                    + Ecdsa::PubkeyDoublingX.curr()
                    + Ecdsa::PubkeyPartialSumX.next()))
            * &ec_op_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_key_add_points_y = (&ecdsa_sig0_exponentiate_key_b0
            * (Ecdsa::PubkeyPartialSumY.curr() + Ecdsa::PubkeyPartialSumY.next())
            - Ecdsa::PubkeyPartialSumSlope.curr()
                * (Ecdsa::PubkeyPartialSumX.curr() - Ecdsa::PubkeyPartialSumX.next()))
            * &ec_op_transition_zerofier_inv;
        // constraint checks that the cell contains 1/(Qx - Px)
        // Why this constraint? it checks that the Qx and Px are not equal
        // with Px the x-coordinate of the doubled pubkey
        // and Qx the x-coordinate of the partial sum of the pubkey
        let ecdsa_signature0_exponentiate_key_add_points_x_diff_inv =
            (Ecdsa::PubkeyPartialSumXDiffInv.curr()
                * (Ecdsa::PubkeyPartialSumX.curr() - Ecdsa::PubkeyDoublingX.curr())
                - &one)
                * &ec_op_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let ecdsa_signature0_exponentiate_key_copy_point_x = (&ecdsa_sig0_exponentiate_key_b0_neg
            * (Ecdsa::PubkeyPartialSumX.next() - Ecdsa::PubkeyPartialSumX.curr()))
            * &ec_op_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_key_copy_point_y = (&ecdsa_sig0_exponentiate_key_b0_neg
            * (Ecdsa::PubkeyPartialSumY.next() - Ecdsa::PubkeyPartialSumY.curr()))
            * &ec_op_transition_zerofier_inv;

        let all_ecdsa_zerofier = X.pow(n / 32768) - &one;
        let all_ecdsa_zerofier_inv = &one / all_ecdsa_zerofier;
        let all_ec_op_zerofier = X.pow(n / 16384) - &one;
        let all_ec_op_zerofier_inv = &one / all_ec_op_zerofier;

        // Check the correct starting values for our partial sums
        // ======================================================
        // #1 Check out generator `G` partial sum is offset with the `-shift_point`
        let ecdsa_sig_config_shift_point_x = Constant(FieldVariant::Fp(ecdsa::SHIFT_POINT.x));
        let ecdsa_sig_config_shift_point_y = Constant(FieldVariant::Fp(ecdsa::SHIFT_POINT.y));
        let ecdsa_signature0_init_gen_x = (Ecdsa::GeneratorPartialSumX.curr()
            - ecdsa_sig_config_shift_point_x)
            * &all_ecdsa_zerofier_inv;
        let ecdsa_signature0_init_gen_y = (Ecdsa::GeneratorPartialSumY.curr()
            + ecdsa_sig_config_shift_point_y)
            * &all_ecdsa_zerofier_inv;
        // #2 Check out pubkey partial sum is offset with the `shift_point`
        let ecdsa_signature0_init_key_x = (Ecdsa::PubkeyPartialSumX.curr()
            - ecdsa_sig_config_shift_point_x)
            * &all_ec_op_zerofier_inv;
        let ecdsa_signature0_init_key_y = (Ecdsa::PubkeyPartialSumY.curr()
            - ecdsa_sig_config_shift_point_y)
            * &all_ec_op_zerofier_inv;

        // Note that there are two elliptic curve operations that span 16384 rows each.
        // 1st is the EC operation for our pubkey partial sum
        // 2nd is the EC operation is for the partial sum of `msg_hash * G + r * P`
        // - with the signature's `r`, Curve's generator point G and pubkey P
        // This constraint checks the starting value for the 2nd EC operation
        // By checking it is the sum `msg_hash * G + r * P`
        //
        // Note: the last GeneratorPartialSum slope is repurposed for the slope of the
        // sum `(msg_hash * G) + (r * P)`.
        let ecdsa_signature0_add_results_slope = (Ecdsa::GeneratorPartialSumY.offset(255)
            - (Ecdsa::PubkeyPartialSumY.offset(255)
                + Ecdsa::BSlope.curr()
                    * (Ecdsa::GeneratorPartialSumX.offset(255)
                        - Ecdsa::PubkeyPartialSumX.offset(255))))
            * &all_ecdsa_zerofier_inv;
        // Now we have the slope finish the addition as per SW curve addition law.
        // `x = m^2 - (msg_hash * G)_x - (R * P)_x, m = dy/dx`
        // `y = m*((msg_hash*G)_x - x) - (msg_hash*G)_y, m = dy/dx`
        let ecdsa_signature0_add_results_x = (Ecdsa::BSlope.curr() * Ecdsa::BSlope.curr()
            - (Ecdsa::GeneratorPartialSumX.offset(255)
                + Ecdsa::PubkeyPartialSumX.offset(255)
                + Ecdsa::PubkeyDoublingX.offset(256)))
            * &all_ecdsa_zerofier_inv;
        // TODO: introduce more generic names for PubkeyDoublingX, PubkeyDoublingY,
        // PubkeyPartialSum* etc. since they're not just for pubkey but also the partial
        // sum of the point `(msg_hash * G) + (r * P)`.
        let ecdsa_signature0_add_results_y = (Ecdsa::GeneratorPartialSumY.offset(255)
            + Ecdsa::PubkeyDoublingY.offset(256)
            - Ecdsa::BSlope.curr()
                * (Ecdsa::GeneratorPartialSumX.offset(255) - Ecdsa::PubkeyDoublingX.offset(256)))
            * &all_ecdsa_zerofier_inv;
        // constraint checks that the cell contains 1/((msg_hash * G)_x - (r * P)_x)
        // Once again like the slope we repurpose the last GeneratorPartialSumXDiffInv
        // Why this constraint? it checks that the (msg_hash * G)_x and (r * P)_x are
        // not equal. Case (1) would mean the ys are distinct => vertical slope => sum
        // would be point at infinity - no good, case (2) would mean the points
        // are equal and there is no slope through the points
        let ecdsa_signature0_add_results_x_diff_inv = (Ecdsa::BXDiffInv.curr()
            * (Ecdsa::GeneratorPartialSumX.offset(255) - Ecdsa::PubkeyPartialSumX.offset(255))
            - &one)
            * &all_ecdsa_zerofier_inv;

        // let `B = ((msg_hash * G) + (r * P)), H = w * B`
        // Here we are trying to calculate `H - shift_point`
        // NOTE: `(H - shift_point)_x` should equal `r`
        // First we need the slope between points `H` and `-shift_point`
        let ecdsa_signature0_extract_r_slope = (Ecdsa::PubkeyPartialSumY.offset(256 + 255)
            + ecdsa_sig_config_shift_point_y
            - Ecdsa::RPointSlope.curr()
                * (Ecdsa::PubkeyPartialSumX.offset(256 + 255) - ecdsa_sig_config_shift_point_x))
            * &all_ecdsa_zerofier_inv;
        // Now we have the slope we can find the x-coordinate of `H - shift_point`
        // (which if the signature is valid will be `r`) using SW curve addition
        // law: `x = m^2 - H_x - (-shift_point)_x, m = dy/dx`
        let ecdsa_signature0_extract_r_x = (Ecdsa::RPointSlope.curr() * Ecdsa::RPointSlope.curr()
            - (Ecdsa::PubkeyPartialSumX.offset(256 + 255)
                + ecdsa_sig_config_shift_point_x
                + Ecdsa::RSuffix.curr()))
            * &all_ecdsa_zerofier_inv;
        // constraint checks that the cell contains 1/(H_x - shift_point_x)
        // Once again like the slope we repurpose the last GeneratorPartialSumXDiffInv
        let ecdsa_signature0_extract_r_x_diff_inv = (Ecdsa::RPointXDiffInv.curr()
            * (Ecdsa::PubkeyPartialSumX.offset(256 + 255) - ecdsa_sig_config_shift_point_x)
            - &one)
            * &all_ecdsa_zerofier_inv;

        // `z` refers to the message hash. Check that it's not the zero hash.
        let ecdsa_signature0_z_nonzero = (Ecdsa::MessageSuffix.curr() * Ecdsa::MessageInv.curr()
            - &one)
            * &all_ecdsa_zerofier_inv;

        // NOTE: `PubkeyDoublingSlope.offset(255)` holds a value that isn't constrained
        // Every 16370th of every 32768 rows PubkeyDoublingSlope contains r^(-1)
        // Every 32754th of every 32768 rows PubkeyDoublingSlope contains w^(-1)
        let ecdsa_signature0_r_and_w_nonzero =
            (Ecdsa::RSuffix.curr() * Ecdsa::PubkeyDoublingSlope.offset(255) - &one)
                * &all_ec_op_zerofier_inv;

        // check the pubkey `Q` is on the elliptic curve
        // aka check `y^2 = x^3 + a*x + b`
        let ecdsa_signature0_q_on_curve_x_squared = (Ecdsa::PubkeyXSquared.curr()
            - Ecdsa::PubkeyDoublingX.curr() * Ecdsa::PubkeyDoublingX.curr())
            * &all_ecdsa_zerofier_inv;
        let ecdsa_sig_config_beta = Constant(FieldVariant::Fp(ECDSA_SIG_CONFIG_BETA));
        let ecdsa_signature0_q_on_curve_on_curve = (Ecdsa::PubkeyDoublingY.curr()
            * Ecdsa::PubkeyDoublingY.curr()
            - (Ecdsa::PubkeyDoublingX.curr() * Ecdsa::PubkeyXSquared.curr()
                + Ecdsa::PubkeyDoublingX.curr() * ecdsa_sig_config_alpha
                + ecdsa_sig_config_beta))
            * &all_ecdsa_zerofier_inv;

        let last_ecdsa_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([32768 * (n / 32768 - 1) as u64])));
        let all_ecdsa_except_last_zerofier_inv = &last_ecdsa_zerofier * &all_ecdsa_zerofier_inv;

        // Check starting address of the ECDSA memory segment
        // memory segments in Cairo are continuous i.e. Memory:
        // |0->100 all pedersen mem|101 -> 151 all RC mem|151 -> 900 all ECDSA mem|
        let ecdsa_init_addr =
            (Npc::EcdsaPubkeyAddr.curr() - InitialEcdsaAddr.hint()) * &first_row_zerofier_inv;

        // NOTE: message address is the 2nd address of each instance
        let ecdsa_message_addr = (Npc::EcdsaMessageAddr.curr()
            - (Npc::EcdsaPubkeyAddr.curr() + &one))
            * &all_ecdsa_zerofier_inv;

        // NOTE: pubkey address is the 1st address of each instance
        let ecdsa_pubkey_addr = (Npc::EcdsaPubkeyAddr.next()
            - (Npc::EcdsaMessageAddr.curr() + &one))
            * &all_ecdsa_except_last_zerofier_inv;

        // Check the ECDSA Message and Pubkey are correctly loaded into memory
        let ecdsa_message_value0 =
            (Npc::EcdsaMessageVal.curr() - Ecdsa::MessageSuffix.curr()) * &all_ecdsa_zerofier_inv;
        let ecdsa_pubkey_value0 =
            (Npc::EcdsaPubkeyVal.curr() - Ecdsa::PubkeyDoublingX.curr()) * &all_ecdsa_zerofier_inv;

        // bitwise builtin
        // ===============

        // check the initial bitwise segment memory address
        // all addresses associated with bitwise checks are continuous
        let bitwise_init_var_pool_addr =
            (Npc::BitwisePoolAddr.curr() - InitialBitwiseAddr.hint()) * &first_row_zerofier_inv;

        // example for trace length n=1024
        // ================================
        // X^(n/1024) - ω^(3*n/4)      = X^(n/1024) - ω^(768*n/1024)
        // X^(n/1024) - ω^(768*n/1024) = (x-ω^768)
        // X^(n/256) - 1               = (x-ω^0)(x-ω^256)(x-ω^512)(x-ω^768)
        // (x-ω^768)/(X^(n/256) - 1)   = 1/((x-ω^0)(x-ω^256)(x-ω^512))
        // vanishes on every 256th row except the 3rd of every 4
        let bitwise_transition_zerofier_inv = (X.pow(n / 1024)
            - Constant(FieldVariant::Fp(g.pow([(3 * n / 4) as u64]))))
            * &every_256_row_zerofier_inv;

        let all_bitwise_zerofier = X.pow(n / 1024) - &one;
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
            X - Constant(FieldVariant::Fp(g.pow([1024 * (n / 1024 - 1) as u64])));
        let all_bitwise_except_last_zerofier_inv =
            &last_bitwise_zerofier * &all_bitwise_zerofier_inv;

        // check the next bitwise instance has the correct address
        let bitwise_next_var_pool_addr = (Npc::BitwisePoolAddr.offset(4)
            - (Npc::BitwiseXOrYAddr.curr() + &one))
            * &all_bitwise_except_last_zerofier_inv;

        // let bitwise_x_addr = Npc::BitwisePoolAddr.offset(0);
        // let bitwise_y_addr = Npc::BitwisePoolAddr.offset(1);
        let bitwise_x_and_y_val = Npc::BitwisePoolVal.offset(2);
        let bitwise_x_xor_y_val = Npc::BitwisePoolVal.offset(3);

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
        // TODO

        // NOTE: `x | y = (x & y) + (x ^ y)`
        let bitwise_or_is_and_plus_xor = (Npc::BitwiseXOrYVal.curr()
            - (&bitwise_x_and_y_val + &bitwise_x_xor_y_val))
            * &all_bitwise_zerofier_inv;

        // example for trace length n=2048
        // ===============================
        // X^(n/1024) - ω^(1*n/64))  = X^(n/1024) - ω^(16 * n / 1024))
        //                           = (x - ω^(16 * 1))(x - ω^(1024 + (16 * 1)))
        // X^(n/1024) - ω^(1*n/32))  = X^(n/1024) - ω^(32 * n / 1024))
        //                           = (x - ω^(16 * 2))(x - ω^(1024 + (16 * 2)))
        // X^(n/1024) - ω^(3*n/64))  = X^(n/1024) - ω^(48 * n / 1024))
        //                           = (x - ω^(16 * 3))(x - ω^(1024 + (16 * 3)))
        // X^(n/1024) - ω^(1*n/16))  = X^(n/1024) - ω^(64 * n / 1024))
        //                           = (x - ω^(16 * 4))(x - ω^(1024 + (16 * 4)))
        // X^(n/1024) - ω^(5*n/64))  = X^(n/1024) - ω^(80 * n / 1024))
        //                           = (x - ω^(16 * 5))(x - ω^(1024 + (16 * 5)))
        // X^(n/1024) - ω^(3*n/32))  = X^(n/1024) - ω^(96 * n / 1024))
        //                           = (x - ω^(16 * 6))(x - ω^(1024 + (16 * 6)))
        // X^(n/1024) - ω^(7*n/64))  = X^(n/1024) - ω^(112 * n / 1024))
        //                           = (x - ω^(16 * 7))(x - ω^(1024 + (16 * 7)))
        // X^(n/1024) - ω^(1*n/8))   = X^(n/1024) - ω^(128 * n / 1024))
        //                           = (x - ω^(16 * 8))(x - ω^(1024 + (16 * 8)))
        // X^(n/1024) - ω^(9*n/64))  = X^(n/1024) - ω^(144 * n / 1024))
        //                           = (x - ω^(16 * 9))(x - ω^(1024 + (16 * 9)))
        // X^(n/1024) - ω^(5*n/32))  = X^(n/1024) - ω^(160 * n / 1024))
        //                           = (x - ω^(16 * 10))(x - ω^(1024 + (16 * 10)))
        // X^(n/1024) - ω^(11*n/64)) = X^(n/1024) - ω^(176 * n / 1024))
        //                           = (x - ω^(16 * 11))(x - ω^(1024 + (16 * 11)))
        // X^(n/1024) - ω^(3*n/16))  = X^(n/1024) - ω^(192 * n / 1024))
        //                           = (x - ω^(16 * 12))(x - ω^(1024 + (16 * 12)))
        // X^(n/1024) - ω^(13*n/64)) = X^(n/1024) - ω^(208 * n / 1024))
        //                           = (x - ω^(16 * 13))(x - ω^(1024 + (16 * 13)))
        // X^(n/1024) - ω^(7*n/32))  = X^(n/1024) - ω^(224 * n / 1024))
        //                           = (x - ω^(16 * 14))(x - ω^(1024 + (16 * 14)))
        // X^(n/1024) - ω^(15*n/64)) = X^(n/1024) - ω^(240 * n / 1024))
        //                           = (x - ω^(16 * 15))(x - ω^(1024 + (16 * 15)))
        // NOTE: when you multiply all these together you get:
        // $\prod_{i=1}^{15}(x - ω^(16 * i))(x - ω^(1024 + (16 * i)))$
        // now multiply this product by $x^(n / 1024) - 1$
        // TODO: isn't this zerofier just equivalent to $x^(n / 16) - 1$?
        let every_16_bit_segment_zerofier = (X.pow(n / 1024)
            - Constant(FieldVariant::Fp(g.pow([n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([n as u64 / 16]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([n as u64 / 8]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([9 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([11 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 16]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([13 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([15 * n as u64 / 64]))))
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

        // let bitwise_unique_unpacking192 =

        // new
        // let bitwise_partition =
        // let bitwise_or_is_and_plus_xor =
        // new

        // let ecdsa_signature0_doubling_key_x =

        // X^(n/512) - ω^(n/2)    = (x-ω^255)(x-ω^511)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the last row in each group

        // point^(trace_length / 512) - trace_generator^(trace_length / 2).
        // let pedersen_hash0_copy_point_x =

        let _tmp = vec![
            &memory_initial_addr,
            &public_memory_addr_zero,
            &public_memory_value_zero,
            &rc16_perm_init0,
            &rc16_perm_step0,
            &rc16_perm_last,
            &rc16_diff_is_bit,
            &rc16_minimum,
            &rc16_maximum,
            // TODO: diluted constraints
            // TODO: understand these constraints
            &pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero,
            &pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192,
            &pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196,
            // TODO: understand these constraints
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
            &ecdsa_signature0_doubling_key_slope,
            &ecdsa_signature0_doubling_key_x,
            &ecdsa_signature0_doubling_key_y,
            &ecdsa_signature0_exponentiate_generator_booleanity_test,
            &ecdsa_signature0_exponentiate_generator_bit_extraction_end,
            &ecdsa_signature0_exponentiate_generator_zeros_tail,
            &ecdsa_signature0_exponentiate_generator_add_points_slope,
            &ecdsa_signature0_exponentiate_generator_add_points_x,
            &ecdsa_signature0_exponentiate_generator_add_points_y,
            &ecdsa_signature0_exponentiate_generator_add_points_x_diff_inv,
            &ecdsa_signature0_exponentiate_generator_copy_point_x,
            &ecdsa_signature0_exponentiate_generator_copy_point_y,
            &ecdsa_signature0_exponentiate_key_booleanity_test,
            &ecdsa_signature0_exponentiate_key_bit_extraction_end,
            &ecdsa_signature0_exponentiate_key_zeros_tail,
            &ecdsa_signature0_exponentiate_key_add_points_slope,
            &ecdsa_signature0_exponentiate_key_add_points_x,
            &ecdsa_signature0_exponentiate_key_add_points_y,
            &ecdsa_signature0_exponentiate_key_add_points_x_diff_inv,
            &ecdsa_signature0_exponentiate_key_copy_point_x,
            &ecdsa_signature0_exponentiate_key_copy_point_y,
            &ecdsa_signature0_init_gen_x,
            &ecdsa_signature0_init_gen_y,
            &ecdsa_signature0_init_key_x,
            &ecdsa_signature0_init_key_y,
            &ecdsa_signature0_add_results_slope,
            &ecdsa_signature0_add_results_x,
            &ecdsa_signature0_add_results_y,
            &ecdsa_signature0_add_results_x_diff_inv,
            &ecdsa_signature0_extract_r_slope,
            &ecdsa_signature0_extract_r_x,
            &ecdsa_signature0_extract_r_x_diff_inv,
            &ecdsa_signature0_z_nonzero,
            &ecdsa_signature0_r_and_w_nonzero,
            &ecdsa_signature0_q_on_curve_x_squared,
            &ecdsa_signature0_q_on_curve_on_curve,
            &ecdsa_init_addr,
            &ecdsa_message_addr,
            &ecdsa_pubkey_addr,
            &ecdsa_message_value0,
            &ecdsa_pubkey_value0,
            &diluted_check_permutation_init0,
            &diluted_check_permutation_step0,
            &diluted_check_permutation_last,
            &diluted_check_init,
            &diluted_check_first_element,
            &diluted_check_step,
            &diluted_check_last,
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
            // diluted_check_permutation_init0,
            // diluted_check_permutation_step0,
            // diluted_check_permutation_last,
            // diluted_check_init,
            // diluted_check_first_element,
            // diluted_check_step,
            // diluted_check_last,
            // // TODO: understand these constraints
            // pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero,
            // pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192,
            // pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196,
            // // TODO: understand these constraints
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
            // rc_builtin_value,
            // rc_builtin_addr_step,
            // rc_builtin_init_addr,
            // ecdsa_signature0_doubling_key_slope,
            // ecdsa_signature0_doubling_key_x,
            // ecdsa_signature0_doubling_key_y,
            // ecdsa_signature0_exponentiate_generator_booleanity_test,
            // ecdsa_signature0_exponentiate_generator_bit_extraction_end,
            // ecdsa_signature0_exponentiate_generator_zeros_tail,
            // ecdsa_signature0_exponentiate_generator_add_points_slope,
            // ecdsa_signature0_exponentiate_generator_add_points_x,
            // ecdsa_signature0_exponentiate_generator_add_points_y,
            // ecdsa_signature0_exponentiate_generator_add_points_x_diff_inv,
            // ecdsa_signature0_exponentiate_generator_copy_point_x,
            // ecdsa_signature0_exponentiate_generator_copy_point_y,
            // ecdsa_signature0_exponentiate_key_booleanity_test,
            // ecdsa_signature0_exponentiate_key_bit_extraction_end,
            // ecdsa_signature0_exponentiate_key_zeros_tail,
            // ecdsa_signature0_exponentiate_key_add_points_slope,
            // ecdsa_signature0_exponentiate_key_add_points_x,
            // ecdsa_signature0_exponentiate_key_add_points_y,
            // ecdsa_signature0_exponentiate_key_add_points_x_diff_inv,
            // ecdsa_signature0_exponentiate_key_copy_point_x,
            // ecdsa_signature0_exponentiate_key_copy_point_y,
            // ecdsa_signature0_init_gen_x,
            // ecdsa_signature0_init_gen_y,
            // ecdsa_signature0_init_key_x,
            // ecdsa_signature0_init_key_y,
            // ecdsa_signature0_add_results_slope,
            // ecdsa_signature0_add_results_x,
            // ecdsa_signature0_add_results_y,
            // ecdsa_signature0_add_results_x_diff_inv,
            // ecdsa_signature0_extract_r_slope,
            // ecdsa_signature0_extract_r_x,
            // ecdsa_signature0_extract_r_x_diff_inv,
            // ecdsa_signature0_z_nonzero,
            // ecdsa_signature0_r_and_w_nonzero,
            // ecdsa_signature0_q_on_curve_x_squared,
            // ecdsa_signature0_q_on_curve_on_curve,
            // ecdsa_init_addr,
            // ecdsa_message_addr,
            // ecdsa_pubkey_addr,
            // ecdsa_message_value0,
            // ecdsa_pubkey_value0,
            bitwise_init_var_pool_addr,
            bitwise_step_var_pool_addr,
            bitwise_x_or_y_addr,
            bitwise_next_var_pool_addr,
            bitwise_partition,
            bitwise_or_is_and_plus_xor,
            bitwise_addition_is_xor_with_and,
            // // TODO: bitwise/addition_is_xor_with_and
            // // TODO: bitwise/unique_unpacking192
        ]
        .into_iter()
        .map(Constraint::new)
        .collect()
    }

    fn gen_hints(
        trace_len: usize,
        execution_info: &ExecutionInfo<Self::Fp>,
        challenges: &Challenges<Self::Fq>,
    ) -> Hints<Self::Fq> {
        use PublicInputHint::*;
        let ExecutionInfo {
            initial_ap,
            initial_pc,
            final_ap,
            final_pc,
            range_check_min,
            range_check_max,
            public_memory,
            public_memory_padding_address,
            public_memory_padding_value,
            initial_pedersen_address,
            initial_rc_address,
            initial_ecdsa_address,
            initial_bitwise_address,
        } = execution_info;

        let initial_pedersen_address = initial_pedersen_address.expect("layout6 requires Pedersen");
        let initial_rc_address = initial_rc_address.expect("layout6 requires range check");
        let initial_ecdsa_address = initial_ecdsa_address.expect("layout6 requires ecdsa");
        let initial_bitwise_address = initial_bitwise_address.expect("layout6 requires bitwise");

        let memory_product = utils::compute_public_memory_quotient(
            challenges[MemoryPermutation::Z],
            challenges[MemoryPermutation::A],
            trace_len,
            public_memory,
            (*public_memory_padding_address as u64).into(),
            *public_memory_padding_value,
        );

        let diluted_cumulative_val = Fp::ONE;
        // let diluted_cumulative_val = compute_diluted_cumulative_value::<
        //     Fp,
        //     Fp,
        //     DILUTED_CHECK_N_BITS,
        //     DILUTED_CHECK_SPACING,
        // >(
        //     challenges[DilutedCheckAggregation::Z],
        //     challenges[DilutedCheckAggregation::A],
        // );

        assert!(range_check_min <= range_check_max);

        Hints::new(vec![
            (InitialAp.index(), *initial_ap),
            (InitialPc.index(), *initial_pc),
            (FinalAp.index(), *final_ap),
            (FinalPc.index(), *final_pc),
            // TODO: this is a wrong value. Must fix
            (MemoryProduct.index(), memory_product),
            (RangeCheckProduct.index(), Fp::ONE),
            (RangeCheckMin.index(), (*range_check_min as u64).into()),
            (RangeCheckMax.index(), (*range_check_max as u64).into()),
            (DilutedCheckProduct.index(), Fp::ONE),
            (DilutedCheckFirst.index(), Fp::ZERO),
            (DilutedCheckCumulativeValue.index(), diluted_cumulative_val),
            (InitialPedersenAddr.index(), initial_pedersen_address.into()),
            (InitialRcAddr.index(), initial_rc_address.into()),
            (InitialEcdsaAddr.index(), initial_ecdsa_address.into()),
            (InitialBitwiseAddr.index(), initial_bitwise_address.into()),
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
        7
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
pub enum Ecdsa {
    PubkeyDoublingX = 4,
    PubkeyDoublingY = 36,
    PubkeyDoublingSlope = 50,
    PubkeyPartialSumX = 20,
    PubkeyPartialSumY = 52,
    PubkeyPartialSumXDiffInv = 42,
    PubkeyPartialSumSlope = 10,
    RSuffix = 12,
    MessageSuffix = 38,
    GeneratorPartialSumY = 70,
    GeneratorPartialSumX = 6,
    GeneratorPartialSumXDiffInv = 22,
    GeneratorPartialSumSlope = 102,
    // NOTE: 16346 % 64 = 26
    // NOTE: 32730 % 64 = 26
    RPointSlope = 16346,
    RPointXDiffInv = 32730,
    // NOTE: 16370 % 64 = 50
    // NOTE: 32754 % 64 = 50
    RInv = 16370,
    WInv = 32754,
    // NOTE: 32762 % 64 = 58
    // NOTE: 16378 % 64 = 58
    MessageInv = 16378,
    PubkeyXSquared = 32762,
    // NOTE: 32742 % 128 = 102
    // NOTE: 32662 % 128 = 22
    BSlope = 32742,
    BXDiffInv = 32662,
}

impl ExecutionTraceColumn for Ecdsa {
    fn index(&self) -> usize {
        match self {
            Self::PubkeyDoublingX
            | Self::PubkeyDoublingY
            | Self::PubkeyPartialSumX
            | Self::PubkeyPartialSumY
            | Self::PubkeyPartialSumXDiffInv
            | Self::PubkeyPartialSumSlope
            | Self::RSuffix
            | Self::MessageSuffix
            | Self::PubkeyDoublingSlope
            | Self::GeneratorPartialSumY
            | Self::GeneratorPartialSumX
            | Self::GeneratorPartialSumXDiffInv
            | Self::GeneratorPartialSumSlope
            | Self::RPointSlope
            | Self::RPointXDiffInv
            | Self::PubkeyXSquared
            | Self::MessageInv
            | Self::BSlope
            | Self::BXDiffInv
            | Self::RInv
            | Self::WInv => 8,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::PubkeyDoublingX
            | Self::PubkeyDoublingY
            | Self::PubkeyDoublingSlope
            | Self::RSuffix
            | Self::PubkeyPartialSumX
            | Self::PubkeyPartialSumY
            | Self::PubkeyPartialSumXDiffInv
            | Self::PubkeyPartialSumSlope => {
                EC_OP_BUILTIN_RATIO * CYCLE_HEIGHT / EC_OP_SCALAR_HEIGHT
            }
            Self::MessageSuffix
            | Self::GeneratorPartialSumX
            | Self::GeneratorPartialSumY
            | Self::GeneratorPartialSumSlope
            | Self::GeneratorPartialSumXDiffInv => {
                ECDSA_BUILTIN_RATIO * CYCLE_HEIGHT / EC_OP_SCALAR_HEIGHT
            }
            Self::RPointSlope
            | Self::RPointXDiffInv
            | Self::PubkeyXSquared
            | Self::MessageInv
            | Self::BSlope
            | Self::BXDiffInv
            | Self::RInv
            | Self::WInv => ECDSA_BUILTIN_RATIO * CYCLE_HEIGHT,
        } as isize;
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum Bitwise {
    /// for 1st chunk 64 bits
    Bits16Chunk0Offset0 = 1,
    Bits16Chunk0Offset1 = 17,
    Bits16Chunk0Offset2 = 33,
    Bits16Chunk0Offset3 = 49,
    /// for 2nd chunk of 64 bits
    Bits16Chunk1Offset0 = 65,
    Bits16Chunk1Offset1 = 81,
    Bits16Chunk1Offset2 = 97,
    Bits16Chunk1Offset3 = 113,
    /// for 3rd chunk of 64 bits
    Bits16Chunk2Offset0 = 129,
    Bits16Chunk2Offset1 = 145,
    Bits16Chunk2Offset2 = 161,
    Bits16Chunk2Offset3 = 177,
    /// for 4th chunk of 64 bits
    Bits16Chunk3Offset0 = 193,
    Bits16Chunk3Offset1 = 209,
    Bits16Chunk3Offset2 = 225,
    Bits16Chunk3Offset3 = 241,
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
            | Self::Bits16Chunk3Offset3 => 7,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        AlgebraicItem::Trace(column, offset * 256 + *self as isize).into()
    }
}

#[derive(Clone, Copy)]
pub enum Pedersen {
    PartialSumX,
    PartialSumY,
    Suffix,
    Slope,
    Bit251AndBit196AndBit192 = 86,
    Bit251AndBit196 = 255,
}

impl ExecutionTraceColumn for Pedersen {
    fn index(&self) -> usize {
        match self {
            Self::PartialSumX => 1,
            Self::PartialSumY => 2,
            Self::Suffix => 3,
            Self::Slope | Self::Bit251AndBit196 => 4,
            Self::Bit251AndBit196AndBit192 => 8,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Self::PartialSumX | Self::PartialSumY | Self::Suffix | Self::Slope => offset,
            Self::Bit251AndBit196AndBit192 | Self::Bit251AndBit196 => {
                (PEDERSEN_BUILTIN_RATIO * CYCLE_HEIGHT) as isize * offset + *self as isize
            }
        };
        AlgebraicItem::Trace(column, trace_offset).into()
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

    PedersenInput0Addr = 6,
    PedersenInput0Val = 7,

    // 262 % 16 = 6
    // 263 % 16 = 7
    PedersenInput1Addr = 262,
    PedersenInput1Val = 263,

    // 134 % 16 = 6
    // 135 % 16 = 7
    PedersenOutputAddr = 134,
    PedersenOutputVal = 135,

    // 70 % 16 = 6
    // 71 % 16 = 7
    RangeCheck128Addr = 70,
    RangeCheck128Val = 71,

    // 390 % 16 = 6
    // 391 % 16 = 7
    EcdsaPubkeyAddr = 390,
    EcdsaPubkeyVal = 391,

    // 16774 % 16 = 6
    // 16775 % 16 = 7
    EcdsaMessageAddr = 16774,
    EcdsaMessageVal = 16775,

    // 198 % 16 = 6
    // 199 % 16 = 7
    BitwisePoolAddr = 198,
    BitwisePoolVal = 199,

    // 902 % 16 = 6
    // 903 % 16 = 7
    BitwiseXOrYAddr = 902,
    BitwiseXOrYVal = 903,

    // EcdsaMessageVal = todo!(),
    MemDstAddr = 8,
    MemDst = 9,
    // NOTE: cycle cells 10 and 11 is occupied by PubMemAddr since the public memory step is 8.
    // This means it applies twice (2, 3) then (8+2, 8+3) within a single 16 row cycle.
    MemOp1Addr = 12,
    MemOp1 = 13,
}

impl ExecutionTraceColumn for Npc {
    fn index(&self) -> usize {
        5
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
            Self::EcdsaMessageAddr
            | Self::EcdsaPubkeyAddr
            | Self::EcdsaMessageVal
            | Self::EcdsaPubkeyVal => CYCLE_HEIGHT * ECDSA_BUILTIN_RATIO,
            Self::Pc
            | Self::Instruction
            | Self::MemOp0Addr
            | Self::MemOp0
            | Self::MemDstAddr
            | Self::MemDst
            | Self::MemOp1Addr
            | Self::MemOp1 => CYCLE_HEIGHT,
            Self::BitwisePoolAddr | Self::BitwisePoolVal => BITWISE_RATIO * CYCLE_HEIGHT / 4,
            Self::BitwiseXOrYAddr | Self::BitwiseXOrYVal => BITWISE_RATIO * CYCLE_HEIGHT,
        } as isize;
        let column = self.index();
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
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

    fn offset<T>(&self, mem_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = MEMORY_STEP as isize * mem_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum DilutedCheck {
    Unordered = 1,
    Ordered = 5,
    Aggregate = 3,
}

impl ExecutionTraceColumn for DilutedCheck {
    fn index(&self) -> usize {
        match self {
            Self::Unordered | Self::Ordered => 7,
            Self::Aggregate => 9,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        AlgebraicItem::Trace(column, 8 * offset + *self as isize).into()
    }
}

// Trace column 7
#[derive(Clone, Copy)]
pub enum RangeCheck {
    OffDst = 0,
    Ordered = 2, // Stores ordered values for the range check
    Ap = 3,      // Allocation pointer (ap)
    // TODO 2
    OffOp1 = 4,
    // Ordered = 6 - trace step is 4
    Op0MulOp1 = 7, // =op0*op1
    OffOp0 = 8,
    // Ordered = 10 - trace step is 4
    Fp = 11, // Frame pointer (fp)
    // This cell alternates cycle to cycle between:
    // - Being used for the 128 bit range checks builtin - even cycles
    // - Filled with padding to fill any gaps - odd cycles
    Unused = 12,
    // Ordered = 14 - trace step is 4
    Res = 15,
}

impl ExecutionTraceColumn for RangeCheck {
    fn index(&self) -> usize {
        7
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
    Tmp0 = 0,
    Tmp1 = 8,
}

impl ExecutionTraceColumn for Auxiliary {
    fn index(&self) -> usize {
        8
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::Tmp0 | Self::Tmp1 => CYCLE_HEIGHT,
        } as isize;
        let trace_offset = step * cycle_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// Trace column 6 - permutations
#[derive(Clone, Copy)]
pub enum Permutation {
    // TODO = 0,
    Memory = 0,
    RangeCheck = 1,
    DilutedCheck = 7,
}

impl ExecutionTraceColumn for Permutation {
    fn index(&self) -> usize {
        9
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Self::Memory => MEMORY_STEP as isize * offset + *self as isize,
            Self::RangeCheck => 4 * offset + *self as isize,
            Self::DilutedCheck => 8 * offset + *self as isize,
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
    MemoryProduct, // TODO
    RangeCheckProduct,
    RangeCheckMin,
    RangeCheckMax,
    DilutedCheckProduct,
    DilutedCheckFirst,
    DilutedCheckCumulativeValue,
    InitialPedersenAddr,
    InitialRcAddr,
    InitialEcdsaAddr,
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
/// (z − TODO1)
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
/// (z − TODO1)
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

    fn eval(&self, x: Expr<AlgebraicItem<T>>) -> Expr<AlgebraicItem<T>> {
        let mut res = Expr::Leaf(AlgebraicItem::Constant(T::zero()));
        let mut acc = Expr::from(AlgebraicItem::Constant(T::one()));
        for coeff in &self.0 {
            res += &acc * AlgebraicItem::Constant(coeff.clone());
            acc *= &x;
        }
        res
    }
}
