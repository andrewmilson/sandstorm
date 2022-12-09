use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use gpu_poly::GpuField;
use ministark::ProofOptions;
use ministark::TraceInfo;
use ark_ff::One;
use ark_ff::Field;
use ministark::constraints::AlgebraicExpression;
use ark_poly::domain::EvaluationDomain;
use ministark::Air;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use ministark::constraints::FieldConstant;
use num_bigint::BigUint;

use crate::Flag;
use crate::binary::NUM_FLAGS;

pub struct CairoAir {
    info: TraceInfo,
    options: ProofOptions,
    inputs: ExecutionInfo,
}

// Section 9.2 https://eprint.iacr.org/2021/1063.pdf
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct ExecutionInfo();
// pub struct ExecutionInfo {
//     pub partial_mem: Vec<Fp>,
//     // TODO
// }

impl Air for CairoAir {
    type Fp = Fp;
    type Fq = Fp;
    type PublicInputs = ExecutionInfo;

    fn new(info: TraceInfo, inputs: ExecutionInfo, options: ministark::ProofOptions) -> Self {
        CairoAir {
            info,
            options,
            inputs,
        }
    }

    fn pub_inputs(&self) -> &Self::PublicInputs {
        &self.inputs
    }

    fn trace_info(&self) -> &ministark::TraceInfo {
        &self.info
    }

    fn options(&self) -> &ministark::ProofOptions {
        &self.options
    }

    // column ideas:
    // =============
    // col0 - flags
    // col3 - pedersen
    // col5 - npc? next program counter?
    // col6 - memory
    // col7 - rc16 (range check 16 bit?)
    // col8 - ecdsa

    fn constraints(&self) -> Vec<AlgebraicExpression<Fp>> {
        use AlgebraicExpression::*;
        // TODO: figure out why this value
        let cycle_height = 16;
        let trace_domain = self.trace_domain();
        let g = trace_domain.group_gen();
        let n = trace_domain.size();
        let one = Constant(FieldConstant::Fp(Fp::one()));
        let two = Constant(FieldConstant::<Fp>::Fp(Fp::from(2u32)));
        let offset_size = two.pow(16);
        let half_offset_size = two.pow(15);

        let cpu_decode_opcode_rc_b0 = Trace(0, 0) - (Trace(0, 1) + Trace(0, 1));
        let cpu_decode_opcode_rc_b1: AlgebraicExpression<Fp> =
            Trace(0, 1) - (Trace(0, 2) + Trace(0, 2));
        let cpu_decode_opcode_rc_b2 = Trace(0, 2) - (Trace(0, 3) + Trace(0, 3));
        let cpu_decode_opcode_rc_b3 = Trace(0, 3) - (Trace(0, 4) + Trace(0, 4));
        let cpu_decode_opcode_rc_b4 = Trace(0, 4) - (Trace(0, 5) + Trace(0, 5));
        let cpu_decode_opcode_rc_b5 = Trace(0, 5) - (Trace(0, 6) + Trace(0, 6));
        let cpu_decode_opcode_rc_b6 = Trace(0, 6) - (Trace(0, 7) + Trace(0, 7));
        let cpu_decode_opcode_rc_b7 = Trace(0, 7) - (Trace(0, 8) + Trace(0, 8));
        let cpu_decode_opcode_rc_b8 = Trace(0, 8) - (Trace(0, 9) + Trace(0, 9));
        let cpu_decode_opcode_rc_b9 = Trace(0, 9) - (Trace(0, 10) + Trace(0, 10));
        let cpu_decode_opcode_rc_b10: AlgebraicExpression<Fp> =
            Trace(0, 10) - (Trace(0, 11) + Trace(0, 11));
        let cpu_decode_opcode_rc_b11: AlgebraicExpression<Fp> =
            Trace(0, 11) - (Trace(0, 12) + Trace(0, 12));
        let cpu_decode_opcode_rc_b12 = Trace(0, 12) - (Trace(0, 13) + Trace(0, 13));
        let cpu_decode_opcode_rc_b13 = Trace(0, 13) - (Trace(0, 14) + Trace(0, 14));
        let cpu_decode_opcode_rc_b14: AlgebraicExpression<Fp> =
            Trace(0, 14) - (Trace(0, 15) + Trace(0, 15));

        // cpu/decode/flag_op1_base_op0_0
        let cpu_decode_flag_op1_base_op0_0: AlgebraicExpression<Fp> =
            &one - (&cpu_decode_opcode_rc_b2 + &cpu_decode_opcode_rc_b4 + &cpu_decode_opcode_rc_b3);
        // cpu/decode/flag_res_op1_0
        let cpu_decode_flag_res_op1_0: AlgebraicExpression<Fp> =
            &one - (&cpu_decode_opcode_rc_b5 + &cpu_decode_opcode_rc_b6 + &cpu_decode_opcode_rc_b9);
        // cpu/decode/flag_pc_update_regular_0
        let cpu_decode_flag_pc_update_regular_0: AlgebraicExpression<Fp> =
            &one - (&cpu_decode_opcode_rc_b7 + &cpu_decode_opcode_rc_b8 + &cpu_decode_opcode_rc_b9);
        // cpu/decode/fp_update_regular_0
        let cpu_decode_fp_update_regular_0: AlgebraicExpression<Fp> =
            &one - (&cpu_decode_opcode_rc_b12 + &cpu_decode_opcode_rc_b13);

        // pc + <instruction size>
        let npc_reg_0 = Trace(5, 0) + &cpu_decode_opcode_rc_b2 + &one;

        let memory_address_diff_0: AlgebraicExpression<Fp> = Trace(6, 2) - Trace(6, 0);

        let rc16_diff_0: AlgebraicExpression<Fp> = Trace(7, 6) - Trace(7, 2);

        let pedersen_hash0_ec_subset_sub_b0 = Trace(3, 0) - (Trace(3, 1) + Trace(3, 1));
        let pedersen_hash0_ec_subset_sum_b0_neg = &one - &pedersen_hash0_ec_subset_sub_b0;

        let rc_builtin_value0_0 = Trace(7, 12);
        let rc_builtin_value1_0 = &rc_builtin_value0_0 * &offset_size + Trace(7, 44);
        let rc_builtin_value2_0 = &rc_builtin_value1_0 * &offset_size + Trace(7, 76);
        let rc_builtin_value3_0 = &rc_builtin_value2_0 * &offset_size + Trace(7, 108);
        let rc_builtin_value4_0 = &rc_builtin_value3_0 * &offset_size + Trace(7, 140);
        let rc_builtin_value5_0 = &rc_builtin_value4_0 * &offset_size + Trace(7, 172);
        let rc_builtin_value6_0 = &rc_builtin_value5_0 * &offset_size + Trace(7, 204);
        let rc_builtin_value7_0 = &rc_builtin_value6_0 * &offset_size + Trace(7, 236);

        let ecdsa_sig0_doubling_key_x_squared: AlgebraicExpression<Fp> = Trace(8, 4) * Trace(8, 4);
        let ecdsa_sig0_exponentiate_generator_b0 = Trace(8, 34) - (Trace(8, 162) + Trace(8, 162));
        let ecdsa_sig0_exponentiate_generator_b0_neg = &one - ecdsa_sig0_exponentiate_generator_b0;
        let ecdsa_sig0_exponentiate_key_b0 = Trace(8, 12) - (Trace(8, 76) + Trace(8, 76));
        let ecdsa_sig0_exponentiate_key_b0_neg = &one - &ecdsa_sig0_exponentiate_key_b0;

        let bitwise_sum_var_0_0: AlgebraicExpression<Fp> = Trace(7, 1)
            + Trace(7, 17) * two.pow(1)
            + Trace(7, 33) * two.pow(2)
            + Trace(7, 49) * two.pow(3)
            + Trace(7, 65) * two.pow(64)
            + Trace(7, 81) * two.pow(65)
            + Trace(7, 97) * two.pow(66)
            + Trace(7, 113) * two.pow(67);

        let bitwise_sum_var_8_0: AlgebraicExpression<Fp> = Trace(7, 129) * two.pow(129)
            + Trace(7, 145) * two.pow(130)
            + Trace(7, 161) * two.pow(131)
            + Trace(7, 177) * two.pow(132)
            + Trace(7, 193) * two.pow(193)
            + Trace(7, 209) * two.pow(194)
            + Trace(7, 255) * two.pow(195)
            + Trace(7, 241) * two.pow(196);

        // helpful example for trace length n=64
        // =====================================
        // x^(n/16)                 = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // x^(n/16) - c             = (x - c*ω_0)(x - c*ω_16)(x - c*ω_32)(x - c*ω_48)
        // x^(n/16) - ω^(n/16)      = (x - ω_1)(x - ω_17)(x - ω_33)(x - ω_49)
        // x^(n/16) - ω^(n/16)^(15) = (x - ω_15)(x - ω_31)(x - ω_47)(x - ω_63)
        let flag0_offset =
            FieldConstant::Fp(g.pow([(Flag::Zero as usize * n / cycle_height) as u64]));
        let flag0_zerofier = X.pow(n / cycle_height) - flag0_offset;
        let flags_zerofier = &flag0_zerofier / (X.pow(n) - &one);

        // checks bits are 0 or 1
        // NOTE: can choose any cpu_decode_opcode_rc_b*
        let cpu_decode_opcode_rc_b = (&cpu_decode_opcode_rc_b0 * &cpu_decode_opcode_rc_b0
            - &cpu_decode_opcode_rc_b0)
            * &flags_zerofier;

        let cpu_decode_opcode_rc_zero = Trace(0, 0) / flag0_zerofier;

        // TODO: Trace(5, 1) First word of each instruction?
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
        let flags = Trace(0, 0);
        // TODO: let off_op1 = Trace(7, 4);
        // TODO: let off_op0 = Trace(7, 8);
        // TODO: let off_dst = Trace(7, 0);

        // force constraint to apply every 16 trace cycles (aka 1 cairo cycle)
        // e.g. (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48) for n=64
        let all_cycle_zerofier = X.pow(n / cycle_height) - &one;
        let cpu_decode_opcode_rc_input = (Trace(5, 1)
            - (((flags * &offset_size + Trace(7, 4)) * &offset_size + Trace(7, 8)) * &offset_size
                + Trace(7, 0)))
            / &all_cycle_zerofier;

        // TODO: constraint for the Op1Src flag group? forces vals 000, 100, 010 or 001
        let cpu_decode_flag_op1_base_op0_bit = (&cpu_decode_flag_op1_base_op0_0
            * &cpu_decode_flag_op1_base_op0_0
            - &cpu_decode_flag_op1_base_op0_0)
            / &all_cycle_zerofier;

        // TODO: forces only one or none of ResAdd, ResMul or PcJnz to be 1
        // TODO: Why the F is PcJnz in here? Res flag group is only bit 5 and 6
        let cpu_decode_flag_res_op1_bit = (&cpu_decode_flag_res_op1_0 * &cpu_decode_flag_res_op1_0
            - &cpu_decode_flag_res_op1_0)
            / &all_cycle_zerofier;

        // TODO: constraint forces PcUpdate flag to be 000, 100, 010 or 001
        let cpu_decode_flag_pc_update_regular_bit = (&cpu_decode_flag_pc_update_regular_0
            * &cpu_decode_flag_pc_update_regular_0
            - &cpu_decode_flag_pc_update_regular_0)
            / &all_cycle_zerofier;

        // TODO: forces max only OpcodeRet or OpcodeAssertEq to be 1
        // TODO: I guess returning and asserting are related to fp?
        // TODO: why OpcodeCall not included? that would make whole flag group
        let cpu_decode_fp_update_regular_bit = (&cpu_decode_fp_update_regular_0
            * &cpu_decode_fp_update_regular_0
            - &cpu_decode_fp_update_regular_0)
            / &all_cycle_zerofier;

        // cpu/operands/mem_dst_addr
        // NOTE: Pseudo code from cairo whitepaper
        // ```
        // if dst_reg == 0:
        //   dst = m(ap + offdst)
        // else:
        //   dst = m(fp + offdst)
        // ```
        // NOTE: Trace(5, 8) dest mem address
        let cpu_operands_mem_dst_addr = (Trace(5, 8) + &half_offset_size
            - (&cpu_decode_opcode_rc_b0 * Trace(7, 11)
                + (&one - &cpu_decode_opcode_rc_b0) * Trace(7, 3)
                + Trace(7, 0)))
            / &all_cycle_zerofier;

        // whitepaper pseudocode
        // ```
        // # Compute op0.
        // if op0_reg == 0:
        // op0 = m(ap + offop0)
        // else:
        // op0 = m(fp + offop0)
        // ```
        // NOTE: StarkEx contracts as: cpu_operands_mem0_addr
        let cpu_operands_mem_op0_addr = (Trace(5, 4) + &half_offset_size
            - (&cpu_decode_opcode_rc_b1 * Trace(7, 11)
                + (&one - &cpu_decode_opcode_rc_b1) * Trace(7, 3)
                + Trace(7, 8)))
            / &all_cycle_zerofier;

        // NOTE: StarkEx contracts as: cpu_operands_mem1_addr
        let cpu_operands_mem_op1_addr = (Trace(5, 12) + &half_offset_size
            - (&cpu_decode_opcode_rc_b2 * Trace(5, 0)
                + &cpu_decode_opcode_rc_b4 * Trace(7, 3)
                + &cpu_decode_opcode_rc_b3 * Trace(7, 11)
                + &cpu_decode_flag_op1_base_op0_0 * Trace(5, 5)
                + Trace(7, 4)))
            / &all_cycle_zerofier;

        // op1 * op0
        // NOTE: starkex cpu/operands/ops_mul
        let cpu_operands_ops_mul = (Trace(7, 7) - Trace(5, 5) * Trace(5, 13)) / &all_cycle_zerofier;

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
        let cpu_operands_res = ((&one - &cpu_decode_opcode_rc_b9) * Trace(7, 15)
            - (&cpu_decode_opcode_rc_b5 * (Trace(5, 5) + Trace(5, 13))
                + &cpu_decode_opcode_rc_b6 * Trace(7, 7)
                + &cpu_decode_flag_res_op1_0 * Trace(5, 13)))
            / &all_cycle_zerofier;

        // helpful example for trace length n=64
        // =====================================
        // all_cycle_zerofier              = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // X - ω^(16*(n/16 - 1))           = x - ω^n/w^16 = x - 1/w_16 = x - w_48
        // (X - w_48) / all_cycle_zerofier = (x - ω_0)(x - ω_16)(x - ω_32)
        let last_cycle_zerofier =
            X - FieldConstant::Fp(g.pow([(cycle_height * (n / cycle_height - 1)) as u64]));
        let all_cycles_except_last_zerofier = &last_cycle_zerofier / &all_cycle_zerofier;

        // Updating the program counter
        // ============================
        // This is not as straight forward as the other constraints. Read section 9.5
        // Updating pc to understand.

        // from whitepaper `t0 = fPC_JNZ * dst`
        let cpu_update_registers_update_pc_tmp0 = (Trace(8, 0)
            - &cpu_decode_opcode_rc_b9 * Trace(5, 9))
            / &all_cycles_except_last_zerofier;

        // From the whitepaper "To verify that we make a regular update if dst = 0, we
        // need an auxiliary variable, v (to fill the trace in the case dst != 0, set v
        // = dst^(−1)): `fPC_JNZ * (dst * v − 1) * (next_pc − (pc + instruction_size)) =
        // 0` NOTE: if fPC_JNZ=1 then `res` is "unused" and repurposed as our
        // temporary variable `v`. The value assigned to v is `dst^(−1)`.
        // NOTE: `t1 = t0 * v`
        let cpu_update_registers_update_pc_tmp1 =
            (Trace(8, 8) - Trace(8, 0) * Trace(7, 15)) / &all_cycles_except_last_zerofier;

        // There are two constraints here bundled in one. The first is `t0 * (next_pc −
        // (pc + op1)) = 0` (ensures if dst != 0 a relative jump is made) and the second
        // is `(1−fPC_JNZ) * next_pc - (regular_update * (pc + instruction_size) +
        // fPC_JUMP_ABS * res + fPC_JUMP_REL * (pc + res)) = 0` (handles update except
        // for jnz). Note that due to the flag group constraints for PcUpdate if jnz=1
        // then the second constraint is trivially 0=0 and if jnz=0 then the first
        // constraint is trivially 0=0. For this reason we can bundle these constraints
        // into one.
        let cpu_update_registers_update_pc_pc_cond_negative = ((&one - &cpu_decode_opcode_rc_b9)
            * Trace(5, 16)
            + Trace(8, 0) * (Trace(5, 16) - (Trace(5, 0) + Trace(5, 13)))
            - (&cpu_decode_flag_pc_update_regular_0 * &npc_reg_0
                + &cpu_decode_opcode_rc_b7 * Trace(7, 15)
                + cpu_decode_opcode_rc_b8 * (Trace(5, 0) + Trace(7, 15))))
            / &all_cycles_except_last_zerofier;

        // ensure `if dst == 0: pc + instruction_size == next_pc`
        let cpu_update_registers_update_pc_pc_cond_positive =
            ((Trace(8, 8) - cpu_decode_opcode_rc_b9) * (Trace(5, 16) - npc_reg_0))
                / &all_cycles_except_last_zerofier;

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
        ]
    }
}
