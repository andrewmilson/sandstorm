use ministark::Matrix;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use ministark::Trace;

pub struct CairoTrace {
    processor_base_trace: Matrix<Fp>,
    memory_base_trace: Matrix<Fp>,
    instruction_base_trace: Matrix<Fp>,
    input_base_trace: Matrix<Fp>,
    output_base_trace: Matrix<Fp>,
    base_trace: Matrix<Fp>,
}

impl Trace for CairoTrace {
    const NUM_BASE_COLUMNS: usize = 0;
    type Fp = Fp;
    type Fq = Fp;

    fn len(&self) -> usize {
        todo!()
    }

    fn base_columns(&self) -> &Matrix<Self::Fp> {
        todo!()
    }
}

// Cairo trace layout
// https://eprint.iacr.org/2021/1063.pdf section 9

enum Flag {
    // dst reg
    DstReg,

    // op0 reg
    Op0Reg, // Operand 0 register

    // op1_src
    Op1Imm, // Operand 1 Immediate
    Op1Fp,  // TODO: Operand 1 frame pointer?
    Op1Ap,  // TODO: Operand 1 allocation pointer?

    // res_logic
    ResAdd, // TODO: Result add?
    ResMul, // TODO: Result multiply?

    // pc_update
    PcJumpAbs, // Jump absolute
    PcJumpRel, // Jump relative
    PcJnz,     // Conditional jump (if not zero)

    // ap_update
    ApAdd,  // TODO: Allocation pointer add?
    ApAdd1, // TODO: Allocation pointer add `1`?

    // opcode
    OpcodeCall,
    OpcodeRet,
    OpcodeAssertEq,

    // 0
    _Unused, // Section 9 "pow-of-2 for technical reasons"
}

enum Offset {
    Dst, // TODO:
    Op0, // TODO:
    Op1, // TODO:
}
