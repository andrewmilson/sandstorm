use ministark::{Matrix, Column};
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

#[derive(Clone, Copy)]
pub enum Flag {
    // dst reg
    DstReg,

    // op0 reg
    Op0Reg,

    // op1_src
    Op1Imm,
    Op1Fp,
    Op1Ap,

    // res_logic
    ResAdd,
    ResMul,

    // pc_update
    PcJumpAbs,
    PcJumpRel,
    PcJnz,

    // ap_update
    ApAdd,
    ApAdd1,

    // opcode
    OpcodeCall,
    OpcodeRet,
    OpcodeAssertEq,

    // 0 - to make flag cells a power-of-2
    _Unused,
}

impl Column for Flag {
    fn index(&self) -> usize {
        *self as usize
    }
}

// enum Offset {
//     Dst, // TODO:
//     Op0, // TODO:
//     Op1, // TODO:
// }
