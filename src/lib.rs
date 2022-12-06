#![feature(buf_read_has_data_left, allocator_api)]
use strum_macros::EnumIter;

mod air;
mod binary;
pub mod prover;
pub mod trace;

/// Cairo flag
/// https://eprint.iacr.org/2021/1063.pdf section 9
#[derive(Clone, Copy, EnumIter, PartialEq, Eq)]
pub enum Flag {
    // Group: [FlagGroup::DstReg]
    DstReg,

    // Group: [FlagGroup::Op0]
    Op0Reg,

    // Group: [FlagGroup::Op1Src]
    Op1Imm,
    Op1Fp,
    Op1Ap,

    // Group: [FlagGroup::ResLogic]
    ResAdd,
    ResMul,

    // Group: [FlagGroup::PcUpdate]
    PcJumpAbs,
    PcJumpRel,
    PcJnz,

    // Group: [FlagGroup::ApUpdate]
    ApAdd,
    ApAdd1,

    // Group: [FlagGroup::Opcode]
    OpcodeCall,
    OpcodeRet,
    OpcodeAssertEq,

    // 0 - padding to make flag cells a power-of-2
    Zero,
}

/// Cairo flag group
/// https://eprint.iacr.org/2021/1063.pdf section 9.4
#[derive(Clone, Copy)]
enum FlagGroup {
    DstReg,
    Op0Reg,
    Op1Src,
    ResLogic,
    PcUpdate,
    ApUpdate,
    Opcode,
}
