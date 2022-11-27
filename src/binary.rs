use crate::Flag;
use crate::FlagGroup;
use cairo_rs::vm::trace::trace_entry::RelocatedTraceEntry as RegisterState;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io::BufRead;
use ark_ff::PrimeField;
use std::io::BufReader;
use std::ops::Deref;
use std::path::PathBuf;

// https://eprint.iacr.org/2021/1063.pdf figure 3
/// Word offset of `off_DST`
pub const OFF_DST_BIT_OFFSET: usize = 0;
/// Word offset of `off_OP0`
pub const OFF_OP0_BIT_OFFSET: usize = 16;
/// Word offset of `off_OP1`
pub const OFF_OP1_BIT_OFFSET: usize = 32;
/// Word offset of instruction flags
pub const FLAGS_BIT_OFFSET: usize = 48;

/// Number of Cairo instruction flags
pub const NUM_FLAGS: usize = 16;

pub struct RegisterStates(Vec<RegisterState>);

impl RegisterStates {
    /// Parses the trace file outputted by a Cairo runner.
    pub fn from_file(trace_path: &PathBuf) -> Self {
        let trace_file = File::open(trace_path).expect("could not open trace file");
        let mut reader = BufReader::new(trace_file);
        let mut register_states = Vec::new();
        while reader.has_data_left().unwrap() {
            let entry: RegisterState = bincode::deserialize_from(&mut reader).unwrap();
            register_states.push(entry);
        }
        RegisterStates(register_states)
    }
}

impl Deref for RegisterStates {
    type Target = Vec<RegisterState>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Memory(Vec<Option<Word>>);

impl Memory {
    /// Parses the partial memory file outputted by a Cairo runner.
    pub fn from_file(memory_path: &PathBuf) -> Self {
        // TODO: each builtin has its own memory segment.
        // check it also contains other builtins
        // this file contains the contiguous memory segments:
        // - program
        // - execution
        // - builtin 0
        // - builtin 1
        // - ...
        let memory_file = File::open(memory_path).expect("could not open memory file");
        let mut reader = BufReader::new(memory_file);
        let mut partial_memory = Vec::new();
        let mut max_address = 0;
        while reader.has_data_left().unwrap() {
            // TODO: ensure always deserializes u64 and both are always little-endian
            let address = bincode::deserialize_from(&mut reader).unwrap();
            // TODO: U256 bincode has memory overallocation bug
            let word_bytes: [u8; 32] = bincode::deserialize_from(&mut reader).unwrap();
            let word = U256::from_le_bytes(word_bytes);
            partial_memory.push((address, Word::new(word)));
            max_address = std::cmp::max(max_address, address);
        }

        // TODO: DOC: None used for nondeterministic values?
        let mut memory = vec![None; max_address + 1];
        for (address, word) in partial_memory {
            // TODO: once arkworks v4 release remove num_bigint
            memory[address] = Some(word);
        }

        Memory(memory)
    }
}

impl Deref for Memory {
    type Target = Vec<Option<Word>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
pub struct CompiledProgram {
    data: Vec<String>,
    prime: String,
}

impl CompiledProgram {
    pub fn validate(&self) {
        // Make sure the field modulus matches the expected
        assert_eq!(
            format!("{:#x}", BigUint::from(Fp::MODULUS)),
            self.prime.to_lowercase(),
        );
    }
}

/// Represents a Cairo word
/// Value is a field element in the range `[0, Fp::MODULUS)`
/// Stored as a U256 to make binary decompositions more efficient
#[derive(Clone, Copy, Debug)]
pub struct Word(U256);

impl Word {
    pub fn new(word: U256) -> Self {
        debug_assert!(BigUint::from(word) < BigUint::from(Fp::MODULUS));
        Word(word)
    }

    /// Calculates $\tilde{f_i}$ - https://eprint.iacr.org/2021/1063.pdf
    pub fn get_flag_prefix(&self, flag: Flag) -> u64 {
        if matches!(flag, Flag::_Unused) {
            return 0;
        }

        let flag = flag as usize;
        let prefix = self.0 >> (FLAGS_BIT_OFFSET + flag);
        let mask = (uint!(1_U256) << (14 - flag)) - uint!(1_U256);
        (prefix & mask).try_into().unwrap()
    }

    pub fn get_flag(&self, flag: Flag) -> bool {
        self.0.bit(FLAGS_BIT_OFFSET + flag as usize)
    }

    pub fn get_flag_group(&self, flag_group: FlagGroup) -> u8 {
        match flag_group {
            FlagGroup::DstReg => self.get_flag(Flag::DstReg) as u8,
            FlagGroup::Op0Reg => self.get_flag(Flag::Op0Reg) as u8,
            FlagGroup::Op1Src => {
                self.get_flag(Flag::Op1Imm) as u8
                    + self.get_flag(Flag::Op1Fp) as u8 * 2
                    + self.get_flag(Flag::Op1Ap) as u8 * 4
            }
            FlagGroup::ResLogic => {
                self.get_flag(Flag::ResAdd) as u8 + self.get_flag(Flag::ResMul) as u8 * 2
            }
            FlagGroup::PcUpdate => {
                self.get_flag(Flag::PcJumpAbs) as u8
                    + self.get_flag(Flag::PcJumpRel) as u8 * 2
                    + self.get_flag(Flag::PcJnz) as u8 * 4
            }
            FlagGroup::ApUpdate => {
                self.get_flag(Flag::ApAdd) as u8 + self.get_flag(Flag::ApAdd1) as u8 * 2
            }
            FlagGroup::Opcode => {
                self.get_flag(Flag::OpcodeCall) as u8
                    + self.get_flag(Flag::OpcodeRet) as u8 * 2
                    + self.get_flag(Flag::OpcodeAssertEq) as u8 * 4
            }
        }
    }
}
