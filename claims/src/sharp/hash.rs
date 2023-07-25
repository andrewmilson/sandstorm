use ministark::hash::HashFn;

/// Hash function used by StarkWare's Solidity verifier
pub struct Keccak256HashFn;

impl HashFn for Keccak256HashFn {}

pub struct MaskedKeccak256HashFn<const MASK: [u8; 32]>;

impl<const MASK: [u8; 32]> HashFn for MaskedKeccak256HashFn<MASK> {}
