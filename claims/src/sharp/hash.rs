use ministark::hash::HashFn;

/// Hash function used by StarkWare's Solidity verifier
pub struct Keccak256HashFn;

impl HashFn for Keccak256HashFn {}
