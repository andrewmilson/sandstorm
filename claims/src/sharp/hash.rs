use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::utils::SerdeOutput;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use sha3::Keccak256;

/// Hash function used by StarkWare's Solidity verifier
pub struct Keccak256HashFn;

impl HashFn for Keccak256HashFn {
    type Digest = SerdeOutput<Keccak256>;
    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: impl IntoIterator<Item = u8>) -> Self::Digest {
        todo!()
    }

    fn merge(v0: &Self::Digest, v1: &Self::Digest) -> Self::Digest {
        todo!()
    }

    fn merge_with_int(seed: &Self::Digest, value: u64) -> Self::Digest {
        todo!()
    }
}

impl ElementHashFn<Fp> for Keccak256HashFn {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> Self::Digest {
        todo!()
    }
}

// pub struct MaskedKeccak256HashFn<const MASK: [u8; 32]>;

// impl<const MASK: [u8; 32]> HashFn for MaskedKeccak256HashFn<MASK> {}
