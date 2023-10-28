use std::fmt::Display;
use std::ops::Deref;
use std::iter::Iterator;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use builtins::poseidon::poseidon_hash_many;
use digest::HashMarker;
use ministark::hash::Digest;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct PoseidonDigest(pub Fp);

impl HashMarker for PoseidonDigest {}

impl Display for PoseidonDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Digest for PoseidonDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let num = U256::from(BigUint::from(self.0));
        num.to_be_bytes::<32>()
    }
}

impl Deref for PoseidonDigest {
    type Target = Fp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Fp> for PoseidonDigest {
    fn from(value: Fp) -> Self {
        PoseidonDigest(value)
    }
}

pub struct PoseidonHashFn;

impl HashFn for PoseidonHashFn {
    type Digest = PoseidonDigest;
    const COLLISION_RESISTANCE: u32 = 125;

    fn hash(_bytes: impl IntoIterator<Item = u8>) -> PoseidonDigest {
        unreachable!()
    }

    fn hash_chunks<'a>(_chunks: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        unreachable!()
    }

    fn merge(v0: &PoseidonDigest, v1: &PoseidonDigest) -> PoseidonDigest {
        PoseidonDigest(poseidon_hash_many([**v0, **v1].to_vec()))
    }

    fn merge_with_int(seed: &PoseidonDigest, value: u64) -> PoseidonDigest {
        PoseidonDigest(poseidon_hash_many([**seed, value.into()].to_vec()))
    }
}

impl ElementHashFn<Fp> for PoseidonHashFn {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> PoseidonDigest {
        PoseidonDigest(poseidon_hash_many(elements.into_iter().collect()))
    }
}
