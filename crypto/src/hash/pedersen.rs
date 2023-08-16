use std::fmt::Display;
use std::ops::Deref;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use builtins::pedersen::pedersen_hash;
use ministark::hash::Digest;
use ministark::hash::ElementHashFn;
use ark_ff::Field;
use ministark::hash::HashFn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct PedersenDigest(pub Fp);

impl Display for PedersenDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Digest for PedersenDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let num = U256::from(BigUint::from(self.0));
        num.to_be_bytes::<32>()
    }
}

impl Deref for PedersenDigest {
    type Target = Fp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Fp> for PedersenDigest {
    fn from(value: Fp) -> Self {
        PedersenDigest(value)
    }
}

pub struct PedersenHashFn;

impl HashFn for PedersenHashFn {
    type Digest = PedersenDigest;
    const COLLISION_RESISTANCE: u32 = 125;

    fn hash(_bytes: impl IntoIterator<Item = u8>) -> PedersenDigest {
        unreachable!()
    }

    fn hash_chunks<'a>(_chunks: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        unreachable!()
    }

    fn merge(v0: &PedersenDigest, v1: &PedersenDigest) -> PedersenDigest {
        PedersenDigest(pedersen_hash(**v0, **v1))
    }

    fn merge_with_int(seed: &PedersenDigest, value: u64) -> PedersenDigest {
        PedersenDigest(pedersen_hash(**seed, value.into()))
    }
}

impl ElementHashFn<Fp> for PedersenHashFn {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> PedersenDigest {
        let mut num_items = 0u64;
        let mut curr_hash = Fp::ZERO;
        for v in elements.into_iter() {
            curr_hash = pedersen_hash(curr_hash, v);
            num_items += 1;
        }
        PedersenDigest(pedersen_hash(curr_hash, num_items.into()))
    }
}
