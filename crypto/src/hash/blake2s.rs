use blake2::Blake2s256;
use ministark::hash::ElementHashFn;
use digest::Digest as _;
use ministark::hash::HashFn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ministark::utils::SerdeOutput;
use crate::utils::to_montgomery;
use super::mask_most_significant_bytes;

pub struct Blake2sHashFn;

impl HashFn for Blake2sHashFn {
    type Digest = SerdeOutput<Blake2s256>;
    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: impl IntoIterator<Item = u8>) -> SerdeOutput<Blake2s256> {
        let mut hasher = Blake2s256::new();
        for byte in bytes {
            hasher.update([byte]);
        }
        SerdeOutput::new(hasher.finalize())
    }

    fn hash_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> SerdeOutput<Blake2s256> {
        let mut hasher = Blake2s256::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        SerdeOutput::new(hasher.finalize())
    }

    fn merge(
        v0: &SerdeOutput<Blake2s256>,
        v1: &SerdeOutput<Blake2s256>,
    ) -> SerdeOutput<Blake2s256> {
        let mut hasher = Blake2s256::new();
        hasher.update(**v0);
        hasher.update(**v1);
        SerdeOutput::new(hasher.finalize())
    }

    fn merge_with_int(seed: &SerdeOutput<Blake2s256>, value: u64) -> SerdeOutput<Blake2s256> {
        let mut hasher = Blake2s256::new();
        hasher.update(**seed);
        hasher.update(value.to_be_bytes());
        SerdeOutput::new(hasher.finalize())
    }
}

impl ElementHashFn<Fp> for Blake2sHashFn {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> SerdeOutput<Blake2s256> {
        let mut hasher = Blake2s256::new();
        for element in elements {
            hasher.update(to_montgomery(element).to_be_bytes::<32>());
            // for limb in (element.0).0.into_iter().rev() {
            //     hasher.update(limb.to_be_bytes());
            // }
        }
        SerdeOutput::new(hasher.finalize())
    }
}

pub struct MaskedBlake2sHashFn<const N_UNMASKED_BYTES: u32>;

impl<const N_UNMASKED_BYTES: u32> HashFn for MaskedBlake2sHashFn<N_UNMASKED_BYTES> {
    type Digest = SerdeOutput<Blake2s256>;
    const COLLISION_RESISTANCE: u32 = N_UNMASKED_BYTES * 8 / 2;

    fn hash(bytes: impl IntoIterator<Item = u8>) -> Self::Digest {
        let mut hash = Blake2sHashFn::hash(bytes);
        mask_most_significant_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }

    fn merge(v0: &Self::Digest, v1: &Self::Digest) -> Self::Digest {
        let mut hash = Blake2sHashFn::merge(v0, v1);
        mask_most_significant_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }

    fn merge_with_int(seed: &Self::Digest, value: u64) -> Self::Digest {
        let mut hash = Blake2sHashFn::merge_with_int(seed, value);
        mask_most_significant_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }

    fn hash_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hash = Blake2sHashFn::hash_chunks(chunks);
        mask_most_significant_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }
}

impl<const N_UNMASKED_BYTES: u32> ElementHashFn<Fp> for MaskedBlake2sHashFn<N_UNMASKED_BYTES> {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> Self::Digest {
        let mut hash = Blake2sHashFn::hash_elements(elements);
        mask_most_significant_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }
}
