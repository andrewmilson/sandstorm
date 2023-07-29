use std::fmt::Display;
use std::ops::Deref;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use blake2::Blake2s256;
use builtins::pedersen::pedersen_hash;
use ministark::hash::Digest;
use ministark::hash::ElementHashFn;
use digest::Digest as _;
use ark_ff::Field;
use ministark::hash::HashFn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ministark::utils::SerdeOutput;
use num_bigint::BigUint;
use ruint::aliases::U256;
use super::utils::mask_most_significant_bytes;
use super::utils::to_montgomery;

pub enum CairoVerifierDigest {
    Blake2s(SerdeOutput<Blake2s256>),
    Pedersen(PedersenDigest),
}

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
            hasher.update(U256::from(to_montgomery(element)).to_be_bytes::<32>());
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct PedersenDigest(Fp);

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

#[cfg(test)]
mod tests {
    use ark_ff::MontFp as Fp;
    use digest::Digest;
    use blake2::Blake2s256;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
    use crate::sharp_to_cairo::utils::hash_elements;

    #[test]
    fn blake2s_matches_cairo_verifier() {
        // Dummy test tested with the cairo code
        // ```
        // let (data: felt*) = alloc();
        // let data_start = data;
        // with data {
        //     blake2s_add_felt(num=17, bigend=1);
        //     blake2s_add_felt(num=32758, bigend=1);
        //     blake2s_add_felt(num=32793, bigend=1);
        //     blake2s_add_felt(num=8319381555716711796, bigend=1);
        // }
        // let n_bytes = (data - data_start) * 4;
        // let (res) = blake2s_bigend(data=data_start, n_bytes=n_bytes);
        // ```
        let log_n_steps: Fp = Fp!("17");
        let rc_min = Fp!("32758");
        let rc_max = Fp!("32793");
        let layout_code = Fp!("8319381555716711796");

        let mut hasher = Blake2s256::new();
        hash_elements(&mut hasher, &[log_n_steps, rc_min, rc_max, layout_code]);
        let hash = hasher.finalize();

        let expected_hash = [
            0xb1, 0x57, 0x37, 0x3e, 0xd1, 0xa5, 0xf6, 0xa8, 0x8f, 0x14, 0xf8, 0x82, 0x67, 0x8a,
            0xc5, 0x8d, 0xa0, 0x92, 0x5b, 0x88, 0xc5, 0x6e, 0xb2, 0x5b, 0xcc, 0xde, 0x4c, 0x9a,
            0x17, 0x96, 0x35, 0x5e,
        ];
        assert_eq!(expected_hash, *hash);
    }
}
