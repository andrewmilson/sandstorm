use crate::hash::blake2s::Blake2sHashFn;
use crate::hash::poseidon::{PoseidonDigest, PoseidonHashFn};
use crate::merkle::mixed::MixedMerkleDigest;
use crate::utils::from_montgomery;
use crate::utils::to_montgomery;
use blake2::Blake2s256;
use builtins::poseidon::poseidon_hash_many;
use digest::generic_array::{GenericArray, typenum::U32};
use ministark::hash::Digest;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::random::PublicCoin;
use ministark::random::leading_zeros;
use ministark::utils::SerdeOutput;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ruint::uint;
use ark_ff::PrimeField;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Public coin based off of StarkWare's cairo verifier
pub struct CairoVerifierPublicCoin {
    digest: SerdeOutput<Blake2s256>,
    counter: usize,
}

impl Debug for CairoVerifierPublicCoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicCoinImpl")
            .field("digest", &self.digest)
            .field("counter", &self.counter)
            .finish()
    }
}

impl CairoVerifierPublicCoin {
    fn reseed_with_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        let mut digest = (U256::try_from_be_slice(&self.digest).unwrap() + uint!(1_U256))
            .to_be_bytes::<32>()
            .to_vec();
        digest.extend(bytes.as_ref().iter());
        let result: GenericArray<u8, U32> = GenericArray::from_iter(
            poseidon_hash_many(digest.iter().map(|x| Fp::from(x.to_owned())).collect())
                .0
                 .0
                .iter()
                .map(|x| x.to_be_bytes())
                .flatten(),
        );
        self.digest = SerdeOutput::new(result);
        self.counter = 0;
    }

    fn draw_bytes(&mut self) -> [u8; 32] {
        let mut digest = U256::try_from_be_slice(&self.digest)
            .unwrap()
            .to_be_bytes::<32>()
            .to_vec();
        digest.extend(U256::from(self.counter).to_be_bytes::<32>().iter());
        let result = poseidon_hash_many(digest.iter().map(|x| Fp::from(x.to_owned())).collect());
        let mut bytes = [0u8; 32];
        for (index, value) in result.0 .0.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        self.counter += 1;
        bytes
    }
}

impl PublicCoin for CairoVerifierPublicCoin {
    type Digest = MixedMerkleDigest<PoseidonDigest, SerdeOutput<Blake2s256>>;
    type Field = Fp;

    fn new(digest: Self::Digest) -> Self {
        if let MixedMerkleDigest::LowLevel(digest) = digest {
            Self { digest, counter: 0 }
        } else {
            unreachable!()
        }
    }

    fn reseed_with_digest(&mut self, val: &Self::Digest) {
        self.reseed_with_bytes(val.as_bytes());
    }

    fn reseed_with_field_elements(&mut self, vals: &[Self::Field]) {
        let hash_felt = PoseidonHashFn::hash_elements(vals.iter().copied());
        let bytes = U256::from(BigUint::from(*hash_felt)).to_be_bytes::<32>();
        self.reseed_with_bytes(bytes);
    }

    fn reseed_with_field_element_vector(&mut self, vector: &[Self::Field]) {
        let mut bytes = Vec::new();
        for val in vector {
            let val = to_montgomery(*val);
            let val_bytes = val.to_be_bytes::<32>();
            bytes.extend_from_slice(&val_bytes)
        }
        self.reseed_with_bytes(bytes);
    }

    fn reseed_with_int(&mut self, val: u64) {
        let bytes = val.to_be_bytes();
        self.reseed_with_bytes(bytes);
    }

    fn draw(&mut self) -> Fp {
        const MODULUS: U256 = U256::from_limbs(Fp::MODULUS.0);
        let bound = MODULUS * uint!(31_U256);
        loop {
            let field_element = U256::from_be_bytes::<32>(self.draw_bytes());
            if field_element < bound {
                return from_montgomery(field_element);
            }
        }
    }

    fn draw_queries(&mut self, max_n: usize, domain_size: usize) -> BTreeSet<usize> {
        let mut bytes = iter::from_fn(|| Some(self.draw_bytes())).flatten();
        let ints = iter::from_fn(|| {
            Some(u64::from_be_bytes([
                bytes.next()?,
                bytes.next()?,
                bytes.next()?,
                bytes.next()?,
                bytes.next()?,
                bytes.next()?,
                bytes.next()?,
                bytes.next()?,
            ]))
        });

        let domain_size = domain_size as u64;
        // NOTE: the cairo verifier samples batches of 4 queries at once
        let mut res = ints
            .take(max_n.next_multiple_of(4))
            .map(|v| (v % domain_size).try_into().unwrap())
            .collect::<Vec<usize>>();
        res.truncate(max_n);
        res.into_iter().collect()
    }

    fn grind_proof_of_work(&self, proof_of_work_bits: u8) -> Option<u64> {
        let mut data = 0x0123456789ABCDEDu64.to_be_bytes().to_vec();
        data.extend(
            U256::try_from_be_slice(&self.digest)
                .unwrap()
                .to_be_bytes::<32>()
                .to_vec(),
        );
        data.extend(vec![proof_of_work_bits]);
        let prefix_hash = poseidon_hash_many(data.iter().map(|x| Fp::from(x.to_owned())).collect());

        let is_valid = |nonce: &u64| {
            let mut proof_of_work_data = vec![Fp::from(prefix_hash.0)];
            proof_of_work_data.extend(
                nonce
                    .to_owned()
                    .to_be_bytes()
                    .iter()
                    .map(|x| Fp::from(x.to_owned()))
                    .collect::<Vec<Fp>>(),
            );
            let proof_of_work_hash = poseidon_hash_many(proof_of_work_data);
            let mut bytes = [0u8; 32];
            for (index, value) in proof_of_work_hash.0 .0.iter().enumerate() {
                bytes[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
            }
            leading_zeros(&bytes) >= u32::from(proof_of_work_bits)
        };

        #[cfg(not(feature = "parallel"))]
        return (1..u64::MAX).find(is_valid);
        #[cfg(feature = "parallel")]
        return (1..u64::MAX).into_par_iter().find_any(is_valid);
    }

    fn verify_proof_of_work(&self, proof_of_work_bits: u8, nonce: u64) -> bool {
        let mut data = 0x0123456789ABCDEDu64.to_be_bytes().to_vec();
        data.extend(
            U256::try_from_be_slice(&self.digest)
                .unwrap()
                .to_be_bytes::<32>()
                .to_vec(),
        );
        data.extend(vec![proof_of_work_bits]);

        let prefix_hash = poseidon_hash_many(
            data.iter()
                .map(|x| Fp::from(x.to_owned()))
                .collect::<Vec<Fp>>(),
        );

        let mut proof_of_work_data = vec![Fp::from(prefix_hash.0)];
        proof_of_work_data.extend(
            nonce
                .to_owned()
                .to_be_bytes()
                .iter()
                .map(|x| Fp::from(x.to_owned()))
                .collect::<Vec<Fp>>(),
        );
        let proof_of_work_hash = poseidon_hash_many(proof_of_work_data);

        let mut bytes = [0u8; 32];
        for (index, value) in proof_of_work_hash.0 .0.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        leading_zeros(&bytes) >= u32::from(proof_of_work_bits)
    }

    fn security_level_bits() -> u32 {
        Blake2sHashFn::COLLISION_RESISTANCE
    }
}

#[cfg(test)]
mod tests {
    use super::CairoVerifierPublicCoin;
    use ark_ff::MontFp as Fp;
    use blake2::Blake2s256;
    use crate::merkle::mixed::MixedMerkleDigest;
    use digest::Output;
    use ministark::random::PublicCoin;
    use ministark::utils::SerdeOutput;
    use num_bigint::BigUint;
    use ruint::aliases::U256;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;

    #[test]
    fn reseed_with_field_element() {
        let seed = SerdeOutput::new(Output::<Blake2s256>::from_iter([
            0x1f, 0x9c, 0x7b, 0xc9, 0xad, 0x41, 0xb8, 0xa6, 0x92, 0x36, 0x00, 0x6e, 0x7e, 0xea,
            0x80, 0x38, 0xae, 0xa4, 0x32, 0x96, 0x07, 0x41, 0xb8, 0x19, 0x79, 0x16, 0x36, 0xf8,
            0x2c, 0xc2, 0xd2, 0x5d,
        ]));
        let mut public_coin = CairoVerifierPublicCoin::new(MixedMerkleDigest::LowLevel(seed));

        let element: Fp = Fp!("941210603170996043151108091873286171552595656949");
        let element_bytes = U256::from(BigUint::from(element));
        public_coin.reseed_with_bytes(element_bytes.to_be_bytes::<32>());

        let expected_digest = [
            0x60, 0x57, 0x79, 0xf6, 0xc9, 0xae, 0x87, 0x1e, 0xd7, 0x30, 0x56, 0xb4, 0xeb, 0xaa,
            0x61, 0xa7, 0x7e, 0x7f, 0xb5, 0x09, 0xbc, 0x08, 0xc1, 0x93, 0xf1, 0x3a, 0xdc, 0xbf,
            0x0c, 0x0b, 0xed, 0xc0,
        ];
        assert_eq!(expected_digest, **public_coin.digest);
    }
}
