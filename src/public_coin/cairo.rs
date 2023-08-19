use binary::AirPublicInput;
use crypto::hash::blake2s::Blake2sHashFn;
use crypto::hash::pedersen::PedersenDigest;
use crypto::hash::pedersen::PedersenHashFn;
use crypto::merkle::mixed::MixedMerkleDigest;
use crypto::utils::from_montgomery;
use crypto::utils::to_montgomery;
use blake2::Blake2s256;
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
use digest::Digest as _;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::iter;
use crate::input::CairoAuxInput;
use super::CairoPublicCoin;

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
        let digest = U256::try_from_be_slice(&self.digest).unwrap();
        let mut hasher = Blake2s256::new();
        hasher.update((digest + uint!(1_U256)).to_be_bytes::<32>());
        hasher.update(bytes);
        self.digest = SerdeOutput::new(hasher.finalize());
        self.counter = 0;
    }

    fn draw_bytes(&mut self) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(*self.digest);
        hasher.update(U256::from(self.counter).to_be_bytes::<32>());
        self.counter += 1;
        (*hasher.finalize()).try_into().unwrap()
    }
}

impl CairoPublicCoin for CairoVerifierPublicCoin {
    fn from_public_input(public_input: &AirPublicInput<Fp>) -> Self {
        let aux_input = CairoAuxInput(public_input);
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements::<PedersenHashFn>() {
            seed.extend_from_slice(&element.to_be_bytes::<32>())
        }
        Self::new(MixedMerkleDigest::LowLevel(Blake2sHashFn::hash_chunks([
            &*seed,
        ])))
    }
}

impl PublicCoin for CairoVerifierPublicCoin {
    type Digest = MixedMerkleDigest<PedersenDigest, SerdeOutput<Blake2s256>>;
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
        let hash_felt = PedersenHashFn::hash_elements(vals.iter().copied());
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

    fn verify_proof_of_work(&self, proof_of_work_bits: u8, nonce: u64) -> bool {
        let mut prefix_hasher = Blake2s256::new();
        prefix_hasher.update(0x0123456789ABCDEDu64.to_be_bytes());
        prefix_hasher.update(*self.digest);
        prefix_hasher.update([proof_of_work_bits]);
        let prefix_hash = prefix_hasher.finalize();

        let mut proof_of_work_hasher = Blake2s256::new();
        proof_of_work_hasher.update(prefix_hash);
        proof_of_work_hasher.update(nonce.to_be_bytes());
        let proof_of_work_hash = proof_of_work_hasher.finalize();

        leading_zeros(&proof_of_work_hash) >= u32::from(proof_of_work_bits)
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
    use crypto::merkle::mixed::MixedMerkleDigest;
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
