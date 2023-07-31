use super::hash::Blake2sHashFn;
use super::hash::PedersenHashFn;
use super::merkle::FriendlyCommitment;
use super::utils::from_montgomery;
use super::utils::to_montgomery;
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

/// Public coin based off of StarkWare's solidity verifier
pub struct CairoPublicCoin {
    digest: SerdeOutput<Blake2s256>,
    counter: usize,
}

impl Debug for CairoPublicCoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicCoinImpl")
            .field("digest", &self.digest)
            .field("counter", &self.counter)
            .finish()
    }
}

impl CairoPublicCoin {
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

impl PublicCoin for CairoPublicCoin {
    type Digest = FriendlyCommitment;
    type Field = Fp;

    fn new(digest: FriendlyCommitment) -> Self {
        match digest {
            FriendlyCommitment::Blake(digest) => Self { digest, counter: 0 },
            FriendlyCommitment::Pedersen(_) => unreachable!(),
        }
    }

    fn reseed_with_digest(&mut self, val: &FriendlyCommitment) {
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
            let val = U256::from(to_montgomery(*val));
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
        let bound = BigUint::from(Fp::MODULUS) * 31u32;
        let mut field_element = bound.clone();
        while field_element >= bound {
            field_element = BigUint::from_bytes_be(&self.draw_bytes());
        }
        from_montgomery(field_element)
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
        ints.take(max_n.next_multiple_of(4))
            .map(|v| (v % domain_size).try_into().unwrap())
            .collect()
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
    use super::CairoPublicCoin;
    use ark_ff::MontFp as Fp;
    use blake2::Blake2s256;
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
        let mut public_coin = CairoPublicCoin::new(seed.into());

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

// #[cfg(test)]
// mod tests {
//     use super::SolidityPublicCoin;
//     use ark_ff::MontFp as Fp;
//     use ark_poly::Radix2EvaluationDomain;
//     use ark_poly::EvaluationDomain;
//     use ministark::random::PublicCoin;
//     use ministark::utils::SerdeOutput;
//     use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
//     use sha2::digest::Output;
//     use ark_ff::FftField;
//     use sha3::Keccak256;

//     #[test]
//     fn draw_matches_solidity_verifier() {
//         let pub_input_hash =
// SerdeOutput::new(Output::<Keccak256>::default());         let mut public_coin
// = SolidityPublicCoin::new(pub_input_hash);

//         assert_eq!(
//
// Fp!("914053382091189896561965228399096618375831658573140010954888220151670628653"
// ),             public_coin.draw()
//         );
//         assert_eq!(
//
// Fp!("3496720894051083870907112578962849417100085660158534559258626637026506475074"
// ),             public_coin.draw()
//         );
//         assert_eq!(
//
// Fp!("1568281537905787801632546124130153362941104398120976544423901633300198530772"
// ),             public_coin.draw()
//         );
//         assert_eq!(
//
// Fp!("539395842685339476048032152056539303790683868668644006005689195830492067187"
// ),             public_coin.draw()
//         );
//     }

//     #[test]
//     fn roots_of_unity() {
//         let trace_domain_size = 2;
//         let lde_domain_size = trace_domain_size * 2;
//         let domain_offset = Fp::GENERATOR;
//         let lde_domain = Radix2EvaluationDomain::new_coset(lde_domain_size,
// domain_offset).unwrap();

//         for element in lde_domain.elements() {
//             println!("e: {}", element);
//         }

//         let half_lde_domain0 =
//             Radix2EvaluationDomain::new_coset(lde_domain_size / 2,
// domain_offset).unwrap();         let half_lde_domain1 =
// Radix2EvaluationDomain::new_coset(             lde_domain_size / 2,
//             domain_offset * lde_domain.group_gen,
//         )
//         .unwrap();

//         for element in half_lde_domain0.elements() {
//             println!("e0: {}", element);
//         }
//         for element in half_lde_domain1.elements() {
//             println!("e1: {}", element);
//         }
//     }
// }
