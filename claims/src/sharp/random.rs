use std::collections::BTreeSet;
use std::fmt::Debug;
use std::iter;

use ministark::random::PublicCoin;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use sha3::digest::Output;
use ark_ff::PrimeField;
use ministark::random::leading_zeros;
use sha3::Digest;
use super::utils::to_montgomery;
use super::utils::from_montgomery;

/// Public coin based off of StarkWare's solidity verifier
pub struct PublicCoinImpl<D: Digest> {
    digest: Output<D>,
    counter: usize,
}

impl<D: Digest> Debug for PublicCoinImpl<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicCoinImpl")
            .field("digest", &self.digest)
            .field("counter", &self.counter)
            .finish()
    }
}

impl<D: Digest> PublicCoinImpl<D> {
    fn reseed_with_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        let digest = U256::try_from_be_slice(&self.digest).unwrap();
        let mut hasher = D::new();
        hasher.update((digest + uint!(1_U256)).to_be_bytes::<32>());
        hasher.update(bytes);
        self.digest = hasher.finalize();
        self.counter = 0;
    }

    fn draw_bytes(&mut self) -> [u8; 32] {
        let mut hasher = D::new();
        hasher.update(&self.digest);
        hasher.update(U256::from(self.counter).to_be_bytes::<32>());
        self.counter += 1;
        (*hasher.finalize()).try_into().unwrap()
    }
}

impl<D: Digest> PublicCoin for PublicCoinImpl<D> {
    type Digest = D;
    type Field = Fp;

    fn new(digest: Output<D>) -> Self {
        Self { digest, counter: 0 }
    }

    fn reseed_with_hash(&mut self, val: &Output<D>) {
        self.reseed_with_bytes(val);
    }

    fn reseed_with_field_element(&mut self, val: &Fp) {
        let bytes = U256::from(to_montgomery(*val)).to_be_bytes::<32>();
        self.reseed_with_bytes(bytes);
    }

    fn reseed_with_field_elements(&mut self, vals: &[Self::Field]) {
        let mut bytes = Vec::new();
        for val in vals {
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
        ints.take(max_n)
            .map(|v| (v % domain_size).try_into().unwrap())
            .collect()
    }

    fn verify_proof_of_work(&self, proof_of_work_bits: u8, nonce: u64) -> bool {
        let mut prefix_hasher = D::new();
        prefix_hasher.update(0x0123456789ABCDEDu64.to_be_bytes());
        prefix_hasher.update(&self.digest);
        prefix_hasher.update([proof_of_work_bits]);
        let prefix_hash = prefix_hasher.finalize();

        let mut proof_of_work_hasher = D::new();
        proof_of_work_hasher.update(prefix_hash);
        proof_of_work_hasher.update(nonce.to_be_bytes());
        let proof_of_work_hash = proof_of_work_hasher.finalize();

        leading_zeros(&proof_of_work_hash) >= u32::from(proof_of_work_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::PublicCoinImpl;
    use ark_ff::MontFp as Fp;
    use ark_poly::Radix2EvaluationDomain;
    use ark_poly::EvaluationDomain;
    use ministark::random::PublicCoin;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
    use sha2::digest::Output;
    use ark_ff::FftField;
    use sha3::Keccak256;

    #[test]
    fn draw_matches_solidity_verifier() {
        let pub_input_hash = Output::<Keccak256>::default();
        let mut public_coin = PublicCoinImpl::<Keccak256>::new(pub_input_hash);

        assert_eq!(
            Fp!("914053382091189896561965228399096618375831658573140010954888220151670628653"),
            public_coin.draw()
        );
        assert_eq!(
            Fp!("3496720894051083870907112578962849417100085660158534559258626637026506475074"),
            public_coin.draw()
        );
        assert_eq!(
            Fp!("1568281537905787801632546124130153362941104398120976544423901633300198530772"),
            public_coin.draw()
        );
        assert_eq!(
            Fp!("539395842685339476048032152056539303790683868668644006005689195830492067187"),
            public_coin.draw()
        );
    }

    #[test]
    fn roots_of_unity() {
        let trace_domain_size = 2;
        let lde_domain_size = trace_domain_size * 2;
        let domain_offset = Fp::GENERATOR;
        let lde_domain = Radix2EvaluationDomain::new_coset(lde_domain_size, domain_offset).unwrap();

        for element in lde_domain.elements() {
            println!("e: {}", element);
        }

        let half_lde_domain0 =
            Radix2EvaluationDomain::new_coset(lde_domain_size / 2, domain_offset).unwrap();
        let half_lde_domain1 = Radix2EvaluationDomain::new_coset(
            lde_domain_size / 2,
            domain_offset * lde_domain.group_gen,
        )
        .unwrap();

        for element in half_lde_domain0.elements() {
            println!("e0: {}", element);
        }
        for element in half_lde_domain1.elements() {
            println!("e1: {}", element);
        }
    }
}
