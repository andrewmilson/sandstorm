use std::collections::BTreeSet;
use std::fmt::Debug;
use std::iter;
use crypto::hash::keccak::CanonicalKeccak256HashFn;
use ministark::hash::HashFn;
use ministark::random::PublicCoin;
use ministark::utils::SerdeOutput;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ruint::aliases::U256;
use binary::AirPublicInput;
use ruint::uint;
use sha3::Keccak256;
use ark_ff::PrimeField;
use ministark::random::leading_zeros;
use sha3::Digest;
use super::CairoPublicCoin;
use crypto::hash::keccak::Keccak256HashFn;
use crate::input::CairoAuxInput;
use crypto::utils::to_montgomery;
use crypto::utils::from_montgomery;

/// Public coin based off of StarkWare's solidity verifier
pub struct SolidityVerifierPublicCoin {
    digest: SerdeOutput<Keccak256>,
    counter: usize,
}

impl Debug for SolidityVerifierPublicCoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicCoinImpl")
            .field("digest", &self.digest)
            .field("counter", &self.counter)
            .finish()
    }
}

impl SolidityVerifierPublicCoin {
    fn reseed_with_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        let digest = U256::try_from_be_slice(&self.digest).unwrap();
        let mut hasher = Keccak256::new();
        hasher.update((digest + uint!(1_U256)).to_be_bytes::<32>());
        hasher.update(bytes);
        self.digest = SerdeOutput::new(hasher.finalize());
        self.counter = 0;
    }

    fn draw_bytes(&mut self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(*self.digest);
        hasher.update(U256::from(self.counter).to_be_bytes::<32>());
        self.counter += 1;
        (*hasher.finalize()).try_into().unwrap()
    }
}

impl CairoPublicCoin for SolidityVerifierPublicCoin {
    fn from_public_input(public_input: &AirPublicInput<Fp>) -> Self {
        let aux_input = CairoAuxInput(public_input);
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements::<CanonicalKeccak256HashFn>() {
            seed.extend_from_slice(&element.to_be_bytes::<32>())
        }
        Self::new(Keccak256HashFn::hash_chunks([&*seed]))
    }
}

impl PublicCoin for SolidityVerifierPublicCoin {
    type Digest = SerdeOutput<Keccak256>;
    type Field = Fp;

    fn new(digest: SerdeOutput<Keccak256>) -> Self {
        Self { digest, counter: 0 }
    }

    fn reseed_with_digest(&mut self, val: &SerdeOutput<Keccak256>) {
        self.reseed_with_bytes(**val);
    }

    fn reseed_with_field_elements(&mut self, vals: &[Fp]) {
        for v in vals {
            let bytes = to_montgomery(*v).to_be_bytes::<32>();
            self.reseed_with_bytes(bytes);
        }
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
        ints.take(max_n)
            .map(|v| (v % domain_size).try_into().unwrap())
            .collect()
    }

    fn verify_proof_of_work(&self, proof_of_work_bits: u8, nonce: u64) -> bool {
        let mut prefix_hasher = Keccak256::new();
        prefix_hasher.update(0x0123456789ABCDEDu64.to_be_bytes());
        prefix_hasher.update(*self.digest);
        prefix_hasher.update([proof_of_work_bits]);
        let prefix_hash = prefix_hasher.finalize();

        let mut proof_of_work_hasher = Keccak256::new();
        proof_of_work_hasher.update(prefix_hash);
        proof_of_work_hasher.update(nonce.to_be_bytes());
        let proof_of_work_hash = proof_of_work_hasher.finalize();

        leading_zeros(&proof_of_work_hash) >= u32::from(proof_of_work_bits)
    }

    fn security_level_bits() -> u32 {
        Keccak256HashFn::COLLISION_RESISTANCE
    }
}

#[cfg(test)]
mod tests {
    use super::SolidityVerifierPublicCoin;
    use ark_ff::MontFp as Fp;
    use digest::Output;
    use ministark::random::PublicCoin;
    use ministark::utils::SerdeOutput;
    use sha3::Keccak256;

    #[test]
    fn draw_matches_solidity_verifier() {
        let pub_input_hash = SerdeOutput::new(Output::<Keccak256>::default());
        let mut public_coin = SolidityVerifierPublicCoin::new(pub_input_hash);

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
}
