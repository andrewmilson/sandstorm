use std::fmt::Debug;

use ministark::random::PublicCoin;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use sha3::digest::Output;
use ark_ff::PrimeField;
use sha3::Digest;

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

impl<D: Digest> PublicCoin for PublicCoinImpl<D> {
    type Digest = D;
    type Field = Fp;

    fn new(digest: Output<D>) -> Self {
        Self { digest, counter: 0 }
    }

    fn reseed(&mut self, val: &Output<D>) {
        let digest = U256::try_from_be_slice(&self.digest).unwrap();
        let mut hasher = D::new();
        hasher.update((digest + uint!(1_U256)).to_be_bytes::<32>());
        hasher.update(val);
        self.digest = hasher.finalize();
        self.counter = 0;
    }

    fn reseed_with_int(&mut self, val: u64) {
        let bytes = U256::from(val).to_be_bytes::<32>();
        self.reseed(&Output::<D>::from_iter(bytes))
    }

    fn draw(&mut self) -> Fp {
        let bound = BigUint::from(Fp::MODULUS) * 31u32;
        let mut field_element = bound.clone();
        while field_element >= bound {
            let mut hasher = D::new();
            hasher.update(&self.digest);
            hasher.update(U256::from(self.counter).to_be_bytes::<32>());
            let digest = hasher.finalize();
            field_element = BigUint::from_bytes_be(&digest[0..32]);
            self.counter += 1;
        }
        from_montgomery(field_element)
    }

    fn draw_int(&mut self, max: usize) -> usize {
        let num: BigUint = self.draw().into();
        (num % BigUint::from(max)).try_into().unwrap()
    }

    fn verify_proof_of_work(&self, proof_of_work_bits: u32, nonce: u64) -> bool {
        // TODO:
        true
    }
}

#[cfg(test)]
mod tests {
    use super::PublicCoinImpl;
    use ark_ff::MontFp as Fp;
    use ministark::random::PublicCoin;
    use sha2::digest::Output;
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
}
