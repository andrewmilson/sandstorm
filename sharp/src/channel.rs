use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use sha3::digest::Output;
use ark_ff::PrimeField;
use sha3::Digest;
use sha3::Keccak256;

use crate::utils::from_montgomery;

/// Channel based of StarkWare solidity verifier
struct Channel {
    digest: Output<Keccak256>,
    counter: usize,
}

impl Channel {
    pub fn new(pub_input_hash: Output<Keccak256>) -> Self {
        Self {
            digest: pub_input_hash,
            counter: 0,
        }
    }

    // Sends a field element through the verifier channel
    pub fn send_field_elements(&mut self, n: usize) -> Vec<Fp> {
        let bound = BigUint::from(Fp::MODULUS) * 31u32;

        let mut res = Vec::new();
        for _ in 0..n {
            let mut field_element = bound.clone();
            while field_element >= bound {
                let mut hasher = Keccak256::new();
                hasher.update(self.digest);
                hasher.update(U256::from(self.counter).to_be_bytes::<32>());
                let digest = hasher.finalize();
                field_element = BigUint::from_bytes_be(&digest[0..32]);
                self.counter += 1;
            }
            res.push(from_montgomery(field_element));
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::Channel;
    use ark_ff::MontFp as Fp;
    use sha2::digest::Output;
    use sha3::Keccak256;

    #[test]
    fn send_field_elements_matches_solidity_verifier() {
        let pub_input_hash = Output::<Keccak256>::default();
        let mut channel = Channel::new(pub_input_hash);

        let res = channel.send_field_elements(4);

        assert_eq!(
            Fp!("914053382091189896561965228399096618375831658573140010954888220151670628653"),
            res[0]
        );
        assert_eq!(
            Fp!("3496720894051083870907112578962849417100085660158534559258626637026506475074"),
            res[1]
        );
        assert_eq!(
            Fp!("1568281537905787801632546124130153362941104398120976544423901633300198530772"),
            res[2]
        );
        assert_eq!(
            Fp!("539395842685339476048032152056539303790683868668644006005689195830492067187"),
            res[3]
        );
    }
}
