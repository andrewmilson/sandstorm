use std::str::FromStr;
use digest::Digest;
use num_bigint::BigUint;
use ark_ff::{PrimeField, BigInteger};
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;

pub(crate) fn get_public_input_hash(public_input: &[Fp]) {
    todo!()
}

/// Hashes elemets to match SHARP
pub fn hash_elements<F: PrimeField, D: Digest>(hasher: &mut D, elements: &[F]) {
    for element in elements {
        let be_bytes = element.into_bigint().to_bytes_be();
        assert_eq!(<F::BigInt as BigInteger>::NUM_LIMBS * 8, be_bytes.len());
        hasher.update(be_bytes);
    }
}

pub(crate) fn from_montgomery(v: BigUint) -> Fp {
    let k_montgomery_r_inv = BigUint::from_str(
        "113078212145816603762751633895895194930089271709401121343797004406777446400",
    )
    .unwrap();
    let modulus = BigUint::from(Fp::MODULUS);
    (k_montgomery_r_inv * v % modulus).into()
}

#[cfg(test)]
mod tests {
    use super::hash_elements;
    use sha3::Keccak256;
    use digest::Digest;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;

    #[test]
    fn hash_elements_with_starkware_field_matches_solidity() {
        // test matches `keccak256(abi.encodePacked([1, 2]))` in solidity
        // (which is what StarkWare uses in their L1 Cairo verifier)
        let mut hasher = Keccak256::new();
        hash_elements(&mut hasher, &[Fp::from(1u8), Fp::from(2u8)]);
        let hash = hasher.finalize();

        assert_eq!(
            &[
                233, 11, 123, 206, 182, 231, 223, 84, 24, 251, 120, 216, 238, 84, 110, 151, 200,
                58, 8, 187, 204, 192, 26, 6, 68, 213, 153, 204, 210, 167, 194, 224
            ],
            &*hash
        )
    }
}
