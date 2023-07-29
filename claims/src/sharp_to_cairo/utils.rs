use digest::Digest;
use num_bigint::BigUint;
use ark_ff::{PrimeField, BigInteger, MontFp as Fp};
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

pub fn from_montgomery(v: BigUint) -> Fp {
    const MONTGOMERY_R_INV: Fp =
        Fp!("113078212145816603762751633895895194930089271709401121343797004406777446400");
    MONTGOMERY_R_INV * Fp::from(v)
}

pub fn to_montgomery(v: Fp) -> BigUint {
    const MONTGOMERY_R: Fp =
        Fp!("3618502788666127798953978732740734578953660990361066340291730267701097005025");
    BigUint::from(MONTGOMERY_R * v)
}

#[inline]
pub fn mask_least_significant_bytes<const N_UNMASKED_BYTES: u32>(bytes: &mut [u8]) {
    let n = bytes.len();
    let mut i = N_UNMASKED_BYTES as usize;
    while i < n {
        bytes[i] = 0;
        i += 1;
    }
}

#[inline]
pub fn mask_most_significant_bytes<const N_UNMASKED_BYTES: u32>(bytes: &mut [u8]) {
    let n = bytes.len();
    let mut i = 0;
    while i < n - N_UNMASKED_BYTES as usize {
        bytes[i] = 0;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::to_montgomery;
    use super::from_montgomery;
    use super::hash_elements;
    use sha3::Keccak256;
    use digest::Digest;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;

    #[test]
    fn hash_elements_with_starkware_field_matches_solidity() {
        let mut hasher = Keccak256::new();
        hash_elements(&mut hasher, &[Fp::from(1u8), Fp::from(2u8)]);
        let hash = hasher.finalize();

        // result of `keccak256(abi.encodePacked([1, 2]))` in solidity
        // (which is what StarkWare uses in their L1 Cairo verifier)
        let hash_from_solidity = &[
            233, 11, 123, 206, 182, 231, 223, 84, 24, 251, 120, 216, 238, 84, 110, 151, 200, 58, 8,
            187, 204, 192, 26, 6, 68, 213, 153, 204, 210, 167, 194, 224,
        ];
        assert_eq!(hash_from_solidity, &*hash)
    }

    #[test]
    fn to_montgomery_is_inverse_of_from_montgomery() {
        let five = Fp::from(5u8);

        assert_eq!(five, from_montgomery(to_montgomery(five)));
    }
}
