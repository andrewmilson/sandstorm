use crate::MemoryEntry;
use alloc::vec::Vec;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use ruint::aliases::U256;
use serde::de;
use serde::Deserialize;
use serde::Deserializer;
use serde_json::value::Number;
use std::fmt::Display;

#[derive(Debug)]
pub struct OutOfRangeError {
    value: BigUint,
    modulus: BigUint,
}

impl Display for OutOfRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid value: {}, must be less than the modulus {}",
            self.value, self.modulus
        )
    }
}

impl std::error::Error for OutOfRangeError {}

fn try_felt_from_u256<F: PrimeField>(value: U256) -> Result<F, OutOfRangeError> {
    let value = BigUint::from(value);
    let modulus = F::MODULUS.into();
    if value < modulus {
        Ok(value.into())
    } else {
        Err(OutOfRangeError { value, modulus })
    }
}

// /// Deserializes a hex string into a field element
// pub fn deserialize_hex_str_as_field<'de, D: Deserializer<'de>, T: Field>(
//     deserializer: D,
// ) -> Result<T, D::Error> {
//     let num = deserialize_hex_str(deserializer)?;
//     let base_field = T::BasePrimeField::from(BigUint::from(num));
//     Ok(T::from_base_prime_field(base_field))
// }

/// Deserializes a hex string into a big integer
pub fn deserialize_hex_str<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
    let hex_str = String::deserialize(deserializer)?;
    hex_str.parse::<U256>().map_err(de::Error::custom)
}

/// Deserializes a list of memory entries of the form
/// `{value: "0x...", address: ...}`
pub fn deserialize_hex_str_memory_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<MemoryEntry<U256>>, D::Error> {
    #[derive(Deserialize)]
    struct Entry {
        #[serde(deserialize_with = "deserialize_hex_str")]
        pub value: U256,
        pub address: u32,
    }
    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter()
        .map(|Entry { address, value }| MemoryEntry { address, value })
        .collect())
}

/// Deserializes a list of hex strings into a list of big integers
pub fn deserialize_vec_hex_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<U256>, D::Error> {
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_hex_str")] U256);
    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().map(|Wrapper(a)| a).collect())
}

/// Deserializes a JSON big integer
/// This deserializer uses serde_json's arbitrary precision features to convert
/// large numbers to a string and then converts that string to a [U256]. Note
/// that you can't just deserialize a [U256] because it deserializes a large
/// number from smaller 32 bit number chunks. TODO: check
pub fn deserialize_big_uint<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
    let num = Number::deserialize(deserializer)?.to_string();
    num.parse::<U256>().map_err(de::Error::custom)
}

/// Deserializes a JSON list of big integers
/// See docs for [deserialize_big_uint] to understand why this is needed.
// TODO: consider removing
pub fn _deserialize_vec_big_uint<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<U256>, D::Error> {
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_big_uint")] U256);
    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().map(|Wrapper(a)| a).collect())
}

/// Calculates the number of bytes per field element the
/// same way as StarkWare's runner
pub const fn field_bytes<F: PrimeField>() -> usize {
    F::MODULUS_BIT_SIZE.next_multiple_of(8) as usize / 8
}

/// Utils for compatibility with StarkWare's SHARed Prover (SHARP)
pub(crate) mod sharp {
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;
    use digest::Digest;

    /// Hashes elemets to match
    pub fn hash_elements<F: PrimeField, D: Digest>(hasher: &mut D, elements: &[F]) {
        for element in elements {
            let be_bytes = element.into_bigint().to_bytes_be();
            assert_eq!(<F::BigInt as BigInteger>::NUM_LIMBS * 8, be_bytes.len());
            hasher.update(be_bytes);
        }
    }

    #[cfg(test)]
    mod tests {
        use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
        use sha3::Digest;
        use sha3::Keccak256;
        use super::hash_elements;

        #[test]
        fn hash_elements_with_starkware_field_matches_solidity() {
            // test matches `keccak256(abi.encodePacked([1, 2]))` in solidity
            // (which is what StarkWare uses in their L1 Cairo verifier)
            let mut hasher = Keccak256::new();
            hash_elements(&mut hasher, &[Fp::from(1u8), Fp::from(2u8)]);
            let hash = hasher.finalize();

            assert_eq!(
                &[
                    233, 11, 123, 206, 182, 231, 223, 84, 24, 251, 120, 216, 238, 84, 110, 151,
                    200, 58, 8, 187, 204, 192, 26, 6, 68, 213, 153, 204, 210, 167, 194, 224
                ],
                &*hash
            )
        }
    }
}
