use crate::errors::InvalidFieldElementError;
use crate::MemoryEntry;
use alloc::vec::Vec;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use ruint::aliases::U256;
use serde::de;
use serde::Deserialize;
use serde::Deserializer;
use serde_json::value::Number;

fn try_felt_from_u256<F: PrimeField>(value: U256) -> Result<F, InvalidFieldElementError> {
    let modulus = U256::from::<BigUint>(F::MODULUS.into());
    if value < modulus {
        Ok(From::<BigUint>::from(value.into()))
    } else {
        Err(InvalidFieldElementError { value, modulus })
    }
}

/// Deserializes a hex string into a field element
pub fn deserialize_hex_str_as_field_element<'de, D: Deserializer<'de>, F: PrimeField>(
    deserializer: D,
) -> Result<F, D::Error> {
    let num = deserialize_hex_str(deserializer)?;
    try_felt_from_u256(num).map_err(de::Error::custom)
}

/// Deserializes a hex string into a big integer
pub fn deserialize_hex_str<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
    let hex_str = String::deserialize(deserializer)?;
    hex_str.parse::<U256>().map_err(de::Error::custom)
}

/// Deserializes a list of memory entries of the form
/// `{value: "0x...", address: ...}`
pub fn deserialize_hex_str_memory_entries<'de, D: Deserializer<'de>, F: PrimeField>(
    deserializer: D,
) -> Result<Vec<MemoryEntry<F>>, D::Error> {
    #[derive(Deserialize)]
    struct Entry<F: PrimeField> {
        #[serde(deserialize_with = "deserialize_hex_str_as_field_element")]
        pub value: F,
        pub address: u32,
    }
    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter()
        .map(|Entry { address, value }| MemoryEntry { address, value })
        .collect())
}

/// Deserializes a list of hex strings into a list of big integers
pub fn deserialize_vec_hex_str<'de, D: Deserializer<'de>, F: PrimeField>(
    deserializer: D,
) -> Result<Vec<F>, D::Error> {
    #[derive(Deserialize)]
    struct Wrapper<F: PrimeField>(
        #[serde(deserialize_with = "deserialize_hex_str_as_field_element")] F,
    );
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
