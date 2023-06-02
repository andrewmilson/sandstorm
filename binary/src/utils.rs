use alloc::vec::Vec;
use ruint::aliases::U256;
use serde::de;
use serde::Deserialize;
use serde::Deserializer;
use serde_json::value::Number;

// /// Deserialises a hex string into a field element
// pub fn deserialize_hex_str_as_field<'de, D: Deserializer<'de>, T: Field>(
//     deserializer: D,
// ) -> Result<T, D::Error> {
//     let num = deserialize_hex_str(deserializer)?;
//     let base_field = T::BasePrimeField::from(BigUint::from(num));
//     Ok(T::from_base_prime_field(base_field))
// }

/// Deserialises a hex string into a big integer
pub fn deserialize_hex_str<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
    let hex_str = String::deserialize(deserializer)?;
    hex_str.parse::<U256>().map_err(de::Error::custom)
}

/// Deserialises a list of hex strings into a list of big integers
pub fn deserialize_vec_hex_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<U256>, D::Error> {
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_hex_str")] U256);
    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().map(|Wrapper(a)| a).collect())
}

/// Deserialises a JSON big integer
/// This deserializer uses serde_json's arbitrary precision features to convert
/// large numbers to a string and then converts that string to a [U256]. Note
/// that you can't just deserialize a [U256] because it deserializes a large
/// number from smaller 32 bit number chunks. TODO: check
pub fn deserialize_big_uint<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
    let num = Number::deserialize(deserializer)?.to_string();
    num.parse::<U256>().map_err(de::Error::custom)
}

/// Deserialises a JSON list of big integers
/// See docs for [deserialize_big_uint] to understand why this is needed.
pub fn deserialize_vec_big_uint<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<U256>, D::Error> {
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_big_uint")] U256);
    let v = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().map(|Wrapper(a)| a).collect())
}
