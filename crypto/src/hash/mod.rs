pub mod blake2s;
pub mod keccak;
pub mod pedersen;
pub mod poseidon;

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
