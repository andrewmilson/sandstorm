use std::str::FromStr;
use num_bigint::BigUint;
use ark_ff::PrimeField;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;

pub(crate) fn get_public_input_hash(public_input: &[Fp]) {
    todo!()
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
    use ark_ff::MontFp as Fp;
    use sha2::digest::Output;
    use sha3::Keccak256;

    #[test]
    fn send_field_elements_matches_solidity_verifier() {
        todo!()
    }
}
