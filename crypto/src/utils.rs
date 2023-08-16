use std::marker::PhantomData;

use ark_ff::BigInt;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ark_ff::PrimeField;
use ruint::aliases::U256;

#[inline]
pub fn from_montgomery(v: U256) -> Fp {
    const MODULUS: U256 = U256::from_limbs(Fp::MODULUS.0);
    ark_ff::Fp(BigInt((v % MODULUS).into_limbs()), PhantomData)
}

#[inline]
pub fn to_montgomery(v: Fp) -> U256 {
    assert!(v.0 < Fp::MODULUS);
    U256::from_limbs((v.0).0)

    // const MONTGOMERY_R: Fp =
    //     Fp!("3618502788666127798953978732740734578953660990361066340291730267701097005025");
    // BigUint::from(MONTGOMERY_R * v)
}
