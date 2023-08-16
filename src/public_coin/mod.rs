pub mod cairo;
pub mod solidity;

use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use binary::AirPublicInput;
use ministark::hash::ElementHashFn;
use ministark::random::PublicCoin;
use ministark::random::PublicCoinImpl;

pub trait CairoPublicCoin: PublicCoin {
    fn from_public_input(
        public_input: &AirPublicInput<<Self::Field as Field>::BasePrimeField>,
    ) -> Self;
}

impl<F: Field, H: ElementHashFn<F>> CairoPublicCoin for PublicCoinImpl<F, H> {
    fn from_public_input(
        air_public_input: &AirPublicInput<<Self::Field as Field>::BasePrimeField>,
    ) -> Self {
        // NOTE: this generic implementation is only intended for experimentation so the
        // implementation is rather strange
        let mut bytes = Vec::new();
        air_public_input.serialize_compressed(&mut bytes).unwrap();
        Self::new(H::hash_chunks([&*bytes]))
    }
}
