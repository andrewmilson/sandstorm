use ark_ec::Group;
use ark_ec::short_weierstrass::Projective;
use ark_ec::short_weierstrass::SWCurveConfig;
use binary::EcdsaInstance;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use ark_ff::Field;
use crate::utils::starkware_curve::Fr;
use crate::utils::starkware_curve::Curve;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ark_ec::short_weierstrass::Affine;
use ark_ff::PrimeField;

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: EcdsaInstance,
}

impl InstanceTrace {
    pub fn new(instance: EcdsaInstance) -> Self {
        Self { instance }
    }
}

// based on: https://github.com/starkware-libs/starkex-resources/blob/844ac3dcb1f735451457f7eecc6e37cd96d1cb2d/crypto/starkware/crypto/signature/signature.py#L192
fn verify(msg_hash: Fp, r: Fp, s: Fr, pubkey: Fp) {
    let w = s.inverse().unwrap();
    let pubkey = Affine::<Curve>::get_point_from_x_unchecked(pubkey, true)
        .expect("pubkey is not on the curve")
        .into();

    // Signature validation.
    // DIFF: original formula is:
    // x = (w*msg_hash)*EC_GEN + (w*r)*public_key
    // While what we implement is:
    // x = w*(msg_hash*EC_GEN + r*public_key).
    // While both mathematically equivalent, one might error while the other
    // doesn't, given the current implementation.
    // This formula ensures that if the verification errors in our AIR, it
    // errors here as well.
    let shift_point = Projective::from(super::pedersen::constants::P0);
    let generator = Curve::GENERATOR.into();
    let zg = mimic_ec_mult_air(msg_hash.into(), generator, -shift_point).unwrap();
    let rq = mimic_ec_mult_air(r.into(), pubkey, shift_point).unwrap();
    let wb = mimic_ec_mult_air(w.into(), zg + rq, shift_point).unwrap();
    let x = 
}

/// Computes `m * point + shift_point` using the same steps like the AIR and
/// Returns None if and only if the AIR errors.
fn mimic_ec_mult_air(
    m: BigUint,
    mut point: Projective<Curve>,
    shift_point: Projective<Curve>,
) -> Option<Projective<Curve>> {
    if !(1..Fp::MODULUS_BIT_SIZE).contains(&(m.bits() as u32)) {
        return None;
    }
    let m_int = U256::from(m);
    let mut partial_sum = shift_point;
    #[allow(clippy::needless_range_loop)]
    for i in 0..256 {
        if Affine::from(partial_sum).x == Affine::from(point).x {
            return None;
        }
        let suffix = m_int >> i;
        let bit = suffix & uint!(1_U256);
        if bit == uint!(1_U256) {
            partial_sum += point;
        }
        point.double_in_place();
    }
    Some(partial_sum)
}
