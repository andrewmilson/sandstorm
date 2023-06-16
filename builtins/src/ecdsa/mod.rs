use std::sync::OnceLock;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::short_weierstrass::Projective;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::Zero;
use binary::EcdsaInstance;
use binary::Signature;
use ministark::utils::FieldVariant;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use ark_ff::Field;
use crate::pedersen::pedersen_hash;
use crate::utils::gen_periodic_table;
use crate::utils::curve::Fr;
use crate::utils::curve::StarkwareCurve;
use crate::utils::curve::calculate_slope;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ark_ec::short_weierstrass::Affine;
use ark_ff::PrimeField;

pub mod periodic;

pub const SHIFT_POINT: Affine<StarkwareCurve> = super::pedersen::constants::P0;

/// An ECDSA trace for a dummy instance
/// Created once since creating new instance traces each time is expensive.
static DUMMY_INSTANCE_TRACE: OnceLock<InstanceTrace> = OnceLock::new();

/// Elliptic Curve multilpy-add (MAD) partial step
#[derive(Clone, Debug)]
pub struct EcMadPartialStep {
    pub partial_sum: Affine<StarkwareCurve>,
    pub fixed_point: Affine<StarkwareCurve>,
    pub suffix: Fp,
    pub slope: Fp,
    pub x_diff_inv: Fp,
}

#[derive(Clone, Copy, Debug)]
pub struct DoublingStep {
    pub point: Affine<StarkwareCurve>,
    pub slope: Fp,
}

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: EcdsaInstance,
    /// pubkey `Q`
    pub pubkey: Affine<StarkwareCurve>,
    pub pubkey_doubling_steps: Vec<DoublingStep>,
    pub w: Fp,
    /// Inverse of `w` in the base field
    pub w_inv: Fp,
    pub r: Fp,
    /// Inverse of `r` in the base field
    pub r_inv: Fp,
    pub r_point_slope: Fp,
    pub r_point_x_diff_inv: Fp,
    /// Message hash `z`
    pub message: Fp,
    pub message_inv: Fp,
    /// Point `B = z * G + r * Q`
    pub b: Affine<StarkwareCurve>,
    /// Slope between points `z * G` and `r * Q`
    pub b_slope: Fp,
    pub b_x_diff_inv: Fp,
    pub b_doubling_steps: Vec<DoublingStep>,
    /// steps for `z * G` where
    /// `G` is the elliptic curve generator point and
    /// `z` is the message hash
    pub zg_steps: Vec<EcMadPartialStep>,
    /// steps for the scalar multiplication `r * Q` where
    /// `Q` is the pubkey point and
    /// `r` is the signature's `r` value
    pub rq_steps: Vec<EcMadPartialStep>,
    /// steps for the scalar multiplication `w * B` where
    /// `B = z * G + r * Q` and
    /// `w` is the inverse of the signature's `s` value (NOTE: that's the
    /// inverse in the curve's scalar field)
    pub wb_steps: Vec<EcMadPartialStep>,
}

impl InstanceTrace {
    // TODO: error handling
    pub fn new(instance: EcdsaInstance) -> Self {
        let message = Fp::from(BigUint::from(instance.message));
        let pubkey_x = Fp::from(BigUint::from(instance.pubkey_x));
        let r = Fp::from(BigUint::from(instance.signature.r));
        let w = Fr::from(BigUint::from(instance.signature.w));
        let s = w.inverse().unwrap();
        let pubkey = verify(message, r, s, pubkey_x).expect("signature is invalid");

        let shift_point = Projective::from(SHIFT_POINT);
        let generator = Projective::from(StarkwareCurve::GENERATOR);

        let zg = Affine::from(mimic_ec_mad_air(message.into(), generator, -shift_point).unwrap());
        let qr = Affine::from(mimic_ec_mad_air(r.into(), pubkey.into(), shift_point).unwrap());

        let b = (zg + qr).into_affine();
        let b_slope = calculate_slope(zg, qr).unwrap();
        let b_x_diff_inv = (zg.x - qr.x).inverse().unwrap();
        let b_doubling_steps = doubling_steps(256, b.into());
        let wb = Affine::from(mimic_ec_mad_air(w.into(), b.into(), shift_point).unwrap());

        let zg_steps = gen_ec_mad_steps(message.into(), generator, -shift_point);
        let rq_steps = gen_ec_mad_steps(r.into(), pubkey.into(), shift_point);
        let wb_steps = gen_ec_mad_steps(w.into(), b.into(), shift_point);

        assert_eq!(zg, zg_steps.last().unwrap().partial_sum);
        assert_eq!(qr, rq_steps.last().unwrap().partial_sum);
        assert_eq!(wb, wb_steps.last().unwrap().partial_sum);

        let w = Fp::from(BigUint::from(w));
        let w_inv = w.inverse().unwrap();
        let r_inv = r.inverse().unwrap();
        let message_inv = message.inverse().unwrap();

        let pubkey_doubling_steps = doubling_steps(256, pubkey.into());

        let shift_point = Affine::from(shift_point);
        let r_point_slope = calculate_slope(wb, -shift_point).unwrap();
        let r_point_x_diff_inv = (wb.x - (-shift_point).x).inverse().unwrap();
        assert_eq!(r, (wb - shift_point).into_affine().x);

        Self {
            instance,
            pubkey,
            pubkey_doubling_steps,
            w,
            w_inv,
            r,
            r_inv,
            r_point_slope,
            r_point_x_diff_inv,
            message,
            message_inv,
            b,
            b_slope,
            b_x_diff_inv,
            b_doubling_steps,
            zg_steps,
            rq_steps,
            wb_steps,
        }
    }

    /// Creates a new dummy instance.
    /// Can be used for filling holes in an execution trace
    pub fn new_dummy(index: u32) -> Self {
        let mut dummy_trace = DUMMY_INSTANCE_TRACE
            .get_or_init(|| {
                let dummy_instance = gen_dummy_instance(0);
                Self::new(dummy_instance)
            })
            .clone();
        dummy_trace.instance.index = index;
        dummy_trace
    }
}

/// Generates a list of the steps involved with an EC multiply-add
fn gen_ec_mad_steps(
    x: BigUint,
    mut point: Projective<StarkwareCurve>,
    shift_point: Projective<StarkwareCurve>,
) -> Vec<EcMadPartialStep> {
    let x = U256::from(x);
    // Assertions fail if the AIR will error
    assert!(x != U256::ZERO);
    assert!(x < uint!(2_U256).pow(uint!(251_U256)));
    let mut partial_sum = shift_point;
    let mut res = Vec::new();
    for i in 0..256 {
        let suffix = x >> i;
        let bit = suffix & uint!(1_U256);

        let mut slope = Fp::ZERO;
        let mut partial_sum_next = partial_sum;
        let partial_sum_affine = partial_sum.into_affine();
        let point_affine = point.into_affine();
        if bit == uint!(1_U256) {
            slope = calculate_slope(point_affine, partial_sum_affine).unwrap();
            partial_sum_next += point;
        }

        res.push(EcMadPartialStep {
            partial_sum: partial_sum_affine,
            fixed_point: point_affine,
            suffix: Fp::from(BigUint::from(suffix)),
            x_diff_inv: (partial_sum_affine.x - point_affine.x).inverse().unwrap(),
            slope,
        });

        partial_sum = partial_sum_next;
        point.double_in_place();
    }
    res
}

pub fn doubling_steps(num_steps: usize, mut p: Projective<StarkwareCurve>) -> Vec<DoublingStep> {
    let mut res = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for _ in 0..num_steps {
        let p_affine = p.into_affine();
        let slope = calculate_slope(p_affine, p_affine).unwrap();
        res.push(DoublingStep {
            point: p_affine,
            slope,
        });
        p.double_in_place();
    }
    res
}

/// Generates a dummy signature using `private_key = 1`
fn gen_dummy_instance(index: u32) -> EcdsaInstance {
    let privkey = Fr::ONE;
    let message_hash = BigUint::from(pedersen_hash(Fp::ONE, Fp::ZERO));
    assert!(!message_hash.is_zero());
    assert!(message_hash < BigUint::from(2u32).pow(251));
    let message_hash = Fr::from(message_hash);

    for i in 1u64.. {
        let k = Fr::from(i);

        // Cannot fail because 0 < k < EC_ORDER and EC_ORDER is prime.
        let x = (StarkwareCurve::GENERATOR * k).into_affine().x;

        let r = BigUint::from(x);
        if r.is_zero() || r >= BigUint::from(2u32).pow(251) {
            // Bad value. This fails with negligible probability.
            continue;
        }

        let r = Fr::from(r);
        if (message_hash + r * privkey).is_zero() {
            // Bad value. This fails with negligible probability.
            continue;
        }

        let w = k / (message_hash + r * privkey);
        let w_int = BigUint::from(w);
        if w_int.is_zero() || w_int >= BigUint::from(2u32).pow(251) {
            // Bad value. This fails with negligible probability.
            continue;
        }

        let pubkey = (StarkwareCurve::GENERATOR * privkey).into_affine();

        return EcdsaInstance {
            index,
            pubkey_x: U256::from(BigUint::from(pubkey.x)),
            message: U256::from(BigUint::from(message_hash)),
            signature: Signature {
                r: U256::from(BigUint::from(r)),
                w: U256::from(w_int),
            },
        };
    }

    unreachable!()
}

/// Verifies a signature
/// Returns the associated public key if the signature is valid
/// Returns None if the signature is invalid
/// based on: https://github.com/starkware-libs/starkex-resources/blob/844ac3dcb1f735451457f7eecc6e37cd96d1cb2d/crypto/starkware/crypto/signature/signature.py#L192
fn verify(msg_hash: Fp, r: Fp, s: Fr, pubkey_x: Fp) -> Option<Affine<StarkwareCurve>> {
    let w = s.inverse().unwrap();
    let (y1, y0) =
        Affine::<StarkwareCurve>::get_ys_from_x_unchecked(pubkey_x).expect("not on the curve");

    for pubkey_y in [y1, y0] {
        let pubkey = Affine::<StarkwareCurve>::new_unchecked(pubkey_x, pubkey_y);
        // Signature validation.
        // DIFF: original formula is:
        // x = (w*msg_hash)*EC_GEN + (w*r)*public_key
        // While what we implement is:
        // x = w*(msg_hash*EC_GEN + r*public_key).
        // While both mathematically equivalent, one might error while the other
        // doesn't, given the current implementation.
        // This formula ensures that if the verification errors in our AIR, it
        // errors here as well.
        let shift_point = Projective::from(SHIFT_POINT);
        let generator = StarkwareCurve::GENERATOR.into();
        let zg = mimic_ec_mad_air(msg_hash.into(), generator, -shift_point).unwrap();
        let rq = mimic_ec_mad_air(r.into(), pubkey.into(), shift_point).unwrap();
        let wb = mimic_ec_mad_air(w.into(), zg + rq, shift_point).unwrap();
        let x = (wb - shift_point).into_affine().x;
        if r == x {
            return Some(pubkey);
        }
    }

    None
}

/// Computes `m * point + shift_point` using the same steps like the AIR and
/// Returns None if and only if the AIR errors.
pub(crate) fn mimic_ec_mad_air(
    m: BigUint,
    mut point: Projective<StarkwareCurve>,
    shift_point: Projective<StarkwareCurve>,
) -> Option<Projective<StarkwareCurve>> {
    if !(1..Fp::MODULUS_BIT_SIZE).contains(&(m.bits() as u32)) {
        return None;
    }
    let mut m = U256::from(m);
    let mut partial_sum = shift_point;
    #[allow(clippy::needless_range_loop)]
    while m != U256::ZERO {
        if Affine::from(partial_sum).x == Affine::from(point).x {
            return None;
        }
        let bit = m & uint!(1_U256);
        if bit == uint!(1_U256) {
            partial_sum += point;
        }
        point.double_in_place();
        m >>= 1;
    }
    Some(partial_sum)
}
