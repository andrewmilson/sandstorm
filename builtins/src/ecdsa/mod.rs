use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::short_weierstrass::Projective;
use ark_ec::short_weierstrass::SWCurveConfig;
use binary::EcdsaInstance;
use ministark::utils::FieldVariant;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use ark_ff::Field;
use crate::utils::gen_periodic_table;
use crate::utils::starkware_curve::Fr;
use crate::utils::starkware_curve::Curve;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ark_ec::short_weierstrass::Affine;
use ark_ff::PrimeField;

#[derive(Clone, Copy, Debug)]
pub struct DoublingStep {
    pub point: Affine<Curve>,
    pub slope: Fp,
}

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: EcdsaInstance,
    /// pubkey `Q`
    pub pubkey: Affine<Curve>,
    pub pubkey_doubling_steps: Vec<DoublingStep>,
}

impl InstanceTrace {
    pub fn new(instance: EcdsaInstance) -> Self {
        let message = Fp::from(BigUint::from(instance.message));
        let pubkey_x = Fp::from(BigUint::from(instance.pubkey_x));
        let r = Fp::from(BigUint::from(instance.signature.r));
        let w = Fr::from(BigUint::from(instance.signature.w));
        let s = w.inverse().unwrap();
        let pubkey = verify(message, r, s, pubkey_x).expect("signature is invalid");

        Self {
            instance,
            pubkey,
            pubkey_doubling_steps: doubling_steps(pubkey.into()),
        }
    }
}

/// Verifies a signature
/// Returns the associated public key if the signature is valid
/// Returns None if the signature is invalid
/// based on: https://github.com/starkware-libs/starkex-resources/blob/844ac3dcb1f735451457f7eecc6e37cd96d1cb2d/crypto/starkware/crypto/signature/signature.py#L192
fn verify(msg_hash: Fp, r: Fp, s: Fr, pubkey_x: Fp) -> Option<Affine<Curve>> {
    let w = s.inverse().unwrap();
    let (y1, y0) = Affine::<Curve>::get_ys_from_x_unchecked(pubkey_x).expect("not on the curve");

    for pubkey_y in [y1, y0] {
        let pubkey = Affine::<Curve>::new_unchecked(pubkey_x, pubkey_y);
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
        let rq = mimic_ec_mult_air(r.into(), pubkey.into(), shift_point).unwrap();
        let wb = mimic_ec_mult_air(w.into(), zg + rq, shift_point).unwrap();
        let x = (wb - shift_point).into_affine().x;
        if r == x {
            return Some(pubkey);
        }
    }

    None
}

fn doubling_steps(mut p: Projective<Curve>) -> Vec<DoublingStep> {
    let mut res = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for _ in 0..256 {
        // point doubling equation
        // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
        let p_affine = p.into_affine();
        let xx = p_affine.x.square();
        let slope = (xx + xx + xx + Curve::COEFF_A) / (p_affine.y + p_affine.y);

        res.push(DoublingStep {
            point: p_affine,
            slope,
        });

        p.double_in_place();
    }
    res
}

/// Computes `m * point + shift_point` using the same steps like the AIR and
/// Returns None if and only if the AIR errors.
fn mimic_ec_mult_air(
    m: BigUint,
    mut point: Projective<Curve>,
    shift_point: Projective<Curve>,
) -> Option<Projective<Curve>> {
    println!("{}", Fp::MODULUS_BIT_SIZE);
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

/// Ouptut is of the form (x_points_coeffs, y_points_coeffs)
// TODO: Generate these constant polynomials at compile time
#[allow(clippy::type_complexity)]
pub fn generator_points_poly() -> (Vec<FieldVariant<Fp, Fp>>, Vec<FieldVariant<Fp, Fp>>) {
    let mut evals = Vec::new();

    let mut acc = Projective::from(Curve::GENERATOR);
    for _ in 0..256 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    // TODO: need to figure out the exact polynomial starkware is using
    // assert_eq!(evals.len(), 256 + 252);
    // evals.resize(512, (Fp::ZERO, Fp::ZERO));

    let (x_evals, y_evals) = evals.into_iter().unzip();
    let mut polys = gen_periodic_table(vec![x_evals, y_evals])
        .into_iter()
        .map(|poly| poly.coeffs.into_iter().map(FieldVariant::Fp).collect());
    let (x_coeffs, y_coeffs) = (polys.next().unwrap(), polys.next().unwrap());
    (x_coeffs, y_coeffs)
}
