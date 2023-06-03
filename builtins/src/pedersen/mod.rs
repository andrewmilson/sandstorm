use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::Projective;
use ark_ff::Field;
use ark_ff::PrimeField;
use binary::PedersenInstance;
use constants::P0;
use constants::P1;
use constants::P2;
use constants::P3;
use constants::P4;
use ministark::utils::FieldVariant;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use crate::utils::starkware_curve::Fr;
use crate::utils::starkware_curve::Curve;
use crate::utils::gen_periodic_table;

pub mod constants;

/// Computes the Starkware version of the Pedersen hash of a and b.
/// The hash is defined by:
///     shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
/// where x_low is the 248 low bits of x, x_high is the 4 high bits of x and
/// similarly for y. shift_point, P_0, P_1, P_2, P_3 are constant points
/// generated from the digits of pi.
/// Based on StarkWare's Python reference implementation: <https://github.com/starkware-libs/starkex-for-spot-trading/blob/master/src/starkware/crypto/starkware/crypto/signature/pedersen_params.json>
pub fn pedersen_hash(a: Fp, b: Fp) -> Fp {
    let processed_a = process_element(a, P1.into(), P2.into());
    let processed_b = process_element(b, P3.into(), P4.into());
    (P0 + processed_a + processed_b).into_affine().x
}

fn process_element(x: Fp, p1: Projective<Curve>, p2: Projective<Curve>) -> Projective<Curve> {
    assert_eq!(252, Fp::MODULUS_BIT_SIZE);
    let x: BigUint = x.into_bigint().into();
    let shift = 252 - 4;
    let high_part = &x >> shift;
    let low_part = x - (&high_part << shift);
    let x_high = Fr::from(high_part);
    let x_low = Fr::from(low_part);
    p1 * x_low + p2 * x_high
}

#[derive(Clone, Copy, Debug)]
pub struct ElementPartialStep {
    pub point: Affine<Curve>,
    pub suffix: Fp,
    pub slope: Fp,
}

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: PedersenInstance,
    pub output: Fp,
    pub a_steps: Vec<ElementPartialStep>,
    pub b_steps: Vec<ElementPartialStep>,
}

impl InstanceTrace {
    pub fn new(instance: PedersenInstance) -> Self {
        let PedersenInstance { a, b, .. } = instance;
        let a = Fp::from(BigUint::from(a));
        let b = Fp::from(BigUint::from(b));

        let a_p0 = P0;
        let a_p1 = P1;
        let a_p2 = P2;
        let a_steps = Self::gen_element_steps(a, a_p0, a_p1, a_p2);

        let b_p0 = (a_p0 + process_element(a, a_p1.into(), a_p2.into())).into();
        let b_p1 = P3;
        let b_p2 = P4;
        // check out initial value for the second input is correct
        assert_eq!(a_steps.last().unwrap().point, b_p0);
        let b_steps = Self::gen_element_steps(b, b_p0, b_p1, b_p2);

        // check the expected output matches
        let output = pedersen_hash(a, b);
        assert_eq!(output, b_steps.last().unwrap().point.x);

        Self {
            instance,
            output,
            a_steps,
            b_steps,
        }
    }

    fn gen_element_steps(
        x: Fp,
        p0: Affine<Curve>,
        p1: Affine<Curve>,
        p2: Affine<Curve>,
    ) -> Vec<ElementPartialStep> {
        // generate our constant points
        let mut constant_points = Vec::new();
        let mut p1_acc = Projective::from(p1);
        for _ in 0..252 - 4 {
            constant_points.push(p1_acc);
            p1_acc.double_in_place();
        }
        let mut p2_acc = Projective::from(p2);
        for _ in 0..4 {
            constant_points.push(p2_acc);
            p2_acc.double_in_place();
        }

        // generate partial sums
        let x_int = U256::from::<BigUint>(x.into());
        let mut partial_point = Projective::from(p0);
        let mut res = Vec::new();
        #[allow(clippy::needless_range_loop)]
        for i in 0..256 {
            let suffix = x_int >> i;
            let bit = suffix & uint!(1_U256);

            let mut slope: Fp = Fp::ZERO;
            let mut partial_point_next = partial_point;
            if bit == uint!(1_U256) {
                let constant_point = constant_points[i];
                let dy = partial_point.y - constant_point.y;
                let dx = partial_point.x - constant_point.x;
                slope = dy / dx;
                partial_point_next += constant_point;
            }

            res.push(ElementPartialStep {
                point: partial_point.into(),
                suffix: Fp::from(BigUint::from(suffix)),
                slope,
            });

            partial_point = partial_point_next;
        }

        res
    }
}

/// Ouptut is of the form (x_points_coeffs, y_points_coeffs)
// TODO: Generate these constant polynomials at compile time
#[allow(clippy::type_complexity)]
pub fn constant_points_poly() -> (Vec<FieldVariant<Fp, Fp>>, Vec<FieldVariant<Fp, Fp>>) {
    let mut evals = Vec::new();

    let mut acc = Projective::from(P1);
    for _ in 0..Fp::MODULUS_BIT_SIZE - 4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    let mut acc = Projective::from(P2);
    for _ in 0..4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    assert_eq!(evals.len(), 252);
    evals.resize(256, (Fp::ZERO, Fp::ZERO));

    let mut acc = Projective::from(P3);
    for _ in 0..Fp::MODULUS_BIT_SIZE - 4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    let mut acc = Projective::from(P4);
    for _ in 0..4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    assert_eq!(evals.len(), 256 + 252);
    evals.resize(512, (Fp::ZERO, Fp::ZERO));

    let (x_evals, y_evals) = evals.into_iter().unzip();
    let mut polys = gen_periodic_table(vec![x_evals, y_evals])
        .into_iter()
        .map(|poly| poly.coeffs.into_iter().map(FieldVariant::Fp).collect());
    let (x_coeffs, y_coeffs) = (polys.next().unwrap(), polys.next().unwrap());
    (x_coeffs, y_coeffs)
}
