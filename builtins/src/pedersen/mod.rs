use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::Projective;
use ark_ff::BigInt;
use ark_ff::Field;
use ark_ff::PrimeField;
use binary::PedersenInstance;
use constants::P0;
use constants::P1;
use constants::P2;
use constants::P3;
use constants::P4;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;
use crate::utils::curve::Fr;
use crate::utils::curve::StarkwareCurve;
use crate::utils::curve::calculate_slope;

pub mod constants;
pub mod periodic;

/// Computes the Pedersen hash of a and b using StarkWare's parameters.
/// The hash is defined by:
///     shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
/// where x_low is the 248 low bits of x, x_high is the 4 high bits of x and
/// similarly for y. shift_point, P_0, P_1, P_2, P_3 are constant points
/// generated from the digits of pi.
pub fn pedersen_hash(a: Fp, b: Fp) -> Fp {
    let a = starknet_crypto::FieldElement::from_mont((a.0).0);
    let b = starknet_crypto::FieldElement::from_mont((b.0).0);
    let res = starknet_crypto::pedersen_hash(&a, &b);
    Fp::new_unchecked(BigInt(res.into_mont()))
}

/// Based on StarkWare's Python reference implementation: <https://github.com/starkware-libs/starkex-for-spot-trading/blob/master/src/starkware/crypto/starkware/crypto/signature/pedersen_params.json>
// TODO: remove
#[deprecated]
pub fn pedersen_hash_slow(a: Fp, b: Fp) -> Fp {
    let a = starknet_crypto::FieldElement::from_mont((a.0).0);
    let b = starknet_crypto::FieldElement::from_mont((b.0).0);
    let res = starknet_crypto::pedersen_hash(&a, &b);
    Fp::new_unchecked(BigInt(res.into_mont()))
}

fn process_element(
    x: Fp,
    p1: Projective<StarkwareCurve>,
    p2: Projective<StarkwareCurve>,
) -> Projective<StarkwareCurve> {
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
    pub point: Affine<StarkwareCurve>,
    pub suffix: Fp,
    pub slope: Fp,
}

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: PedersenInstance,
    pub output: Fp,
    pub a_steps: Vec<ElementPartialStep>,
    pub b_steps: Vec<ElementPartialStep>,
    pub a_bit251_and_bit196_and_bit192: bool,
    pub a_bit251_and_bit196: bool,
    pub b_bit251_and_bit196_and_bit192: bool,
    pub b_bit251_and_bit196: bool,
}

impl InstanceTrace {
    pub fn new(instance: PedersenInstance) -> Self {
        let PedersenInstance { a, b, .. } = instance;
        let a = Fp::from(BigUint::from(a));
        let b = Fp::from(BigUint::from(b));

        let a_p0 = P0;
        let a_p1 = P1;
        let a_p2 = P2;
        let a_steps = gen_element_steps(a, a_p0, a_p1, a_p2);

        let b_p0 = (a_p0 + process_element(a, a_p1.into(), a_p2.into())).into();
        let b_p1 = P3;
        let b_p2 = P4;
        // check out initial value for the second input is correct
        assert_eq!(a_steps.last().unwrap().point, b_p0);
        let b_steps = gen_element_steps(b, b_p0, b_p1, b_p2);

        // check the expected output matches
        let output = pedersen_hash(a, b);
        assert_eq!(output, b_steps.last().unwrap().point.x);

        let a_bit251 = instance.a.bit(251);
        let a_bit196 = instance.a.bit(196);
        let a_bit192 = instance.a.bit(192);
        let a_bit251_and_bit196_and_bit192 = a_bit251 && a_bit196 && a_bit192;
        let a_bit251_and_bit196 = a_bit251 && a_bit196;

        let b_bit251 = instance.b.bit(251);
        let b_bit196 = instance.b.bit(196);
        let b_bit192 = instance.b.bit(192);
        let b_bit251_and_bit196_and_bit192 = b_bit251 && b_bit196 && b_bit192;
        let b_bit251_and_bit196 = b_bit251 && b_bit196;

        Self {
            instance,
            output,
            a_steps,
            b_steps,
            a_bit251_and_bit196_and_bit192,
            a_bit251_and_bit196,
            b_bit251_and_bit196_and_bit192,
            b_bit251_and_bit196,
        }
    }
}

fn gen_element_steps(
    x: Fp,
    p0: Affine<StarkwareCurve>,
    p1: Affine<StarkwareCurve>,
    p2: Affine<StarkwareCurve>,
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
        let partial_point_affine = partial_point.into_affine();
        if bit == uint!(1_U256) {
            let constant_point = constant_points[i];
            slope = calculate_slope(constant_point.into(), partial_point_affine).unwrap();
            partial_point_next += constant_point;
        }

        res.push(ElementPartialStep {
            point: partial_point_affine,
            suffix: Fp::from(BigUint::from(suffix)),
            slope,
        });

        partial_point = partial_point_next;
    }

    res
}

#[cfg(test)]
mod tests {
    use crate::pedersen::pedersen_hash;
    use ark_ff::MontFp as Fp;

    #[test]
    fn hash_example0_works() {
        // Example source:
        // https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature_test_data.json#L87
        let a = Fp!("1740729136829561885683894917751815192814966525555656371386868611731128807883");
        let b = Fp!("919869093895560023824014392670608914007817594969197822578496829435657368346");

        let output = pedersen_hash(a, b);

        assert_eq!(
            Fp!("1382171651951541052082654537810074813456022260470662576358627909045455537762"),
            output
        )
    }

    #[test]
    fn hash_example1_works() {
        // Example source:
        // https://github.com/starkware-libs/starkex-resources/blob/master/crypto/starkware/crypto/signature/signature_test_data.json#L92
        let a = Fp!("2514830971251288745316508723959465399194546626755475650431255835704887319877");
        let b = Fp!("3405079826265633459083097571806844574925613129801245865843963067353416465931");

        let output = pedersen_hash(a, b);

        assert_eq!(
            Fp!("2962565761002374879415469392216379291665599807391815720833106117558254791559"),
            output
        )
    }
}
