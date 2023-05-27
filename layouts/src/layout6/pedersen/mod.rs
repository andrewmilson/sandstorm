use ark_ec::CurveConfig;
use ark_ec::CurveGroup;
use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::Projective;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::Field;
use ark_ff::Fp256;
use ark_ff::MontBackend;
use ark_ff::MontFp as Fp;
use ark_ff::MontConfig;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_poly::Evaluations;
use ark_poly::Radix2EvaluationDomain;
use ministark::utils::FieldVariant;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;

pub mod params;

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[generator = "3"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

// Pedersen curve params: https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html
pub struct PedersenCurveConfig;

impl CurveConfig for PedersenCurveConfig {
    type BaseField = Fp;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = &[1];
    const COFACTOR_INV: Self::ScalarField = Fr::ONE;
}

impl SWCurveConfig for PedersenCurveConfig {
    const COEFF_A: Self::BaseField = Fp::ONE;
    const COEFF_B: Self::BaseField =
        Fp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

    const GENERATOR: Affine<Self> = Affine::new_unchecked(
        Fp!("874739451078007766457464989774322083649278607533249481151382481072868806602"),
        Fp!("152666792071518830868575557812948353041420400780739481342941381225525861407"),
    );
}

/// Computes the Starkware version of the Pedersen hash of a and b.
/// The hash is defined by:
///     shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
/// where x_low is the 248 low bits of x, x_high is the 4 high bits of x and
/// similarly for y. shift_point, P_0, P_1, P_2, P_3 are constant points
/// generated from the digits of pi.
/// Based on StarkWare's Python reference implementation: <https://github.com/starkware-libs/starkex-for-spot-trading/blob/master/src/starkware/crypto/starkware/crypto/signature/pedersen_params.json>
pub fn hash(a: Fp, b: Fp) -> Fp {
    (params::PEDERSEN_SHIFT_POINT
        + process_element(a, params::PEDERSEN_P1.into(), params::PEDERSEN_P2.into())
        + process_element(b, params::PEDERSEN_P3.into(), params::PEDERSEN_P4.into()))
    .into_affine()
    .x
}

fn process_element(
    x: Fp,
    p1: Projective<PedersenCurveConfig>,
    p2: Projective<PedersenCurveConfig>,
) -> Projective<PedersenCurveConfig> {
    assert_eq!(252, Fp::MODULUS_BIT_SIZE);
    let x: BigUint = x.into_bigint().into();
    let shift = 252 - 4;
    let high_part = &x >> shift;
    let low_part = x - (&high_part << shift);
    let x_high = Fr::from(high_part);
    let x_low = Fr::from(low_part);
    p1 * x_low + p2 * x_high
}

/// Ouptut is of the form (x_points, y_points)
// TODO: Generate these constant polynomials at compile time
#[allow(clippy::type_complexity)]
pub fn points_poly() -> (Vec<FieldVariant<Fp, Fp>>, Vec<FieldVariant<Fp, Fp>>) {
    let mut evals = Vec::new();

    let mut acc = Projective::from(params::PEDERSEN_P1);
    for _ in 0..Fp::MODULUS_BIT_SIZE - 4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    let mut acc = Projective::from(params::PEDERSEN_P2);
    for _ in 0..4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    assert_eq!(evals.len(), 252);
    evals.resize(256, (Fp::ZERO, Fp::ZERO));

    let mut acc = Projective::from(params::PEDERSEN_P3);
    for _ in 0..Fp::MODULUS_BIT_SIZE - 4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    let mut acc = Projective::from(params::PEDERSEN_P4);
    for _ in 0..4 {
        let p = acc.into_affine();
        evals.push((p.x, p.y));
        acc += acc;
    }

    assert_eq!(evals.len(), 256 + 252);
    evals.resize(512, (Fp::ZERO, Fp::ZERO));

    let (x_evals, y_evals) = evals.into_iter().unzip();
    let domain = Radix2EvaluationDomain::new(512).unwrap();
    let x_coeffs = Evaluations::from_vec_and_domain(x_evals, domain).interpolate();
    let y_coeffs = Evaluations::from_vec_and_domain(y_evals, domain).interpolate();
    (
        x_coeffs.coeffs.into_iter().map(FieldVariant::Fp).collect(),
        y_coeffs.coeffs.into_iter().map(FieldVariant::Fp).collect(),
    )
}
