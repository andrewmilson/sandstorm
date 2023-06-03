use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly::Evaluations;
use ark_poly::Radix2EvaluationDomain;

/// Generates a periodic table comprising of values in the matrix.
/// The columns of the periodic table are are represented by polynomials that
/// evaluate to the `i`th row when evaluated on the `i`th power of the `n`th
/// root of unity where n is the power-of-2 height of the table. For example a
/// matrix with 4 rows and 2 columns would be represented by two columns
/// `P_0(X)` and `P_1(X)`:
///
/// ```text
/// ┌───────────┬────────────────────┬────────────────────┐
/// │     X     │       P_0(X)       │       P_1(X)       │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^0    │     matrix_0_0     │     matrix_0_1     │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^1    │     matrix_1_0     │     matrix_1_1     │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^0    │     matrix_2_0     │     matrix_2_1     │
/// ├───────────┼────────────────────┼────────────────────┤
/// │    ω^1    │     matrix_3_0     │     matrix_3_1     │
/// └───────────┴────────────────────┴────────────────────┘
/// ```
///
/// Input and output matrix are to be represented in column-major.
pub fn gen_periodic_table<F: FftField>(matrix: Vec<Vec<F>>) -> Vec<DensePolynomial<F>> {
    if matrix.is_empty() {
        return Vec::new();
    }

    let num_rows = matrix[0].len();
    assert!(num_rows.is_power_of_two());
    assert!(matrix.iter().all(|col| col.len() == num_rows));

    let domain = Radix2EvaluationDomain::new(num_rows).unwrap();
    matrix
        .into_iter()
        .map(|col| Evaluations::from_vec_and_domain(col, domain).interpolate())
        .collect()
}

pub mod starkware_curve {
    use ark_ec::CurveConfig;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ff::Fp256;
    use ark_ff::Field;
    use ark_ff::MontBackend;
    use ark_ff::MontConfig;
    use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
    use ark_ec::short_weierstrass::Affine;
    use ark_ff::MontFp as Fp;

    #[derive(MontConfig)]
    #[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
    #[generator = "3"]
    pub struct FrConfig;
    pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

    // StarkWare's Cairo curve params: https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html
    pub struct Curve;

    impl CurveConfig for Curve {
        type BaseField = Fp;
        type ScalarField = Fr;

        const COFACTOR: &'static [u64] = &[1];
        const COFACTOR_INV: Self::ScalarField = Fr::ONE;
    }

    impl SWCurveConfig for Curve {
        const COEFF_A: Self::BaseField = Fp::ONE;
        const COEFF_B: Self::BaseField =
            Fp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

        const GENERATOR: Affine<Self> = Affine::new_unchecked(
            Fp!("874739451078007766457464989774322083649278607533249481151382481072868806602"),
            Fp!("152666792071518830868575557812948353041420400780739481342941381225525861407"),
        );
    }
}
