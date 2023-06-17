use ark_ff::FftField;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly::Evaluations;
use ark_poly::Radix2EvaluationDomain;
use std::ops::Mul;

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
// TODO: consider deleting
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

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mat3x3<T>(pub [[T; 3]; 3]);

impl<T> Mat3x3<T> {
    pub fn transpose(self) -> Self {
        let [[a, b, c], [d, e, f], [g, h, i]] = self.0;
        Mat3x3([[a, d, g], [b, e, h], [c, f, i]])
    }
}

impl<F: Field> Mat3x3<F> {
    pub fn identity() -> Self {
        Self([
            [F::one(), F::zero(), F::zero()],
            [F::zero(), F::one(), F::zero()],
            [F::zero(), F::zero(), F::one()],
        ])
    }

    pub fn inverse(self) -> Option<Self> {
        let [[a, b, c], [d, e, f], [g, h, i]] = self.0;
        let a_prime = e * i - f * h;
        let b_prime = -(b * i - c * h);
        let c_prime = b * f - c * e;
        let d_prime = -(d * i - f * g);
        let e_prime = a * i - c * g;
        let f_prime = -(a * f - c * d);
        let g_prime = d * h - e * g;
        let h_prime = -(a * h - b * g);
        let i_prime = a * e - b * d;
        let det = a * a_prime + b * d_prime + c * g_prime;
        let det_inv = det.inverse()?;
        let inv = Self([
            [a_prime, b_prime, c_prime],
            [d_prime, e_prime, f_prime],
            [g_prime, h_prime, i_prime],
        ]) * det_inv;
        debug_assert_eq!(self * inv, Self::identity());
        Some(inv)
    }
}

impl<F: Field> Mul<F> for Mat3x3<F> {
    type Output = Self;

    /// Multiplies the matrix by a vector
    fn mul(self, rhs: F) -> Self {
        Self(self.0.map(|row| row.map(|cell| cell * rhs)))
    }
}

impl<F: Field> Mul<Self> for Mat3x3<F> {
    type Output = Self;

    /// Multiplies the matrix by a vector
    fn mul(self, rhs: Self) -> Self {
        let [v0, v1, v2] = rhs.transpose().0;
        Mat3x3([self * v0, self * v1, self * v2]).transpose()
    }
}

impl<F: Field> Mul<[F; 3]> for Mat3x3<F> {
    type Output = [F; 3];

    /// Multiplies the matrix by a vector
    fn mul(self, [x, y, z]: [F; 3]) -> [F; 3] {
        let [[a, b, c], [d, e, f], [g, h, i]] = self.0;
        [
            x * a + y * b + z * c,
            x * d + y * e + z * f,
            x * g + y * h + z * i,
        ]
    }
}

pub mod curve {
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
    pub struct StarkwareCurve;

    impl CurveConfig for StarkwareCurve {
        type BaseField = Fp;
        type ScalarField = Fr;

        const COFACTOR: &'static [u64] = &[1];
        const COFACTOR_INV: Self::ScalarField = Fr::ONE;
    }

    impl SWCurveConfig for StarkwareCurve {
        const COEFF_A: Self::BaseField = Fp::ONE;
        const COEFF_B: Self::BaseField =
            Fp!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

        const GENERATOR: Affine<Self> = Affine::new_unchecked(
            Fp!("874739451078007766457464989774322083649278607533249481151382481072868806602"),
            Fp!("152666792071518830868575557812948353041420400780739481342941381225525861407"),
        );
    }

    /// calculates the slope between points `p1` and `p2`
    /// Returns None if one of the points is the point at infinity
    pub fn calculate_slope(p1: Affine<StarkwareCurve>, p2: Affine<StarkwareCurve>) -> Option<Fp> {
        if p1.infinity || p2.infinity || (p1.x == p2.x && p1.y != p2.y) {
            return None;
        }

        let y1 = p1.y;
        let y2 = p2.y;
        let x1 = p1.x;
        let x2 = p2.x;

        Some(if x1 == x2 {
            // use tangent line
            assert_eq!(y1, y2);
            let xx = x1.square();
            (xx + xx + xx + StarkwareCurve::COEFF_A) / (y1 + y1)
        } else {
            // use slope
            (y2 - y1) / (x2 - x1)
        })
    }
}
