use std::sync::OnceLock;

use crate::utils::curve::StarkwareCurve;
use crate::utils::curve::calculate_slope;
use crate::ecdsa::doubling_steps;
use crate::ecdsa::DoublingStep;
use crate::ecdsa::EcMadPartialStep;
use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::short_weierstrass::Projective; 
use ark_ec::CurveGroup;
use ark_ec::Group;
use binary::EcOpInstance;
use ark_ff::Field;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;
use ruint::uint;

/// An ECDSA trace for a dummy instance
/// Created once since creating new instance traces each time is expensive.
static DUMMY_INSTANCE_TRACE: OnceLock<InstanceTrace> = OnceLock::new();

/// Elliptic Curve operation instance trace for `r = p + m * q` with scalar `m`
/// and points `p`, `q` and `r` on an elliptic curve
#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: EcOpInstance,
    pub p: Affine<StarkwareCurve>,
    pub q: Affine<StarkwareCurve>,
    pub q_doubling_steps: Vec<DoublingStep>,
    pub r: Affine<StarkwareCurve>,
    pub r_steps: Vec<EcMadPartialStep>,
    pub m: Fp,
    pub m_bit251_and_bit196_and_bit192: bool,
    pub m_bit251_and_bit196: bool,
}

impl InstanceTrace {
    pub fn new(instance: EcOpInstance) -> Self {
        let p_x = BigUint::from(instance.p_x).into();
        let p_y = BigUint::from(instance.p_y).into();
        let p = Affine::new(p_x, p_y);

        let q_x = BigUint::from(instance.q_x).into();
        let q_y = BigUint::from(instance.q_y).into();
        let q = Affine::new(q_x, q_y);
        let q_doubling_steps = doubling_steps(256, q.into());

        let m = Fp::from(BigUint::from(instance.m));
        let m_bit251 = instance.m.bit(251);
        let m_bit196 = instance.m.bit(196);
        let m_bit192 = instance.m.bit(192);
        let m_bit251_and_bit196_and_bit192 = m_bit251 && m_bit196 && m_bit192;
        let m_bit251_and_bit196 = m_bit251 && m_bit196;

        let r = mimic_ec_mad_air(m, q.into(), p.into()).unwrap().into();
        let r_steps = gen_ec_mad_steps(m, q.into(), p.into());
        assert_eq!(r, r_steps.last().unwrap().partial_sum);

        Self {
            instance,
            p,
            q,
            q_doubling_steps,
            m,
            m_bit251_and_bit196_and_bit192,
            m_bit251_and_bit196,
            r,
            r_steps,
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

/// Generates a dummy EC op instance using `private_key = 1`
fn gen_dummy_instance(index: u32) -> EcOpInstance {
    let p = crate::pedersen::constants::P0;
    let q = StarkwareCurve::GENERATOR;
    EcOpInstance {
        index,
        p_x: U256::from(BigUint::from(p.x)),
        p_y: U256::from(BigUint::from(p.y)),
        q_x: U256::from(BigUint::from(q.x)),
        q_y: U256::from(BigUint::from(q.y)),
        m: uint!(1_U256),
    }
}

/// Generates a list of the steps involved with `p + m * q`
/// Different failure cases to [crate::ecdsa::gen_ec_mad_steps]
fn gen_ec_mad_steps(
    m: Fp,
    mut q: Projective<StarkwareCurve>,
    p: Projective<StarkwareCurve>,
) -> Vec<EcMadPartialStep> {
    let m = U256::from(BigUint::from(m));
    let mut partial_sum = p;
    let mut res = Vec::new();
    for i in 0..256 {
        let suffix = m >> i;
        let bit = suffix & uint!(1_U256);

        let mut slope = Fp::ZERO;
        let mut partial_sum_next = partial_sum;
        let partial_sum_affine = partial_sum.into_affine();
        let q_affine = q.into_affine();
        if bit == uint!(1_U256) {
            slope = calculate_slope(q_affine, partial_sum_affine).unwrap();
            partial_sum_next += q;
        }

        res.push(EcMadPartialStep {
            partial_sum: partial_sum_affine,
            fixed_point: q_affine,
            suffix: Fp::from(BigUint::from(suffix)),
            x_diff_inv: (partial_sum_affine.x - q_affine.x).inverse().unwrap(),
            slope,
        });

        partial_sum = partial_sum_next;
        q.double_in_place();
    }
    res
}

/// Computes `p + m * q` using the same steps as the AIR
/// Returns None if and only if the AIR errors.
pub(crate) fn mimic_ec_mad_air(
    m: Fp,
    mut q: Projective<StarkwareCurve>,
    p: Projective<StarkwareCurve>,
) -> Option<Projective<StarkwareCurve>> {
    let mut m = U256::from(BigUint::from(m));
    let mut partial_sum = p;
    #[allow(clippy::needless_range_loop)]
    while m != U256::ZERO {
        if Affine::from(partial_sum).x == Affine::from(q).x {
            return None;
        }
        let bit = m & uint!(1_U256);
        if bit == uint!(1_U256) {
            partial_sum += q;
        }
        q.double_in_place();
        m >>= 1;
    }
    Some(partial_sum)
}
