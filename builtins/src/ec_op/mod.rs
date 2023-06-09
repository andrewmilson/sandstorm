use std::sync::OnceLock;

use crate::{utils::curve::StarkwareCurve, ecdsa::{mimic_ec_mult_air, doubling_steps, DoublingStep}, pedersen};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use binary::EcOpInstance;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::{aliases::U256, uint};

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
    // pub q_doubling_steps: Vec<DoublingStep>,
    pub r: Affine<StarkwareCurve>,
    pub m: Fp,
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

        let r = mimic_ec_mult_air(m.into(), q.into(), p.into())
            .unwrap()
            .into();

        Self {
            instance,
            p,
            q,
            q_doubling_steps,
            m,
            r,
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
    let p = pedersen::constants::P0;
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
