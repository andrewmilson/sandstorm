use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use gpu_poly::GpuField;
use ministark::Air;
use ministark::Constraint;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;

use crate::trace::Flag;

pub struct CairoAir {
    transition_constraints: Vec<Constraint<Fp>>,
    boundary_constraints: Vec<Constraint<Fp>>,
}

// Section 9.2 https://eprint.iacr.org/2021/1063.pdf
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct ExecutionInfo {
    pub partial_mem: Vec<Fp>,
    // TODO
}

impl Air for CairoAir {
    type Fp = Fp;
    type Fq = Fp;
    type PublicInputs = ExecutionInfo;

    fn new(
        info: ministark::TraceInfo,
        inputs: Self::PublicInputs,
        options: ministark::ProofOptions,
    ) -> Self {
        todo!()
    }

    fn pub_inputs(&self) -> &Self::PublicInputs {
        todo!()
    }

    fn trace_info(&self) -> &ministark::TraceInfo {
        todo!()
    }

    fn options(&self) -> &ministark::ProofOptions {
        todo!()
    }
}
