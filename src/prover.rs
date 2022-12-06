use crate::air::CairoAir;
use crate::air::ExecutionInfo;
use crate::trace::ExecutionTrace;
use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use ministark::ProofOptions;
use ministark::Prover;

pub struct CairoProver(ProofOptions);

impl Prover for CairoProver {
    type Fp = Fp;
    type Fq = Fp;
    type Air = CairoAir;
    type Trace = ExecutionTrace;

    fn new(options: ProofOptions) -> Self {
        CairoProver(options)
    }

    fn options(&self) -> ProofOptions {
        self.0
    }

    fn get_pub_inputs(&self, _trace: &ExecutionTrace) -> ExecutionInfo {
        ExecutionInfo()
    }
}
