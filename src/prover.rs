use crate::air::CairoAir;
use crate::air::ExecutionInfo;
use crate::binary::RegisterState;
use crate::trace::ExecutionTrace;
use cairo_rs::vm::trace::trace_entry::RelocatedTraceEntry;
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

    fn get_pub_inputs(&self, trace: &ExecutionTrace) -> ExecutionInfo {
        assert_eq!(trace.initial_registers.ap, trace.initial_registers.fp);
        assert_eq!(trace.initial_registers.ap, trace.final_registers.fp);
        ExecutionInfo {
            initial_ap: (trace.initial_registers.ap as u64).into(),
            initial_pc: (trace.initial_registers.pc as u64).into(),
            final_ap: (trace.final_registers.ap as u64).into(),
            final_pc: (trace.final_registers.pc as u64).into(),
        }
    }
}
