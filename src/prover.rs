use ark_ff::PrimeField;
use gpu_poly::GpuFftField;
use layouts::layout6;
use layouts::ExecutionInfo;
use ministark::ProofOptions;
use ministark::Prover;
use ministark::StarkExtensionOf;
use std::marker::PhantomData;

pub struct CairoProver<Fp, Fq> {
    options: ProofOptions,
    _marker: PhantomData<(Fp, Fq)>,
}

impl<Fp: GpuFftField + PrimeField, Fq: StarkExtensionOf<Fp>> Prover for CairoProver<Fp, Fq> {
    type Fp = Fp;
    type Fq = Fq;
    type AirConfig = layout6::AirConfig<Fp, Fq>;
    type Trace = layout6::ExecutionTrace<Fp, Fq>;

    fn new(options: ProofOptions) -> Self {
        CairoProver {
            options,
            _marker: PhantomData,
        }
    }

    fn options(&self) -> ProofOptions {
        self.options
    }

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ExecutionInfo<Fp> {
        assert_eq!(trace.initial_registers.ap, trace.initial_registers.fp);
        assert_eq!(trace.initial_registers.ap, trace.final_registers.fp);
        ExecutionInfo {
            initial_ap: (trace.initial_registers.ap as u64).into(),
            initial_pc: (trace.initial_registers.pc as u64).into(),
            final_ap: (trace.final_registers.ap as u64).into(),
            final_pc: (trace.final_registers.pc as u64).into(),
            public_memory: trace.public_memory.clone(),
            range_check_min: trace.range_check_min,
            range_check_max: trace.range_check_max,
            public_memory_padding_address: trace.public_memory_padding_address,
            public_memory_padding_value: trace.public_memory_padding_value,
        }
    }
}
