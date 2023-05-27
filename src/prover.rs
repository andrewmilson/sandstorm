use ark_ff::PrimeField;
use layouts::CairoAirConfig;
use layouts::CairoExecutionTrace;
use layouts::ExecutionInfo;
use ministark::ProofOptions;
use ministark::Prover;
use std::marker::PhantomData;

pub struct CairoProver<A: CairoAirConfig, T: CairoExecutionTrace>
where
    A::Fp: PrimeField,
{
    options: ProofOptions,
    _marker: PhantomData<(A, T)>,
}

impl<A: CairoAirConfig, T: CairoExecutionTrace<Fp = A::Fp, Fq = A::Fq>> Prover for CairoProver<A, T>
where
    A::Fp: PrimeField,
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Trace = T;

    fn new(options: ProofOptions) -> Self {
        CairoProver {
            options,
            _marker: PhantomData,
        }
    }

    fn options(&self) -> ProofOptions {
        self.options
    }

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ExecutionInfo<A::Fp> {
        trace.execution_info()
    }
}
